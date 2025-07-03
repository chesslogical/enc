//! Threefish‑1024 + HMAC‑SHA‑256 CLI encryptor / decryptor
//!
//! Usage:
//!     threefish_cli [--encrypt|--decrypt] <FILE>

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
    env,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use threefish::Threefish1024;
use zeroize::Zeroizing;

/* -------------------------------------------------------------------------- */
/*                               CONSTANTS                                    */
/* -------------------------------------------------------------------------- */

/// 128 B cipher key + 32 B MAC key
const KEY_BYTES: usize = 160;

/// Header (big‑endian, fixed size = 48 B)
/// magic(4) | ver(1) | cipher_id(1) | mac_id(1) | reserved(1)
/// | nonce128(16) | reserved(24)
const MAGIC: &[u8; 4] = b"T1FS";
const VERSION: u8 = 1;
const CIPHER_ID_THREEFISH1024_STREAM: u8 = 0x01;
const MAC_ID_HMAC_SHA256: u8 = 0x01;

const HEADER_LEN: usize = 48;
const NONCE_LEN: usize = 16;            // 128‑bit nonce
const MAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 128;          // Threefish‑1024 block size
const IO_BUF_SIZE: usize = 16 * 1024;   // 16 KiB

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

/* -------------------------------------------------------------------------- */
/*                                   MAIN                                     */
/* -------------------------------------------------------------------------- */

fn main() -> Result<()> {
    /* ---------- Parse command‑line --------------------------------------- */
    let (mode_override, path) = parse_cli()?;

    /* ---------- Load keyfile -------------------------------------------- */
    let (cipher_key, mac_key) = load_keyfile(Path::new("key.key"))?;

    /* ---------- Decide mode --------------------------------------------- */
    let mode = mode_override.unwrap_or_else(|| detect_mode(&path).unwrap());

    println!(
        "{} → {}",
        path.display(),
        match mode {
            Mode::Encrypt => "encrypted",
            Mode::Decrypt => "decrypted",
        }
    );

    process_file(&path, mode, &cipher_key, &mac_key)
}

/* -------------------------------------------------------------------------- */
/*                           CLI & AUTO‑DETECTION                            */
/* -------------------------------------------------------------------------- */

fn parse_cli() -> Result<(Option<Mode>, PathBuf)> {
    let mut args = env::args().skip(1);
    let mut mode_override = None::<Mode>;
    let mut file: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-e" | "--encrypt" => mode_override = Some(Mode::Encrypt),
            "-d" | "--decrypt" => mode_override = Some(Mode::Decrypt),
            _ => {
                if file.is_none() {
                    file = Some(PathBuf::from(arg));
                } else {
                    return Err(anyhow!("unexpected extra argument: {arg}"));
                }
            }
        }
    }
    let file = file.ok_or_else(|| anyhow!("usage: threefish_cli [--encrypt|--decrypt] <FILE>"))?;
    Ok((mode_override, file))
}

/// Decide whether `path` looks like our ciphertext or plain data.
fn detect_mode(path: &Path) -> Result<Mode> {
    let mut f = File::open(path).with_context(|| format!("open {:?}", path))?;
    let meta = f.metadata()?;
    if meta.len() < (HEADER_LEN + MAC_LEN) as u64 {
        return Ok(Mode::Encrypt); // too small to be ciphertext
    }

    let mut header = [0u8; HEADER_LEN];
    f.read_exact(&mut header)?;

    match validate_header(&header) {
        Ok(_) => Ok(Mode::Decrypt),
        Err(_) => Ok(Mode::Encrypt),
    }
}

/* -------------------------------------------------------------------------- */
/*                           DISPATCH                                        */
/* -------------------------------------------------------------------------- */

fn process_file(
    path: &Path,
    mode: Mode,
    cipher_key: &[u8; 128],
    mac_key: &[u8; 32],
) -> Result<()> {
    match mode {
        Mode::Encrypt => encrypt_file(path, cipher_key, mac_key),
        Mode::Decrypt => decrypt_file(path, cipher_key, mac_key),
    }
}

/* -------------------------------------------------------------------------- */
/*                               KEY HANDLING                                 */
/* -------------------------------------------------------------------------- */

/// Read 160‑byte key file and return (cipher_key, mac_key); both are
/// wrapped in `Zeroizing` so that memory is wiped on drop.
fn load_keyfile(path: &Path) -> Result<(Zeroizing<[u8; 128]>, Zeroizing<[u8; 32]>)> {
    let mut buf = Zeroizing::new([0u8; KEY_BYTES]);
    File::open(path)
        .with_context(|| format!("open key file {path:?}"))?
        .read_exact(buf.as_mut())
        .with_context(|| "read key bytes")?;

    let mut cipher_key = Zeroizing::new([0u8; 128]);
    let mut mac_key = Zeroizing::new([0u8; 32]);
    cipher_key.copy_from_slice(&buf[..128]);
    mac_key.copy_from_slice(&buf[128..]);
    Ok((cipher_key, mac_key))
}

/* -------------------------------------------------------------------------- */
/*                          LIGHTWEIGHT STREAM‑CIPHER                         */
/* -------------------------------------------------------------------------- */

/// Stateless helper that produces a keystream block‑by‑block.
struct StreamCipher<'a> {
    key64: &'a [u64; 16],
    nonce_hi: u64,
    nonce_lo: u64,
    block_idx: u64,
}

impl<'a> StreamCipher<'a> {
    fn new(key64: &'a [u64; 16], nonce_hi: u64, nonce_lo: u64) -> Self {
        Self {
            key64,
            nonce_hi,
            nonce_lo,
            block_idx: 0,
        }
    }

    /// XOR‑encrypt/decrypt `data` in place.
    fn xor_in_place(&mut self, mut data: &mut [u8]) {
        while !data.is_empty() {
            let tweak = [self.nonce_hi, self.block_idx ^ self.nonce_lo];
            self.block_idx = self
                .block_idx
                .checked_add(1)
                .expect("file size would overflow u64");

            let cipher = Threefish1024::new_with_tweak_u64(self.key64, &tweak);
            let mut ks_words = [0u64; 16];
            cipher.encrypt_block_u64(&mut ks_words);

            let mut keystream = [0u8; BLOCK_SIZE];
            for (i, w) in ks_words.iter().enumerate() {
                keystream[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
            }

            let n = data.len().min(BLOCK_SIZE);
            for (b, k) in data[..n].iter_mut().zip(keystream.iter()) {
                *b ^= *k;
            }
            data = &mut data[n..];
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                               ENCRYPTION                                   */
/* -------------------------------------------------------------------------- */

fn encrypt_file(src_path: &Path, cipher_key: &[u8; 128], mac_key: &[u8; 32]) -> Result<()> {
    let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src_path)?);

    // Temp file in the same directory (so rename is atomic)
    let tmp = NamedTempFile::new_in(
        src_path
            .parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp.reopen()?);

    /* -------- Build header (128‑bit random nonce) -------- */
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hi = u64::from_be_bytes(nonce_bytes[0..8].try_into().expect("slice len 8"));
    let nonce_lo = u64::from_be_bytes(nonce_bytes[8..16].try_into().expect("slice len 8"));
    let header = build_header(&nonce_bytes);
    writer.write_all(&header)?;

    /* -------- Prepare MAC -------- */
    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&header);

    /* -------- Stream‑encrypt -------- */
    let key64 = to_u64_key(cipher_key);
    let mut sc = StreamCipher::new(&key64, nonce_hi, nonce_lo);

    let mut buf = [0u8; IO_BUF_SIZE];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sc.xor_in_place(&mut buf[..read]);
        hmac.update(&buf[..read]);
        writer.write_all(&buf[..read])?;
    }

    /* -------- Finalise tag -------- */
    writer.write_all(&hmac.finalize().into_bytes())?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    tmp.as_file().sync_all()?; // extra safety

    /* -------- Promote temp file -------- */
    promote_with_backup(src_path, tmp.path())
}

/* -------------------------------------------------------------------------- */
/*                               DECRYPTION                                   */
/* -------------------------------------------------------------------------- */

fn decrypt_file(src_path: &Path, cipher_key: &[u8; 128], mac_key: &[u8; 32]) -> Result<()> {
    /* -------- 1️⃣  First pass – verify MAC ----------------------------- */
    {
        let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src_path)?);

        // Parse header
        let mut header = [0u8; HEADER_LEN];
        reader.read_exact(&mut header)?;
        validate_header(&header)?;

        let nonce_hi =
            u64::from_be_bytes(header[8..16].try_into().expect("slice len 8"));
        let nonce_lo =
            u64::from_be_bytes(header[16..24].try_into().expect("slice len 8"));

        // Compute tag over ciphertext
        let mut hmac = HmacSha256::new_from_slice(mac_key)?;
        hmac.update(&header);

        let mut buf = [0u8; IO_BUF_SIZE];
        let file_len = reader.get_ref().metadata()?.len();
        let ciphertext_len = file_len
            .checked_sub(HEADER_LEN as u64 + MAC_LEN as u64)
            .ok_or_else(|| anyhow!("file too small"))?;

        let mut remaining = ciphertext_len;
        while remaining != 0 {
            let chunk = remaining.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..chunk])?;
            hmac.update(&buf[..chunk]);
            remaining -= chunk as u64;
        }

        // Read MAC and verify
        let mut mac_on_disk = [0u8; MAC_LEN];
        reader.read_exact(&mut mac_on_disk)?;
        hmac.verify_slice(&mac_on_disk)
            .map_err(|_| anyhow!("authentication failed"))?;

        /* If we reach here, authentication succeeded. */
        drop(reader); // close handle

        /* -------- 2️⃣  Second pass – decrypt --------------------------- */
        let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src_path)?);
        reader.seek(SeekFrom::Start(HEADER_LEN as u64))?; // skip header

        let key64 = to_u64_key(cipher_key);
        let mut sc = StreamCipher::new(&key64, nonce_hi, nonce_lo);

        // Temp file for plaintext
        let tmp = NamedTempFile::new_in(
            src_path
                .parent()
                .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
        )?;
        let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp.reopen()?);

        let mut buf = [0u8; IO_BUF_SIZE];
        let mut remaining = ciphertext_len;
        while remaining != 0 {
            let chunk = remaining.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..chunk])?;
            sc.xor_in_place(&mut buf[..chunk]);
            writer.write_all(&buf[..chunk])?;
            remaining -= chunk as u64;
        }

        writer.flush()?;
        writer.get_ref().sync_all()?;
        tmp.as_file().sync_all()?;
        promote_with_backup(src_path, tmp.path())
    }
}

/* -------------------------------------------------------------------------- */
/*                             FILE PROMOTION                                 */
/* -------------------------------------------------------------------------- */

/// Promote `tmp_path` to `final_path`, keeping a `*.bak` backup of the original.
fn promote_with_backup(final_path: &Path, tmp_path: &Path) -> Result<()> {
    let backup = final_path.with_extension("bak");
    let _ = fs::remove_file(&backup);           // clear stale
    fs::rename(final_path, &backup).ok();       // ignore error if first run

    match fs::rename(tmp_path, final_path) {
        Ok(_) => {
            let _ = fs::remove_file(&backup);
            Ok(())
        }
        Err(e) => {
            let _ = fs::rename(&backup, final_path);
            Err(e).context("failed to promote temp file")
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                             CRYPTO HELPERS                                 */
/* -------------------------------------------------------------------------- */

/// Build header bytes (big‑endian) with 128‑bit nonce.
fn build_header(nonce128: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut hdr = [0u8; HEADER_LEN];
    hdr[..4].copy_from_slice(MAGIC);             // magic
    hdr[4] = VERSION;                            // version
    hdr[5] = CIPHER_ID_THREEFISH1024_STREAM;     // cipher_id
    hdr[6] = MAC_ID_HMAC_SHA256;                 // mac_id
    hdr[7] = 0;                                  // reserved
    hdr[8..24].copy_from_slice(nonce128);        // 128‑bit nonce
    // bytes 24‑47 remain zero (reserved)
    hdr
}

/// Sanity‑check header values.
fn validate_header(hdr: &[u8; HEADER_LEN]) -> Result<()> {
    if &hdr[..4] != MAGIC {
        return Err(anyhow!("bad magic"));
    }
    if hdr[4] != VERSION {
        return Err(anyhow!("unsupported version {}", hdr[4]));
    }
    if hdr[5] != CIPHER_ID_THREEFISH1024_STREAM || hdr[6] != MAC_ID_HMAC_SHA256 {
        return Err(anyhow!("unknown algorithm identifiers"));
    }
    Ok(())
}

/// Convert 128‑byte key into 16×u64 Little‑Endian words.
fn to_u64_key(key: &[u8; 128]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, chunk) in key.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().expect("chunk len 8"));
    }
    out
}

/* -------------------------------------------------------------------------- */
/*                                  TESTS                                     */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::io::{Seek, SeekFrom, Write};

    fn write_random_key() -> ([u8; 128], [u8; 32]) {
        let mut key = [0u8; KEY_BYTES];
        OsRng.fill_bytes(&mut key);
        File::create("key.key").unwrap().write_all(&key).unwrap();

        let mut ck = [0u8; 128];
        let mut mk = [0u8; 32];
        ck.copy_from_slice(&key[..128]);
        mk.copy_from_slice(&key[128..]);
        (ck, mk)
    }

    #[test]
    fn roundtrip_small() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"hello world").unwrap();

        let (ck, mk) = write_random_key();
        encrypt_file(tmpfile.path(), &ck, &mk).unwrap();
        decrypt_file(tmpfile.path(), &ck, &mk).unwrap();

        let mut plain = Vec::new();
        File::open(tmpfile.path())
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, b"hello world");
        let _ = std::fs::remove_file("key.key");
    }

    #[test]
    fn non_block_multiple() {
        let mut data = vec![0u8; BLOCK_SIZE + 17];
        OsRng.fill_bytes(&mut data);
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&data).unwrap();

        let (ck, mk) = write_random_key();
        encrypt_file(tmpfile.path(), &ck, &mk).unwrap();
        decrypt_file(tmpfile.path(), &ck, &mk).unwrap();

        let mut out = Vec::new();
        File::open(tmpfile.path()).unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(data, out);
        let _ = std::fs::remove_file("key.key");
    }

    #[test]
    fn mac_failure() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"abcdefg").unwrap();
        let (ck, mk) = write_random_key();
        encrypt_file(tmpfile.path(), &ck, &mk).unwrap();

        // flip one byte
        {
            let mut file = File::options()
                .read(true)
                .write(true)
                .open(tmpfile.path())
                .unwrap();
            let mut byte = [0u8; 1];
            file.seek(SeekFrom::Start(HEADER_LEN as u64 + 1)).unwrap();
            file.read_exact(&mut byte).unwrap();
            byte[0] ^= 0x55;
            file.seek(SeekFrom::Start(HEADER_LEN as u64 + 1)).unwrap();
            file.write_all(&byte).unwrap();
        }

        // decryption must fail
        let res = decrypt_file(tmpfile.path(), &ck, &mk);
        assert!(res.is_err());
        let _ = std::fs::remove_file("key.key");
    }

    #[test]
    fn large_roundtrip() {
        let mut data = vec![0u8; 2 * 1024 * 1024 + 3]; // ~2 MiB + 3 bytes
        OsRng.fill_bytes(&mut data);
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&data).unwrap();

        let (ck, mk) = write_random_key();
        encrypt_file(tmpfile.path(), &ck, &mk).unwrap();
        decrypt_file(tmpfile.path(), &ck, &mk).unwrap();

        let mut out = Vec::new();
        File::open(tmpfile.path()).unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(data, out);
        let _ = std::fs::remove_file("key.key");
    }
}
