
//! Threefish‑1024 + HMAC‑SHA‑256 CLI encryptor / decryptor
//!
//! • Keys are read from a 160 byte file called `key.key` in the current
//!   directory: the first 128 B for Threefish, the last 32 B for HMAC‑SHA‑256.
//! • Invoke as:   threefish_cli <FILE>
//!   If the file already carries the magic header it is decrypted;
//!   otherwise it is encrypted in place.

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
    env,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
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

/// Header (big‑endian, fixed size)
/// magic(4) | version(1) | cipher_id(1) | mac_id(1) | reserved(1)
/// | nonce(8) | reserved(32)
const MAGIC: &[u8; 4] = b"T1FS";
const VERSION: u8 = 1;
const CIPHER_ID_THREEFISH1024_STREAM: u8 = 0x01;
const MAC_ID_HMAC_SHA256: u8 = 0x01;

const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 8 + 32; // = 48
const MAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 128; // Threefish‑1024 block size in bytes

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
    /* -------- Parse command‑line -------- */
    let path: PathBuf = env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("usage: threefish_cli <FILE>"))?;

    /* -------- Load keyfile -------- */
    let (cipher_key, mac_key) = load_keyfile(Path::new("key.key"))?;

    /* -------- Decide mode -------- */
    let mode = detect_mode(&path)?;

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
/*                           AUTO‑DETECTION LOGIC                             */
/* -------------------------------------------------------------------------- */

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

/// Dispatch to the right routine.
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
/*                               ENCRYPTION                                   */
/* -------------------------------------------------------------------------- */

fn encrypt_file(
    src_path: &Path,
    cipher_key: &[u8; 128],
    mac_key: &[u8; 32],
) -> Result<()> {
    let mut reader = BufReader::new(File::open(src_path)?);

    // Write to temp file in same directory
    let tmp = NamedTempFile::new_in(
        src_path
            .parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::new(tmp.reopen()?);

    // Fresh nonce
    let mut rng = OsRng;
    let nonce = rng.next_u64();

    // Build & write header
    let header = build_header(nonce);
    writer.write_all(&header)?;

    // Prepare MAC
    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&header);

    let key64 = to_u64_key(cipher_key);
    let mut block_idx = 0u64;
    let mut buf = [0u8; BLOCK_SIZE];

    // Stream‑encrypt
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        xor_keystream(&mut buf[..read], &key64, nonce, block_idx);
        block_idx += 1;

        hmac.update(&buf[..read]);
        writer.write_all(&buf[..read])?;
    }

    // Finalise MAC and append
    writer.write_all(&hmac.finalize().into_bytes())?;
    writer.flush()?;
    writer.get_ref().sync_all()?; // durability

    /* ---------- Atomic replacement with backup ---------- */
    drop(reader);
    promote_with_backup(src_path, tmp.path())
}

/* -------------------------------------------------------------------------- */
/*                               DECRYPTION                                   */
/* -------------------------------------------------------------------------- */

fn decrypt_file(
    src_path: &Path,
    cipher_key: &[u8; 128],
    mac_key: &[u8; 32],
) -> Result<()> {
    let mut reader = BufReader::new(File::open(src_path)?);

    /* -------- 1. Parse header -------- */
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;
    validate_header(&header)?;

    let nonce = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let file_len = reader.get_ref().metadata()?.len();
    if file_len < HEADER_LEN as u64 + MAC_LEN as u64 {
        return Err(anyhow!("file too small"));
    }
    let ciphertext_len = file_len - HEADER_LEN as u64 - MAC_LEN as u64;

    /* -------- 2. Prepare for single‑pass MAC‑and‑decrypt -------- */
    let tmp = NamedTempFile::new_in(
        src_path
            .parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::new(tmp.reopen()?);

    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&header);

    let key64 = to_u64_key(cipher_key);
    let mut block_idx = 0u64;
    let mut remaining = ciphertext_len;
    let mut buf = [0u8; BLOCK_SIZE];

    /* -------- 3. MAC‑check and decrypt in one scan -------- */
    while remaining != 0 {
        let chunk = remaining.min(BLOCK_SIZE as u64) as usize;
        reader.read_exact(&mut buf[..chunk])?;
        hmac.update(&buf[..chunk]);

        xor_keystream(&mut buf[..chunk], &key64, nonce, block_idx);
        block_idx += 1;

        writer.write_all(&buf[..chunk])?;
        remaining -= chunk as u64;
    }

    /* -------- 4. Verify tag -------- */
    let mut mac_on_disk = [0u8; MAC_LEN];
    reader.read_exact(&mut mac_on_disk)?;
    hmac.verify_slice(&mac_on_disk)
        .map_err(|_| anyhow!("authentication failed"))?;

    writer.flush()?;
    writer.get_ref().sync_all()?;

    /* -------- 5. Promote tmp file, keeping backup -------- */
    drop(reader);
    promote_with_backup(src_path, tmp.path())
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

/// Build header bytes (big‑endian).
fn build_header(nonce: u64) -> [u8; HEADER_LEN] {
    let mut hdr = [0u8; HEADER_LEN];
    hdr[..4].copy_from_slice(MAGIC);             // magic
    hdr[4] = VERSION;                            // version
    hdr[5] = CIPHER_ID_THREEFISH1024_STREAM;     // cipher_id
    hdr[6] = MAC_ID_HMAC_SHA256;                 // mac_id
    hdr[7] = 0;                                  // reserved
    hdr[8..16].copy_from_slice(&nonce.to_be_bytes());
    // bytes 16‑47 already zero (reserved)
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
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

/// XOR `buf` with keystream Threefish(key, tweak = [nonce, block_idx]).
fn xor_keystream(buf: &mut [u8], key64: &[u64; 16], nonce: u64, block_idx: u64) {
    let cipher = Threefish1024::new_with_tweak_u64(key64, &[nonce, block_idx]);
    let mut state = [0u64; 16];
    cipher.encrypt_block_u64(&mut state);

    let mut ks = [0u8; BLOCK_SIZE];
    for (i, word) in state.iter().enumerate() {
        ks[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
}

/* -------------------------------------------------------------------------- */
/*                                  TESTS                                     */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::io::{Seek, SeekFrom, Write};

    /// Helper to write a random key to `key.key` in CWD.
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
        // encrypt
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
