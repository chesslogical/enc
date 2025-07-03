//! threefish‑cli – Threefish‑1024 + HMAC‑SHA‑256 file encryptor / decryptor
//!
//! © 2025  MIT License

/* -------------------------------------------------------------------------- */
/*                                DEPENDENCIES                                */
/* -------------------------------------------------------------------------- */

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::{NamedTempFile, TempPath};
use threefish::Threefish1024;
use zeroize::Zeroizing;

/* -------------------------------------------------------------------------- */
/*                                 CONSTANTS                                  */
/* -------------------------------------------------------------------------- */

const KEY_BYTES: usize = 160;          // 1024‑bit cipher key + 256‑bit MAC key
const HEADER_LEN_V2: usize = 24;
const MAC_LEN: usize = 32;

const BLOCK_SIZE: usize = 128;
const IO_BUF_SIZE: usize = 64 * 1024;  // 64 KiB buffer

const MAGIC: &[u8; 4] = b"T1FS";
const VERSION_V2: u8 = 2;

const CIPHER_ID_THREEFISH1024_STREAM: u8 = 0x01;
const MAC_ID_HMAC_SHA256: u8 = 0x01;

type HmacSha256 = Hmac<Sha256>;

/* -------------------------------------------------------------------------- */
/*                                  HEADER                                    */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Copy)]
struct HeaderV2 {
    magic:  [u8; 4],
    ver:    u8,
    cipher: u8,
    mac:    u8,
    pad:    u8,
    nonce:  [u8; 16],
}

impl HeaderV2 {
    fn new(nonce: [u8; 16]) -> Self {
        Self {
            magic: *MAGIC,
            ver: VERSION_V2,
            cipher: CIPHER_ID_THREEFISH1024_STREAM,
            mac: MAC_ID_HMAC_SHA256,
            pad: 0,
            nonce,
        }
    }

    fn to_bytes(&self) -> [u8; HEADER_LEN_V2] {
        let mut out = [0u8; HEADER_LEN_V2];
        out[0..4].copy_from_slice(&self.magic);
        out[4]  = self.ver;
        out[5]  = self.cipher;
        out[6]  = self.mac;
        out[7]  = self.pad;
        out[8..24].copy_from_slice(&self.nonce);
        out
    }
}

/* -------------------------------------------------------------------------- */
/*                                   CLI                                      */
/* -------------------------------------------------------------------------- */

/// File‑level encryptor / decryptor using Threefish‑1024 and HMAC‑SHA‑256.
///
/// If neither `--encrypt` nor `--decrypt` is supplied, the program inspects the
/// file header and decides automatically.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Path to the key file (default: key.key)
    #[arg(long, value_name = "FILE", default_value = "key.key")]
    key: PathBuf,

    /// Force encryption
    #[arg(short = 'e', long, conflicts_with = "decrypt")]
    encrypt: bool,

    /// Force decryption
    #[arg(short = 'd', long)]
    decrypt: bool,

    /// File to operate on
    file: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (cipher_key, mac_key) = load_keyfile(&cli.key)?;

    // ▸ Decide mode
    let mode = match (cli.encrypt, cli.decrypt) {
        (true, false) => Mode::Encrypt,
        (false, true) => Mode::Decrypt,
        _ => detect_mode(&cli.file)?,
    };

    process_file(&cli.file, mode, &cipher_key, &mac_key)?;
    println!("{} {}", match mode { Mode::Encrypt => "encrypted", Mode::Decrypt => "decrypted" }, cli.file.display());
    Ok(())
}

/* -------------------------------------------------------------------------- */
/*                              TOP‑LEVEL DISPATCH                            */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

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
/*                         AUTOMATIC MODE DETECTION                           */
/* -------------------------------------------------------------------------- */

fn detect_mode(path: &Path) -> Result<Mode> {
    let mut f = File::open(path).with_context(|| format!("open {:?}", path))?;
    if f.metadata()?.len() < (HEADER_LEN_V2 + MAC_LEN) as u64 {
        return Ok(Mode::Encrypt);                    // far too small to be ciphertext
    }
    let mut prefix = [0u8; 5];
    f.read_exact(&mut prefix)?;
    if &prefix[..4] == MAGIC && prefix[4] == VERSION_V2 {
        Ok(Mode::Decrypt)
    } else {
        Ok(Mode::Encrypt)
    }
}

/* -------------------------------------------------------------------------- */
/*                               KEY HANDLING                                 */
/* -------------------------------------------------------------------------- */

#[cfg(unix)]
fn check_keyfile_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o177 != 0 {
        return Err(anyhow!(
            "key file {:?} must not be accessible to group/others (mode {:o})",
            path,
            mode
        ));
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_keyfile_perms(_: &Path) -> Result<()> {
    Ok(())
}

fn load_keyfile(path: &Path) -> Result<(Zeroizing<[u8; 128]>, Zeroizing<[u8; 32]>)> {
    check_keyfile_perms(path)?;
    let mut buf = Zeroizing::new([0u8; KEY_BYTES]);
    File::open(path)
        .with_context(|| format!("open key file {:?}", path))?
        .read_exact(buf.as_mut())
        .with_context(|| format!("read key file {:?}", path))?;

    let mut cipher_key = Zeroizing::new([0u8; 128]);
    let mut mac_key = Zeroizing::new([0u8; 32]);
    cipher_key.copy_from_slice(&buf[..128]);
    mac_key.copy_from_slice(&buf[128..]);
    Ok((cipher_key, mac_key))
}

/* -------------------------------------------------------------------------- */
/*                            STREAM‑CIPHER STATE                             */
/* -------------------------------------------------------------------------- */

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

    fn xor_in_place(&mut self, mut data: &mut [u8]) {
        let mut keystream = Zeroizing::new([0u8; BLOCK_SIZE]);

        while !data.is_empty() {
            // ----- counter & overflow guard -----
            if self.block_idx == u64::MAX {
                panic!("stream‑cipher block counter exhausted");
            }
            let tweak = [self.nonce_hi, self.block_idx ^ self.nonce_lo];
            self.block_idx += 1;

            // ----- generate keystream for one block -----
            let mut block = [0u64; 16];          // fresh ZERO block each round
            let cipher = Threefish1024::new_with_tweak_u64(self.key64, &tweak);
            cipher.encrypt_block_u64(&mut block);
            for (i, w) in block.iter().enumerate() {
                keystream[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
            }

            // ----- XOR -----
            let n = data.len().min(BLOCK_SIZE);
            for (b, k) in data[..n].iter_mut().zip(&keystream[..n]) {
                *b ^= *k;
            }
            data = &mut data[n..];
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                               ENCRYPTION                                   */
/* -------------------------------------------------------------------------- */

fn encrypt_file(src: &Path, cipher_key: &[u8; 128], mac_key: &[u8; 32]) -> Result<()> {
    let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src)?);

    let tmp_file = NamedTempFile::new_in(
        src.parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp_file.reopen()?);

    /* header */
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let hdr = HeaderV2::new(nonce);
    let hdr_bytes = hdr.to_bytes();
    writer.write_all(&hdr_bytes)?;

    /* MAC initialisation */
    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&hdr_bytes);

    /* cipher init */
    let key64 = to_u64_key(cipher_key);
    let mut sc = StreamCipher::new(
        &key64,
        u64::from_be_bytes(nonce[..8].try_into().unwrap()),
        u64::from_be_bytes(nonce[8..].try_into().unwrap()),
    );

    /* streaming loop */
    let mut buf = Zeroizing::new([0u8; IO_BUF_SIZE]);
    loop {
        let n = reader.read(buf.as_mut())?;
        if n == 0 {
            break;
        }
        sc.xor_in_place(&mut buf[..n]);
        hmac.update(&buf[..n]);
        writer.write_all(&buf[..n])?;
    }

    /* MAC footer */
    writer.write_all(&hmac.finalize().into_bytes())?;
    writer.flush()?;
    writer.get_ref().sync_all()?;  // durable
    drop(writer);
    drop(reader);

    /* promote */
    let temp_path = tmp_file.into_temp_path();
    promote_atomically(temp_path, src)
}

/* -------------------------------------------------------------------------- */
/*                               DECRYPTION                                   */
/* -------------------------------------------------------------------------- */

fn decrypt_file(src: &Path, cipher_key: &[u8; 128], mac_key: &[u8; 32]) -> Result<()> {
    let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src)?);

    /* ---------- header ---------- */
    let mut header = [0u8; HEADER_LEN_V2];
    reader.read_exact(&mut header)?;

    if &header[..4] != MAGIC {
        return Err(anyhow!("bad magic bytes"));
    }
    if header[4] != VERSION_V2 {
        return Err(anyhow!("unsupported header version {}", header[4]));
    }
    if header[5] != CIPHER_ID_THREEFISH1024_STREAM || header[6] != MAC_ID_HMAC_SHA256 {
        return Err(anyhow!("unknown algorithm identifiers"));
    }
    if header[7] != 0 {
        return Err(anyhow!("non‑zero padding byte – file is corrupted"));
    }

    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&header[8..24]);

    /* ---------- MAC ---------- */
    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&header);

    /* ---------- cipher init ---------- */
    let key64 = to_u64_key(cipher_key);
    let mut sc = StreamCipher::new(
        &key64,
        u64::from_be_bytes(nonce[..8].try_into().unwrap()),
        u64::from_be_bytes(nonce[8..].try_into().unwrap()),
    );

    /* ---------- prepare temp plaintext ---------- */
    let tmp_file = NamedTempFile::new_in(
        src.parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp_file.reopen()?);

    /* ---------- ciphertext → MAC verify & decrypt ---------- */
    let file_len = reader.get_ref().metadata()?.len();
    let cipher_len = file_len
        .checked_sub((HEADER_LEN_V2 + MAC_LEN) as u64)
        .ok_or_else(|| anyhow!("file too small"))?;

    let mut remaining = cipher_len;
    let mut buf = Zeroizing::new([0u8; IO_BUF_SIZE]);

    while remaining != 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..n])?;
        hmac.update(&buf[..n]);
        sc.xor_in_place(&mut buf[..n]);
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }

    /* ---------- MAC footer ---------- */
    let mut mac_on_disk = [0u8; MAC_LEN];
    reader.read_exact(&mut mac_on_disk)?;
    hmac.verify_slice(&mac_on_disk)
        .map_err(|_| anyhow!("authentication failed"))?;

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    drop(reader);

    /* ---------- promote ---------- */
    let temp_path = tmp_file.into_temp_path();
    promote_atomically(temp_path, src)
}

/* -------------------------------------------------------------------------- */
/*                            ATOMIC PROMOTION                                */
/* -------------------------------------------------------------------------- */

/// Atomically replace `final_path` with `temp_path`, keeping a “*.bak” backup.
fn promote_atomically(temp_path: TempPath, final_path: &Path) -> Result<()> {
    let bak = final_path.with_extension("bak");
    let _ = fs::remove_file(&bak);
    fs::rename(final_path, &bak).ok(); // fine if original absent

    match temp_path.persist_noclobber(final_path) {
        Ok(_) => {
            let _ = fs::remove_file(&bak);
            Ok(())
        }
        Err(e) => {
            let _ = fs::rename(&bak, final_path); // rollback
            Err(e.error).context("failed to promote temp file")
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                   UTIL                                     */
/* -------------------------------------------------------------------------- */

fn to_u64_key(key: &[u8; 128]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, chunk) in key.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

/* -------------------------------------------------------------------------- */
/*                                   TESTS                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn random_key() -> ([u8; 128], [u8; 32]) {
        let mut k = [0u8; KEY_BYTES];
        OsRng.fill_bytes(&mut k);
        File::create("key.key").unwrap().write_all(&k).unwrap();
        let mut ck = [0u8; 128];
        let mut mk = [0u8; 32];
        ck.copy_from_slice(&k[..128]);
        mk.copy_from_slice(&k[128..]);
        (ck, mk)
    }

    #[test]
    fn small_roundtrip() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello").unwrap();
        let (ck, mk) = random_key();
        encrypt_file(f.path(), &ck, &mk).unwrap();
        decrypt_file(f.path(), &ck, &mk).unwrap();
        let mut v = Vec::<u8>::new();
        File::open(f.path()).unwrap().read_to_end(&mut v).unwrap();
        assert_eq!(v, b"hello");
        let _ = fs::remove_file("key.key");
    }

    #[test]
    fn mac_fail() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        let (ck, mk) = random_key();
        encrypt_file(f.path(), &ck, &mk).unwrap();

        // flip one byte in ciphertext
        let mut fh = File::options().read(true).write(true).open(f.path()).unwrap();
        fh.seek(SeekFrom::Start(HEADER_LEN_V2 as u64 + 1)).unwrap();
        let mut b = [0u8; 1];
        fh.read_exact(&mut b).unwrap();
        b[0] ^= 0x55;
        fh.seek(SeekFrom::Current(-1)).unwrap();
        fh.write_all(&b).unwrap();

        assert!(decrypt_file(f.path(), &ck, &mk).is_err());
        let _ = fs::remove_file("key.key");
    }

    #[test]
    fn counter_overflow_panics() {
        let key = [0u64; 16];
        let mut sc = super::StreamCipher::new(&key, 0, 0);
        sc.block_idx = u64::MAX;
        let mut data = [0u8; 1];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sc.xor_in_place(&mut data);
        }));
        assert!(result.is_err());
    }
}
