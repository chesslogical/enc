//! Threefish‑1024 + HMAC‑SHA‑256 CLI encryptor / decryptor.
//
//! • Key is a fixed‑size **160 byte** file (`key.key`) located in the working directory.
//!   − first 128 bytes → Threefish key
//!   − last  32 bytes → HMAC‑SHA‑256 key
//! • No pass‑phrase / KDF path is present in this build.
//! • Encryption mode: Threefish‑1024 used as a counter‑mode stream cipher
//!   with a 64‑bit random nonce.
//! • Authenticates header + ciphertext with HMAC‑SHA‑256
//!   (encrypt‑then‑MAC pattern).

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
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

/// Header (big‑endian, fixed size)
/// magic(4) | version(1) | cipher_id(1) | mac_id(1) | reserved(1)
/// | nonce(8) | reserved(32)
const MAGIC: &[u8; 4] = b"T1FS";
const VERSION: u8 = 1;
const CIPHER_ID_THREEFISH1024_STREAM: u8 = 0x01;
const MAC_ID_HMAC_SHA256: u8 = 0x01;

const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 8 + 32;
const MAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 128; // Threefish‑1024 block size in bytes

type HmacSha256 = Hmac<Sha256>;

/* -------------------------------------------------------------------------- */
/*                              CLI DEFINITION                                */
/* -------------------------------------------------------------------------- */

#[derive(Parser)]
#[command(author, version, about = "Threefish‑based file encryption")]
struct Cli {
    /// Path of the file to encrypt/decrypt
    path: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt file in‑place
    Encrypt,
    /// Decrypt file in‑place
    Decrypt,
}

/* -------------------------------------------------------------------------- */
/*                                   MAIN                                     */
/* -------------------------------------------------------------------------- */

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Always load "./key.key"
    let key_path = Path::new("key.key");
    let (cipher_key, mac_key) = load_keyfile(key_path)?;

    match cli.command {
        Commands::Encrypt => encrypt_file(&cli.path, &cipher_key, &mac_key),
        Commands::Decrypt => decrypt_file(&cli.path, &cipher_key, &mac_key),
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

fn encrypt_file<P: AsRef<Path>>(
    path: P,
    cipher_key: &[u8; 128],
    mac_key: &[u8; 32],
) -> Result<()> {
    let src_path = path.as_ref();
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

    // Atomic rename (Windows‑safe: remove old file first)
    drop(reader);
    let _ = fs::remove_file(src_path);
    fs::rename(tmp.path(), src_path)?;

    Ok(())
}

/* -------------------------------------------------------------------------- */
/*                               DECRYPTION                                   */
/* -------------------------------------------------------------------------- */

fn decrypt_file<P: AsRef<Path>>(
    path: P,
    cipher_key: &[u8; 128],
    mac_key: &[u8; 32],
) -> Result<()> {
    let src_path = path.as_ref();
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

    /* -------- 2. Verify MAC -------- */
    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&header);

    let mut remaining = ciphertext_len;
    let mut buf = [0u8; BLOCK_SIZE];
    while remaining != 0 {
        let chunk = remaining.min(BLOCK_SIZE as u64) as usize;
        reader.read_exact(&mut buf[..chunk])?;
        hmac.update(&buf[..chunk]);
        remaining -= chunk as u64;
    }
    let mut mac_on_disk = [0u8; MAC_LEN];
    reader.read_exact(&mut mac_on_disk)?;
    hmac.verify_slice(&mac_on_disk)
        .map_err(|_| anyhow!("authentication failed"))?;

    /* -------- 3. MAC OK → decrypt -------- */
    reader.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let tmp = NamedTempFile::new_in(
        src_path
            .parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::new(tmp.reopen()?);

    let key64 = to_u64_key(cipher_key);
    let mut block_idx = 0u64;
    let mut remaining = ciphertext_len;

    while remaining != 0 {
        let chunk = remaining.min(BLOCK_SIZE as u64) as usize;
        reader.read_exact(&mut buf[..chunk])?;
        xor_keystream(&mut buf[..chunk], &key64, nonce, block_idx);
        block_idx += 1;

        writer.write_all(&buf[..chunk])?;
        remaining -= chunk as u64;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;

    drop(reader);
    let _ = fs::remove_file(src_path);
    fs::rename(tmp.path(), src_path)?;

    Ok(())
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
    // bytes 16‑47 already zero (reserved)
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

/// XOR‑`buf` with keystream Threefish(key, tweak = [nonce, block_idx]).
fn xor_keystream(buf: &mut [u8], key64: &[u64; 16], nonce: u64, block_idx: u64) {
    let cipher = Threefish1024::new_with_tweak_u64(key64, &[nonce, block_idx]);
    let mut state = [0u64; 16];
    cipher.encrypt_block_u64(&mut state);

    // Flatten words to bytes and xor
    for (i, b) in buf.iter_mut().enumerate() {
        let word_bytes = state[i / 8].to_le_bytes();
        *b ^= word_bytes[i % 8];
    }
}

/* -------------------------------------------------------------------------- */
/*                                  TESTS                                     */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::io::Write;

    #[test]
    fn roundtrip_small() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(b"hello world").unwrap();

        // Generate random key & save as key.key
        let mut key = [0u8; KEY_BYTES];
        let mut rng = OsRng;
        rng.fill_bytes(&mut key);
        {
            let mut key_f = tempfile::NamedTempFile::new().unwrap();
            key_f.write_all(&key).unwrap();
            std::fs::copy(key_f.path(), "key.key").unwrap();
        }

        let (ck, mk) = load_keyfile(Path::new("key.key")).unwrap();
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
}
