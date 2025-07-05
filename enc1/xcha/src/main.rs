//! xcha – in‑place XChaCha20‑Poly1305 file encryptor/decryptor
//! Build with: `cargo build --release`

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use clap::Parser;
use rand_core::RngCore;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// 4‑byte ASCII magic (includes version = 1)
const MAGIC: &[u8; 4] = b"XCP1";
/// MAGIC (4) + nonce (24) = 28
const HEADER_LEN: usize = MAGIC.len() + 24;
/// Poly1305 tag size is a fixed 16 bytes.
const TAG_LEN: usize = 16;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Target file as a positional argument.
    /// e.g. `xcp secret.pdf`
    #[arg(value_name = "FILE", conflicts_with = "flag_file")]
    file: Option<PathBuf>,

    /// Same parameter but as a flag for scriptability.
    /// e.g. `xcp -f secret.pdf`
    #[arg(short = 'f', long = "file", value_name = "FILE", conflicts_with = "file")]
    flag_file: Option<PathBuf>,
}

/// Load a 32‑byte key from `key.key` in the same directory as `target`.
fn load_key(dir: &Path) -> Result<chacha20poly1305::Key> {
    let key_path = dir.join("key.key");
    let mut key_bytes =
        fs::read(&key_path).with_context(|| format!("reading key file {}", key_path.display()))?;
    if key_bytes.len() != 32 {
        bail!("key.key must be exactly 32 bytes (found {})", key_bytes.len());
    }
    let key = chacha20poly1305::Key::from_slice(&key_bytes).to_owned();
    key_bytes.zeroize(); // wipe plaintext key material
    Ok(key)
}

/// True if `buf` begins with the magic header.
fn file_is_encrypted(buf: &[u8]) -> bool {
    buf.starts_with(MAGIC)
}

/// Encrypt `in_data` and return header + ciphertext.
fn encrypt(in_data: &[u8], cipher: &XChaCha20Poly1305) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

    let mut out =
        Vec::with_capacity(HEADER_LEN + in_data.len() + TAG_LEN); // pre‑size buffer

    // header = magic || nonce
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);

    // AAD is the header itself
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: in_data,
                aad: &out[..HEADER_LEN],
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;

    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt buffer that must begin with the header.
fn decrypt(buf: &[u8], cipher: &XChaCha20Poly1305) -> Result<Vec<u8>> {
    if buf.len() < HEADER_LEN + TAG_LEN {
        bail!("ciphertext too short");
    }
    if !file_is_encrypted(buf) {
        bail!("missing magic header");
    }

    let nonce_bytes = &buf[MAGIC.len()..HEADER_LEN];
    let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);

    let aad = &buf[..HEADER_LEN];
    let ciphertext = &buf[HEADER_LEN..];

    cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload { msg: ciphertext, aad },
        )
        .map_err(|_| anyhow!("decryption failed (wrong key or data corrupted)"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Determine which path was supplied (positional or flag)
    let file_path = match cli.file.or(cli.flag_file) {
        Some(p) => p,
        None => {
            eprint!("Enter path: ");
            io::stdout().flush()?;
            let mut s = String::new();
            io::stdin().read_line(&mut s)?;
            PathBuf::from(s.trim())
        }
    };

    let abs_path =
        fs::canonicalize(&file_path).with_context(|| format!("locating {}", file_path.display()))?;
    let parent = abs_path
        .parent()
        .context("cannot determine parent directory")?;

    // Initialise cipher
    let key = load_key(parent)?;
    let cipher = XChaCha20Poly1305::new(&key);

    // Read entire file (use streaming for multi‑GB files)
    let in_data = fs::read(&abs_path).with_context(|| format!("reading {}", abs_path.display()))?;

    let out_data = if file_is_encrypted(&in_data) {
        println!("🔓  Decrypting '{}'", abs_path.display());
        decrypt(&in_data, &cipher)?
    } else {
        println!("🔐  Encrypting '{}'", abs_path.display());
        encrypt(&in_data, &cipher)?
    };

    // Atomic replace: write to temp, then rename
    let tmp_path = abs_path.with_extension("xcp_tmp");
    {
        let mut tmp =
            File::create(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
        tmp.write_all(&out_data)
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        tmp.sync_all()?;
    }
    fs::rename(&tmp_path, &abs_path)
        .with_context(|| format!("replacing {}", abs_path.display()))?;

    println!("✅  Done.");
    Ok(())
}
