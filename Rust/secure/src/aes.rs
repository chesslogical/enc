//! aes.rs – authenticated file encryption/decryption (AES‑256‑GCM‑SIV)
//!
//! Build & run:
//!   cargo run --release -- aes --encrypt file.txt
//!   cargo run --release -- aes --decrypt file.txt

#![cfg(feature = "aes")]
#![forbid(unsafe_code)]

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256GcmSiv,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, ValueEnum};
use filetime::FileTime;
use fs2::FileExt;
use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use zeroize::Zeroize;

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/* ------------------------------------------------------------------------- */

const KEY_FILE: &str = "key.key";
const HEADER: &[u8] = b"AESGCM-SIVv1";
const NONCE_LEN: usize = 12;

/* ------------------------------------------------------------------------- */

#[derive(Copy, Clone, ValueEnum)]
pub enum Force {
    Encrypt,
    Decrypt,
}

/// CLI for the `aes` sub‑command
#[derive(Args, Debug)]
#[command(
    about = "Encrypt or decrypt a file with AES‑256‑GCM‑SIV using key.key",
    group(
        clap::ArgGroup::new("mode")
            .args(["encrypt", "decrypt"])
            .multiple(false)
    )
)]
pub struct AesArgs {
    /// Force encryption even if the file *looks* already encrypted
    #[arg(long)]
    pub encrypt: bool,

    /// Force decryption even if the file *doesn't* look encrypted
    #[arg(long)]
    pub decrypt: bool,

    /// Target file
    pub file: PathBuf,

    /// Write output here instead of overwriting the input
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Copy, Clone)]
enum Mode {
    Encrypt,
    Decrypt,
}

/* ------------------------------------------------------------------------- */

pub fn run(opt: AesArgs) -> Result<()> {
    let path = &opt.file;

    /* ---------- pre‑flight checks ------------------------------------- */
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat '{}'", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to operate on a symlink: {}", path.display());
    }

    /* ---------- exclusive lock ---------------------------------------- */
    let mut locked = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open '{}'", path.display()))?;
    locked
        .try_lock_exclusive()
        .with_context(|| format!("failed to lock '{}'", path.display()))?;

    /* ---------- capture metadata we will restore ---------------------- */
    let orig_perm = meta.permissions();
    let orig_mtime = FileTime::from_last_modification_time(&meta);

    /* ---------- load entire file into RAM ----------------------------- */
    let mut data = Vec::new();
    locked
        .read_to_end(&mut data)
        .context("failed to read target file")?;

    /* ---------- decide mode ------------------------------------------- */
    let looks_enc = data.len() >= HEADER.len()
        && data[..HEADER.len()].ct_eq(HEADER).unwrap_u8() == 1;
    let mode = if opt.encrypt {
        Mode::Encrypt
    } else if opt.decrypt {
        Mode::Decrypt
    } else if looks_enc {
        Mode::Decrypt
    } else {
        Mode::Encrypt
    };

    /* ---------- obtain & zeroise key ---------------------------------- */
    let mut key_bytes = fs::read(KEY_FILE).context("failed to read key.key")?;
    if key_bytes.len() != 32 {
        bail!("{} must be exactly 32 bytes", KEY_FILE);
    }
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key_bytes));
    key_bytes.zeroize();

    /* ---------- create secure temp file ------------------------------- */
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = NamedTempFile::new_in(dir).context("failed to create temp file")?;

    #[cfg(unix)]
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("failed to set 0600 on temp file")?;

    /* ---------- encrypt OR decrypt ------------------------------------ */
    match mode {
        Mode::Decrypt => decrypt(&cipher, &data, &mut tmp)?,
        Mode::Encrypt => encrypt(&cipher, &data, looks_enc, &mut tmp, opt.encrypt)?,
    }

    tmp.as_file().sync_all()?; // durability

    /* ---------- atomically place result ------------------------------- */
    let out_path = opt.out.as_ref().unwrap_or(path);

    #[cfg(unix)]
    tmp.persist_overwrite(out_path)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    #[cfg(not(unix))]
    {
        let _ = fs::remove_file(out_path);
        tmp.persist(out_path)
            .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    }

    /* ---------- fsync & restore metadata ------------------------------ */
    OpenOptions::new().write(true).open(out_path)?.sync_all()?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;

    fs::set_permissions(out_path, orig_perm)?;
    filetime::set_file_mtime(out_path, orig_mtime)?;

    data.zeroize();

    println!(
        "✅ {} → {}",
        match mode {
            Mode::Encrypt => "Encrypted",
            Mode::Decrypt => "Decrypted",
        },
        out_path.display()
    );
    Ok(())
}

/* ------------------------------------------------------------------------- */

fn decrypt(cipher: &Aes256GcmSiv, data: &[u8], tmp: &mut NamedTempFile) -> Result<()> {
    if data.len() < HEADER.len() || data[..HEADER.len()].ct_eq(HEADER).unwrap_u8() == 0 {
        bail!("file is not in recognised encrypted format");
    }
    let body = &data[HEADER.len()..];
    if body.len() < NONCE_LEN {
        bail!("encrypted file is truncated");
    }
    let (nonce_bytes, ciphertext) = body.split_at(NONCE_LEN);
    let nonce = GenericArray::from_slice(nonce_bytes);

    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: HEADER,
            },
        )
        .map_err(|_| anyhow!("decryption failed – bad key or corrupted data"))?;
    tmp.write_all(&plaintext)?;
    plaintext.zeroize();
    Ok(())
}

fn encrypt(
    cipher: &Aes256GcmSiv,
    plaintext: &[u8],
    looks_enc: bool,
    tmp: &mut NamedTempFile,
    forced: bool,
) -> Result<()> {
    if looks_enc && !forced {
        bail!("file already appears encrypted – use --encrypt to force");
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: HEADER,
            },
        )
        .map_err(|e| anyhow!("encryption failed: {:?}", e))?;

    tmp.write_all(HEADER)?;
    tmp.write_all(&nonce_bytes)?;
    tmp.write_all(&ciphertext)?;

    nonce_bytes.zeroize();
    Ok(())
}
