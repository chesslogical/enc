#![forbid(unsafe_code)]

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    Aes256GcmSiv,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use filetime::FileTime;
use fs2::FileExt;
use subtle::ConstantTimeEq;
use tempfile::NamedTempFile;
use zeroize::Zeroize;

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const KEY_FILE: &str = "key.key";
const HEADER: &[u8] = b"AESGCM-SIVv1";
const NONCE_LEN: usize = 12;

#[derive(Parser)]
#[command(author, version, about, disable_help_subcommand = true)]
struct Opts {
    /// Force encryption (overrides auto‑detection)
    #[arg(long, conflicts_with = "decrypt")]
    encrypt: bool,

    /// Force decryption (overrides auto‑detection)
    #[arg(long, conflicts_with = "encrypt")]
    decrypt: bool,

    /// Target file
    file: PathBuf,

    /// Write output to this path instead of overwriting the input
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Copy, Clone)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn main() -> Result<()> {
    let opt = Opts::parse();
    let path = &opt.file;

    // decide mode ------------------------------------------------------------
    let mut mode = if opt.encrypt {
        Mode::Encrypt
    } else if opt.decrypt {
        Mode::Decrypt
    } else {
        // auto, decide later once we've read the file
        Mode::Encrypt /* placeholder */
    };

    // --- sanity checks ------------------------------------------------------
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat '{}'", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("refusing to operate on a symlink: {}", path.display());
    }

    // --- exclusive lock -----------------------------------------------------
    let mut locked = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open '{}'", path.display()))?;
    locked
        .try_lock_exclusive()
        .with_context(|| format!("failed to lock '{}'", path.display()))?;

    // snapshot metadata we want to restore later
    let orig_perm = meta.permissions();
    let orig_mtime = FileTime::from_last_modification_time(&meta);

    // read full file (streaming variant omitted for brevity)
    let mut data = Vec::new();
    locked
        .read_to_end(&mut data)
        .context("failed to read target file")?;

    // auto‑detect if neither flag supplied
    if !opt.encrypt && !opt.decrypt {
        let looks_encrypted = data.len() >= HEADER.len()
            && data[..HEADER.len()].ct_eq(HEADER).unwrap_u8() == 1;
        mode = if looks_encrypted {
            Mode::Decrypt
        } else {
            Mode::Encrypt
        };
    }

    // --- load & wipe key ----------------------------------------------------
    let mut key_bytes = fs::read(KEY_FILE).context("failed to read key.key")?;
    if key_bytes.len() != 32 {
        bail!("{} must be exactly 32 bytes", KEY_FILE);
    }
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key_bytes));
    key_bytes.zeroize();

    // --- temp output file ---------------------------------------------------
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = NamedTempFile::new_in(dir).context("failed to create temp file")?;

    #[cfg(unix)]
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("failed to set 0600 on temp file")?;

    // --- encrypt OR decrypt -------------------------------------------------
    match mode {
        Mode::Decrypt => {
            // integrity check
            if data.len() < HEADER.len()
                || data[..HEADER.len()].ct_eq(HEADER).unwrap_u8() == 0
            {
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
        }
        Mode::Encrypt => {
            // refuse to double‑encrypt
            if data.len() >= HEADER.len()
                && data[..HEADER.len()].ct_eq(HEADER).unwrap_u8() == 1
                && !opt.encrypt
            {
                bail!("file already appears to be encrypted – use --encrypt to force");
            }

            let plaintext = &data;
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
        }
    }

    tmp.as_file().sync_all()?; // durability: flush temp file

    // where to place the completed file
    let out_path = opt.out.as_ref().unwrap_or(path);

    // atomic rename
    #[cfg(unix)]
    tmp.persist_overwrite(out_path)
        .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    #[cfg(not(unix))]
    {
        let _ = fs::remove_file(out_path);
        tmp.persist(out_path)
            .with_context(|| format!("failed to write '{}'", out_path.display()))?;
    }

    // fsync the new file (needs write handle on Windows)
    OpenOptions::new()
        .write(true)
        .open(out_path)?
        .sync_all()?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;

    // restore original permissions / mtime
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
