
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tempfile::{Builder, NamedTempFile};
use zeroize::Zeroize;

/// Process in 1 MiB blocks.
const CHUNK_SIZE: usize = 1 * 1024 * 1024;

/// XOR‑encipher/decipher a file **in place** on Linux, using a key file
/// called `key.key` (or another path supplied with `--key`).
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// File to overwrite atomically.
    input: PathBuf,

    /// Optional key file path (defaults to <dir>/key.key).
    #[arg(short, long)]
    key: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // ---------- Resolve paths ----------
    let input_path = cli
        .input
        .canonicalize()
        .with_context(|| format!("Input file {:?} not found", cli.input))?;
    let dir = input_path
        .parent()
        .context("Cannot determine input directory")?;

    let key_path = cli
        .key
        .map(|k| dir.join(k))
        .unwrap_or_else(|| dir.join("key.key"));

    if !key_path.is_file() {
        bail!("Key file {:?} not found", key_path);
    }

    // ---------- Validate key length ----------
    let key_len = key_path.metadata()?.len();
    let input_len = input_path.metadata()?.len();
    if key_len < input_len {
        bail!(
            "Key too short: {} bytes < payload {} bytes (OTP security requires ≥).",
            key_len,
            input_len
        );
    }

    // Preserve original mode bits (ownership may change to current user).
    let orig_mode = input_path.metadata()?.permissions().mode() & 0o777;

    // ---------- Create temp file in same directory ----------
    let mut tmp: NamedTempFile = Builder::new()
        .prefix(".xorpad.tmp.")
        .rand_bytes(6)
        .tempfile_in(dir)
        .context("Failed to create temporary file")?;

    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(orig_mode))?;

    // ---------- Stream‑XOR ----------
    let mut in_file = BufReader::with_capacity(CHUNK_SIZE, File::open(&input_path)?);
    let mut key_file = BufReader::with_capacity(CHUNK_SIZE, File::open(&key_path)?);

    {
        let mut out_file = BufWriter::with_capacity(CHUNK_SIZE, tmp.as_file_mut());

        let mut data_buf = vec![0u8; CHUNK_SIZE];
        let mut key_buf = vec![0u8; CHUNK_SIZE];

        loop {
            let read_bytes = in_file.read(&mut data_buf)?;
            if read_bytes == 0 {
                break;
            }
            key_file.read_exact(&mut key_buf[..read_bytes])?;

            for i in 0..read_bytes {
                data_buf[i] ^= key_buf[i];
            }

            out_file.write_all(&data_buf[..read_bytes])?;
        }
        out_file.flush()?;

        // Wipe sensitive data before drop
        data_buf.zeroize();
        key_buf.zeroize();
    }

    // ---------- Durability & atomic replace ----------
    tmp.as_file().sync_all()?;            // 1) flush temp data to disk
    let tmp_path = tmp.into_temp_path();  // detach so Drop won't delete too early
    std::fs::rename(&tmp_path, &input_path)?; // 2) atomic rename
    File::open(dir)?.sync_all()?;         // 3) flush directory entry
    // tmp_path now refers to a non‑existent file and will do nothing on Drop.

    println!("✅ Overwrote in place: {}", input_path.display());
    Ok(())
}

