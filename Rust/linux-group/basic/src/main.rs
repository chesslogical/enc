use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tempfile::NamedTempFile;
use zeroize::Zeroize; // Securely wipe temporary buffers on drop

/// Default streaming chunk (1 MiB).  Tune if desired.
const CHUNK_SIZE: usize = 1 * 1024 * 1024;

/// XOR a file with `key.key` located in the same directory.
///
/// Encryption ⟺ decryption (XOR is its own inverse).
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// File to encrypt / decrypt.
    input: PathBuf,

    /// Optional output path.  Defaults to <input>.xor (or .plain with --reverse).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Treat operation as “decrypt” – only affects default extension.
    #[arg(long)]
    reverse: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // ---------- Locate input & key ----------
    let input_path = cli
        .input
        .canonicalize()
        .with_context(|| format!("Input file {:?} not found", cli.input))?;

    let dir = input_path
        .parent()
        .context("Cannot determine input directory")?;

    let key_path = dir.join("key.key");
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

    // ---------- Determine output path ----------
    let output_path = cli.output.unwrap_or_else(|| {
        let mut p = input_path.clone();
        p.set_extension(if cli.reverse { "plain" } else { "xor" });
        p
    });
    if output_path.exists() {
        bail!("Refusing to overwrite existing file {:?}", output_path);
    }

    // ---------- Stream‑process ----------
    let mut in_file = BufReader::with_capacity(CHUNK_SIZE, File::open(&input_path)?);
    let mut key_file = BufReader::with_capacity(CHUNK_SIZE, File::open(&key_path)?);

    // Write to temp file in the same dir for atomicity.
    let mut tmp = NamedTempFile::new_in(dir)?;
    {
        let mut out_file = BufWriter::with_capacity(CHUNK_SIZE, tmp.as_file_mut());

        // Re‑usable buffers
        let mut data_buf = vec![0u8; CHUNK_SIZE];
        let mut key_buf = vec![0u8; CHUNK_SIZE];

        loop {
            let read_bytes = in_file.read(&mut data_buf)?;
            if read_bytes == 0 {
                break;
            }
            key_file.read_exact(&mut key_buf[..read_bytes])?;

            // XOR in‑place
            for i in 0..read_bytes {
                data_buf[i] ^= key_buf[i];
            }

            out_file.write_all(&data_buf[..read_bytes])?;
        }
        out_file.flush()?;          // flush kernel buffers
    }
    tmp.as_file().sync_all()?;      // fsync for durability
    tmp.persist(&output_path)?;     // atomic rename

    // Zeroise sensitive buffers
    // (not strictly needed thanks to scope drop, but explicit is safer)
    // data_buf and key_buf are dropped here and wiped by zeroize.

    println!("✅ Wrote XORed data to: {}", output_path.display());
    Ok(())
}

