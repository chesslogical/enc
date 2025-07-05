//! Hardened one‑time‑pad XOR transformer with crash‑safe, atomic
//! replacement and optional post‑write verification / xattr copy.
//!
//! Build examples
//! --------------
//!   cargo build --release                          # base binary
//!   cargo build --release --features verify        # + SHA‑256 verify pass
//!   cargo build --release --features "verify xattrs"   # + verify & xattrs

use clap::Parser;
use std::{
    fs,
    io::{self, Read, Write, BufReader, BufWriter},
    path::{Path, PathBuf},
    time::Instant,
};

use fs2::FileExt;
use tempfile::Builder;
use zeroize::Zeroize;

#[cfg(feature = "verify")]
use sha2::{Digest, Sha256};

const BUF_CAP: usize = 64 * 1024; // 64 KiB working buffers

// ─────────────────────────── CLI ────────────────────────────────
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// File to encrypt / decrypt in place
    input: PathBuf,

    /// One‑time‑pad key file (defaults to key.key or $OTP_KEY)
    #[arg(short, long)]
    key: Option<PathBuf>,

    /// Require key and data to be exactly the same length (OTP discipline).
    /// Disabled by default; enable with --strict-len for maximum safety.
    #[arg(long)]
    strict_len: bool,

    /// Print SHA‑256 of output and compare to EXPECT (hex)
    #[cfg(feature = "verify")]
    #[arg(long)]
    expect: Option<String>,
}

fn main() -> io::Result<()> {
    let started = Instant::now();
    let args = Args::parse();

    // ── Resolve paths ──────────────────────────────────────────
    let input_path = args.input;
    let key_path: PathBuf = args
        .key
        .or_else(|| std::env::var_os("OTP_KEY").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("key.key"));

    // ── Pre‑flight checks ─────────────────────────────────────
    let src_meta = fs::metadata(&input_path)?;
    let key_len  = fs::metadata(&key_path)?.len();
    let data_len = src_meta.len();

    // 1. Refuse if key is shorter than data – always fatal
    if key_len < data_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Key is shorter ({key_len} B) than data ({data_len} B)"
            ),
        ));
    }

    // 2. Optional strict equality check (opt‑in)
    if args.strict_len && key_len != data_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Strict mode: key length must equal data length \
                (key {key_len} B, data {data_len} B)"
            ),
        ));
    }

    // ── Create a temp file beside the source for atomic replace ──
    let tmp = Builder::new()
        .prefix(".enc_tmp.")
        .tempfile_in(input_path.parent().unwrap_or(Path::new(".")))?;
    let tmp_handle = tmp.reopen()?;
    fs::set_permissions(tmp.path(), src_meta.permissions())?;

    // ── All heavy I/O in its own scope so every handle is dropped
    //    before we attempt the Windows rename.                  ──
    {
        // --- Exclusive lock on source so no other process touches it -----
        let src_file = fs::OpenOptions::new().read(true).open(&input_path)?;
        src_file.lock_exclusive()?;           // unlocks on drop below

        // Buffered reader for data (we will zero its scratch manually)
        let mut data = BufReader::with_capacity(BUF_CAP, &src_file);

        // Unbuffered key file – avoids lingering plaintext in internal buf
        let mut key_file = fs::OpenOptions::new().read(true).open(&key_path)?;

        // Buffered writer for tmp
        let mut out = BufWriter::with_capacity(BUF_CAP, &tmp_handle);

        // Scratch buffers
        let mut data_buf = [0u8; BUF_CAP];
        let mut key_buf  = [0u8; BUF_CAP];

        loop {
            let n = data.read(&mut data_buf)?;
            if n == 0 { break; } // EOF

            key_file.read_exact(&mut key_buf[..n])?;
            for (d, k) in data_buf[..n].iter_mut().zip(&key_buf[..n]) {
                *d ^= *k;
            }
            out.write_all(&data_buf[..n])?;

            // Scrub sensitive material
            data_buf[..n].zeroize();
            key_buf[..n].zeroize();
        }

        // --- Durability for data blocks ----------------------------------
        out.flush()?;
        tmp_handle.sync_all()?;   // ensure tmp data on disk
    } //  <-- src_file, data, key_file, out all dropped here

    // ── Windows rename needs destination write‑permission  ──────────────
    #[cfg(windows)]
    {
        let mut perms = fs::metadata(&input_path)?.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            fs::set_permissions(&input_path, perms)?;
        }
    }

    // ── Atomic replace ---------------------------------------------------
    tmp.persist(&input_path)?;

    // ── Fsync parent directory so the rename is durable (best‑effort) ───
    if let Ok(dir) = fs::File::open(input_path.parent().unwrap()) {
        let _ = dir.sync_all();
    }

    // ── Restore timestamps (+ optional xattrs) on Unix ──────────────────
    #[cfg(unix)]
    {
        use filetime::{set_file_times, FileTime};
        let atime = FileTime::from_last_access_time(&src_meta);
        let mtime = FileTime::from_last_modification_time(&src_meta);
        set_file_times(&input_path, atime, mtime)?;

        #[cfg(feature = "xattrs")]
        {
            for attr in xattr::list(&key_path)? {
                if let Some(val) = xattr::get(&key_path, &attr)? {
                    xattr::set(&input_path, &attr, &val)?;
                }
            }
        }
    }

    // ── Optional verification pass ──────────────────────────────────────
    #[cfg(feature = "verify")]
    {
        let mut f       = fs::File::open(&input_path)?;
        let mut hasher  = Sha256::new();
        let mut buf     = [0u8; BUF_CAP];

        loop {
            let m = f.read(&mut buf)?;
            if m == 0 { break; }
            hasher.update(&buf[..m]);
        }
        let digest = format!("{:x}", hasher.finalize());

        if let Some(expected) = args.expect {
            if digest != expected.to_lowercase() {
                eprintln!("❌ SHA‑256 mismatch! expected {expected}, got {digest}");
                std::process::exit(1);
            }
            eprintln!("✓ SHA‑256 verified");
        } else {
            eprintln!("SHA‑256(output) = {digest}");
        }
    }

    eprintln!("✓ done in {:.2?}", started.elapsed());
    Ok(())
}
