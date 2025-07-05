//! votp 2.0 – versatile one‑time‑pad XOR transformer
//!            + deterministic key generator (`--features keygen`)

#![cfg_attr(docsrs, feature(doc_cfg))]

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    time::Instant,
};
use tempfile::Builder;
use zeroize::Zeroize;

#[cfg(feature = "verify")]
use atty;
#[cfg(feature = "verify")]
use sha2::{Digest, Sha256};

#[cfg(unix)]
use filetime::{set_file_times, FileTime};

#[cfg(feature = "keygen")]
mod key;                         // the new key generator module (src/key.rs)

const BUF_CAP: usize = 64 * 1024; // 64 KiB streaming buffers
const TMP_PREFIX: &str = ".votp-tmp-";

/* ─────────────────────────────── CLI ──────────────────────────────────── */

#[derive(Subcommand, Debug)]
enum Command {
    /// One‑time‑pad XOR transform (default when no sub‑command is given)
    #[command(name = "xor", alias = "enc")]
    Xor(XorArgs),

    /// Deterministic key generator (requires `--features keygen`)
    #[cfg(feature = "keygen")]
    Keygen(key::KeyArgs),
}

#[derive(Parser, Debug)]
#[command(author, version, about, disable_help_subcommand = true)]
struct Cli {
    /// Optional sub‑command; if omitted we treat arguments as `xor` flags.
    #[command(subcommand)]
    cmd: Option<Command>,
}

/// Flags for the XOR transformer (identical to the original tool)
#[derive(Parser, Debug)]
struct XorArgs {
    /// Input file (use '-' for STDIN; '--in-place' forbidden with STDIN)
    #[arg(short, long)]
    input: PathBuf,

    /// Key file (falls back to $OTP_KEY, then 'key.key')
    #[arg(short, long)]
    key: Option<PathBuf>,

    /// Output file (use '-' for STDOUT). Ignored with --in-place.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Encrypt/decrypt in place (atomic replace of INPUT)
    #[arg(long, conflicts_with = "output")]
    in_place: bool,

    /// Require key length ≥ data length (refuse short‑key mode)
    #[arg(long, conflicts_with = "strict_len")]
    min_len: bool,

    /// Require key length == data length (classical OTP discipline)
    #[arg(long)]
    strict_len: bool,

    /// Print SHA‑256 of result or compare to EXPECT (needs --features verify)
    #[cfg(feature = "verify")]
    #[arg(long)]
    expect: Option<String>,
}

/* ───────────────────────────── main() ─────────────────────────────────── */

fn main() -> Result<()> {
    // If the first non‑binary argument is a known sub‑command, delegate to it;
    // otherwise we keep full backwards compatibility with the old flat XOR CLI.
    let first_non_bin = std::env::args().nth(1);
    let looks_like_sub = matches!(
        first_non_bin.as_deref(),
        Some("xor") | Some("keygen")
    );

    if looks_like_sub {
        let cli = Cli::parse();
        match cli.cmd.expect("sub‑command is present") {
            Command::Xor(args) => run_xor(args),
            #[cfg(feature = "keygen")]
            Command::Keygen(kargs) => key::run(kargs).map_err(|e| anyhow!(e)),
        }
    } else {
        let args = XorArgs::parse();
        run_xor(args)
    }
}

/* ─────────────────── One‑Time‑Pad transformer (XOR) ───────────────────── */

fn run_xor(args: XorArgs) -> Result<()> {
    let t0 = Instant::now();

    /* -------- resolve key path ----------------------------------------- */
    let key_path = args
        .key
        .or_else(|| std::env::var_os("OTP_KEY").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("key.key"));

    /* -------- source metadata (skip for STDIN) -------------------------- */
    let (data_len, src_meta_opt) = if args.input == PathBuf::from("-") {
        (0, None) // length unknown – cannot enforce min/strict checks
    } else {
        let m = fs::metadata(&args.input)
            .with_context(|| format!("reading metadata for '{}'", args.input.display()))?;
        (m.len(), Some(m))
    };

    /* -------- key length checks ---------------------------------------- */
    let key_len = fs::metadata(&key_path)
        .with_context(|| format!("reading metadata for key '{}'", key_path.display()))?
        .len();

    if data_len != 0 && args.strict_len && key_len != data_len {
        bail!(
            "--strict-len: key length {} ≠ data length {}",
            key_len,
            data_len
        );
    }
    if data_len != 0 && args.min_len && key_len < data_len {
        bail!(
            "--min-len: key length {} < data length {}",
            key_len,
            data_len
        );
    }

    /* -------- prepare streams ------------------------------------------ */

    // Key reader
    let mut key_file = File::open(&key_path)
        .with_context(|| format!("opening key '{}'", key_path.display()))?;

    // Writer (tmp file when --in-place)
    let (mut writer, tmp_path): (Box<dyn Write>, Option<PathBuf>) = if args.in_place {
        if args.input == PathBuf::from("-") {
            bail!("--in-place cannot be used with STDIN");
        }
        let dir = args
            .input
            .parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory of input"))?;
        let tmp = Builder::new()
            .prefix(TMP_PREFIX)
            .tempfile_in(dir)
            .context("creating temporary file")?;

        if let Some(ref meta) = src_meta_opt {
            fs::set_permissions(tmp.path(), meta.permissions())
                .context("copying permissions to temp file")?;
        }

        let (handle, path) = tmp.keep().context("persisting temporary file")?;
        (Box::new(handle), Some(path))
    } else {
        let out_path = args
            .output
            .clone()
            .ok_or_else(|| anyhow!("--output or --in-place must be supplied"))?;
        if out_path == PathBuf::from("-") {
            (Box::new(std::io::stdout().lock()), None)
        } else {
            let f = File::create(&out_path)
                .with_context(|| format!("creating output '{}'", out_path.display()))?;
            (Box::new(f), None)
        }
    };

    // Reader (stdin or file)
    let mut reader: Box<dyn Read> = if args.input == PathBuf::from("-") {
        Box::new(std::io::stdin().lock())
    } else {
        let f = OpenOptions::new()
            .read(true)
            .open(&args.input)
            .with_context(|| format!("opening input '{}'", args.input.display()))?;
        f.lock_exclusive()
            .with_context(|| "locking input file for exclusive access")?;
        Box::new(f)
    };

    /* -------- streaming XOR loop --------------------------------------- */

    let mut data_buf = vec![0u8; BUF_CAP];
    let mut key_buf  = vec![0u8; BUF_CAP];

    #[cfg(feature = "verify")]
    let mut hasher_opt = if args.expect.is_some() {
        Some(Sha256::new())
    } else {
        None
    };

    loop {
        let n = reader.read(&mut data_buf)?;
        if n == 0 {
            break;
        }
        fill_key_slice(&mut key_file, &mut key_buf[..n])?;
        for (d, k) in data_buf[..n].iter_mut().zip(&key_buf[..n]) {
            *d ^= *k;
        }

        #[cfg(feature = "verify")]
        if let Some(ref mut h) = hasher_opt {
            h.update(&data_buf[..n]);     // hash in‑flight (no 2nd disk pass)
        }

        writer.write_all(&data_buf[..n])?;
        data_buf[..n].zeroize();
        key_buf[..n].zeroize();
    }
    writer.flush()?;

    /* -------- durability fences & in‑place swap ------------------------ */
    if let Some(ref tmp) = tmp_path {
        let f = OpenOptions::new().write(true).open(tmp)?;
        f.sync_all()?;
        if let Some(parent) = tmp.parent() {
            if let Ok(d) = File::open(parent) {
                let _ = d.sync_all(); // best‑effort dir fsync
            }
        }

        #[cfg(windows)]
        {
            let mut perms = fs::metadata(&args.input)?.permissions();
            if perms.readonly() {
                perms.set_readonly(false);
                fs::set_permissions(&args.input, perms)?;
            }
        }
        fs::rename(&tmp, &args.input).context("atomic rename failed")?;

        #[cfg(unix)]
        {
            if let Some(src_meta) = src_meta_opt {
                let atime = FileTime::from_last_access_time(&src_meta);
                let mtime = FileTime::from_last_modification_time(&src_meta);
                set_file_times(&args.input, atime, mtime)
                    .context("restoring timestamps")?;
            }

            #[cfg(feature = "xattrs")]
            for attr in xattr::list(&key_path).unwrap_or_default() {
                if let Some(val) = xattr::get(&key_path, &attr).unwrap_or(None) {
                    let _ = xattr::set(&args.input, &attr, &val);
                }
            }
        }
    }

    /* -------- optional SHA‑256 verification ---------------------------- */
    #[cfg(feature = "verify")]
    if let Some(hasher) = hasher_opt {
        let digest = format!("{:x}", hasher.finalize());

        match args.expect {
            Some(expected) => {
                if digest.to_lowercase() != expected.to_lowercase() {
                    bail!("SHA‑256 mismatch! expected {expected}, got {digest}");
                }
                eprintln!("✓ SHA‑256 verified");
            }
            None => {
                if atty::is(atty::Stream::Stderr) {
                    eprintln!("SHA‑256(output) = {digest}");
                }
            }
        }
    }

    eprintln!("✓ done in {:.2?}", t0.elapsed());
    Ok(())
}

/* ───────────────────────────── Helpers ─────────────────────────────────── */

/// Fill `dest` completely with bytes from `key`, rewinding on EOF.
fn fill_key_slice<R: Read + Seek>(key: &mut R, dest: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < dest.len() {
        let n = key.read(&mut dest[filled..])?;
        if n == 0 {
            key.seek(SeekFrom::Start(0))?;
            continue;
        }
        filled += n;
    }
    Ok(())
}

