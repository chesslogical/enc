//! dkey — deterministic cryptographic key generator

use std::{
    fs::File,
    io::{self, BufWriter, Write},
    process,
    time::Instant,
};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake3;
use clap::{Parser, ValueEnum};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Compile‑time default salt (change to reset the entire key universe)
const COMPILE_TIME_SALT: &[u8] = b"change-this-salt-to-change-key-universe";

const DEFAULT_ARGON2_MEMORY_KIB: u32 = 512 * 1024; // 512 MiB
const DEFAULT_ARGON2_TIME_COST: u32 = 10;
const DEFAULT_ARGON2_PARALLELISM: u32 = 1;

/// Output stream algorithm
#[derive(Copy, Clone, ValueEnum)]
enum StreamAlgo {
    Blake3,
    Chacha,
}

impl std::fmt::Display for StreamAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamAlgo::Blake3 => write!(f, "blake3"),
            StreamAlgo::Chacha => write!(f, "chacha"),
        }
    }
}

/// Command‑line interface
#[derive(Parser)]
#[command(
    author,
    version,
    about = "Deterministic high‑strength key generator",
    after_help = "Size suffixes: <n>[kb|mb|gb|kib|mib|gib] (case‑insensitive). \
                  Without a suffix, size is interpreted as raw bytes."
)]
struct Args {
    /// Key size (e.g. 10kb, 5mb, 1gb)
    size: String,

    /// Output file path
    #[arg(short, long, default_value = "key.key")]
    output: String,

    /// Output stream algorithm: blake3 (default) or chacha
    #[arg(short = 'a', long = "algo", value_enum, default_value_t = StreamAlgo::Blake3)]
    algo: StreamAlgo,

    /// Optional salt (base64). Omit to use the built‑in compile‑time salt.
    #[arg(short, long)]
    salt: Option<String>,

    /// Argon2 memory in KiB (default 524 288 = 512 MiB)
    #[arg(long, default_value_t = DEFAULT_ARGON2_MEMORY_KIB)]
    argon2_memory: u32,

    /// Argon2 time cost (default 10)
    #[arg(long, default_value_t = DEFAULT_ARGON2_TIME_COST)]
    argon2_time: u32,

    /// Argon2 parallelism (default 1)
    #[arg(long, default_value_t = DEFAULT_ARGON2_PARALLELISM)]
    argon2_par: u32,
}

/// Derive a 32‑byte deterministic seed from the password.
fn derive_seed(
    password: &Zeroizing<String>,
    salt_bytes: &[u8],
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    // Defensive limit (≤ 4 GiB) to prevent accidental DoS
    if mem > 4 * 1024 * 1024 {
        eprintln!(
            "❌ argon2-memory ({mem} KiB) exceeds safety limit (4 GiB). Refusing."
        );
        process::exit(1);
    }

    let params = Params::new(mem, time, par, None)
        .expect("Invalid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_bytes, &mut seed)
        .unwrap_or_else(|e| {
            eprintln!("❌ Argon2id hashing failed: {e}");
            process::exit(1);
        });
    seed
}

/// Write key material using BLAKE3 XOF
fn write_blake3(output: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
    stream_to_file(output, size, |buf| xof.fill(buf))
}

/// Write key material using ChaCha20Rng
fn write_chacha(output: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    stream_to_file(output, size, |buf| rng.fill_bytes(buf))
}

/// Helper: stream arbitrary generator into a file
fn stream_to_file<F>(path: &str, mut remaining: usize, mut fill: F) -> io::Result<()>
where
    F: FnMut(&mut [u8]),
{
    let mut buffer = [0u8; 8192];
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    while remaining != 0 {
        let chunk = remaining.min(buffer.len());
        fill(&mut buffer[..chunk]);
        writer.write_all(&buffer[..chunk])?;
        remaining -= chunk;
    }
    writer.flush()?;
    Ok(())
}

/// Parse human‑friendly sizes (e.g. 5mb → 5 000 000; 5MiB → 5 242 880)
fn parse_size(arg: &str) -> Option<usize> {
    let s = arg.trim().to_lowercase();
    let (num, mul) = if let Some(n) = s.strip_suffix("gib") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("mib") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("kib") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("gb") {
        (n, 1_000_000_000)
    } else if let Some(n) = s.strip_suffix("mb") {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix("kb") {
        (n, 1_000)
    } else {
        (s.as_str(), 1)
    };

    num.parse::<f64>()
        .ok()
        .map(|v| (v * mul as f64).round() as usize)
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    // --- size parsing -------------------------------------------------------
    let size = match parse_size(&args.size) {
        Some(s) if s > 0 => s,
        _ => {
            eprintln!("❌ Invalid size: '{}'", args.size);
            process::exit(1);
        }
    };

    // --- password input & confirmation -------------------------------------
    let pwd1: Zeroizing<String> =
        Zeroizing::new(prompt_password("🔐 Enter password: ")?);
    let pwd2: Zeroizing<String> =
        Zeroizing::new(prompt_password("🔐 Confirm password: ")?);

    if pwd1.as_bytes().ct_eq(pwd2.as_bytes()).unwrap_u8() == 0 {
        eprintln!("❌ Passwords do not match. Aborting.");
        process::exit(1);
    }

    // --- salt ---------------------------------------------------------------
    let salt_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        args.salt
            .as_deref()
            .map(|s| {
                B64.decode(s).unwrap_or_else(|_| {
                    eprintln!("❌ Salt is not valid base64");
                    process::exit(1);
                })
            })
            .unwrap_or_else(|| COMPILE_TIME_SALT.to_vec()),
    );

    // --- seed derivation ----------------------------------------------------
    println!(
        "📦 Generating {size} bytes with {} / Argon2id(mem={} KiB, t={}, p={})",
        args.algo, args.argon2_memory, args.argon2_time, args.argon2_par
    );

    let start = Instant::now();
    let mut seed = derive_seed(
        &pwd1,
        &salt_bytes,
        args.argon2_memory,
        args.argon2_time,
        args.argon2_par,
    );

    // --- stream key ---------------------------------------------------------
    let result = match args.algo {
        StreamAlgo::Blake3 => write_blake3(&args.output, &seed, size),
        StreamAlgo::Chacha => write_chacha(&args.output, &seed, size),
    };

    // --- clean up & exit ----------------------------------------------------
    seed.zeroize();
    result?;

    println!("✅ Key written to '{}' in {:.2?}", args.output, start.elapsed());
    Ok(())
}
