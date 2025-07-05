//! key.rs – deterministic high‑strength key material generator
//!
//! Build (stand‑alone):
//!   cargo run --release --features keygen -- keygen 10MiB my.key
//! 
//! Integrated with votp’s CLI as the `keygen` sub‑command.

#![cfg(feature = "keygen")]

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
use clap::{Args, ValueEnum};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rpassword::prompt_password;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const COMPILE_TIME_SALT: &[u8] = b"change-this-salt-to-change-key-universe";
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 512 * 1024; // 512 MiB
const DEFAULT_ARGON2_TIME_COST:  u32 = 10;
const DEFAULT_ARGON2_PARALLELISM:u32 = 1;

#[derive(Copy, Clone, ValueEnum)]
pub enum StreamAlgo { Blake3, Chacha }

impl std::fmt::Display for StreamAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamAlgo::Blake3 => write!(f, "blake3"),
            StreamAlgo::Chacha => write!(f, "chacha"),
        }
    }
}

/// CLI for the `keygen` sub‑command
#[derive(Args)]
#[command(
    about       = "Deterministic cryptographic key generator",
    after_help  = "Size suffixes: <n>[kb|mb|gb|kib|mib|gib] (case‑insensitive)"
)]
pub struct KeyArgs {
    /// Key size (e.g. 10kb, 5mb, 1gb)
    pub size: String,

    /// Output file path
    #[arg(short, long, default_value = "key.key")]
    pub output: String,

    /// Output stream algorithm
    #[arg(short = 'a', long = "algo", value_enum, default_value_t = StreamAlgo::Blake3)]
    pub algo: StreamAlgo,

    /// Optional salt (base64). Omit to use the built‑in compile‑time salt
    #[arg(short, long)]
    pub salt: Option<String>,

    /// Argon2 memory in KiB
    #[arg(long, default_value_t = DEFAULT_ARGON2_MEMORY_KIB)]
    pub argon2_memory: u32,

    /// Argon2 time cost
    #[arg(long, default_value_t = DEFAULT_ARGON2_TIME_COST)]
    pub argon2_time: u32,

    /// Argon2 parallelism
    #[arg(long, default_value_t = DEFAULT_ARGON2_PARALLELISM)]
    pub argon2_par: u32,
}

/* ------------------------------------------------------------------------- */

pub fn run(k: KeyArgs) -> io::Result<()> {
    // -------- size parsing -------------------------------------------------
    let size = parse_size(&k.size).unwrap_or_else(|| {
        eprintln!("❌ Invalid size: '{}'", k.size);
        process::exit(1);
    });

    // -------- password input + confirmation -------------------------------
    let pwd1: Zeroizing<String> = Zeroizing::new(prompt_password("🔐 Enter password: ")?);
    let pwd2: Zeroizing<String> = Zeroizing::new(prompt_password("🔐 Confirm password: ")?);

    if pwd1.as_bytes().ct_eq(pwd2.as_bytes()).unwrap_u8() == 0 {
        eprintln!("❌ Passwords do not match. Aborting.");
        process::exit(1);
    }

    // -------- salt ---------------------------------------------------------
    let salt_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        k.salt.as_deref()
            .map(|s| B64.decode(s).unwrap_or_else(|_| {
                eprintln!("❌ Salt is not valid base64");
                process::exit(1);
            }))
            .unwrap_or_else(|| COMPILE_TIME_SALT.to_vec())
    );

    // -------- derive 32‑byte seed -----------------------------------------
    println!(
        "📦 Generating {size} bytes with {} / Argon2id(mem={} KiB, t={}, p={})",
        k.algo, k.argon2_memory, k.argon2_time, k.argon2_par
    );

    let start = Instant::now();
    let mut seed = derive_seed(
        &pwd1, &salt_bytes,
        k.argon2_memory, k.argon2_time, k.argon2_par
    );

    // -------- stream key ---------------------------------------------------
    let result = match k.algo {
        StreamAlgo::Blake3 => write_blake3(&k.output, &seed, size),
        StreamAlgo::Chacha => write_chacha(&k.output, &seed, size),
    };

    // -------- clean‑up -----------------------------------------------------
    seed.zeroize();
    result?;
    println!("✅ Key written to '{}' in {:.2?}", k.output, start.elapsed());
    Ok(())
}

/* ========== internal helpers ============================================ */

fn derive_seed(
    password: &Zeroizing<String>,
    salt_bytes: &[u8],
    mem: u32,
    time: u32,
    par: u32,
) -> [u8; 32] {
    if mem > 4 * 1024 * 1024 {      // 4 GiB safety brake
        eprintln!("❌ argon2-memory ({mem} KiB) exceeds 4 GiB limit.");
        process::exit(1);
    }

    let params  = Params::new(mem, time, par, None)
        .expect("invalid Argon2 parameters");
    let argon2  = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt_bytes, &mut seed)
        .unwrap_or_else(|e| {
            eprintln!("❌ Argon2id hashing failed: {e}");
            process::exit(1);
        });
    seed
}

fn write_blake3(path: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut xof = blake3::Hasher::new_keyed(seed).finalize_xof();
    stream_to_file(path, size, |buf| xof.fill(buf))
}

fn write_chacha(path: &str, seed: &[u8; 32], size: usize) -> io::Result<()> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    stream_to_file(path, size, |buf| rng.fill_bytes(buf))
}

fn stream_to_file<F>(path: &str, mut remaining: usize, mut fill: F) -> io::Result<()>
where
    F: FnMut(&mut [u8]),
{
    let file   = File::create(path)?;
    let mut w  = BufWriter::new(file);
    let mut buf= [0u8; 8192];

    while remaining != 0 {
        let n = remaining.min(buf.len());
        fill(&mut buf[..n]);
        w.write_all(&buf[..n])?;
        remaining -= n;
    }
    w.flush()
}

/// Parse sizes like 5mb, 2MiB, 123
fn parse_size(arg: &str) -> Option<usize> {
    let s = arg.trim().to_lowercase();
    let (num, mul) = if let Some(n) = s.strip_suffix("gib") { (n, 1024usize.pow(3)) }
        else if let Some(n) = s.strip_suffix("mib")        { (n, 1024usize.pow(2)) }
        else if let Some(n) = s.strip_suffix("kib")        { (n, 1024)            }
        else if let Some(n) = s.strip_suffix("gb")         { (n, 1_000_000_000)   }
        else if let Some(n) = s.strip_suffix("mb")         { (n, 1_000_000)       }
        else if let Some(n) = s.strip_suffix("kb")         { (n, 1_000)           }
        else                                               { (s.as_str(), 1)      };

    num.parse::<f64>().ok()
        .map(|v| (v * mul as f64).round() as usize)
}
