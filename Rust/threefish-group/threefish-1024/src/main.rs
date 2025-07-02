// Add to Cargo.toml under [dependencies]:
// tempfile = "3.5"
// rand = "0.9.1"

use std::{
    io::{Read, Write, Seek, SeekFrom},
    path::Path,
};

use clap::{Parser, Subcommand};
use rand::random;
use threefish::Threefish1024;
use zeroize::Zeroize;
use tempfile::NamedTempFile;
use anyhow::{anyhow, Result};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"T1FS";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 8; // MAGIC + VERSION + NONCE
const MAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 128;

#[derive(Parser)]
#[command(author, version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt file in-place
    Encrypt { path: String },
    /// Decrypt file in-place
    Decrypt { path: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt { path } => process(&path, true),
        Commands::Decrypt { path } => process(&path, false),
    }
}

fn load_keys() -> Result<([u8; 128], [u8; 32])> {
    let path = Path::new("key.key");
    if !path.exists() {
        return Err(anyhow!("No key.key found. Generate and place it in key.key"));
    }

    let meta = std::fs::metadata(path)?;
    if meta.len() != 160 {
        return Err(anyhow!("Invalid key length: expected 160 bytes, got {}", meta.len()));
    }

    let mut file = std::fs::File::open(path)?;
    let mut full_key = [0u8; 160];
    file.read_exact(&mut full_key)?;

    let mut key = [0u8; 128];
    let mut hmac_key = [0u8; 32];
    key.copy_from_slice(&full_key[..128]);
    hmac_key.copy_from_slice(&full_key[128..]);

    full_key.zeroize();
    Ok((key, hmac_key))
}

fn process(path_str: &str, encrypt: bool) -> Result<()> {
    let (mut key, mut hmac_key) = load_keys()?;
    let in_path = Path::new(path_str);
    let mut tmp = NamedTempFile::new_in(
        in_path.parent().unwrap_or_else(|| Path::new("."))
    )?;

    if encrypt {
        let mut infile = std::fs::File::open(in_path)?;
        let mut hmac = HmacSha256::new_from_slice(&hmac_key)?;

        // Write header
        tmp.write_all(MAGIC)?;
        tmp.write_all(&[VERSION])?;

        // Generate a 64-bit nonce
let nonce: u64 = random();
let nonce_bytes = nonce.to_le_bytes();
        tmp.write_all(&nonce_bytes)?;

        // HMAC header
        hmac.update(MAGIC);
        hmac.update(&[VERSION]);
        hmac.update(&nonce_bytes);

        // Stream encryption
        let key_u64 = to_u64_key(&key);
        let mut block_index = 0u64;
        let mut buffer = [0u8; BLOCK_SIZE];

        loop {
            let n = infile.read(&mut buffer)?;
            if n == 0 { break; }
            let keystream = generate_keystream_block(&key_u64, &nonce_bytes, block_index);
            for i in 0..n { buffer[i] ^= keystream[i]; }
            hmac.update(&buffer[..n]);
            tmp.write_all(&buffer[..n])?;
            block_index += 1;
        }

        // Write HMAC
        let mac = hmac.finalize().into_bytes();
        tmp.write_all(&mac)?;
    } else {
        let mut infile = std::fs::File::open(in_path)?;
        let metadata = infile.metadata()?;
        if metadata.len() < (HEADER_LEN + MAC_LEN) as u64 {
            return Err(anyhow!("File too short"));
        }

        // Read header
        let mut header = [0u8; HEADER_LEN];
        infile.read_exact(&mut header)?;
        if &header[..4] != MAGIC { return Err(anyhow!("Invalid file format")); }
        if header[4] != VERSION { return Err(anyhow!("Unsupported version")); }
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&header[5..13]);

        // Pass 1: verify HMAC
        let mut hmac = HmacSha256::new_from_slice(&hmac_key)?;
        hmac.update(&header);
        let mut remaining = metadata.len() - HEADER_LEN as u64 - MAC_LEN as u64;
        let mut buf = [0u8; BLOCK_SIZE];
        while remaining > 0 {
            let to_read = remaining.min(BLOCK_SIZE as u64) as usize;
            infile.read_exact(&mut buf[..to_read])?;
            hmac.update(&buf[..to_read]);
            remaining -= to_read as u64;
        }
        let mut expected_mac = [0u8; MAC_LEN];
        infile.read_exact(&mut expected_mac)?;
        hmac.verify_slice(&expected_mac).map_err(|_| anyhow!("Authentication failed"))?;

        // Pass 2: decrypt
        infile.seek(SeekFrom::Start(HEADER_LEN as u64))?;
        let key_u64 = to_u64_key(&key);
        let mut block_index = 0u64;
        let mut reader = infile.take(metadata.len() - HEADER_LEN as u64 - MAC_LEN as u64);
        let mut out_buf = [0u8; BLOCK_SIZE];

        loop {
            let n = reader.read(&mut out_buf)?;
            if n == 0 { break; }
            let mut block = [0u8; BLOCK_SIZE];
            block[..n].copy_from_slice(&out_buf[..n]);
            let keystream = generate_keystream_block(&key_u64, &nonce_bytes, block_index);
            for i in 0..n { block[i] ^= keystream[i]; }
            tmp.write_all(&block[..n])?;
            block_index += 1;
        }
    }

    // Zeroize keys
    key.zeroize();
    hmac_key.zeroize();

    // Atomically replace
    tmp.persist(in_path)?;
    Ok(())
}

fn to_u64_key(key: &[u8; 128]) -> [u64; 16] {
    let mut k = [0u64; 16];
    for (i, chunk) in key.chunks_exact(8).enumerate() {
        k[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    k
}

fn generate_keystream_block(
    key_u64: &[u64; 16],
    nonce_bytes: &[u8; 8],
    block_index: u64,
) -> [u8; BLOCK_SIZE] {
    let tweak = [u64::from_le_bytes(*nonce_bytes), block_index];
    let mut block = [0u64; 16];
    let cipher = Threefish1024::new_with_tweak_u64(key_u64, &tweak);
    cipher.encrypt_block_u64(&mut block);

    let mut out = [0u8; BLOCK_SIZE];
    for (i, &v) in block.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}
