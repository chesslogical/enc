// Cargo.toml dependencies:
// clap = { version = "4.5.40", features = ["derive"] }
// threefish = "0.5.2"
// rand = "0.9.1"
// zeroize = "1.8.1"
// anyhow = "1.0.98"
// hmac = "0.12.1"
// sha2 = "0.10.0"
// tempfile = "3.20.0"
// argon2 = "0.5.3"
// rpassword = "7.4.0"

use std::{
    io::{Read, Write, Seek, SeekFrom},
    path::Path,
};
use clap::{Parser, Subcommand, ArgGroup};
use rand::random;
use argon2::Argon2;
use rpassword::prompt_password;
use threefish::Threefish1024;
use zeroize::Zeroize;
use tempfile::NamedTempFile;
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Type for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Constants
const MAGIC: &[u8; 4] = b"T1FS";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + 8; // MAGIC + VERSION + SALT + NONCE
const MAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 128;

#[derive(Parser)]
#[command(author, version)]
#[command(group(
    ArgGroup::new("key_source").required(true).args(&["keyfile", "password"])
))]
struct Cli {
    /// Path to raw key file (160 bytes)
    #[arg(long, conflicts_with = "password")]
    keyfile: Option<String>,

    /// Use a passphrase instead of key file
    #[arg(long, conflicts_with = "keyfile")]
    password: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file in-place
    Encrypt { path: String },
    /// Decrypt a file in-place
    Decrypt { path: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Encrypt { path } => encrypt_path(&cli, path),
        Commands::Decrypt { path } => decrypt_path(&cli, path),
    }
}

fn encrypt_path(cli: &Cli, path_str: &str) -> Result<()> {
    // Initialize salt
    let mut salt_bytes = [0u8; SALT_LEN];
    // Derive or load keys
    let (mut key, mut hmac_key) = if cli.password {
        // Prompt for passphrase
        let pwd = prompt_password("Enter encryption passphrase: ")?;
        // Generate a 16-byte salt
        let salt_val: u128 = random();
        salt_bytes = salt_val.to_le_bytes();
        // Derive 160-byte key material via Argon2id
        let mut full = [0u8; 160];
        Argon2::default()
            .hash_password_into(pwd.as_bytes(), &salt_bytes, &mut full)
            .map_err(|e| anyhow!("KDF error: {}", e))?;
        // Split into cipher key and HMAC key
        let mut k = [0u8;128]; k.copy_from_slice(&full[..128]);
        let mut hm = [0u8;32]; hm.copy_from_slice(&full[128..]);
        full.zeroize();
        (k, hm)
    } else {
        // Load raw key file
        load_keyfile(cli.keyfile.as_ref().unwrap())?
    };

    // Generate a random nonce
    let nonce: u64 = random();
    // Encrypt the file
    encrypt_file(path_str, &salt_bytes, nonce, &key, &hmac_key)?;
    // Zeroize sensitive material
    key.zeroize();
    hmac_key.zeroize();
    Ok(())
}

fn decrypt_path(cli: &Cli, path_str: &str) -> Result<()> {
    // Open file and read header
    let mut infile = std::fs::File::open(path_str)?;
    let mut header = [0u8; HEADER_LEN];
    infile.read_exact(&mut header)?;
    // Verify magic and version
    if &header[..4] != MAGIC { return Err(anyhow!("Invalid file format")); }
    if header[4] != VERSION { return Err(anyhow!("Unsupported version")); }
    // Extract salt and nonce
    let mut salt_bytes = [0u8; SALT_LEN];
    salt_bytes.copy_from_slice(&header[5..5+SALT_LEN]);
    let mut nb = [0u8;8];
    nb.copy_from_slice(&header[5+SALT_LEN..HEADER_LEN]);
    let nonce = u64::from_le_bytes(nb);
    // Derive or load keys
    let (mut key, mut hmac_key) = if cli.password {
        let pwd = prompt_password("Enter decryption passphrase: ")?;
        let mut full = [0u8; 160];
        Argon2::default()
            .hash_password_into(pwd.as_bytes(), &salt_bytes, &mut full)
            .map_err(|e| anyhow!("KDF error: {}", e))?;
        let mut k = [0u8;128]; k.copy_from_slice(&full[..128]);
        let mut hm = [0u8;32]; hm.copy_from_slice(&full[128..]);
        full.zeroize();
        (k, hm)
    } else {
        load_keyfile(cli.keyfile.as_ref().unwrap())?
    };
    // Decrypt the file
    decrypt_file(path_str, &salt_bytes, nonce, &key, &hmac_key)?;
    // Zeroize keys
    key.zeroize();
    hmac_key.zeroize();
    Ok(())
}

fn load_keyfile(path: &str) -> Result<([u8;128],[u8;32])> {
    let mut full = [0u8;160];
    std::fs::File::open(Path::new(path))?.read_exact(&mut full)?;
    let mut k = [0u8;128]; k.copy_from_slice(&full[..128]);
    let mut hm = [0u8;32]; hm.copy_from_slice(&full[128..]);
    full.zeroize();
    Ok((k, hm))
}

fn encrypt_file(path: &str, salt: &[u8;SALT_LEN], nonce: u64, key: &[u8;128], hmac_key: &[u8;32]) -> Result<()> {
    let in_path = Path::new(path);
    let mut tmp = NamedTempFile::new_in(
        in_path.parent().unwrap_or_else(|| Path::new(".")))?;
    let mut infile = std::fs::File::open(in_path)?;
    let mut hmac = HmacSha256::new_from_slice(hmac_key)?;
    // Write header
    tmp.write_all(MAGIC)?;
    tmp.write_all(&[VERSION])?;
    tmp.write_all(salt)?;
    tmp.write_all(&nonce.to_le_bytes())?;
    // Feed header into HMAC
    hmac.update(MAGIC);
    hmac.update(&[VERSION]);
    hmac.update(salt);
    hmac.update(&nonce.to_le_bytes());
    // Encrypt stream
    let key_u64 = to_u64_key(key);
    let mut block_index = 0u64;
    let mut buf = [0u8; BLOCK_SIZE];
    while let Ok(n) = infile.read(&mut buf) {
        if n == 0 { break; }
        let ks = generate_keystream_block(&key_u64, nonce, block_index);
        for i in 0..n { buf[i] ^= ks[i]; }
        hmac.update(&buf[..n]);
        tmp.write_all(&buf[..n])?;
        block_index += 1;
    }
    tmp.write_all(&hmac.finalize().into_bytes())?;
    // On Windows, remove the original before renaming
    let _ = std::fs::remove_file(in_path);
    tmp.persist(in_path)?;
    Ok(())
}

fn decrypt_file(path: &str, salt: &[u8;SALT_LEN], nonce: u64, key: &[u8;128], hmac_key: &[u8;32]) -> Result<()> {
    let in_path = Path::new(path);
    let mut infile = std::fs::File::open(in_path)?;
    infile.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let metadata = infile.metadata()?;
    let ciphertext_len = metadata.len() - HEADER_LEN as u64 - MAC_LEN as u64;
    // Verify HMAC
    let mut hmac = HmacSha256::new_from_slice(hmac_key)?;
    hmac.update(MAGIC);
    hmac.update(&[VERSION]);
    hmac.update(salt);
    hmac.update(&nonce.to_le_bytes());
    let mut remaining = ciphertext_len;
    let mut buf = [0u8; BLOCK_SIZE];
    while remaining > 0 {
        let to_read = remaining.min(BLOCK_SIZE as u64) as usize;
        infile.read_exact(&mut buf[..to_read])?;
        hmac.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }
    let mut mac = [0u8; MAC_LEN]; infile.read_exact(&mut mac)?;
    hmac.verify_slice(&mac).map_err(|_| anyhow!("Authentication failed"))?;
    // Decrypt stream
    infile.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let mut tmp = NamedTempFile::new_in(in_path.parent().unwrap_or_else(|| Path::new(".")))?;
    let key_u64 = to_u64_key(key);
    let mut block_index = 0u64;
    let mut reader = infile.take(ciphertext_len);
    let mut out_buf = [0u8; BLOCK_SIZE];
    while let Ok(n) = reader.read(&mut out_buf) {
        if n == 0 { break; }
        let mut block = [0u8; BLOCK_SIZE];
        block[..n].copy_from_slice(&out_buf[..n]);
        let ks = generate_keystream_block(&key_u64, nonce, block_index);
        for i in 0..n { block[i] ^= ks[i]; }
        tmp.write_all(&block[..n])?;
        block_index += 1;
    }
    // On Windows, ensure original is deleted before rename
    let _ = std::fs::remove_file(in_path);
    tmp.persist(in_path)?;
    Ok(())
}

fn to_u64_key(key: &[u8;128]) -> [u64;16] {
    let mut out = [0u64;16];
    for (i, chunk) in key.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

fn generate_keystream_block(key_u64: &[u64;16], nonce: u64, block_index: u64) -> [u8; BLOCK_SIZE] {
    let tweak = [nonce, block_index];
    let mut state = [0u64;16];
    let cipher = Threefish1024::new_with_tweak_u64(key_u64, &tweak);
    cipher.encrypt_block_u64(&mut state);
    let mut out = [0u8; BLOCK_SIZE];
    for (i, &v) in state.iter().enumerate() {
        out[i*8..(i+1)*8].copy_from_slice(&v.to_le_bytes());
    }
    out
}
