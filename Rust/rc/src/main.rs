//! A simple Rust CLI for file encryption/decryption using AES-256-GCM.
//!
//! HARD-CODED SETTINGS (change these before compiling):
const PASSWORD: &str = "CHANGE_THIS_PASSWORD";
const SALT: &[u8]     = b"CHANGE_THIS_SALT";

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use clap::{Parser, Subcommand};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use anyhow::{Result, anyhow};
use rand::RngCore;
use rand::rngs::OsRng;

/// Simple file encryption/decryption CLI
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Operation to perform
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt an input file to an output file
    Encrypt {
        /// Path to the plaintext input file
        #[arg(short, long)]
        input: PathBuf,
        /// Path to write the ciphertext
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Decrypt an input file to an output file
    Decrypt {
        /// Path to the ciphertext input file
        #[arg(short, long)]
        input: PathBuf,
        /// Path to write the decrypted plaintext
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn derive_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    // Derive a 256-bit key from PASSWORD and SALT using PBKDF2-SHA256
    pbkdf2_hmac::<Sha256>(
        PASSWORD.as_bytes(),
        SALT,
        100_000,
        &mut key,
    );
    key
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let key_bytes = derive_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

    match cli.command {
        Commands::Encrypt { input, output } => {
            // Read plaintext
            let mut plaintext = Vec::new();
            File::open(&input)?.read_to_end(&mut plaintext)?;
            // Generate random nonce
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            // Encrypt
            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
                .map_err(|e| anyhow!("Encryption error: {}", e))?;
            // Write nonce + ciphertext
            let mut out_file = File::create(&output)?;
            out_file.write_all(&nonce_bytes)?;
            out_file.write_all(&ciphertext)?;

            println!("Encrypted '{}' → '{}'", input.display(), output.display());
        }
        Commands::Decrypt { input, output } => {
            // Read nonce + ciphertext
            let mut in_file = File::open(&input)?;
            let mut nonce_bytes = [0u8; 12];
            in_file.read_exact(&mut nonce_bytes)?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            let mut ciphertext = Vec::new();
            in_file.read_to_end(&mut ciphertext)?;
            // Decrypt
            let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
                .map_err(|e| anyhow!("Decryption error: {}", e))?;
            fs::write(&output, &plaintext)?;

            println!("Decrypted '{}' → '{}'", input.display(), output.display());
        }
    }

    Ok(())
}

