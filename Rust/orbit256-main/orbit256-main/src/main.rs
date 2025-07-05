
//! orbit‑256 ‑ demo file cipher in one source file
//! Build:  `cargo run --release -- encrypt in out -p "secret"`
use clap::{Parser, Subcommand};
use sha3::{Digest, Sha3_256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

/* ------------------------------------------------------------------------- */
/*  Orbit‑256 algorithm                                                     */
/* ------------------------------------------------------------------------- */

/// Derive a 256‑bit key from a UTF‑8 passphrase plus a fixed salt tag.
///
/// *For production use you would switch to a proper memory‑hard KDF with a
/// per‑file random salt.  This is intentionally minimal for demonstration.*
fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(b"orbit-256:salt:v0"); // fixed tag prevents trivial reuse
    hasher.finalize().into()
}

/// Internal 256‑bit state of the keystream generator.
#[derive(Clone)]
struct Orbit256 {
    s: [u64; 4],
}

impl Orbit256 {
    /// Create a new cipher instance from a raw 32‑byte key.
    fn new(key: [u8; 32]) -> Self {
        let mut s = [0u64; 4];
        for (i, chunk) in key.chunks_exact(8).enumerate() {
            s[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Self { s }
    }

    /// Return the next 64‑bit keystream word.
    fn next_word(&mut self) -> u64 {
        const PHI64: u64 = 0x9E37_79B1_85EB_CA87; // 64‑bit fractional Φ
        let t = self.s[0] ^ (self.s[0] << 23);
        self.s[0] = self.s[1];
        self.s[1] = self.s[2];
        self.s[2] = self.s[3];
        self.s[3] = (self.s[3] ^ (self.s[3] >> 17)) ^ (t ^ (t >> 18));
        self.s[3] = self.s[3].wrapping_add(PHI64);
        self.s[3]
    }

    /// Fill `buf` with keystream bytes.
    fn fill_keystream(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let ks = self.next_word().to_le_bytes();
            let take = core::cmp::min(8, buf.len() - i);
            buf[i..i + take].copy_from_slice(&ks[..take]);
            i += take;
        }
    }

    /// XOR‑encrypt / decrypt `data` in place.
    fn xor_stream(&mut self, data: &mut [u8]) {
        let mut ks = vec![0u8; data.len()];
        self.fill_keystream(&mut ks);
        for (b, k) in data.iter_mut().zip(ks) {
            *b ^= k;
        }
    }
}

/* ------------------------------------------------------------------------- */
/*  Command‑line interface                                                  */
/* ------------------------------------------------------------------------- */

/// Orbit‑256 ‑ **experimental** stream‑cipher file tool.
///
/// ```text
/// # encrypt
/// orbit-256 encrypt plain.txt cipher.bin -p "correct horse battery staple"
///
/// # decrypt
/// orbit-256 decrypt cipher.bin recovered.txt -p "correct horse battery staple"
/// ```
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Passphrase (ASCII / UTF‑8). Use a *random* key for real security.
    #[arg(short, long)]
    passphrase: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt <INPUT> to <OUTPUT>
    Encrypt { input: PathBuf, output: PathBuf },
    /// Decrypt <INPUT> to <OUTPUT>
    Decrypt { input: PathBuf, output: PathBuf },
}

/* ------------------------------------------------------------------------- */
/*  Helpers                                                                 */
/* ------------------------------------------------------------------------- */

fn read_file(path: &PathBuf) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    File::open(path)?.read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_file(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    File::create(path)?.write_all(data)?;
    Ok(())
}

/* ------------------------------------------------------------------------- */
/*  Entry point                                                             */
/* ------------------------------------------------------------------------- */

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let key = derive_key(&cli.passphrase);
    println!("derived key : {}", hex::encode(key));

    match cli.command {
        Commands::Encrypt { input, output } => {
            let mut data = read_file(&input)?;
            Orbit256::new(key).xor_stream(&mut data);
            write_file(&output, &data)?;
            println!("encrypted ⇒ {}", output.display());
        }
        Commands::Decrypt { input, output } => {
            let mut data = read_file(&input)?;
            Orbit256::new(key).xor_stream(&mut data);
            write_file(&output, &data)?;
            println!("decrypted ⇒ {}", output.display());
        }
    }
    Ok(())
}
