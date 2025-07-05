
//! orbit‑256 ‑ header‑aware, in‑place file cipher (demo / educational)
//
//! Build:  cargo build --release
//! Usage:  orbit-256 -p "pass phrase" <file>
use clap::Parser;
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/* --------------------------------------------------------------------- */
/*  Format constants                                                     */
/* --------------------------------------------------------------------- */

const MAGIC: &[u8; 8] = b"ORB256V1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 8;

/* --------------------------------------------------------------------- */
/*  Orbit‑256 core                                                       */
/* --------------------------------------------------------------------- */

#[derive(Clone)]
struct Orbit256 {
    s: [u64; 4],
}

impl Orbit256 {
    fn new(key: [u8; 32], nonce: [u8; 8]) -> Self {
        // Mix nonce into key material (simple, *not* provably secure).
        let mut mix = [0u8; 40];
        mix[..32].copy_from_slice(&key);
        mix[32..].copy_from_slice(&nonce);
        let mixed_key: [u8; 32] = Sha3_256::digest(&mix).into();

        let mut s = [0u64; 4];
        for (i, chunk) in mixed_key.chunks_exact(8).enumerate() {
            s[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Self { s }
    }

    fn next_word(&mut self) -> u64 {
        const PHI64: u64 = 0x9E37_79B1_85EB_CA87;
        let t = self.s[0] ^ (self.s[0] << 23);
        self.s[0] = self.s[1];
        self.s[1] = self.s[2];
        self.s[2] = self.s[3];
        self.s[3] = (self.s[3] ^ (self.s[3] >> 17)) ^ (t ^ (t >> 18));
        self.s[3] = self.s[3].wrapping_add(PHI64);
        self.s[3]
    }

    fn xor_stream(&mut self, data: &mut [u8]) {
        let mut i = 0;
        while i < data.len() {
            for b in self.next_word().to_le_bytes() {
                if i == data.len() {
                    break;
                }
                data[i] ^= b;
                i += 1;
            }
        }
    }
}

/* --------------------------------------------------------------------- */
/*  CLI specification                                                    */
/* --------------------------------------------------------------------- */

/// Encrypt **or** decrypt a file *in place*.
///
/// If the file starts with the magic header it will be decrypted,
/// otherwise it will be encrypted and the header will be added.
#[derive(Parser)]
#[command(author, version, about, disable_help_subcommand = true)]
struct Cli {
    /// UTF‑8 pass‑phrase (stretched with SHA3‑256 + random salt)
    #[arg(short, long)]                 //  ← removed `global = true`
    passphrase: String,

    /// File to process in place
    file: PathBuf,
}

/* --------------------------------------------------------------------- */
/*  Helpers                                                              */
/* --------------------------------------------------------------------- */

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

fn write_atomically(target: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp_path = target.with_file_name(format!(
        ".{}.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("orbit256")
    ));
    File::create(&tmp_path)?.write_all(data)?;
    fs::rename(tmp_path, target)?;
    Ok(())
}

/* --------------------------------------------------------------------- */
/*  Entry point                                                          */
/* --------------------------------------------------------------------- */

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    /* ----- read full file -------------------------------------------- */
    let mut buf = Vec::new();
    File::open(&cli.file)?.read_to_end(&mut buf)?;

    if buf.starts_with(MAGIC) {
        /* ==================== Decrypt ================================ */
        if buf.len() < MAGIC.len() + SALT_LEN + NONCE_LEN {
            eprintln!("Ciphertext too short or corrupted.");
            std::process::exit(1);
        }
        let salt_off = MAGIC.len();
        let nonce_off = salt_off + SALT_LEN;
        let data_off = nonce_off + NONCE_LEN;

        let salt = &buf[salt_off..nonce_off];
        let nonce: [u8; 8] = buf[nonce_off..data_off].try_into().unwrap();
        let mut payload = buf[data_off..].to_vec();

        let key = derive_key(&cli.passphrase, salt);
        Orbit256::new(key, nonce).xor_stream(&mut payload);

        write_atomically(&cli.file, &payload)?;
        println!("Decrypted {}.", cli.file.display());
    } else {
        /* ==================== Encrypt ================================ */
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let key = derive_key(&cli.passphrase, &salt);
        let mut payload = buf.clone();
        Orbit256::new(key, nonce).xor_stream(&mut payload);

        let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + payload.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&payload);

        write_atomically(&cli.file, &out)?;
        println!(
            "Encrypted {} (added {}‑byte header).",
            cli.file.display(),
            MAGIC.len() + SALT_LEN + NONCE_LEN
        );
    }
    Ok(())
}
