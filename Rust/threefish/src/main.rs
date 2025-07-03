//! threefish‑cli – Threefish‑1024 + HMAC‑SHA‑256 file encryptor / decryptor
//!
//! © 2025  MIT License
#![forbid(unsafe_code)]

/* -------------------------------------------------------------------------- */
/*                                DEPENDENCIES                                */
/* -------------------------------------------------------------------------- */

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::Parser;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::{NamedTempFile, TempPath};
use threefish::Threefish1024;
use zeroize::Zeroizing;

/* -------------------------------------------------------------------------- */
/*                                   TYPES                                    */
/* -------------------------------------------------------------------------- */

type HmacSha256 = Hmac<Sha256>;

/* -------------------------------------------------------------------------- */
/*                                   CONSTS                                   */
/* -------------------------------------------------------------------------- */

const IO_BUF_SIZE: usize = 64 * 1024; // 64 KiB
const BLOCK_SIZE: usize = 128;        // Threefish‑1024 block size

/* ---------- ciphertext header ---------- */
const MAGIC: &[u8; 4] = b"T1FS";
const VERSION_V2: u8 = 2;
const HEADER_LEN_V2: usize = 24;

const CIPHER_ID_THREEFISH1024_STREAM: u8 = 0x01;
const MAC_ID_HMAC_SHA256: u8 = 0x01;
const MAC_LEN: usize = 32;

/* ---------- key‑file v2 ---------- */
const KEYFILE_MAGIC: &[u8; 4] = b"TKF2";
const KEYFILE_VERSION: u8 = 2;
const KDF_ID_ARGON2ID: u8 = 0x13;
const KEYFILE_SALT_LEN: usize = 16;
const KEY_BYTES_TOTAL: usize = 160; // 128 B cipher + 32 B MAC
const KEYFILE_STATIC_LEN: usize =
    4 + 1 + 1 + 4 + 4 + 1 + KEYFILE_SALT_LEN + KEY_BYTES_TOTAL; // without checksum
const KEYFILE_CHECKSUM_LEN: usize = 32;

/* -------------------------------------------------------------------------- */
/*                                   CLI                                      */
/* -------------------------------------------------------------------------- */

/// Threefish‑1024 + HMAC‑SHA‑256 file encryptor / decryptor.
#[derive(Parser)]
#[command(author, version)]
struct Cli {
    /// Generate a key file from a password (`key.key` unless --key is given)
    #[arg(short = 'k', long, conflicts_with_all = ["encrypt", "decrypt"])]
    keygen: bool,

    /// Overwrite existing key file when using --keygen
    #[arg(long)]
    overwrite: bool,

    /// Path to key file (default: key.key)
    #[arg(long, value_name = "FILE", default_value = "key.key")]
    key: PathBuf,

    /// Force encryption
    #[arg(short = 'e', long, conflicts_with = "decrypt")]
    encrypt: bool,

    /// Force decryption
    #[arg(short = 'd', long)]
    decrypt: bool,

    /// File to operate on (omitted when --keygen)
    file: Option<PathBuf>,

    /// Argon2id memory (KiB) for --keygen [default: 65536]
    #[arg(long, value_parser = clap::value_parser!(u32).range(8_192..))]
    kdf_mem: Option<u32>,

    /// Argon2id iterations for --keygen [default: 3]
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    kdf_iters: Option<u32>,

    /// Argon2id parallelism for --keygen [default: logical CPUs capped at 4]
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..64))]
    kdf_par: Option<u8>,
}

/* -------------------------------------------------------------------------- */
/*                                   MAIN                                     */
/* -------------------------------------------------------------------------- */

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.keygen {
        keygen(&cli)?;
        return Ok(());
    }

    let file = cli
        .file
        .as_deref()
        .ok_or_else(|| anyhow!("no file specified"))?;

    let (cipher_key, mac_key) = load_keyfile(&cli.key)?;
    let mode = decide_mode(file, cli.encrypt, cli.decrypt)?;

    process_file(file, mode, &cipher_key, &mac_key)?;
    println!(
        "{} {}",
        match mode {
            Mode::Encrypt => "encrypted",
            Mode::Decrypt => "decrypted",
        },
        file.display()
    );
    Ok(())
}

/* -------------------------------------------------------------------------- */
/*                         KEY‑FILE GENERATION (--keygen)                     */
/* -------------------------------------------------------------------------- */

fn keygen(cli: &Cli) -> Result<()> {
    if cli.key.exists() && !cli.overwrite {
        bail!(
            "key file {:?} already exists (use --overwrite to replace)",
            cli.key
        );
    }

    let password = prompt_password("Password: ")?;
    let confirm = prompt_password("Repeat password: ")?;
    if password != confirm {
        bail!("passwords do not match");
    }

    let password_z = Zeroizing::new(password.into_bytes());

    /* ----- Argon2id parameters ----- */
    let mem_cost = cli.kdf_mem.unwrap_or(65_536); // 64 MiB
    let iter_cost = cli.kdf_iters.unwrap_or(3);
    let par_cost = cli.kdf_par.unwrap_or_else(|| num_cpus::get().min(4) as u8);

    let params = Params::new(
        mem_cost,
        iter_cost,
        u32::from(par_cost),     // lanes
        Some(KEY_BYTES_TOTAL),   // output length
    )
    .map_err(|e| anyhow!("bad Argon2 parameters: {e}"))?;

    let mut salt = [0u8; KEYFILE_SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = Zeroizing::new(vec![0u8; KEY_BYTES_TOTAL]);
    argon2
        .hash_password_into(&password_z, &salt, &mut key_bytes)
        .map_err(|e| anyhow!("Argon2id failed: {e}"))?;

    write_keyfile_v2(
        &cli.key,
        mem_cost,
        iter_cost,
        par_cost,
        &salt,
        &key_bytes,
    )?;
    println!("wrote key file {:?}", cli.key);
    Ok(())
}

/* -------------------------------------------------------------------------- */
/*                             KEY‑FILE HANDLING                              */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Copy)]
enum KeyfileType {
    Raw160,
    V2,
}

fn load_keyfile(
    path: &Path,
) -> Result<(Zeroizing<[u8; 128]>, Zeroizing<[u8; 32]>)> {
    check_keyfile_perms(path)?;
    let mut f = File::open(path).with_context(|| format!("open key file {:?}", path))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;

    let ktype = if &magic == KEYFILE_MAGIC {
        KeyfileType::V2
    } else {
        if f.metadata()?.len() != KEY_BYTES_TOTAL as u64 {
            bail!(
                "unexpected legacy key file size (expected {KEY_BYTES_TOTAL} B)"
            );
        }
        f.seek(SeekFrom::Start(0))?;
        KeyfileType::Raw160
    };

    match ktype {
        KeyfileType::Raw160 => {
            let mut buf = Zeroizing::new([0u8; KEY_BYTES_TOTAL]);
            f.read_exact(buf.as_mut())?;
            let mut ck = Zeroizing::new([0u8; 128]);
            let mut mk = Zeroizing::new([0u8; 32]);
            ck.copy_from_slice(&buf[..128]);
            mk.copy_from_slice(&buf[128..]);
            Ok((ck, mk))
        }
        KeyfileType::V2 => {
            let mut rest = vec![0u8; KEYFILE_STATIC_LEN - 4];
            f.read_exact(&mut rest)?;
            let mut checksum = [0u8; KEYFILE_CHECKSUM_LEN];
            f.read_exact(&mut checksum)?;

            let mut hasher = Sha256::new();
            hasher.update(&magic);
            hasher.update(&rest);
            if checksum != hasher.finalize()[..] {
                bail!("key file checksum mismatch");
            }

            let cursor = &rest[..];
            let version = cursor[0];
            if version != KEYFILE_VERSION {
                bail!("unsupported key file version {version}");
            }
            if cursor[1] != KDF_ID_ARGON2ID {
                bail!("unsupported KDF id {}", cursor[1]);
            }

            let key_offset = 11 + KEYFILE_SALT_LEN;
            let key = &cursor[key_offset..];

            let mut ck = Zeroizing::new([0u8; 128]);
            ck.copy_from_slice(&key[..128]);
            let mut mk = Zeroizing::new([0u8; 32]);
            mk.copy_from_slice(&key[128..]);
            Ok((ck, mk))
        }
    }
}

/* ----- write key file v2 ----- */
fn write_keyfile_v2(
    path: &Path,
    mem: u32,
    iters: u32,
    par: u8,
    salt: &[u8],
    key: &[u8],
) -> Result<()> {
    assert_eq!(salt.len(), KEYFILE_SALT_LEN);
    assert_eq!(key.len(), KEY_BYTES_TOTAL);

    let mut buf = Vec::with_capacity(KEYFILE_STATIC_LEN + KEYFILE_CHECKSUM_LEN);
    buf.extend_from_slice(KEYFILE_MAGIC);
    buf.push(KEYFILE_VERSION);
    buf.push(KDF_ID_ARGON2ID);
    buf.extend_from_slice(&mem.to_le_bytes());
    buf.extend_from_slice(&iters.to_le_bytes());
    buf.push(par);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(key);

    let checksum = Sha256::digest(&buf);
    buf.extend_from_slice(&checksum);

    let mut tmp = NamedTempFile::new_in(
        path.parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    tmp.write_all(&buf)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    promote_atomically(tmp.into_temp_path(), path)
}

/* ----- key file permission check (Unix only) ----- */
#[cfg(unix)]
fn check_keyfile_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o177 != 0 {
        bail!(
            "key file {:?} must not be accessible to group/others (mode {:o})",
            path,
            mode
        );
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_keyfile_perms(_: &Path) -> Result<()> {
    Ok(())
}

/* -------------------------------------------------------------------------- */
/*                              MODE SELECTION                                */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn decide_mode(path: &Path, encrypt_flag: bool, decrypt_flag: bool) -> Result<Mode> {
    match (encrypt_flag, decrypt_flag) {
        (true, false) => Ok(Mode::Encrypt),
        (false, true) => Ok(Mode::Decrypt),
        _ => detect_mode(path),
    }
}

fn detect_mode(path: &Path) -> Result<Mode> {
    let mut f = File::open(path)?;
    if f.metadata()?.len() < (HEADER_LEN_V2 + MAC_LEN) as u64 {
        return Ok(Mode::Encrypt);
    }
    let mut prefix = [0u8; 5];
    f.read_exact(&mut prefix)?;
    if &prefix[..4] == MAGIC && prefix[4] == VERSION_V2 {
        Ok(Mode::Decrypt)
    } else {
        Ok(Mode::Encrypt)
    }
}

/* -------------------------------------------------------------------------- */
/*                             FILE PROCESSING                                */
/* -------------------------------------------------------------------------- */

fn process_file(
    path: &Path,
    mode: Mode,
    cipher_key: &[u8; 128],
    mac_key: &[u8; 32],
) -> Result<()> {
    match mode {
        Mode::Encrypt => encrypt_file(path, cipher_key, mac_key),
        Mode::Decrypt => decrypt_file(path, cipher_key, mac_key),
    }
}

/* -------------------------------------------------------------------------- */
/*                            STREAM‑CIPHER STATE                             */
/* -------------------------------------------------------------------------- */

struct StreamCipher<'a> {
    key64: &'a [u64; 16],
    nonce_hi: u64,
    nonce_lo: u64,
    block_idx: u64,
}

impl<'a> StreamCipher<'a> {
    fn new(key64: &'a [u64; 16], nonce_hi: u64, nonce_lo: u64) -> Self {
        Self {
            key64,
            nonce_hi,
            nonce_lo,
            block_idx: 0,
        }
    }

    fn xor_in_place(&mut self, mut data: &mut [u8]) {
        let mut keystream = Zeroizing::new([0u8; BLOCK_SIZE]);

        while !data.is_empty() {
            if self.block_idx == u64::MAX {
                panic!("stream‑cipher block counter exhausted");
            }
            let tweak = [self.nonce_hi, self.block_idx ^ self.nonce_lo];
            self.block_idx += 1;

            let mut block = [0u64; 16];
            let cipher = Threefish1024::new_with_tweak_u64(self.key64, &tweak);
            cipher.encrypt_block_u64(&mut block);
            for (i, w) in block.iter().enumerate() {
                keystream[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
            }

            let n = data.len().min(BLOCK_SIZE);
            for (b, k) in data[..n].iter_mut().zip(&keystream[..n]) {
                *b ^= *k;
            }
            data = &mut data[n..];
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                              ENCRYPTION                                    */
/* -------------------------------------------------------------------------- */

fn encrypt_file(src: &Path, cipher_key: &[u8; 128], mac_key: &[u8; 32]) -> Result<()> {
    let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src)?);

    let tmp_file = NamedTempFile::new_in(
        src.parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp_file.reopen()?);

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let hdr = HeaderV2::new(nonce);
    let hdr_bytes = hdr.to_bytes();
    writer.write_all(&hdr_bytes)?;

    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&hdr_bytes);

    let key64 = Zeroizing::new(to_u64_key(cipher_key));
    let mut sc = StreamCipher::new(
        &key64,
        u64::from_be_bytes(nonce[..8].try_into()?),
        u64::from_be_bytes(nonce[8..].try_into()?),
    );

    let mut buf = Zeroizing::new([0u8; IO_BUF_SIZE]);
    loop {
        let n = reader.read(buf.as_mut())?;
        if n == 0 {
            break;
        }
        sc.xor_in_place(&mut buf[..n]);
        hmac.update(&buf[..n]);
        writer.write_all(&buf[..n])?;
    }

    writer.write_all(&hmac.finalize().into_bytes())?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    drop(reader);

    promote_atomically(tmp_file.into_temp_path(), src)
}

/* -------------------------------------------------------------------------- */
/*                              DECRYPTION                                    */
/* -------------------------------------------------------------------------- */

fn decrypt_file(src: &Path, cipher_key: &[u8; 128], mac_key: &[u8; 32]) -> Result<()> {
    let mut file = OpenOptions::new().read(true).open(src)?;

    let file_len = file.metadata()?.len();
    if file_len < (HEADER_LEN_V2 + MAC_LEN) as u64 {
        bail!("ciphertext too short");
    }

    let mut header = [0u8; HEADER_LEN_V2];
    file.read_exact(&mut header)?;
    if &header[..4] != MAGIC {
        bail!("bad magic bytes");
    }
    if header[4] != VERSION_V2 {
        bail!("unsupported header version {}", header[4]);
    }
    if header[5] != CIPHER_ID_THREEFISH1024_STREAM || header[6] != MAC_ID_HMAC_SHA256 {
        bail!("unknown algorithm identifiers");
    }
    if header[7] != 0 {
        bail!("non‑zero padding byte – file is corrupted");
    }

    /* --- pass 1: MAC verification --- */
    let cipher_len = file_len - HEADER_LEN_V2 as u64 - MAC_LEN as u64;
    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&header);

    let mut remaining = cipher_len;
    let mut buf = Zeroizing::new([0u8; IO_BUF_SIZE]);
    while remaining != 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        file.read_exact(&mut buf[..n])?;
        hmac.update(&buf[..n]);
        remaining -= n as u64;
    }

    let mut tag = [0u8; MAC_LEN];
    file.read_exact(&mut tag)?;
    hmac.verify_slice(&tag)
        .map_err(|_| anyhow!("authentication failed"))?;

    /* --- pass 2: decryption --- */
    file.seek(SeekFrom::Start(HEADER_LEN_V2 as u64))?;
    let tmp_file = NamedTempFile::new_in(
        src.parent()
            .ok_or_else(|| anyhow!("cannot determine parent directory"))?,
    )?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp_file.reopen()?);

    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&header[8..24]);
    let key64 = Zeroizing::new(to_u64_key(cipher_key));
    let mut sc = StreamCipher::new(
        &key64,
        u64::from_be_bytes(nonce[..8].try_into()?),
        u64::from_be_bytes(nonce[8..].try_into()?),
    );

    let mut remaining = cipher_len;
    while remaining != 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        file.read_exact(&mut buf[..n])?;
        sc.xor_in_place(&mut buf[..n]);
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    drop(file);

    promote_atomically(tmp_file.into_temp_path(), src)
}

/* -------------------------------------------------------------------------- */
/*                                   HEADER                                   */
/* -------------------------------------------------------------------------- */

#[derive(Clone, Copy)]
struct HeaderV2 {
    magic: [u8; 4],
    ver: u8,
    cipher: u8,
    mac: u8,
    pad: u8,
    nonce: [u8; 16],
}

impl HeaderV2 {
    fn new(nonce: [u8; 16]) -> Self {
        Self {
            magic: *MAGIC,
            ver: VERSION_V2,
            cipher: CIPHER_ID_THREEFISH1024_STREAM,
            mac: MAC_ID_HMAC_SHA256,
            pad: 0,
            nonce,
        }
    }

    fn to_bytes(&self) -> [u8; HEADER_LEN_V2] {
        let mut out = [0u8; HEADER_LEN_V2];
        out[0..4].copy_from_slice(&self.magic);
        out[4] = self.ver;
        out[5] = self.cipher;
        out[6] = self.mac;
        out[7] = self.pad;
        out[8..24].copy_from_slice(&self.nonce);
        out
    }
}

/* -------------------------------------------------------------------------- */
/*                                   UTIL                                     */
/* -------------------------------------------------------------------------- */

fn to_u64_key(key: &[u8; 128]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, chunk) in key.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

fn promote_atomically(temp_path: TempPath, final_path: &Path) -> Result<()> {
    let bak = final_path.with_extension("bak");
    let _ = fs::remove_file(&bak);
    fs::rename(final_path, &bak).ok();

    match temp_path.persist_noclobber(final_path) {
        Ok(_) => {
            let _ = fs::remove_file(&bak);
            Ok(())
        }
        Err(e) => {
            let _ = fs::rename(&bak, final_path);
            Err(e.error).context("failed to promote temp file")
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                   TESTS                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> ([u8; 128], [u8; 32]) {
        let mut k = [0u8; KEY_BYTES_TOTAL];
        OsRng.fill_bytes(&mut k);
        let mut ck = [0u8; 128];
        let mut mk = [0u8; 32];
        ck.copy_from_slice(&k[..128]);
        mk.copy_from_slice(&k[128..]);
        (ck, mk)
    }

    #[test]
    fn roundtrip_small() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        let (ck, mk) = random_key();
        encrypt_file(f.path(), &ck, &mk).unwrap();
        decrypt_file(f.path(), &ck, &mk).unwrap();
        let mut v = Vec::new();
        File::open(f.path()).unwrap().read_to_end(&mut v).unwrap();
        assert_eq!(v, b"hello world");
    }

    #[test]
    fn mac_detects_tamper() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"abcdef").unwrap();
        let (ck, mk) = random_key();
        encrypt_file(f.path(), &ck, &mk).unwrap();

        {
            let mut fh = OpenOptions::new().read(true).write(true).open(f.path()).unwrap();
            fh.seek(SeekFrom::Start(HEADER_LEN_V2 as u64 + 2)).unwrap();
            let mut byte = [0u8; 1];
            fh.read_exact(&mut byte).unwrap();
            byte[0] ^= 0xAA;
            fh.seek(SeekFrom::Current(-1)).unwrap();
            fh.write_all(&byte).unwrap();
        }

        assert!(decrypt_file(f.path(), &ck, &mk).is_err());
    }
}
