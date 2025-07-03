use anyhow::{anyhow, Context, Result};
use clap::Parser;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use threefish::Threefish1024;
use zeroize::Zeroizing;   

/* -------------------------------------------------------------------------- */
/*                               CONSTANTS                                    */
/* -------------------------------------------------------------------------- */

/// 128 B cipher key + 32 B MAC key
const KEY_BYTES: usize = 160;

/// Header is always 48 bytes
const HEADER_LEN: usize = 48;
const NONCE_LEN: usize = 16;            // 128‑bit nonce
const MAC_LEN: usize = 32;
const BLOCK_SIZE: usize = 128;          // Threefish‑1024 block size
const IO_BUF_SIZE: usize = 16 * 1024;   // 16 KiB

const MAGIC: &[u8; 4] = b"T1FS";
const VERSION: u8 = 1;
const CIPHER_ID_THREEFISH1024_STREAM: u8 = 0x01;
const MAC_ID_HMAC_SHA256: u8 = 0x01;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
enum Mode {
    Encrypt,
    Decrypt,
}

/* -------------------------------------------------------------------------- */
/*                                   HEADER                                   */
/* -------------------------------------------------------------------------- */

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Header {
    magic:   [u8; 4],
    ver:     u8,
    cipher:  u8,
    mac:     u8,
    _rsvd1:  u8,
    nonce:   [u8; 16],
    _rsvd2:  [u8; 24],
}

impl Header {
    fn new(nonce: [u8; 16]) -> Self {
        Self {
            magic: *MAGIC,
            ver: VERSION,
            cipher: CIPHER_ID_THREEFISH1024_STREAM,
            mac: MAC_ID_HMAC_SHA256,
            _rsvd1: 0,
            nonce,
            _rsvd2: [0u8; 24],
        }
    }

    fn validate(&self) -> Result<()> {
        if &self.magic != MAGIC           { return Err(anyhow!("bad magic")); }
        if self.ver != VERSION            { return Err(anyhow!("unsupported version {}", self.ver)); }
        if self.cipher != CIPHER_ID_THREEFISH1024_STREAM
        || self.mac    != MAC_ID_HMAC_SHA256 { return Err(anyhow!("unknown algorithm identifiers")); }
        Ok(())
    }

    fn as_bytes(&self) -> [u8; HEADER_LEN] {
        // safe because repr(C) with no padding
        unsafe { core::mem::transmute::<Header, [u8; HEADER_LEN]>(*self) }
    }

    fn from_bytes(bytes: &[u8; HEADER_LEN]) -> Self {
        unsafe { core::mem::transmute::<[u8; HEADER_LEN], Header>(*bytes) }
    }
}

/* -------------------------------------------------------------------------- */
/*                                    CLI                                     */
/* -------------------------------------------------------------------------- */

/// Threefish‑1024 + HMAC‑SHA‑256 file encryptor/decryptor
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Encrypt `path`
    #[arg(short='e', long, conflicts_with="decrypt")]
    encrypt: bool,

    /// Decrypt `path`
    #[arg(short='d', long)]
    decrypt: bool,

    /// File to operate on
    path: PathBuf,
}

fn main() -> Result<()> {
    /* ---------- CLI ---------- */
    let cli = Cli::parse();

    /* ---------- Keys ---------- */
    let (cipher_key, mac_key) = load_keyfile(Path::new("key.key"))?;

    /* ---------- Mode ---------- */
    let mode = match (cli.encrypt, cli.decrypt) {
        (true,  false) => Mode::Encrypt,
        (false, true ) => Mode::Decrypt,
        _               => detect_mode(&cli.path)?,
    };

    println!(
        "{} → {}",
        cli.path.display(),
        match mode { Mode::Encrypt => "encrypted", Mode::Decrypt => "decrypted" }
    );

    process_file(&cli.path, mode, &cipher_key, &mac_key)
}

/* -------------------------------------------------------------------------- */
/*                                  DISPATCH                                  */
/* -------------------------------------------------------------------------- */

fn process_file(path: &Path,
                mode: Mode,
                cipher_key: &[u8; 128],
                mac_key:    &[u8; 32]) -> Result<()> {
    match mode {
        Mode::Encrypt => encrypt_file(path, cipher_key, mac_key),
        Mode::Decrypt => decrypt_file(path, cipher_key, mac_key),
    }
}

/* -------------------------------------------------------------------------- */
/*                         CLI AUTO‑DETECTION                                 */
/* -------------------------------------------------------------------------- */

fn detect_mode(path: &Path) -> Result<Mode> {
    let mut f = File::open(path).with_context(|| format!("open {:?}", path))?;
    if f.metadata()?.len() < (HEADER_LEN + MAC_LEN) as u64 {
        return Ok(Mode::Encrypt);        // too small to be ciphertext
    }
    let mut hdr_bytes = [0u8; HEADER_LEN];
    f.read_exact(&mut hdr_bytes)?;
    match Header::from_bytes(&hdr_bytes).validate() {
        Ok(_)  => Ok(Mode::Decrypt),
        Err(_) => Ok(Mode::Encrypt),
    }
}

/* -------------------------------------------------------------------------- */
/*                               KEY HANDLING                                 */
/* -------------------------------------------------------------------------- */

fn load_keyfile(path: &Path)
    -> Result<(Zeroizing<[u8; 128]>, Zeroizing<[u8; 32]>)>
{
    let mut buf = Zeroizing::new([0u8; KEY_BYTES]);
    File::open(path)?.read_exact(buf.as_mut())
        .with_context(|| format!("read key file {path:?}"))?;

    let mut cipher_key = Zeroizing::new([0u8; 128]);
    let mut mac_key    = Zeroizing::new([0u8;  32]);
    cipher_key.copy_from_slice(&buf[..128]);
    mac_key.copy_from_slice(&buf[128..]);
    Ok((cipher_key, mac_key))
}

/* -------------------------------------------------------------------------- */
/*                           STREAM‑CIPHER                                    */
/* -------------------------------------------------------------------------- */

struct StreamCipher<'a> {
    key64:     &'a [u64; 16],
    nonce_hi:  u64,
    nonce_lo:  u64,
    block_idx: u64,
}

impl<'a> StreamCipher<'a> {
    fn new(key64: &'a [u64; 16], nonce_hi: u64, nonce_lo: u64) -> Self {
        Self { key64, nonce_hi, nonce_lo, block_idx: 0 }
    }

    fn xor_in_place(&mut self, mut data: &mut [u8]) {
        let mut ks_words   = Zeroizing::new([0u64; 16]);      // reused
        let mut keystream  = Zeroizing::new([0u8 ; BLOCK_SIZE]);

        while !data.is_empty() {
            let tweak = [self.nonce_hi,
                         self.block_idx ^ self.nonce_lo];
            self.block_idx = self.block_idx.checked_add(1)
                                          .expect("u64 overflow");

            let cipher = Threefish1024::new_with_tweak_u64(self.key64, &tweak);
            cipher.encrypt_block_u64(&mut ks_words);

            for (i, w) in ks_words.iter().enumerate() {
                keystream[i*8 .. (i+1)*8].copy_from_slice(&w.to_le_bytes());
            }

            let n = data.len().min(BLOCK_SIZE);
            for (b,k) in data[..n].iter_mut().zip(&keystream[..n]) {
                *b ^= *k;
            }
            data = &mut data[n..];
        }
    }
}

/* -------------------------------------------------------------------------- */
/*                                ENCRYPTION                                  */
/* -------------------------------------------------------------------------- */

fn encrypt_file(src: &Path, cipher_key: &[u8;128], mac_key: &[u8;32]) -> Result<()> {
    let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src)?);

    let tmp = NamedTempFile::new_in(src.parent().ok_or_else(|| anyhow!("no parent dir"))?)?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp.reopen()?);

    /*  header  */
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let hdr = Header::new(nonce);
    let hdr_bytes = hdr.as_bytes();
    writer.write_all(&hdr_bytes)?;

    /*  MAC  */
    let mut hmac = HmacSha256::new_from_slice(mac_key)?;
    hmac.update(&hdr_bytes);

    /*  cipher  */
    let key64 = to_u64_key(cipher_key);
    let mut sc = StreamCipher::new(&key64,
                                   u64::from_be_bytes(nonce[0..8].try_into().unwrap()),
                                   u64::from_be_bytes(nonce[8..16].try_into().unwrap()));

    let mut buf = Zeroizing::new([0u8; IO_BUF_SIZE]);
    loop {
        let n = reader.read(buf.as_mut())?;
        if n == 0 { break; }
        sc.xor_in_place(&mut buf[..n]);
        hmac.update(&buf[..n]);
        writer.write_all(&buf[..n])?;
    }

    writer.write_all(&hmac.finalize().into_bytes())?;
    writer.flush()?; writer.get_ref().sync_all()?; tmp.as_file().sync_all()?;

    promote_with_backup(src, tmp.path())
}

/* -------------------------------------------------------------------------- */
/*                                DECRYPTION                                  */
/* -------------------------------------------------------------------------- */

fn decrypt_file(src: &Path, cipher_key: &[u8;128], mac_key: &[u8;32]) -> Result<()> {
    let mut reader = BufReader::with_capacity(IO_BUF_SIZE, File::open(src)?);

    /*  header  */
    let mut hdr_bytes = [0u8; HEADER_LEN];
    reader.read_exact(&mut hdr_bytes)?;
    let hdr = Header::from_bytes(&hdr_bytes); hdr.validate()?;

    let nonce_hi = u64::from_be_bytes(hdr.nonce[0..8].try_into().unwrap());
    let nonce_lo = u64::from_be_bytes(hdr.nonce[8..16].try_into().unwrap());

    /*  prep  */
    let mut hmac = HmacSha256::new_from_slice(mac_key)?; hmac.update(&hdr_bytes);
    let key64 = to_u64_key(cipher_key);
    let mut sc = StreamCipher::new(&key64, nonce_hi, nonce_lo);

    /*  tmp plaintext file  */
    let tmp = NamedTempFile::new_in(src.parent().ok_or_else(|| anyhow!("no parent dir"))?)?;
    let mut writer = BufWriter::with_capacity(IO_BUF_SIZE, tmp.reopen()?);

    /*  ciphertext → MAC verify & decrypt  */
    let file_len = reader.get_ref().metadata()?.len();
    let cipher_len = file_len.checked_sub((HEADER_LEN + MAC_LEN) as u64)
                             .ok_or_else(|| anyhow!("file too small"))?;
    let mut remaining = cipher_len;
    let mut buf = Zeroizing::new([0u8; IO_BUF_SIZE]);

    while remaining != 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..n])?;
        hmac.update(&buf[..n]);
        sc.xor_in_place(&mut buf[..n]);
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
    }

    /*  MAC  */
    let mut mac_on_disk = [0u8; MAC_LEN];
    reader.read_exact(&mut mac_on_disk)?;
    hmac.verify_slice(&mac_on_disk).map_err(|_| anyhow!("authentication failed"))?;

    writer.flush()?; writer.get_ref().sync_all()?; tmp.as_file().sync_all()?;
    promote_with_backup(src, tmp.path())
}

/* -------------------------------------------------------------------------- */
/*                               FILE PROMOTION                               */
/* -------------------------------------------------------------------------- */

fn promote_with_backup(final_path: &Path, tmp_path: &Path) -> Result<()> {
    let bak = final_path.with_extension("bak");
    let _ = fs::remove_file(&bak);
    fs::rename(final_path, &bak).ok();          // fine if original absent

    match fs::rename(tmp_path, final_path) {
        Ok(_)  => { let _ = fs::remove_file(&bak); Ok(()) },
        Err(e) => { let _ = fs::rename(&bak, final_path);
                    Err(e).context("failed to promote temp file") }
    }
}

/* -------------------------------------------------------------------------- */
/*                               UTILITIES                                    */
/* -------------------------------------------------------------------------- */

fn to_u64_key(key: &[u8;128]) -> [u64;16] {
    let mut out = [0u64;16];
    for (i,chunk) in key.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

/* -------------------------------------------------------------------------- */
/*                                   TESTS                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::io::{Seek, Write};

    fn random_key() -> ([u8;128],[u8;32]) {
        let mut k = [0u8; KEY_BYTES]; OsRng.fill_bytes(&mut k);
        File::create("key.key").unwrap().write_all(&k).unwrap();
        let mut ck=[0u8;128]; let mut mk=[0u8;32];
        ck.copy_from_slice(&k[..128]); mk.copy_from_slice(&k[128..]);
        (ck,mk)
    }

    #[test] fn small_roundtrip() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hello").unwrap();
        let (ck,mk)=random_key();
        encrypt_file(f.path(),&ck,&mk).unwrap();
        decrypt_file(f.path(),&ck,&mk).unwrap();
        let mut v=Vec::<u8>::new(); File::open(f.path()).unwrap().read_to_end(&mut v).unwrap();
        assert_eq!(v,b"hello");
        let _ = fs::remove_file("key.key");
    }

    #[test] fn mac_fail() {
        let mut f=tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        let (ck,mk)=random_key();
        encrypt_file(f.path(),&ck,&mk).unwrap();

        // flip byte
        let mut fh = File::options().read(true).write(true).open(f.path()).unwrap();
        fh.seek(SeekFrom::Start(HEADER_LEN as u64 + 1)).unwrap();
        let mut b=[0u8;1]; fh.read_exact(&mut b).unwrap(); b[0]^=0x55;
        fh.seek(SeekFrom::Current(-1)).unwrap(); fh.write_all(&b).unwrap();

        assert!(decrypt_file(f.path(),&ck,&mk).is_err());
        let _ = fs::remove_file("key.key");
    }
}
