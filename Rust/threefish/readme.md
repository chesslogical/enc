# Threefish CLI – Authenticated Stream‑Cipher File Encryptor

SIMPLE! Runs on one command with an optional flag, processes the file in-place, and transparently encrypts or decrypts it based on its header.

A minimal, no‑nonsense CLI that uses Threefish‑1024 in a counter‑style stream mode plus HMAC‑SHA‑256 authentication to protect your files.

---

## ✨ Features

* **Strong, future‑proof encryption** – Threefish‑1024 block cipher (128 B block size) in tweakable counter mode.
* **Built‑in authentication** – HMAC‑SHA‑256 covers both the 48 B header and the ciphertext to detect any tampering.
* **Random nonces** – 128‑bit OS‑random nonce per file; identical plaintexts produce distinct ciphertexts.
* **One‑pass decryption** – Verifies MAC and decrypts in a single streaming pass, cutting I/O in half.
* **Atomic updates with backup** – Writes to a temp file, verifies/authenticates, then renames over the original and leaves a `.bak` backup.
* **Zeroized buffers** – Ephemeral keys, keystream words, and I/O buffers are wrapped in `Zeroizing` so memory is cleared on drop.
* **Typed header struct** – A `#[repr(C)] Header` ensures reserved bytes are always zero and field‑wise validation is straightforward.
* **Ergonomic CLI** – Powered by `clap` derive, with `--encrypt`/`--decrypt` flags, auto‑help/version, and mutually‑exclusive mode flags.
* **Portable & lightweight** – Pure Rust with only `threefish`, `hmac`, `sha2`, `rand`, `tempfile`, and `zeroize` dependencies.

---

## 🔐 Security Model

Designed to protect your files at rest against offline attackers. Does **not** provide deniability or forward secrecy and assumes your external key file remains secret.

**Cipher**: Threefish‑1024 (1024 bits key, 128 B block) in counter‑style tweakable mode

**Authentication**: HMAC‑SHA‑256 over `header || ciphertext`

**Key material**: 160 bytes total in `key.key`:

* First 128 bytes → Threefish key
* Next 32 bytes  → HMAC key

**Header (48 bytes, big‑endian)**

```text
"T1FS"    (4 B magic)
0x01       (1 B version)
0x01       (1 B cipher ID)
0x01       (1 B MAC ID)
0x00       (1 B reserved)
<16 B nonce>
<24 B reserved, zero>
```

**Nonce requirement**: Must be unique per encryption under the same key. Generated with `OsRng`.

**MAC tag**: 32 bytes appended after ciphertext; decryption aborts if verification fails.

---

## 🏗️ Building

Requires Rust 1.65+.

```bash
git clone https://github.com/yourusername/threefish_cli.git
cd threefish_cli
cargo build --release
```

Your `threefish_cli` binary will appear in `target/release/`.

---

## 🔑 Generating a Key File

Create a 160‑byte random key file named **`key.key`** in the directory where you run the CLI:

```bash
# Unix-like
openssl rand -out key.key 160

# Windows (PowerShell)
# Requires a CSPRNG source; e.g. via OpenSSL or other tool
```

**Keep `key.key` secret** and back it up. Losing this file makes data unrecoverable.

---

## 🚀 Usage

```text
threefish_cli [--encrypt | --decrypt] <FILE>
```

* **Encrypt** explicitly:

  ```bash
  threefish_cli --encrypt secrets.db
  ```

  Encrypts `secrets.db`, leaves `secrets.db.bak` as backup.

* **Decrypt** explicitly:

  ```bash
  threefish_cli --decrypt secrets.db
  ```

* **Auto‑detect** mode (recommended):

  ```bash
  threefish_cli secrets.db
  ```

  The utility inspects the 4‑byte magic & version; if valid, it decrypts, otherwise it encrypts.

> **Tip:** Omit flags to let the tool pick the right action by header.

---

## 🧪 Running Tests

```bash
cargo test --all-targets -- --nocapture
```

Tests include:

* Small‑file roundtrips
* Non‑block multiple lengths
* MAC‑failure detection
* Large (multi‑MiB) datasets

---

## 📄 File Format in Detail

```text
Offset  Size  Field         Description
------  ----  --------      --------------------------------------------
0x00     4 B  Magic         "T1FS"
0x04     1 B  Version       0x01
0x05     1 B  Cipher ID     0x01 (Threefish1024-Stream)
0x06     1 B  MAC ID        0x01 (HMAC-SHA256)
0x07     1 B  Reserved      Zero
0x08    16 B  Nonce         128-bit random
0x18    24 B  Reserved      Zero (future algorithm agility)
...     ...   Ciphertext    Stream-encrypted payload
EOF-32  32 B  MAC Tag       HMAC-SHA256(header ‖ ciphertext)
```

---

## 🛠️ Internals & Design Notes

* **CLI parsing**: `clap` derive auto‑generates help/version and enforces `--encrypt`/`--decrypt` exclusivity.
* **Header struct**: `#[repr(C)] Header` zeroes reserved fields and simplifies (de)serialization via `transmute`.
* **StreamCipher**: Reuses a single `ks_words` and `keystream` buffer wrapped in `Zeroizing` to avoid reallocs and clear memory on drop.
* **One-pass decrypt**: During streaming, HMAC is updated, data is decrypted & written to temp, then final MAC is verified before promotion.
* **Atomic promotion**: Writes to `NamedTempFile`, syncs both data & directory metadata, then renames with a `.bak` fallback.

---

## ⚠️ Caveats & Future Work

* No password‑based key derivation (PBKDF2, Argon2) – raw key file required.
* No parallel file processing; could leverage Rayon for chunk‑parallelism.
* Agility reserved but not implemented: future AEAD or multiple key slots.
* Progress bar integration (e.g. `indicatif`) suggested for large files.

---

## 🤝 Contributing

1. Fork this repo
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Implement your changes with tests
4. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` pass
5. Open a Pull Request describing your feature

---

## 📜 License

Licensed under either:

* MIT License
* Apache License 2.0

Choose whichever suits your project requirements.

---

## 🙏 Acknowledgements

* Threefish design by Bruce Schneier, Niels Ferguson, Stefan Lucks, et al.
* RustCrypto crates: `threefish`, `hmac`, `sha2`, `rand`, `zeroize`.
* Inspired by OpenBSD encrypt(1) style atomic file workflows.
