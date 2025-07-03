# Threefish CLI – Authenticated Stream‑Cipher File Encryptor

SIMPLE! Runs on one command, the file to process, and it encrypts or encrypts it automatically! 

A minimal, no‑nonsense command‑line utility that transparently **encrypts and decrypts files in‑place** using a Threefish‑1024 stream cipher and HMAC‑SHA‑256 authentication.

---

## ✨ Features

* **Strong encryption** – 1024‑bit Threefish block cipher operated in a counter‑style stream mode.
* **Built‑in authentication** – 256‑bit HMAC‑SHA‑256 covers *header + ciphertext* to prevent undetected tampering.
* **Nonce‑based keystream** – 128‑bit random nonce per file; identical plaintexts yield distinct ciphertexts.
* **Atomic updates** – Encrypts/decrypts to a temporary file and then atomically renames, leaving a `.bak` backup of the original.
* **Key hygiene** – Encryption and MAC keys are held in `Zeroizing` buffers so RAM is wiped on drop.
* **Self‑detecting mode** – Omits the `-e / -d` flag if the file header already identifies ciphertext.
* **Portable, dependency‑light** – Pure‑Rust implementation; only depends on `threefish`, `hmac`, `sha2`, and `rand`.

---

## 🔐 Security Model

| Property             | Details                                                                                                      |     |            |         |      |          |           |
| -------------------- | ------------------------------------------------------------------------------------------------------------ | --- | ---------- | ------- | ---- | -------- | --------- |
| Cipher               | Threefish‑1024 (block size = 128 bytes)                                                                      |     |            |         |      |          |           |
| Mode                 | Counter‑like stream mode with 128‑bit nonce ‖ 64‑bit block index tweak                                       |     |            |         |      |          |           |
| Authentication       | HMAC‑SHA‑256 over header + ciphertext                                                                        |     |            |         |      |          |           |
| Key material         | **160 bytes** total ⇒ `key.key` file<br>  • first 128 bytes → Threefish key<br>  • last 32 bytes  → HMAC key |     |            |         |      |          |           |
| Header (48 bytes BE) | \`"T1FS"                                                                                                     | ver | cipher\_id | mac\_id | rsvd | nonce128 | 24 rsvd\` |
| MAC tag              | 32 bytes appended to file end                                                                                |     |            |         |      |          |           |

> **Threat model**: designed to safeguard at‑rest file contents against disclosure or alteration by an offline adversary. It does **not** provide deniability or forward secrecy and assumes the key file stays secret.

---

## 🏗️ Building

```bash
# Requires stable Rust ≥ 1.76
cargo build --release
```

The resulting binary will be at `target/release/threefish_cli`.

---

## 🔑 Generating a Key File

The program expects a 160‑byte file named **`key.key`** in the working directory.

```bash
# Unix-like systems – using OpenSSL
openssl rand -out key.key 160

# Windows (PowerShell ≥ 5)
# NOTE: Requires OpenSSL or another random‑byte source
```

Keep this file *secret* and *backed‑up*; losing it renders data unrecoverable.

---

## 🚀 Usage

```text
threefish_cli [--encrypt | --decrypt] <FILE>
```

### Examples

#### Encrypt a file (explicit)

```bash
threefish_cli --encrypt secrets.db
```

Output: `secrets.db` → encrypted, original saved as `secrets.db.bak`.

#### Decrypt (auto‑detect)

```bash
threefish_cli secrets.db   # header indicates ciphertext
```

If MAC verification fails, decryption aborts with `authentication failed`.

> **Tip:** omit the flag to let the tool decide based on the 4‑byte magic and version.

---

## 🧪 Running Tests

```bash
cargo test --all-features --all-targets
```

The test‑suite covers:

* Small‑file round‑trip
* Non‑block‑aligned lengths
* Tamper detection
* Multi‑MiB datasets

---

## 📄 File Format in Detail

```
Offset  Size  Field                     Description
0x00    4     "T1FS"                   Magic
0x04    1     0x01                     Version
0x05    1     0x01                     Cipher ID (Threefish1024‑Stream)
0x06    1     0x01                     MAC ID (HMAC‑SHA‑256)
0x07    1     Reserved (0x00)
0x08    16    Nonce N                  128‑bit random number
0x18    24    Reserved (zero)         For future use
...     ...   Ciphertext              Stream‑encrypted payload
EOF‑32  32    MAC tag T               HMAC‑SHA‑256(header ‖ ciphertext)
```

---

## 🛠️ Internals & Design Notes

* **StreamCipher** is a stateless helper that feeds block‑indexed tweaks into Threefish and XORs the resulting keystream.
* **Authentication‑then‑Encrypt**: HMAC is computed *during* streaming; the plaintext never touches disk unencrypted.
* **Temp file promotion** ensures power‑failure safety and preserves a backup copy of the previous state.
* **Error handling** uses `anyhow::Result` for readable context‑rich messages.

---

## ⚠️ Caveats 

* No key‑derivation or password‑based mode – relies on raw key file- that is on purpose for max security.
* No parallelism; large files process sequentially (could adopt Rayon). (maybe later) 
* Header reserves 24 bytes for potential algorithm agility (e.g. AEAD, Argon2 salt).


---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feat/my‑feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feat/my‑feature`)
5. Open a Pull Request

---

## 📜 License

Licensed under either of

* Apache License, Version 2.0
* MIT license

at your option.

See `LICENSE-*` files for details.

---

## 🙏 Acknowledgements

* [Threefish cipher](https://www.schneier.com/skein/) by Niels Ferguson, Stefan Lucks, et al.
* \[`hmac`], \[`sha2`], \[`rand`], and \[`zeroize`] crates by the RustCrypto project.
* Inspired by OpenBSD `encrypt(1)` file‑encryption concepts.

