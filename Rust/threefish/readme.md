### Why the key file is **223 bytes**

Yes—that size is expected.

| Field                       | Bytes         |
| --------------------------- | ------------- |
| Magic `"TKF2"`              | 4             |
| Version                     | 1             |
| KDF ID (`0x13` = Argon2id)  | 1             |
| Argon2 memory (u32 LE)      | 4             |
| Argon2 iterations (u32 LE)  | 4             |
| Argon2 parallelism (u8)     | 1             |
| Salt                        | 16            |
| Cipher‑key (Threefish‑1024) | 128           |
| MAC‑key (HMAC‑SHA‑256)      | 32            |
| SHA‑256 checksum            | 32            |
| **Total**                   | **223 bytes** |

The format is fixed‑width and self‑describing, so every key file created with `--keygen` will be **exactly 223 bytes**.

---

# threefish‑cli

*Threefish‑1024 + HMAC‑SHA‑256 file encryptor / decryptor*

![license: MIT](https://img.shields.io/badge/license-MIT-blue)

---

## Features

| Capability          | Detail                                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------- |
| **Confidentiality** | Threefish‑1024 used in stream‑cipher mode (encrypt‑zero, XOR).                                            |
| **Integrity**       | Encrypt‑then‑MAC with HMAC‑SHA‑256 (256‑bit tag).                                                         |
| **Atomic writes**   | Data is written to a temp file, flushed, synced, then atomically promoted.                                |
| **Password‑to‑key** | `--keygen` derives a deterministic 160‑byte key (128 B cipher + 32 B MAC) from a password using Argon2id. |
| **Cross‑platform**  | Pure Rust, no `unsafe`, builds on Linux / macOS / Windows.                                                |

---

## Quick start

```console
# 1. Build
cargo build --release
./target/release/threefish_cli --help

# 2. Create key file from password (prompts twice)
./threefish_cli --keygen

# key.key now exists (223 bytes, mode 600 on Unix)

# 3. Encrypt a file (auto‑detects mode)
./threefish_cli secret.txt

# 4. Decrypt the same file
./threefish_cli secret.txt
```

> **Important:** possession of `key.key` implies full access.
> Store it securely and back it up.

---

## File formats

### Ciphertext

```
| "T1FS" | 02 | 01 | 01 | 00 |  NONCE(16) | CIPHERTEXT | TAG(32) |
   magic   ver  enc   mac  pad               128‑bit      HMAC‑SHA‑256
                     id   id                                   footer
```

* Nonce is selected randomly for every encryption.
* Tag = HMAC‑SHA‑256(header ∥ ciphertext).

### Key file v2 (`TKF2`)

| Offset | Bytes | Meaning                                |
| ------ | ----- | -------------------------------------- |
| 0      | 4     | `"TKF2"` magic                         |
| 4      | 1     | Version (`0x02`)                       |
| 5      | 1     | KDF ID (`0x13` = Argon2id)             |
| 6      | 4     | Argon2 memory (KiB, LE)                |
| 10     | 4     | Argon2 iterations (LE)                 |
| 14     | 1     | Argon2 parallelism                     |
| 15     | 16    | Salt                                   |
| 31     | 160   | 128‑byte cipher key ‖ 32‑byte MAC key  |
| 191    | 32    | SHA‑256 checksum of all previous bytes |

Total: **223 bytes**.

---

## Security notes

* **Authenticate before decrypting.**
  Decryption is a *second pass* performed only after the tag is verified.
* **Zeroization.**
  All secret buffers (`cipher_key`, `mac_key`, derived keys) are wrapped in [`Zeroizing`](https://docs.rs/zeroize) and wiped on drop.
* **Argon2id defaults**

  * 64 MiB memory
  * 3 iterations
  * parallelism = `min(logical‑CPUs, 4)`
    Tune with `--kdf-mem`, `--kdf-iters`, `--kdf-par`.

---

## Command‑line reference

```
threefish_cli [OPTIONS] <file>

OPTIONS:
  -e, --encrypt          Force encryption mode
  -d, --decrypt          Force decryption mode
  -k, --keygen           Create key.key from password (no file operand)
      --overwrite        Allow --keygen to overwrite an existing key
      --key <FILE>       Path to key file [default: key.key]
      --kdf-mem <KiB>    Argon2id memory (KiB) for --keygen
      --kdf-iters <N>    Argon2id iterations for --keygen
      --kdf-par <N>      Argon2id parallelism for --keygen
  -h, --help             Print help
  -V, --version          Print version
```

If neither `--encrypt` nor `--decrypt` is given, the program inspects the file
header and decides automatically.

---

## Development

```console
# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Audit dependencies
cargo audit
```

CI runs on Linux, macOS and Windows (stable Rust).

---

## License

MIT © 2025, your‑name‑or‑organisation.
