\# threefish\\\_cli



\*\*Threefish-1024 + HMAC-SHA-256 CLI File Encryptor/Decryptor\*\*



A lightweight, high-security command-line utility to encrypt and decrypt files using the Threefish-1024 stream cipher combined with HMAC-SHA-256 authentication. It operates in a streaming fashion, supports atomic file replacement with backups, and keeps cryptographic keys in an external key file.



---



\## Table of Contents



1\. \[Features](#features)

2\. \[Getting Started](#getting-started)



&nbsp;  \* \[Prerequisites](#prerequisites)

&nbsp;  \* \[Installation](#installation)

3\. \[Usage](#usage)



&nbsp;  \* \[Basic Commands](#basic-commands)

&nbsp;  \* \[Options](#options)

4\. \[File Format \& Header](#file-format--header)

5\. \[Key File](#key-file)

6\. \[Design \& Internals](#design--internals)



&nbsp;  \* \[One-Pass Decryption](#one-pass-decryption)

&nbsp;  \* \[StreamCipher Implementation](#streamcipher-implementation)

&nbsp;  \* \[Typed Header Struct](#typed-header-struct)

&nbsp;  \* \[Zeroizing Sensitive Buffers](#zeroizing-sensitive-buffers)

7\. \[Error Handling](#error-handling)

8\. \[Security Considerations](#security-considerations)



&nbsp;  \* \[Nonce Uniqueness](#nonce-uniqueness)

&nbsp;  \* \[MAC Verification](#mac-verification)

&nbsp;  \* \[Atomic File Replacement](#atomic-file-replacement)

9\. \[Performance Optimizations](#performance-optimizations)

10\. \[Testing](#testing)

11\. \[Contributing](#contributing)

12\. \[License](#license)



---



\## Features



\* \*\*Streaming Encryption \& Decryption\*\*: Processes files in constant memory, ideal for large files.

\* \*\*Authenticated Encryption\*\*: Uses HMAC-SHA-256 to ensure integrity and authenticity.

\* \*\*Atomic Replacement\*\*: Writes to a temporary file and renames with a `.bak` backup on success.

\* \*\*External Keyfile\*\*: Keeps a 160-byte key file (`128 B` cipher key + `32 B` MAC key) out-of-band.

\* \*\*Progressive CLI\*\*: Built with `clap` derive for ergonomic flags, `--help`, and `--version`.

\* \*\*Zeroized Buffers\*\*: Sensitive data is zeroed on drop to reduce in-memory exposure.

\* \*\*Typed Header\*\*: Clear representation of file header fields with field-wise validation.

\* \*\*One-Pass Decryption\*\*: Verifies and decrypts in a single streaming pass, halving I/O.



---



\## Getting Started



\### Prerequisites



\* \*\*Rust toolchain\*\*: Rust 1.65+ (with `cargo`)

\* \*\*Operating System\*\*: Cross-platform (Windows, macOS, Linux)



\### Installation



```bash

\# Clone the repository

git clone https://github.com/yourusername/threefish\_cli.git

cd threefish\_cli



\# Build the release binary

cargo build --release



\# (Optional) Install to your Cargo bin directory

cargo install --path .

```



After installation, the `threefish\_cli` executable will be available in your `$PATH`.



---



\## Usage



```text

threefish\_cli \[OPTIONS] <FILE>

```



\### Basic Commands



\* \*\*Encrypt a file\*\* (auto-detect or force):



&nbsp; ```bash

&nbsp; threefish\_cli --encrypt secret.txt

&nbsp; ```

\* \*\*Decrypt a file\*\* (auto-detect or force):



&nbsp; ```bash

&nbsp; threefish\_cli --decrypt secret.txt.enc

&nbsp; ```

\* \*\*Auto-detect mode\*\* (inspect header):



&nbsp; ```bash

&nbsp; threefish\_cli data.bin

&nbsp; ```



\### Options



| Flag              | Description                                       |

| ----------------- | ------------------------------------------------- |

| `-e`, `--encrypt` | Force encryption mode (treat input as plaintext)  |

| `-d`, `--decrypt` | Force decryption mode (treat input as ciphertext) |

| `-h`, `--help`    | Print help information                            |

| `-V`, `--version` | Print version information                         |



---



\## File Format \& Header



All ciphertext files produced by `threefish\_cli` begin with a fixed-size 48 B header:



```text

Offset | Length | Field

-------|--------|----------------------------

0x00   | 4      | Magic (`"T1FS"`)

0x04   | 1      | Version (`0x01`)

0x05   | 1      | Cipher ID (`0x01` for Threefish1024)

0x06   | 1      | MAC ID (`0x01` for HMAC-SHA256)

0x07   | 1      | Reserved (zero)

0x08   | 16     | Nonce (128‑bit)

0x18   | 24     | Reserved (zero)

```



After the header:



1\. \*\*Ciphertext stream\*\* encrypted via Threefish1024 in counter-tweak mode.

2\. \*\*32 byte\*\* HMAC-SHA256 tag authenticating header + ciphertext.



---



\## Key File



The key file (`key.key`) must be exactly \*\*160 bytes\*\*:



\* \*\*First 128 bytes\*\*: Threefish1024 cipher key.

\* \*\*Next 32 bytes\*\*: HMAC-SHA256 key.



\*No keyfile generation is provided by this utility\*; supply your own, or use a companion tool that writes 160 cryptographically-random bytes.



---



\## Design \& Internals



\### One-Pass Decryption



Instead of reading the file twice (MAC verify then decrypt), we:



1\. Initialize HMAC and Threefish stream cipher with extracted nonce.

2\. For each chunk of ciphertext:



&nbsp;  \* Update HMAC.

&nbsp;  \* Decrypt in-place.

&nbsp;  \* Write plaintext to temp file.

3\. After streaming, read on-disk MAC tag and verify.

4\. If successful, atomically replace original file with plaintext.



This halves disk I/O and simplifies retries on failure.



\### StreamCipher Implementation



\* \*\*Keystream buffers\*\* (`ks\_words`, `keystream`) are allocated once and wrapped in `Zeroizing`.

\* Counter/tweak per block: `tweak = (nonce\_hi, nonce\_lo ^ block\_idx)`.

\* XOR in-place for streaming speed.



\### Typed Header Struct



Using a `#\[repr(C)] struct Header` ensures:



\* Reserved bytes are always zero.

\* Safe, field-wise validation.

\* Easy `transmute` to/from byte arrays without per-field copying.



\### Zeroizing Sensitive Buffers



All ephemeral buffers that hold key material, keystream words, and plaintext chunks use `Zeroizing<T>` to clear memory when dropped.



---



\## Error Handling



\* \*\*`anyhow`\*\* for ergonomic error propagation and context.

\* CLI flags auto-validate via `clap` derive (mutually-exclusive `-e/-d`).

\* Detailed context on file I/O, key loading, header parsing, and MAC failures.



---



\## Security Considerations



\### Nonce Uniqueness



\*\*Critical\*\*: Never reuse the same key/nonce pair. The 128-bit nonce is randomly generated with `OsRng` per encryption.



\### MAC Verification



The HMAC covers both the header and ciphertext.  If verification fails, decryption aborts and no data is written to the original file.



\### Atomic File Replacement



On success, the original file is backed up with a `.bak` extension, and the temp file is renamed. In case of crash or power loss, either the old file (`.bak`) or new file remains intact.



---



\## Performance Optimizations



1\. \*\*Reused Keystream Buffers\*\*: Avoids per-block allocations.

2\. \*\*One-Pass Decrypt\*\*: Halves I/O operations.

3\. \*\*Buffered I/O\*\*: 16 KiB buffer to balance syscalls vs memory use.

4\. \*\*Optional Progress Bar\*\*: (Suggest `indicatif` integration) for large files.



---



\## Testing



\* \*\*Unit Tests \& Roundtrip\*\*: Small file, non-block-multiple, large (\\~2 MiB+3 bytes).

\* \*\*MAC Failure Test\*\*: Flip a byte and assert decryption error.

\* \*\*Property-Based/Fuzzing\*\*: (\*future\*) integrate `proptest` to validate random inputs.



Run tests via:



```bash

cargo test -- --nocapture

```



---



\## Contributing



1\. Fork the repo and create a feature branch.

2\. Write tests for new functionality.

3\. Submit a pull request with detailed description.

4\. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.



---



\## License



This project is licensed under the \*\*MIT License\*\*. See \[LICENSE](LICENSE) for details.



---



Thank you for using `threefish\_cli`! Secure your files with confidence.



