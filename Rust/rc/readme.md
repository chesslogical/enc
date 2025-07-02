# rc (Rust Crypt)

A simple, bulletproof Rust CLI for encrypting and decrypting files using **AES-256-GCM**. Designed for reliability and data safety, with a hard‑coded password and salt near the top of the source for easy configuration.

---

## Benefits

* **No memorization required for informal use**
  Keys and passwords are embedded at compile time, so you don’t need to remember or manage credentials for quick, throwaway encryption tasks.

* **Binary diversity**
  Each build of `rc` can use different embedded credentials or compilation options, producing unique binaries. You can even encrypt one `rc` binary with another to create layered protection.

* **Strong, authenticated encryption**
  Under the hood, `rc` uses AES‑256‑GCM, providing 256‑bit security with both confidentiality and integrity. The 12‑byte nonce and robust PBKDF2‑SHA256 key derivation guard against replay, tampering, and brute‑force attacks.

---

## Features

* **AES‑256‑GCM** for authenticated encryption (confidentiality + integrity)
* **PBKDF2‑SHA256** key derivation (100,000 iterations)
* Built with **Clap** for clean CLI interface
* Hard‑coded `PASSWORD` and `SALT` constants for straightforward setup
* Cross‑platform: works on Linux, macOS, Windows
* Integrates seamlessly into scripts to batch‑process files

---

## Prerequisites

* Rust toolchain (1.65+)
* `cargo` available in your `$PATH`

---

## Installation

Clone the repo and build in release mode:

```bash
git clone https://github.com/yourusername/rc.git
cd rc
cargo build --release
# The binary will be at target/release/rc
```

---

## Configuration

Open `src/main.rs` and modify the top constants before compiling:

```rust
const PASSWORD: &str = "CHANGE_THIS_PASSWORD";
const SALT: &[u8]     = b"CHANGE_THIS_SALT";
```

Rebuild after any change:

```bash
cargo build --release
```

> **Tip:** For more flexible key management, replace the `const` values with environment‑variable reads or a config file.

---

## Usage

```text
USAGE:
    rc <COMMAND>

COMMANDS:
    encrypt    Encrypt a file
    decrypt    Decrypt a file
```

### Encrypt

```bash
rc encrypt -i plain.txt -o ciphertext.bin
```

* `-i, --input`  Path to plaintext file
* `-o, --output` Path to write ciphertext

### Decrypt

```bash
rc decrypt -i ciphertext.bin -o recovered.txt
```

* `-i, --input`  Path to ciphertext file
* `-o, --output` Path to write decrypted plaintext

---

## Scripting Examples

Once the `rc` binary is built, you can batch‑process many files via shell scripts.

### Bash (Linux/macOS)

Encrypt all `.txt` files:

```bash
#!/usr/bin/env bash
set -euo pipefail

for src in *.txt; do
  out="${src%.txt}.enc"
  echo "Encrypting $src → $out"
  rc encrypt -i "$src" -o "$out"
done
```

Decrypt all `.enc` back to `.dec.txt`:

```bash
#!/usr/bin/env bash
set -euo pipefail

for src in *.enc; do
  out="${src%.enc}.dec.txt"
  echo "Decrypting $src → $out"
  rc decrypt -i "$src" -o "$out"
done
```

Recursively encrypt with `find`:

```bash
find . -name '*.txt' -print0 | \
  while IFS= read -r -d '' src; do
    dst="${src%.txt}.enc"
    echo "Encrypting $src → $dst"
    rc encrypt -i "$src" -o "$dst"
  done
```

Parallelize with GNU Parallel:

```bash
find . -name '*.txt' -print0 \
  | parallel -0 rc encrypt -i {} -o {.}.enc
```

---

### Windows Batch (.bat)

```bat
@echo off
setlocal enabledelayedexpansion

for %%F in (*.txt) do (
  set "outfile=%%~nF.enc"
  echo Encrypting %%F -> !outfile!
  rc.exe encrypt -i "%%F" -o "!outfile!"
)
```

---

### PowerShell

```powershell
Get-ChildItem -Filter *.txt | ForEach-Object {
  $out = "${($_.BaseName)}.enc"
  Write-Host "Encrypting $($_.Name) → $out"
  & rc encrypt -i $_.FullName -o $out
}
```

> **Tip:** Halt on errors (`set -o errexit` in bash, `|| exit /b %ERRORLEVEL%` in batch) and redirect logs for auditing:

```bash
rc encrypt -i ... > encrypt.log 2>&1
```

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Open a pull request

Please adhere to Rust API guidelines and include tests for new functionality.

---

## License

This project is licensed under the [MIT License](LICENSE).

