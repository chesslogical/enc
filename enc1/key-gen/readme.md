# dkey – Deterministic High‑Strength Key Generator



Generate reproducible (key = \*deterministic\*) cryptographic keystreams of \*\*any size\*\* using modern primitives (Argon2id, BLAKE dkey – Deterministic High‑Strength Key Generator



Generate reproducible (key = \*deterministic\*) cryptographic keystreams of \*\*any size\*\* using modern primitives (Argon2id, BLAKE3, ChaCha20).

Ideal for \*\*one‑time pads\*\*, \*\*test fixtures\*\*, reproducible random data in CI, or any workflow where \*the same inputs must always yield the same bytes\*.



---



## ✨ Features



| Category                  | Details                                                                                    |

| ------------------------- | ------------------------------------------------------------------------------------------ |

| \*\*Deterministic\*\*         | Same \*password ✕ salt ✕ Argon2 params ✕ algorithm ✕ size\* → identical output, bit‑for‑bit. |

| \*\*Modern crypto\*\*         | • Argon2id KDF<br>• BLAKE3 XOF (default)<br>• ChaCha20 stream option.                      |

| \*\*Strong defaults\*\*       | 512 MiB memory, 10 passes, 1 thread – tunable via flags.                                   |

| \*\*Secret hygiene\*\*        | Password, salt, and seed are zero‑wiped from RAM (`zeroize`).                              |

| \*\*Constant‑time checks\*\*  | Password confirmation rejects on \*fixed time\*; no leak.                                    |

| \*\*Human‑friendly sizes\*\*  | `1gb`, `256MiB`, `42\_000`, etc. Decimal \*\*and\*\* binary suffixes.                           |

| \*\*Self‑contained binary\*\* | No runtime deps—ship one executable.                                                       |

| \*\*MIT OR Apache‑2.0\*\*     | Choose the license that suits you.                                                         |



---



## 📦 Building



```console

$ git clone https://github.com/you/dkey.git

$ cd dkey

$ cargo build --release     # requires Rust 1.79+ (edition 2024)

```



Result: `target/release/dkey` (or `dkey.exe` on Windows).



---



## 🚀 Quick start



```console

\# 256‑MiB key, BLAKE3 (default), saved to my.key

$ dkey 256mib -o my.key



\# 1‑GiB key, ChaCha20 stream, custom Argon2 params

$ dkey 1gib -a chacha \\

&nbsp;     --argon2-memory 1024 --argon2-time 4 \\

&nbsp;     --salt "$(openssl rand -base64 16)"

```



> \*\*Password prompts\*\*

> `dkey` always asks twice (constant‑time comparison).

> If you need non‑interactive use, pipe via a tool such as `expect` \*\*only on an encrypted channel or localhost\*\*.



---



\## ⚙️ CLI reference



```console

USAGE:

&nbsp;   dkey <SIZE> \[OPTIONS]



ARGS:

&nbsp;   <SIZE>                  Key size: raw bytes or with suffix kb/mb/gb/kib/mib/gib



OPTIONS:

&nbsp;   -o, --output <FILE>     Output file (default: key.key)

&nbsp;   -a, --algo <blake3|chacha>

&nbsp;                           Output stream (default: blake3)

&nbsp;       --argon2-memory <KiB>  Argon2 memory   (default 524 288 KiB = 512 MiB)

&nbsp;       --argon2-time <n>      Argon2 passes   (default 10)

&nbsp;       --argon2-par <n>       Argon2 threads  (default 1)

&nbsp;   -s, --salt <BASE64>     Base64 salt (omit to use built‑in constant)

&nbsp;   -h, --help              Show full help

&nbsp;   -V, --version           Show version

```



---



## 🔐 Security notes



\* \*\*Passwords \& seed are wiped\*\* from memory on scope drop (`Zeroizing`).

\* The built‑in compile‑time salt establishes a \*default\* key universe.

&nbsp; Supply `--salt` to isolate projects or rotate secrets without recompiling.

\* Argon2 memory is capped at 4 GiB to prevent accidental DoS.

&nbsp; Tune `--argon2-memory`/`--argon2-time` for your threat model vs. hardware.

\* Output is purely deterministic; anyone who knows all parameters and the

&nbsp; password can regenerate the keystream. \*\*Treat your password \& salt as keys.\*\*



---



## ⏱️ Performance tuning



| Scenario                          | Recommended flags                                      |

| --------------------------------- | ------------------------------------------------------ |

| \*\*Low‑RAM device (Raspberry Pi)\*\* | `--argon2-memory 128 --argon2-time 3`                  |

| \*\*CI / fast tests\*\*               | `--argon2-memory 32 --argon2-time 1`                   |

| \*\*Cold‑storage secrets\*\*          | `--argon2-memory 2048 --argon2-time 20 --argon2-par 1` |



BLAKE3 is 2‑5× faster than ChaCha20; choose ChaCha only if you require its

wider vetting in streaming RNG contexts.



---



## 📜 Algorithm overview



```

(password, salt) ──Argon2id──▶ 32‑byte SEED

&nbsp;      │

&nbsp;      └─(argon2‑memory, time, threads)             user‑tunable cost

&nbsp;                           │

&nbsp;             ┌─────────────┴───────────────┐

&nbsp;             ▼                             ▼

&nbsp;          BLAKE3 XOF                   ChaCha20Rng

&nbsp;             │                             │

&nbsp;             └─────▶ Infinite keystream ◀──┘

```



The first \*N\* bytes of that keystream are written verbatim to `--output`.



---



\## 🤝 Contributing



1\. Fork / feature branch.

2\. `cargo clippy --all-targets --all-features -- -D warnings`

3\. PR with a clear description of \*why\* the change matters.



---



\## 📝 License



\*\*MIT OR Apache‑2.0\*\* – pick the terms you prefer.



---



\## 🙏 Acknowledgments



\* \*\*Argon2id\*\* creators (Password Hashing Competition, 2015).

\* \*\*BLAKE3\*\* authors (Oprea, W. White, et al., 2020).

\* Rust security ecosystem: `zeroize`, `subtle`, `rand`, `clap`, et al.



> Keep your entropy high and your keys reproducible!

KE3, ChaCha20).

Ideal for \*\*one‑time pads\*\*, \*\*test fixtures\*\*, reproducible random data in CI, or any workflow where \*the same inputs must always yield the same bytes\*.



---



\## ✨ Features



| Category                  | Details                                                                                    |

| ------------------------- | ------------------------------------------------------------------------------------------ |

| \*\*Deterministic\*\*         | Same \*password ✕ salt ✕ Argon2 params ✕ algorithm ✕ size\* → identical output, bit‑for‑bit. |

| \*\*Modern crypto\*\*         | • Argon2id KDF<br>• BLAKE3 XOF (default)<br>• ChaCha20 stream option.                      |

| \*\*Strong defaults\*\*       | 512 MiB memory, 10 passes, 1 thread – tunable via flags.                                   |

| \*\*Secret hygiene\*\*        | Password, salt, and seed are zero‑wiped from RAM (`zeroize`).                              |

| \*\*Constant‑time checks\*\*  | Password confirmation rejects on \*fixed time\*; no leak.                                    |

| \*\*Human‑friendly sizes\*\*  | `1gb`, `256MiB`, `42\_000`, etc. Decimal \*\*and\*\* binary suffixes.                           |

| \*\*Self‑contained binary\*\* | No runtime deps—ship one executable.                                                       |

| \*\*MIT OR Apache‑2.0\*\*     | Choose the license that suits you.                                                         |



---



\## 📦 Building



```console

$ git clone https://github.com/you/dkey.git

$ cd dkey

$ cargo build --release     # requires Rust 1.79+ (edition 2024)

```



Result: `target/release/dkey` (or `dkey.exe` on Windows).



---



\## 🚀 Quick start



```console

\# 256‑MiB key, BLAKE3 (default), saved to my.key

$ dkey 256mib -o my.key



\# 1‑GiB key, ChaCha20 stream, custom Argon2 params

$ dkey 1gib -a chacha \\

&nbsp;     --argon2-memory 1024 --argon2-time 4 \\

&nbsp;     --salt "$(openssl rand -base64 16)"

```



> \*\*Password prompts\*\*

> `dkey` always asks twice (constant‑time comparison).

> If you need non‑interactive use, pipe via a tool such as `expect` \*\*only on an encrypted channel or localhost\*\*.



---



\## ⚙️ CLI reference



```console

USAGE:

&nbsp;   dkey <SIZE> \[OPTIONS]



ARGS:

&nbsp;   <SIZE>                  Key size: raw bytes or with suffix kb/mb/gb/kib/mib/gib



OPTIONS:

&nbsp;   -o, --output <FILE>     Output file (default: key.key)

&nbsp;   -a, --algo <blake3|chacha>

&nbsp;                           Output stream (default: blake3)

&nbsp;       --argon2-memory <KiB>  Argon2 memory   (default 524 288 KiB = 512 MiB)

&nbsp;       --argon2-time <n>      Argon2 passes   (default 10)

&nbsp;       --argon2-par <n>       Argon2 threads  (default 1)

&nbsp;   -s, --salt <BASE64>     Base64 salt (omit to use built‑in constant)

&nbsp;   -h, --help              Show full help

&nbsp;   -V, --version           Show version

```



---



\## 🔐 Security notes



\* \*\*Passwords \& seed are wiped\*\* from memory on scope drop (`Zeroizing`).

\* The built‑in compile‑time salt establishes a \*default\* key universe.

&nbsp; Supply `--salt` to isolate projects or rotate secrets without recompiling.

\* Argon2 memory is capped at 4 GiB to prevent accidental DoS.

&nbsp; Tune `--argon2-memory`/`--argon2-time` for your threat model vs. hardware.

\* Output is purely deterministic; anyone who knows all parameters and the

&nbsp; password can regenerate the keystream. \*\*Treat your password \& salt as keys.\*\*



---



\## ⏱️ Performance tuning



| Scenario                          | Recommended flags                                      |

| --------------------------------- | ------------------------------------------------------ |

| \*\*Low‑RAM device (Raspberry Pi)\*\* | `--argon2-memory 128 --argon2-time 3`                  |

| \*\*CI / fast tests\*\*               | `--argon2-memory 32 --argon2-time 1`                   |

| \*\*Cold‑storage secrets\*\*          | `--argon2-memory 2048 --argon2-time 20 --argon2-par 1` |



BLAKE3 is 2‑5× faster than ChaCha20; choose ChaCha only if you require its

wider vetting in streaming RNG contexts.



---



\## 📜 Algorithm overview



```

(password, salt) ──Argon2id──▶ 32‑byte SEED

&nbsp;      │

&nbsp;      └─(argon2‑memory, time, threads)             user‑tunable cost

&nbsp;                           │

&nbsp;             ┌─────────────┴───────────────┐

&nbsp;             ▼                             ▼

&nbsp;          BLAKE3 XOF                   ChaCha20Rng

&nbsp;             │                             │

&nbsp;             └─────▶ Infinite keystream ◀──┘

```



The first \*N\* bytes of that keystream are written verbatim to `--output`.



---



\## 🤝 Contributing



1\. Fork / feature branch.

2\. `cargo clippy --all-targets --all-features -- -D warnings`

3\. PR with a clear description of \*why\* the change matters.



---



\## 📝 License



\*\*MIT OR Apache‑2.0\*\* – pick the terms you prefer.



---



\## 🙏 Acknowledgments



\* \*\*Argon2id\*\* creators (Password Hashing Competition, 2015).

\* \*\*BLAKE3\*\* authors (Oprea, W. White, et al., 2020).

\* Rust security ecosystem: `zeroize`, `subtle`, `rand`, `clap`, et al.



> Keep your entropy high and your keys reproducible!



