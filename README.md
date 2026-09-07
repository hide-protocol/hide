# HIDE Protocol — Interop Zero (0.1, experimental)

*Human-friendly Identity & Data Encryption.* The goal is to encrypt to a person, not to a key.
This repository currently implements the **file format engine only**, and the CLI is a test harness for it.

> **Do not use this for sensitive data.** The protocol is a draft, the code is unaudited, no
> external security review has happened, and the hybrid KEM tracks a moving IETF draft.

## What is verified today

Every claim below was produced by a command in this repository, on Rust 1.97.1.

- Encrypt/decrypt round-trips across chunk boundaries (0 B, 1 B, 64 KiB ± 1, multi-chunk).
- One payload, many recipients: the file is encrypted once; only the content key is wrapped per recipient.
- Tamper detection: flipping **any single byte** of a container makes decryption fail (`cargo test -p hide-object --test vectors`).
- Truncation, chunk reordering, duplication, deletion and trailing bytes are all rejected.
- **Independent interoperability**: a separate Node implementation (`@hpke/hybridkem-x-wing`, `cbor`,
  Node `crypto`) decrypts the Rust vectors, and Rust decrypts Node's container byte-identically.
- **Cross-OS**: the full suite passes on Windows 11 and on Linux (WSL2 Ubuntu 24.04), and a Linux
  build opens a container produced on Windows.
- Degenerate recipient keys are refused: an X25519 component of small order would silently remove the
  classical half of the hybrid, so all seven such points are rejected before use.
- Property tests (`proptest`) assert the parser never panics on arbitrary input, that any single-byte
  mutation of a container fails to decrypt, and that truncation or appended bytes always fail.

## Measured performance

On this machine (release build, 256 MiB payload):

| Metric | Value |
| --- | --- |
| Encrypt / decrypt (in memory) | ~1250 / ~1550 MiB/s |
| Peak RSS for a 256 MB file | **7 MB** — constant, independent of input size |
| Size overhead | 0.033% (~85 KB, dominated by the 1120-byte hybrid encapsulation) |
| `hide.exe` | 675 KB |

Streaming reuses two fixed 64 KiB buffers and one expanded AEAD instance, so there is no per-chunk
allocation or rekeying. `cargo run --release -p hide-object --example throughput` reproduces the numbers.

## What is NOT implemented or guaranteed

Being explicit here matters more than the feature list.

- **No identity, directory or key transparency.** Recipients are raw test key files that you must
  exchange over a channel you already trust. Nothing proves a key belongs to a particular person.
- **Sender authentication only when the container is signed.** For an unsigned container, a successful
  decryption proves it was not altered; it does **not** prove who created it. A signed container binds
  a signing key to the recipient set, the metadata and the exact plaintext — but it attests to a *key*,
  and nothing yet proves that key belongs to a particular person.
- **No forward secrecy** for stored objects: anyone who later obtains the recipient secret can decrypt
  previously captured containers. Device revocation cannot retroactively protect data an attacker already holds.
- **No hardware protection.** Secret keys are sealed with a passphrase (Argon2id + ChaCha20-Poly1305),
  but there is no Keychain, TPM, Secure Enclave or Keystore integration, and `--insecure-plaintext`
  still writes an unencrypted key on request.
- **Recipient privacy is limited.** Stanzas carry no identifiers, but the recipient *count* and the
  ciphertext size are visible, and metadata is encrypted rather than hidden. A *public* signature also
  reveals the signer's key to anyone holding the file; the confidential placement avoids this.
- **Signing is not streaming.** A signature commits to the plaintext, so signing buffers the payload.
- Not yet built: identity state, device enrollment, recovery, revocation, key transparency,
  SSH authentication, MLS messaging.

## Download

Releases carry three kinds of build. Verify any download against `SHA256SUMS` first.

| Build | File | Use it when |
| --- | --- | --- |
| Desktop application | `HIDE_*-setup.exe`, `*.dmg`, `*.deb`, `*.AppImage` | You want a window, not a terminal. |
| Portable | `hide-portable-*` | You want one executable, no installation, keys kept beside it. |
| Command line | `hide-*` | You want to script it. |

The portable build writes nothing outside its own folder: keys go into a `hide-keys` directory
next to the executable, so it runs from a USB stick and leaves no trace in your user profile.

### Platforms

The CLI is built for Linux (x86-64, ARM64, and a static musl build for Alpine and
scratch containers), Windows (x86-64, ARM64) and macOS (Apple silicon, Intel).

### Package managers

Manifests for Homebrew, Scoop, WinGet and the AUR live in [`packaging/`](packaging/) and are
generated with the real checksums by the release workflow. None is published yet: putting an
unaudited encryption tool in a default package manager reaches people who will not read the
warnings, so that step is taken deliberately rather than automatically.

## SDKs

Every binding calls the same Rust core through one C ABI ([`crates/hide-ffi`](crates/hide-ffi)).
No language reimplements the cryptography, so there is a single implementation to review, and
[`conformance/cross-surface`](conformance/cross-surface) asserts that what one surface produces
every other surface can open.

| Language | Path | How it binds |
| --- | --- | --- |
| C / C++ | [`crates/hide-ffi/include/hide.h`](crates/hide-ffi/include/hide.h) | The ABI itself |
| Python | [`sdk/python`](sdk/python) | `ctypes`, so a wheel needs no compiler |
| TypeScript / Node | [`sdk/node`](sdk/node) | `koffi` over the same shared library |
| Browser | [`sdk/wasm`](sdk/wasm) | WebAssembly, compiled from the same crates |
| Go | [`sdk/go`](sdk/go) | `cgo` |
| Java / Kotlin | [`sdk/java`](sdk/java) | Foreign Function & Memory API, no JNI shim |
| Ruby | [`sdk/ruby`](sdk/ruby) | stdlib `fiddle`, no native gem to build |
| PHP | [`sdk/php`](sdk/php) | `ext-ffi` |
| .NET / C# | [`sdk/dotnet`](sdk/dotnet) | Source-generated `LibraryImport` |

Secret keys never cross into the host language: each SDK holds an opaque handle, and there is
deliberately no function that exports key material.

```python
import hide_protocol as hide

with hide.SecretKey.generate() as secret:
  box = hide.encrypt(b"hello", [secret.public_key()])
  assert hide.decrypt(box, secret).data == b"hello"
```

A browser is a weaker place to hold a key than a desktop: any script on the page shares the
heap, so an XSS bug is equivalent to key theft. Prefer the CLI or the desktop application for
keys that matter.

## Try it

```powershell
cargo test --workspace --all-features

# A key pair. The secret is sealed with a passphrase unless you opt out.
cargo run -p hide-cli -- --experimental keygen --secret alice.hide-key --public alice.hide-pub

# Files.
cargo run -p hide-cli -- --experimental encrypt report.pdf --recipient alice.hide-pub --output report.pdf.hide
cargo run -p hide-cli -- --experimental open report.pdf.hide --secret alice.hide-key --output report.pdf

# Sign as you encrypt. The signature is readable only by the recipients unless
# you pass --public-signature.
cargo run -p hide-cli -- --experimental encrypt report.pdf --recipient alice.hide-pub --output report.pdf.hide --sign alice.hide-key

# Or sign a file in place, leaving report.pdf.hide-sig beside it.
cargo run -p hide-cli -- --experimental sign report.pdf --secret alice.hide-key
cargo run -p hide-cli -- --experimental verify report.pdf --signer alice.hide-pub.sign

# Text messages, as a block you can paste into email or chat.
cargo run -p hide-cli -- --experimental seal "meet at six" --recipient alice.hide-pub
cargo run -p hide-cli -- --experimental unseal message.txt --secret alice.hide-key

# What is this file? Answered without decrypting it.
cargo run -p hide-cli -- --experimental info report.pdf.hide
```

The CLI never overwrites an existing file, writes plaintext to private staging first, and publishes the
result only after authentication succeeds. `--experimental` is mandatory, so the risk is acknowledged explicitly.

`keygen` writes three files: one secret master seed, and two shareable public keys — `alice.hide-pub`
for encryption and `alice.hide-pub.sign` for checking signatures. Both derive from the master seed, so
there is a single thing to back up, and neither can be computed from the other. A key file created
before signatures existed still decrypts; signing with it fails and says so.

A signature proves possession of a key. HIDE has no directory or transparency log, so nothing ties that
key to a person — compare a signer's key against one you already trust.

### Building the desktop application

```powershell
cd apps/hide-desktop
pnpm install --ignore-workspace
pnpm tauri build        # installer
pnpm build:portable     # single portable executable
```

The application calls the same Rust crates as the CLI; it contains no separate cryptographic code.
Key material never reaches the user interface layer. A test in `src-tauri/tests/interop.rs` asserts
that each surface can open what the other produced, so they cannot silently diverge.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/hide-format` | Preamble, bounded canonical CBOR, portable-filename metadata |
| `crates/hide-crypto` | HPKE X-Wing wrapping, HKDF, HMAC, ChaCha20-Poly1305; secrets zeroize and cannot be printed |
| `crates/hide-object` | Envelope encryption and authenticated 64 KiB streaming |
| `crates/hide-keyring` | Passphrase-sealed key files (Argon2id) and public-key armor |
| `crates/hide-ffi` | The C ABI every language binding calls |
| `crates/hide-wasm` | WebAssembly bindings for the browser |
| `apps/hide-cli` | `hide` binary |
| `apps/hide-desktop` | Desktop application (Tauri) and the portable build |
| `sdk/` | Python, Node, WASM, Go and Java packages |
| `packaging/` | Homebrew, Scoop, WinGet and AUR manifests |
| `conformance/` | Frozen vectors plus the independent Node verifier |
| `spec/hide-0.1.md` | Wire format |

## Cryptography

Suite 1 is HPKE base mode with the X-Wing hybrid KEM (X25519 + ML-KEM-768), HKDF-SHA256 and
ChaCha20-Poly1305, via the `hpke` and RustCrypto crates. No primitive is implemented here. Because
X-Wing and HPKE-PQ are still drafts, the wire format is pinned to exact dependency versions and will
change; vectors will be regenerated when the upstream construction changes.

## License

Apache-2.0 — the specification and vectors are freely implementable, with no requirement to use any
particular server or service.
