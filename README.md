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
- **No sender authentication.** A successful decryption proves the container was not altered; it does
  **not** prove who created it.
- **No forward secrecy** for stored objects: anyone who later obtains the recipient secret can decrypt
  previously captured containers. Device revocation cannot retroactively protect data an attacker already holds.
- **No hardware protection.** `hide test-keygen` writes an **unencrypted** secret key file. There is no
  Keychain, TPM, Secure Enclave or Keystore integration yet, and no passphrase.
- **Recipient privacy is limited.** Stanzas carry no identifiers, but the recipient *count* and the
  ciphertext size are visible, and metadata is encrypted rather than hidden.
- Not yet built: identity state, device enrollment, recovery, revocation, signatures, MLS messaging, GUI apps.

## Try it

```powershell
cargo test --workspace --all-features
cargo run -p hide-cli -- --experimental test-keygen --secret alice.test-secret --public alice.test-public
cargo run -p hide-cli -- --experimental encrypt report.pdf --recipient alice.test-public --output report.pdf.hide
cargo run -p hide-cli -- --experimental open report.pdf.hide --secret alice.test-secret --output report.pdf
```

The CLI never overwrites an existing file, writes plaintext to private staging first, and publishes the
result only after authentication succeeds. `--experimental` is mandatory, so the risk is acknowledged explicitly.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/hide-format` | Preamble, bounded canonical CBOR, portable-filename metadata |
| `crates/hide-crypto` | HPKE X-Wing wrapping, HKDF, HMAC, ChaCha20-Poly1305; secrets zeroize and cannot be printed |
| `crates/hide-object` | Envelope encryption and authenticated 64 KiB streaming |
| `apps/hide-cli` | `hide` binary |
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
