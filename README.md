# HIDE Protocol — 0.6, experimental

*Human-friendly Identity & Data Encryption.* The goal is to encrypt to a person, not to a key.
This repository implements the **file format engine**, a **hybrid signature scheme**, and the
machinery an identity needs to outlive a single key: device enrollment and revocation, forward
security by erasure, an auditable history, and group messaging over MLS.

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
- **Hybrid signatures**: Ed25519 + ML-DSA-65, concatenated; a signature verifies only if **both**
  halves do, so neither a quantum nor a classical break of one is enough.
- **Signatures cross surfaces**: a signature made in WASM verifies in Node and vice versa, and every
  SDK returns the same verdict on the same bytes (`node conformance/cross-surface/verify.mjs`).
- **OpenSSH accepts our agent**: `ssh-add -l` lists the key, `ssh-keygen -Y sign` obtains a signature
  through it, and `ssh-keygen -Y verify` reports it good — verified by OpenSSH's own tools, not ours.
- **Replay is refused**: a challenge answer is accepted once; presenting the identical valid signature
  again is rejected, as is one given for a different audience or after its expiry.
- **Revocation means something**: an identity is a hash-linked log of device events, and authority is
  evaluated at the point in the log where an entry appears rather than against the final state. A
  revoked device cannot re-enrol itself, cannot revoke the device that removed it, and cannot rewrite
  anything after its removal. Only an offline recovery key can replace the device set.
- **Forward security by erasure**: keys are grouped into epochs, and destroying an epoch's secret makes
  every container written to it unreadable — including by the intended recipient. Epoch secrets are
  independent random keys, not derived from a master seed, because a derived chain would let anyone
  holding the seed reconstruct what was supposedly erased.
- **A rewritten history is detectable**: the transparency log answers RFC 6962 inclusion and consistency
  proofs, swept over every size from 1 to 33 and every index. A log that alters or drops an entry it
  already published cannot produce a consistency proof against the root it published before.
- **Group messages survive revocation**: MLS proves a message came from a group member, but not that
  the member's device is still trusted. `accept_from_trusted` refuses a message from a device the
  identity revoked, even though MLS itself considers it a valid member.

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
- **SSH authentication is not post-quantum.** `hide agent` offers the Ed25519 half of an identity and
  nothing more. OpenSSH accepts only `ssh-ed25519`, `sk-*` and RSA for user authentication;
  post-quantum algorithms exist there only in key exchange. What this buys is one sealed identity
  instead of a plaintext private key sitting in `~/.ssh`, not quantum resistance.
- **An agent is a signing oracle.** Anything that can reach the endpoint can ask for a signature.
  That is why confirmation is the default and `--no-confirm` must be asked for.
- **Group messaging is not post-quantum.** `hide-mls` uses X25519, because MLS's post-quantum
  ciphersuites are still an Internet-Draft and no Rust provider implements them. Object encryption
  *is* hybrid post-quantum, so a group message and a sealed file are protected differently. The API
  states this in `PQ_STATUS` rather than letting the file format imply uniform protection.
- **`mls-rs` is unaudited too**, like everything else here.
- **A transparency log cannot detect a split view by itself.** Two divergent logs are each internally
  consistent; catching that needs independent witnesses who gossip roots and refuse to sign two roots
  for one size. No witnessing is implemented, so the log is a promise rather than a proof.
- **Epoch secrets are not persisted.** `hide epoch-init` publishes a history, but the secret exists
  only in the process that made it. A durable epoch store is not built, so erasure is demonstrable
  but not yet operationally useful.
- **Revocation is deliberately not retroactive.** Entries signed before a device was revoked stay
  valid, because invalidating them would invalidate every message that device ever sent. Revoking a
  device also does not evict it from MLS groups automatically; that is a separate, explicit call.
- **An identity still is not a person.** The log proves which devices an identity trusts over time. It
  does not prove that identity belongs to a particular human, and there is no directory to ask.

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

A signature proves possession of a key. HIDE has no directory, so nothing ties that key to a person —
compare a signer's key against one you already trust.

### An identity with more than one device

A key is a thing you lose. An identity is a log of device events, each signed by a device the log
already trusted, so it can survive losing one.

```powershell
# The founding device, plus an offline recovery key kept somewhere else entirely.
cargo run -p hide-cli -- --experimental identity-create --secret laptop.hide-key `
  --recovery recovery.hide-pub.sign --label laptop --output alice.hide-log

# Add a phone. Signed by the laptop, because only a trusted device may enrol another.
cargo run -p hide-cli -- --experimental identity-enrol --log alice.hide-log `
  --secret laptop.hide-key --device phone.hide-pub.sign --label phone `
  --recovery recovery.hide-pub.sign

# The phone is stolen.
cargo run -p hide-cli -- --experimental identity-revoke --log alice.hide-log `
  --secret laptop.hide-key --device phone.hide-pub.sign --recovery recovery.hide-pub.sign

# Anyone can replay the log and see who is trusted now. No secret required.
cargo run -p hide-cli -- --experimental identity-show --log alice.hide-log `
  --recovery recovery.hide-pub.sign
```

The log is public and append-only: verifying it needs no secret, which is what lets someone else check
which devices you trust. Revocation applies from the point it appears — the revoked phone cannot
re-enrol itself or revoke the laptop, but containers it already holds stay readable to it, and
signatures it made while trusted stay valid. Nothing can reach back and change that.

If every device is lost, the offline recovery key replaces the whole device set. It is the only key
that can, which is why it belongs somewhere that is not a computer.

### Logging in over SSH

The same identity can act as an ssh-agent, so the key that authenticates you is never written to disk
in the clear.

```powershell
# Print the public line to paste into ~/.ssh/authorized_keys or github.com/settings/keys.
cargo run -p hide-cli -- --experimental ssh-key --secret alice.hide-key

# Serve it. Every signature asks for confirmation unless you pass --no-confirm.
cargo run -p hide-cli -- --experimental agent --secret alice.hide-key
```

Then point SSH at it with `SSH_AUTH_SOCK` — the socket path on Unix, the pipe
path on Windows (`$env:SSH_AUTH_SOCK = '\\.\pipe\hide-agent'`). OpenSSH for
Windows 9.5p2 ignores `-o IdentityAgent`, so use the environment variable on
both platforms.

This offers the Ed25519 half of the identity only. SSH cannot carry the post-quantum half, so an SSH
login is not post-quantum; what it avoids is a plaintext private key on disk. Treat the endpoint as
sensitive: anything that can reach it can ask for a signature.

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
