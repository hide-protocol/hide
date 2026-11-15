# HIDE — hybrid post-quantum file & message encryption (X25519 + ML-KEM-768)

*Human-friendly Identity & Data Encryption.* The goal is to **encrypt to a person, not to a key**.
This repository implements the **file format engine** for post-quantum file encryption, a
**hybrid signature scheme**, and the machinery an identity needs to outlive a single key: device
enrollment and revocation, forward security by erasure, an auditable history, and group messaging
over MLS.

HIDE is end-to-end encryption for files and short messages whose key encapsulation is designed
to resist quantum attacks: every content key is wrapped with X-Wing, a hybrid of X25519 and
ML-KEM-768 as standardised in **NIST FIPS 203 (ML-KEM)**, and every signature is a hybrid of
Ed25519 and ML-DSA-65 from **FIPS 204 (ML-DSA)**. A break of either half alone is not enough.

> **HIDE is experimental and unaudited. Do not use this for sensitive data.** The wire format is a
> release candidate, not 1.0; no third party has reviewed the code, and the hybrid KEM tracks an
> IETF draft. The crates it depends on are not audited either: the READMEs of `ml-kem`, `ml-dsa`
> and `x-wing` each say the implementation "has never been independently audited", and the `hpke`
> README says "nobody has performed a paid audit of this crate" (it records one internal review,
> by Cloudflare, of version 0.8).

## What is verified today

Every claim below was produced by a command in this repository, on Rust 1.99.0 (toolchain
`stable`; the minimum supported Rust version is 1.88).

- Encrypt/decrypt round-trips across chunk boundaries (0 B, 1 B, 64 KiB ± 1, multi-chunk).
- One payload, many recipients: the file is encrypted once; only the content key is wrapped per recipient.
- Tamper detection: flipping **every byte position of the frozen vector `hello.hide`** makes
  decryption fail (`cargo test -p hide-object --test vectors`), and property tests extend that to
  random single-byte mutations of random containers.
- Truncation, chunk reordering, duplication, deletion and trailing bytes are all rejected.
- Thirty-two **frozen rejection vectors** (`conformance/vectors/rejections/`) — among them bad magic,
  minor 0, an unknown preamble flag, header-length overflow, flipped header and FINAL bits,
  truncation before FINAL, trailing bytes, a stripped or unexpected signature, a recipient who
  re-MACed a changed extension or removed an unknown stanza, critical header and metadata keys,
  oversize extensions, a small-order or non-canonically encoded recipient key, a key file
  demanding 2.4 GiB of Argon2 memory — are refused by both the Rust crates and the independent
  Node implementation, so the two agree on what is *invalid*, not only on what is valid.
- **Forward compatibility is tested, not promised**: the GREASE vectors (`grease.hide`,
  `grease-signed.hide`, `grease-minor.hide`) carry an unknown recipient stanza, ignorable header and
  metadata extensions and a future minor, and must open. `conformance/vectors/manifest.json` lists
  all 84 vectors with expected outcome and SHA-256 ([conformance/vectors/README.md](conformance/vectors/README.md)).
- **Fuzzed**: eleven libFuzzer targets under `fuzz/` (`format_header`, `object_open`,
  `keyring_open`, `identity_log`, `epoch_chain`, `transparency_proofs`, `challenge_decode`,
  `mls_message`, `epoch_store`, `checkpoint_note`, `identity_bindings`) run 45 seconds each in CI
  on every push and four hours each nightly with a corpus carried forward. The nightly workflow
  opens an issue when a target fails. Two nightly jobs in October 2026 (`identity_log` on the 5th,
  `object_open` on the 21st) lost their hosted runner before any step ran, so they left no
  reproducer and no issue; the list of workflow runs, not the issue list, is the complete record.
- `unsafe_code = "forbid"` in every crate except `hide-ffi`, where the C ABI needs it; 397 tests
  (`cargo test --workspace --all-features`).
- **Independent interoperability**: a separate Node implementation (`@hpke/hybridkem-x-wing`, `cbor`,
  Node `crypto`) decrypts the Rust vectors (`node conformance/node/verify.mjs`), and the
  differential run (`node conformance/differential/run.mjs`) feeds Node-built and Node-mutated
  containers to the Rust reader on every CI run and fails on any accept/reject disagreement.
- **Cross-OS**: the full suite runs on Linux, Windows and macOS in CI (`ubuntu-24.04`,
  `windows-2025`, `macos-15`), and the same frozen vector files must open on all three. That is
  the cross-OS check; no test moves a container produced on one system to another.
- **Relying-party structures (0.9.1)**: recovery binding, epoch binding and C2SP signed
  checkpoints with a distinct-witness cosignature threshold verify in Rust, the C ABI, WASM and
  every SDK (`cargo test -p hide-identity --test bindings`,
  `cargo test -p hide-transparency --test checkpoint`, `node conformance/node/subsystems.mjs`).
- Degenerate recipient keys are refused: an X25519 component of small order would silently remove the
  classical half of the hybrid, so all seven such points are rejected before use.
- Property tests (`proptest`) assert the parser never panics on arbitrary input, that any single-byte
  mutation of a container fails to decrypt, and that truncation or appended bytes always fail.
- **Hybrid signatures**: Ed25519 + ML-DSA-65, concatenated; a signature verifies only if **both**
  halves do, so neither a quantum nor a classical break of one is enough.
- **Signatures cross surfaces**: a signature made in WASM verifies in Node and vice versa, and
  every surface in the cross-surface matrix (WASM, Node, the CLI, Python, Go, Java, Ruby, PHP and
  .NET) opens what every other surface produced (`node conformance/cross-surface/verify.mjs`,
  with `HIDE_CROSS_REQUIRE` naming the runtimes CI must not skip).
- **OpenSSH accepted our agent**: `ssh-add -l` listed the key, `ssh-keygen -Y sign` obtained a
  signature through it, and `ssh-keygen -Y verify` reported it good. That was verified by hand with
  OpenSSH's own tools on 0.5.0 and is recorded in `docs/tracker.csv` (P4.2, P4.5, P4.8); it is not
  re-run by CI. The agent's wire framing is unit-tested in `apps/hide-cli/src/agent.rs`.
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

One run, release build, 256 MiB payload, on 2026-11-11 (Windows 11, x86-64, Rust 1.99.0, a
workstation that was busy with other builds at the time):

| Metric | Value |
| --- | --- |
| Encrypt / decrypt (in memory) | 217 / 102 MiB/s |
| `hide.exe`, release build | 1,922,048 bytes |
| `hide-v0.9.1-x86_64-pc-windows-msvc.zip` (release asset) | 794,614 bytes |

These are single measurements on a machine that was doing other work, not a benchmark; your CPU
and OS will give different numbers. Earlier versions of this README quoted higher throughput, a
675 KB executable and a 7 MB peak RSS; no command output was recorded for those figures, so they
have been removed. Peak memory is not measured by any command in this repository.

Streaming reuses two fixed 64 KiB buffers and one expanded AEAD instance, so there is no per-chunk
allocation or rekeying; that is a property of the code (`hide-object`), reviewed rather than
asserted by a test. It applies to *unsigned* encryption: signed encryption commits to
`SHA-256(plaintext)`, so it buffers the plaintext and is capped at 1 GiB. The format adds a header
(dominated by the 1120-byte hybrid encapsulation per recipient) and 21 bytes per 64 KiB record.

**Reproduce with:** `cargo run --release -p hide-object --example throughput` (prints throughput
and the size overhead) and `cargo build --release -p hide-cli` (the executable is
`target/release/hide` or `hide.exe`).

## Compared with age, GPG, libsodium

Checked on 2026-11-11; sources for the cells about other projects are listed under the table.

| | HIDE | age | GPG | libsodium sealed box | Signal / MLS | AWS KMS envelope |
| --- | --- | --- | --- | --- | --- | --- |
| Post-quantum KEM | X-Wing (X25519 + ML-KEM-768), always | Yes, opt-in: `age-keygen -pq` gives ML-KEM-768 + X25519 since v1.3.0 | GnuPG 2.5 and later: Kyber (ML-KEM) encryption keys. Separately, RFC 9980 defines post-quantum algorithms for OpenPGP | No (X25519) | Signal: PQXDH; MLS: PQ suites are a draft | ML-KEM in TLS to the service; envelope key is AES |
| Multi-device identity | Signed device log with revocation; no directory | No — one key per recipient | Keyring, subkeys, web of trust | No — a key is a key | Yes, service-operated directory | IAM principals, not people |
| Forward secrecy | By erasure of epoch keys, no ratchet | No | No | No | Yes, double ratchet / tree ratchet | Rotation policy on the master key |
| Signatures | Ed25519 + ML-DSA-65 hybrid | No (integrity only) | Yes, classical | Separate `crypto_sign`, Ed25519 | Implicit via ratchet authentication | Separate KMS sign API |
| Streaming large files | Yes, 64 KiB chunks, constant memory (unsigned) | Yes, 64 KiB STREAM | Yes | No — one message in memory | Attachments handled by the app | Application concern |
| Third-party audit | **None** | See the project; no public audit report located as of 2026-11-11 | Long public review history | Yes (Cryptography Engineering, 2017, sponsored by Private Internet Access) | Yes (multiple) | Vendor-attested |

Sources: age v1.3.0 release notes (post-quantum recipients,
https://github.com/FiloSottile/age/releases/tag/v1.3.0); GnuPG 2.5.16 announcement (2.5 declared
stable, Kyber "aka ML-KEM or FIPS-203" as PQC encryption algorithm,
https://lists.gnupg.org/pipermail/gnupg-announce/2025q4/000500.html); RFC 9980, Post-Quantum
Cryptography in OpenPGP (https://www.rfc-editor.org/info/rfc9980); libsodium audit by
Dr. Matthew Green of Cryptography Engineering, sponsored by Private Internet Access
(https://www.privateinternetaccess.com/blog/libsodium-audit-results/). The remaining cells about
other projects are the maintainer's reading of their public documentation and are not individually
sourced here.

age and libsodium are far more widely deployed and reviewed than HIDE, and age has offered a
hybrid post-quantum recipient type since v1.3.0. If what you need is post-quantum file encryption
to a key, **use age**: HIDE is unaudited and has no deployment history. An earlier version of
this README said age had a Trail of Bits audit with findings fixed in August 2026. No source for
that was found (the age v1.3.2 release notes of 2026-08-29,
https://github.com/FiloSottile/age/releases/tag/v1.3.2, say only "a wide range of fixes and
hardening improvements"), so the statement is withdrawn. What HIDE adds on top is a signed
multi-device identity with revocation, hybrid signatures on containers, forward security by epoch
erasure, a transparency-log primitive and MLS group binding, all under one format. Detail in
[`docs/comparison.md`](docs/comparison.md).

## What is NOT implemented or guaranteed

Being explicit here matters more than the feature list.

- **No directory, and no key-transparency *service*.** The RFC 6962 log primitive exists, but no
  one operates a log, so recipients are still raw key files that you must exchange over a channel
  you already trust. Nothing proves a key belongs to a particular person.
- **Sender authentication only when the container is signed.** For an unsigned container, a successful
  decryption proves it was not altered; it does **not** prove who created it. A signed container binds
  a signing key to the recipient set, the metadata and the exact plaintext — but it attests to a *key*,
  and nothing yet proves that key belongs to a particular person.
- **Forward secrecy is by erasure, not by ratchet.** It exists only if the holder actually destroys
  the epoch secret; anyone who later obtains a secret that was *not* erased can decrypt every
  container captured under it. Device revocation cannot retroactively protect data an attacker
  already holds.
- **No hardware protection.** Secret keys are sealed with a passphrase (Argon2id + ChaCha20-Poly1305),
  but there is no Keychain, TPM, Secure Enclave or Keystore integration, and `--insecure-plaintext`
  still writes an unencrypted key on request.
- **Recipient privacy is limited.** Stanzas carry no identifiers, but the recipient *count* and the
  ciphertext size are visible, and metadata is encrypted rather than hidden. A *public* signature also
  reveals the signer's key to anyone holding the file; the confidential placement avoids this.
- **Signing is not streaming.** A signature commits to the plaintext, so signing buffers the payload.
- **SSH authentication is not post-quantum.** `hide agent` offers the Ed25519 half of an identity and
  nothing more. OpenSSH 10.6 (2026-10-06) enables a hybrid post-quantum signature algorithm,
  `ssh-mldsa44-ed25519` (https://www.openssh.org/txt/release-10.6), but HIDE signs with ML-DSA-65
  and exports an Ed25519 SSH key only, so it does not produce such keys. What this buys is one
  sealed identity instead of a plaintext private key sitting in `~/.ssh`, not quantum resistance.
- **An agent is a signing oracle.** Anything that can reach the endpoint can ask for a signature.
  That is why confirmation is the default and `--no-confirm` must be asked for. On Unix the socket
  sits in a directory only the user can enter; on Windows the named pipe is not restricted to the
  current user, so `--no-confirm` is refused there.
- **Group messaging is not post-quantum.** `hide-mls` uses X25519, because MLS's post-quantum
  ciphersuites are still an Internet-Draft (as of 2026-11) and HIDE has not adopted an
  implementation of them. Object encryption *is* hybrid post-quantum, so a group message and a
  sealed file are protected differently. The API states this in `PQ_STATUS` rather than letting the
  file format imply uniform protection.
- **`mls-rs` is unaudited too**, like everything else here: its README says it "has not yet
  received a full security audit by a 3rd party".
- **A transparency log cannot detect a split view by itself.** Two divergent logs are each internally
  consistent; catching that needs independent witnesses who gossip roots and refuse to sign two roots
  for one size. Witness cosignatures on a checkpoint are verified (`spec/hide-1.md` §16.2), but no
  one operates a log or a witness, so the log is a promise rather than a proof.
- **Epoch erasure is only as strong as the storage underneath.** `hide epoch-init --store`,
  `epoch-advance` and `epoch-erase` keep epoch secrets in one passphrase-sealed store, and erasing
  an epoch reseals the store without it. An older copy of that file — a backup, a filesystem
  snapshot, an SSD's remapped blocks — still holds the epochs it held, for whoever also has the
  passphrase.
- **Revocation is deliberately not retroactive.** Entries signed before a device was revoked stay
  valid, because invalidating them would invalidate every message that device ever sent. Revoking a
  device also does not evict it from MLS groups automatically; that is a separate, explicit call.
- **An identity still is not a person.** The log proves which devices an identity trusts over time. It
  does not prove that identity belongs to a particular human, and there is no directory to ask.
- **The MLS credential binding was introduced in 0.7.0** and has been exercised only by this
  repository's own tests; no other implementation has parsed it.
- **The installers are not code-signed.** No Authenticode or Apple Developer ID signature is
  applied by the release workflow, so the operating system may warn about or block an unknown
  publisher. See "Download" for what can be checked instead.

## Download

Releases carry three kinds of build. The installers and executables are **not code-signed**, so
Windows or macOS may warn that the publisher is unknown. Verify any download before running it:

```
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify <file> --repo hide-protocol/hide
```

The first compares the file with the checksum list published in the same release (on Windows
without `sha256sum`, compare the output of `Get-FileHash <file>` with the line in `SHA256SUMS`).
The second checks the build-provenance attestation, which shows the file was built by this
repository's release workflow; it needs the GitHub CLI. Neither says anything about whether the
code is correct.

| Build | File | Use it when |
| --- | --- | --- |
| Desktop application | `HIDE_*-setup.exe`, `*.dmg`, `*.deb`, `*.AppImage` | You want a window, not a terminal. |
| Portable | `hide-portable-*` | You want one executable, no installation, keys kept beside it. |
| Command line | `hide-*` | You want to script it. |

The portable build keeps its keys in a `hide-keys` directory next to the executable, so it runs
from a USB stick. Only the key folder is redirected: the system webview that draws the window may
still keep its own data (cache, settings) in your user profile.

### Platforms

The CLI is built for Linux (x86-64, ARM64, and a static musl build for Alpine and
scratch containers), Windows (x86-64, ARM64) and macOS (Apple silicon, Intel).

With a Rust toolchain (1.88 or later), `cargo install hide-cli` builds the same `hide` binary
from crates.io.

### Package managers

Templates for Homebrew, Scoop, WinGet and the AUR live in [`packaging/`](packaging/). The
committed files carry placeholder hashes; the release workflow runs `packaging/generate.sh` to
fill in the checksums of that release and uploads the result as a workflow artifact named
`packaging-manifests`. None is published to a package manager: putting an unaudited encryption
tool in a default package manager reaches people who will not read the warnings, so that step is
taken deliberately rather than automatically.

## SDKs

Every binding calls the same Rust core through one C ABI ([`crates/hide-ffi`](crates/hide-ffi)).
No language reimplements the cryptography, so there is a single implementation to review, and
[`conformance/cross-surface`](conformance/cross-surface) checks that what one surface produces
every other surface can open, for WASM, Node, the CLI, Python, Go, Java, Ruby, PHP and .NET.

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

### Installing

```
pip install hide-protocol
npm install hide-protocol
gem install hide-protocol
dotnet add package HideProtocol
npm install @hide-protocol/wasm     # browser
cargo install hide-cli              # the command-line tool, built from source
```

The npm, RubyGems and NuGet packages carry the compiled core for seven targets —
x86-64 and ARM64 Linux (glibc), x86-64 Linux (musl), x86-64 and ARM64 Windows,
and Apple silicon and Intel macOS — so they need no Rust toolchain. PyPI has
wheels for three platforms: `manylinux_2_28_x86_64`, `win_amd64` and
`macosx_11_0_arm64`; on any other platform, build the core yourself as
[`sdk/python/README.md`](sdk/python/README.md) describes. The WASM package is
compiled from the same crates.

Go is clone-and-build: `go get github.com/hide-protocol/hide/sdk/go` alone does
not give a package that compiles, because the C header and the static library
that `cgo` links are not committed to the module. Clone the repository, build
the core and copy both into place as [`sdk/go/README.md`](sdk/go/README.md)
describes.

Java (`org.hide-protocol:hide`) is not yet on Maven Central and PHP
(`hide-protocol/hide`) is not yet on Packagist: build both from source. Neither
ships a binary: build it with `cargo build --release -p hide-ffi` and point
`HIDE_LIBRARY` (Java also accepts `-Dhide.library=`) at the result, with
`HIDE_ALLOW_LIBRARY_OVERRIDE=1` set as well. The same pair overrides the bundled
library everywhere; it is a development-only override, since it replaces the
entire cryptographic core, which is why the second variable is required.

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

# Print a public key as text you can paste into email or chat.
cargo run -p hide-cli -- --experimental share alice.hide-pub

# Change the passphrase that seals a key file.
cargo run -p hide-cli -- --experimental passwd --secret alice.hide-key
```

The CLI never overwrites an existing file when it writes a container, a plaintext, a key or a new
identity log; it writes plaintext to private staging first and publishes the result only after
authentication succeeds. Files that grow or change by design are replaced in place: an identity
log on enrol, revoke and recover, an epoch store on advance and erase, and a key file on `passwd`.
`--experimental` is mandatory, so the risk is acknowledged explicitly.

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

If every device is lost, the offline recovery key replaces the whole device set, with
`hide identity-recover` (from 0.10.0; `hide identity-recover --help` lists its arguments). It is
the only key that can, which is why it belongs somewhere that is not a computer.

### Keys you can erase

An epoch chain is a public history of rotating encryption keys. The matching secrets sit in one
passphrase-sealed store, and erasing an epoch's secret makes every container encrypted to that
epoch unreadable, including to you.

```powershell
# A public chain to publish, and a sealed store to keep.
cargo run -p hide-cli -- --experimental epoch-init --output alice.hide-epochs --store alice.hide-epoch-store

# A sender encrypts to the current epoch's public key.
cargo run -p hide-cli -- --experimental epoch-public --chain alice.hide-epochs --output epoch.hide-pub
cargo run -p hide-cli -- --experimental encrypt notes.txt --recipient epoch.hide-pub --output notes.txt.hide

# The holder opens it with the store, which tries every epoch secret it still has.
cargo run -p hide-cli -- --experimental open notes.txt.hide --epoch-store alice.hide-epoch-store --output notes.txt

# Start a new epoch, then erase the old one (epoch numbers are shown by epoch-show).
cargo run -p hide-cli -- --experimental epoch-advance --chain alice.hide-epochs --store alice.hide-epoch-store
cargo run -p hide-cli -- --experimental epoch-show --chain alice.hide-epochs
cargo run -p hide-cli -- --experimental epoch-erase 0 --chain alice.hide-epochs --store alice.hide-epoch-store
```

Erasure is only as strong as the storage underneath: an older copy of the store (a backup, a
snapshot) still holds the epochs it held. The file names above are examples; the CLI does not
require any particular extension.

### Logging in over SSH

The same identity can act as an ssh-agent, so the key that authenticates you is never written to disk
in the clear.

```powershell
# Print the public line to paste into ~/.ssh/authorized_keys or github.com/settings/keys.
cargo run -p hide-cli -- --experimental ssh-key --secret alice.hide-key

# Serve it. Every signature asks for confirmation. On Unix, --no-confirm turns
# that off; on Windows the flag is refused, because the pipe is not restricted
# to the current user.
cargo run -p hide-cli -- --experimental agent --secret alice.hide-key
```

Then point SSH at it with `SSH_AUTH_SOCK` — the socket path on Unix, the pipe
path on Windows (`$env:SSH_AUTH_SOCK = '\\.\pipe\hide-agent'`). OpenSSH for
Windows 9.5p2 ignores `-o IdentityAgent`, so use the environment variable on
both platforms.

This offers the Ed25519 half of the identity only. HIDE's post-quantum half is ML-DSA-65, and the
hybrid algorithm OpenSSH 10.6 enabled uses ML-DSA-44, so an SSH login with HIDE is not
post-quantum; what it avoids is a plaintext private key on disk. Treat the endpoint as sensitive:
anything that can reach it can ask for a signature.

### Building the desktop application

```powershell
cd apps/hide-desktop
pnpm install --ignore-workspace
pnpm tauri build        # installer
pnpm build:portable     # single portable executable
```

The application calls the same Rust crates as the CLI; it contains no separate cryptographic code.
Key material never reaches the user interface layer. A test in
`apps/hide-desktop/src-tauri/tests/interop.rs` asserts that each surface can open what the other
produced, so they cannot silently diverge.

## Repository layout

| Path | Purpose |
| --- | --- |
| `crates/hide-format` | Preamble, bounded canonical CBOR, portable-filename metadata |
| `crates/hide-crypto` | HPKE X-Wing wrapping, HKDF, HMAC, ChaCha20-Poly1305; secrets zeroize and cannot be printed |
| `crates/hide-sign` | Hybrid Ed25519 + ML-DSA-65 signatures, detached signatures, challenge–response |
| `crates/hide-keyring` | Passphrase-sealed key files (Argon2id) and public-key armor |
| `crates/hide-object` | Envelope encryption and authenticated 64 KiB streaming |
| `crates/hide-epoch` | Epoch chains: forward security by erasure |
| `crates/hide-identity` | Hash-linked device log: create, enrol, revoke, recover |
| `crates/hide-transparency` | RFC 6962 Merkle tree, inclusion and consistency proofs |
| `crates/hide-mls` | MLS (RFC 9420) groups bound to HIDE identities via `mls-rs` |
| `crates/hide-ffi` | The C ABI every language binding calls |
| `crates/hide-wasm` | WebAssembly bindings for the browser (not published to crates.io) |
| `apps/hide-cli` | `hide` binary |
| `apps/hide-desktop` | Desktop application (Tauri) and the portable build |
| `sdk/` | Python, Node, WASM, Go, Java, Ruby, PHP and .NET packages; the C header is `crates/hide-ffi/include/hide.h` |
| `packaging/` | Homebrew, Scoop, WinGet and AUR manifests |
| `conformance/` | Frozen vectors, rejection vectors, the independent Node verifier and the cross-surface check |
| `fuzz/` | libFuzzer targets, run in CI |
| `docs/` | Threat model, comparison, architecture, stability policy, tracker |
| `spec/hide-1.md` | Wire format (HIDE 1, release candidate); `spec/hide-0.1.md` is superseded |

## Cryptography

Suite 1 is HPKE base mode with the X-Wing hybrid KEM (X25519 + ML-KEM-768), HKDF-SHA256 and
ChaCha20-Poly1305 in 64 KiB chunks, via the `hpke` and RustCrypto crates. Signatures are Ed25519 +
ML-DSA-65 (FIPS 204). Key files are sealed with Argon2id. The transparency log is an RFC 6962 Merkle
tree. Group messaging is MLS (RFC 9420) through `mls-rs`, on the classical X25519 suite only. No
primitive is implemented here. Because X-Wing and HPKE-PQ are still drafts (as of 2026-11), every
dependency is pinned to an exact version. The wire format is frozen from 0.9.0
([`spec/hide-1.md`](spec/hide-1.md)) and changes before 1.0 only to fix a security flaw; if the
final HPKE-PQ RFC changed X-Wing, HIDE would add a new suite id rather than alter suite 1
([`docs/stability.md`](docs/stability.md)).

## Documentation

- [`docs/threat-model.md`](docs/threat-model.md) — who the adversary is and what is not defended
- [`docs/comparison.md`](docs/comparison.md) — HIDE against age, GPG, libsodium, MLS and KMS envelopes
- [`docs/use-cases.md`](docs/use-cases.md) — where it fits and where it does not
- [`docs/faq.md`](docs/faq.md)
- [`docs/stability.md`](docs/stability.md) — what may change before 1.0 and how it is announced
- [`docs/migrating-from-age.md`](docs/migrating-from-age.md)
- [`docs/architecture.md`](docs/architecture.md) — crate boundaries and the C ABI
- [`docs/audit-status.md`](docs/audit-status.md) — what has and has not been reviewed
- [`spec/`](spec/) — the wire format, [`SECURITY.md`](SECURITY.md), [`CHANGELOG.md`](CHANGELOG.md)

## Help audit this

No third party has audited HIDE, and an unaudited encryption tool should be treated as broken until
proven otherwise. An audit that would change that should cover: the HPKE/X-Wing composition and the
key schedule (`spec/hide-1.md` §3); the authenticated streaming and the FINAL rule (§5); the
signature transcripts and what a recipient can forge without one (§6–7); the identity log's
authority-at-position rule (§10); the epoch chain and what "erased" actually guarantees (§11); the
RFC 6962 proofs (§12); the MLS credential binding (§13); the C ABI's memory and panic handling in
`hide-ffi`; and the ssh-agent's confirmation path. Internal review found real defects in 0.7.0
([`SECURITY.md`](SECURITY.md) lists them) and fuzzing found a key-file memory exhaustion fixed in
0.8.0 ([HIDE-2026-001](docs/advisories.md)), which is evidence that more exist. Report privately,
either through GitHub's advisory form
(https://github.com/hide-protocol/hide/security/advisories/new) or by mail to
hide-security@codai.ro, as described in [`SECURITY.md`](SECURITY.md); a finding is credited in the
CHANGELOG and in `docs/advisories.md` unless you prefer otherwise. There is no bounty and no
guaranteed response time: HIDE has one maintainer.

## Privacy

HIDE has no telemetry, update check, crash reporting or accounts. No code written in this
repository (the crates, the CLI, the SDKs, the desktop application's Rust and TypeScript) opens a
network connection; `hide agent` listens on a local socket or named pipe only. Two things are
outside that statement: the desktop application is built on Tauri and draws its window with the
system webview (WebView2 on Windows, WebKit elsewhere), components HIDE does not control, and the
Windows installer may download Microsoft's WebView2 runtime from Microsoft if it is not already
installed. The maintainer receives no personal data from your use of the software. The project
site is static and hosted on GitHub Pages; GitHub logs visitor IP addresses for security
(https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).

## Export notice

HIDE contains cryptographic software. Its source code and the binaries built from it are
published openly and without restriction. Laws on the import, possession, use and re-export of
encryption software differ between countries; you are responsible for complying with those that
apply to you.

## License

Apache-2.0 ([`LICENSE`](LICENSE)). The specification and the conformance vectors are under the same
licence, and nothing in the format requires any particular server or service. From 0.10.0 the
release archives and installers carry `THIRD-PARTY-LICENSES.txt`, the licence texts of the
open-source components compiled into them.
