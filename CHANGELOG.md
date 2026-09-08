# Changelog

This project is pre-1.0. The wire format may change while the version is 0.x,
and a format change is always called out here explicitly.

## 0.6.1

**`npm install hide-protocol` now works.** No format change, no API change:
every 0.6.0 container still opens and the frozen 0.1.0 vectors still pass.

### Fixed

- The Node, Ruby and .NET packages shipped without a native library, so they
  failed at import with an error telling the user to "install a platform
  package" — packages that did not exist. Only the Python wheel carried its
  binary. Each ecosystem now ships the compiled core for all seven supported
  targets: `x86_64`/`aarch64` Linux (glibc), `x86_64` Linux (musl),
  `x86_64`/`aarch64` Windows, and Apple Silicon/Intel macOS.
  - **npm**: seven `@hide-protocol/<platform>` packages, declared as optional
    dependencies and constrained by `os`/`cpu`/`libc`, so exactly one installs.
    When none matches, the error now names the package to install.
  - **RubyGems**: a gem per platform, so `gem install` fetches one binary
    rather than all seven.
  - **NuGet**: one package carrying every runtime identifier under
    `runtimes/<rid>/native`.
- The publish workflow proves each package works before publishing it, by
  installing it into a clean directory with `HIDE_LIBRARY` unset and running a
  round trip. That is the check whose absence let 0.6.0 ship broken.

## 0.6.0

**An identity stops being a single key.** The container format is unchanged:
every 0.5.0 container still opens, and the frozen 0.1.0 vectors still pass. What
is new sits alongside the format rather than inside it — device history, key
rotation, an auditable log, and group messaging.

### Added

- **`hide-identity`**: an identity is a hash-linked log of device events, each
  signed by a device the log already trusted. Authority is evaluated at the
  point in the log where an entry appears, never against the final state, which
  is what makes revocation mean something: a revoked device cannot re-enrol
  itself, revoke the device that removed it, or author anything after its
  removal. Only an offline recovery key may replace the device set.
- **`hide-epoch`**: forward security by erasure. Destroying an epoch's secret
  makes every container written to it unreadable, including by the intended
  recipient. Epoch secrets are independent random keys rather than derived from
  a seed — a derived chain would let anyone holding the seed reconstruct what
  was supposedly erased.
- **`hide-transparency`**: RFC 6962 inclusion and consistency proofs. A log that
  alters or drops an entry it already published cannot produce a consistency
  proof against the root it published before.
- **`hide-mls`**: group messaging over MLS (RFC 9420) via `mls-rs`, joined to
  HIDE identities so a message from a revoked device is refused even though MLS
  itself considers it a valid member.
- **CLI**: `identity-create`, `identity-enrol`, `identity-revoke`,
  `identity-show`, `epoch-init`, `epoch-show`.
- **All eight SDKs** expose identity, epoch and transparency verification, over
  the same C ABI and against the same published test vectors.
- **`scripts/set-version.ps1`**, because the version lives in 22 files across
  seven ecosystems and every release so far moved them by hand.

### Limits worth knowing before you use any of this

- **Group messaging is not post-quantum.** MLS's PQ ciphersuites are still an
  Internet-Draft and no Rust provider implements them, so `hide-mls` uses
  X25519. Object encryption *is* hybrid PQ, so the two are protected
  differently; `hide_mls::PQ_STATUS` says so in the API.
- **A transparency log cannot detect a split view alone.** Two divergent logs
  are each internally consistent. Catching that needs witnesses, and no
  witnessing is implemented.
- **Epoch secrets are not persisted.** `epoch-init` publishes a history, but the
  secret lives only in that process, so erasure is demonstrable and not yet
  operationally useful.
- **Revocation is not retroactive**, deliberately: entries signed before it stay
  valid, because invalidating them would invalidate every message that device
  ever sent. Revoking a device also does not evict it from MLS groups
  automatically.
- **`mls-rs` is unaudited**, like everything else here.

### Fixed

- The CLI wrote logs through the container path, which refuses to overwrite, so
  an append-only log could never grow past its first entry.

## 0.5.0

**The container format gains signatures.** Unsigned containers are unchanged
byte for byte, and the frozen 0.1.0 vectors still pass. Signed containers
advertise preamble minor `2`, so a reader that predates signatures refuses them
rather than opening them with the signature silently ignored.

### Added

- **Hybrid Ed25519 + ML-DSA-65 signatures** (`hide-sign`). Both halves must
  verify; neither alone is accepted.
- **`hide sign` and `hide verify`** for detached signatures, written as
  `<file>.hide-sig` beside the file.
- **`hide encrypt --sign`**, which signs the container as it is written. The
  signature is readable only by the recipients unless `--public-signature` puts
  it in the clear, where it identifies the signer to anyone holding the file.
- **`hide open` and `hide unseal` report the signer**, as a key fingerprint and
  an explicit reminder that a key is not a person.
- **`hide info`** recognises signing keys, detached signatures, and signed
  containers.
- **`hide agent`** serves an identity to OpenSSH over the ssh-agent protocol —
  a Unix socket, or a named pipe on Windows — so the key that logs you in is
  never written to disk in the clear. Every signature asks for confirmation
  unless `--no-confirm` is passed.
- **`hide ssh-key`** prints the OpenSSH public line for `authorized_keys` or
  GitHub.
- **Challenge–response** (`hide-sign`): a verifier issues a random nonce bound
  to an audience and an expiry, and the prover signs it. Unlike a detached
  signature, an answer cannot be replayed to another service or reused later.
  `SpentNonces` records what has been answered and forgets entries once expiry
  alone would refuse them.
- **Signing, verification and challenges in all eight SDKs** — Python, Node,
  Go, Java, Ruby, PHP, .NET and WASM — plus the C ABI they are built on.
  `verify` throws or returns an error in every language; none returns a boolean
  a caller can forget to check.
- **`hide_identity_generate`** in the C ABI, so a binding can create an identity
  rather than only load one.

### Changed

- **`hide keygen` now creates an identity**: one sealed master seed, plus an
  encryption public key and a signing public key (`<public>.sign`) derived from
  it. One backup, one passphrase, and neither derived key reveals the other.
- **Key files carry a purpose byte** (format version 2), so a signing key can no
  longer be used silently where an encryption key was meant. Version 1 files
  still open and are treated as encryption-only; signing with one fails with a
  message naming the fix.

### Security

### Fixed

- **A raw key file meant different things to the CLI and to the SDKs.** Since
  the identity work landed, `hide keygen --insecure-plaintext` writes a master
  seed and the CLI derives the encryption key from it, but every SDK read those
  32 bytes as the key itself — so a container encrypted to the CLI's own public
  key could not be opened through any SDK. `hide_keyring::open` now derives, and
  a protected identity file also yields its encryption key. Protected key files
  written by 0.4.0 are unaffected and still open.

- **SSH authentication is not post-quantum, and the README says so.** OpenSSH
  accepts only `ssh-ed25519`, `sk-*` and RSA for user authentication, so the
  agent offers the Ed25519 half of an identity and the ML-DSA half goes unused.
  What this buys is a sealed key instead of a plaintext one, not quantum
  resistance.
- **The agent asks before every signature by default.** Anything that can reach
  the endpoint can request one, so silence has to be asked for explicitly. On
  Unix the socket is created with mode `0600`.
- A signature commits to the **plaintext**, not merely the header. Binding only
  the header would have been forgeable by any recipient: they hold the content
  key and the payload salt is public, so they could re-encrypt different content
  under an unchanged header and the original signature would still verify.
  Signing therefore buffers the payload and is not a one-pass stream.

## 0.4.0

The container format is **unchanged**: 0.1.0 containers still open, and the
frozen vectors still pass byte for byte in every language.

### Added

- **Ruby, PHP and .NET SDKs**, bringing the total to eight surfaces on one C
  core. Ruby binds through stdlib `fiddle`, PHP through `ext-ffi` and .NET
  through source-generated `LibraryImport`, so none of them needs a native
  build step or a hand-written shim.
- **Publishing to RubyGems and NuGet**, and a second manual workflow that
  pushes the generated Homebrew and Scoop manifests to a tap. Both default to
  a dry run, and the manifests are regenerated from the checksums of the
  published release and verified against the real assets before any push.
- **`packaging/PUBLISHING.md`** records what a human must do: the credential
  each registry needs, why PyPI should use Trusted Publishing rather than a
  token, and that `hide` on crates.io belongs to an unrelated project.

### Changed

- The cross-surface conformance test covers all eight surfaces and gained a
  `HIDE_CROSS_REQUIRE` gate. Without it a missing runtime would quietly shrink
  the matrix, and a skipped interop check is indistinguishable from a passing
  one. CI names every runtime, so an absent one now fails.
- `hide_encrypt` refuses a filename or media type containing a NUL rather than
  silently truncating it. Those cross the ABI as C strings, so the shortened
  value would have been sealed into the container without the caller knowing.

### Fixed

- Cross-compiled release builds could not link. A cross `gcc` alone is not
  enough — `Scrt1.o` and `crti.o` come from the target C library, which
  `--no-install-recommends` had dropped, so the Linux ARM64 binary never built.

## 0.3.0

The container format is **unchanged**: 0.1.0 containers still open, and the
frozen vectors still pass byte for byte in every language.

### Added

- **SDKs for six surfaces**, all calling one C ABI (`crates/hide-ffi`) so the
  cryptography has a single implementation: C/C++, Python (`ctypes`), Node
  (`koffi`), Go (`cgo`), Java (Foreign Function & Memory API, no JNI shim), and
  a WebAssembly build for browsers.
- **`conformance/cross-surface`** opens each surface's output with every other
  surface, including the frozen 0.1.0 vectors, and asserts a damaged container
  is refused everywhere. Missing pieces fail the run rather than skipping.
- **More CLI targets**: Linux ARM64, a static musl build for Alpine and scratch
  containers, Windows ARM64 and Intel macOS, alongside the existing three.
- **Package manager manifests** for Homebrew, Scoop, WinGet and the AUR,
  generated by the release workflow from the checksums of the artifacts that
  were actually built. `packaging/generate.sh` refuses to emit a manifest when
  a checksum is missing rather than writing an empty hash.
- **A publish workflow** for crates.io, PyPI and npm. It is started by hand,
  not by a tag: publishing to a registry claims a name permanently and, on
  crates.io and PyPI, cannot be undone.

### Changed

- The FFI returns metadata and armor as length-prefixed buffers rather than C
  strings. Attacker-controlled text containing a NUL silently truncates when
  passed as a C string, and it removed a crash where a binding could not both
  decode and free the same pointer.

## 0.2.1

### Fixed

- The Windows installer asked for administrator rights and could not complete
  without them. It now installs for the current user, which needs no elevation
  and matches what an unaudited tool should be allowed to do.

## 0.2.0

The container format is **unchanged**: 0.1.0 containers open with 0.2.0 and the
frozen vectors still pass byte for byte.

### Added

- **Passphrase-protected secret keys.** `hide keygen` now seals the secret with
  Argon2id (19 MiB, t=2, OWASP 2024 baseline) and ChaCha20-Poly1305. The Argon2
  parameters are stored in the file and authenticated, so they can be raised
  later without orphaning existing keys. Raw keys still open, so nothing that
  worked before stops working.
- **Text messages.** `hide seal` and `hide unseal` encrypt a message into a
  pasteable block for email or chat.
- **`hide info`** describes a container or key file without decrypting it, and
  without revealing the original filename.
- **`hide share`** prints a public key in a pasteable armored form; armored keys
  are accepted anywhere a public key file is.
- **`hide passwd`** changes the passphrase on an existing key.
- **Desktop application** (Tauri) with keys, files, messages and inspection. It
  calls the same crates as the CLI and contains no separate cryptographic code;
  key material never crosses into the user interface layer.
- **Portable build.** A single executable that requires no installation and
  keeps its keys in a `hide-keys` folder beside itself, writing nothing to the
  user profile.
- An interoperability test asserting the CLI and the desktop application can
  each open what the other produced.

### Changed

- `hide test-keygen` is deprecated in favour of `keygen --insecure-plaintext`.
  It still works and still writes an unencrypted key.
- A passphrase is never read from a pipe, only from a terminal, so it cannot be
  captured from shell history or a CI log.

## 0.1.0

First release. File-format engine only: HPKE X-Wing (X25519 + ML-KEM-768) key
wrapping and authenticated 64 KiB streaming with constant memory, a CLI test
harness, frozen vectors and an independent Node verifier.
