# HIDE architecture

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

HIDE is a Rust workspace of ten library crates and one binary, a Tauri desktop app kept outside the workspace, and nine language SDKs that all sit on one C ABI. This document describes the crate boundaries, the single seam every binding crosses, how the SDKs find the compiled core, how releases are built, and how CI enforces the invariants in [../AGENTS.md](../AGENTS.md).

## Crate dependency graph

Derived from each crate's `Cargo.toml` on 0.6.2. Arrows point at dependencies.

```mermaid
graph TD
    format[hide-format<br/>bounded canonical CBOR]
    crypto[hide-crypto<br/>HPKE X-Wing, HKDF, HMAC, AEAD]
    sign[hide-sign<br/>Ed25519 + ML-DSA-65]
    keyring[hide-keyring<br/>Argon2id key files]
    object[hide-object<br/>envelope + 64 KiB streaming]
    identity[hide-identity<br/>device log]
    epoch[hide-epoch<br/>epoch chains]
    transparency[hide-transparency<br/>RFC 6962]
    mls[hide-mls<br/>MLS via mls-rs]
    ffi[hide-ffi<br/>C ABI, the only unsafe]
    wasm[hide-wasm<br/>browser]
    cli[apps/hide-cli]
    desktop[apps/hide-desktop<br/>outside workspace]

    sign --> crypto
    keyring --> crypto
    object --> format
    object --> crypto
    object --> sign
    object --> keyring
    identity --> sign
    epoch --> crypto
    mls --> identity
    mls --> sign

    ffi --> crypto & keyring & object & sign & identity & epoch & transparency
    wasm --> crypto & keyring & object & sign & identity & epoch & transparency
    cli --> crypto & keyring & sign & object & identity & epoch
    desktop --> crypto & keyring & object

    sdks[sdk/: Python, Node, Go, Java,<br/>Ruby, PHP, .NET] -.load.-> ffi
    browser[@hide-protocol/wasm] -.-> wasm
```

`hide-transparency` has no HIDE dependencies (SHA-256 only). `hide-mls` is not reached by the CLI, the FFI or WASM yet; it is a Rust-only surface in 0.6.x.

## One paragraph per crate

**hide-format** — The preamble (16 bytes: magic, major, minor, kind, flags, `header_len`), bounded deterministic CBOR per RFC 8949 §4.2, the protected header map, and portable-filename validation. Every limit (header ≤ 1 MiB, 1..=64 recipients, metadata ≤ 256 KiB + 16, chunk ≤ 64 KiB) is checked before any allocation from an untrusted length. The decoder re-encodes and compares bytes so that non-canonical input is refused rather than normalised.

**hide-crypto** — Wraps the `hpke` crate's X-Wing KEM (X25519 + ML-KEM-768, KEM id `0x647A`) in HPKE base mode with HKDF-SHA256 and ChaCha20-Poly1305, and provides the derived-key helpers (HKDF, HMAC-SHA256) and `ChunkCipher`, the reusable AEAD instance streaming depends on. `RecipientPublic::from_bytes` rejects the seven small-order X25519 points. Secret types (`RecipientSecret`, `Identity`) never derive `Debug`, `Clone` or `Serialize` and zeroize on drop; there is deliberately no `to_bytes` on a secret, only an explicitly named `expose_seed_for_sealing`.

**hide-sign** — Hybrid signatures: a 1984-byte verifying key (`ed25519(32) ‖ ml_dsa(1952)`) and a 3373-byte signature (`ed25519(64) ‖ ml_dsa(3309)`), both halves evaluated before deciding. Detached signatures, the challenge–response scheme (nonce bound to audience and expiry) and `SpentNonces` for replay refusal. Signing is deterministic, which the vector test asserts. Both halves derive from one master seed via HKDF domain separation.

**hide-keyring** — Passphrase-sealed key files: Argon2id (19 MiB, t = 2, p = 1 by default; parameters stored in the authenticated header so they can be raised later; floor 8 MiB / t = 1 enforced on open) then ChaCha20-Poly1305 over the 32-byte seed. Format version 2 adds a purpose byte so a signing key cannot be used where an encryption key was meant. Public-key armor. `open()` derives the encryption key from a raw seed file rather than treating the file as the key.

**hide-object** — The container: header construction with one wrapped CEK per recipient, header MAC, encrypted metadata, and the 64 KiB record stream with counter + kind in the nonce and a 91-byte AAD (label, object id, `SHA-256(protected)`, counter, kind, plaintext length). `encrypt` streams with two fixed buffers; `encrypt_signed` buffers up to 1 GiB because the transcript binds `SHA-256(plaintext)`. `decrypt` publishes nothing before FINAL and the signature (if any) verify. Holds the frozen-vector tests and the byte-exact AAD/nonce assertions.

**hide-identity** — An identity as a hash-linked log of signed events (`Create`, `Enrol`, `Revoke`, `Recover`), each entry's `previous` inside the signed bytes, every variable-length field length-prefixed. Authority is evaluated by replaying from entry 0, so a revoked device cannot author anything after its removal. Only the offline recovery key signs `Recover`. Verification needs no secret.

**hide-epoch** — `EpochChain`: independent random per-epoch recipient keys, a public SHA-256-linked history, `advance`, `erase`, `erase_before`, `is_readable`, and `recipient_for` to encrypt to a given epoch. Nothing derives from a seed, so an erased secret cannot be reconstructed. Persistence is not implemented; the CLI publishes the history only.

**hide-transparency** — RFC 6962 Merkle tree with `0x00`/`0x01` leaf/node prefixes, checkpoint `size ‖ root`, inclusion and consistency proofs, swept over every size 1..=33 in tests. No witnessing, so split views are not detected.

**hide-mls** — MLS (RFC 9420) through `mls-rs` 0.56 on `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (classical; `PQ_STATUS` says so). Supplies credential type `0xF01D`: a HIDE-signed binding of device id and MLS signature key, checked against the identity log's current membership on every roster change. `accept_from_trusted` refuses messages from revoked devices; `untrusted_members` lists who to remove.

**hide-ffi** — The C ABI, and the only crate without `unsafe_code = "forbid"`. Opaque handles for secret keys, signing identities and spent-nonce sets; length-prefixed `HideBuffer` for every output; integer error codes including `HIDE_ERR_MALFORMED` distinct from `HIDE_ERR_AUTHENTICATION`. Built with `panic = "unwind"` so a panic becomes `HIDE_ERR_PANIC` instead of aborting the host. The header is `include/hide.h`.

**hide-wasm** — `wasm-bindgen` exports compiled from the same crates for the browser package `@hide-protocol/wasm`. Not published to crates.io. Signatures are positional and recipients are concatenated bytes.

**hide-cli** — The `hide` binary. Every subcommand requires `--experimental`. Refuses to overwrite, writes to private staging and commits atomically, never uses a decrypted filename as a path, reads passphrases only from a terminal, and serves the ssh-agent protocol with per-signature confirmation on the controlling tty.

**hide-desktop** — Tauri 2 + React. Calls `hide-crypto`, `hide-keyring` and `hide-object` directly; contains no cryptography of its own and key material never reaches the webview. Kept outside the cargo workspace so `cargo test --workspace` needs no Node; tested with `cargo test --manifest-path apps/hide-desktop/src-tauri/Cargo.toml`.

## The C ABI is the single seam

Every non-Rust surface — Python (`ctypes`), Node (`koffi`), Go (`cgo`, static), Java (FFM, no JNI), Ruby (`fiddle`), PHP (`ext-ffi`), .NET (`LibraryImport`) — calls the functions declared in [../crates/hide-ffi/include/hide.h](../crates/hide-ffi/include/hide.h). No binding contains cryptographic code. Consequences:

- One implementation to review; a defect in the core is a defect in nine SDKs, and a fix is one fix.
- Key material never crosses the boundary. Bindings hold opaque handles; there is no export function. `hide_inspect_key` sniffs a format and never validates — rejection happens at `hide_secret_key_open`.
- Text crosses as length-prefixed buffers, not C strings, after `koffi` could not both decode and free one pointer. Filename and media type are the exception (NUL-terminated), so an embedded NUL is refused at the boundary.
- `verify` returns an error code; every SDK throws or returns an error, and none returns a boolean a caller can forget to check.

`conformance/cross-surface/verify.mjs` asserts that what any surface produces every other surface opens, plus the frozen vectors. `HIDE_CROSS_REQUIRE=ruby,php,dotnet` turns an absent runtime into a failure rather than a smaller matrix.

## How SDKs load the library

Each package bundles the compiled core for seven targets listed in [../sdk/native-targets.json](../sdk/native-targets.json): x86-64 and ARM64 Linux (glibc), x86-64 Linux (musl), x86-64 and ARM64 Windows, Apple silicon and Intel macOS. npm ships seven `@hide-protocol/<platform>` optional dependencies constrained by `os`/`cpu`/`libc`; RubyGems ships a gem per platform; NuGet ships one package with `runtimes/<rid>/native`; the Python wheel carries its binary; Go links the staticlib through `cgo`.

`HIDE_LIBRARY` overrides the bundled library **only when `HIDE_ALLOW_LIBRARY_OVERRIDE=1` is also set**. Before 0.7.0 the first variable alone was honoured, which let any process able to set an environment variable replace the cryptographic core; that is one of the seven findings in [audit-status.md](audit-status.md). Java also accepts `-Dhide.library=` under the same gate. The override is for development against a locally built `hide_ffi` and for Java and PHP, which do not yet ship binaries.

## Build, test and release

**Local.** `cargo test --workspace --all-features` (297 tests). The desktop crate is tested separately by manifest path. Husky hooks installed by `npm install` at the root: pre-commit runs `cargo fmt` and `clippy -D warnings` when Rust files are staged; pre-push runs the full suite, a release build, the desktop clippy/test, the cross-surface check, and refuses to push if `conformance/vectors` is dirty.

**CI (`.github/workflows/ci.yml`).** Jobs: `lint` (fmt, clippy, `scripts/set-version.ps1 -Check`), `test` on ubuntu-24.04 / windows-2025 / macos-15, `desktop` (Linux; greps for the interop skip message and fails), `sdks` (builds the core, runs all nine surfaces plus the C ABI test and the cross-surface check, greps for skip messages), `interoperability` (Rust vector test and the independent Node verifier), `minimum-supported-rust` (`cargo +1.85 check`), `supply-chain` (`cargo audit --deny warnings`), `fuzz` (six libFuzzer targets seeded from the frozen vectors, 45 s each, crashes kept as artifacts).

**Release (`release.yml`).** Builds the CLI for Linux x86-64/ARM64/musl, Windows x86-64/ARM64, macOS ARM64/x86-64; the desktop installers and the portable build; `SHA256SUMS` over every asset; generates `packaging/` manifests from the real checksums (unpublished by policy).

**Publishing (`publish-sdks.yml`, manual).** Builds `hide-ffi` for the seven native targets, assembles each package, installs it into a clean directory with `HIDE_LIBRARY` unset and runs a round trip *before* publishing, then publishes to crates.io (11 crates), PyPI, npm (8 packages), RubyGems and NuGet — all via OIDC trusted publishing with no long-lived registry secret. Java (Maven Central) and PHP (Packagist) are not yet published.

## Where the invariants live and how CI enforces them

The invariants are written once, in [../AGENTS.md](../AGENTS.md). Each has at least one mechanical check.

| Invariant | Enforcement |
| --- | --- |
| No new primitives, no hand-rolled KEM combiner | Review; the dependency list is pinned `=` and `cargo audit` runs in CI |
| Secrets never derive `Debug`/`Clone`/`Serialize`; zeroize on drop | Compile-time: a test that `unwrap_err()`s a `Result<RecipientSecret,_>` does not compile, which is the point |
| Validate limits before allocating | Fuzz targets `format_header`, `object_open`, `keyring_open`, `identity_log`, `epoch_chain`, `transparency_proofs`; proptest "parser never panics" |
| Authenticate the exact received `protected` bytes | Frozen vectors are byte-exact; rejection vectors include flipped header bits |
| Never publish plaintext before FINAL authenticates | Truncation and trailing-byte rejection vectors; property tests; CLI staging-then-commit |
| Never use a decrypted filename as a path | Filename validation in `hide-format`; `/` refused as malformed at the ABI |
| Reject small-order X25519 components | Rejection vector `small-order recipient key`; unit test over all seven points |
| Streaming allocates nothing per chunk | Throughput example and the measured 7 MB peak RSS; reviewed, not asserted in CI |
| Claims in README/spec are backed by a test | Convention; the "What is verified today" list in the README names the test per claim |
| Desktop app contains no cryptography | It depends only on `hide-crypto`, `hide-keyring`, `hide-object`; no `unsafe`; key material stays in Rust commands |
| CLI and desktop open each other's output; the test cannot silently skip | `src-tauri/tests/interop.rs`; CI greps `desktop-tests.log` for the skip message and fails |
| C header constants equal the Rust ones | `hide-ffi/tests/c_abi.rs::the_header_constants_match_the_rust_ones`, plus a C program compiled against `hide.h`; the skip message is also grepped |
| Panics become error codes, not aborts | `c_abi.rs::a_panic_inside_the_library_becomes_an_error_code_not_an_abort` |
| Version is consistent across 22 files in 7 ecosystems | `scripts/set-version.ps1 -Check` in the `lint` job |
| Vectors are frozen | pre-push hook refuses a dirty `conformance/vectors`; regeneration needs the `test-vectors` feature and an explicit example run |
| Every surface agrees | `conformance/cross-surface/verify.mjs` with `HIDE_CROSS_REQUIRE` |
| Passphrases come only from a terminal | ssh-agent confirmation reads the controlling tty (0.7.0 fix); reviewed |
| Published packages work without `HIDE_LIBRARY` | `publish-sdks.yml` installs each package clean and round-trips before publishing |
