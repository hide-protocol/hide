# HIDE — tracker

The row-level record of what exists, what is planned and what verified it is
[`tracker.csv`](tracker.csv). That file is canonical; this page is the
one-screen summary. Update both in the same commit as the work they describe.
A row that claims DONE without a verifying command in its Evidence column is not
done.

## What exists at 0.9.1 (published 2026-09-27 to every registry)

- **Format release candidate**: the wire in `spec/hide-1.md` is frozen from
  0.9.0 (security fixes only before 1.0). Critical flags (SIGNED 0x01), minor
  as a non-breaking revision, ignorable extension keys 64..65535, unknown
  recipient stanzas skipped; GREASE vectors and `manifest.json` prove it.

- **Container format** (`hide-format`, `hide-crypto`, `hide-object`): HPKE with
  X-Wing (X25519 + ML-KEM-768), ChaCha20-Poly1305 in 64 KiB authenticated
  chunks, deterministic CBOR, constant-memory streaming for unsigned objects.
- **Signatures** (`hide-sign`): hybrid Ed25519 + ML-DSA-65; signed containers
  (public or confidential placement), detached signatures, challenge–response
  with replay refusal. Exactly one signature stanza is admitted since 0.7.0.
- **Key files** (`hide-keyring`): one Argon2id-sealed master seed deriving the
  encryption and signing keys; a parameter floor and, since 0.8.0, ceilings
  (memory 8–256 MiB, parallelism ≤ 4, passes 1–64) are enforced on open.
- **Identity** (`hide-identity`): hash-linked device log with create / enrol /
  revoke / recover; authority evaluated at position; canonical encoding.
- **Forward security** (`hide-epoch`): epoch chains with independent random
  secrets; erasure is demonstrable; since 0.9.0 secrets persist in a
  passphrase-sealed epoch keystore (`--epoch-store`).
- **Transparency** (`hide-transparency`): RFC 6962 inclusion and consistency
  proofs; no operator and no witnessing exist.
- **Group messaging** (`hide-mls`): MLS via `mls-rs`, classical suite; the
  credential is a HIDE-signed binding of device id to MLS key since 0.7.0.
- **C ABI** (`hide-ffi`): the single boundary every binding crosses;
  `panic = "unwind"` so `HIDE_ERR_PANIC` is reachable.
- **SDKs**: Python, Node, WASM, Go, Java, Ruby, PHP, .NET and the C header.
  Python, npm, RubyGems and NuGet ship native binaries for seven targets; Java
  and PHP build from source. `HIDE_LIBRARY` needs `HIDE_ALLOW_LIBRARY_OVERRIDE=1`.
- **CLI** (`hide`): keygen, encrypt, open, sign, verify, seal, unseal, info,
  identity-*, epoch-*, ssh-key and an ssh-agent that confirms on the tty.
- **Desktop** (`apps/hide-desktop`): Tauri app and portable build over the same
  crates; `interop.rs` proves it opens CLI output and vice versa.
- **Assurance**: 397 workspace tests, eleven libFuzzer targets — one per parser of
  untrusted bytes — run 45 s on every push and four hours nightly with a
  corpus carried forward (`fuzz-nightly.yml`; a finding files an issue).
  Three real bugs in the first three runs: P11.3, P11.4, P12.1. `cargo audit` and `cargo deny`
  gate advisories, licences, banned crypto stacks and duplicate versions.
  Thirty-two frozen rejection vectors shared with
  the independent Node verifier (containers, signatures, §10–§12 and §16 subsystems),
  a Rust↔Node differential fuzzer in CI, cross-surface conformance,
  `unsafe_code = "forbid"` outside `hide-ffi`, every dependency pinned exactly.
- **Relying-party layer (0.9.1, P14)**: recovery binding, signed C2SP
  checkpoints with witness thresholds, transparency leaves and proof encoding,
  epoch binding (spec §16) in Rust, C ABI, WASM and all seven SDKs; every
  spec §15 limitation closed or decided without a wire change.

## What does not exist

No third-party audit. No directory or operated transparency log. No PQ group
messaging. No hardware key protection. No recipient
anonymity. See `SECURITY.md` and `docs/threat-model.md`.

## History

The 0.4 → 0.6 design narrative (decisions D1–D13, mutation-testing lessons,
the recipient-forgery finding that shaped the signature transcript) lives in
git history of this file and in `CHANGELOG.md`.
