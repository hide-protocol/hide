# HIDE — tracker

The row-level record of what exists, what is planned and what verified it is
[`tracker.csv`](tracker.csv). That file is canonical; this page is the
one-screen summary. Update both in the same commit as the work they describe.
A row that claims DONE without a verifying command in its Evidence column is not
done.

## What exists at 0.10.0 (published 2026-11-15 to every registry)

0.10.0 is the audit round: no byte of the frozen wire changed, and the
behavioural changes are all API-level (a challenge answer is bound to the
verifier that issued it, a revoked device cannot commit into an MLS group it is
still in, the writer refuses to emit metadata a reader must reject, the C ABI
distinguishes forgery from corruption, `identity-create` no longer overwrites).
The measurements below were taken at 0.10.0.

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
  proofs, and since 0.10.0 the C2SP witness half of the picture — an Ed25519
  cosignature verifier, the `add-checkpoint` request body and the response
  classification (`c2sp.org/tlog-witness`). No operator and no running witness
  exist; ML-DSA-44 cosignatures are out of scope.
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
- **Assurance**: 411 workspace tests, twelve libFuzzer targets — one per parser of
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
- **Third-party conformance (0.10.0, RC-11)**: `conformance/harness` runs any
  implementation against every frozen vector and reports the verdict through
  exit statuses, checking the *class* of each refusal; levels and behaviours are
  machine-readable in `conformance/compliance.json`. **No implementation
  maintained outside this repository has run it**, so criterion 3 for 1.0 is
  still open.

## Reality check 2026-11-15 (phase 15, released as 0.10.0)

The full audit and its numbers are in
[`reality-check-2026-11-15.md`](reality-check-2026-11-15.md); the rows are
`RC-01`…`RC-14`, `DSK-01`…`DSK-09` and `FE-03` in
[`tracker.csv`](tracker.csv). Every surface was read by a separate reader
(container, identity/epoch/transparency/MLS, applications, SDK/FFI,
supply-chain), nothing was compiled during the audit, and every fix was
verified by someone other than its author through the gates in the report.

Four security defects worth naming, all fixed and tested: a challenge answer
carried no binding to the verifier that issued it, so a verifier that took the
challenge back from the client accepted an answer minted for another service;
a device revoked in the identity log could still commit into an MLS group it
was already in; the ssh-agent would sign a HIDE-shaped payload with the Ed25519
half of the hybrid key, quietly reducing it to ML-DSA; and `passwd` on an
unprotected key resealed a master seed as an encryption-only key, changing the
identity. All eight surfaces and all eight SDKs were moved together for the
first one, and the cross-surface check proves the refusal rather than the claim.

Security hardening in the same round: `identity-create` is no-clobber, an
interrupted run no longer leaves plaintext staging behind, `identity-recover`
and the spec §16 binding commands exist, the ssh-agent framing is reachable as
a library so it has a fuzz target, and a user-supplied unix endpoint is removed
only when it is a stale socket.

CI: the minimum-supported-rust job now actually runs 1.88 (it ran `stable`
because `rust-toolchain.toml` overrode the action, so the gate could never
fail), every cargo invocation is `--locked`, the fuzz workspace has a committed
lockfile that CI checks, the desktop lockfile is audited with its own attributed
ignore list, a weekly supply-chain job runs between pushes, and a `report` job
classifies a fuzz-nightly loss as infrastructure instead of leaving no record at
all — which is what the two unexplained failures of 2026-10-05 and 2026-10-21
were.

Rebalanced: the WASM test suite runs in CI (it ran zero tests on the host
before), the desktop frontend is built in CI (a TypeScript error used to first
appear on tag day), and every measurable claim in the documentation was
corrected against a command, including the notification that HIDE does sign its
release assets with Sigstore provenance and that an earlier claim about age's
audit had no source.

## Desktop app P1 audit (part of the round above)

Rows `DSK-01`…`DSK-09` and `FE-03` in
[`tracker.csv`](tracker.csv). The window can no longer name a file: the
operating-system dialogs run in Rust, which keeps the path the user picked and
hands the webview an opaque id, and the JavaScript dialog permission is
withdrawn with the imports. Decryption is no-clobber like encryption, through
the same publish the CLI performs; the secret key file and the decrypted output
are 0600 on unix; a signature that verified is reported by key fingerprint
instead of "the sender is not authenticated"; the commands run off the UI thread
and their buttons are disabled while one is in flight; and the app states its
version, that the build is unsigned, and how to check a download.

`interop.rs` now covers encrypted files in both directions, signed containers in
both placements, every positive frozen container through `decrypt_file`, and a
passphrase-protected key file — and fails rather than skips when `CI` is set.

## What does not exist

No third-party audit. No directory or operated transparency log. No PQ group
messaging. No hardware key protection. No recipient
anonymity. See `SECURITY.md` and `docs/threat-model.md`.

## History

The 0.4 → 0.6 design narrative (decisions D1–D13, mutation-testing lessons,
the recipient-forgery finding that shaped the signature transcript) lives in
git history of this file and in `CHANGELOG.md`.
