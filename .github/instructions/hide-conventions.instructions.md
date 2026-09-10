---
applyTo: "**"
description: "HIDE repo invariants and verified gotchas: untrusted input, workspace layout, vectors, fuzzing, CI/release, tracker"
---

# HIDE conventions (always on)

Every bullet below was paid for by a real failure. Mechanism, not story.

## Untrusted input

- Every decoder of untrusted bytes gets a fuzz target in `fuzz/fuzz_targets/` that
  asserts `assert_eq!(encode(&decode(x)?), x)`. Code review missed non-canonical
  CBOR (`9a 00 00 00 00` = 5-byte length prefix for a small array) in two crates;
  the fuzzer found the second in under 4 minutes.
- Canonical form is enforced by re-encoding and comparing (`hide-identity/src/lib.rs`
  `if encode(&entries)? != bytes { Malformed }`), never by inspecting the encoder.
- Loops in verifiers are bounded by the input's BIT WIDTH, never by its value.
  `largest_power_of_two_below` shifted a probe until `> n`; for `n > 2^63` the probe
  wrapped to 0 and spun forever. Correct: `1 << (n - 1).ilog2()`.
- Every numeric field read from untrusted input has an explicit `MAX_*` checked before
  any allocation or loop. Argon2 `m_cost` from a key-file header was allowed up to
  4 GiB; a 95-byte file requested 2.4 GiB. Ceiling is now `MAX_MEMORY_KIB = 256 MiB`.
- Never `Vec::with_capacity(declared_count)`. Never `as usize`; use `usize::try_from`.
- Authenticate the exact received `protected` bytes; never re-serialize then verify.
- Never publish decrypted output before the FINAL record authenticates.
- Never use a decrypted filename to choose an output path.
- Reject the 7 RFC 7748 small-order X25519 points in `RecipientPublic::from_bytes`.
- Secret types never derive `Debug`, `Clone` or `Serialize`; zeroize on drop.
  Consequence: `Result<Secret,_>.unwrap_err()` does not compile; match instead.
- No new cryptographic primitives; no hand-rolled KEM combiner.
- Key files: an unprotected 32-byte file is a MASTER SEED. Derive with
  `Identity::from_seed(seed)`; `RecipientSecret::from_bytes(file)` is the v0.1.0
  meaning and yields a different key. Writers only ever emit Argon2 m=19 MiB, t=2, p=1.

## Workspace layout

- `apps/hide-desktop` is OUTSIDE the cargo workspace (`exclude` in root `Cargo.toml`).
  `cargo test --workspace` never compiles it. After touching any shared crate run
  `cargo test --manifest-path apps/hide-desktop/src-tauri/Cargo.toml` (pre-push does).
  `src-tauri/tests/interop.rs` is the CLI↔desktop proof; it must never skip in CI.
- The desktop app contains no cryptography; key material never enters the webview.
- `unsafe_code = "forbid"` is workspace-wide except `hide-ffi`.
- Dependency versions are pinned `=`; the wire format depends on them.
- A test target that uses `#[cfg(feature = ...)]` hooks needs `[[test]] required-features`
  in its `Cargo.toml`, or plain `cargo test -p <crate>` fails to compile instead of
  skipping (`hide-object/tests/signing.rs`).
- `deny.toml` (CI `supply-chain`): licence allow-list, banned second crypto stacks
  (`openssl`, `ring`), unknown registries, duplicate versions. Every known duplicate
  is attributed in `skip`/`skip-tree` with its reason; a new duplicate is drift.
  Run `cargo deny check` locally after any `Cargo.toml` change.
- `.husky/pre-commit` = fmt + clippy (only when `.rs`/`Cargo.*` staged, matched per
  line); `.husky/pre-push` = full suite + desktop + release build + vectors clean.
  Bypass only with `HIDE_SKIP_PUSH_CHECKS=1`.

## Vectors & .gitignore

- `conformance/vectors/**` are frozen. Changing one is a protocol change: regenerate
  with `cargo run -p hide-object --features test-vectors --example generate_vectors`,
  update `spec/hide-0.1.md` in the same PR.
- Rejection vectors: `conformance/vectors/rejections/<name>.{hide,test-public,test-secret}`
  listed in `rejections.txt` as `name<TAB>reason`. Both
  `crates/hide-object/tests/vectors.rs` and `conformance/node/verify.mjs` branch on the
  extension; a new extension needs a branch in BOTH. See skill `add-rejection-vector`.
- `.gitignore` ignores `*.hide`, `*.test-secret`, `fuzz/corpus/` globally, with
  `!conformance/vectors/...` exceptions. A NEW vector location needs its own `!` line
  or a clean clone (CI) sees `NotFound` while the local tree passes.
- `.gitattributes` marks `*.hide`/`*.test-secret`/`*.test-public` `binary` per
  extension; a new vector extension needs its own line or `text=auto` rewrites it.
- Round-trip tests cannot catch a symmetric wire change; pin exact bytes.

## Fuzzing

- `rust-toolchain.toml` pins stable, so fuzzing is `cargo +nightly fuzz run`.
- Always `--target x86_64-unknown-linux-gnu`: the runner default resolves to musl and
  ASAN cannot link a static libc. Flags in CI: `-timeout=60 -rss_limit_mb=2048`.
- `fuzz-nightly.yml`: 4 h per target, corpus via `actions/cache` with `restore-keys`
  prefix `fuzz-corpus-<target>-`, a finding opens an issue labelled `fuzz`+`security`.
- Reproducers are in the `fuzz-artifacts-<target>` artifact:
  `gh run download <id> --pattern fuzz-artifacts-<target>`. Inspect bytes with
  python (`open(p,'rb').read().hex()`), never PowerShell (`$b` gets typed as XML).
- A reproducer becomes BOTH a unit regression test and a frozen rejection vector,
  then seeds the corpus. See skill `fuzz-triage`.

## CI / Release

- CI jobs: lint, test, desktop, sdks, interoperability, minimum-supported-rust,
  supply-chain, fuzz. Per-step timing: `gh run view <id> --json jobs` → `steps[]`
  `startedAt`/`completedAt`. Drill to the step before optimising anything.
- Feature flags thrash one target dir: `--features portable` and the plain build
  each mark the other stale. Give the second its own `CARGO_TARGET_DIR` and cache both.
- A tag runs the workflow AS OF THAT TAG: `git show <tag>:.github/workflows/x.yml`
  before re-running a tag-triggered failure.
- Publishing is `publish-sdks.yml`, manual, all OIDC trusted publishing.
  `gh secret list` is empty and must stay so. Trusted publishing cannot create a
  NEW package name: one manual publish per new name. crates.io: 1 new crate / 10 min.
- npm lockfile records not-yet-published optional platform packages with an empty
  version, so `npm ci` fails after every release; CI uses `npm install`. After a
  release: `cd sdk/node; npm install --package-lock-only` and commit.
- Order: CI green → tag `vX.Y.Z` (release.yml, 15 assets) → publish-sdks
  `dry_run=true` → `dry_run=false` → verify via registry APIs → clean-dir install →
  tracker row. See skill `release`.
- `scripts/set-version.ps1 -Version X` bumps 23 files; `-Check` runs in CI `lint`.
- GitHub Pages: `configure-pages` with `enablement: true` still fails (`Resource not
  accessible by integration` — GITHUB_TOKEN cannot create the site). Create it once with
  an admin token: `gh api -X POST repos/hide-protocol/hide/pages -f build_type=workflow`,
  then re-run `pages.yml`. Live: https://hide-protocol.github.io/hide/ (+ `llms.txt`).
- Verify action versions with `gh api repos/<o>/<r>/git/matching-refs/tags/<tag>`;
  `dtolnay/rust-toolchain` and `ruby/setup-ruby` use BRANCHES, not tags.

## Docs / tracker

- `docs/tracker.csv` is canonical (`id,phase,type,title,status,depends_on,surface,
  evidence,notes`). A DONE row needs a verifying COMMAND in `evidence`.
  `docs/TRACKER.md` is the summary; update both in the same commit.
- `node scripts/build-llms-full.mjs` regenerates `llms-full.txt`; `pages.yml` diffs it.
  Regenerate after editing README, `docs/`, or `SECURITY.md`.
- Claims in README/spec must be backed by a test. No stubs. Comments explain why.
- Never claim age lacks post-quantum: it has ML-KEM-768+X25519 since 1.3.0.
