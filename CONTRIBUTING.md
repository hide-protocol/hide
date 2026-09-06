# Contributing

Thanks for looking at HIDE. The most valuable contributions right now are
independent implementations, adversarial tests, and review of the wire format.

## Before you start

Read [spec/hide-0.1.md](spec/hide-0.1.md). The specification is the source of
truth; the Rust code is one implementation of it.

## Running everything

Install the git hooks once, so failures surface locally instead of in CI:

```powershell
npm install
```

`pre-commit` runs `cargo fmt --check` and clippy (about 3 s warm, and skipped
entirely when no Rust file is staged). `pre-push` runs the full test suite and a
release build (about 20 s warm), and refuses the push if `conformance/vectors`
has uncommitted changes.

Node is only needed for these hooks and for the independent verifier; the
protocol itself is pure Rust.

```powershell
cargo test --workspace --all-features
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Independent cross-check, which must pass whenever the format changes:

```powershell
cd conformance/node
npm install --no-package-lock
node verify.mjs
```

## Rules that are not negotiable

These exist because breaking them silently is easy and the failure is invisible:

- **No new cryptographic primitives**, and no hand-rolled KEM combiner. Compose
  reviewed crates.
- **Secrets never derive `Debug`, `Clone` or `Serialize`**, and they zeroize on
  drop.
- **Validate limits before allocating** from any length field in untrusted input.
- **Authenticate the exact received bytes.** Never re-serialize a structure and
  verify the result.
- **Never publish decrypted output before the FINAL record authenticates.**
- **Never use a decrypted filename to choose an output path.**
- **Every claim in the README or spec needs a test behind it.** Do not describe
  a guarantee that is not implemented.

## Changing the wire format

The vectors under `conformance/vectors/` are frozen artifacts. If a change makes
them fail, that is a protocol change, and it must be deliberate:

1. Say in the PR why the format has to change.
2. Regenerate:
   `cargo run -p hide-object --features test-vectors --example generate_vectors`
3. Confirm `conformance/node/verify.mjs` still passes, so the new format is
   still implementable from the spec alone.
4. Update `spec/hide-0.1.md` in the same PR.

While the version is 0.x, breaking the format is allowed. After 1.0 it is not.

## Tests

New behaviour needs a test that would fail without it. For anything touching
the format or the key schedule, prefer a test that pins the exact bytes.

A round-trip test alone is not sufficient there: encrypt and decrypt share the
same code, so a symmetric change passes unnoticed. This has already happened
once, and only the frozen vectors caught it.

Adversarial cases are worth more than happy paths: truncation, reordering,
duplication, trailing bytes, oversized lengths, and single-byte mutations.

## Commits and PRs

Conventional Commits (`fix:`, `feat:`, `docs:`, `test:`), imperative mood. Keep
PRs focused. Say what you ran and what you saw — "tests pass" without output is
not evidence.
