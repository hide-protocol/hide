# HIDE — repository guide

Experimental encrypted-file protocol. Rust workspace; the CLI exists to exercise the format.

## Commands

- `cargo test --workspace --all-features` — full suite (Windows and Linux).
- `cd apps/hide-desktop; pnpm install --ignore-workspace; pnpm tauri build` — desktop app.
  `pnpm build:portable` produces the single portable executable. The desktop crate is
  deliberately OUTSIDE the cargo workspace: it needs a built frontend, which would drag
  Node into `cargo test --workspace` in CI. Test it with
  `cargo test --manifest-path apps/hide-desktop/src-tauri/Cargo.toml`.
- `cargo run -p hide-object --features test-vectors --example generate_vectors` — regenerate vectors;
  only when the format intentionally changes.
- `cd conformance/node; pnpm install --ignore-workspace; node verify.mjs` — independent verification.
- `npm install` at the root installs the husky hooks: pre-commit runs fmt +
  clippy, pre-push runs the full suite and a release build.
- Linux check: copy `Cargo.toml crates apps conformance` into WSL and run cargo there. Export a clean
  `PATH` first; the inherited Windows PATH contains parentheses that break `bash -lc`.

## Invariants

- No new cryptographic primitives, and no hand-rolled KEM combiner.
- Secret types never derive `Debug`, `Clone` or `Serialize`; they zeroize on drop.
- Validate limits before allocating from any length field in untrusted input.
- Authenticate the exact received `protected` bytes; never re-serialize before verifying.
- Never publish decrypted output before the FINAL record authenticates.
- Never use a decrypted filename to choose an output path.
- Reject small-order X25519 components in recipient public keys.
- Streaming allocates nothing per chunk: reuse the fixed buffers and the `ChunkCipher` instance.
- Claims in README/spec must be backed by a test; do not describe unimplemented guarantees.
- The desktop app must never contain its own cryptography: it calls the same crates as the CLI.
  Key material stays in Rust and never crosses into the webview.
- The CLI and the desktop app must open each other's output; `src-tauri/tests/interop.rs`
  is what enforces this, and it must not be allowed to silently skip in CI.
- Never read a passphrase from anything but a terminal.

## Conventions

- Comments explain why, not what. No stubs or placeholder functions.
- Dependency versions are pinned exactly, because the wire format depends on them.
- Vectors are frozen artifacts: changing them is a protocol change and must be deliberate.

## Agent config

- `.github/instructions/hide-conventions.instructions.md` (always on): invariants and
  verified gotchas — untrusted input, workspace layout, vectors/.gitignore, fuzzing, CI/release.
- `.github/instructions/rust-crates.instructions.md` (`crates/**`, `apps/**` `.rs`): error
  enums, bound-before-allocate, canonical re-encode, test style.
- Skills: `.github/skills/fuzz-triage`, `release`, `add-rejection-vector` — step lists with commands.
