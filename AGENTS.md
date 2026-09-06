# HIDE — repository guide

Experimental encrypted-file protocol. Rust workspace; the CLI exists to exercise the format.

## Commands

- `cargo test --workspace --all-features` — full suite (Windows and Linux).
- `cargo run -p hide-object --features test-vectors --example generate_vectors` — regenerate vectors;
  only when the format intentionally changes.
- `cd conformance/node; pnpm install --ignore-workspace; node verify.mjs` — independent verification.
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

## Conventions

- Comments explain why, not what. No stubs or placeholder functions.
- Dependency versions are pinned exactly, because the wire format depends on them.
- Vectors are frozen artifacts: changing them is a protocol change and must be deliberate.
