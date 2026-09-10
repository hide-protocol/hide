---
applyTo: "crates/**/*.rs, apps/**/*.rs"
description: "Rust coding rules observed in the HIDE crates: error enums, bound-before-allocate, canonical re-encode, test style"
---

# Rust in HIDE crates

## Errors

- One `pub enum XxxError` per crate, `#[derive(Debug, Error, PartialEq, Eq)]` via
  `thiserror::Error`, short lowercase `#[error("...")]` strings (see
  `hide-format/src/lib.rs` `FormatError`). Variants are unit-like unless a payload is
  needed. Convert foreign errors with `#[from]` or a manual `From`.
- `CryptoError::Random(#[from] getrandom::Error)` is not `Eq`; an `Eq` enum that must
  carry it stores a `String` and implements `From` by hand (`KeyringError` does).
- One error per attacker distinction that matters; do not leak WHICH check failed
  where the spec says "refuse" (e.g. header MAC vs version byte both yield
  `NoMatchingRecipient`).

## Bound before allocate (every length/count/cost from untrusted bytes)

Declare the ceiling as a named `const`, check the range, then read. From
`hide-keyring/src/lib.rs`:

```rust
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 4;
// ...
if parallelism == 0
    || parallelism > MAX_PARALLELISM
    || !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
    || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
    || memory / 8 < parallelism
{
    return Err(KeyringError::UnreasonableParameters);
}
```

And `hide-format/src/lib.rs`: `if header_len == 0 || header_len > MAX_HEADER_LEN {
return Err(FormatError::HeaderTooLarge); }` runs before any `Vec` exists.

- Never `Vec::with_capacity(n)` where `n` came off the wire. Push into a bounded
  reader or pre-check `n <= MAX_*`.
- `usize::try_from(x).map_err(...)`, never `x as usize` (truncates on 32-bit,
  and hides an oversized value on 64-bit).
- Loops driven by an untrusted number iterate over its bit width:
  `1 << (n - 1).ilog2()` (`hide-transparency/src/lib.rs`), never
  `while probe <= n { probe <<= 1 }`.
- Streaming: allocate nothing per chunk; reuse fixed buffers and one `ChunkCipher`.

## Canonical decode

Decoders of hash-linked or signed structures re-encode and compare, so exactly one
byte string exists per value (`hide-identity/src/lib.rs`):

```rust
if encode(&entries)? != bytes {
    return Err(IdentityError::Malformed);
}
Ok(entries)
```

Do this in every `decode_*` that feeds a hash, a signature or a transparency leaf.
The matching fuzz target asserts `encode(decode(x)) == x`.

## Secrets

- No `Debug`, `Clone`, `Serialize` on secret types; `ZeroizeOnDrop`.
- Export only through a loudly named accessor (`expose_seed_for_sealing()`).
- Tests cannot `unwrap_err()` a `Result<Secret, _>`; use a `match` helper.
- Passphrases are read from a terminal only.

## Tests (style as in `crates/*/tests/*.rs`)

- Integration tests return `Result<(), Box<dyn Error>>` and use `?`.
- Paths anchor on `env!("CARGO_MANIFEST_DIR")` and join `../../conformance/vectors`;
  the cwd on CI runners is not guaranteed.
- Assert exact bytes for anything touching the wire or the key schedule; a
  round-trip test is symmetric and passes through a symmetric bug.
- Attacker-shaped tests bypass the friendly constructor (`client_for`,
  `encrypt_*_for_test`) and build the hostile input at the source; byte-patching a
  MAC-covered header only reaches the MAC check.
- Every claim in a `#[test]` name is what the assertion proves; a test that greps its
  own source is bounded to the function body.
- Mutation-test signing and verification paths; a surviving mutant is either a
  missing test or a redundant defence — decide which before adding a test.
- `[profile.test.package."*"] opt-level = 2` is set; do not time tests in debug.
- Skip-if-absent is decorative in CI; the desktop job greps the skip message and
  fails. Prefer failing to skipping.

## Misc

- Comments explain why. No stubs, no `todo!()`, no placeholder functions.
- `unsafe_code = "forbid"` everywhere but `hide-ffi`; Windows named pipes go through
  `interprocess` with the full `\\.\pipe\name` path.
- Two crates cannot both have `examples/<same>.rs` on Windows (LNK1104).
- `hybrid-array` converts from `&[T; N]`, not `&[T]`: `slice.try_into()?` first.
- `ml_dsa::VerifyingKey` has `PartialEq` only, no `Eq`.
