---
name: add-rejection-vector
description: Freeze a new negative conformance vector under conformance/vectors/rejections/ for a container (.hide), key file (.test-secret) or recipient public key (.test-public) — the file, the rejections.txt row, the extension branch in crates/hide-object/tests/vectors.rs AND conformance/node/verify.mjs, the `listed >= N` floor, the .gitignore exception, and the verifying commands. Use after a fuzz finding, after adding a new refusal rule, or whenever a class of malformed input gains a test.
---

# Add a frozen rejection vector

A rejection vector is an input that MUST be refused, shared between the Rust
tests and the independent Node verifier so a second implementation can assert
the same list. Ten exist (`conformance/vectors/rejections/`). Adding one is a
spec-visible change: commit the vector, the index, both verifiers and the
tracker together.

## 1. Produce the bytes

- Container: extend `crates/hide-object/examples/generate_rejections.rs` with a
  new case (mutate a real container produced from the fixed `recipient.test-public`),
  then `cargo run -p hide-object --features test-vectors --example generate_rejections`.
  Never hand-edit an existing `.hide`.
- Key file / public key / fuzz reproducer: copy the exact bytes. Confirm size and
  content with python, not PowerShell:
  `python -c "import sys,pathlib; b=pathlib.Path(sys.argv[1]).read_bytes(); print(len(b), b.hex(' '))" <file>`

Name: `kebab-case-reason`. Extension decides the verifier branch:

| Extension | Refused by (Rust) | Refused by (Node) |
|---|---|---|
| `.hide` | `decrypt_to_staging(.., recipient.test-secret)` is `Err` | `decrypt()` rejects |
| `.test-secret` | `hide_keyring::unprotect(bytes, "passphrase")` is `Err` | structural check on the header (m_cost at offset 10 > 256 MiB) |
| `.test-public` | `RecipientPublic::from_bytes` is `Err` | structural check (X25519 half `[1184..1216]` all zero) |

A NEW extension needs a new branch in BOTH files (step 3) and a `.gitignore`
exception (step 4).

## 2. Index row

Append to `conformance/vectors/rejections/rejections.txt`, TAB-separated, one
line, reason in the imperative that a second implementer can act on:

```
argon2-memory.test-secret	key file header demands 2.4 GiB of Argon2 memory; refuse before allocating
```

`.hide` entries omit the extension; key/public entries include it. Every file
on disk must be listed — the Rust test counts the directory and compares.

## 3. Verifiers

`crates/hide-object/tests/vectors.rs` `every_frozen_rejection_vector_is_refused`:

- Existing extension: nothing to add except the floor:
  `assert!(listed >= 10, ...)` → `listed >= 11`. The floor is what makes a
  deleted vector fail instead of silently shrinking the set.
- New extension: add an `if name.ends_with(".<ext>") { ... continue; }` branch
  BEFORE the container fallthrough, calling the refusing API and asserting
  `is_err()` with `"{name} must be refused: {reason}"`.

`conformance/node/verify.mjs` (loop over `index` near line 283):

- Existing extension: nothing.
- New extension: add `if (name.endsWith(".<ext>")) { ...; continue; }` with a
  structural assertion an independent implementation can make from the bytes
  alone (Node has no Argon2/HPKE key parser; it asserts the offending field).
  The final `console.log` prints `index.length`, so the count updates itself.

Also `fuzz/fuzz_targets/*.rs` need nothing; but add a `cp` line for the new
file in the "Seed the corpus" step of BOTH `ci.yml` and `fuzz-nightly.yml` if
the extension is not already globbed there (`*.hide`, `*.test-secret` are).

## 4. .gitignore

`*.hide` and `*.test-secret` are ignored globally. Existing exceptions:

```
!conformance/vectors/*.hide
!conformance/vectors/rejections/*.hide
!conformance/vectors/*.test-secret
!conformance/vectors/rejections/*.test-secret
```

A new ignored extension or a new directory needs its own `!` line, else the
local tree passes and a clean clone (CI) fails with `NotFound`. Check:

```powershell
git check-ignore -v conformance/vectors/rejections/<file>     # must print nothing
git add conformance/vectors/rejections/<file>; git status --short conformance/vectors
```

`.gitattributes` marks `*.hide`, `*.test-secret`, `*.test-public` and
`conformance/vectors/*.txt` `binary` per EXTENSION. A new extension needs its own
`<ext> binary` line or `* text=auto eol=lf` rewrites the bytes on checkout.

## 5. Verify

```powershell
cargo test -p hide-object --test vectors
Set-Location conformance/node; node verify.mjs; Set-Location ../..
```

Expect `PASS independent Node refuses all <N> rejection vectors` with the new N.
Also run the owning crate's unit regression test for the same bytes, and:

```powershell
cargo test --workspace --all-features
cargo test --manifest-path apps/hide-desktop/src-tauri/Cargo.toml
```

Mutation check: temporarily comment out the refusal in the crate → the vectors
test must FAIL naming your vector. Restore.

## 6. Record

- `docs/tracker.csv` row: `type=vector`, `status=DONE`,
  `evidence=cargo test -p hide-object --test vectors; node conformance/node/verify.mjs`.
- `docs/TRACKER.md`: bump "N frozen rejection vectors".
- `CHANGELOG.md` `## Unreleased`: one line, name + reason.
- `spec/hide-0.1.md` only if the refusal rule itself is new to the spec.

Commit explicit paths (shared clone). `.husky/pre-push` refuses a push while
`conformance/vectors` has uncommitted changes.
