# Contributing

Thanks for looking at HIDE. The most valuable contributions right now are
independent implementations, adversarial tests, and review of the wire format.

## Before you start

Read [spec/hide-1.md](spec/hide-1.md). The specification is the source of
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

The toolchain is pinned to `stable` in `rust-toolchain.toml`; the minimum
supported Rust version is 1.88 (`rust-version` in the root `Cargo.toml`), and CI
checks that the workspace still builds with it.

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
  existing crates (RustCrypto, `hpke`) and pin them to an exact version. None of
  the post-quantum crates has had an independent audit, by their own READMEs, so
  "use a crate" is not the same as "use audited code".
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
4. Update `spec/hide-1.md` in the same PR.

The format is frozen since 0.9.0. Before 1.0 it changes only to fix a security
flaw; a change for any other reason is not accepted. A change that does happen
is recorded in the specification's change log (`spec/hide-1.md`, Appendix B)
and in the CHANGELOG, and restarts the one-year clock that
[docs/stability.md](docs/stability.md) requires before 1.0.

The **rejection vectors** under `conformance/vectors/rejections/` are frozen too.
Each is a container or key file that MUST be refused, with the reason in
`conformance/vectors/rejections/rejections.txt`;
both the Rust tests and `conformance/node/verify.mjs` consume them. A new
class of malformed input should get a vector there, regenerated with
`cargo run -p hide-object --features test-vectors --example generate_rejections`.

## Stability and versioning

What may change before 1.0, how a format change is signalled, and what a minor
version promises is written down in [docs/stability.md](docs/stability.md).
Read it before proposing a change to a public API or a wire layout.

## Tests

New behaviour needs a test that would fail without it. For anything touching
the format or the key schedule, prefer a test that pins the exact bytes.

A round-trip test alone is not sufficient there: encrypt and decrypt share the
same code, so a symmetric change passes unnoticed. This has already happened
once, and only the frozen vectors caught it.

Adversarial cases are worth more than happy paths: truncation, reordering,
duplication, trailing bytes, oversized lengths, and single-byte mutations.

### Fuzzing

Eleven libFuzzer targets live in `fuzz/fuzz_targets/`: `format_header`,
`object_open`, `keyring_open`, `identity_log`, `epoch_chain`,
`transparency_proofs`, `challenge_decode`, `mls_message`, `epoch_store`,
`checkpoint_note` and `identity_bindings`. CI runs each for 45 seconds on every
push and for four hours every night. Every decoder of untrusted bytes needs
one. CI and the nightly job fuzz on Linux; on Windows, run this inside WSL:

```sh
cargo +nightly fuzz run --target x86_64-unknown-linux-gnu format_header -- \
  -max_total_time=60 -timeout=60 -rss_limit_mb=2048
```

The explicit `--target` matters: without it the build can resolve to musl,
and AddressSanitizer cannot link a static libc.

A crash input belongs in a regression test, and usually also in
`conformance/vectors/rejections/`.

## Reporting a vulnerability

Not in a pull request or a public issue. Use the private advisory form
(<https://github.com/hide-protocol/hide/security/advisories/new>) or mail
<hide-security@codai.ro>; [SECURITY.md](SECURITY.md) has the details.

## Licence of contributions

By submitting a contribution you agree that it is licensed under Apache-2.0
(Section 5 of the licence), and you certify the Developer Certificate of Origin
1.1 (<https://developercertificate.org>) by adding
`Signed-off-by: Name <email>` to each commit (`git commit -s`). Commit names and
email addresses become a permanent, public part of the history; use your GitHub
noreply address if you prefer.

## Commits and PRs

Conventional Commits (`fix:`, `feat:`, `docs:`, `test:`), imperative mood. Keep
PRs focused. Say what you ran and what you saw — "tests pass" without output is
not evidence.
