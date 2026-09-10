# HIDE audit status

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

## No third-party audit has been performed.

No security firm, academic group or independent researcher has reviewed HIDE's design or code under any engagement. Nothing below changes that. An unaudited encryption tool should be treated as broken until shown otherwise; the CLI requires `--experimental` for that reason.

## What has been reviewed, and by whom

The only reviews are internal — performed by the maintainers on their own code. They are listed because they are evidence of process, not evidence of security, and because the defects they found are the best indication that others remain.

| Date | Reviewer | Scope | Findings | Status |
| --- | --- | --- | --- | --- |
| 2026-09-08 | maintainers (internal) | MLS credential binding, signature stanza handling, confidential-signature metadata path, identity-log encoding, C ABI panic handling, SDK library loading, ssh-agent confirmation and Windows pipe ACL, Argon2id parameter floor | 7 | all fixed in 0.7.0; each fix has a test that fails on the previous code |
| 2026-09-06 | maintainers (internal) | X25519 small-order points in recipient keys; chunk AAD/nonce byte layout | 2 | fixed in 0.3.0; AAD/nonce bytes now pinned exactly in tests |
| 2026-09-06 | maintainers (internal) | Signature transcript: header-only signing forgeable by any recipient | 1 | design changed before 0.5.0 shipped; transcript binds `SHA-256(plaintext)` |

### The seven 0.7.0 findings

From [../SECURITY.md](../SECURITY.md) and [../CHANGELOG.md](../CHANGELOG.md):

1. **MLS credentials were self-asserted** — a member could present another device's id; nothing proved it held that device's key. Now a HIDE-signed binding over the MLS signature key ([../spec/hide-0.1.md](../spec/hide-0.1.md) §11).
2. **7 of 8 signature stanzas were never verified** — only the first of up to eight public stanzas was checked. `MAX_SIGNATURES` is now 1 and a second stanza is rejected.
3. **One metadata key and nonce sealed two plaintexts** in the confidential-signature path. No disclosure, but nonce reuse under one key.
4. **The identity-log encoding was not canonical** — two event sequences could serialise identically. Every variable-length field is now length-prefixed.
5. **`panic = "abort"` made `HIDE_ERR_PANIC` unreachable** in the C ABI. The FFI now builds with `panic = "unwind"` and catches at the boundary.
6. **`HIDE_LIBRARY` was an unconditional library-injection vector** in every SDK. Honoured only with `HIDE_ALLOW_LIBRARY_OVERRIDE=1`.
7. **The ssh-agent read confirmation from stdin, and the Windows pipe had no ACL.** Confirmation now reads the controlling tty; the pipe is restricted to the current user. (Listed alongside: Argon2id parameters gained a floor — a key file declaring weaker parameters is refused.)

## Automated evidence that exists

These are not audits. They constrain what a bug can look like; they do not show its absence.

- 297 tests, run on Linux, Windows and macOS in CI.
- Property tests (`proptest`): the parser never panics on arbitrary input; any single-byte mutation of a container fails to decrypt; truncation and appended bytes always fail.
- Eight libFuzzer targets under [../fuzz/fuzz_targets](../fuzz/fuzz_targets) (container header, object open, keyring open, identity log, epoch chain, transparency proofs, challenge decode, MLS message), run in CI on every push and for four hours per target every night with a persistent corpus ([fuzz-nightly.yml](../.github/workflows/fuzz-nightly.yml)). A finding files an issue automatically. Three bugs found so far: two fixed in 0.7.0, the third (a key file requesting 2.4 GiB of Argon2 memory, [#6](https://github.com/hide-protocol/hide/issues/6)) fixed on `main`.
- `cargo deny` ([../deny.toml](../deny.toml)) in CI: licence allow-list, a ban on any second cryptographic stack, unknown registries refused, and every duplicated dependency version attributed to its cause so a new one is visible.
- Frozen vectors under [../conformance/vectors](../conformance/vectors), including nine rejection vectors; flipping every byte position of the frozen containers is asserted to fail.
- An independent Node implementation ([../conformance/node/verify.mjs](../conformance/node/verify.mjs)) decrypts the Rust vectors and refuses the rejection vectors.
- Mutation testing was applied by hand to the signing and keyring code during development; results are recorded in commit messages, not in a report.
- `cargo audit` runs in CI (`supply-chain` job); every dependency is pinned to an exact version.

## What an audit should cover

In priority order. File references are the entry points; the normative text is [../spec/hide-0.1.md](../spec/hide-0.1.md).

| # | Component | Why it is first | Where |
| --- | --- | --- | --- |
| 1 | Container key schedule and HPKE/X-Wing composition | A flaw here breaks confidentiality for every file | spec §3; [../crates/hide-crypto/src/lib.rs](../crates/hide-crypto/src/lib.rs) |
| 2 | Authenticated streaming and the FINAL rule | Truncation, reordering, and early plaintext release | spec §5; [../crates/hide-object/src/lib.rs](../crates/hide-object/src/lib.rs) |
| 3 | Header parsing and limits | Untrusted input; bounded canonical CBOR | spec §1–2; [../crates/hide-format/src/lib.rs](../crates/hide-format/src/lib.rs) |
| 4 | Signature transcript and what a recipient can forge | Recipients hold the CEK; the transcript is the only thing that stops them re-encrypting under a valid signature | spec §7; [../crates/hide-sign/src/lib.rs](../crates/hide-sign/src/lib.rs), `transcript()` in hide-object |
| 5 | Identity log: authority-at-position | Revocation is meaningless if a revoked device can author a later entry | spec §8; [../crates/hide-identity/src/lib.rs](../crates/hide-identity/src/lib.rs) |
| 6 | C ABI: memory ownership, panic catching, error codes | Nine SDKs sit on it; a bug is a bug in all of them | [../crates/hide-ffi/src/lib.rs](../crates/hide-ffi/src/lib.rs), [../crates/hide-ffi/include/hide.h](../crates/hide-ffi/include/hide.h) |
| 7 | Key files: Argon2id parameters, purpose byte, seed derivation | The at-rest protection of every secret | [../crates/hide-keyring/src/lib.rs](../crates/hide-keyring/src/lib.rs) |
| 8 | Epoch chain: what "erased" guarantees | Independent random keys, no derivation | spec §9; [../crates/hide-epoch/src/lib.rs](../crates/hide-epoch/src/lib.rs) |
| 9 | RFC 6962 proofs | Consistency-proof forgery would make history rewriting undetectable | spec §10; [../crates/hide-transparency/src/lib.rs](../crates/hide-transparency/src/lib.rs) |
| 10 | MLS credential binding | New in 0.7.0, parsed by no other implementation | spec §11; [../crates/hide-mls/src/lib.rs](../crates/hide-mls/src/lib.rs) |
| 11 | ssh-agent confirmation path and endpoint permissions | A signing oracle reachable by local processes | [../apps/hide-cli/src](../apps/hide-cli/src) |
| 12 | SDK library loading and handle lifetimes | Injection and use-after-free at the language boundary | [../sdk](../sdk) |

Out of scope for a first audit, and stated so a reviewer does not waste time: the cryptographic primitives themselves (`hpke`, `ml-kem`, `ml-dsa`, `ed25519-dalek`, `chacha20poly1305`, `argon2` — upstream crates), the desktop UI (it contains no cryptography), and `mls-rs` internals (upstream, itself unaudited).

## Estimated scope

Our estimate, not a quote. It assumes a reviewer familiar with Rust and with HPKE, reading the spec first.

| Component | Reviewer-days |
| --- | --- |
| Container (format + crypto + object; items 1–3) | 5–7 |
| Signatures and transcript (item 4) | 2–3 |
| Identity log (item 5) | 2 |
| C ABI and one SDK in depth, others by diff (items 6, 12) | 3–4 |
| Key files (item 7) | 1 |
| Epoch chain and transparency (items 8–9) | 2 |
| MLS binding (item 10) | 2 |
| ssh-agent (item 11) | 1 |
| **Total** | **18–22** |

A design review of the spec alone, without reading code, is roughly 3–4 days and would already be valuable.

## How to perform or fund one

- **Perform one**: clone the repository, read [../spec/hide-0.1.md](../spec/hide-0.1.md), start with the table above. Report through the private advisory channel in [../SECURITY.md](../SECURITY.md). Every finding is credited in the changelog and in [advisories.md](advisories.md).
- **Fund one**: open a GitHub issue titled "audit funding" to coordinate. The maintainers have no budget for a commercial audit; a sponsor who engages a firm directly is the realistic path.
- **Commitment**: the full report of any third-party audit will be published in this directory, unredacted, with the maintainers' response and the fix status of each finding. Findings that cannot be fixed will be listed as known limitations in [threat-model.md](threat-model.md).

## Formal verification

None. No component has a machine-checked proof, a Tamarin or ProVerif model, or a verified implementation. It is not planned before 1.0; a third-party code audit is the prerequisite, and a symbolic model of the container key schedule and the signature transcript would be the first candidate after it.
