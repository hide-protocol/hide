# HIDE stability policy

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

This document says what may change while the version is 0.x, how a change is announced, and what has to be true before 1.0. It applies to the wire format, the Rust crates, the C ABI, the SDKs and the CLI. The normative wire format is [../spec/hide-1.md](../spec/hide-1.md); 0.9.0 is its release candidate.

## Wire format

### Frozen from 0.9.0

These are the HIDE 1 wire format ([../spec/hide-1.md](../spec/hide-1.md), "Frozen vs implementation-defined"). From 0.9.0 they change only if a security flaw forces it, and such a change is recorded in the spec's change log (Appendix B) and in [../CHANGELOG.md](../CHANGELOG.md) with the release that made it.

- The container (spec §1–§7): preamble, protected header, recipient and signature stanzas, key schedule, metadata, payload, both signature transcripts, and the read rules for legacy minor 2.
- HIDE-Sign (§8): key derivation, the signed payload framing, verification rules.
- Key files (§9): the unprotected 32-byte master seed, the protected `HIDE-KEY` file, the recipient and signing public key files.
- The identity log (§10), including the read rule for the 0.6–0.8 six-item entry head.
- The epoch chain (§11).
- Transparency hashing and proof verification (§12).
- The MLS credential binding (§13).
- Every domain-separation label and registry (spec Appendix A).

### Implementation-defined

Described in spec §14 so other tools can interoperate with the reference implementation, but they may change in any release without a format version:

- ASCII armor for messages and public keys.
- The challenge format (`hide_sign::Challenge`).
- The detached-signature file (`<file>.hide-sig`).
- The epoch keystore file (`HIDE-EPK`). It holds one holder's secrets for that holder's own tool and is never exchanged; epochs interoperate through the public, frozen epoch chain.
- CLI commands and flags, SDK and C ABI functions, and the text of error messages. Their own stability is governed by the tables below, not by the format.

### How the format evolves without breaking

- **The preamble minor is a non-breaking revision number.** Writers of HIDE 1 write minor 1. A reader accepts any minor except 0 and processes minor ≥ 3 exactly as minor 1; the minor is inside the header MAC and the signature transcript, so it cannot be altered undetected. Minor 2 is the legacy HIDE/0.5–0.8 signed form: still read, with its own transcript, never written. Minor 0 is refused.
- **Every preamble flag is critical.** A reader refuses a container with a flag it does not know. Flag `0x01` (SIGNED) marks a signed container; a stripped or unexpected signature is refused.
- **Extension ranges.** Header and metadata keys 64–65535 are ignorable byte-string extensions (at most 16, each at most 64 KiB): a reader that does not understand one keeps its bytes, which are authenticated and signed, and opens the container. Keys 6–63 are critical and refused while unassigned. Unknown recipient stanza types are skipped (a container with only unknown stanzas has no matching recipient); unknown signature stanzas are refused.
- **What this means in practice.** A later 1.x can add optional data that a 0.9.0 reader opens, or a critical feature that a 0.9.0 reader refuses explicitly. It cannot add something an old reader silently misreads. HIDE 1 writers emit no extensions, so an unsigned HIDE 1 container without extensions is structurally identical to HIDE/0.1 and opens in every 0.x reader; a signed HIDE 1 container (flag `0x01`) does not open in 0.1–0.8 readers.
- **Old files keep opening.** Every container, key file and identity log written by 0.1–0.8 remains readable. The frozen vectors under `conformance/vectors/` are tested byte-for-byte on every commit, in Rust and in the independent Node implementation, and `conformance/vectors/manifest.json` lists every vector with its expected outcome and SHA-256 ([../conformance/vectors/README.md](../conformance/vectors/README.md)). A release that cannot open them is not made.
- **Vectors are frozen artifacts.** The generators refuse to rewrite an existing vector with different bytes; changing one is a protocol change and is done only deliberately, never as a side effect.
- **Upstream drafts.** X-Wing's byte format has been stable across `draft-ietf-hpke-pq` revisions and its KEM id `0x647A` is IANA-allocated. If the final RFC changed the construction, HIDE would add a new suite id rather than alter suite 1; existing containers would keep opening.
- **Before 0.9.0 the format changed in minor releases** (0.5.0 signatures, 0.6.0 identity logs and epochs, 0.7.0 one signature and the MLS binding). That is history; see the spec change log.

## Public API, per crate

| Crate | Status | Meaning |
| --- | --- | --- |
| `hide-object` | stable-intent | `encrypt`, `encrypt_signed`, `decrypt`, the `Decrypted` type. Signatures may gain optional parameters; existing calls keep compiling within a minor except when a format change forces otherwise |
| `hide-crypto` | stable-intent | `RecipientPublic`, `RecipientSecret`, `Identity::from_seed`. Secret types will never gain `Debug`, `Clone` or `Serialize` |
| `hide-sign` | stable-intent | `SigningIdentity`, `sign`, `verify`, challenge–response, `SpentNonces` |
| `hide-keyring` | stable-intent | `open`, `protect`, `unprotect_seed`, `KeyPurpose`. Argon2id parameters may be raised; the floor may be raised (which refuses weaker files). Since 0.8.0 `open` also enforces ceilings (memory 8–256 MiB, parallelism ≤ 4, passes 1–64), which may be adjusted |
| `hide-ffi` (C ABI) | stable-intent | Functions and error codes in `include/hide.h`. Additions only; a removed function breaks every SDK at import, so it will not happen in a patch |
| `hide-format` | evolving | Parser internals; used by `hide-object`, not intended for direct use |
| `hide-identity` | evolving | The log's bytes are frozen (spec §10); the Rust event types and `Membership` may still change shape |
| `hide-epoch` | evolving | The chain's bytes are frozen (spec §11); the in-memory `EpochChain` API may change. Epoch secrets persist in `hide-keyring`'s implementation-defined `EpochStore` |
| `hide-transparency` | evolving | Proof types follow RFC 6962 and are unlikely to change; the checkpoint format may gain a signature |
| `hide-mls` | evolving | New in 0.6/0.7; follows `mls-rs` 0.56, whose own API is 0.x |
| `hide-wasm` | evolving | Browser surface; not published to crates.io |
| `hide-cli` | internal | The binary is the interface; the crate has no library API. Command names and flags are stable-intent (below) |

"Stable-intent" means: we intend not to break it before 1.0, and if we must, it is a minor bump with a changelog entry and a migration note. "Evolving" means a minor bump may change it without a migration note. "Internal" means no guarantee.

## SemVer for 0.x

| Bump | May include | Never includes |
| --- | --- | --- |
| **Minor** (0.9 → 0.10) | API changes in any crate, new features, MSRV bump, dependency major bumps, removed deprecated items, changes to implementation-defined formats | A change to a frozen format, unless a security flaw forces it (then recorded in the spec change log) |
| **Patch** (0.6.1 → 0.6.2) | Bug fixes, security fixes, packaging fixes, documentation, new SDK platform targets | Format changes, API breaks, MSRV bump, removal of anything |

All crates in the workspace share one version (`Cargo.toml` `[workspace.package]`) and are released together; `scripts/set-version.ps1 -Check` runs in CI so the version cannot drift across the 23 files in seven ecosystems that carry it.

## Minimum supported Rust version

MSRV is **1.85** (`rust-version` in `Cargo.toml`), verified in CI by the `minimum-supported-rust` job. Raising it is a **minor** bump and is listed in the changelog. The toolchain used for development is whatever `rust-toolchain.toml` pins.

## Deprecation

An item scheduled for removal is marked `#[deprecated]` (Rust) or documented as deprecated (C header, SDKs, CLI) for **two minor releases** before removal. Example: `hide test-keygen` was deprecated in 0.2.0 and still works; it remains until at least two minors after its deprecation note. A deprecation is not a break; the removal is, and happens only in a minor.

## SDK surfaces covered

| Surface | Covered by this policy | Notes |
| --- | --- | --- |
| C header `crates/hide-ffi/include/hide.h` | Yes — stable-intent | The single seam every binding uses; the `c_abi` test asserts header constants equal the Rust ones |
| Python `hide_protocol` | Yes — stable-intent for the public names in `__init__.py` | Underscore-prefixed modules are internal |
| Node `hide-protocol` | Yes — stable-intent for exports of `index.ts` | Platform packages `@hide-protocol/<platform>` are internal to the loader |
| WASM `@hide-protocol/wasm` | Evolving | Function signatures differ from Node (positional, concatenated recipients) and may converge |
| Go `sdk/go` | Stable-intent | Exported identifiers only |
| Java `org.hide-protocol:hide` | Evolving | Not yet on Maven Central |
| Ruby `hide-protocol` | Stable-intent | Public methods of `Hide` |
| PHP `hide-protocol/hide` | Evolving | Not yet on Packagist |
| .NET `HideProtocol` | Stable-intent | Public types in the `HideProtocol` namespace |
| CLI `hide` | Stable-intent | Subcommand names and long flags; output text is not stable and should not be parsed |
| Desktop app | Not an API | Opens what the CLI writes; enforced by `src-tauri/tests/interop.rs` |

Cross-surface agreement is enforced by `conformance/cross-surface/verify.mjs`: each surface must open every other surface's output and the frozen vectors, and a missing surface fails rather than skips.

## What 1.0 requires

All of the following, in this order of dependency:

1. **A third-party audit** of the container format, the key schedule, the authenticated streaming and the signature transcript (items 1–4 in [audit-status.md](audit-status.md)), with every finding fixed or documented as a known limitation, and the report published unredacted.
2. **One year of frozen container format** after the last format change to suite 1, measured from the release that made it.
3. **Two independent implementations** passing the full vector set in `conformance/vectors/manifest.json`, including the rejection vectors. The Rust crates are one; the Node verifier under `conformance/node` (`verify.mjs` for the container and signatures, `subsystems.mjs` for identity logs, epoch chains and transparency proofs) is written in this repository by the same maintainers, so an implementation maintained outside it is still wanted.
4. The HPKE-PQ specification carrying X-Wing published as an RFC, or a documented decision to freeze on the draft with a HIDE-owned suite id.
5. Epoch secrets persisted, so forward security by erasure is operational rather than demonstrable.
6. The stability table above with no "evolving" row among the crates a container depends on.

The one-year clock in criterion 2 starts at 0.9.0, the format release candidate. Meeting the format freeze alone does not make 1.0: every criterion above must hold. Current status of each: [audit-status.md](audit-status.md#road-to-10).

1.0 does not require post-quantum MLS, a key directory, hardware key storage, or formal verification. Those remain out of scope and are listed as such in [threat-model.md](threat-model.md).
