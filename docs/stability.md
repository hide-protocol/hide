# HIDE stability policy

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

This document says what may change while the version is 0.x, how a change is announced, and what has to be true before 1.0. Current version: 0.6.2 (0.7.0 in progress). It applies to the wire format, the Rust crates, the C ABI, the SDKs and the CLI.

## Wire format

- **Before 1.0 the format may change.** Any change to bytes on disk — container, key file, detached signature, identity log, epoch chain, transparency checkpoint, MLS credential — is a **format change** and is called out in [../CHANGELOG.md](../CHANGELOG.md) under its own heading, with the version that introduced it. A format change bumps the *minor* version.
- **Frozen vectors must keep opening.** The containers under `conformance/vectors/` produced by 0.1.0 are tested byte-for-byte on every commit, in Rust and in the independent Node implementation. A release that cannot open them is not made. Every 0.1.0–0.6.2 container opens in 0.6.2.
- **New capabilities are additive when possible.** Signatures (0.5.0) reused header key 5, which 0.1.0 wrote as an empty array, so unsigned containers stayed byte-identical; signed ones advertise preamble minor 2 so an old reader refuses rather than silently ignores.
- **Vectors are frozen artifacts.** Regenerating them is a protocol change and is done only deliberately (`cargo run -p hide-object --features test-vectors --example generate_vectors`), never as a side effect.
- **Upstream drafts.** X-Wing's byte format has been stable across `draft-ietf-hpke-pq` revisions and its KEM id `0x647A` is IANA-allocated. If the final RFC changed the construction, HIDE would add a new suite id rather than alter suite 1; existing containers would keep opening.
- **After 1.0 the format never breaks.** A reader of version 1.x opens every container written by any 1.y. New features arrive as new suite ids, new optional header keys, or new preamble minors that old readers refuse explicitly.

## Public API, per crate

| Crate | Status | Meaning |
| --- | --- | --- |
| `hide-object` | stable-intent | `encrypt`, `encrypt_signed`, `decrypt`, the `Decrypted` type. Signatures may gain optional parameters; existing calls keep compiling within a minor except when a format change forces otherwise |
| `hide-crypto` | stable-intent | `RecipientPublic`, `RecipientSecret`, `Identity::from_seed`. Secret types will never gain `Debug`, `Clone` or `Serialize` |
| `hide-sign` | stable-intent | `SigningIdentity`, `sign`, `verify`, challenge–response, `SpentNonces` |
| `hide-keyring` | stable-intent | `open`, `protect`, `unprotect_seed`, `KeyPurpose`. Argon2id parameters may be raised; the floor may be raised (which refuses weaker files) |
| `hide-ffi` (C ABI) | stable-intent | Functions and error codes in `include/hide.h`. Additions only; a removed function breaks every SDK at import, so it will not happen in a patch |
| `hide-format` | evolving | Parser internals; used by `hide-object`, not intended for direct use |
| `hide-identity` | evolving | Event types and `Membership` may change shape while the log format is 0.x |
| `hide-epoch` | evolving | `EpochChain` will gain persistence; the in-memory API may change |
| `hide-transparency` | evolving | Proof types follow RFC 6962 and are unlikely to change; the checkpoint format may gain a signature |
| `hide-mls` | evolving | New in 0.6/0.7; follows `mls-rs` 0.56, whose own API is 0.x |
| `hide-wasm` | evolving | Browser surface; not published to crates.io |
| `hide-cli` | internal | The binary is the interface; the crate has no library API. Command names and flags are stable-intent (below) |

"Stable-intent" means: we intend not to break it before 1.0, and if we must, it is a minor bump with a changelog entry and a migration note. "Evolving" means a minor bump may change it without a migration note. "Internal" means no guarantee.

## SemVer for 0.x

| Bump | May include | Never includes |
| --- | --- | --- |
| **Minor** (0.6 → 0.7) | Format changes, API changes in any crate, new features, MSRV bump, dependency major bumps, removed deprecated items | — |
| **Patch** (0.6.1 → 0.6.2) | Bug fixes, security fixes, packaging fixes, documentation, new SDK platform targets | Format changes, API breaks, MSRV bump, removal of anything |

All crates in the workspace share one version (`Cargo.toml` `[workspace.package]`) and are released together; `scripts/set-version.ps1 -Check` runs in CI so the version cannot drift across the 22 files in seven ecosystems that carry it.

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
3. **Two independent implementations** passing the full vector set, including the rejection vectors. The Rust crates are one; the Node verifier under `conformance/node` is a second for the container, and must be extended to signatures, identity logs and epoch chains — or replaced by an implementation maintained outside this repository.
4. The HPKE-PQ specification carrying X-Wing published as an RFC, or a documented decision to freeze on the draft with a HIDE-owned suite id.
5. Epoch secrets persisted, so forward security by erasure is operational rather than demonstrable.
6. The stability table above with no "evolving" row among the crates a container depends on.

1.0 does not require post-quantum MLS, a key directory, hardware key storage, or formal verification. Those remain out of scope and are listed as such in [threat-model.md](threat-model.md).
