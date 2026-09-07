# HIDE — canonical tracker

The single source of truth for what exists, what is planned, and why. Machine
readable status lives in [`tracker.csv`](tracker.csv); this file carries the
reasoning that a spreadsheet cell cannot hold.

Update both in the same commit as the work they describe. A row that claims
DONE without a verifying command in the Evidence column is not done.

---

## Where the project stands

Shipped through **v0.4.0**: a file-format engine (X-Wing = X25519 + ML-KEM-768,
ChaCha20-Poly1305, 64 KiB authenticated streaming), a CLI on seven targets, a
desktop app, and eight language SDKs over one C ABI.

**The gap this milestone closes.** Every one of those surfaces can prove a
container was *not altered*. None can prove *who made it*. There is no
signature primitive anywhere in the codebase, which is why SSH authentication,
signed containers and any challenge-response login are all currently
impossible.

---

## Milestone 0.5.0 — identity and authentication

### Goal

Give a HIDE identity the ability to **sign**, then build the three things that
follow from it: signed containers, an SSH agent, and a challenge-response
primitive for API and browser login.

### Decisions

These were put to the user as questions; the answers were not given before work
started, so the following were taken as the defaults most consistent with the
project's existing invariants. **Each is reversible until 0.5.0 is tagged** —
raise it if you disagree.

| # | Decision | Chosen | Why | Cost |
| --- | --- | --- | --- | --- |
| D1 | Signature scheme | **Hybrid Ed25519 + ML-DSA-65**, concatenated, both must verify | The KEM is already hybrid. A signature that is only classical would let a future quantum adversary forge every identity retroactively, which contradicts the project's stated purpose | ~3.4 KB per signature, ~2 KB public key. The container already carries 1.2 KB of encapsulation, so this does not change the order of magnitude |
| D2 | SSH integration | **Agent first**, export as an escape hatch | See the constraint below | The agent offers only the Ed25519 half |
| D3 | Scope | **The whole chain**, through all eight SDKs | Shipping the core without the bindings is the incomplete-ripple failure this repo has avoided so far | Touches nearly every file |
| D4 | Identity derivation | Signing key is **separate** from the encryption key, both derived from one seed | Compromise of one must not imply the other, and the seed keeps a single thing to back up | One extra key to carry in the file format |

### The constraint that shapes D2

**OpenSSH does not accept post-quantum signatures for user authentication.**
Verified against the current OpenSSH: user auth accepts `ssh-ed25519`, the
`sk-*` FIDO2 types and RSA. Post-quantum exists *only* in key exchange
(`mlkem768x25519-sha256`), never in identity.

So `ssh user@host` against an unmodified server **cannot** be made to accept an
ML-DSA signature. What is achievable, and what this milestone builds:

- `hide agent` speaks the ssh-agent protocol and offers the **Ed25519 half** of
  the identity. This works today against any unmodified OpenSSH server, GitHub
  and GitLab included.
- The private key stays sealed with Argon2id inside HIDE rather than sitting as
  plaintext in `~/.ssh`.
- The **ML-DSA half is used everywhere HIDE controls both ends**: signed
  containers and challenge-response. Those are genuinely post-quantum.

This must be stated plainly in the README. Claiming "post-quantum SSH" would be
false, and the whole point of the security posture here is not to overclaim.

### Stories

- **S1** As someone holding a HIDE identity, I can sign a container so a
  recipient learns who sent it, not merely that it is intact.
- **S2** As a developer, I can `git push` to GitHub authenticated by a key that
  never exists in plaintext on disk.
- **S3** As a service, I can hand a client a challenge and verify the response
  against a public key, with no shared secret and no password.
- **S4** As a maintainer, I can verify a signature from any of the eight SDKs
  and get a byte-identical verdict.

### Non-goals for 0.5.0

Named so they are not mistaken for oversights: no key transparency or
directory; no revocation or expiry (a compromised key must be replaced out of
band); no certificate authority or web of trust; no OpenSSH *server* patch; no
forward secrecy for stored objects.

---

## Status

See [`tracker.csv`](tracker.csv). Summary of the phases:

| Phase | What it delivers |
| --- | --- |
| P1 | `hide-sign` crate: hybrid keypair, sign, verify, frozen test vectors |
| P2 | Signature in the wire format, and `spec/` updated |
| P3 | CLI: `sign`, `verify`, signed `encrypt`, identity management |
| P4 | `hide agent`: ssh-agent protocol, plus `hide ssh-key` export |
| P5 | Challenge-response: nonce, domain separation, replay window |
| P6 | C ABI + all eight SDKs + cross-surface conformance |
| P7 | Release 0.5.0, verified end to end against the published artifacts |

---

## Log

### P1 — `hide-sign` (crate complete, KATs partial)

15 tests pass, clippy is clean at `-D warnings`, and the whole workspace still
passes. Three findings worth keeping, because each was a wrong assumption that
a green suite would not have caught:

- **`ed25519-dalek` accepts an all-zero public key at parse time.** Point
  decompression is deferred, so a degenerate key is only refused at
  verification. The test now asserts the property that actually matters — such
  a key can never validate anything — instead of asserting a rejection that
  does not happen.
- **Mutation testing found two decorative tests.** Replacing `verify_strict`
  with plain `verify`, and deriving both halves from the same HKDF info, both
  left the suite green. `.copilot-tmp/mutate-sign.ps1` now covers seven
  mutations, all DETECTED. Re-run it after touching `verify` or `from_seed`.
- **A source-inspecting test can satisfy itself.** The `verify_strict` guard
  originally searched a slice that contained its own literal, so it passed
  under the mutation. It is now bounded to the function body. Any test that
  greps its own source must be mutation-checked.

Frozen bytes now pin **both** halves of the verifying key for seed `0x42`.
Changing either is a protocol change, not a refactor.

Remaining in P1: FIPS-204 ML-DSA known-answer vectors (P1.5) and the frozen
signature vectors under `conformance/vectors` (P1.6).

---

## Rules that apply to this milestone

Carried from `AGENTS.md`, repeated because they are what makes the work
trustworthy:

- No new cryptographic primitives, and no hand-rolled hybrid construction.
  Compose reviewed crates.
- A hybrid signature verifies **only if both halves verify**. Accepting either
  alone silently reduces security to the weaker one.
- Secret types never derive `Debug`, `Clone` or `Serialize`; they zeroize.
- Validate every length from untrusted input before allocating.
- Never publish output before verification completes.
- Every claim in README or spec is backed by a test.
- Signature vectors, once frozen, are a protocol artifact: changing them is a
  format change and must be deliberate.
