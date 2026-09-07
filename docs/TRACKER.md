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
| D5 | What a signature covers | A **transcript** binding suite, object id, recipient set, metadata and `SHA-256(plaintext)` | Signing the header alone is forgeable: every recipient holds the CEK and the payload salt is public, so a recipient can re-encrypt different content under an unchanged header and the signature still verifies | Signing buffers the payload, so it is no longer one-pass |
| D6 | Signature placement | **Both**, chosen per container: public in the header, or confidential inside the encrypted metadata | Public attestation and private mail are genuinely different needs; a header signature is visible to storage providers and network observers | Two code paths and two spec sections for every SDK |
| D7 | Version signalling | Signed containers advertise preamble minor **2** | A v0.1 reader refuses a signed container instead of opening it and silently ignoring the signature | Signed files are unreadable by older readers, deliberately |
| D8 | Identity on disk | One **master seed**, sealed once; the encryption and signing keys are derived from it | `keygen` writes one secret and two public files, so there is a single backup and a single passphrase, and neither derived key reveals the other | A key-file format change, and old keys cannot sign |
| D9 | Key file typing | A **purpose byte**, key format version 2 | A signing key and an encryption key were byte-indistinguishable, so the wrong file could be used silently | Another format version to keep readable |
| D10 | Detached signatures | Sign **SHA-256 of the file**, with its own context label | One streaming pass, no buffering, and consistent with the container transcript | The signature does not carry the file, so it must be kept beside it |
| D11 | ssh-agent wire format | **Hand-rolled**, no `ssh-key` crate | ~60 lines, not cryptography, and it keeps a release-candidate dependency out of a tree that pins exact versions | Ours to maintain if OpenSSH extends the protocol |
| D12 | Agent transport | std on Unix, **`interprocess` on Windows only** | Windows agents are named pipes, which need `unsafe` — forbidden workspace-wide — or a crate | One dependency, confined behind `cfg(windows)` |
| D13 | Signing confirmation | **Ask every time**, `--no-confirm` opts out | A reachable agent is a signing oracle; silence should be requested, not assumed | Unattended use needs an explicit flag |

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

### P1 complete — 21 tests, 9/9 mutations detected

- **P1.5, known-answer tests.** RFC 8032 TEST 3 for Ed25519, and NIST ACVP
  `ML-DSA-keyGen` ML-DSA-65 tcId 26 for the post-quantum half. These prove the
  crates implement the standards rather than merely agreeing with themselves,
  and the ML-DSA vector also catches a silent swap to a different security
  level — a mutation to `MlDsa44` is now detected.
- **P1.6, frozen vectors.** `signer.test-seed`, `signer.test-public`,
  `hello.sig` and `empty.sig` under `conformance/vectors`, from seed `0x55`,
  regenerated by `cargo run -p hide-sign --example generate_vectors`.
  Regeneration was verified byte-identical. `crates/hide-sign/tests/vectors.rs`
  fails if the bytes drift, so changing them has to be deliberate.

Two things worth recording. **Signing is deterministic**, measured rather than
assumed, so `hide-sign` needs no `test-vectors` feature — the one that was
scaffolded has been removed rather than left as dead configuration. And the
vector test asserts the signature both verifies *and* reproduces exactly: if
verification alone passed, the scheme would have silently become randomised.

---

### P2 — signatures in the wire format

105 workspace tests, clippy clean, 10/10 mutations detected, and the
independent Node verifier agrees on both placements.

**The forgery that shaped the design.** The plan said "sign the header hash,
which is already chained into every chunk's AAD, so it binds the payload." That
is true only against someone who cannot compute AEAD tags. A *recipient* holds
the CEK, and the payload salt is written in the clear, so a recipient can keep
a signed header byte-for-byte, re-encrypt entirely different plaintext, and
ship a container in which every tag is valid and the original signature still
verifies. Multi-recipient makes it worse: any one recipient can forge to all
the others. The signature now covers `SHA-256(plaintext)`, which is what makes
it mean *this signer produced this content* rather than *this signer addressed
these recipients*. `forge_payload_for_test` mounts exactly this attack, and
`a_recipient_cannot_swap_the_payload_and_keep_the_signature` proves it fails.

**Compatibility.** Key 5 of the protected header was an empty array in v0.1 and
now carries public signatures. An unsigned header still encodes `05 80`, so
`hello.hide` and `empty.hide` regenerate byte-identically — verified through
git, not by inspection. Metadata gained an optional key 3 for the confidential
placement.

**Two testing lessons.** First, the signing tests were initially *vacuous*:
signer and verifier call the same `transcript` function, so weakening it
weakens both symmetrically and every round-trip still passed. Seven of ten
mutations survived. Only mounting the real attack made them meaningful — a
round-trip test structurally cannot catch a weakened binding. Second, two
tamper tests asserted the wrong layer: the header MAC covers the preamble and
the protected header, so editing a version byte or a signature stanza is caught
as `NoMatchingRecipient` long before signature verification runs. Reaching the
stripped-signature check at all required building a container that is signed
and then has its stanza removed, which is what
`encrypt_stripped_signature_for_test` exists for.

**A Node trap worth remembering.** `cbor.encodeCanonical` returns a *single
byte* for a `Map` — it truncates. The existing verifier already had a probe
guarding against this for its own encoder; the signature path had to use the
same async encoder.

---

### P3 — signing from the CLI

131 workspace tests, clippy clean, 9/9 mutations detected.

**The problem that shaped the key format.** `RecipientSecret` and
`SigningIdentity` are *both* 32-byte seeds, and the keyring sealed any 32-byte
seed under the same `HIDE-KEY` magic with no type tag — so a sealed signing key
and a sealed encryption key were byte-indistinguishable. Feeding the wrong file
to the wrong command would have failed confusingly or, worse, succeeded against
a key derived for another purpose. Key files now carry a purpose byte at format
version 2, and version 1 files still open as encryption-only.

`keygen` writes one master seed and derives both keys from it with
domain-separated HKDF, so there is a single backup and a single passphrase.
A pre-signature key still decrypts; signing with it fails and names the fix.

**Two mutation survivors that were NOT gaps.** `detached message drops the
length` and `detached context equals container context` both survived, and the
instinct was to write tests until they died. They survived because the defences
are genuinely redundant: SHA-256 already detects truncation, so the length is
decorative, and a container transcript binds the recipient set and metadata
while a detached message binds a file digest — the two can never collide
whatever the context label says. Verified by removing *both* separation layers
at once and watching the cross-domain test still pass. The mutations were
removed from the suite and the redundancy documented in the code, so nobody
later "simplifies" it believing it load-bearing.

The lesson generalises: a surviving mutation means *either* a missing test *or*
a redundant defence, and deciding which requires an experiment, not a guess.

### P4 — `hide agent`

133 workspace tests, clippy clean, 6/6 mutations detected.

**What SSH can and cannot carry.** OpenSSH user authentication accepts only
`ssh-ed25519`, `sk-*` and RSA; post-quantum algorithms exist there solely in
key exchange. So the agent offers the Ed25519 half of an identity and the
ML-DSA half goes unused. The honest claim is "one sealed identity instead of a
plaintext key in `~/.ssh`", never "post-quantum SSH", and the README says so.

**Hand-rolled framing, one dependency for transport.** The wire format is
~60 lines and is not cryptography, so `ssh-key` (still a release candidate)
stays out of the tree. The transport could not follow: Windows agents are named
pipes, which need either `unsafe` — forbidden workspace-wide — or a crate.
`interprocess` is therefore a Windows-only dependency, while Unix uses std.

**Verified by OpenSSH itself, not by our own tests.** `ssh-keygen -l` computes
the same fingerprint from our exported line; `ssh-add -l` lists the key through
the running agent; `ssh-keygen -Y sign` obtains a signature via SIGN_REQUEST
and `-Y verify` then reports `Good "file" signature`. Refusing the confirmation
prompt yields `agent refused operation` and no signature file.

A `ssh localhost` login was attempted and failed — but it also fails with the
agent stopped, because this machine authorises no key for this account. That is
the environment, not the agent, and it is why the evidence above uses OpenSSH's
own signing tools, which exercise the identical code path.

**Two mutation survivors that WERE gaps.** Unlike P3, both were real. The tests
asserted the right outcome through the wrong code path: an over-long string
prefix was caught later by the key comparison, and an absurd framed length was
caught by end-of-file rather than by the bound. Naming the cause in the
assertion, and testing the reader directly, killed both.

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
