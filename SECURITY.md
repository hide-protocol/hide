# Security Policy

## HIDE is experimental — do not protect real data with it

The wire format is a release candidate, frozen since 0.9.0 and not 1.0; the
current release line is 0.10.x. The implementation has never been audited by a
third party, and the hybrid KEM follows an IETF draft that is not yet an RFC.
Treat every container as a test artifact. The CLI requires `--experimental`
for this reason.

## Supported versions

Only the latest release line (0.10.x) receives security fixes. Nothing is
backported to earlier minors.

## Cryptographic scope

HIDE implements no primitives of its own and defines no novel KEM combiner. It
composes crates from the RustCrypto and `hpke` projects, all pinned to exact
versions:

- **Key encapsulation**: HPKE base mode with X-Wing (X25519 + ML-KEM-768,
  FIPS 203), HKDF-SHA256, ChaCha20-Poly1305.
- **Payload**: ChaCha20-Poly1305 in 64 KiB authenticated chunks; HMAC-SHA256
  over the header.
- **Signatures**: hybrid Ed25519 + ML-DSA-65 (FIPS 204); both halves must
  verify.
- **Key files**: Argon2id with an enforced parameter floor and ceiling
  (memory 8–256 MiB, at most 4 lanes, 1–64 passes), then ChaCha20-Poly1305.
- **Transparency**: RFC 6962 Merkle tree, inclusion and consistency proofs.
- **Group messaging**: MLS (RFC 9420) through `mls-rs`, classical X25519 suite
  only — post-quantum MLS suites are still an IETF draft.

`unsafe_code = "forbid"` applies to every crate except `hide-ffi`. A flaw in an
upstream primitive belongs upstream, though a report here is still appreciated
so the dependency can be pinned or replaced.

The crates that carry the post-quantum and HPKE code are not audited either.
The READMEs of `ml-kem`, `ml-dsa` and `x-wing` each say the implementation "has
never been independently audited"; the `hpke` README says that "nobody has
performed a paid audit of this crate" and records one internal security review,
by Cloudflare, of version 0.8; the `mls-rs` README says it "has not yet received
a full security audit by a 3rd party". Pinning a version fixes which unaudited
code runs; it does not make it audited.

## Threat model in one paragraph

HIDE defends a container against anyone who is not a recipient: they cannot read
it, alter it, truncate it, reorder its chunks, or learn its filename. A *signed*
container additionally proves which key produced exactly this content, even to
another recipient. It does **not** bind a key to a person, hide who or how many
the recipients are, hide the file size, or protect a key that an attacker can
read from process memory. The full model, including what a malicious recipient
and a malicious log operator can do, is in
[`docs/threat-model.md`](docs/threat-model.md).

## What this version does not protect against

Known and documented, not new findings:

- **An identity is not a person.** The device log proves which devices an
  identity trusts over time; nothing proves the identity belongs to a given
  human. There is no directory, and no key-transparency *service* — the log
  primitive exists and witness cosignatures on checkpoints are verified
  (`spec/hide-1.md` §16.2), but no one operates a log or a witness.
- **Sender authentication only when signed.** A recipient of an *unsigned*
  container holds the CEK and can rewrite the recipient set and recompute a
  valid header MAC. A signature closes this; its absence does not.
- **Forward secrecy is by erasure, not by ratchet.** It exists only if the
  holder actually destroys the epoch secret. The CLI keeps epoch secrets in a
  passphrase-sealed store and erasing reseals it without the epoch, but an
  older copy of that file (backup, snapshot, remapped flash blocks) still holds
  what it held.
- **No recipient anonymity.** Ciphertext size and recipient count are visible;
  metadata is encrypted, not hidden. A public signature reveals the signer.
- **No hardware protection.** Argon2id resists an attacker who copies a key
  file, not one who reads memory while the key is in use. There is no Keychain,
  TPM, Secure Enclave or Keystore integration, and `keygen --insecure-plaintext`
  writes an unencrypted key on request.
- **A forgotten passphrase is unrecoverable.** There is no escrow or reset.
- **Group messaging is not post-quantum**, and `mls-rs` is as unaudited as the
  rest. The credential binding described below was introduced in 0.7.0 and has
  been parsed by no implementation outside this repository.
- **SSH authentication is not post-quantum.** `hide agent` offers the Ed25519
  half only. OpenSSH 10.6 (2026-10-06) enables the hybrid signature algorithm
  `ssh-mldsa44-ed25519` (https://www.openssh.org/txt/release-10.6), but HIDE
  signs with ML-DSA-65 and its SSH key is Ed25519 alone, so HIDE's SSH support
  stays classical. It avoids a plaintext key on disk; nothing more.
- **An agent is a signing oracle.** Anything that can reach the endpoint can
  request a signature, which is why confirmation is the default.
- **Replay is only detectable by the verifier.** A replayed challenge answer is
  a genuine signature; a verifier that keeps no spent-nonce record gains nothing
  over a plain signature.

## What changed in 0.8.0

- **Advisory [HIDE-2026-001](docs/advisories.md#hide-2026-001--a-95-byte-key-file-could-make-open-allocate-up-to-4-gib):
  a 95-byte key file could make `open` allocate up to 4 GiB** (affected
  0.2.0–0.7.x). Found by the nightly fuzzer after 0.7.0 shipped, which is why
  it has an advisory and the 0.7.0 findings below do not. Memory is now capped
  at 256 MiB and parallelism at 4, before any allocation.
- Identity and epoch decoders no longer reserve memory from the declared entry
  count; MLS messages and `hide unseal` input are capped at 1 MiB; a `u64`
  length or index is refused on 32-bit targets instead of being truncated.
- Sixteen fuzz targets cover every parser of untrusted bytes — the container,
  key files, identity logs, epoch chains, transparency proofs, MLS messages,
  the ssh-agent decoder, public-key armor, the MLS device credential, the
  relying-party verifiers, and every byte-taking entry point of the C ABI —
  each fuzzed four hours every night with the corpus carried forward.

Found after 0.8.0 shipped: the identity-log transport encoding declared six
fields per entry and wrote seven. Rust read its own output, so no HIDE surface
was affected, but any other CBOR decoder misread the log. It is an
interoperability defect, not a security one. 0.9.0 writes `array(7)` and still
reads the 0.6–0.8 form (`spec/hide-1.md` §10.3).

## What changed in 0.7.0

An internal review — not a third-party audit — found the following. All are
fixed in 0.7.0, and each fix has a test that fails on the previous code. They
are listed because their existence is the best evidence that others remain.

- **MLS credentials were self-asserted.** A group member could present another
  device's id in its credential; nothing proved it held that device's key. The
  credential is now a HIDE-signed binding over the MLS signature key
  (`spec/hide-1.md` §13), verified on every roster change.
- **7 of 8 signature stanzas were never verified.** The header admitted up to
  eight public signatures but checked only the first, so a recipient could
  append stanzas nobody examined. `MAX_SIGNATURES` is now 1 and a second stanza
  is rejected, not skipped.
- **One metadata key and nonce sealed two plaintexts** in the
  confidential-signature path (the metadata before and after the signature was
  inserted). No disclosure resulted, but nonce reuse under one key is a
  fragility that should not exist.
- **The identity-log encoding was not canonical**: two distinct event
  sequences could serialise to the same bytes. Every variable-length field is
  now length-prefixed.
- **`panic = "abort"` made `HIDE_ERR_PANIC` unreachable** in the C ABI: a panic
  inside the library aborted the host process instead of returning the error
  code the header documents. The FFI now builds with `panic = "unwind"` and
  catches at the boundary.
- **`HIDE_LIBRARY` was an unconditional library-injection vector** in every
  SDK: any process able to set an environment variable could replace the
  cryptographic core. It is now honoured only when
  `HIDE_ALLOW_LIBRARY_OVERRIDE=1` is also set.
- **The ssh-agent read its confirmation from stdin, not the terminal**, so a
  piped process could answer for the user; and on Windows the agent's named
  pipe was created without an ACL. Confirmation now reads the controlling tty.
  On Unix the socket lives in a directory created with mode 0700. On Windows
  the named pipe is still not restricted to the current user
  (`apps/hide-cli/src/transport.rs`); instead `--no-confirm` is refused there,
  so every signature must be confirmed on the terminal.
- **Argon2id parameters have a floor.** A key file declaring weaker parameters
  than the floor is refused rather than opened.

## Reporting a vulnerability

Report privately through either channel:

1. **GitHub private vulnerability reporting**:
   <https://github.com/hide-protocol/hide/security/advisories/new> (the
   **Report a vulnerability** button under the Security tab). The form is
   access-controlled, so prefer it for anything with sensitive detail.
2. **Email**: <hide-security@codai.ro>. No PGP or HIDE key is published for it,
   and mail is not end-to-end encrypted, so keep sensitive detail out of email
   or send only a pointer and continue in the GitHub advisory.

Do not open a public issue for a suspected vulnerability. Public issues are for
questions that are not sensitive. The machine-readable contact file is
<https://hide-protocol.github.io/hide/.well-known/security.txt> (RFC 9116).

Include the affected version or commit, a reproduction (a container plus the
steps), and what you believe the impact is. A failing test is the most useful
form.

HIDE has one maintainer. A report is acknowledged as soon as he reads it; there
is no guaranteed response time. We aim to publish a fix or a mitigation within
90 days and to coordinate disclosure with you; that is an aim, not a guarantee.
If you have had no reply at all after 14 days, treat the report as unread and
send it again through the other channel. Only the latest release line is fixed
(see "Supported versions" above).

No bug bounty exists. A finding is credited in the CHANGELOG and in
`docs/advisories.md` unless you prefer otherwise.

## Safe harbor

Good-faith security research against your own HIDE instances, keys and data is
authorised, and we will not pursue or support legal action over it. Do not
access, alter or exfiltrate data belonging to anyone else, do not degrade a
service other people rely on, and give us a reasonable window to fix what you
find before publishing. If you are unsure whether something is in scope, ask
first through either channel above.

## Findings that are especially valuable

- A container that decrypts under a key it was not encrypted to.
- A tampered container that authenticates successfully.
- Any input that causes a panic, an unbounded allocation, or non-termination in
  a parser — the fuzz targets under `fuzz/` are the starting point.
- Divergence between the Rust implementation and `conformance/node/verify.mjs`,
  since either side may be the wrong one.
- Secret material reaching a log, an error message, or a file on disk.
- **Identity-log forgery**: an entry accepted as authored by a device that was
  not trusted at that position in the log, or a revoked device regaining
  authority without the recovery key.
- **Epoch-chain rewriting**: a chain that verifies while omitting, reordering
  or replacing an epoch that was published.
- **Consistency-proof forgery**: a proof accepted between two checkpoints where
  the smaller log is not a prefix of the larger.
- **MLS binding bypass**: a roster entry accepted whose credential does not
  bind the MLS key to a device currently in the identity's membership.
