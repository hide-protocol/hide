# HIDE threat model

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

This document states what HIDE defends, against whom, and what it does not. Every "provided" claim below is backed by a test in the repository; every "not provided" is a deliberate statement, not an omission. The normative wire format is [../spec/hide-0.1.md](../spec/hide-0.1.md).

## Assets

| Asset | Where it lives | Protected by |
| --- | --- | --- |
| Plaintext of a container | Never on disk unencrypted except at the sender and after a recipient's successful decryption | X-Wing (X25519 + ML-KEM-768, NIST FIPS 203) via HPKE, ChaCha20-Poly1305 chunks |
| Content encryption key (CEK) | Wrapped once per recipient in the header | HPKE seal to each recipient's public key |
| Recipient secret key | A key file, or process memory while in use | Argon2id (19 MiB, t=2 default; floor 8 MiB) + ChaCha20-Poly1305 at rest; nothing while in memory |
| Signing key | Same master seed, domain-separated | Same key file |
| Metadata (filename, media type, confidential signature) | Encrypted in the header | ChaCha20-Poly1305 under a key derived from the CEK |
| Container integrity: chunk order, count, end of stream, recipient set | Header MAC + per-chunk AAD + FINAL record | HMAC-SHA256 over `preamble ‖ protected`; 91-byte AAD binding object id, header hash, counter, kind, length |
| Authorship of content | Only if signed | Ed25519 + ML-DSA-65 (FIPS 204) hybrid over a transcript that includes `SHA-256(plaintext)` and the recipient set |
| Device membership of an identity | Public hash-linked log | Signatures by already-trusted devices; authority evaluated at entry position |
| Epoch history | Public hash-linked chain | SHA-256 links; secrets are independent random keys |
| Published log state | Checkpoint `size ‖ root` | RFC 6962 inclusion and consistency proofs |

## Adversaries

**Passive network observer.** Sees containers in transit. Learns ciphertext length, recipient count (number of stanzas), and whether the container is signed (preamble minor 2). Learns a *public* signer's key. Cannot read plaintext, metadata, or a confidential signature.

**Storage or cloud provider.** Holds containers indefinitely. Same view as the network observer, plus the ability to serve altered or old containers. Alteration is detected; substitution of a whole older container is not (HIDE has no freshness).

**Malicious co-recipient.** Holds the CEK. For an *unsigned* container can rewrite the recipient set, re-encrypt arbitrary plaintext under the same header, and recompute a valid header MAC — the container will look authentic to every other recipient. For a *signed* container, cannot do any of that without invalidating the signature, because the transcript binds the stanza list and the plaintext hash. Cannot learn the other recipients' secret keys.

**Compromised device.** An attacker with a recipient's secret key reads every container encrypted to that key, past and future, until the key is revoked *and* senders stop using it. Can sign as that device until revocation appears in the log. Cannot forge entries that appear after its revocation, cannot re-enrol itself, cannot revoke the device that removed it.

**Quantum-capable future adversary ("harvest now, decrypt later").** Records containers today, attacks them when a cryptographically relevant quantum computer exists. Must break both X25519 *and* ML-KEM-768 to recover a CEK. Must break both Ed25519 *and* ML-DSA-65 to forge a signature. This is the adversary HIDE's hybrid construction exists for. It does *not* apply to `hide-mls` group messages, which use classical X25519 only.

**Coercion or legal compulsion.** A party who can compel a key holder. HIDE provides no deniability; a signed container is non-repudiable proof that a key signed that content. Epoch erasure limits what a compelled holder *can* hand over, but only if the erasure happened before the compulsion and is genuine.

**Malicious log operator.** Operates a transparency log. Can present a rewritten history to a client who never saw the earlier root — a split view. Cannot produce a consistency proof from a published root to a history that dropped or altered an entry.

## Trust boundaries

1. **Sender ↔ recipient key.** HIDE has no directory. A public key arrives over a channel you already trust, or you compare a fingerprint out of band. Nothing in HIDE proves a key belongs to a person.
2. **Container ↔ decrypting application.** The filename in metadata is untrusted; an application must never use it to choose an output path. Plaintext is not published until FINAL authenticates.
3. **Rust core ↔ host language.** Every SDK crosses one C ABI. Key material never crosses it; handles do. A browser page is one trust domain: any script on it can use the key.
4. **Identity log ↔ verifier.** The log is public and self-verifying. The offline recovery key's public half is the root of trust a verifier must obtain independently.
5. **Epoch holder ↔ everyone.** Forward security exists only if the holder erases. Nothing external can confirm erasure happened.

## Property × adversary

Legend: **P** provided (tested) · **–** not provided · **~** partial, reason in the cell.

| Property | Network observer | Storage provider | Co-recipient (unsigned) | Co-recipient (signed) | Compromised device | Quantum (future) | Log operator |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Confidentiality of plaintext | P | P | – (is a recipient) | – (is a recipient) | – | P (hybrid) | P |
| Confidentiality of metadata | P | P | – | – | – | P | P |
| Integrity: tamper, truncate, reorder, duplicate | P | P | – (holds CEK) | P (transcript) | – for own containers | P | n/a |
| Recipient set cannot be rewritten | P | P | **–** | P | – | P | n/a |
| Authorship of content | – (unsigned) | – (unsigned) | – | P | ~ until revocation appears | P (hybrid sig) | n/a |
| Confidentiality of signer | P (confidential placement) / – (public) | same | – | – | – | same | n/a |
| Recipient anonymity | – (count visible) | – | – | – | – | – | n/a |
| Plaintext length hidden | – | – | – | – | – | – | n/a |
| Freshness / anti-rollback | – | **–** | – | – | – | – | – |
| Forward secrecy | ~ by erasure only; no ratchet | ~ same | ~ | ~ | ~ only for epochs erased before compromise | ~ | n/a |
| Post-compromise security | – | – | – | – | – (no ratchet) | – | n/a |
| Revocation takes effect | n/a | n/a | n/a | n/a | P from log position; **not retroactive** | n/a | n/a |
| History rewrite detectable | n/a | n/a | n/a | n/a | n/a | n/a | P with a prior root; **– split view** |
| Deniability | – | – | – | – | – | – | – |
| Group-message PQ | n/a | n/a | n/a | n/a | n/a | **–** (X25519 only) | n/a |
| Key in process memory | out of scope | out of scope | out of scope | out of scope | – | out of scope | out of scope |

## Explicitly out of scope

- **Binding a key to a person.** No directory, no key server, no transparency *service*. The RFC 6962 primitive exists; nobody operates a log.
- **Recipient anonymity and traffic analysis.** Stanzas carry no identifiers but the count and the ciphertext length are visible.
- **Hiding file size.** No padding scheme.
- **Freshness.** A storage provider can return an older valid container.
- **Post-compromise security and ratcheting.** Forward security is by erasure only.
- **Deniability.** Signatures are non-repudiable.
- **Hardware-backed keys.** No TPM, Secure Enclave, Keychain, Keystore or PIV integration.
- **Memory disclosure.** An attacker who reads process memory while a key is in use obtains the key. Secrets are zeroized on drop and never derive `Debug`, `Clone` or `Serialize`; that is hygiene, not a defence.
- **Post-quantum group messaging.** `hide-mls` uses `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; PQ MLS suites are an Internet-Draft with no Rust provider.
- **Post-quantum SSH.** `hide agent` offers the Ed25519 half only; OpenSSH accepts no PQ user-authentication algorithm.
- **Side channels** beyond constant-time primitives in upstream crates and evaluating both signature halves before deciding.
- **Split-view detection** in the transparency log. Needs witnesses and gossip; none is implemented.
- **Availability.** Altering the unauthenticated 16-byte `payload_salt` makes a container unreadable. This is denial of service and nothing more.

## Residual risks

- **Unaudited composition.** The primitives are upstream and pinned; the composition (key schedule, AAD layout, transcript, log encoding) is ours and has been reviewed only internally. Internal review found seven real defects in 0.7.0 ([audit-status.md](audit-status.md)); more exist.
- **Moving standards.** X-Wing is stable across draft-ietf-hpke-pq revisions and KEM id `0x647A` is IANA-allocated, but the HPKE-PQ document is still a draft. A change would require regenerating vectors and is a format change ([stability.md](stability.md)).
- **Unsigned containers are trusted by habit.** Users may assume an unsigned container that decrypts came from who they think. It proves only that it was not altered by a non-recipient.
- **Epoch secrets are not persisted.** `hide epoch-init` publishes a history but the secret lives only in that process, so erasure is demonstrable and not yet operationally useful.
- **Key file passphrase is the only at-rest protection.** A weak passphrase plus a copied key file is a recoverable key. There is no escrow or reset; a forgotten passphrase is unrecoverable.
- **The MLS binding is parsed by exactly one implementation.** Ours.
- **SDK boundaries.** Nine bindings over one ABI mean one bug is nine bugs. The cross-surface test catches divergence, not shared defects.

## Device revocation versus epoch erasure

These are different mechanisms that answer different questions.

| | Revoking a device | Erasing an epoch |
| --- | --- | --- |
| What changes | The identity log gains a `Revoke` entry signed by a still-trusted device (or `Recover` by the offline key) | The holder destroys the epoch's secret key; the public chain is unchanged |
| Effect on containers the device already holds | **None.** It still has the CEK for anything it decrypted, and the secret key for anything encrypted to it. | Every container encrypted to that epoch becomes unreadable **by everyone**, including the legitimate recipient, if no copy of the secret exists |
| Effect on future containers | Senders who replay the log stop encrypting to it. Senders who do not replay the log continue to. | Senders who follow the chain move to the next epoch; the erased epoch's public key still verifies as having existed |
| Effect on past signatures and log entries | Remain valid. Revocation is not retroactive by design. | n/a — epochs carry no signing authority |
| Effect on MLS groups | Member becomes detectable as untrusted via `accept_from_trusted`; not automatically evicted | n/a |
| Who can verify it happened | Anyone with the log and the recovery public key | Nobody. Erasure is an act by the holder; the chain proves the epoch existed, not that its secret is gone |
| Protects against | A stolen device *continuing* to be trusted | A key obtained *later* being used on data captured *earlier* |
| Does not protect against | Data the device already had | A secret copied before erasure; a holder who claims to have erased and did not |

Revoke when a device is lost or untrusted. Erase epochs on a schedule to bound how much a future key compromise exposes. Doing one does not do the other.
