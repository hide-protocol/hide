# HIDE compared with other encryption tools

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

This is a comparison on properties, not a ranking. Several tools below are audited and widely deployed; HIDE is neither. If your threat model does not require a hybrid post-quantum KEM, hybrid signatures, or a multi-device identity log, one of the audited tools is the safer choice today. Facts about other tools were checked against their public repositories on 2026-09-08; where a date could not be confirmed the cell says so.

## Property table

| Tool | PQ KEM | Hybrid | Streaming | Multi-recipient | Signatures | Multi-device identity | Forward secrecy | Group messaging | Third-party audit | Language bindings | License |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **HIDE 0.6.x** | X-Wing (X25519 + ML-KEM-768, FIPS 203) | Yes, KEM and signature | Yes, 64 KiB chunks, constant memory (unsigned) | Yes, ≤64 | Ed25519 + ML-DSA-65 (FIPS 204); both must verify | Hash-linked device log with revocation and recovery | By epoch erasure only; no ratchet | MLS via `mls-rs`, **classical suite only** | **None** | 9 over one C ABI: C, Python, Node, WASM, Go, Java, Ruby, PHP, .NET | Apache-2.0 |
| **age** (Go reference) | ML-KEM-768 + X25519 hybrid recipients since v1.3.0 (`age-keygen -pq`); not default | Yes for PQ recipients | Yes, 64 KiB STREAM | Yes | No (integrity only) | No — one key per recipient | No | No | Yes — Trail of Bits; findings fixed in v1.3.2 (Aug 2026) | Go; Rust (rage); TypeScript (typage) | BSD-3-Clause |
| **rage** (Rust) | Via age plugin system (`age-plugin-pq`); built-in PQ status: see project | As age | As age | As age | No | No | No | No | Not known to us | Rust crate `age` | Apache-2.0 OR MIT |
| **GPG / OpenPGP** | No in RFC 9580; PQ composite drafts in progress | Drafts only | Yes | Yes | Yes, classical | Keyring with subkeys; web of trust | No | No | Long public review history; no single audit to cite | Many via GPGME | GPL-3.0 (GnuPG) |
| **libsodium `crypto_box_seal`** | No (X25519) | No | No — one message in memory | No (one recipient per sealed box) | Separate `crypto_sign` (Ed25519) | No | No | No | Yes — Private Internet Access, 2017 | Very many | ISC |
| **minisign / signify** | No (Ed25519) | No | Signing only, prehash mode | n/a | Yes, Ed25519 only | No | n/a | n/a | Widely reviewed; no formal audit known to us | Several ports | ISC (minisign); ISC/BSD (signify) |
| **Signal Protocol** | PQXDH (ML-KEM) for initial key agreement; SPQR ratchet announced | Yes | Attachments handled by app | Pairwise + Sender Keys | Implicit via ratchet | Yes, service-operated directory and key transparency | Yes, double ratchet | Yes | Yes, multiple academic analyses and audits (see project) | libsignal: Rust with Java/Swift/TS | AGPL-3.0 |
| **MLS (RFC 9420), bare** | No — PQ suites are `draft-ietf-mls-pq-ciphersuites` | Draft | n/a | n/a (group) | Per-leaf signature keys | Credential is application-defined | Yes, tree ratchet | Yes, the point of it | Protocol has formal analysis; implementations vary | OpenMLS (Rust), mls-rs (Rust), others | Spec: IETF; impls vary |
| **Tink** | No | No | Yes (streaming AEAD) | Via hybrid encryption, one recipient per ciphertext | Yes, classical | No (KMS-backed keysets) | No | No | Google-internal review; see project | Java, C++, Go, Python, Obj-C | Apache-2.0 |
| **AWS KMS envelope / Encryption SDK** | ML-KEM in TLS to the service; data keys are AES | No | Yes (ESDK framing) | Via multiple CMKs / keyrings | Separate KMS Sign API | IAM principals, not people | Key rotation policy; no FS | No | Vendor-attested; FIPS 140 validated HSMs (vendor claim) | Java, Python, C, JS, .NET, Go, Rust, CLI | Apache-2.0 (SDK); service proprietary |
| **Kryptor** | Pre-shared symmetric keys only ("post-quantum secure key exchange" via PSK) | No | Not checked | Yes | Yes, Ed25519 with comment | No | No | No | Not known to us | .NET only | GPL-3.0 |

Cells say "see project" where a claim is plausible but a specific auditor or year could not be verified from the project's own material during this check. HIDE's own column has no such cell: it has not been audited.

## Tool by tool

### age and rage

**What age does that HIDE does not.** age is audited; HIDE is not. age is packaged in nearly every distribution and has a plugin ecosystem (YubiKey/PIV via `age-plugin-yubikey`, `age-plugin-pq`, and others). age encrypts to existing `ssh-ed25519` and `ssh-rsa` public keys, including a GitHub user's published keys; HIDE's `ssh-key` and `agent` commands are for SSH *login*, not for encrypting to SSH keys. age's format is deliberately small and has three interoperable implementations (Go, Rust, TypeScript). age v1.3.0 added hybrid ML-KEM-768 + X25519 recipients, so "age has no post-quantum option" is no longer true; it is opt-in and recipients are ~2000 characters long.

**What HIDE adds.** Hybrid signatures (Ed25519 + ML-DSA-65) inside or beside the container, so a file can be both confidential and attributable to a key. A recipient set that cannot be rewritten by a co-recipient when signed. A device log with revocation and an offline recovery key, so an identity can survive losing a device. Epoch chains for forward security by erasure. RFC 6962 proofs. Encrypted metadata (filename, media type). A single C ABI with nine bindings. PQ KEM as the only mode rather than an option.

See [migrating-from-age.md](migrating-from-age.md) for a command mapping.

### GPG / OpenPGP

**What GPG does better.** Decades of deployment, review and tooling; keyservers, subkeys, expiry, the web of trust; smartcard support; integration with git, email, and package managers. OpenPGP has an active standardisation process (RFC 9580) and PQ composite schemes are being drafted in the IETF.

**What HIDE adds.** A hybrid post-quantum KEM today rather than in a draft. A small, fully specified format with frozen vectors and rejection vectors that a second implementation actually passes. No algorithm negotiation or configuration surface. Canonical, bounded parsing with fuzz targets. HIDE does not attempt GPG's scope: no email integration, no keyservers, no smartcards.

### libsodium `crypto_box_seal`

**What libsodium does better.** Audited (Private Internet Access, 2017), ubiquitous, minimal, and the right tool when you need a sealed message to one recipient inside your own protocol. Constant-time primitives with a long track record.

**What HIDE adds.** A complete file format rather than a primitive: multi-recipient, streaming with constant memory, authenticated chunk ordering and end-of-stream, encrypted metadata, hybrid PQ KEM, hybrid signatures. libsodium sealed boxes are X25519 only and hold the whole message in memory.

### minisign / signify

**What they do better.** Tiny, mature, widely reviewed, and the standard for signing release artifacts and OS packages. Ed25519 only, which is a feature: nothing to configure.

**What HIDE adds.** A hybrid signature where both a classical and a post-quantum half must verify. A signature that can be *confidential* — inside the encrypted metadata, visible only to recipients. Challenge–response with replay protection. Identity logs so a signing key can be rotated with an auditable history. HIDE's detached signatures are 5357 bytes versus minisign's ~100; that is the cost of ML-DSA-65.

### Signal Protocol

**What Signal does better.** Real forward secrecy and post-compromise security through the double ratchet. PQXDH gives hybrid post-quantum initial key agreement, and a PQ ratchet (SPQR) has been announced. A service-operated directory and key transparency. Extensive academic analysis. Signal is a messaging protocol; comparing it to a file format is mostly a category error.

**What HIDE adds.** Nothing for interactive messaging. HIDE is for data at rest: files, backups, artifacts. Its forward security is by erasure, not ratchet, and it has no directory. If you need a ratchet, use Signal or MLS. libsignal is AGPL-3.0; HIDE is Apache-2.0.

### MLS (RFC 9420), bare

**What MLS does better.** Group key agreement with a tree ratchet, forward secrecy and post-compromise security, formally analysed, standardised. This is what `hide-mls` uses internally.

**What HIDE adds.** A credential: MLS leaves the credential type to the application, and `hide-mls` supplies a HIDE-signed binding of a device id to the MLS signature key, checked against the identity log so a revoked device is detectable as untrusted. HIDE does *not* add post-quantum protection to MLS — the suite is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` and `hide_mls::PQ_STATUS` says so in the API.

### Tink

**What Tink does better.** A key-management-first design: keysets, rotation, KMS-wrapped keys, and misuse-resistant APIs across five languages, maintained by Google. Streaming AEAD for large data. If you are inside a cloud with a KMS, Tink is built for that.

**What HIDE adds.** A portable, self-describing file that needs no KMS or key management service, a hybrid PQ KEM, hybrid signatures, and multi-recipient encryption of one payload. Tink's hybrid encryption is classical and one-recipient.

### AWS KMS envelope encryption / AWS Encryption SDK

**What KMS does better.** Keys never leave FIPS-validated HSMs; access is IAM-governed and audited in CloudTrail; rotation is a policy. The Encryption SDK gives a framed, streaming format with multiple keyrings. It is the right answer when the keys should belong to an organisation, not a person, and the organisation lives in AWS.

**What HIDE adds.** Independence from a cloud provider: a container is decryptable with a key file and nothing else. Recipients are people or devices, not IAM principals. PQ protection on the data key itself rather than only on the TLS connection to the service. Signatures bound to the plaintext.

### Kryptor

**What Kryptor does better.** A single-binary tool with passphrase, symmetric and asymmetric modes, encrypted filenames, and ciphertexts indistinguishable from random. Signing with comments. Simple UX.

**What HIDE adds.** An asymmetric post-quantum KEM; Kryptor's PQ story is a pre-shared symmetric key, which is a different deployment model. Hybrid signatures. Identity logs, epochs, transparency proofs. Nine language bindings; Kryptor is .NET only. Kryptor is GPL-3.0; HIDE is Apache-2.0.

## What HIDE is not

HIDE is not audited, not formally verified, not a messaging protocol, not a key directory, and not post-quantum for group messaging or SSH. The list of what is not implemented is in the README and [threat-model.md](threat-model.md); it is longer than this comparison.
