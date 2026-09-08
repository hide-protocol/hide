# HIDE use cases — where it fits and where it does not

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

Each section says when HIDE is a reasonable fit, when it is not, and shows a recipe using the real CLI flags (checked against `hide --help` on 0.6.2) or SDK calls (checked against `sdk/python` and `sdk/node`). Every CLI invocation needs `--experimental`; the recipes omit `cargo run -p hide-cli --` and assume `hide` is on `PATH`. Nothing here is a recommendation to protect data that matters with an unaudited tool.

## 1. Encrypting files for a person or a team

**Fits when** you want hybrid post-quantum file encryption to one or more people whose public keys you already have, optionally signed so the recipients know which key produced the content, and you can live with a format that may change before 1.0.

**Does not fit when** you need an audited tool (use age), when recipients only have SSH keys (age encrypts to `ssh-ed25519`; HIDE does not), or when you need to discover a person's key — HIDE has no directory.

```powershell
# Each person, once. The secret is passphrase-sealed; keygen also writes alice.hide-pub.sign.
hide --experimental keygen --secret alice.hide-key --public alice.hide-pub

# Exchange public keys over a channel you already trust; compare fingerprints out of band.
hide --experimental share alice.hide-pub

# Encrypt once for the whole team (up to 64 recipients); sign it so they know it came from you.
hide --experimental encrypt report.pdf --recipient alice.hide-pub --recipient bob.hide-pub `
  --output report.pdf.hide --sign you.hide-key

# Decrypt. Refuses to overwrite; publishes only after FINAL and the signature verify.
hide --experimental open report.pdf.hide --secret bob.hide-key --output report.pdf
```

Without `--sign`, any recipient can rewrite the recipient set and re-encrypt different content under a valid header ([threat-model.md](threat-model.md), "Malicious co-recipient"). Sign anything a second recipient will rely on.

## 2. Database field encryption

**The honest caveat first.** HIDE is an asymmetric envelope format. Encrypting a column with it means every row carries a 1120-byte X-Wing encapsulation plus header (roughly 1.3 KB of overhead per container), and decryption trial-decapsulates against the recipient's secret. For a field you read on every request, a symmetric AEAD with a KMS-managed key (Tink, AWS Encryption SDK, or `chacha20poly1305` directly with a key from your KMS) is the right tool: smaller, faster, key rotation built in.

**Fits when** the writer must not be able to read back what it wrote — a service that ingests documents and hands them to an auditor, an intake form whose contents only a specific team may open — and the number of encrypted objects is moderate. Encrypt a per-row data key, not the row.

**Pattern.** Generate a random 32-byte DEK per row, encrypt the row's sensitive fields with a symmetric AEAD under the DEK, then wrap the DEK with `hide.encrypt` to the reader's HIDE public key. Store the wrapped DEK beside the row. The service that writes rows never holds a HIDE secret.

```python
import os, hide_protocol as hide
from chacha20poly1305 import ChaCha20Poly1305  # any AEAD; not part of HIDE

reader_public = open("auditor.hide-pub", "rb").read()

def write_row(fields: bytes) -> tuple[bytes, bytes, bytes]:
    dek = os.urandom(32)
    nonce = os.urandom(12)
    body = ChaCha20Poly1305(dek).encrypt(nonce, fields, b"row-v1")
    wrapped_dek = hide.encrypt(dek, [reader_public])   # ~1.3 KB, PQ-hybrid
    return wrapped_dek, nonce, body

# The reader, elsewhere, holding the secret:
with hide.SecretKey.load(open("auditor.hide-key", "rb").read(), passphrase=...) as secret:
    dek = hide.decrypt(wrapped_dek, secret).data
```

**Does not fit when** you need searchable or deterministic encryption, per-request decryption at scale, or key rotation without re-wrapping every DEK. Rotation in HIDE means re-encrypting each wrapped DEK to the new public key.

## 3. End-to-end chat over MLS groups

**Read this before anything else: `hide-mls` group messages are not post-quantum.** The MLS cipher suite is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, because post-quantum MLS suites are still `draft-ietf-mls-pq-ciphersuites` and no Rust provider implements them. `hide_mls::PQ_STATUS` states this in the API. A file sealed with HIDE and a message sent through `hide-mls` are protected differently.

**Fits when** you are building a group messaging feature in Rust, want MLS (RFC 9420) via `mls-rs` 0.56, and want a member's roster entry anchored to a HIDE identity so that revoking a device in the identity log makes its messages detectable as untrusted. `mls-rs` is unaudited, like HIDE.

**Does not fit when** you need PQ messaging (Signal's PQXDH, or wait for PQ MLS), a delivery service (HIDE ships none), or an audited stack.

```rust
use hide_mls::{client_for, accept_from_trusted, untrusted_members};

// `membership` is the current head of the identity log (hide_identity).
// `client_for` returns an mls-rs Client whose credential is the HIDE-signed
// binding of this device id to its MLS signature key (spec §11).
let client = client_for(&membership, &device_signer)?;   // Err(UntrustedDevice) if the log does not trust this device
let mut group = client.create_group(Default::default(), Default::default(), None)?;

// On receipt: MLS proves membership; HIDE proves the member's device is still trusted.
let message = accept_from_trusted(&mut group, &membership, incoming)?;

// Roster hygiene after a revocation lands in the log:
for device in untrusted_members(&group, &membership)? { /* propose removal */ }
```

Revoking a device does *not* evict it from the group automatically; `untrusted_members` tells you who to remove.

## 4. Backups to untrusted storage with epoch erasure

**Fits when** backups go to a cloud bucket you do not trust, you want them unreadable by a quantum-capable adversary who copies the bucket today, and you want to bound how much a *future* key compromise exposes by erasing old epochs.

**Does not fit when** the backup key must be recoverable after loss (erasure is permanent and affects the legitimate owner too), or when you need operational epoch storage today: **epoch secrets are not persisted by the CLI**. `hide epoch-init` publishes the public history; the secret lives only in that process. The Rust API is complete; a durable store is not built.

```powershell
# Publish an epoch history (public; the secret is NOT saved by the CLI yet).
hide --experimental epoch-init --output backups.hide-epochs
hide --experimental epoch-show --chain backups.hide-epochs
```

```rust
use hide_epoch::{EpochChain, recipient_for};

let mut chain = EpochChain::new()?;               // epoch 0, independent random key
let current = chain.current();
let recipient = recipient_for(chain.records(), current)?;   // a hide_crypto::RecipientPublic
// ... hide_object::encrypt(&mut input, &mut output, &[recipient], ...) for this month's backups ...

let next = chain.advance()?;                      // new random key, hash-linked
chain.erase(current)?;                            // every container sent to epoch 0 is now unreadable by anyone
assert!(!chain.is_readable(current));
```

Forward security here exists only if you actually erase and no copy of the secret survives. Nothing can prove to a third party that you did ([threat-model.md](threat-model.md), "Device revocation versus epoch erasure").

## 5. Secrets and config files in repositories

**Fits when** a small team wants `.env`-style files committed encrypted, with hybrid PQ protection and a signature proving which maintainer produced the file. Encrypt to each maintainer plus a CI recipient.

**Does not fit when** you want the mature tooling — `sops` with age or KMS backends, `git-crypt`, sealed-secrets — or when secrets must be revocable per environment without re-encrypting (use a secrets manager). HIDE's recipient set is fixed at encryption time; removing a person means re-encrypting.

```powershell
hide --experimental encrypt .env.production --recipient alice.hide-pub --recipient ci.hide-pub `
  --output .env.production.hide --sign alice.hide-key
git add .env.production.hide

# CI, with the sealed key and passphrase from its secret store:
hide --experimental --quiet open .env.production.hide --secret ci.hide-key --output .env.production
```

`hide open` refuses to overwrite an existing file; delete the plaintext first in a fresh checkout.

## 6. IoT and device fleets with identity logs and revocation

**Fits when** a fleet owner wants each device to hold its own signing identity, wants enrolment and revocation to be a public, replayable log rather than a database row, and wants an offline recovery key that can replace the whole set if the enrolling laptop is lost. Verification of the log needs no secret, so a relying party can check it independently.

**Does not fit when** you need the log served and witnessed (no directory or witness is implemented; a log operator can present a split view), automatic propagation of revocation to relying parties (they must fetch and replay the log), or constrained devices — ML-DSA-65 signatures are 3309 bytes and verifying keys 1952 bytes.

```powershell
# Fleet owner's laptop is the founding device; the recovery key lives offline.
hide --experimental keygen --secret recovery.hide-key --public recovery.hide-pub   # writes recovery.hide-pub.sign
hide --experimental identity-create --secret laptop.hide-key --recovery recovery.hide-pub.sign `
  --label laptop --output fleet.hide-log

# Enrol a device by its signing public key.
hide --experimental identity-enrol --log fleet.hide-log --secret laptop.hide-key `
  --device sensor-042.hide-pub.sign --label sensor-042 --recovery recovery.hide-pub.sign

# Revoke it. From this entry on it cannot re-enrol itself or revoke the laptop.
hide --experimental identity-revoke --log fleet.hide-log --secret laptop.hide-key `
  --device sensor-042.hide-pub.sign --recovery recovery.hide-pub.sign

# Anyone can replay the log; no secret needed.
hide --experimental identity-show --log fleet.hide-log --recovery recovery.hide-pub.sign
```

```python
# A relying party in Python:
head_count = hide.verify_identity(log_bytes, recovery_public_signing_key)
trusted = hide.identity_trusts_device(log_bytes, recovery_public_signing_key, device_public_signing_key)
```

Revocation is not retroactive: signatures the device made while trusted stay valid.

## 7. Signing release artifacts

**Fits when** you want a detached hybrid signature (Ed25519 + ML-DSA-65; both must verify) on a release tarball, and your consumers can run `hide verify` or an SDK.

**Does not fit when** consumers expect minisign/signify/cosign, or when you need transparency-log-backed signing today. **HIDE cannot yet verify its own releases with HIDE**: release binaries are checked against `SHA256SUMS` only. Sigstore-based signing of releases is planned but not implemented. A 5357-byte `.hide-sig` beside each artifact is the cost of ML-DSA-65.

```powershell
hide --experimental sign hide-0.6.2-x86_64-unknown-linux-musl.tar.gz --secret release.hide-key
#   -> hide-0.6.2-x86_64-unknown-linux-musl.tar.gz.hide-sig

# Consumer, holding release.hide-pub.sign obtained out of band:
hide --experimental verify hide-0.6.2-x86_64-unknown-linux-musl.tar.gz --signer release.hide-pub.sign
```

Rotate the release key through an identity log (§6) so consumers can see that a new signing key was enrolled by the old one rather than trusting an announcement.

## 8. Browser (WASM)

**Fits when** a web application must encrypt in the client to a server-side or user-held HIDE key, and the key that matters is *not* the one in the browser — for example the browser holds only public keys and encrypts uploads.

**The XSS caveat.** Any script on the page shares the heap with the WASM module. A secret key loaded in a browser is readable by any XSS. Use the browser for encrypting to others; keep decryption keys on the CLI or desktop app. The WASM package (`@hide-protocol/wasm`) is compiled from the same crates and passes the same cross-surface conformance check as every other SDK.

```ts
import { encrypt } from "@hide-protocol/wasm";

// recipients are concatenated 1216-byte public keys; filename and media type are optional
const container = encrypt(fileBytes, serverPublicKey, "upload.bin", undefined);
// POST container; the server decrypts with hide_protocol (Python/Node/…).
```

**Does not fit when** the browser is the only place a decryption key can live and the data matters. That is a browser-security problem, not a HIDE one, but HIDE does not solve it.

## What to use instead

| If you need | Use | Because |
| --- | --- | --- |
| Audited file encryption, today | age (Go) or rage (Rust); age v1.3+ has opt-in ML-KEM-768 hybrid recipients | Audited, packaged everywhere, three interoperable implementations |
| Encrypting to SSH keys or a GitHub user's keys | age `-R` | HIDE's SSH support is for login, not for recipients |
| Interactive messaging with forward secrecy and PQ | Signal (PQXDH) | Ratchets; HIDE has no ratchet and its MLS is classical |
| Post-quantum group messaging | Wait for `draft-ietf-mls-pq-ciphersuites` and a provider | `hide-mls` is X25519 only |
| High-volume symmetric field encryption | Tink, AWS Encryption SDK, or an AEAD with a KMS key | Envelope-per-row asymmetric wrapping is the wrong shape |
| Keys owned by an organisation with IAM and HSMs | AWS KMS / GCP KMS / Azure Key Vault | Access control, audit trail, rotation policy |
| Signing artifacts consumers already verify | minisign, signify, cosign/Sigstore | Established verifiers; transparency log in Sigstore's case |
| Secrets in repos with mature tooling | sops (age or KMS backend), git-crypt | Editor integration, per-key rotation, key groups |
| A key directory or key transparency service | Signal, WhatsApp, or Keybase-style services | HIDE has the RFC 6962 primitive and no operator |
| Hardware-backed keys | age-plugin-yubikey, GPG with a smartcard, platform keystores | HIDE has no TPM/Secure Enclave/PIV integration |
| Deniable encryption | OTR-style protocols; not a file-format problem | HIDE signatures are non-repudiable |
