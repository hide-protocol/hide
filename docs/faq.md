# HIDE frequently asked questions

*HIDE is experimental and has not been audited by a third party. See [audit-status.md](audit-status.md).*

Short factual answers. Each links to the document that carries the detail. "HIDE" here means version 0.6.x of the crates, CLI and SDKs in this repository.

## What is HIDE?

HIDE is a hybrid post-quantum file encryption format and toolset. Every content key is wrapped with X-Wing — X25519 combined with ML-KEM-768 (NIST FIPS 203) — through HPKE (RFC 9180), and every signature is Ed25519 combined with ML-DSA-65 (FIPS 204). It ships a Rust core, a CLI, a desktop app, and SDKs for nine languages over one C ABI. Wire format: [../spec/hide-0.1.md](../spec/hide-0.1.md).

## Is HIDE post-quantum?

For file and message encryption, yes, in the hybrid sense: an attacker must break both X25519 and ML-KEM-768 to recover a content key, and both Ed25519 and ML-DSA-65 to forge a signature. Two parts are **not** post-quantum: `hide-mls` group messaging (classical X25519 suite) and SSH login through `hide agent` (Ed25519 only, because OpenSSH accepts no PQ user-authentication algorithm). See [threat-model.md](threat-model.md).

## Is HIDE audited?

No. No third party has reviewed the design or code. Internal review on 2026-09-08 found seven real defects, all fixed in 0.7.0, which is evidence that others remain. Details, and what an audit should cover, in [audit-status.md](audit-status.md).

## Should I use HIDE in production?

Not for data whose loss or disclosure would matter. The CLI requires `--experimental` for this reason. Use it to evaluate the format, to build against the API, or to review the code. For production file encryption today, an audited tool such as age is the safer choice ([comparison.md](comparison.md)).

## How is HIDE different from age?

age is audited, packaged everywhere, and since v1.3.0 offers opt-in hybrid ML-KEM-768 + X25519 recipients. HIDE is unaudited, PQ-hybrid by default, and adds hybrid signatures, encrypted metadata, a multi-device identity log with revocation, epoch chains for forward security by erasure, and RFC 6962 proofs. age encrypts to SSH keys; HIDE does not. Full mapping in [migrating-from-age.md](migrating-from-age.md) and [comparison.md](comparison.md).

## Does HIDE replace GPG?

No. GPG covers email, keyservers, smartcards, the web of trust and decades of tooling. HIDE covers file and message encryption plus signatures with a small, fully specified format and a hybrid PQ KEM. If you use GPG for email or package signing, HIDE is not a substitute ([comparison.md](comparison.md)).

## What does "encrypt to a person" mean?

It is the design goal, not a delivered property. Today a recipient is a public key file. The identity log lets one identity span several devices and survive losing one, but nothing in HIDE proves a key or a log belongs to a particular human — there is no directory. You still exchange keys over a channel you trust ([threat-model.md](threat-model.md), "Trust boundaries").

## Why hybrid and not pure ML-KEM?

ML-KEM is new; X25519 has two decades of scrutiny. A hybrid means a flaw in either half alone does not break confidentiality. This is the same reasoning behind hybrid TLS deployments and age's PQ recipients. The cost is 1120 bytes of encapsulation per recipient.

## Why X-Wing?

X-Wing is a specified, analysed combiner of X25519 and ML-KEM-768 with an IANA-allocated HPKE KEM id (`0x647A`), implemented in the `hpke` crate. Using it means HIDE defines no combiner of its own, which is an explicit invariant in [../AGENTS.md](../AGENTS.md). Its byte format has been stable across draft revisions.

## Why 64 KiB chunks?

64 KiB is large enough that per-chunk overhead (16-byte tag, 5-byte record header) is 0.03 %, and small enough that a decryptor holds two fixed buffers — measured peak RSS is 7 MB for a 256 MB file. It is also the chunk size age's STREAM uses, so the trade-off is well understood. Each chunk's AAD binds object id, header hash, counter, kind and length ([../spec/hide-0.1.md](../spec/hide-0.1.md) §5).

## Can HIDE stream large files?

Unsigned encryption and all decryption stream with constant memory. Signed encryption buffers the plaintext, because the signature commits to `SHA-256(plaintext)`, and is capped at 1 GiB (`MAX_SIGNED_INPUT`). Sign a detached signature with `hide sign` if the file is larger.

## Can a recipient forge a container?

For an **unsigned** container, yes: every recipient holds the content key and can rewrite the recipient set or re-encrypt different content with a valid header MAC. For a **signed** container, no: the transcript binds the recipient stanzas and the plaintext hash, and both signature halves must verify. Sign anything a second recipient will rely on ([threat-model.md](threat-model.md)).

## Does decryption prove who sent a file?

Only if the container is signed, and even then it proves which *key* signed it, not which person. An unsigned container that decrypts proves only that no non-recipient altered it.

## Is forward secrecy real?

It is forward security **by erasure**: keys live in epochs with independent random secrets, and destroying an epoch's secret makes every container sent to it unreadable by everyone. There is no ratchet, and nothing can prove to a third party that erasure happened. The CLI does not yet persist epoch secrets, so this is demonstrable in the Rust API and not yet operational ([threat-model.md](threat-model.md), "Device revocation versus epoch erasure").

## What happens if my device is stolen?

Revoke it from another trusted device with `hide identity-revoke`, or from the offline recovery key if every device is gone. From that log entry on, the device cannot re-enrol itself or revoke others. It **keeps** access to everything it already held or was encrypted to before senders replay the log. Revocation is not retroactive ([threat-model.md](threat-model.md)).

## Are group messages post-quantum?

No. `hide-mls` uses `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` because PQ MLS suites are still `draft-ietf-mls-pq-ciphersuites` with no Rust provider. The constant `hide_mls::PQ_STATUS` says so in the API. What HIDE adds to MLS is a credential bound to a HIDE identity so a revoked device is detectable ([use-cases.md](use-cases.md) §3).

## Is SSH login through `hide agent` post-quantum?

No. It offers the Ed25519 half of the identity. OpenSSH accepts only `ssh-ed25519`, `sk-*` and RSA for user authentication; PQ exists in SSH key exchange only. What it buys is a passphrase-sealed key instead of a plaintext one in `~/.ssh`.

## Can I encrypt to someone's SSH key like age does?

No. `hide ssh-key` and `hide agent` are for logging in over SSH with a HIDE identity. HIDE recipients are HIDE public keys only ([migrating-from-age.md](migrating-from-age.md)).

## Which languages have SDKs?

C (the ABI itself), Python, TypeScript/Node, browser WASM, Go, Java/Kotlin, Ruby, PHP and .NET — nine surfaces over one C ABI in `crates/hide-ffi`. No language reimplements the cryptography, and key material never crosses into the host language. Python, npm, RubyGems, NuGet and crates.io packages are published via OIDC trusted publishing ([architecture.md](architecture.md)).

## How do I verify a download?

Check the file against `SHA256SUMS` from the same GitHub release. HIDE does not yet sign its own releases with HIDE or with Sigstore; that is planned. Package-manager manifests exist in `packaging/` but are deliberately not published ([../README.md](../README.md), "Download").

## Why is the version 0.x?

Because the wire format and APIs may still change, the HPKE-PQ document is a draft, and no audit has happened. A 0.x minor bump may break format or API and is always called out in the changelog; frozen vectors must keep opening. What 1.0 requires is in [stability.md](stability.md).

## Will files I encrypt today open in a future version?

Every container produced by 0.1.0 through 0.6.2 still opens; the frozen vectors are tested on every commit. If a 0.x release ever cannot open an earlier container, the changelog will say so and the previous binary will still be available. After 1.0 the format never breaks ([stability.md](stability.md)).

## Is my filename hidden?

Yes — filename and media type are encrypted in the header. Not hidden: the ciphertext size, the recipient count, whether the container is signed, and the signer's key if the signature is *public* rather than confidential ([threat-model.md](threat-model.md)).

## What if I forget my passphrase?

The key is unrecoverable. Key files are sealed with Argon2id (19 MiB, t = 2 by default; a floor of 8 MiB is enforced) and ChaCha20-Poly1305; there is no escrow or reset. Back up the sealed key file and remember the passphrase, or keep an identity with a second device and an offline recovery key.

## Does HIDE use any hardware key storage?

No. There is no TPM, Secure Enclave, Keychain, Android Keystore or PIV integration. The passphrase-sealed key file is the only at-rest protection, and `keygen --insecure-plaintext` writes an unsealed key on request.

## Is using HIDE in a browser safe?

The WASM package is the same code as every other SDK, but any script on the page shares the heap: an XSS bug equals key theft. Use the browser to encrypt *to* others; keep decryption keys in the CLI or desktop app ([use-cases.md](use-cases.md) §8).

## Does the desktop app implement its own cryptography?

No. It calls the same Rust crates as the CLI, key material never reaches the webview, and `apps/hide-desktop/src-tauri/tests/interop.rs` proves the CLI and the app open each other's output. CI fails if that test skips ([architecture.md](architecture.md)).

## Is there a formal specification and are there test vectors?

Yes: [../spec/hide-0.1.md](../spec/hide-0.1.md) is normative, and `conformance/vectors/` holds frozen containers plus nine rejection vectors. An independent Node implementation (`conformance/node/verify.mjs`) decrypts the vectors and refuses the rejections, so two implementations agree on what is invalid, not only on what is valid.

## How can I help, audit or fund?

Read [audit-status.md](audit-status.md) for the prioritised list of what to review and an estimate of effort. Report findings through GitHub's private advisory ([../SECURITY.md](../SECURITY.md)). To fund a third-party audit, open an issue titled "audit funding"; the report will be published unredacted.

## Is there a bug bounty?

No. Reporters receive credit in the changelog and in [advisories.md](advisories.md), and a fast fix.

## What license is HIDE under?

Apache-2.0, for the code, the specification and the vectors. There is no requirement to use any server or service.
