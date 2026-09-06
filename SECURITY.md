# Security Policy

## HIDE/0.1 is experimental — do not protect real data with it

The protocol is a draft, the implementation is unaudited, and no external
security review has taken place. The hybrid KEM follows IETF drafts that are
still changing. Treat every container as a test artifact.

The CLI requires `--experimental` for this reason.

## What this version does not protect against

Reporting these is welcome, but they are known and documented, not new findings:

- **No sender authentication.** A successful decryption proves the container was
  not altered. It does not prove who produced it.
- **No identity binding.** Recipient keys are raw files. Nothing links a key to a
  person; there is no directory and no key transparency.
- **No forward secrecy.** Anyone who later obtains a recipient secret can decrypt
  containers captured earlier.
- **No hardware protection.** Secret keys are sealed at rest with Argon2id
  (19 MiB, t=2) and ChaCha20-Poly1305, which resists an attacker who copies the
  file but not one who can read the process memory while the key is in use.
  There is no Keychain, TPM, Secure Enclave or Keystore integration, and
  `keygen --insecure-plaintext` still writes an unencrypted key on request.
- **A forgotten passphrase is unrecoverable.** There is no escrow, reset or
  backdoor. Losing it destroys access to everything encrypted to that key.
- **Metadata is encrypted, not hidden.** Ciphertext size and recipient count
  remain observable.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button under the Security tab, which
opens a private advisory. Please do not open a public issue for a suspected
vulnerability.

Include the affected commit, a reproduction (a container plus the steps), and
what you believe the impact is. A failing test is the most useful form.

Expect an acknowledgement within 7 days. Because this is a pre-1.0 experiment
maintained without a dedicated security team, fixes ship on a best-effort basis.

## Findings that are especially valuable

- A container that decrypts under a key it was not encrypted to.
- Any input that causes a panic, an unbounded allocation, or non-termination in
  the parser.
- A tampered container that authenticates successfully.
- Divergence between the Rust implementation and `conformance/node/verify.mjs`,
  since either side may be the wrong one.
- Secret material reaching a log, an error message, or a file on disk.

## Cryptographic scope

HIDE implements no primitives of its own and defines no novel KEM combiner. It
composes HPKE (X-Wing: X25519 + ML-KEM-768), HKDF-SHA256, HMAC-SHA256 and
ChaCha20-Poly1305 from established crates. A flaw in one of those belongs
upstream, though a report here is still appreciated so the dependency can be
pinned or replaced.
