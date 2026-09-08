# hide-keyring

At-rest key handling for the [HIDE](https://github.com/hide-protocol/hide)
protocol. `hide-crypto` knows nothing about files or passphrases; this crate
seals the 32-byte master seed under Argon2id + ChaCha20-Poly1305, with the KDF
parameters stored in the file and authenticated as AAD, and armors public keys
as text.

An `Identity` is one seed from which the encryption key and the signing seed
are derived by domain-separated HKDF — one thing to back up.

```rust
use hide_keyring::{Identity, KeyFormat, decode_public, encode_public, inspect, open, protect_identity};

let identity = Identity::generate()?;
let sealed = protect_identity(identity.expose_seed_for_sealing(), "correct horse battery")?;
assert_eq!(inspect(&sealed), KeyFormat::Protected);

// `open` derives the recipient key the same way every HIDE surface does.
let secret = open(&sealed, Some("correct horse battery"))?;
let public = secret.public_key()?.to_bytes();

let armored = encode_public(&public);
assert_eq!(decode_public(&armored)?, public);
# Ok::<(), hide_keyring::KeyringError>(())
```

This protects a key file at rest; it is not a hardware-backed vault. While in
use, the key lives in ordinary process memory (zeroized on drop).

**Experimental and unaudited.** Licensed Apache-2.0.
