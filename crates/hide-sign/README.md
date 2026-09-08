# hide-sign

Hybrid Ed25519 + ML-DSA-65 signatures for the
[HIDE](https://github.com/hide-protocol/hide) protocol. A signature is the
concatenation of both halves and verifies **only if both halves verify**, so
the scheme is never silently reduced to the weaker one. Both halves derive
from a single 32-byte seed through domain-separated HKDF.

Also provides `Challenge`/`SpentNonces` for replay-safe proof of possession.

```rust
use hide_sign::{SigningIdentity, VerifyingIdentity, SIGNATURE_LENGTH};

let identity = SigningIdentity::generate()?;
let verifying: VerifyingIdentity = identity.verifying_key();

let context = b"hide/example";
let signature: [u8; SIGNATURE_LENGTH] = identity.sign(context, b"hello");
verifying.verify(context, b"hello", &signature)?;

// Public keys and signatures are fixed-size byte arrays.
let restored = VerifyingIdentity::from_bytes(&verifying.to_bytes())?;
assert!(restored.verify(context, b"tampered", &signature).is_err());
# Ok::<(), hide_sign::SignError>(())
```

Signing is deterministic. No primitive is implemented here; the crate composes
`ed25519-dalek` and `ml-dsa` and owns only the combination.

**Experimental and unaudited.** Do not rely on it for anything you cannot
afford to lose or expose. Licensed Apache-2.0.
