# hide-crypto

Hybrid post-quantum primitives for the [HIDE](https://github.com/hide-protocol/hide)
protocol: X25519 + ML-KEM-768 via X-Wing (HPKE), HKDF-SHA-256, HMAC and
ChaCha20-Poly1305. No primitive is implemented here; the crate composes
reviewed implementations and owns only the combination and key derivation.

Secret types never derive `Debug`, `Clone` or `Serialize` and zeroize on drop.

```rust
use hide_crypto::{ContentKey, RecipientSecret, derive_key, seal, open};

let secret = RecipientSecret::generate()?;
let public = secret.public_key()?;
let cek = ContentKey::generate()?;

// Wrap the content key to a recipient, bound to a 32-byte object id.
let object_id = hide_crypto::random_array::<32>()?;
let wrapped = hide_crypto::wrap_cek(&public, &cek, &object_id)?;
let unwrapped =
    hide_crypto::unwrap_cek(&secret, &object_id, &wrapped.encapsulation, &wrapped.wrapped_cek)?;

let key = derive_key(&unwrapped, b"salt", b"info")?;
let nonce = [0u8; 12];
let ciphertext = seal(&key, &nonce, b"aad", b"hello")?;
let plaintext = open(&key, &nonce, b"aad", &ciphertext)?;
assert_eq!(&plaintext[..], b"hello");
# Ok::<(), hide_crypto::CryptoError>(())
```

Most users want [`hide-object`](https://docs.rs/hide-object), which turns these
primitives into a sealed, streamed container.

**Experimental and unaudited.** Do not protect data you cannot afford to lose
or expose. Licensed Apache-2.0.
