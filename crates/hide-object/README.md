# hide-object

The sealed container of the [HIDE](https://github.com/hide-protocol/hide)
protocol: one content key wrapped to up to 64 recipients with X25519 +
ML-KEM-768 (X-Wing), payload streamed in 64 KiB authenticated chunks, optional
hybrid Ed25519 + ML-DSA-65 signature over the plaintext transcript.

Decryption writes to a **staging** writer and only reports success once the
FINAL chunk authenticates; nothing is published before then. The decrypted
filename is returned as data, never used as a path.

```rust
use hide_crypto::RecipientSecret;
use hide_object::{decrypt_to_staging, encrypt, Metadata};
use std::io::Cursor;

let secret = RecipientSecret::generate()?;
let recipients = [secret.public_key()?];
let metadata = Metadata { filename: Some("hello.txt".into()), ..Metadata::default() };

let mut container = Vec::new();
encrypt(&mut Cursor::new(b"hello".to_vec()), &mut container, &recipients, &metadata)?;

let mut staging = Vec::new();
let verified = decrypt_to_staging(&mut Cursor::new(container), &mut staging, &secret)?;
assert_eq!(staging, b"hello");
assert_eq!(verified.metadata.filename.as_deref(), Some("hello.txt"));
assert!(verified.signer.is_none());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Memory is constant regardless of input size (fixed buffers, one `ChunkCipher`).
Frozen conformance vectors pin the wire bytes.

**Experimental and unaudited.** Do not protect data you cannot afford to lose
or expose. Licensed Apache-2.0.
