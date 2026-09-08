# hide-transparency

Append-only Merkle log for the [HIDE](https://github.com/hide-protocol/hide)
protocol, with RFC 6962-style inclusion and consistency proofs and a compact
signed-checkpoint encoding. It is the witness layer: two copies of an identity
log are each internally valid, and only a transparency log lets a verifier
notice that they were shown different histories.

Proof lengths are bounded before any work is done, so a hostile proof cannot
make a verifier allocate or loop unboundedly.

```rust
use hide_transparency::{TransparencyLog, leaf_hash, verify_consistency, verify_inclusion};

let mut log = TransparencyLog::new();
let index = log.append(b"identity-head-1");
log.append(b"identity-head-2");
let old_root = log.root();
let old_size = log.len();

log.append(b"identity-head-3");
let new_root = log.root();

// The entry is in the log of size `old_size`...
let inclusion = log.prove_inclusion(index, old_size)?;
verify_inclusion(&inclusion, &leaf_hash(b"identity-head-1"), &old_root)?;

// ...and the newer log is an extension of the older one, not a rewrite.
let consistency = log.prove_consistency(old_size, log.len())?;
verify_consistency(&consistency, &old_root, &new_root)?;

let checkpoint = hide_transparency::encode_checkpoint(log.len(), &new_root);
assert_eq!(hide_transparency::decode_checkpoint(&checkpoint)?, (log.len(), new_root));
# Ok::<(), hide_transparency::LogError>(())
```

No cryptography beyond SHA-256 is used; the crate owns only the tree shape.

**Experimental and unaudited.** Licensed Apache-2.0.
