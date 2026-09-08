# hide-epoch

Forward security by erasure for the
[HIDE](https://github.com/hide-protocol/hide) protocol. A recipient holds a
chain of epoch keys, each an **independent** random X25519 + ML-KEM-768 key
(never derived from the master seed, or a later seed compromise would re-derive
everything). Once an epoch's secret is erased, every container written to that
epoch is permanently unreadable — by anyone, including the recipient.

The chain stores only public keys plus a hash chain binding them in order, so
a sender can verify which key was current at epoch *n* without being able to
recover an erased one.

```rust
use hide_epoch::{EpochChain, encode_records, decode_records, recipient_for};

let mut chain = EpochChain::new()?;          // epoch 0
let first = chain.current();
chain.advance()?;                            // epoch 1 is now current

// Publish the public side; a sender picks a recipient key for an epoch.
let published = encode_records(chain.records())?;
let records = decode_records(&published)?;
EpochChain::verify(&records)?;
let recipient = recipient_for(&records, first)?;
let _ = recipient.to_bytes();

// Close the window: the epoch-0 secret is zeroized and gone.
chain.erase(first)?;
assert!(!chain.is_readable(first));
assert!(chain.is_readable(chain.current()));
# Ok::<(), hide_epoch::EpochError>(())
```

The guarantee is only as good as the erasure. This crate zeroizes its own
copy; it cannot speak for backups, swap, filesystem snapshots or SSD
wear-levelling.

**Experimental and unaudited.** Licensed Apache-2.0.
