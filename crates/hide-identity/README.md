# hide-identity

Device enrollment, revocation and recovery for a
[HIDE](https://github.com/hide-protocol/hide) identity. An identity is not a
key: it is an ordered, hash-linked log of events, each signed by a device the
log had *already* authorised at that point. Replaying the log from its root
yields the set of devices trusted now.

Authority is evaluated at the position in the log where an entry appears, never
against the final state, so a revoked device cannot re-enrol itself or rewrite
anything after its removal. Recovery is a separate hybrid signing key that can
replace the whole device set.

```rust
use hide_identity::{IdentityLog, device_id};
use hide_sign::SigningIdentity;

let laptop = SigningIdentity::generate()?;
let phone = SigningIdentity::generate()?;
let recovery = SigningIdentity::generate()?;

let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key())?;
log.enrol(&laptop, &phone.verifying_key(), "phone")?;
log.revoke(&laptop, device_id(&phone.verifying_key()))?;

// Anyone holding the recovery public key can replay and check the history.
let bytes = hide_identity::encode(log.entries())?;
let entries = hide_identity::decode(&bytes)?;
let membership = IdentityLog::verify(&entries, &recovery.verifying_key())?;
assert!(membership.contains(&device_id(&laptop.verifying_key())));
assert!(!membership.contains(&device_id(&phone.verifying_key())));
# Ok::<(), Box<dyn std::error::Error>>(())
```

This does not prove a log belongs to a particular person, and two divergent
copies are each internally valid: detecting a split needs a witness — see
[`hide-transparency`](https://docs.rs/hide-transparency).

**Experimental and unaudited.** Licensed Apache-2.0.
