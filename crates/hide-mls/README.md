# hide-mls

Group messaging for [HIDE](https://github.com/hide-protocol/hide) identities
over MLS (RFC 9420), built on `mls-rs`. The join this crate implements: an MLS
credential carries a HIDE device id, the device's hybrid verifying key, and a
HIDE signature over the fresh MLS signature key. The identity provider checks
every roster entry against the identity log's current `Membership`, so a
device the log has revoked is refused at the door and visible as stale if it
was already inside.

HIDE adds no cryptography of its own on top of MLS. The MLS ciphersuite is
classical: post-quantum MLS suites are still a draft (`hide_mls::PQ_STATUS`).

```rust
use hide_identity::IdentityLog;
use hide_mls::{client_for, untrusted_members};
use hide_sign::SigningIdentity;

let laptop = SigningIdentity::generate()?;
let phone = SigningIdentity::generate()?;
let recovery = SigningIdentity::generate()?;
let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key())?;
log.enrol(&laptop, &phone.verifying_key(), "phone")?;

let alice = client_for(&log.membership(), &laptop)?;
let bob = client_for(&log.membership(), &phone)?;

let mut group = alice.create_group(Default::default(), Default::default(), None)?;
let key_package = bob.generate_key_package_message(Default::default(), Default::default(), None)?;
let commit = group.commit_builder().add_member(key_package)?.build()?;
group.apply_pending_commit()?;
let (mut bobs_group, _) = bob.join_group(None, &commit.welcome_messages[0], None)?;

let sent = group.encrypt_application_message(b"salut", Default::default())?;
let received = bobs_group.process_incoming_message(sent)?;
assert!(matches!(received, hide_mls::Received::ApplicationMessage(_)));
assert!(untrusted_members(&group, &log.membership())?.is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

`mls-rs` has no public third-party audit; neither does this crate.

**Experimental and unaudited.** Licensed Apache-2.0.
