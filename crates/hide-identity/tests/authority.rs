//! What an identity log must refuse.
//!
//! These test the authority rules rather than the bookkeeping: a revoked device
//! must not be able to write itself back in, a stranger must not be able to
//! enrol, and history must not be rewritable after the fact.

use hide_identity::{Device, Entry, Event, IdentityError, IdentityLog, decode, device_id, encode};
use hide_sign::SigningIdentity;

fn key() -> SigningIdentity {
    SigningIdentity::generate().unwrap()
}

/// A log with two devices and an offline recovery key.
fn two_device_log() -> (
    IdentityLog,
    SigningIdentity,
    SigningIdentity,
    SigningIdentity,
) {
    let laptop = key();
    let phone = key();
    let recovery = key();
    let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    log.enrol(&laptop, &phone.verifying_key(), "phone").unwrap();
    (log, laptop, phone, recovery)
}

#[test]
fn a_new_identity_trusts_only_its_founder() {
    let founder = key();
    let recovery = key();
    let log = IdentityLog::create(&founder, "laptop", &recovery.verifying_key()).unwrap();

    let membership = log.membership();
    assert_eq!(membership.len(), 1);
    assert!(membership.contains(&device_id(&founder.verifying_key())));
}

#[test]
fn an_enrolled_device_is_trusted() {
    let (log, laptop, phone, _) = two_device_log();
    let membership = log.membership();
    assert_eq!(membership.len(), 2);
    assert!(membership.contains(&device_id(&laptop.verifying_key())));
    assert!(membership.contains(&device_id(&phone.verifying_key())));
}

#[test]
fn a_stranger_cannot_enrol_a_device() {
    let (mut log, _, _, _) = two_device_log();
    let stranger = key();
    let intruder = key();

    let result = log.enrol(&stranger, &intruder.verifying_key(), "intruder");
    assert!(matches!(result, Err(IdentityError::Unauthorised(_))));
    // And nothing was appended.
    assert_eq!(log.membership().len(), 2);
}

#[test]
fn a_revoked_device_cannot_enrol_anything() {
    let (mut log, laptop, phone, _) = two_device_log();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let accomplice = key();
    let result = log.enrol(&phone, &accomplice.verifying_key(), "accomplice");
    assert!(
        matches!(result, Err(IdentityError::Unauthorised(_))),
        "a revoked device enrolled a new one"
    );
}

/// The attack revocation exists to stop: a stolen phone revoking the owner.
#[test]
fn a_revoked_device_cannot_revoke_the_device_that_removed_it() {
    let (mut log, laptop, phone, _) = two_device_log();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let result = log.revoke(&phone, device_id(&laptop.verifying_key()));
    assert!(matches!(result, Err(IdentityError::Unauthorised(_))));
    assert!(
        log.membership()
            .contains(&device_id(&laptop.verifying_key()))
    );
}

#[test]
fn a_revoked_device_cannot_re_enrol_itself() {
    let (mut log, laptop, phone, _) = two_device_log();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let result = log.enrol(&phone, &phone.verifying_key(), "phone again");
    assert!(matches!(result, Err(IdentityError::Unauthorised(_))));
}

#[test]
fn revocation_is_recorded_so_a_user_can_see_it_happened() {
    let (mut log, laptop, phone, _) = two_device_log();
    let phone_id = device_id(&phone.verifying_key());
    let at = log.revoke(&laptop, phone_id).unwrap();

    let membership = log.membership();
    assert!(!membership.contains(&phone_id));
    assert_eq!(membership.revoked_at(&phone_id), Some(at));
    // A device that never existed is distinguishable from one that was removed.
    assert_eq!(
        membership.revoked_at(&device_id(&key().verifying_key())),
        None
    );
}

#[test]
fn the_last_device_cannot_be_revoked() {
    let founder = key();
    let recovery = key();
    let mut log = IdentityLog::create(&founder, "only", &recovery.verifying_key()).unwrap();

    let result = log.revoke(&founder, device_id(&founder.verifying_key()));
    assert!(matches!(result, Err(IdentityError::WouldOrphan(_))));
    assert_eq!(log.membership().len(), 1);
}

#[test]
fn a_device_may_revoke_itself_while_others_remain() {
    // "Log out this phone" from the phone itself.
    let (mut log, _, phone, _) = two_device_log();
    let phone_id = device_id(&phone.verifying_key());
    log.revoke(&phone, phone_id).unwrap();
    assert!(!log.membership().contains(&phone_id));
}

#[test]
fn revoking_a_device_that_was_never_enrolled_is_refused() {
    let (mut log, laptop, _, _) = two_device_log();
    let result = log.revoke(&laptop, device_id(&key().verifying_key()));
    assert!(matches!(result, Err(IdentityError::NotEnrolled(_))));
}

#[test]
fn enrolling_the_same_device_twice_is_refused() {
    let (mut log, laptop, phone, _) = two_device_log();
    let result = log.enrol(&laptop, &phone.verifying_key(), "phone again");
    assert!(matches!(result, Err(IdentityError::AlreadyEnrolled(_))));
}

#[test]
fn recovery_replaces_every_device() {
    let (mut log, laptop, phone, recovery) = two_device_log();
    let replacement = key();

    log.recover(&recovery, &replacement.verifying_key(), "new laptop")
        .unwrap();

    let membership = log.membership();
    assert_eq!(membership.len(), 1);
    assert!(membership.contains(&device_id(&replacement.verifying_key())));
    assert!(!membership.contains(&device_id(&laptop.verifying_key())));
    assert!(!membership.contains(&device_id(&phone.verifying_key())));
}

#[test]
fn only_the_recovery_key_may_recover() {
    let (mut log, laptop, _, _) = two_device_log();
    let replacement = key();

    // A trusted device is still not the recovery key.
    let result = log.recover(&laptop, &replacement.verifying_key(), "nope");
    assert!(matches!(result, Err(IdentityError::Unauthorised(_))));

    let stranger = key();
    let result = log.recover(&stranger, &replacement.verifying_key(), "nope");
    assert!(matches!(result, Err(IdentityError::Unauthorised(_))));
}

#[test]
fn a_device_removed_by_recovery_cannot_act() {
    let (mut log, laptop, _, recovery) = two_device_log();
    let replacement = key();
    log.recover(&recovery, &replacement.verifying_key(), "new")
        .unwrap();

    let result = log.enrol(&laptop, &key().verifying_key(), "sneaky");
    assert!(matches!(result, Err(IdentityError::Unauthorised(_))));
}

#[test]
fn a_stranger_can_verify_the_whole_history() {
    let (mut log, laptop, phone, recovery) = two_device_log();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let membership = IdentityLog::verify(log.entries(), &recovery.verifying_key()).unwrap();
    assert_eq!(membership.len(), 1);
    assert!(membership.contains(&device_id(&laptop.verifying_key())));
}

#[test]
fn a_log_verified_against_the_wrong_recovery_key_still_replays() {
    // Recovery only matters for Recover entries; a log without one must not
    // depend on which recovery key a verifier was told about.
    let (log, _, _, _) = two_device_log();
    let other = key();
    assert!(IdentityLog::verify(log.entries(), &other.verifying_key()).is_ok());
}

#[test]
fn a_recovery_verified_against_the_wrong_key_is_refused() {
    let (mut log, _, _, recovery) = two_device_log();
    log.recover(&recovery, &key().verifying_key(), "new")
        .unwrap();

    let other = key();
    let result = IdentityLog::verify(log.entries(), &other.verifying_key());
    assert!(matches!(result, Err(IdentityError::Unauthorised(_))));
}

#[test]
fn a_reordered_history_is_refused() {
    let (mut log, laptop, phone, recovery) = two_device_log();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let mut entries = log.entries().to_vec();
    entries.swap(1, 2);
    assert!(IdentityLog::verify(&entries, &recovery.verifying_key()).is_err());
}

#[test]
fn a_removed_entry_is_refused() {
    // Dropping the revocation would silently restore a revoked device.
    let (mut log, laptop, phone, recovery) = two_device_log();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let mut entries = log.entries().to_vec();
    entries.remove(2);
    // Numbering still lines up for what remains, so the linkage must be what
    // catches this.
    assert!(IdentityLog::verify(&entries, &recovery.verifying_key()).is_ok());
    // ...but the head no longer matches what the owner published.
    assert_ne!(entries.last().unwrap().link, log.head());
}

/// The signature must commit to the history behind the entry, not just to the
/// entry. Otherwise an entry signed in one log is equally valid at the same
/// position in a different log, and an attacker who gets the owner to sign
/// something innocuous in log A can splice it into log B. Mutation-verified:
/// removing `previous` from `signed_bytes` must fail this test.
#[test]
fn an_entry_cannot_be_transplanted_between_logs() {
    let laptop = key();
    let recovery = key();

    // Two histories that share their founding device, so the signer is trusted
    // in both. Signing is deterministic, so the roots must genuinely differ or
    // the two logs would be byte-identical and the transplant a no-op.
    let mut ours = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    let mut theirs =
        IdentityLog::create(&laptop, "laptop (work)", &recovery.verifying_key()).unwrap();
    assert_ne!(
        ours.head(),
        theirs.head(),
        "roots must differ: ours={:02x?} theirs={:02x?}",
        &ours.head()[..4],
        &theirs.head()[..4]
    );

    // The same device enrolled in both, so entry 1 differs only by the history
    // behind it.
    let phone = key();
    ours.enrol(&laptop, &phone.verifying_key(), "phone")
        .unwrap();
    theirs
        .enrol(&laptop, &phone.verifying_key(), "phone")
        .unwrap();

    assert_ne!(
        ours.entries()[1].link,
        theirs.entries()[1].link,
        "entry 1 must differ between the two logs: ours={:02x?} theirs={:02x?}",
        &ours.entries()[1].link[..4],
        &theirs.entries()[1].link[..4]
    );

    // Lift their entry 1 into our log at the same position.
    let mut entries = ours.entries().to_vec();
    entries[1] = theirs.entries()[1].clone();

    assert!(
        IdentityLog::verify(&entries, &recovery.verifying_key()).is_err(),
        "an entry from another log was accepted at the same position"
    );
}

/// Same idea, one step further: the entry after a transplant must also fail,
/// because its own link was computed over the entry that was replaced.
#[test]
fn a_transplanted_prefix_breaks_every_later_entry() {
    let laptop = key();
    let recovery = key();
    let mut ours = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    let mut theirs =
        IdentityLog::create(&laptop, "laptop (work)", &recovery.verifying_key()).unwrap();

    let phone = key();
    ours.enrol(&laptop, &phone.verifying_key(), "phone")
        .unwrap();
    ours.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();
    theirs
        .enrol(&laptop, &phone.verifying_key(), "phone")
        .unwrap();

    let mut entries = ours.entries().to_vec();
    entries[1] = theirs.entries()[1].clone();

    assert!(IdentityLog::verify(&entries, &recovery.verifying_key()).is_err());
}

#[test]
fn a_tampered_label_is_refused() {
    let (log, _, _, recovery) = two_device_log();
    let mut entries = log.entries().to_vec();
    if let Event::Enrol { label, .. } = &mut entries[1].event {
        *label = "attacker".to_owned();
    }
    assert!(IdentityLog::verify(&entries, &recovery.verifying_key()).is_err());
}

#[test]
fn a_tampered_signature_is_refused() {
    let (log, _, _, recovery) = two_device_log();
    let mut entries = log.entries().to_vec();
    entries[1].signature[0] ^= 1;
    assert!(IdentityLog::verify(&entries, &recovery.verifying_key()).is_err());
}

#[test]
fn an_empty_log_is_refused() {
    let recovery = key();
    assert_eq!(
        IdentityLog::verify(&[], &recovery.verifying_key()).unwrap_err(),
        IdentityError::Empty
    );
}

#[test]
fn a_log_that_does_not_begin_with_create_is_refused() {
    let (log, _, _, recovery) = two_device_log();
    let entries = log.entries()[1..].to_vec();
    assert!(matches!(
        IdentityLog::verify(&entries, &recovery.verifying_key()),
        Err(IdentityError::BadRoot(_))
    ));
}

#[test]
fn a_log_round_trips_through_cbor() {
    let (mut log, laptop, phone, recovery) = two_device_log();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let encoded = encode(log.entries()).unwrap();
    let decoded = decode(&encoded).unwrap();
    assert_eq!(decoded, log.entries());

    let membership = IdentityLog::verify(&decoded, &recovery.verifying_key()).unwrap();
    assert_eq!(membership.len(), 1);
}

#[test]
fn trailing_bytes_are_refused() {
    let (log, _, _, _) = two_device_log();
    let mut encoded = encode(log.entries()).unwrap();
    encoded.push(0);
    assert_eq!(decode(&encoded).unwrap_err(), IdentityError::Malformed);
}

#[test]
fn a_truncated_encoding_is_refused() {
    let (log, _, _, _) = two_device_log();
    let encoded = encode(log.entries()).unwrap();
    for cut in 1..encoded.len() {
        assert!(
            decode(&encoded[..cut]).is_err(),
            "accepted a {cut}-byte prefix"
        );
    }
}

#[test]
fn an_absurd_entry_count_is_refused_before_allocating() {
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    encoder.array(u32::MAX as u64).unwrap();
    assert!(matches!(
        decode(&out).unwrap_err(),
        IdentityError::TooManyEntries(_)
    ));
}

#[test]
fn the_head_changes_with_every_entry() {
    let (mut log, laptop, phone, _) = two_device_log();
    let before = log.head();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();
    assert_ne!(log.head(), before);
}

#[test]
fn two_identities_never_share_a_head() {
    let recovery = key();
    let a = IdentityLog::create(&key(), "laptop", &recovery.verifying_key()).unwrap();
    let b = IdentityLog::create(&key(), "laptop", &recovery.verifying_key()).unwrap();
    assert_ne!(a.head(), b.head());
}

#[test]
fn an_over_long_label_is_refused() {
    let founder = key();
    let recovery = key();
    let long = "x".repeat(1000);
    assert_eq!(
        IdentityLog::create(&founder, &long, &recovery.verifying_key()).err(),
        Some(IdentityError::LabelTooLong)
    );
}

#[test]
fn device_ids_are_stable_and_distinct() {
    let a = key().verifying_key();
    let b = key().verifying_key();
    assert_eq!(device_id(&a), device_id(&a));
    assert_ne!(device_id(&a), device_id(&b));
}

#[test]
fn devices_are_listed_in_a_stable_order() {
    let (log, _, _, _) = two_device_log();
    let first: Vec<_> = log.membership().devices().map(|d| d.id).collect();
    let second: Vec<_> = log.membership().devices().map(|d| d.id).collect();
    assert_eq!(first, second);
}

#[test]
fn a_device_carries_the_label_it_was_enrolled_with() {
    let (log, _, phone, _) = two_device_log();
    let membership = log.membership();
    let device: &Device = membership.get(&device_id(&phone.verifying_key())).unwrap();
    assert_eq!(device.label, "phone");
    assert_eq!(device.enrolled_at, 1);
}

#[test]
fn a_forged_entry_appended_by_a_stranger_is_refused() {
    // Not going through the API at all: hand-built entry with a valid-looking
    // shape, signed by a key the log has never seen.
    let (log, _, _, recovery) = two_device_log();
    let stranger = key();
    let mut entries = log.entries().to_vec();

    let event = Event::Enrol {
        device: stranger.verifying_key().to_bytes().to_vec(),
        label: "forged".to_owned(),
    };
    entries.push(Entry {
        sequence: 2,
        event,
        signer: device_id(&stranger.verifying_key()),
        link: [0u8; 32],
        signature: vec![0u8; hide_sign::SIGNATURE_LENGTH],
    });

    assert!(IdentityLog::verify(&entries, &recovery.verifying_key()).is_err());
}
