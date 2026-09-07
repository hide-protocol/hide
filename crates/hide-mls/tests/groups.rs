//! What the identity/MLS join must guarantee.
//!
//! MLS itself is exercised only enough to build a real group; the tests that
//! matter here are the ones about HIDE identities, because that join is the
//! part this crate actually implements.

use hide_identity::{IdentityLog, device_id};
use hide_mls::{
    MlsError, accept_from_trusted, client_for, decode_message, encode_message, sender_device,
    untrusted_members,
};
use hide_sign::SigningIdentity;

fn key() -> SigningIdentity {
    SigningIdentity::generate().unwrap()
}

/// An identity with two devices: a laptop that founded it and a phone.
fn identity() -> (IdentityLog, SigningIdentity, SigningIdentity) {
    let laptop = key();
    let phone = key();
    let recovery = key();
    let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    log.enrol(&laptop, &phone.verifying_key(), "phone").unwrap();
    (log, laptop, phone)
}

#[test]
fn a_trusted_device_gets_a_client() {
    let (log, laptop, _) = identity();
    assert!(client_for(&log.membership(), laptop.verifying_key()).is_ok());
}

#[test]
fn a_device_the_identity_does_not_know_is_refused() {
    let (log, _, _) = identity();
    let stranger = key();
    assert!(matches!(
        client_for(&log.membership(), stranger.verifying_key()),
        Err(MlsError::UntrustedDevice)
    ));
}

#[test]
fn a_revoked_device_can_no_longer_get_a_client() {
    let (mut log, laptop, phone) = identity();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    assert!(matches!(
        client_for(&log.membership(), phone.verifying_key()),
        Err(MlsError::UntrustedDevice)
    ));
}

#[test]
fn two_devices_exchange_a_message() {
    let (log, laptop, phone) = identity();
    let alice = client_for(&log.membership(), laptop.verifying_key()).unwrap();
    let bob = client_for(&log.membership(), phone.verifying_key()).unwrap();

    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let commit = group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let (mut bobs, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .unwrap();

    let sent = group
        .encrypt_application_message(b"salut", Default::default())
        .unwrap();
    let received = bobs.process_incoming_message(sent).unwrap();

    match &received {
        hide_mls::Received::ApplicationMessage(m) => assert_eq!(m.data(), b"salut"),
        other => panic!("unexpected message: {other:?}"),
    }
}

/// The join that this crate exists for: a group member carries a HIDE device
/// id, so a revoked device is visible as stale membership.
#[test]
fn a_revoked_device_is_reported_as_stale_group_membership() {
    let (mut log, laptop, phone) = identity();
    let alice = client_for(&log.membership(), laptop.verifying_key()).unwrap();
    let bob = client_for(&log.membership(), phone.verifying_key()).unwrap();

    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();

    // Everyone is trusted while the identity still lists both devices.
    assert!(
        untrusted_members(&group, &log.membership())
            .unwrap()
            .is_empty()
    );

    // Revoking the phone must surface it, even though MLS itself is unaware.
    let phone_id = device_id(&phone.verifying_key());
    log.revoke(&laptop, phone_id).unwrap();
    assert_eq!(
        untrusted_members(&group, &log.membership()).unwrap(),
        vec![phone_id]
    );
}

/// MLS proves a message came from a group member; it cannot know the member's
/// device was revoked in the identity log. That gap is what this closes.
#[test]
fn a_message_from_a_revoked_device_is_rejected() {
    let (mut log, laptop, phone) = identity();
    let alice = client_for(&log.membership(), laptop.verifying_key()).unwrap();
    let bob = client_for(&log.membership(), phone.verifying_key()).unwrap();

    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let commit = group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let (mut bobs, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .unwrap();

    // Bob sends while still trusted.
    let sent = bobs
        .encrypt_application_message(b"still trusted", Default::default())
        .unwrap();
    let received = group.process_incoming_message(sent).unwrap();
    assert!(accept_from_trusted(&group, &received, &log.membership()).is_ok());

    // The phone is revoked; a later message from it must be refused.
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();
    let sent = bobs
        .encrypt_application_message(b"no longer trusted", Default::default())
        .unwrap();
    let received = group.process_incoming_message(sent).unwrap();
    assert!(matches!(
        accept_from_trusted(&group, &received, &log.membership()),
        Err(MlsError::UntrustedSender)
    ));
}

#[test]
fn the_sender_device_is_recoverable_from_a_message() {
    let (log, laptop, phone) = identity();
    let alice = client_for(&log.membership(), laptop.verifying_key()).unwrap();
    let bob = client_for(&log.membership(), phone.verifying_key()).unwrap();

    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let commit = group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let (mut bobs, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .unwrap();

    let sent = bobs
        .encrypt_application_message(b"from the phone", Default::default())
        .unwrap();
    let received = group.process_incoming_message(sent).unwrap();

    assert_eq!(
        sender_device(&group, &received).unwrap(),
        Some(device_id(&phone.verifying_key()))
    );
}

#[test]
fn a_message_round_trips_through_its_encoding() {
    let (log, laptop, phone) = identity();
    let alice = client_for(&log.membership(), laptop.verifying_key()).unwrap();
    let bob = client_for(&log.membership(), phone.verifying_key()).unwrap();

    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let commit = group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let (mut bobs, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .unwrap();

    let sent = group
        .encrypt_application_message(b"over the wire", Default::default())
        .unwrap();
    let bytes = encode_message(&sent).unwrap();
    let decoded = decode_message(&bytes).unwrap();

    match bobs.process_incoming_message(decoded).unwrap() {
        hide_mls::Received::ApplicationMessage(m) => assert_eq!(m.data(), b"over the wire"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn a_corrupted_message_is_refused() {
    let (log, laptop, phone) = identity();
    let alice = client_for(&log.membership(), laptop.verifying_key()).unwrap();
    let bob = client_for(&log.membership(), phone.verifying_key()).unwrap();

    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .unwrap();
    let kp = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let commit = group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let (mut bobs, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .unwrap();

    let sent = group
        .encrypt_application_message(b"tamper me", Default::default())
        .unwrap();
    let mut bytes = encode_message(&sent).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;

    let refused = match decode_message(&bytes) {
        Err(_) => true,
        Ok(message) => bobs.process_incoming_message(message).is_err(),
    };
    assert!(refused, "a corrupted message was accepted");
}

/// The API must not imply post-quantum protection it does not have.
#[test]
fn the_pq_status_is_stated_and_says_group_messages_are_classical() {
    assert!(hide_mls::PQ_STATUS.contains("not post-quantum"));
    assert!(hide_mls::PQ_STATUS.contains("Internet-Draft"));
}
