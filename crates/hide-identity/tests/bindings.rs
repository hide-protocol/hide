//! Spec §16.1 (recovery binding) and §16.4 (epoch binding), attacker-shaped.

use hide_epoch::EpochChain;
use hide_identity::{
    EPOCH_BINDING_LENGTH, EpochBinding, IdentityError, IdentityLog, RECOVERY_BINDING_CONTEXT,
    RECOVERY_BINDING_LENGTH, RecoveryBinding, decode, device_id, encode,
};
use hide_sign::SigningIdentity;
use sha2::{Digest, Sha256};

fn key(byte: u8) -> SigningIdentity {
    SigningIdentity::from_bytes(&[byte; 32]).expect("seed")
}

fn err<T>(result: Result<T, IdentityError>) -> IdentityError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error,
    }
}

struct World {
    laptop: SigningIdentity,
    phone: SigningIdentity,
    recovery: SigningIdentity,
    log: IdentityLog,
    binding: RecoveryBinding,
}

fn world() -> World {
    let laptop = key(1);
    let phone = key(2);
    let recovery = key(3);
    let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    let binding = RecoveryBinding::create(&log, &laptop).unwrap();
    log.enrol(&laptop, &phone.verifying_key(), "phone").unwrap();
    World {
        laptop,
        phone,
        recovery,
        log,
        binding,
    }
}

/// §15.1, the attack itself: take a real log, append a Recover signed by the
/// attacker's key, and present the attacker's key as "the recovery key". The
/// bare replay accepts it; the pinned binding refuses it.
#[test]
fn the_recover_hijack_replays_without_a_binding_and_fails_with_one() {
    let w = world();
    let mallory = key(0x66);
    let mallory_device = key(0x67);

    let mut hijacked =
        IdentityLog::from_entries(w.log.entries().to_vec(), mallory.verifying_key()).unwrap();
    hijacked
        .recover(&mallory, &mallory_device.verifying_key(), "mine")
        .unwrap();
    let membership = IdentityLog::verify(hijacked.entries(), &mallory.verifying_key()).unwrap();
    assert!(
        membership.contains(&device_id(&mallory_device.verifying_key())),
        "premise: the frozen replay accepts the hijack"
    );

    let pinned = w.log.root();
    assert_eq!(hijacked.root(), pinned, "premise: same identity root");
    // Mallory can only offer the genuine binding (it names the real recovery
    // key, under which her Recover is unauthorised) or forge one.
    assert_eq!(
        err(w
            .binding
            .verify_pinned(hijacked.entries().to_vec(), &pinned)),
        IdentityError::Unauthorised(2)
    );
    let forged = RecoveryBinding {
        root: pinned,
        recovery_key: mallory.verifying_key(),
        signature: mallory
            .sign(
                RECOVERY_BINDING_CONTEXT,
                &[&pinned[..], &mallory.verifying_key().to_bytes()[..]].concat(),
            )
            .to_vec(),
    };
    assert_eq!(
        err(forged.verify_pinned(hijacked.entries().to_vec(), &pinned)),
        IdentityError::BadBinding
    );
}

#[test]
fn the_genuine_binding_verifies_and_survives_recovery() {
    let mut w = world();
    let log = w
        .binding
        .verify_pinned(w.log.entries().to_vec(), &w.log.root())
        .unwrap();
    assert_eq!(log.membership().len(), 2);

    let replacement = key(9);
    w.log
        .recover(&w.recovery, &replacement.verifying_key(), "new phone")
        .unwrap();
    let log = w
        .binding
        .verify_pinned(w.log.entries().to_vec(), &w.log.root())
        .unwrap();
    assert!(
        log.membership()
            .contains(&device_id(&replacement.verifying_key()))
    );
    assert_eq!(log.membership().len(), 1);
}

#[test]
fn a_binding_for_another_identity_or_pin_is_refused() {
    let w = world();
    let other = IdentityLog::create(&key(0x40), "other", &key(0x41).verifying_key()).unwrap();
    assert_eq!(
        err(w.binding.verify(other.entries().to_vec())),
        IdentityError::WrongIdentity
    );
    assert_eq!(
        err(w
            .binding
            .verify_pinned(w.log.entries().to_vec(), &other.root())),
        IdentityError::WrongIdentity
    );
}

#[test]
fn only_the_founder_can_create_the_binding() {
    let w = world();
    assert_eq!(
        err(RecoveryBinding::create(&w.log, &w.phone)),
        IdentityError::Unauthorised(0)
    );
}

#[test]
fn every_byte_of_a_recovery_binding_is_load_bearing() {
    let w = world();
    let bytes = w.binding.encode();
    assert_eq!(bytes.len(), RECOVERY_BINDING_LENGTH);
    assert_eq!(RecoveryBinding::decode(&bytes).unwrap(), w.binding);
    for at in [
        0,
        31,
        32,
        32 + 31,
        32 + 1983,
        32 + 1984,
        RECOVERY_BINDING_LENGTH - 1,
    ] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        let refused = RecoveryBinding::decode(&bad)
            .map_or(true, |b| b.verify(w.log.entries().to_vec()).is_err());
        assert!(refused, "flip at {at} accepted");
    }
    for len in [0, RECOVERY_BINDING_LENGTH - 1, RECOVERY_BINDING_LENGTH + 1] {
        assert_eq!(
            err(RecoveryBinding::decode(&vec![0; len])),
            IdentityError::Malformed
        );
    }
}

/// §16.1 recomputed from the formula, not from the code.
#[test]
fn the_recovery_binding_bytes_match_the_spec() {
    let w = world();
    let message = [
        &w.log.root()[..],
        &w.recovery.verifying_key().to_bytes()[..],
    ]
    .concat();
    w.laptop
        .verifying_key()
        .verify(b"HIDE/1.0 recovery binding", &message, &w.binding.signature)
        .expect("signature over root || recovery_key");
    assert_eq!(&w.binding.encode()[..32], &w.log.root());
}

fn chain(epochs: usize) -> EpochChain {
    let mut chain = EpochChain::new().unwrap();
    for _ in 1..epochs {
        chain.advance().unwrap();
    }
    chain
}

#[test]
fn an_epoch_binding_verifies_for_its_chain_only() {
    let w = world();
    let mine = chain(2);
    let binding = EpochBinding::create(&w.log, &w.phone, mine.records()).unwrap();
    assert_eq!(binding.encode().len(), EPOCH_BINDING_LENGTH);
    assert_eq!(EpochBinding::decode(&binding.encode()).unwrap(), binding);
    binding.verify(&w.log, mine.records()).unwrap();

    // §15.4: a chain someone else published for this identity.
    let theirs = chain(2);
    assert_eq!(
        err(binding.verify(&w.log, theirs.records())),
        IdentityError::StaleBinding
    );
    // A prefix of the right chain is not the bound chain either.
    assert_eq!(
        err(binding.verify(&w.log, &mine.records()[..1])),
        IdentityError::StaleBinding
    );
}

#[test]
fn an_epoch_binding_needs_a_currently_trusted_signer() {
    let mut w = world();
    let mine = chain(1);
    assert_eq!(
        err(EpochBinding::create(&w.log, &key(0x70), mine.records())),
        IdentityError::Unauthorised(2)
    );
    let binding = EpochBinding::create(&w.log, &w.phone, mine.records()).unwrap();
    w.log
        .revoke(&w.laptop, device_id(&w.phone.verifying_key()))
        .unwrap();
    assert!(matches!(
        err(binding.verify(&w.log, mine.records())),
        IdentityError::Unauthorised(_)
    ));
    // The remaining device re-binds, over the head that includes the revoke.
    let again = EpochBinding::create(&w.log, &w.laptop, mine.records()).unwrap();
    again.verify(&w.log, mine.records()).unwrap();
}

#[test]
fn an_epoch_binding_for_an_unknown_head_or_other_identity_is_refused() {
    let w = world();
    let mine = chain(1);
    let mut binding = EpochBinding::create(&w.log, &w.phone, mine.records()).unwrap();
    let other = IdentityLog::create(&key(0x40), "other", &key(0x41).verifying_key()).unwrap();
    assert_eq!(
        err(binding.verify(&other, mine.records())),
        IdentityError::WrongIdentity
    );
    binding.identity_head = [0x55; 32];
    assert_eq!(
        err(binding.verify(&w.log, mine.records())),
        IdentityError::StaleBinding
    );
}

#[test]
fn every_byte_of_an_epoch_binding_is_load_bearing() {
    let w = world();
    let mine = chain(3);
    let bytes = EpochBinding::create(&w.log, &w.phone, mine.records())
        .unwrap()
        .encode();
    for at in [0, 32, 64, 96, 103, 104, 135, 136, EPOCH_BINDING_LENGTH - 1] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        let refused =
            EpochBinding::decode(&bad).map_or(true, |b| b.verify(&w.log, mine.records()).is_err());
        assert!(refused, "flip at {at} accepted");
    }
}

/// §16.4 recomputed from the formula.
#[test]
fn the_epoch_binding_bytes_match_the_spec() {
    let w = world();
    let mine = chain(2);
    let binding = EpochBinding::create(&w.log, &w.phone, mine.records()).unwrap();
    let signer = device_id(&w.phone.verifying_key());
    let mut message = Vec::new();
    message.extend_from_slice(&w.log.root());
    message.extend_from_slice(&w.log.head());
    message.extend_from_slice(&mine.head());
    message.extend_from_slice(&2u64.to_be_bytes());
    message.extend_from_slice(&signer);
    assert_eq!(&binding.encode()[..136], &message[..]);
    w.phone
        .verifying_key()
        .verify(b"HIDE/1.0 epoch binding", &message, &binding.signature)
        .expect("signature over the documented message");
}

/// §15.9: the root and head are links, which the framing does not touch, so a
/// legacy log and its re-encoding bind identically.
#[test]
fn bindings_are_framing_independent() {
    let w = world();
    let bytes = encode(w.log.entries()).unwrap();
    let entries = decode(&bytes).unwrap();
    let log = w.binding.verify_pinned(entries, &w.log.root()).unwrap();
    assert_eq!(log.head(), w.log.head());
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_ne!(
        digest,
        log.head(),
        "the head is a link, not a hash of the encoding"
    );
}
