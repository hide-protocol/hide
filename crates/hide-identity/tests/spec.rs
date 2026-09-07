//! Checks `spec/hide-0.1.md` §8 against the implementation by recomputing the
//! documented values here from the formula alone.
//!
//! A specification nobody executes drifts silently, and a wrong spec is worse
//! than none: it is trusted by whoever writes the second implementation. Three
//! errors in this section were caught by writing these tests.

use hide_identity::IdentityLog;
use hide_sign::SigningIdentity;
use sha2::{Digest, Sha256};

/// §8: `SHA-256("HIDE/0.6 device id" || verifying_key)`, all 32 bytes.
#[test]
fn the_device_id_matches_the_spec() {
    let key = SigningIdentity::generate().unwrap().verifying_key();

    let mut hasher = Sha256::new();
    hasher.update(b"HIDE/0.6 device id");
    hasher.update(key.to_bytes());
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(hide_identity::device_id(&key), expected);
}

/// §8: the link covers the length-prefixed signed bytes and signature, under
/// its own label — distinct from the label the signature itself uses.
#[test]
fn the_entry_link_matches_the_spec() {
    let laptop = SigningIdentity::generate().unwrap();
    let recovery = SigningIdentity::generate().unwrap();
    let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    let phone = SigningIdentity::generate().unwrap();
    log.enrol(&laptop, &phone.verifying_key(), "phone").unwrap();

    // Checked for both entries, so the `previous` chaining is covered too.
    let mut previous = [0u8; 32];
    for entry in log.entries() {
        let signed = entry.signed_bytes(&previous);

        let mut hasher = Sha256::new();
        hasher.update(b"HIDE/0.6 identity link");
        hasher.update((signed.len() as u64).to_be_bytes());
        hasher.update(&signed);
        hasher.update((entry.signature.len() as u64).to_be_bytes());
        hasher.update(&entry.signature);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            entry.link, expected,
            "entry {}: the implementation and spec §8 disagree about the link",
            entry.sequence
        );
        previous = entry.link;
    }
}

/// §8: the signature is over `signed` with the entry context label.
#[test]
fn the_entry_signature_context_matches_the_spec() {
    let laptop = SigningIdentity::generate().unwrap();
    let recovery = SigningIdentity::generate().unwrap();
    let log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    let entry = &log.entries()[0];

    let signed = entry.signed_bytes(&[0u8; 32]);
    let signature: [u8; hide_sign::SIGNATURE_LENGTH] = entry
        .signature
        .as_slice()
        .try_into()
        .expect("a signature is fixed width");

    laptop
        .verifying_key()
        .verify(b"HIDE/0.6 identity entry", &signed, &signature)
        .expect("the spec's context label and signed layout must verify");
}

/// §8 claims `previous` is inside the signed bytes, which is what stops an
/// entry being transplanted. Assert it literally rather than trusting the prose.
#[test]
fn the_predecessor_is_inside_the_signed_bytes() {
    let laptop = SigningIdentity::generate().unwrap();
    let recovery = SigningIdentity::generate().unwrap();
    let log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    let entry = &log.entries()[0];

    let with_zero = entry.signed_bytes(&[0u8; 32]);
    let with_other = entry.signed_bytes(&[1u8; 32]);

    assert_ne!(
        with_zero, with_other,
        "changing the predecessor did not change the signed bytes"
    );
    assert_eq!(&with_zero[..32], &[0u8; 32], "§8 places previous first");
}
