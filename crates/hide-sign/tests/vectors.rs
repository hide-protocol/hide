//! The frozen vectors are protocol artifacts: regenerating them is a format
//! change, so this suite fails rather than silently accepting new bytes.

use hide_sign::{SIGNATURE_LENGTH, SigningIdentity, VerifyingIdentity};

const CONTEXT: &[u8] = b"HIDE/0.5 vector";

fn vector(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/vectors");
    std::fs::read(format!("{path}/{name}")).expect("vectors are committed")
}

#[test]
fn the_frozen_seed_still_derives_the_frozen_public_key() {
    let signing = SigningIdentity::from_bytes(&vector("signer.test-seed")).expect("valid seed");
    assert_eq!(
        signing.verifying_key().to_bytes()[..],
        vector("signer.test-public")[..],
        "key derivation changed: regenerate vectors only as a deliberate protocol change"
    );
}

#[test]
fn the_frozen_signatures_verify_and_reproduce_exactly() {
    let signing = SigningIdentity::from_bytes(&vector("signer.test-seed")).expect("valid seed");
    let verifying =
        VerifyingIdentity::from_bytes(&vector("signer.test-public")).expect("valid key");

    for (name, message) in [
        ("hello", b"Hello HIDE\n".as_slice()),
        ("empty", b"".as_slice()),
    ] {
        let frozen = vector(&format!("{name}.sig"));
        assert_eq!(frozen.len(), SIGNATURE_LENGTH);
        verifying
            .verify(CONTEXT, message, &frozen)
            .unwrap_or_else(|_| panic!("frozen signature {name}.sig no longer verifies"));
        // Signing is deterministic, so the bytes must reproduce. If this fails
        // but verification passed, the scheme became randomised.
        assert_eq!(
            signing.sign(CONTEXT, message)[..],
            frozen[..],
            "signing is no longer deterministic for {name}"
        );
    }
}

#[test]
fn a_frozen_signature_is_rejected_under_a_different_context() {
    let verifying =
        VerifyingIdentity::from_bytes(&vector("signer.test-public")).expect("valid key");
    assert!(
        verifying
            .verify(b"HIDE/0.5 other", b"Hello HIDE\n", &vector("hello.sig"))
            .is_err()
    );
}
