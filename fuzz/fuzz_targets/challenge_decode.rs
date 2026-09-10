#![no_main]
//! A challenge travels from the verifier to the prover and back as bytes, and
//! the answer arrives from a party that has not yet proved anything. Decoding
//! must never panic, must be canonical (one wire form per challenge, so a
//! prover cannot answer a re-encoded twin), and the replay guard must reject a
//! garbage signature rather than crash on it.

use hide_sign::{Challenge, SigningIdentity, SpentNonces, VerifyingIdentity};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

// A fixed, public test key. Deriving ML-DSA keys is too slow to repeat per
// input, and the target needs a verifier without any private material in
// the loop: the fuzzer supplies the "signature", the key only checks it.
static PROVER: LazyLock<VerifyingIdentity> = LazyLock::new(|| {
    SigningIdentity::from_bytes(&[0x42; hide_sign::SEED_LENGTH])
        .expect("seed length is fixed")
        .verifying_key()
});

fuzz_target!(|data: &[u8]| {
    let Ok(challenge) = Challenge::decode(data) else {
        return;
    };
    assert_eq!(challenge.encode(), data, "non-canonical challenge accepted");

    // Feed the same bytes back as the answer: wrong length or wrong content,
    // the verifier must return an error, never panic, and must not spend the
    // nonce for an answer it did not accept.
    let mut spent = SpentNonces::new();
    let now = challenge.expires_at();
    let _ = spent.accept(&challenge, data, &PROVER, now);
    assert!(spent.is_empty(), "unverified answer spent a nonce");
    let _ = spent.accept(&challenge, data, &PROVER, now.saturating_add(1));
});
