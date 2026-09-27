#![no_main]
//! An identity log arrives from an untrusted directory. Decoding must never
//! panic, must reject non-canonical bytes, and a log that decodes must verify
//! against SOME recovery key or be rejected — never crash on the way.

use hide_identity::{IdentityLog, decode, encode};
use hide_sign::VerifyingIdentity;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static RECOVERY: LazyLock<VerifyingIdentity> = LazyLock::new(|| {
    hide_sign::SigningIdentity::from_bytes(&[3u8; 32])
        .expect("32 bytes is a seed")
        .verifying_key()
});

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = decode(data) {
        // `encode` always writes the current framing; a legacy (0.6-0.8) input
        // differs from it only in each entry's array header, 0x86 for 0x87.
        // Anything else is a second encoding of the same history.
        let reencoded = encode(&entries).unwrap();
        assert_eq!(reencoded.len(), data.len(), "non-canonical log accepted");
        let mut differing = 0usize;
        for (&ours, &theirs) in reencoded.iter().zip(data) {
            if ours != theirs {
                assert!(ours == 0x87 && theirs == 0x86, "non-canonical log accepted");
                differing += 1;
            }
        }
        assert!(
            differing == 0 || differing == entries.len(),
            "a log mixing framings was accepted"
        );
        let _ = IdentityLog::verify(&entries, &RECOVERY);
    }
});
