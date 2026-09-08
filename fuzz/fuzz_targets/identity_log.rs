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
        assert_eq!(encode(&entries).unwrap(), data, "non-canonical log accepted");
        let _ = IdentityLog::verify(&entries, &RECOVERY);
    }
});
