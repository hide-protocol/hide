#![no_main]
//! Recovery and epoch bindings arrive beside an identity log from the same
//! untrusted source (spec §16.1, §16.4). Decoding is fixed-length, so every
//! accepted input must re-encode to itself, and verifying against a real log
//! must never panic whatever the bytes claim.

use hide_identity::{EpochBinding, IdentityLog, RecoveryBinding};
use hide_sign::SigningIdentity;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn log() -> &'static IdentityLog {
    static LOG: OnceLock<IdentityLog> = OnceLock::new();
    LOG.get_or_init(|| {
        let founder = SigningIdentity::from_bytes(&[0x61; 32]).expect("seed");
        let recovery = SigningIdentity::from_bytes(&[0x63; 32]).expect("seed");
        IdentityLog::create(&founder, "founder", &recovery.verifying_key()).expect("log")
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(binding) = RecoveryBinding::decode(data) {
        assert_eq!(binding.encode(), data, "non-canonical recovery binding");
        let _ = binding.verify(log().entries().to_vec());
    }
    if let Ok(binding) = EpochBinding::decode(data) {
        assert_eq!(binding.encode(), data, "non-canonical epoch binding");
        let _ = binding.verify(log(), &[]);
    }
});
