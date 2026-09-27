#![no_main]
//! Signed checkpoint notes and encoded proofs come from a log operator or a
//! witness the client does not trust (spec §16.2, §16.3). Neither parser may
//! panic, and each accepts only its canonical encoding.

use hide_sign::SigningIdentity;
use hide_transparency::{Checkpoint, ConsistencyProof, InclusionProof, SignedNote};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn log_key() -> &'static SigningIdentity {
    static KEY: OnceLock<SigningIdentity> = OnceLock::new();
    KEY.get_or_init(|| SigningIdentity::from_bytes(&[0x70; 32]).expect("seed"))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(note) = SignedNote::decode(data) {
        assert_eq!(note.encode().as_bytes(), data, "non-canonical note accepted");
    }
    let _ = Checkpoint::verify(data, "log.example/hide", &log_key().verifying_key());

    if let Ok(proof) = InclusionProof::decode(data) {
        assert_eq!(proof.encode().as_deref().ok(), Some(data), "non-canonical inclusion proof");
    }
    if let Ok(proof) = ConsistencyProof::decode(data) {
        assert_eq!(proof.encode().as_deref().ok(), Some(data), "non-canonical consistency proof");
    }
});
