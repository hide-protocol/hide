#![no_main]
//! The verifiers a relying party runs on artifacts it did not write.
//!
//! These are the bodies behind the C ABI's `hide_identity_verify_pinned`,
//! `hide_epoch_verify_bound`, `hide_checkpoint_verify`,
//! `hide_transparency_verify_inclusion` and `hide_transparency_verify_consistency`:
//! a log with its recovery binding, an epoch chain, a signed checkpoint note, an
//! RFC 6962 inclusion proof and a consistency proof. Each arrives over the
//! network, so each is untrusted bytes, and each must terminate and refuse
//! rather than index, allocate or loop without a bound.

use std::sync::OnceLock;

use hide_sign::{SigningIdentity, VerifyingIdentity};
use hide_transparency::{
    Checkpoint, ConsistencyProof, InclusionProof, verify_consistency, verify_inclusion,
};
use libfuzzer_sys::fuzz_target;

/// A log key that only ever has to exist; nothing in this target can produce a
/// signature that verifies under it.
fn log_key() -> &'static VerifyingIdentity {
    static KEY: OnceLock<VerifyingIdentity> = OnceLock::new();
    KEY.get_or_init(|| {
        SigningIdentity::from_bytes(&[0x6b; 32])
            .expect("a fixed seed")
            .verifying_key()
    })
}

fuzz_target!(|data: &[u8]| {
    // Three views of one input, so the corpus feeds every verifier without the
    // target having to guess a layout.
    let (head, rest) = data.split_at(data.len().min(32));
    let (middle, tail) = rest.split_at(rest.len() / 2);

    let mut pinned_root = [0_u8; 32];
    for (slot, byte) in pinned_root.iter_mut().zip(head) {
        *slot = *byte;
    }

    // §16.1: the log through its recovery binding, under the root the relying
    // party trusts. A wrong or absent binding must not produce a log.
    if let Ok(binding) = hide_identity::RecoveryBinding::decode(tail) {
        if let Ok(entries) = hide_identity::decode(middle) {
            let _ = binding.verify_pinned(entries, &pinned_root);
        }
        if let Ok(entries) = hide_identity::decode(middle) {
            let _ = binding.verify(entries);
        }
    }

    // §11: the chain decoder and its hash linkage.
    if let Ok(records) = hide_epoch::decode_records(middle) {
        let _ = hide_epoch::EpochChain::verify(&records);
    }

    // §12: the structured proofs, and the checks that use only a root.
    if let Ok(proof) = InclusionProof::decode(middle) {
        let _ = verify_inclusion(&proof, &pinned_root, &pinned_root);
    }
    if let Ok(proof) = ConsistencyProof::decode(middle) {
        let _ = verify_consistency(&proof, &pinned_root, &pinned_root);
    }

    // §16.2: the signed checkpoint note, which a log or a witness hands out.
    let _ = Checkpoint::verify(tail, "fuzz.invalid", log_key());
});
