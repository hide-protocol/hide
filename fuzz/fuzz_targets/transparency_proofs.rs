#![no_main]
//! Proofs and checkpoints come from a log operator the client does not trust.
//! The verifier must bound the path length before doing work, must never panic
//! on a crafted (index, size, path) triple, and a checkpoint must be canonical.

use hide_transparency::{
    ConsistencyProof, Hash, InclusionProof, decode_checkpoint, encode_checkpoint,
    verify_consistency, verify_inclusion,
};
use libfuzzer_sys::fuzz_target;

fn hashes(bytes: &[u8]) -> Vec<Hash> {
    bytes.chunks_exact(32).map(|c| c.try_into().unwrap()).collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 + 64 {
        return;
    }
    let (head, rest) = data.split_at(16);
    let a = u64::from_le_bytes(head[..8].try_into().unwrap());
    let b = u64::from_le_bytes(head[8..].try_into().unwrap());
    let (roots, path) = rest.split_at(64);
    let root_a: Hash = roots[..32].try_into().unwrap();
    let root_b: Hash = roots[32..].try_into().unwrap();
    let path = hashes(path);

    let inclusion = InclusionProof {
        index: a,
        size: b,
        path: path.clone(),
    };
    let _ = verify_inclusion(&inclusion, &root_a, &root_b);

    let consistency = ConsistencyProof {
        old_size: a,
        new_size: b,
        path,
    };
    let _ = verify_consistency(&consistency, &root_a, &root_b);

    if let Ok((size, root)) = decode_checkpoint(data) {
        assert_eq!(encode_checkpoint(size, &root), data, "non-canonical checkpoint accepted");
    }
});
