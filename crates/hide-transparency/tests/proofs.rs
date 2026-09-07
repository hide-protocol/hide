//! Merkle proofs are easy to get subtly wrong in a way that only shows up at
//! one awkward tree shape, so these tests sweep every size and index in a range
//! rather than sampling a few. A proof system that works for 8 entries and
//! fails for 7 is worse than none.

use hide_transparency::{
    ConsistencyProof, InclusionProof, LogError, TransparencyLog, decode_checkpoint,
    encode_checkpoint, leaf_hash, verify_consistency, verify_inclusion,
};

fn log_of(n: u64) -> TransparencyLog {
    let mut log = TransparencyLog::new();
    for i in 0..n {
        log.append(format!("entry {i}").as_bytes());
    }
    log
}

fn entry(i: u64) -> Vec<u8> {
    format!("entry {i}").into_bytes()
}

#[test]
fn every_entry_proves_in_every_size() {
    // The sweep that catches shape-specific bugs.
    for size in 1..=33u64 {
        let log = log_of(size);
        let root = log.root();
        for index in 0..size {
            let proof = log.prove_inclusion(index, size).unwrap();
            verify_inclusion(&proof, &leaf_hash(&entry(index)), &root)
                .unwrap_or_else(|e| panic!("size {size} index {index}: {e}"));
        }
    }
}

#[test]
fn a_proof_for_the_wrong_entry_is_refused() {
    let log = log_of(16);
    let root = log.root();
    let proof = log.prove_inclusion(5, 16).unwrap();

    assert!(verify_inclusion(&proof, &leaf_hash(&entry(6)), &root).is_err());
    assert!(verify_inclusion(&proof, &leaf_hash(b"not in the log"), &root).is_err());
}

#[test]
fn a_proof_against_the_wrong_root_is_refused() {
    let log = log_of(16);
    let other = log_of(15);
    let proof = log.prove_inclusion(5, 16).unwrap();

    assert!(verify_inclusion(&proof, &leaf_hash(&entry(5)), &other.root()).is_err());
}

#[test]
fn a_tampered_path_is_refused() {
    let log = log_of(9);
    let root = log.root();
    for corrupt in 0..log.prove_inclusion(3, 9).unwrap().path.len() {
        let mut proof = log.prove_inclusion(3, 9).unwrap();
        proof.path[corrupt][0] ^= 1;
        assert!(
            verify_inclusion(&proof, &leaf_hash(&entry(3)), &root).is_err(),
            "a flipped bit at position {corrupt} was accepted"
        );
    }
}

#[test]
fn a_truncated_or_padded_path_is_refused() {
    let log = log_of(9);
    let root = log.root();
    let good = log.prove_inclusion(3, 9).unwrap();

    let mut short = good.clone();
    short.path.pop();
    assert!(verify_inclusion(&short, &leaf_hash(&entry(3)), &root).is_err());

    let mut long = good.clone();
    long.path.push([0u8; 32]);
    assert!(verify_inclusion(&long, &leaf_hash(&entry(3)), &root).is_err());
}

#[test]
fn an_absurdly_long_path_is_refused_before_hashing() {
    let proof = InclusionProof {
        index: 0,
        size: 1,
        path: vec![[0u8; 32]; 1000],
    };
    assert!(matches!(
        verify_inclusion(&proof, &[0u8; 32], &[0u8; 32]),
        Err(LogError::ProofTooLong(_))
    ));
}

#[test]
fn an_index_outside_the_size_is_refused() {
    let log = log_of(4);
    assert!(matches!(
        log.prove_inclusion(4, 4),
        Err(LogError::OutOfRange { .. })
    ));
    let proof = InclusionProof {
        index: 9,
        size: 4,
        path: vec![],
    };
    assert!(matches!(
        verify_inclusion(&proof, &[0u8; 32], &[0u8; 32]),
        Err(LogError::OutOfRange { .. })
    ));
}

/// The property the whole crate exists for: a published root can never be
/// reinterpreted later.
#[test]
fn every_prefix_is_provably_consistent() {
    for new_size in 1..=33u64 {
        let log = log_of(new_size);
        let new_root = log.root();
        for old_size in 1..=new_size {
            let old_root = log.root_at(old_size).unwrap();
            let proof = log.prove_consistency(old_size, new_size).unwrap();
            verify_consistency(&proof, &old_root, &new_root)
                .unwrap_or_else(|e| panic!("{old_size} -> {new_size}: {e}"));
        }
    }
}

/// A log that rewrites an already-published entry cannot produce a consistency
/// proof against the root it published before.
#[test]
fn a_rewritten_history_cannot_be_proved_consistent() {
    let honest = log_of(8);
    let published_root = honest.root_at(5).unwrap();

    // The operator quietly changes entry 2 and keeps appending.
    let mut forged = TransparencyLog::new();
    for i in 0..8u64 {
        if i == 2 {
            forged.append(b"substituted");
        } else {
            forged.append(&entry(i));
        }
    }

    let proof = forged.prove_consistency(5, 8).unwrap();
    assert!(
        verify_consistency(&proof, &published_root, &forged.root()).is_err(),
        "a rewritten log produced a consistency proof against the old root"
    );
}

#[test]
fn a_removed_entry_cannot_be_proved_consistent() {
    let honest = log_of(8);
    let published_root = honest.root_at(8).unwrap();

    let mut shortened = TransparencyLog::new();
    for i in 0..8u64 {
        if i == 6 {
            continue;
        }
        shortened.append(&entry(i));
    }
    shortened.append(b"replacement");

    let proof = shortened.prove_consistency(8, 8).unwrap();
    assert!(verify_consistency(&proof, &published_root, &shortened.root()).is_err());
}

#[test]
fn a_consistency_proof_between_the_wrong_roots_is_refused() {
    let log = log_of(16);
    let other = log_of(16);
    let proof = log.prove_consistency(5, 16).unwrap();

    // Same shape, but `other` has different leaves only if we make them differ.
    let mut different = TransparencyLog::new();
    for i in 0..16u64 {
        different.append(format!("other {i}").as_bytes());
    }
    let _ = other;

    assert!(verify_consistency(&proof, &different.root_at(5).unwrap(), &different.root()).is_err());
}

#[test]
fn a_tampered_consistency_path_is_refused() {
    let log = log_of(13);
    let old_root = log.root_at(6).unwrap();
    let new_root = log.root();
    let good = log.prove_consistency(6, 13).unwrap();

    for corrupt in 0..good.path.len() {
        let mut proof = good.clone();
        proof.path[corrupt][0] ^= 1;
        assert!(
            verify_consistency(&proof, &old_root, &new_root).is_err(),
            "a flipped bit at position {corrupt} was accepted"
        );
    }
}

#[test]
fn a_consistency_proof_with_extra_hashes_is_refused() {
    let log = log_of(13);
    let old_root = log.root_at(6).unwrap();
    let new_root = log.root();
    let mut proof = log.prove_consistency(6, 13).unwrap();
    proof.path.push([0u8; 32]);
    assert!(verify_consistency(&proof, &old_root, &new_root).is_err());
}

#[test]
fn growing_backwards_is_refused() {
    let log = log_of(8);
    assert!(matches!(
        log.prove_consistency(8, 4),
        Err(LogError::NotAPrefix { .. })
    ));
    let proof = ConsistencyProof {
        old_size: 8,
        new_size: 4,
        path: vec![],
    };
    assert!(matches!(
        verify_consistency(&proof, &[0u8; 32], &[0u8; 32]),
        Err(LogError::NotAPrefix { .. })
    ));
}

#[test]
fn a_log_is_consistent_with_itself() {
    let log = log_of(7);
    let root = log.root();
    let proof = log.prove_consistency(7, 7).unwrap();
    verify_consistency(&proof, &root, &root).unwrap();
}

#[test]
fn the_root_changes_with_every_append() {
    let mut log = TransparencyLog::new();
    let mut seen = vec![log.root()];
    for i in 0..12u64 {
        log.append(&entry(i));
        let root = log.root();
        assert!(
            !seen.contains(&root),
            "root repeated after {} appends",
            i + 1
        );
        seen.push(root);
    }
}

/// RFC 6962's prefixes exist to stop a leaf being reinterpreted as an interior
/// node. Without them an attacker could present two entries as one subtree.
#[test]
fn a_leaf_cannot_be_confused_with_a_node() {
    let a = leaf_hash(b"a");
    let b = leaf_hash(b"b");

    let mut two = TransparencyLog::new();
    two.append(b"a");
    two.append(b"b");

    // The root over two leaves must not equal the hash of their concatenation
    // treated as a leaf, which is what an unprefixed tree would allow.
    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&a);
    concatenated.extend_from_slice(&b);
    assert_ne!(two.root(), leaf_hash(&concatenated));
}

#[test]
fn an_empty_log_has_a_defined_root() {
    let log = TransparencyLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    // Defined, and different from any single-entry log.
    let mut one = TransparencyLog::new();
    one.append(b"");
    assert_ne!(log.root(), one.root());
}

#[test]
fn root_at_matches_a_log_built_to_that_size() {
    for size in 0..=20u64 {
        let big = log_of(20);
        let small = log_of(size);
        assert_eq!(big.root_at(size).unwrap(), small.root(), "size {size}");
    }
}

#[test]
fn root_at_beyond_the_log_is_refused() {
    let log = log_of(3);
    assert!(matches!(log.root_at(4), Err(LogError::OutOfRange { .. })));
}

#[test]
fn a_checkpoint_round_trips() {
    let log = log_of(9);
    let encoded = encode_checkpoint(log.len(), &log.root());
    let (size, root) = decode_checkpoint(&encoded).unwrap();
    assert_eq!(size, 9);
    assert_eq!(root, log.root());
}

#[test]
fn a_malformed_checkpoint_is_refused() {
    assert_eq!(decode_checkpoint(&[]).unwrap_err(), LogError::Malformed);
    assert_eq!(
        decode_checkpoint(&[0u8; 39]).unwrap_err(),
        LogError::Malformed
    );
    assert_eq!(
        decode_checkpoint(&[0u8; 41]).unwrap_err(),
        LogError::Malformed
    );
}

/// A checkpoint binds a size to a root: the same root under a different claimed
/// size must not be mistaken for the same commitment.
#[test]
fn a_checkpoint_binds_the_size() {
    let log = log_of(9);
    let a = encode_checkpoint(9, &log.root());
    let b = encode_checkpoint(10, &log.root());
    assert_ne!(a, b);
}
