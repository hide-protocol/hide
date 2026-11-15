//! Properties a log-proof, checkpoint and signed-note decoder must hold
//! (spec §16.2, §16.3).
//!
//! `fuzz/fuzz_targets/transparency_proofs.rs` and `checkpoint_note.rs` explore
//! the same surface; this suite pins the statements. Every input here comes from
//! a log operator or a witness the client does not trust, which is why the
//! declared path length — one byte the sender chooses — gets its own properties:
//! a declaration larger than the input must be refused, and the decoder must
//! never allocate or loop for hashes the input cannot hold.

use hide_sign::SigningIdentity;
use hide_transparency::{
    Checkpoint, ConsistencyProof, Hash, InclusionProof, MAX_NOTE_BYTES, SignedNote,
    TransparencyLog, decode_checkpoint, encode_checkpoint, leaf_hash, verify_consistency,
    verify_inclusion,
};
use proptest::prelude::*;
use std::sync::LazyLock;

/// `tag(1) || u64be || u64be || count(1)`, then 32 bytes per hash (§16.3).
const PROOF_HEADER: usize = 18;
/// The crate's own `MAX_PROOF_LEN`, which is private: a path longer than this is
/// refused before anything is read for it.
const MAX_PROOF_LEN: usize = 64;
/// Entries in the real log every proof property is checked against.
const LOG_ENTRIES: u32 = 17;

const ORIGIN: &str = "log.example/hide";

/// A real log, built once. Appending is cheap; what the properties need is a log
/// whose proofs actually verify against its own roots.
static LOG: LazyLock<TransparencyLog> = LazyLock::new(|| {
    let mut log = TransparencyLog::new();
    for entry in 0..LOG_ENTRIES {
        log.append(&entry.to_be_bytes());
    }
    log
});

/// The log key a checkpoint is arbitrarily assumed to be signed by. Key
/// generation is the expensive part, so it happens once.
static LOG_KEY: LazyLock<SigningIdentity> =
    LazyLock::new(|| SigningIdentity::from_bytes(&[0x70; 32]).expect("32 bytes is a seed"));

/// The leaf hash of entry `index`, recomputed the way the log hashed it.
fn leaf(index: u32) -> Hash {
    leaf_hash(&index.to_be_bytes())
}

/// A proof header declaring `count` hashes, followed by exactly `body` bytes.
/// The two are deliberately allowed to disagree: that is the attack.
fn proof_with_declared_path(tag: u8, count: u8, body: usize) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.push(count);
    bytes.resize(PROOF_HEADER + body, 0);
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Proofs, checkpoints and notes come from an operator the client does not
    /// trust. Whatever the bytes, decoding and verifying must return Ok or Err
    /// and never panic.
    #[test]
    fn arbitrary_bytes_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..8192),
        claimed_leaf in any::<[u8; 32]>(),
        root_a in any::<[u8; 32]>(),
        root_b in any::<[u8; 32]>(),
    ) {
        if let Ok(proof) = InclusionProof::decode(&bytes) {
            let _ = verify_inclusion(&proof, &claimed_leaf, &root_a);
        }
        if let Ok(proof) = ConsistencyProof::decode(&bytes) {
            let _ = verify_consistency(&proof, &root_a, &root_b);
        }
        let _ = SignedNote::decode(&bytes);
        let _ = Checkpoint::verify(&bytes, ORIGIN, &LOG_KEY.verifying_key());
        let _ = decode_checkpoint(&bytes);
    }

    /// One proof, one encoding. These layouts are fixed, so an accepted input is
    /// exactly the bytes the encoder writes — asserted per decoder, because a
    /// second encoding of one proof lets two verifiers disagree about what a log
    /// operator published.
    #[test]
    fn decoded_proofs_and_notes_re_encode_to_the_same_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..8192)
    ) {
        if let Ok(proof) = InclusionProof::decode(&bytes) {
            prop_assert_eq!(proof.encode()?, bytes.clone());
        }
        if let Ok(proof) = ConsistencyProof::decode(&bytes) {
            prop_assert_eq!(proof.encode()?, bytes.clone());
        }
        if let Ok(note) = SignedNote::decode(&bytes) {
            let encoded = note.encode();
            prop_assert_eq!(encoded.as_bytes(), bytes.as_slice());
        }
        if let Ok((size, root)) = decode_checkpoint(&bytes) {
            prop_assert_eq!(encode_checkpoint(size, &root), bytes);
        }
    }

    /// A proof that was cut short, or that carries bytes after its last hash, is
    /// neither a shorter nor a longer proof: the declared count and the actual
    /// length are checked against each other, so both are refused.
    #[test]
    fn truncation_and_trailing_bytes_are_refused(
        index in any::<u64>(),
        size in any::<u64>(),
        path in prop::collection::vec(any::<[u8; 32]>(), 0..=MAX_PROOF_LEN),
        cut in any::<prop::sample::Index>(),
        suffix in prop::collection::vec(any::<u8>(), 1..8),
    ) {
        let inclusion = InclusionProof { index, size, path: path.clone() };
        let encoded = inclusion.encode()?;
        let position = cut.index(encoded.len());
        prop_assert!(
            InclusionProof::decode(&encoded[..position]).is_err(),
            "accepted a {position} byte prefix of an inclusion proof"
        );
        let mut extended = encoded.clone();
        extended.extend_from_slice(&suffix);
        prop_assert!(InclusionProof::decode(&extended).is_err());

        let consistency = ConsistencyProof { old_size: index, new_size: size, path };
        let encoded = consistency.encode()?;
        let position = cut.index(encoded.len());
        prop_assert!(ConsistencyProof::decode(&encoded[..position]).is_err());
        let mut extended = encoded.clone();
        extended.extend_from_slice(&suffix);
        prop_assert!(ConsistencyProof::decode(&extended).is_err());
    }

    /// A path length is one byte the sender chooses. A declaration that outruns
    /// the bytes actually present must be refused — never allocated or looped
    /// for — however few bytes the input holds.
    #[test]
    fn a_declared_path_length_beyond_the_input_is_refused(
        count in 1u8..=MAX_PROOF_LEN as u8,
        shortfall in 1usize..=(MAX_PROOF_LEN * 32),
    ) {
        let body = (usize::from(count) * 32).saturating_sub(shortfall);
        let short = proof_with_declared_path(0x01, count, body);
        prop_assert!(
            InclusionProof::decode(&short).is_err(),
            "accepted a path of {count} hashes from {body} bytes"
        );
        prop_assert!(ConsistencyProof::decode(&proof_with_declared_path(0x02, count, body)).is_err());
    }

    /// ...and the other half of the same statement: when the declaration does
    /// fit, exactly that many hashes come back and the input re-encodes to
    /// itself. Nothing is read that the input does not contain.
    #[test]
    fn an_exact_path_length_decodes_to_that_many_hashes(
        count in 0u8..=MAX_PROOF_LEN as u8,
        consistency in any::<bool>(),
    ) {
        let body = usize::from(count) * 32;
        if consistency {
            let bytes = proof_with_declared_path(0x02, count, body);
            let proof = ConsistencyProof::decode(&bytes)?;
            prop_assert_eq!(proof.path.len(), usize::from(count));
            prop_assert_eq!(proof.encode()?, bytes);
        } else {
            let bytes = proof_with_declared_path(0x01, count, body);
            let proof = InclusionProof::decode(&bytes)?;
            prop_assert_eq!(proof.path.len(), usize::from(count));
            prop_assert_eq!(proof.encode()?, bytes);
        }
    }

    /// A declared path above the limit is refused whatever the input length is:
    /// the limit is applied before the body is read, so no proof can make a
    /// client work for a path it will never accept.
    #[test]
    fn a_declared_path_length_above_the_limit_is_refused(
        count in (MAX_PROOF_LEN as u8 + 1)..=u8::MAX,
        body in 0usize..(MAX_PROOF_LEN * 32),
    ) {
        prop_assert!(InclusionProof::decode(&proof_with_declared_path(0x01, count, body)).is_err());
        prop_assert!(ConsistencyProof::decode(&proof_with_declared_path(0x02, count, body)).is_err());
    }

    /// A note larger than the format allows is refused before it is read: the
    /// limit exists so that a log operator cannot make a client parse a
    /// gigabyte of text to find one signature line.
    #[test]
    fn an_oversized_note_is_refused_without_being_read(extra in 1usize..1024) {
        let bytes = vec![b'a'; MAX_NOTE_BYTES + extra];
        prop_assert!(SignedNote::decode(&bytes).is_err());
        prop_assert!(Checkpoint::verify(&bytes, ORIGIN, &LOG_KEY.verifying_key()).is_err());
    }

    /// The real thing: proofs of a log this crate built. They verify against the
    /// log's own roots, they are refused against another root or another leaf —
    /// which is the whole point of an audit path — and a single damaged byte
    /// leaves a proof that either fails to decode or fails to verify.
    #[test]
    fn real_inclusion_proofs_verify(index in 0u64..LOG_ENTRIES as u64, size in 1u64..=LOG_ENTRIES as u64, byte in any::<prop::sample::Index>(), delta in 1u8..=255) {
        prop_assume!(index < size);
        let proof = LOG.prove_inclusion(index, size)?;
        let root = LOG.root_at(size)?;
        prop_assert!(verify_inclusion(&proof, &leaf(index as u32), &root).is_ok());
        // A different entry, or a different root, must not accept this path.
        prop_assert!(verify_inclusion(&proof, &leaf(index as u32 + 1), &root).is_err());
        prop_assert!(verify_inclusion(&proof, &leaf(index as u32), &[0u8; 32]).is_err());

        let encoded = proof.encode()?;
        prop_assert_eq!(InclusionProof::decode(&encoded)?.encode()?, encoded.clone());
        let mut damaged = encoded.clone();
        let position = byte.index(damaged.len());
        damaged[position] = damaged[position].wrapping_add(delta);
        if let Ok(reparsed) = InclusionProof::decode(&damaged) {
            prop_assert_ne!(&reparsed, &proof);
            prop_assert!(
                verify_inclusion(&reparsed, &leaf(index as u32), &root).is_err(),
                "a proof damaged at byte {position} still verified"
            );
        }
    }

    /// The consistency proof is the one that catches a rewritten history, so it
    /// gets the same treatment against the same log.
    #[test]
    fn real_consistency_proofs_verify(old_size in 1u64..=LOG_ENTRIES as u64, new_size in 1u64..=LOG_ENTRIES as u64, byte in any::<prop::sample::Index>(), delta in 1u8..=255) {
        prop_assume!(old_size <= new_size);
        let proof = LOG.prove_consistency(old_size, new_size)?;
        let old_root = LOG.root_at(old_size)?;
        let new_root = LOG.root_at(new_size)?;
        prop_assert!(verify_consistency(&proof, &old_root, &new_root).is_ok());
        // Two different sizes must have two different roots, or the proof
        // proves nothing; and a proof must not carry over to another history.
        if old_size < new_size {
            prop_assert_ne!(old_root, new_root);
            prop_assert!(verify_consistency(&proof, &new_root, &old_root).is_err());
            prop_assert!(verify_consistency(&proof, &[0u8; 32], &new_root).is_err());
        }

        let encoded = proof.encode()?;
        prop_assert_eq!(ConsistencyProof::decode(&encoded)?.encode()?, encoded.clone());
        let mut damaged = encoded.clone();
        let position = byte.index(damaged.len());
        damaged[position] = damaged[position].wrapping_add(delta);
        if let Ok(reparsed) = ConsistencyProof::decode(&damaged) {
            prop_assert_ne!(&reparsed, &proof);
            prop_assert!(
                verify_consistency(&reparsed, &old_root, &new_root).is_err(),
                "a proof damaged at byte {position} still verified"
            );
        }
    }
}
