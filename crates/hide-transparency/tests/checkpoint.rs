//! Spec §16.2 (signed checkpoints) and §16.3 (leaves and proof encoding).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hide_sign::SigningIdentity;
use hide_transparency::{
    CHECKPOINT_CONTEXT, Checkpoint, ConsistencyProof, InclusionProof, LogError, SignedNote,
    TransparencyLog, epoch_leaf, identity_leaf, key_id, leaf_hash, verify_consistency,
    verify_inclusion,
};
use sha2::{Digest, Sha256};

const ORIGIN: &str = "log.example/hide";

fn key(byte: u8) -> SigningIdentity {
    SigningIdentity::from_bytes(&[byte; 32]).expect("seed")
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        origin: ORIGIN.into(),
        size: 5,
        root: [0xab; 32],
    }
}

#[test]
fn a_signed_checkpoint_round_trips_and_verifies() {
    let log = key(1);
    let note = checkpoint().sign(&log).unwrap().encode();
    assert!(note.starts_with("log.example/hide\n5\nq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=\n\n\u{2014} log.example/hide "));
    let verified = Checkpoint::verify(note.as_bytes(), ORIGIN, &log.verifying_key()).unwrap();
    assert_eq!(verified, checkpoint());
}

/// §15.3: an unsigned 40-byte checkpoint said nothing about who published it.
#[test]
fn another_key_or_origin_is_refused() {
    let note = checkpoint().sign(&key(1)).unwrap().encode();
    assert_eq!(
        Checkpoint::verify(note.as_bytes(), ORIGIN, &key(2).verifying_key()),
        Err(LogError::Unsigned)
    );
    assert!(matches!(
        Checkpoint::verify(
            note.as_bytes(),
            "other.example/log",
            &key(1).verifying_key()
        ),
        Err(LogError::WrongOrigin { .. })
    ));
}

#[test]
fn a_changed_size_or_root_breaks_the_signature() {
    let log = key(1);
    let note = checkpoint().sign(&log).unwrap().encode();
    for (from, to) in [("\n5\n", "\n6\n"), ("q6ur", "q6us")] {
        let bad = note.replacen(from, to, 1);
        assert_eq!(
            Checkpoint::verify(bad.as_bytes(), ORIGIN, &log.verifying_key()),
            Err(LogError::BadSignature),
            "{from} -> {to}"
        );
    }
}

#[test]
fn non_canonical_notes_are_malformed() {
    let log = key(1);
    let good = checkpoint().sign(&log).unwrap();
    let text = good.encode();
    let mut cases = vec![
        text.replacen("\n5\n", "\n05\n", 1),
        text.replacen("\n5\n", "\n+5\n", 1),
        text.replacen("\n\n", "\nextension\n\n", 1),
        text.trim_end_matches('\n').to_owned(),
        text.replacen("\u{2014} ", "- ", 1),
        text.replacen("\n", "\r\n", 1),
        format!("{text}\u{2014} {ORIGIN} AAAA\n"),
    ];
    cases.push(String::from_utf8_lossy(&[b'x'; 200_000]).into_owned());
    for bad in cases {
        let result = Checkpoint::verify(bad.as_bytes(), ORIGIN, &log.verifying_key());
        assert!(
            matches!(
                result,
                Err(LogError::Malformed) | Err(LogError::BadSignature)
            ),
            "accepted {:?}: {result:?}",
            &bad[..bad.len().min(40)]
        );
    }
    assert_eq!(SignedNote::decode(&[0xff, 0xfe]), Err(LogError::Malformed));
}

/// signed-note: signatures from unknown keys are ignored, so a note carrying a
/// stranger's line still verifies for the log.
#[test]
fn unknown_signature_lines_are_ignored() {
    let log = key(1);
    let mut note = checkpoint().sign(&log).unwrap();
    Checkpoint::cosign(&mut note, "stranger.example/w", &key(9)).unwrap();
    note.signatures.push(hide_transparency::NoteSignature {
        name: "ed25519.example/w".into(),
        key_id: [1, 2, 3, 4],
        signature: vec![0; 64],
    });
    Checkpoint::verify(note.encode().as_bytes(), ORIGIN, &log.verifying_key()).unwrap();
}

#[test]
fn a_witness_threshold_counts_distinct_valid_cosigners() {
    let log = key(1);
    let (w1, w2) = (key(11), key(12));
    let (v1, v2) = (w1.verifying_key(), w2.verifying_key());
    let mut note = checkpoint().sign(&log).unwrap();
    Checkpoint::cosign(&mut note, "w1.example", &w1).unwrap();
    let bytes = note.encode();
    let witnesses = [("w1.example", &v1), ("w2.example", &v2)];
    Checkpoint::verify_witnessed(
        bytes.as_bytes(),
        ORIGIN,
        &log.verifying_key(),
        &witnesses,
        1,
    )
    .unwrap();
    assert_eq!(
        Checkpoint::verify_witnessed(
            bytes.as_bytes(),
            ORIGIN,
            &log.verifying_key(),
            &witnesses,
            2
        ),
        Err(LogError::Unsigned)
    );
    // The same witness listed twice does not satisfy a threshold of two.
    let twice = [("w1.example", &v1), ("w1.example", &v1)];
    assert_eq!(
        Checkpoint::verify_witnessed(bytes.as_bytes(), ORIGIN, &log.verifying_key(), &twice, 2),
        Err(LogError::Unsigned)
    );
    // Nor does the log vouching for itself.
    let log_key = log.verifying_key();
    let itself = [(ORIGIN, &log_key)];
    assert_eq!(
        Checkpoint::verify_witnessed(bytes.as_bytes(), ORIGIN, &log.verifying_key(), &itself, 1),
        Err(LogError::Unsigned)
    );
    Checkpoint::cosign(&mut note, "w2.example", &w2).unwrap();
    Checkpoint::verify_witnessed(
        note.encode().as_bytes(),
        ORIGIN,
        &log.verifying_key(),
        &witnesses,
        2,
    )
    .unwrap();
}

/// A known key whose line fails to verify rejects the note, never skips it.
#[test]
fn a_bad_line_from_a_known_key_rejects_the_note() {
    let log = key(1);
    let mut note = checkpoint().sign(&log).unwrap();
    note.signatures[0].signature[10] ^= 1;
    assert_eq!(
        Checkpoint::verify(note.encode().as_bytes(), ORIGIN, &log.verifying_key()),
        Err(LogError::BadSignature)
    );
}

/// §16.2 recomputed: key id and signed bytes from the formula alone.
#[test]
fn the_note_bytes_match_the_spec() {
    let log = key(1);
    let note = checkpoint().sign(&log).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(ORIGIN.as_bytes());
    hasher.update(b"\n\xffHIDE/1.0 hide-sign");
    hasher.update(log.verifying_key().to_bytes());
    let digest = hasher.finalize();
    assert_eq!(key_id(ORIGIN, &log.verifying_key()), digest[..4]);
    let text = format!("{ORIGIN}\n5\n{}\n", STANDARD.encode([0xab; 32]));
    assert_eq!(note.text, text);
    log.verifying_key()
        .verify(
            CHECKPOINT_CONTEXT,
            text.as_bytes(),
            &note.signatures[0].signature,
        )
        .unwrap();
    assert_eq!(CHECKPOINT_CONTEXT, b"HIDE/1.0 checkpoint");
}

#[test]
fn leaves_match_the_spec() {
    let leaf = identity_leaf(&[1; 32], &[2; 32], &[3; 32], 7);
    let expected = [
        &b"HIDE/1.0 identity leaf"[..],
        &[1; 32],
        &[2; 32],
        &[3; 32],
        &7u64.to_be_bytes(),
    ]
    .concat();
    assert_eq!(leaf, expected);
    let leaf = epoch_leaf(&[1; 32], &[4; 32], 3);
    let expected = [
        &b"HIDE/1.0 epoch leaf"[..],
        &[1; 32],
        &[4; 32],
        &3u64.to_be_bytes(),
    ]
    .concat();
    assert_eq!(leaf, expected);
    assert_ne!(
        leaf_hash(&identity_leaf(&[1; 32], &[2; 32], &[3; 32], 7)),
        leaf_hash(&identity_leaf(&[1; 32], &[2; 32], &[3; 32], 8))
    );
}

#[test]
fn proofs_round_trip_through_their_encoding_and_still_verify() {
    let mut log = TransparencyLog::new();
    for n in 0..11u64 {
        log.append(&epoch_leaf(&[n as u8; 32], &[0; 32], n));
    }
    let inclusion = log.prove_inclusion(6, 11).unwrap();
    let bytes = inclusion.encode().unwrap();
    assert_eq!(bytes[0], 0x01);
    assert_eq!(&bytes[1..9], &6u64.to_be_bytes());
    assert_eq!(&bytes[9..17], &11u64.to_be_bytes());
    assert_eq!(usize::from(bytes[17]), inclusion.path.len());
    assert_eq!(bytes.len(), 18 + 32 * inclusion.path.len());
    let decoded = InclusionProof::decode(&bytes).unwrap();
    assert_eq!(decoded, inclusion);
    let leaf = leaf_hash(&epoch_leaf(&[6; 32], &[0; 32], 6));
    verify_inclusion(&decoded, &leaf, &log.root()).unwrap();

    let consistency = log.prove_consistency(4, 11).unwrap();
    let bytes = consistency.encode().unwrap();
    assert_eq!(bytes[0], 0x02);
    let decoded = ConsistencyProof::decode(&bytes).unwrap();
    verify_consistency(&decoded, &log.root_at(4).unwrap(), &log.root()).unwrap();
    // A consistency proof is not an inclusion proof and vice versa.
    assert_eq!(InclusionProof::decode(&bytes), Err(LogError::Malformed));
}

#[test]
fn malformed_proof_encodings_are_refused_before_copying() {
    let good = InclusionProof {
        index: 0,
        size: 2,
        path: vec![[7; 32]],
    }
    .encode()
    .unwrap();
    let mut long = good.clone();
    long[17] = 65;
    assert_eq!(
        InclusionProof::decode(&long),
        Err(LogError::ProofTooLong(65))
    );
    for bad in [
        &good[..17],
        &good[..good.len() - 1],
        &[&good[..], &[0]].concat()[..],
    ] {
        assert_eq!(InclusionProof::decode(bad), Err(LogError::Malformed));
    }
    let too_many = InclusionProof {
        index: 0,
        size: 2,
        path: vec![[0; 32]; 65],
    };
    assert_eq!(too_many.encode(), Err(LogError::ProofTooLong(65)));
}
