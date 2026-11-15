//! Interoperability with the C2SP transparency-log witness network.
//!
//! HIDE's own cosignature (`Checkpoint::cosign`) is a HIDE-Sign hybrid signature
//! over the checkpoint text, which only another HIDE implementation can verify.
//! That is enough for a HIDE-only deployment and useless for reaching the
//! public witness network, whose members are ordinary C2SP witnesses: an HTTP
//! service identified by a name and a public key, speaking
//! [`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness) and cosigning in the
//! format of [`c2sp.org/tlog-cosignature`](https://c2sp.org/tlog-cosignature).
//!
//! A HIDE checkpoint note is already a C2SP note — origin, size, base64 root,
//! then signature lines — so the two can live in one note. This module adds the
//! missing half: building the `add-checkpoint` request, reading the response the
//! way the specification classifies it, and verifying an Ed25519 cosignature a
//! standard witness returned.
//!
//! # Honest limits
//!
//! - **ML-DSA-44 cosignatures are out of scope.** `c2sp.org/tlog-cosignature`
//!   defines two algorithms and recommends ML-DSA-44 for new deployments. HIDE
//!   implements ML-DSA-65, so it can verify the Ed25519 algorithm and cannot
//!   verify the ML-DSA-44 one. A witness offering only ML-DSA-44 is refused
//!   explicitly rather than silently ignored.
//! - **Cosigning a HIDE checkpoint proves nothing about HIDE.** A cosignature
//!   attests to one tree head at one time, exactly as it does for any other log.
//! - Nothing here talks to the network: the request and response are bytes, so
//!   the caller decides what performs the HTTP call and how it is authenticated.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::checkpoint::{Checkpoint, MAX_NOTE_BYTES, SignedNote, valid_name};
use crate::{Hash, LogError};

/// The C2SP algorithm byte for Ed25519 cosignatures. `c2sp.org/signed-note`
/// assigns `0x01`; HIDE-Sign uses the `0xff` escape followed by a type string,
/// so a note carrying both can never confuse the two.
pub const C2SP_ED25519_ALGORITHM: u8 = 0x01;

/// A witness is allowed at most 63 consistency proof lines.
pub const MAX_WITNESS_PROOF_LINES: usize = 63;

/// Domain separation for the cosignature, per `c2sp.org/tlog-cosignature`.
const COSIGNATURE_LABEL: &[u8] = b"cosignature/v1";
/// The empty tree, RFC 6962 §2.1: the hash of an empty string.
pub fn empty_tree_root() -> Hash {
    use sha2::Digest;
    let digest = sha2::Sha256::digest([]);
    let mut root = [0_u8; 32];
    root.copy_from_slice(&digest);
    root
}

/// The key id a C2SP cosignature line carries:
/// `SHA-256(name || 0x0A || algorithm || public_key)[:4]`.
///
/// Distinct from [`crate::key_id`], which uses the signed-note escape byte and a
/// type string; the two derivations cannot collide on the same key.
pub fn c2sp_key_id(name: &str, ed25519_public: &[u8; 32]) -> [u8; 4] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0x0a, C2SP_ED25519_ALGORITHM]);
    hasher.update(ed25519_public);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The exact bytes an Ed25519 C2SP cosignature is computed over. Every line is
/// newline-terminated, and the timestamp is ASCII decimal with no leading zeroes.
///
/// Reproduced from the specification rather than derived, because a signature
/// covers exactly these bytes and any difference is a failed verification that
/// looks like a dishonest witness.
pub fn cosignature_input(timestamp: u64, checkpoint_text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + checkpoint_text.len());
    out.extend_from_slice(COSIGNATURE_LABEL);
    out.push(b'\n');
    out.extend_from_slice(format!("time {timestamp}\n").as_bytes());
    out.extend_from_slice(checkpoint_text.as_bytes());
    out
}

/// A witness the caller trusts for this log: a name and an Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub name: String,
    pub ed25519_public: [u8; 32],
}

impl Witness {
    /// Refuses a name a C2SP note could not carry, so an unusable witness is a
    /// configuration error rather than a silent non-match later.
    pub fn new(name: impl Into<String>, ed25519_public: [u8; 32]) -> Result<Self, LogError> {
        let name = name.into();
        if !valid_name(&name) {
            return Err(LogError::Malformed);
        }
        Ok(Self {
            name,
            ed25519_public,
        })
    }
}

/// How a cosignature line was verified, so a caller can tell "the witness I
/// meant signed this" from "some line had the right key id".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cosignature {
    pub timestamp: u64,
}

/// Verifies a C2SP Ed25519 cosignature from `witness` over `note`, in addition
/// to the log's own HIDE-Sign signature, and requires the checkpoint to be the
/// one `origin` names.
///
/// The timestamp is recovered by trying the candidate: a cosignature signs the
/// timestamp, so it cannot be read off the line and checked afterwards. The
/// specification sends it in a `time` line inside the *signed* message, which is
/// what this rebuilds — the value therefore comes from the witness's own
/// signature input and must be supplied by the caller from the response the
/// witness returned.
pub fn verify_ed25519_cosignature(
    note: &[u8],
    origin: &str,
    log: &hide_sign::VerifyingIdentity,
    witness: &Witness,
    timestamp: u64,
) -> Result<(Checkpoint, Cosignature), LogError> {
    // The log's signature is checked first: a cosignature over a checkpoint the
    // log never signed is worth nothing, however well it verifies.
    let checkpoint = Checkpoint::verify(note, origin, log)?;

    if note.len() > MAX_NOTE_BYTES {
        return Err(LogError::Malformed);
    }
    let parsed = SignedNote::decode(note)?;
    let id = c2sp_key_id(&witness.name, &witness.ed25519_public);
    let line = parsed
        .signatures
        .iter()
        .find(|line| line.name == witness.name && line.key_id == id)
        .ok_or(LogError::Unsigned)?;

    let key =
        VerifyingKey::from_bytes(&witness.ed25519_public).map_err(|_| LogError::BadSignature)?;
    let signature = Signature::from_slice(&line.signature).map_err(|_| LogError::BadSignature)?;
    let message = cosignature_input(timestamp, &parsed.text);
    // Strict, because a non-canonical encoding or a small-order key would
    // otherwise be accepted here and refused by a stricter peer.
    key.verify_strict(&message, &signature)
        .map_err(|_| LogError::BadSignature)?;

    Ok((checkpoint, Cosignature { timestamp }))
}

/// The body of a `POST <prefix>/add-checkpoint` request: the old size line, the
/// consistency proof lines, an empty line, then the note.
///
/// `proof` must be the RFC 6962 consistency proof from `old_size` to the
/// checkpoint's size, and empty when `old_size` is zero — the specification makes
/// a non-empty proof at size zero a `422`.
pub fn add_checkpoint_body(
    old_size: u64,
    proof: &[Hash],
    note: &[u8],
) -> Result<Vec<u8>, LogError> {
    use base64::Engine;
    if proof.len() > MAX_WITNESS_PROOF_LINES {
        return Err(LogError::ProofTooLong(proof.len()));
    }
    if old_size == 0 && !proof.is_empty() {
        return Err(LogError::Malformed);
    }
    if note.len() > MAX_NOTE_BYTES {
        return Err(LogError::Malformed);
    }
    let mut out = Vec::with_capacity(32 + 45 * proof.len() + note.len());
    out.extend_from_slice(format!("old {old_size}\n").as_bytes());
    for hash in proof {
        out.extend_from_slice(
            base64::engine::general_purpose::STANDARD
                .encode(hash)
                .as_bytes(),
        );
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(note);
    Ok(out)
}

/// What a witness said, classified from the status code exactly as
/// `c2sp.org/tlog-witness` defines it, so a caller never has to guess from a
/// status alone which of the four refusals it received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddCheckpointOutcome {
    /// `200`: the body is the cosignature line the witness returned.
    Cosigned(Vec<u8>),
    /// `404`: the witness does not serve this origin.
    UnknownOrigin,
    /// `403`: no signature from a trusted key, or the checkpoint is malformed.
    NotSigned,
    /// `400`: the old size is above the checkpoint size.
    BadOldSize,
    /// `409`: the old size is not what this witness last cosigned. The body
    /// carries the size it did cosign, which is what the caller must retry from.
    Conflict { newest_size: u64 },
    /// `422`: the proof does not verify, or a size-zero checkpoint has a root
    /// that is not the empty tree.
    ProofRejected,
}

/// Classifies an `add-checkpoint` response. A status this specification does not
/// name is refused rather than mapped onto the nearest one.
pub fn classify_add_checkpoint(status: u16, body: &[u8]) -> Result<AddCheckpointOutcome, LogError> {
    Ok(match status {
        200 => AddCheckpointOutcome::Cosigned(body.to_vec()),
        403 => AddCheckpointOutcome::NotSigned,
        404 => AddCheckpointOutcome::UnknownOrigin,
        400 => AddCheckpointOutcome::BadOldSize,
        409 => {
            let text = std::str::from_utf8(body).map_err(|_| LogError::Malformed)?;
            let line = text.strip_suffix('\n').ok_or(LogError::Malformed)?;
            // `parse` would accept "+5" and "05"; the specification allows
            // neither, and the value is what a retry is based on.
            if line.is_empty() || !line.bytes().all(|b| b.is_ascii_digit()) {
                return Err(LogError::Malformed);
            }
            if line.len() > 1 && line.starts_with('0') {
                return Err(LogError::Malformed);
            }
            let newest_size: u64 = line.parse().map_err(|_| LogError::Malformed)?;
            AddCheckpointOutcome::Conflict { newest_size }
        }
        422 => AddCheckpointOutcome::ProofRejected,
        _ => return Err(LogError::Malformed),
    })
}

/// The root a size-zero checkpoint must carry, so a caller can build one that a
/// witness will not reject with `422`.
/// Whether a checkpoint a witness would accept at size zero is well-formed.
pub fn is_empty_tree_checkpoint(checkpoint: &Checkpoint) -> bool {
    checkpoint.size == 0 && checkpoint.root == empty_tree_root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn checkpoint(size: u64) -> Checkpoint {
        Checkpoint {
            origin: "hide.example/log".into(),
            size,
            root: [7_u8; 32],
        }
    }

    fn witness_key() -> SigningKey {
        SigningKey::from_bytes(&[0x51; 32])
    }

    fn cosigned_note(timestamp: u64) -> (Vec<u8>, Witness) {
        let log = hide_sign::SigningIdentity::from_bytes(&[0x42; 32]).unwrap();
        let text = checkpoint(9).text().unwrap();
        let mut note = checkpoint(9).sign(&log).unwrap();
        let witness =
            Witness::new("witness.example", witness_key().verifying_key().to_bytes()).unwrap();
        let signature = witness_key().sign(&cosignature_input(timestamp, &text));
        let mut raw = Vec::new();
        raw.extend_from_slice(&c2sp_key_id(&witness.name, &witness.ed25519_public));
        raw.extend_from_slice(&signature.to_bytes());
        note.signatures.push(crate::checkpoint::NoteSignature {
            name: witness.name.clone(),
            key_id: c2sp_key_id(&witness.name, &witness.ed25519_public),
            signature: raw[4..].to_vec(),
        });
        (note.encode().into_bytes(), witness)
    }

    /// The whole point: a standard Ed25519 witness cosignature over a HIDE
    /// checkpoint verifies, and the log's own signature is still required.
    #[test]
    fn a_c2sp_ed25519_cosignature_verifies_over_a_hide_checkpoint() {
        let log = hide_sign::SigningIdentity::from_bytes(&[0x42; 32]).unwrap();
        let (note, witness) = cosigned_note(1_700_000_000);
        let (checkpoint, cosignature) = verify_ed25519_cosignature(
            &note,
            "hide.example/log",
            &log.verifying_key(),
            &witness,
            1_700_000_000,
        )
        .expect("a genuine cosignature verifies");
        assert_eq!(checkpoint.size, 9);
        assert_eq!(cosignature.timestamp, 1_700_000_000);
    }

    /// The timestamp is signed, so the same note must fail at a different one.
    #[test]
    fn a_cosignature_is_bound_to_its_timestamp() {
        let log = hide_sign::SigningIdentity::from_bytes(&[0x42; 32]).unwrap();
        let (note, witness) = cosigned_note(1_700_000_000);
        assert_eq!(
            verify_ed25519_cosignature(
                &note,
                "hide.example/log",
                &log.verifying_key(),
                &witness,
                1_700_000_001
            ),
            Err(LogError::BadSignature)
        );
    }

    /// A cosignature is not a substitute for the log's signature.
    #[test]
    fn a_cosignature_over_an_unsigned_checkpoint_is_refused() {
        let other = hide_sign::SigningIdentity::from_bytes(&[0x43; 32]).unwrap();
        let (note, witness) = cosigned_note(1_700_000_000);
        // No signature line carries the key id of `other`, so the failure is
        // reported as "not signed by the expected log key" rather than as a
        // broken signature: the two are different findings for a caller.
        assert_eq!(
            verify_ed25519_cosignature(
                &note,
                "hide.example/log",
                &other.verifying_key(),
                &witness,
                1_700_000_000
            ),
            Err(LogError::Unsigned)
        );
    }

    /// A witness the caller did not configure cannot be substituted, even with a
    /// correctly derived key id.
    #[test]
    fn a_cosignature_from_another_witness_is_refused() {
        let log = hide_sign::SigningIdentity::from_bytes(&[0x42; 32]).unwrap();
        let (note, _) = cosigned_note(1_700_000_000);
        let other = SigningKey::from_bytes(&[0x52; 32]);
        let stranger = Witness::new("witness.example", other.verifying_key().to_bytes()).unwrap();
        assert_eq!(
            verify_ed25519_cosignature(
                &note,
                "hide.example/log",
                &log.verifying_key(),
                &stranger,
                1_700_000_000
            ),
            Err(LogError::Unsigned)
        );
    }

    /// The request body is framed the way the specification shows it, including
    /// the empty line before the note.
    #[test]
    fn the_request_body_has_the_specified_framing() {
        let note = b"origin\n1\nAAAA\n\xe2\x80\x94 sig AAAA\n";
        let proof = [[1_u8; 32], [2_u8; 32]];
        let body = add_checkpoint_body(5, &proof, note).unwrap();
        let text = String::from_utf8(body.clone()).unwrap();
        let mut lines = text.split_inclusive('\n');
        assert_eq!(lines.next().unwrap(), "old 5\n");
        assert_eq!(
            lines.next().unwrap(),
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"
        );
        assert_eq!(
            lines.next().unwrap(),
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n"
        );
        assert_eq!(lines.next().unwrap(), "\n");
        assert_eq!(text.split("\n\n").nth(1).unwrap().as_bytes(), note);
    }

    /// A non-empty proof at size zero is refused here rather than by the witness,
    /// because the specification makes it a `422`.
    #[test]
    fn a_non_empty_proof_at_size_zero_is_refused() {
        let note = b"origin\n0\nAAAA\n";
        assert_eq!(
            add_checkpoint_body(0, &[[1_u8; 32]], note),
            Err(LogError::Malformed)
        );
        assert!(add_checkpoint_body(0, &[], note).is_ok());
    }

    /// More proof lines than the specification allows are refused before the
    /// body is built.
    #[test]
    fn too_many_proof_lines_are_refused() {
        let note = b"origin\n1\nAAAA\n";
        let proof = vec![[1_u8; 32]; MAX_WITNESS_PROOF_LINES + 1];
        assert!(matches!(
            add_checkpoint_body(1, &proof, note),
            Err(LogError::ProofTooLong(_))
        ));
        assert!(add_checkpoint_body(1, &vec![[1_u8; 32]; MAX_WITNESS_PROOF_LINES], note).is_ok());
    }

    #[test]
    fn every_named_status_is_classified() {
        assert_eq!(
            classify_add_checkpoint(200, b"\xe2\x80\x94 w AAAA\n").unwrap(),
            AddCheckpointOutcome::Cosigned(b"\xe2\x80\x94 w AAAA\n".to_vec())
        );
        assert_eq!(
            classify_add_checkpoint(403, b"").unwrap(),
            AddCheckpointOutcome::NotSigned
        );
        assert_eq!(
            classify_add_checkpoint(404, b"").unwrap(),
            AddCheckpointOutcome::UnknownOrigin
        );
        assert_eq!(
            classify_add_checkpoint(400, b"").unwrap(),
            AddCheckpointOutcome::BadOldSize
        );
        assert_eq!(
            classify_add_checkpoint(409, b"20852014\n").unwrap(),
            AddCheckpointOutcome::Conflict {
                newest_size: 20_852_014
            }
        );
        assert_eq!(
            classify_add_checkpoint(422, b"").unwrap(),
            AddCheckpointOutcome::ProofRejected
        );
    }

    /// A conflict body is a retry instruction, so a value the specification does
    /// not allow must not be read as a size.
    #[test]
    fn a_malformed_conflict_body_is_refused() {
        for body in [
            &b"05\n"[..],
            &b"+5\n"[..],
            &b"5"[..],
            &b"\n"[..],
            &b"5 5\n"[..],
            &b"18446744073709551616\n"[..],
        ] {
            assert_eq!(
                classify_add_checkpoint(409, body),
                Err(LogError::Malformed),
                "accepted {body:?}"
            );
        }
    }

    /// A status the specification does not name is not mapped onto a nearby one.
    #[test]
    fn an_unnamed_status_is_refused() {
        for status in [201, 301, 500, 0] {
            assert_eq!(
                classify_add_checkpoint(status, b""),
                Err(LogError::Malformed)
            );
        }
    }

    /// A two-line input and a one-line input are not the same message.
    #[test]
    fn the_cosignature_input_cannot_be_shifted() {
        assert_ne!(cosignature_input(1, "a\n"), cosignature_input(11, "\n"));
        assert_eq!(
            cosignature_input(1, "origin\n1\nAAAA\n"),
            b"cosignature/v1\ntime 1\norigin\n1\nAAAA\n".to_vec()
        );
    }

    /// A witness name a note cannot carry is a configuration error, not a
    /// non-match discovered at verification time.
    #[test]
    fn an_unusable_witness_name_is_refused() {
        assert!(Witness::new("", [0_u8; 32]).is_err());
        assert!(Witness::new("has space", [0_u8; 32]).is_err());
        assert!(Witness::new("has+plus", [0_u8; 32]).is_err());
        assert!(Witness::new("witness.example", [0_u8; 32]).is_ok());
    }

    /// The empty-tree root is the RFC 6962 §2.1 hash of the empty string, which
    /// is what a witness requires of a size-zero checkpoint.
    #[test]
    fn the_empty_root_matches_rfc_6962() {
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(empty_tree_root()),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        assert!(is_empty_tree_checkpoint(&Checkpoint {
            origin: "o".into(),
            size: 0,
            root: empty_tree_root(),
        }));
        assert!(!is_empty_tree_checkpoint(&Checkpoint {
            origin: "o".into(),
            size: 0,
            root: [1_u8; 32],
        }));
        assert!(!is_empty_tree_checkpoint(&checkpoint(1)));
    }

    /// The two key-id derivations must not collide for the same key, or a note
    /// carrying both kinds of line could be read wrongly.
    #[test]
    fn the_two_key_id_derivations_differ() {
        let log = hide_sign::SigningIdentity::from_bytes(&[0x42; 32]).unwrap();
        let ed = log.verifying_key().ed25519_bytes();
        let name = "witness.example";
        assert_ne!(
            c2sp_key_id(name, &ed),
            crate::key_id(name, &log.verifying_key())
        );
    }
}
