//! Signed checkpoints in the C2SP `tlog-checkpoint` / `signed-note` text form.
//!
//! The 40-byte checkpoint of §12 says nothing about who published it. This
//! wraps the same size and root in the note format Go's sumdb, Sigstore and
//! the public witness network already parse, signed with HIDE-Sign under the
//! signed-note "0xff" (unassigned type) convention. Witnesses cosign by adding
//! their own signature line over the same text; a verifier that demands a
//! threshold of witnesses turns a split view into a detectable event, because
//! an honest witness never signs two roots for one size.
//!
//! Spec §16.2 is normative for every byte here.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hide_sign::{SIGNATURE_LENGTH, SigningIdentity, VerifyingIdentity};
use sha2::{Digest, Sha256};

use crate::{Hash, LogError};

/// Signature context for a checkpoint note, log or witness alike.
pub const CHECKPOINT_CONTEXT: &[u8] = b"HIDE/1.0 checkpoint";

/// Distinguishes a HIDE-Sign key in the signed-note key id: `0xff` is the
/// signed-note escape for types without an assigned byte, followed by a
/// longer identifier as that specification recommends.
const SIGNATURE_TYPE: &[u8] = b"\xffHIDE/1.0 hide-sign";

/// Origins are ASCII without spaces or '+', so a key name can equal the origin
/// and no Unicode lookalike can name the same log twice.
pub const MAX_ORIGIN_BYTES: usize = 256;
/// Signed-note verifiers must accept at least 16 signatures.
const MAX_SIGNATURES: usize = 32;
/// 32 HIDE-Sign lines are about 150 KB; anything larger is refused unread.
pub const MAX_NOTE_BYTES: usize = 196_608;

const DASH: &str = "\u{2014} ";

/// One signature line: who, which key, and the raw signature bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    pub name: String,
    pub key_id: [u8; 4],
    pub signature: Vec<u8>,
}

/// A parsed note: the signed text and every signature line, known or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedNote {
    pub text: String,
    pub signatures: Vec<NoteSignature>,
}

/// `SHA-256(name || 0x0A || 0xFF || "HIDE/1.0 hide-sign" || verifying_key)[:4]`.
pub fn key_id(name: &str, key: &VerifyingIdentity) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0x0a]);
    hasher.update(SIGNATURE_TYPE);
    hasher.update(key.to_bytes());
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ORIGIN_BYTES
        && name
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'+')
}

impl SignedNote {
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(self.text.len() + 4600 * self.signatures.len());
        out.push_str(&self.text);
        out.push('\n');
        for signature in &self.signatures {
            let mut raw = Vec::with_capacity(4 + signature.signature.len());
            raw.extend_from_slice(&signature.key_id);
            raw.extend_from_slice(&signature.signature);
            out.push_str(DASH);
            out.push_str(&signature.name);
            out.push(' ');
            out.push_str(&STANDARD.encode(raw));
            out.push('\n');
        }
        out
    }

    /// Parses the note structure. Signatures are not verified here.
    pub fn decode(bytes: &[u8]) -> Result<Self, LogError> {
        if bytes.len() > MAX_NOTE_BYTES {
            return Err(LogError::Malformed);
        }
        let note = std::str::from_utf8(bytes).map_err(|_| LogError::Malformed)?;
        if note.chars().any(|c| c.is_control() && c != '\n') || !note.ends_with('\n') {
            return Err(LogError::Malformed);
        }
        // The text ends at the LAST blank line; it keeps its final newline.
        let split = note.rfind("\n\n").ok_or(LogError::Malformed)?;
        let text = &note[..=split];
        let block = &note[split + 2..];
        let mut signatures = Vec::new();
        for line in block.split_terminator('\n') {
            if signatures.len() == MAX_SIGNATURES {
                return Err(LogError::Malformed);
            }
            let rest = line.strip_prefix(DASH).ok_or(LogError::Malformed)?;
            let (name, encoded) = rest.split_once(' ').ok_or(LogError::Malformed)?;
            if !valid_name(name) {
                return Err(LogError::Malformed);
            }
            let raw = STANDARD.decode(encoded).map_err(|_| LogError::Malformed)?;
            if raw.len() < 5 {
                return Err(LogError::Malformed);
            }
            signatures.push(NoteSignature {
                name: name.to_owned(),
                key_id: [raw[0], raw[1], raw[2], raw[3]],
                signature: raw[4..].to_vec(),
            });
        }
        if signatures.is_empty() {
            return Err(LogError::Malformed);
        }
        let parsed = Self {
            text: text.to_owned(),
            signatures,
        };
        // One note, one encoding: base64 padding, stray spaces and the like
        // all fail here rather than being silently normalised.
        if parsed.encode().as_bytes() != bytes {
            return Err(LogError::Malformed);
        }
        Ok(parsed)
    }

    /// Whether `key`, named `name`, signed this note. Unknown keys (name or id
    /// differing) are skipped, as signed-note requires; a matching line whose
    /// signature fails is an error, never a skip.
    fn signed_by(&self, name: &str, key: &VerifyingIdentity) -> Result<bool, LogError> {
        let id = key_id(name, key);
        let mut found = false;
        for line in self
            .signatures
            .iter()
            .filter(|s| s.name == name && s.key_id == id)
        {
            if line.signature.len() != SIGNATURE_LENGTH
                || key
                    .verify(CHECKPOINT_CONTEXT, self.text.as_bytes(), &line.signature)
                    .is_err()
            {
                return Err(LogError::BadSignature);
            }
            found = true;
        }
        Ok(found)
    }
}

/// The tree head a log publishes: origin, size and root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

impl Checkpoint {
    /// The note text: exactly three lines, no extension lines.
    pub fn text(&self) -> Result<String, LogError> {
        if !valid_name(&self.origin) {
            return Err(LogError::Malformed);
        }
        Ok(format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            STANDARD.encode(self.root)
        ))
    }

    fn parse_text(text: &str) -> Result<Self, LogError> {
        let lines: Vec<&str> = text.split_terminator('\n').collect();
        let [origin, size, root] = lines.as_slice() else {
            return Err(LogError::Malformed);
        };
        if !valid_name(origin) {
            return Err(LogError::Malformed);
        }
        let size: u64 = size.parse().map_err(|_| LogError::Malformed)?;
        let root: Hash = STANDARD
            .decode(root)
            .map_err(|_| LogError::Malformed)?
            .try_into()
            .map_err(|_| LogError::Malformed)?;
        let checkpoint = Self {
            origin: (*origin).to_owned(),
            size,
            root,
        };
        // Rejects "+5", "05", and anything else `parse` tolerates.
        if checkpoint.text()? != text {
            return Err(LogError::Malformed);
        }
        Ok(checkpoint)
    }

    /// Signs as the log. The key name is the origin.
    pub fn sign(&self, log: &SigningIdentity) -> Result<SignedNote, LogError> {
        let text = self.text()?;
        Ok(SignedNote {
            signatures: vec![NoteSignature {
                name: self.origin.clone(),
                key_id: key_id(&self.origin, &log.verifying_key()),
                signature: log.sign(CHECKPOINT_CONTEXT, text.as_bytes()).to_vec(),
            }],
            text,
        })
    }

    /// Adds a witness cosignature to a note that already carries the log's.
    pub fn cosign(
        note: &mut SignedNote,
        name: &str,
        witness: &SigningIdentity,
    ) -> Result<(), LogError> {
        if !valid_name(name) || note.signatures.len() >= MAX_SIGNATURES {
            return Err(LogError::Malformed);
        }
        note.signatures.push(NoteSignature {
            name: name.to_owned(),
            key_id: key_id(name, &witness.verifying_key()),
            signature: witness
                .sign(CHECKPOINT_CONTEXT, note.text.as_bytes())
                .to_vec(),
        });
        Ok(())
    }

    /// Parses and verifies a note from the log at `origin` signed by `log`.
    pub fn verify(note: &[u8], origin: &str, log: &VerifyingIdentity) -> Result<Self, LogError> {
        Self::verify_witnessed(note, origin, log, &[], 0)
    }

    /// As [`Self::verify`], and additionally requires at least `threshold`
    /// distinct witnesses from `witnesses` to have cosigned.
    pub fn verify_witnessed(
        note: &[u8],
        origin: &str,
        log: &VerifyingIdentity,
        witnesses: &[(&str, &VerifyingIdentity)],
        threshold: usize,
    ) -> Result<Self, LogError> {
        let parsed = SignedNote::decode(note)?;
        let checkpoint = Self::parse_text(&parsed.text)?;
        if checkpoint.origin != origin {
            return Err(LogError::WrongOrigin {
                found: checkpoint.origin,
            });
        }
        if !parsed.signed_by(origin, log)? {
            return Err(LogError::Unsigned);
        }
        // A witness listed twice (or the log listed as its own witness) must
        // not count twice toward the threshold.
        let mut counted: Vec<(&str, [u8; 4])> = vec![(origin, key_id(origin, log))];
        let mut cosigned = 0;
        for (name, key) in witnesses {
            let id = key_id(name, key);
            if counted.iter().any(|(n, k)| n == name || *k == id) {
                continue;
            }
            if parsed.signed_by(name, key)? {
                cosigned += 1;
                counted.push((name, id));
            }
        }
        if cosigned < threshold {
            return Err(LogError::Unsigned);
        }
        Ok(checkpoint)
    }
}
