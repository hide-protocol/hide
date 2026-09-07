//! An ssh-agent that offers the Ed25519 half of a HIDE identity.
//!
//! OpenSSH user authentication accepts only `ssh-ed25519`, `sk-*` and RSA.
//! Post-quantum algorithms exist in SSH key exchange but not in user
//! authentication, so the ML-DSA half of a HIDE identity cannot be offered
//! here. What this buys is not post-quantum SSH; it is one sealed identity
//! instead of a plaintext key sitting in `~/.ssh`.

use std::io::{self, Read, Write};

use ed25519_dalek::{Signer, SigningKey};
use hide_sign::SigningIdentity;
use sha2::{Digest, Sha256};

use crate::Result;

// From OpenSSH authfd.h. Only the four we answer are named.
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const FAILURE: u8 = 5;

pub const KEY_TYPE: &str = "ssh-ed25519";

/// OpenSSH caps a request at 256 KiB. Ours are far smaller, but the bound has
/// to exist before any length from the socket reaches an allocator.
const MAX_MESSAGE: u32 = 256 * 1024;

/// Reads an RFC 4251 string without trusting its length prefix.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn u32(&mut self) -> Result<u32> {
        let (head, rest) = self
            .bytes
            .split_at_checked(4)
            .ok_or("truncated length prefix")?;
        self.bytes = rest;
        Ok(u32::from_be_bytes(head.try_into().expect("split at four")))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let length = self.u32()? as usize;
        let (head, rest) = self
            .bytes
            .split_at_checked(length)
            .ok_or("string longer than the message containing it")?;
        self.bytes = rest;
        Ok(head)
    }
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

/// The `ssh-ed25519` public key blob, as it appears in `authorized_keys` and
/// in an agent's identity list.
pub fn public_key_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, public);
    blob
}

/// The one-line form written to `authorized_keys`.
pub fn authorized_key_line(public: &[u8; 32], comment: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    format!(
        "{KEY_TYPE} {} {comment}",
        STANDARD.encode(public_key_blob(public))
    )
}

/// The `SHA256:...` fingerprint OpenSSH prints, over the same blob.
pub fn fingerprint(public: &[u8; 32]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
    let digest = Sha256::digest(public_key_blob(public));
    format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
}

/// Decides whether a signature may be produced. Separated from the transport
/// so the confirmation policy can be tested without a socket.
pub trait Approver {
    fn approve(&mut self, fingerprint: &str) -> bool;
}

/// Asks on the terminal. Reads from the tty rather than stdin so that a
/// process on the far end of the socket cannot answer its own prompt.
pub struct AskOnTerminal;

impl Approver for AskOnTerminal {
    fn approve(&mut self, fingerprint: &str) -> bool {
        eprintln!("hide agent: a signature was requested with {fingerprint}");
        eprint!("Allow it? [y/N] ");
        let _ = io::stderr().flush();
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_err() {
            return false;
        }
        matches!(answer.trim(), "y" | "Y" | "yes")
    }
}

/// Approves everything, for `--no-confirm`.
pub struct ApproveEverything;

impl Approver for ApproveEverything {
    fn approve(&mut self, _fingerprint: &str) -> bool {
        true
    }
}

pub struct Agent {
    key: SigningKey,
    public: [u8; 32],
    comment: String,
}

impl Agent {
    pub fn new(identity: &SigningIdentity, comment: String) -> Self {
        let key = SigningKey::from_bytes(&identity.ed25519_seed());
        let public = key.verifying_key().to_bytes();
        Self {
            key,
            public,
            comment,
        }
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Answers one request. Anything unrecognised, malformed, or refused
    /// becomes FAILURE: the agent must not tell a caller why it said no.
    pub fn respond(&self, request: &[u8], approver: &mut dyn Approver) -> Vec<u8> {
        self.try_respond(request, approver)
            .unwrap_or_else(|_| vec![FAILURE])
    }

    fn try_respond(&self, request: &[u8], approver: &mut dyn Approver) -> Result<Vec<u8>> {
        let (kind, body) = request.split_first().ok_or("empty request")?;
        match *kind {
            REQUEST_IDENTITIES => Ok(self.identities()),
            SIGN_REQUEST => self.sign(body, approver),
            _ => Err(format!("unsupported request {kind}").into()),
        }
    }

    fn identities(&self) -> Vec<u8> {
        let mut out = vec![IDENTITIES_ANSWER];
        out.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut out, &public_key_blob(&self.public));
        put_string(&mut out, self.comment.as_bytes());
        out
    }

    fn sign(&self, body: &[u8], approver: &mut dyn Approver) -> Result<Vec<u8>> {
        let mut reader = Reader::new(body);
        let requested = reader.string()?;
        let data = reader.string()?;
        // Flags select RSA hash algorithms. Ed25519 has one signature
        // algorithm, so any flag value is simply not applicable.
        let _flags = reader.u32()?;

        if requested != public_key_blob(&self.public) {
            return Err("the requested key is not ours".into());
        }
        if !approver.approve(&fingerprint(&self.public)) {
            return Err("refused".into());
        }

        let signature = self.key.sign(data).to_bytes();
        let mut blob = Vec::with_capacity(83);
        put_string(&mut blob, KEY_TYPE.as_bytes());
        put_string(&mut blob, &signature);

        let mut out = vec![SIGN_RESPONSE];
        put_string(&mut out, &blob);
        Ok(out)
    }
}

/// Serves one connection until the peer hangs up.
pub fn serve<S: Read + Write>(
    agent: &Agent,
    stream: &mut S,
    approver: &mut dyn Approver,
) -> Result<()> {
    loop {
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }

        let length = u32::from_be_bytes(header);
        if length == 0 || length > MAX_MESSAGE {
            // Do not allocate on a length we have already judged absurd.
            return Err(format!("request length {length} is out of range").into());
        }

        let mut request = vec![0u8; length as usize];
        stream.read_exact(&mut request)?;

        let response = agent.respond(&request, approver);
        stream.write_all(&(response.len() as u32).to_be_bytes())?;
        stream.write_all(&response)?;
        stream.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Agent {
        let identity = SigningIdentity::from_bytes(&[7u8; 32]).expect("a valid seed");
        Agent::new(&identity, "hide".into())
    }

    fn framed(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![kind];
        for part in parts {
            put_string(&mut out, part);
        }
        out
    }

    /// The blob is what OpenSSH parses, so its shape is not ours to choose:
    /// "ssh-ed25519" then the 32-byte key, each length-prefixed.
    #[test]
    fn the_public_key_blob_has_the_openssh_shape() {
        let blob = public_key_blob(&[0xAB; 32]);
        assert_eq!(blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(&blob[..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes());
        assert_eq!(&blob[19..], &[0xAB; 32]);
    }

    #[test]
    fn identities_answer_lists_exactly_one_key() {
        let agent = agent();
        let reply = agent.respond(&[REQUEST_IDENTITIES], &mut ApproveEverything);
        assert_eq!(reply[0], IDENTITIES_ANSWER);
        let mut reader = Reader::new(&reply[1..]);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.string().unwrap(), public_key_blob(agent.public()));
        assert_eq!(reader.string().unwrap(), b"hide");
    }

    /// The signature must verify under the same key the agent advertises,
    /// or no server would ever accept it.
    #[test]
    fn a_signature_verifies_under_the_advertised_key() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let agent = agent();
        let data = b"session identifier and userauth request";
        let request = framed(
            SIGN_REQUEST,
            &[&public_key_blob(agent.public()), data.as_slice()],
        );
        let mut request = request;
        request.extend_from_slice(&0u32.to_be_bytes());

        let reply = agent.respond(&request, &mut ApproveEverything);
        assert_eq!(reply[0], SIGN_RESPONSE);

        let mut reader = Reader::new(&reply[1..]);
        let blob = reader.string().unwrap();
        let mut inner = Reader::new(blob);
        assert_eq!(inner.string().unwrap(), b"ssh-ed25519");
        let signature = Signature::from_slice(inner.string().unwrap()).unwrap();

        let key = VerifyingKey::from_bytes(agent.public()).unwrap();
        key.verify(data, &signature).expect("the server would too");
    }

    /// An agent that signs for a key it does not hold would let a caller
    /// launder a signature through it.
    #[test]
    fn a_request_for_another_key_is_refused() {
        let agent = agent();
        let mut request = framed(SIGN_REQUEST, &[&public_key_blob(&[9u8; 32]), b"data"]);
        request.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            agent.respond(&request, &mut ApproveEverything),
            vec![FAILURE]
        );
    }

    /// Refusing at the prompt must produce no signature at all.
    #[test]
    fn a_refused_confirmation_produces_no_signature() {
        struct Refuse;
        impl Approver for Refuse {
            fn approve(&mut self, _: &str) -> bool {
                false
            }
        }

        let agent = agent();
        let mut request = framed(
            SIGN_REQUEST,
            &[&public_key_blob(agent.public()), b"data".as_slice()],
        );
        request.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(agent.respond(&request, &mut Refuse), vec![FAILURE]);
    }

    /// Every prefix of a valid request is malformed. None may panic: this is
    /// attacker-controlled input from a socket.
    #[test]
    fn every_truncation_is_refused_without_panicking() {
        let agent = agent();
        let mut full = framed(
            SIGN_REQUEST,
            &[&public_key_blob(agent.public()), b"data".as_slice()],
        );
        full.extend_from_slice(&0u32.to_be_bytes());

        for end in 0..full.len() {
            assert_eq!(
                agent.respond(&full[..end], &mut ApproveEverything),
                vec![FAILURE],
                "a truncation at {end} was not refused"
            );
        }
    }

    /// A length prefix that promises more than the message contains must be
    /// rejected on the promise, never by allocating it.
    #[test]
    fn a_lying_length_prefix_is_refused() {
        let agent = agent();
        let mut request = vec![SIGN_REQUEST];
        request.extend_from_slice(&u32::MAX.to_be_bytes());
        request.extend_from_slice(b"short");
        assert_eq!(
            agent.respond(&request, &mut ApproveEverything),
            vec![FAILURE]
        );
    }

    /// The agent above would also refuse this because the key does not match,
    /// so that test alone cannot tell a length check from a key check. Read the
    /// length directly: an over-long string must be an error, never a silent
    /// truncation to whatever happens to be left in the buffer.
    #[test]
    fn an_over_long_string_is_an_error_rather_than_a_truncation() {
        let mut encoded = 64u32.to_be_bytes().to_vec();
        encoded.extend_from_slice(b"only eight");
        let mut reader = Reader::new(&encoded);
        assert!(reader.string().is_err());
    }

    #[test]
    fn an_unknown_request_type_fails_rather_than_being_ignored() {
        let agent = agent();
        for kind in [0u8, 1, 17, 27, 99, 255] {
            assert_eq!(
                agent.respond(&[kind], &mut ApproveEverything),
                vec![FAILURE]
            );
        }
    }

    /// The fingerprint is what a user compares against `ssh-add -l`, so it
    /// must be the SHA-256 of the blob, base64 without padding.
    #[test]
    fn the_fingerprint_matches_the_openssh_recipe() {
        let public = [0x42u8; 32];
        let expected = {
            use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
            let digest = Sha256::digest(public_key_blob(&public));
            format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
        };
        assert_eq!(fingerprint(&public), expected);
        assert!(!fingerprint(&public).ends_with('='));
    }

    /// The framing loop must survive a peer that hangs up mid-message.
    #[test]
    fn a_stream_that_ends_early_is_not_an_error_at_a_boundary() {
        let agent = agent();
        let mut empty = io::Cursor::new(Vec::new());
        serve(&agent, &mut empty, &mut ApproveEverything).expect("a clean hangup");
    }

    #[test]
    fn an_absurd_framed_length_is_refused_before_allocating() {
        let agent = agent();
        let mut stream = io::Cursor::new(u32::MAX.to_be_bytes().to_vec());
        let error = serve(&agent, &mut stream, &mut ApproveEverything)
            .expect_err("a four-gigabyte request is not a request");
        // Without naming the cause this passes even if the bound is removed,
        // because the short stream would then fail at end-of-file instead.
        assert!(
            error.to_string().contains("out of range"),
            "refused for the wrong reason: {error}"
        );
    }
}
