//! Proving possession of an identity to a live verifier.
//!
//! A detached signature proves possession *at some point*; it says nothing
//! about when, or to whom. Replayed to a second service it is just as valid,
//! which is why a captured signature must not be usable as a login.
//!
//! A challenge fixes all three. The verifier chooses a random nonce, so the
//! prover cannot have answered in advance; names an audience, so an answer
//! given to one service is meaningless at another; and stamps a time, so an
//! old answer expires. All three are signed, and a verifier that does not
//! check them is not doing anything a plain signature could not.
//!
//! The nonce alone is what makes replay detectable. Audience and expiry narrow
//! the window; the record of spent nonces is what closes it, and that record
//! must be kept by the verifier because a prover has no reason to co-operate.

use crate::{SIGNATURE_LENGTH, SignError, SigningIdentity, VerifyingIdentity};

/// Separate from every other use of an identity. A container signature or a
/// detached file signature must never verify as a login, whatever an attacker
/// can arrange for the other side to sign.
const CHALLENGE_CONTEXT: &[u8] = b"HIDE/0.5 challenge";

/// Long enough that guessing or colliding is not a strategy.
pub const NONCE_LENGTH: usize = 32;

/// A challenge exists to prove liveness within one request. A lifetime longer
/// than this keeps a nonce spendable for no reason, so it is refused as a
/// mistake rather than accepted.
pub const MAX_CHALLENGE_LIFETIME: u64 = 3600;

/// A verifier's demand: prove you hold the key, to me, now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    nonce: [u8; NONCE_LENGTH],
    audience: String,
    issued_at: u64,
    valid_for: u64,
}

impl Challenge {
    /// `audience` names the verifier, and must be a name the prover can check
    /// rather than one it is told at the time of proving. An empty audience
    /// names nobody, so it is refused.
    pub fn new(audience: impl Into<String>, now: u64, valid_for: u64) -> Result<Self, SignError> {
        let audience = audience.into();
        if audience.is_empty() || valid_for == 0 || valid_for > MAX_CHALLENGE_LIFETIME {
            return Err(SignError::MalformedChallenge);
        }
        let mut nonce = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|_| SignError::Random)?;
        Ok(Self {
            nonce,
            audience,
            issued_at: now,
            valid_for,
        })
    }

    pub fn nonce(&self) -> &[u8; NONCE_LENGTH] {
        &self.nonce
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn expires_at(&self) -> u64 {
        self.issued_at.saturating_add(self.valid_for)
    }

    /// What both sides sign. Every field is length-prefixed so that no two
    /// different challenges can produce the same bytes by shifting a boundary
    /// between the audience and what follows it.
    fn to_signed_bytes(&self) -> Vec<u8> {
        let audience = self.audience.as_bytes();
        let mut bytes = Vec::with_capacity(NONCE_LENGTH + audience.len() + 24);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(audience.len() as u64).to_be_bytes());
        bytes.extend_from_slice(audience);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.valid_for.to_be_bytes());
        bytes
    }

    /// Answers the challenge. The prover signs the challenge as the verifier
    /// stated it, so a verifier that alters any field will not verify its own.
    pub fn answer(&self, identity: &SigningIdentity) -> [u8; SIGNATURE_LENGTH] {
        identity.sign(CHALLENGE_CONTEXT, &self.to_signed_bytes())
    }
}

/// Why an answer was not accepted. A caller should log this but tell the
/// prover only that authentication failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeError {
    /// The signature does not verify, or was made over a different challenge.
    NotSigned,
    /// The challenge was answered after it expired.
    Expired,
    /// This nonce was already spent. Either a replay, or a duplicate delivery.
    Replayed,
    /// The challenge names a different audience than this verifier. An answer
    /// given to another service must be worthless here.
    WrongAudience,
}

/// The nonces already spent. Kept by the verifier, because a prover has no
/// incentive to remember. Entries are dropped once no live challenge could
/// still carry them, so this does not grow without bound.
#[derive(Debug, Default)]
pub struct SpentNonces {
    audience: String,
    seen: Vec<([u8; NONCE_LENGTH], u64)>,
}

impl SpentNonces {
    /// `audience` is the name this verifier answers to, exactly as it was used
    /// to issue challenges. Binding it here rather than at each `accept` is
    /// what makes the check impossible to forget: a verifier that takes the
    /// challenge bytes back from the client still refuses an answer minted for
    /// another service, because the record itself knows who it is.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            seen: Vec::new(),
        }
    }

    /// The audience this record accepts answers for.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Accepts an answer once. A second call with the same nonce is a replay,
    /// even if the signature is perfectly valid — which is the point.
    pub fn accept(
        &mut self,
        challenge: &Challenge,
        signature: &[u8],
        prover: &VerifyingIdentity,
        now: u64,
    ) -> Result<(), ChallengeError> {
        // Audience first: an answer minted for another service must never
        // reach the signature check, and there is no reason to spend a nonce
        // on it either. An empty expectation accepts nothing, so a caller that
        // forgot to name its audience fails closed.
        if self.audience.is_empty() || challenge.audience() != self.audience {
            return Err(ChallengeError::WrongAudience);
        }
        // Check freshness before spending the nonce, so an expired answer
        // cannot consume a nonce that a live challenge still needs.
        if now > challenge.expires_at() {
            return Err(ChallengeError::Expired);
        }
        prover
            .verify(CHALLENGE_CONTEXT, &challenge.to_signed_bytes(), signature)
            .map_err(|_| ChallengeError::NotSigned)?;

        self.forget_expired(now);
        if self
            .seen
            .iter()
            .any(|(nonce, _)| nonce == challenge.nonce())
        {
            return Err(ChallengeError::Replayed);
        }
        self.seen.push((*challenge.nonce(), challenge.expires_at()));
        Ok(())
    }

    fn forget_expired(&mut self, now: u64) {
        self.seen.retain(|(_, expires_at)| *expires_at >= now);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// A challenge is not secret, so it may be handed to the prover as bytes.
/// Kept explicit rather than derived, so the wire form cannot drift silently.
impl Challenge {
    pub fn encode(&self) -> Vec<u8> {
        self.to_signed_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SignError> {
        let (nonce, rest) = bytes
            .split_at_checked(NONCE_LENGTH)
            .ok_or(SignError::MalformedChallenge)?;
        let (length, rest) = rest
            .split_at_checked(8)
            .ok_or(SignError::MalformedChallenge)?;
        // `as usize` would wrap on a 32-bit target and accept a length that
        // does not fit, selecting the wrong slice.
        let length = usize::try_from(u64::from_be_bytes(
            length.try_into().expect("split at eight"),
        ))
        .map_err(|_| SignError::MalformedChallenge)?;
        let (audience, rest) = rest
            .split_at_checked(length)
            .ok_or(SignError::MalformedChallenge)?;
        let (issued_at, rest) = rest
            .split_at_checked(8)
            .ok_or(SignError::MalformedChallenge)?;
        let (valid_for, rest) = rest
            .split_at_checked(8)
            .ok_or(SignError::MalformedChallenge)?;
        if !rest.is_empty() {
            return Err(SignError::MalformedChallenge);
        }
        let audience =
            String::from_utf8(audience.to_vec()).map_err(|_| SignError::MalformedChallenge)?;
        let valid_for = u64::from_be_bytes(valid_for.try_into().expect("split at eight"));
        // The same bounds a freshly issued challenge must satisfy, so a decoded
        // challenge is never one that `new` would have refused.
        if audience.is_empty() || valid_for == 0 || valid_for > MAX_CHALLENGE_LIFETIME {
            return Err(SignError::MalformedChallenge);
        }
        Ok(Self {
            nonce: nonce.try_into().expect("split at the nonce length"),
            audience,
            issued_at: u64::from_be_bytes(issued_at.try_into().expect("split at eight")),
            valid_for,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SEED_LENGTH;

    const NOW: u64 = 1_000_000;
    const WINDOW: u64 = 60;

    fn identity() -> SigningIdentity {
        SigningIdentity::from_bytes(&[0x42; SEED_LENGTH]).expect("a 32-byte seed is valid")
    }

    fn challenge() -> Challenge {
        Challenge::new("ssh://host.example", NOW, WINDOW).expect("randomness is available")
    }

    fn spent() -> SpentNonces {
        SpentNonces::new("ssh://host.example")
    }

    /// A challenge that names nobody, or that lives longer than a request could
    /// plausibly last, is a mistake and must not be issued.
    #[test]
    fn an_empty_audience_or_absurd_lifetime_is_refused() {
        assert!(Challenge::new("", NOW, WINDOW).is_err());
        assert!(Challenge::new("ssh://host.example", NOW, 0).is_err());
        assert!(Challenge::new("ssh://host.example", NOW, MAX_CHALLENGE_LIFETIME + 1).is_err());
        assert!(Challenge::new("ssh://host.example", NOW, MAX_CHALLENGE_LIFETIME).is_ok());
    }

    /// A verifier that takes the challenge back from the client still refuses
    /// an answer minted for another service: the record knows its own audience.
    #[test]
    fn the_record_refuses_an_answer_for_another_audience() {
        let identity = identity();
        let elsewhere = Challenge::new("ssh://attacker.example", NOW, WINDOW).unwrap();
        let answer = elsewhere.answer(&identity);
        let mut spent = spent();
        assert_eq!(
            spent.accept(&elsewhere, &answer, &identity.verifying_key(), NOW),
            Err(ChallengeError::WrongAudience)
        );
        // A wrong-audience answer must not spend the nonce either.
        assert!(spent.is_empty());
    }

    /// A record with no audience accepts nothing rather than everything.
    #[test]
    fn a_record_without_an_audience_accepts_nothing() {
        let identity = identity();
        let challenge = challenge();
        let answer = challenge.answer(&identity);
        let mut spent = SpentNonces::new("");
        assert_eq!(
            spent.accept(&challenge, &answer, &identity.verifying_key(), NOW),
            Err(ChallengeError::WrongAudience)
        );
    }

    /// A declared audience length above `usize::MAX` must be refused, not
    /// truncated by an `as usize` cast that would wrap on a 32-bit target.
    #[test]
    fn an_oversized_audience_length_is_refused() {
        let mut bytes = vec![0u8; NONCE_LENGTH];
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            Challenge::decode(&bytes),
            Err(SignError::MalformedChallenge)
        ));
    }

    #[test]
    fn an_honest_answer_is_accepted_once() {
        let identity = identity();
        let challenge = challenge();
        let answer = challenge.answer(&identity);
        let mut spent = spent();
        assert_eq!(
            spent.accept(&challenge, &answer, &identity.verifying_key(), NOW),
            Ok(())
        );
    }

    /// The whole reason a challenge exists. A captured answer is still a valid
    /// signature, so only the record of spent nonces can refuse it.
    #[test]
    fn the_same_answer_replayed_is_refused() {
        let identity = identity();
        let challenge = challenge();
        let answer = challenge.answer(&identity);
        let mut spent = spent();
        spent
            .accept(&challenge, &answer, &identity.verifying_key(), NOW)
            .expect("the first answer is honest");
        assert_eq!(
            spent.accept(&challenge, &answer, &identity.verifying_key(), NOW),
            Err(ChallengeError::Replayed)
        );
    }

    #[test]
    fn an_answer_after_the_window_is_refused() {
        let identity = identity();
        let challenge = challenge();
        let answer = challenge.answer(&identity);
        let mut spent = spent();
        assert_eq!(
            spent.accept(
                &challenge,
                &answer,
                &identity.verifying_key(),
                NOW + WINDOW + 1
            ),
            Err(ChallengeError::Expired)
        );
    }

    /// An answer given to one service must be worthless at another, or a
    /// malicious verifier could relay it to log in somewhere else. The
    /// signature covers the audience, so even a verifier that names itself
    /// after the other service cannot accept the relayed answer.
    #[test]
    fn an_answer_for_another_audience_does_not_verify() {
        let identity = identity();
        let asked = challenge();
        let answer = asked.answer(&identity);

        let mut elsewhere = asked.clone();
        elsewhere.audience = "ssh://attacker.example".to_string();

        // Match the mutated audience, so the only thing left to fail is the
        // signature: this is what proves the audience is signed, not just read.
        let mut spent = SpentNonces::new("ssh://attacker.example");
        assert_eq!(
            spent.accept(&elsewhere, &answer, &identity.verifying_key(), NOW),
            Err(ChallengeError::NotSigned)
        );
    }

    #[test]
    fn an_answer_for_another_nonce_does_not_verify() {
        let identity = identity();
        let asked = challenge();
        let answer = asked.answer(&identity);

        let mut other = asked.clone();
        other.nonce = [0x11; NONCE_LENGTH];

        let mut spent = spent();
        assert_eq!(
            spent.accept(&other, &answer, &identity.verifying_key(), NOW),
            Err(ChallengeError::NotSigned)
        );
    }

    #[test]
    fn another_identity_cannot_answer_for_this_one() {
        let challenge = challenge();
        let impostor = SigningIdentity::from_bytes(&[0x07; SEED_LENGTH]).expect("valid seed");
        let answer = challenge.answer(&impostor);
        let mut spent = spent();
        assert_eq!(
            spent.accept(&challenge, &answer, &identity().verifying_key(), NOW),
            Err(ChallengeError::NotSigned)
        );
    }

    /// P5.2: a signature made for any other purpose must not authenticate a
    /// login, however the attacker arranges for it to be produced.
    #[test]
    fn a_signature_from_another_context_is_not_a_valid_answer() {
        let identity = identity();
        let challenge = challenge();
        let forged = identity.sign(b"HIDE/0.5 detached", &challenge.to_signed_bytes());
        let mut spent = spent();
        assert_eq!(
            spent.accept(&challenge, &forged, &identity.verifying_key(), NOW),
            Err(ChallengeError::NotSigned)
        );
    }

    /// And the converse: answering a challenge must not hand out a signature
    /// that verifies over a file.
    #[test]
    fn an_answer_is_not_a_valid_detached_signature() {
        let identity = identity();
        let challenge = challenge();
        let answer = challenge.answer(&identity);
        assert!(
            identity
                .verifying_key()
                .verify(b"HIDE/0.5 detached", &challenge.to_signed_bytes(), &answer)
                .is_err()
        );
    }

    #[test]
    fn two_challenges_never_share_a_nonce() {
        assert_ne!(challenge().nonce(), challenge().nonce());
    }

    /// An expired nonce is forgotten, or a long-lived verifier would grow
    /// without bound. Forgetting it is safe: expiry already refuses it.
    #[test]
    fn spent_nonces_are_forgotten_once_nothing_can_use_them() {
        let identity = identity();
        let first = challenge();
        let answer = first.answer(&identity);
        let mut spent = spent();
        spent
            .accept(&first, &answer, &identity.verifying_key(), NOW)
            .expect("honest");
        assert_eq!(spent.len(), 1);

        let later = Challenge::new("ssh://host.example", NOW + WINDOW + 1, WINDOW).expect("random");
        let later_answer = later.answer(&identity);
        spent
            .accept(
                &later,
                &later_answer,
                &identity.verifying_key(),
                NOW + WINDOW + 1,
            )
            .expect("honest");
        assert_eq!(spent.len(), 1, "the first nonce should have been dropped");
    }

    /// An expired answer must not consume the nonce, or a hostile party could
    /// spend nonces belonging to challenges that are still live.
    #[test]
    fn an_expired_answer_does_not_spend_the_nonce() {
        let identity = identity();
        let challenge = challenge();
        let answer = challenge.answer(&identity);
        let mut spent = spent();
        assert_eq!(
            spent.accept(
                &challenge,
                &answer,
                &identity.verifying_key(),
                NOW + WINDOW + 1
            ),
            Err(ChallengeError::Expired)
        );
        assert!(spent.is_empty());
        assert_eq!(
            spent.accept(&challenge, &answer, &identity.verifying_key(), NOW),
            Ok(())
        );
    }

    #[test]
    fn a_challenge_survives_a_round_trip() {
        let original = challenge();
        let decoded = Challenge::decode(&original.encode()).expect("our own encoding");
        assert_eq!(decoded, original);
    }

    #[test]
    fn every_truncation_of_a_challenge_is_refused() {
        let encoded = challenge().encode();
        for length in 0..encoded.len() {
            assert!(
                Challenge::decode(&encoded[..length]).is_err(),
                "accepted a challenge truncated to {length} bytes"
            );
        }
    }

    #[test]
    fn trailing_bytes_after_a_challenge_are_refused() {
        let mut encoded = challenge().encode();
        encoded.push(0);
        assert!(Challenge::decode(&encoded).is_err());
    }

    /// A length prefix is a promise, not a fact.
    #[test]
    fn a_lying_audience_length_is_refused_without_panicking() {
        let mut encoded = challenge().encode();
        encoded[NONCE_LENGTH..NONCE_LENGTH + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Challenge::decode(&encoded).is_err());
    }
}
