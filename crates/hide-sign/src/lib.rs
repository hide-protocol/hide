//! Hybrid Ed25519 + ML-DSA-65 signatures for HIDE.
//!
//! A signature is the concatenation of both halves and verifies **only if both
//! halves verify**. Accepting either alone would silently reduce the scheme to
//! the weaker of the two, which is the whole reason for pairing them: Ed25519
//! falls to a quantum adversary, and ML-DSA is young enough that a classical
//! break cannot be ruled out.
//!
//! Both halves are derived from one 32-byte seed through domain-separated
//! HKDF, so an identity is a single thing to back up. The seed is also
//! separate from the encryption key: compromise of one must not imply the
//! other.
//!
//! No primitive is implemented here. This crate composes reviewed crates and
//! owns only the combination.

use ed25519_dalek::{
    Signer as _, SigningKey as EdSigningKey, Verifier as _, VerifyingKey as EdVerifyingKey,
};
use hkdf::Hkdf;
use ml_dsa::{
    KeyInit as _, MlDsa65, Signature as MlSignature, SigningKey as MlSigningKey,
    VerifyingKey as MlVerifyingKey, signature::Keypair as _,
};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

mod challenge;
pub use challenge::{Challenge, ChallengeError, NONCE_LENGTH, SpentNonces};

/// The seed an identity is stored and backed up as.
pub const SEED_LENGTH: usize = 32;

const ED25519_PUBLIC_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const ML_DSA_PUBLIC_LEN: usize = 1952;
const ML_DSA_SIGNATURE_LEN: usize = 3309;

/// A hybrid verifying key: the Ed25519 half followed by the ML-DSA-65 half.
pub const VERIFYING_KEY_LENGTH: usize = ED25519_PUBLIC_LEN + ML_DSA_PUBLIC_LEN;
/// A hybrid signature: the Ed25519 half followed by the ML-DSA-65 half.
pub const SIGNATURE_LENGTH: usize = ED25519_SIGNATURE_LEN + ML_DSA_SIGNATURE_LEN;

/// Separates the two halves so neither key can stand in for the other, and
/// separates a signing seed from the encryption seed of the same identity.
const ED25519_INFO: &[u8] = b"HIDE/0.5 identity ed25519";
const ML_DSA_INFO: &[u8] = b"HIDE/0.5 identity ml-dsa-65";

/// An error that carries no key material and no signed plaintext.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignError {
    /// Deliberately does not say which half failed: that distinction is not
    /// useful to a caller and would tell an attacker which half to attack.
    #[error("signature verification failed")]
    Verification,
    #[error("invalid {name} length: expected {expected}, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("verifying key is malformed")]
    MalformedKey,
    #[error("challenge is malformed")]
    MalformedChallenge,
    #[error("operating-system randomness failed")]
    Random,
}

fn require_length(name: &'static str, expected: usize, actual: usize) -> Result<(), SignError> {
    if expected == actual {
        Ok(())
    } else {
        Err(SignError::InvalidLength {
            name,
            expected,
            actual,
        })
    }
}

fn derive(seed: &[u8; SEED_LENGTH], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0_u8; 32]);
    // HKDF-Expand cannot fail for a 32-byte output, and a panic here would be a
    // logic error rather than anything an input can cause.
    Hkdf::<Sha256>::from_prk(seed)
        .expect("a 32-byte PRK is long enough for HKDF-SHA256")
        .expand(info, output.as_mut())
        .expect("32 bytes is within HKDF's output limit");
    output
}

/// A signing identity, intentionally not `Debug`, `Clone` or `Serialize`.
///
/// ```compile_fail,E0277
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<hide_sign::SigningIdentity>();
/// ```
///
/// ```compile_fail,E0277
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<hide_sign::SigningIdentity>();
/// ```
pub struct SigningIdentity {
    seed: Zeroizing<[u8; SEED_LENGTH]>,
    ed25519: EdSigningKey,
    ml_dsa: MlSigningKey<MlDsa65>,
}

impl SigningIdentity {
    pub fn generate() -> Result<Self, SignError> {
        let mut seed = Zeroizing::new([0_u8; SEED_LENGTH]);
        getrandom::fill(seed.as_mut()).map_err(|_| SignError::Random)?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        require_length("signing seed", SEED_LENGTH, bytes.len())?;
        let mut seed = Zeroizing::new([0_u8; SEED_LENGTH]);
        seed.copy_from_slice(bytes);
        Ok(Self::from_seed(&seed))
    }

    fn from_seed(seed: &Zeroizing<[u8; SEED_LENGTH]>) -> Self {
        let ed_seed = derive(seed, ED25519_INFO);
        let ml_seed = derive(seed, ML_DSA_INFO);
        Self {
            seed: seed.clone(),
            ed25519: EdSigningKey::from_bytes(&ed_seed),
            ml_dsa: MlSigningKey::<MlDsa65>::new((&*ml_seed).into()),
        }
    }

    /// The seed to back up. This is key material: never log or transmit it.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SEED_LENGTH]> {
        self.seed.clone()
    }

    pub fn verifying_key(&self) -> VerifyingIdentity {
        VerifyingIdentity {
            ed25519: self.ed25519.verifying_key(),
            ml_dsa: self.ml_dsa.verifying_key().clone(),
        }
    }

    /// Signs with both halves. `context` separates uses of one identity, so a
    /// signature made for one purpose cannot be replayed as another.
    pub fn sign(&self, context: &[u8], message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let payload = bind(context, message);
        let ed = self.ed25519.sign(&payload);
        let ml = self.ml_dsa.sign(&payload);
        let mut signature = [0_u8; SIGNATURE_LENGTH];
        signature[..ED25519_SIGNATURE_LEN].copy_from_slice(&ed.to_bytes());
        signature[ED25519_SIGNATURE_LEN..].copy_from_slice(&ml.encode());
        signature
    }

    /// The Ed25519 half alone, for the SSH agent. OpenSSH has no post-quantum
    /// signature type for user authentication, so this is what an unmodified
    /// server can actually verify.
    pub fn ed25519_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.ed25519.to_bytes())
    }
}

/// The public half of an identity: shareable, and safe to print.
#[derive(Clone)]
pub struct VerifyingIdentity {
    ed25519: EdVerifyingKey,
    ml_dsa: MlVerifyingKey<MlDsa65>,
}

// Hand-written because ml_dsa::VerifyingKey implements PartialEq but not Eq.
// Equality over the encoded bytes is reflexive, so Eq is sound here.
impl PartialEq for VerifyingIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for VerifyingIdentity {}

impl core::fmt::Debug for VerifyingIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public material, but printing 1984 bytes helps nobody.
        formatter
            .debug_struct("VerifyingIdentity")
            .field("ed25519", &hex_prefix(&self.ed25519_bytes()))
            .finish_non_exhaustive()
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl VerifyingIdentity {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        require_length("verifying key", VERIFYING_KEY_LENGTH, bytes.len())?;
        let (ed, ml) = bytes.split_at(ED25519_PUBLIC_LEN);
        let ed: [u8; ED25519_PUBLIC_LEN] = ed.try_into().expect("split at the exact length");
        let ml: &[u8; ML_DSA_PUBLIC_LEN] = ml.try_into().expect("split at the exact length");
        Ok(Self {
            ed25519: EdVerifyingKey::from_bytes(&ed).map_err(|_| SignError::MalformedKey)?,
            ml_dsa: MlVerifyingKey::<MlDsa65>::new(ml.into()),
        })
    }

    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LENGTH] {
        let mut bytes = [0_u8; VERIFYING_KEY_LENGTH];
        bytes[..ED25519_PUBLIC_LEN].copy_from_slice(self.ed25519.as_bytes());
        bytes[ED25519_PUBLIC_LEN..].copy_from_slice(&self.ml_dsa.encode());
        bytes
    }

    /// The Ed25519 half, in the 32-byte form OpenSSH uses.
    pub fn ed25519_bytes(&self) -> [u8; ED25519_PUBLIC_LEN] {
        self.ed25519.to_bytes()
    }

    /// Verifies both halves. Neither alone is accepted.
    pub fn verify(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignError> {
        require_length("signature", SIGNATURE_LENGTH, signature.len())?;
        let payload = bind(context, message);
        let (ed, ml) = signature.split_at(ED25519_SIGNATURE_LEN);

        let ed: [u8; ED25519_SIGNATURE_LEN] = ed.try_into().expect("split at the exact length");
        // verify_strict rejects keys and signatures of small order, which
        // plain verify accepts and which break the usual uniqueness guarantee.
        let classical = self
            .ed25519
            .verify_strict(&payload, &ed_signature(&ed))
            .is_ok();

        let ml: [u8; ML_DSA_SIGNATURE_LEN] = ml.try_into().expect("split at the exact length");
        let quantum = match MlSignature::<MlDsa65>::decode(&ml.into()) {
            Some(parsed) => self.ml_dsa.verify(&payload, &parsed).is_ok(),
            None => false,
        };

        // Both are evaluated before the decision so the time taken does not
        // reveal which half failed.
        if classical && quantum {
            Ok(())
        } else {
            Err(SignError::Verification)
        }
    }
}

fn ed_signature(bytes: &[u8; ED25519_SIGNATURE_LEN]) -> ed25519_dalek::Signature {
    ed25519_dalek::Signature::from_bytes(bytes)
}

/// Binds the context to the message length-prefixed, so that no two distinct
/// (context, message) pairs can produce the same signed bytes. Concatenating
/// them directly would let a crafted context absorb part of the message.
fn bind(context: &[u8], message: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + context.len() + message.len());
    payload.extend_from_slice(&(context.len() as u64).to_be_bytes());
    payload.extend_from_slice(context);
    payload.extend_from_slice(message);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &[u8] = b"HIDE/0.5 test";

    fn identity() -> SigningIdentity {
        SigningIdentity::from_bytes(&[0x42; SEED_LENGTH]).expect("a 32-byte seed is valid")
    }

    #[test]
    fn a_signature_round_trips_and_has_the_documented_size() {
        let signing = identity();
        let verifying = signing.verifying_key();
        let signature = signing.sign(CONTEXT, b"attack at dawn");

        assert_eq!(signature.len(), SIGNATURE_LENGTH);
        assert_eq!(verifying.to_bytes().len(), VERIFYING_KEY_LENGTH);
        verifying
            .verify(CONTEXT, b"attack at dawn", &signature)
            .expect("a fresh signature verifies");
    }

    #[test]
    fn the_seed_reproduces_the_same_identity() {
        let first = identity();
        let second = SigningIdentity::from_bytes(&first.to_bytes()[..]).expect("round trip");
        assert_eq!(
            first.verifying_key().to_bytes(),
            second.verifying_key().to_bytes()
        );

        let signature = first.sign(CONTEXT, b"same seed");
        second
            .verifying_key()
            .verify(CONTEXT, b"same seed", &signature)
            .expect("the derived key is identical");
    }

    #[test]
    fn a_verifying_key_survives_encoding() {
        let verifying = identity().verifying_key();
        let decoded = VerifyingIdentity::from_bytes(&verifying.to_bytes()).expect("round trip");
        assert!(decoded == verifying);
    }

    /// The central invariant: a signature valid in one half only must fail.
    #[test]
    fn neither_half_alone_is_accepted() {
        let alice = identity();
        let bob = SigningIdentity::from_bytes(&[0x99; SEED_LENGTH]).expect("valid seed");
        let message = b"transfer 100";

        let from_alice = alice.sign(CONTEXT, message);
        let from_bob = bob.sign(CONTEXT, message);

        // Alice's Ed25519 half with Bob's ML-DSA half, and the reverse.
        let mut classical_only = from_alice;
        classical_only[ED25519_SIGNATURE_LEN..].copy_from_slice(&from_bob[ED25519_SIGNATURE_LEN..]);
        assert_eq!(
            alice
                .verifying_key()
                .verify(CONTEXT, message, &classical_only),
            Err(SignError::Verification),
            "a valid Ed25519 half was accepted despite a foreign ML-DSA half"
        );

        let mut quantum_only = from_alice;
        quantum_only[..ED25519_SIGNATURE_LEN].copy_from_slice(&from_bob[..ED25519_SIGNATURE_LEN]);
        assert_eq!(
            alice
                .verifying_key()
                .verify(CONTEXT, message, &quantum_only),
            Err(SignError::Verification),
            "a valid ML-DSA half was accepted despite a foreign Ed25519 half"
        );
    }

    #[test]
    fn a_changed_message_context_or_signer_is_rejected() {
        let signing = identity();
        let verifying = signing.verifying_key();
        let signature = signing.sign(CONTEXT, b"pay Ana");

        assert_eq!(
            verifying.verify(CONTEXT, b"pay Bob", &signature),
            Err(SignError::Verification)
        );
        assert_eq!(
            verifying.verify(b"HIDE/0.5 other", b"pay Ana", &signature),
            Err(SignError::Verification),
            "a signature was replayed under a different context"
        );

        let other = SigningIdentity::from_bytes(&[7; SEED_LENGTH]).expect("valid seed");
        assert_eq!(
            other
                .verifying_key()
                .verify(CONTEXT, b"pay Ana", &signature),
            Err(SignError::Verification)
        );
    }

    #[test]
    fn every_single_bit_flip_in_a_signature_is_rejected() {
        let signing = identity();
        let verifying = signing.verifying_key();
        let message = b"integrity";
        let signature = signing.sign(CONTEXT, message);

        // Both halves, at their boundaries and in the middle of each.
        for offset in [
            0,
            1,
            ED25519_SIGNATURE_LEN - 1,
            ED25519_SIGNATURE_LEN,
            ED25519_SIGNATURE_LEN + 1,
            SIGNATURE_LENGTH / 2,
            SIGNATURE_LENGTH - 1,
        ] {
            let mut damaged = signature;
            damaged[offset] ^= 1;
            assert_eq!(
                verifying.verify(CONTEXT, message, &damaged),
                Err(SignError::Verification),
                "a flipped bit at offset {offset} was accepted"
            );
        }
    }

    #[test]
    fn a_truncated_or_extended_signature_is_refused_before_verifying() {
        let signing = identity();
        let verifying = signing.verifying_key();
        let signature = signing.sign(CONTEXT, b"bounds");

        for length in [0, 1, ED25519_SIGNATURE_LEN, SIGNATURE_LENGTH - 1] {
            assert!(matches!(
                verifying.verify(CONTEXT, b"bounds", &signature[..length]),
                Err(SignError::InvalidLength { .. })
            ));
        }
        let mut extended = signature.to_vec();
        extended.push(0);
        assert!(matches!(
            verifying.verify(CONTEXT, b"bounds", &extended),
            Err(SignError::InvalidLength { .. })
        ));
    }

    #[test]
    fn a_malformed_key_or_seed_is_refused_rather_than_panicking() {
        for length in [0, 31, 33, 64] {
            assert!(SigningIdentity::from_bytes(&vec![0; length]).is_err());
        }
        for length in [0, VERIFYING_KEY_LENGTH - 1, VERIFYING_KEY_LENGTH + 1] {
            assert!(VerifyingIdentity::from_bytes(&vec![0; length]).is_err());
        }
        // An all-zero Ed25519 half parses: dalek defers point decompression,
        // so a degenerate key is caught at verification rather than here.
        // What matters is that it can never validate anything, which is the
        // reason this code uses verify_strict.
        let degenerate =
            VerifyingIdentity::from_bytes(&[0; VERIFYING_KEY_LENGTH]).expect("parses lazily");
        let signature = identity().sign(CONTEXT, b"anything");
        assert_eq!(
            degenerate.verify(CONTEXT, b"anything", &signature),
            Err(SignError::Verification),
            "a small-order key validated a signature"
        );
        assert_eq!(
            degenerate.verify(CONTEXT, b"anything", &[0; SIGNATURE_LENGTH]),
            Err(SignError::Verification)
        );
    }

    #[test]
    fn the_context_cannot_absorb_part_of_the_message() {
        let signing = identity();
        let verifying = signing.verifying_key();
        // Without a length prefix, ("ab", "c") and ("a", "bc") would sign the
        // same bytes and a signature would transfer between them.
        let signature = signing.sign(b"ab", b"c");
        assert_eq!(
            verifying.verify(b"a", b"bc", &signature),
            Err(SignError::Verification)
        );
    }

    /// Case 1 of the ed25519-speccheck suite: a small-order public key with a
    /// matching small-order signature. Plain `verify` accepts it; `verify_strict`
    /// must not. Without this, swapping verify_strict for verify is undetectable.
    #[test]
    fn a_small_order_ed25519_key_is_rejected() {
        let pubkey = hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa");
        let sig = hex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a\
             0000000000000000000000000000000000000000000000000000000000000000",
        );
        let message = hex("8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6");

        let key = EdVerifyingKey::from_bytes(&pubkey.try_into().expect("32 bytes"))
            .expect("the point decodes");
        let signature = ed25519_dalek::Signature::from_bytes(&sig.try_into().expect("64 bytes"));

        // The premise: this is exactly the case the two APIs disagree on.
        assert!(
            key.verify(&message, &signature).is_ok(),
            "vector no longer exercises the small-order path"
        );
        assert!(
            key.verify_strict(&message, &signature).is_err(),
            "verify_strict accepted a small-order key"
        );
    }

    /// The vector above cannot be routed through `VerifyingIdentity::verify`,
    /// because `bind` length-prefixes every payload and the vector's message is
    /// fixed. Guard the call site directly instead, so downgrading it to plain
    /// `verify` cannot pass unnoticed.
    #[test]
    fn the_classical_half_uses_verify_strict() {
        let source = include_str!("lib.rs");
        let after = source
            .split("fn verify(")
            .nth(1)
            .expect("verify is defined here");
        // Stop at the end of the function, otherwise this test's own source
        // (which mentions verify_strict) would satisfy the assertion.
        let body = after.split("\n    }\n").next().expect("the body ends");
        assert!(
            body.contains(".verify_strict("),
            "VerifyingIdentity::verify must use verify_strict"
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16)
                    .expect("hex digits")
            })
            .collect()
    }

    /// A wiring mistake that fed the same seed to both halves would leave every
    /// other test green, so pin the derived material to frozen bytes.
    #[test]
    fn the_derived_halves_match_frozen_bytes() {
        let bytes = identity().verifying_key().to_bytes();
        assert_eq!(
            &bytes[..ED25519_PUBLIC_LEN],
            &hex("d272bef04a4165fcd3fe54571231cc1f7ddb9a0750b5dfb014743007ca39afd6")[..],
            "derived Ed25519 half changed: this is a protocol change"
        );
        // Pin the post-quantum half too. Without this, feeding both halves the
        // same seed leaves every other test green.
        assert_eq!(
            &bytes[ED25519_PUBLIC_LEN..ED25519_PUBLIC_LEN + 32],
            &hex("f8119f4e0a419adc36f51d2babba246d7e03260d0b904ca695859c9af81d462f")[..],
            "derived ML-DSA half changed: this is a protocol change"
        );
    }

    /// RFC 8032 section 7.1, TEST 3. Proves ed25519-dalek is wired to the
    /// standard, not merely self-consistent.
    #[test]
    fn the_classical_half_matches_rfc_8032() {
        let secret = hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let message = hex("af82");
        let expected = hex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );

        let signing = EdSigningKey::from_bytes(&secret.try_into().expect("32-byte seed"));
        assert_eq!(
            signing.sign(&message).to_bytes()[..],
            expected[..],
            "Ed25519 does not match RFC 8032"
        );
    }

    /// NIST ACVP ML-DSA keyGen, ML-DSA-65, tcId 26. Proves the ml-dsa crate
    /// implements FIPS-204 with the parameter set this code selects; a silent
    /// swap to ML-DSA-44 or -87 would change these bytes.
    #[test]
    fn the_quantum_half_matches_fips_204() {
        let seed = hex("A991FD42B071D49C48AE3E75C647459E0DAAD1E1BA356A04801912D3294BCFF8");
        let seed: [u8; 32] = seed.try_into().expect("32 bytes");
        let signing = MlSigningKey::<MlDsa65>::new((&seed).into());
        let public = signing.verifying_key().encode();

        assert_eq!(
            public.len(),
            ML_DSA_PUBLIC_LEN,
            "wrong ML-DSA parameter set"
        );
        assert_eq!(
            &public[..32],
            &hex("36DB0B5DCE98BD190CB139E80B71B49C7D7040B71C5A1F3412C46BDE939192B1")[..],
            "ML-DSA-65 does not match the NIST vector"
        );
    }

    #[test]
    fn a_context_change_alone_invalidates() {
        let signing = identity();
        let verifying = signing.verifying_key();
        let signature = signing.sign(b"one", b"m");
        assert_eq!(
            verifying.verify(b"two", b"m", &signature),
            Err(SignError::Verification)
        );
    }

    #[test]
    fn the_two_halves_are_derived_independently() {
        let signing = identity();
        let bytes = signing.verifying_key().to_bytes();
        // A wiring mistake that fed the same seed to both would be invisible in
        // a round-trip test, so compare the derived material directly.
        assert_ne!(
            &bytes[..ED25519_PUBLIC_LEN],
            &signing.to_bytes()[..],
            "the Ed25519 key is the raw seed rather than a derived one"
        );
        assert_ne!(
            derive(&signing.to_bytes(), ED25519_INFO).as_ref(),
            derive(&signing.to_bytes(), ML_DSA_INFO).as_ref()
        );
    }
}
