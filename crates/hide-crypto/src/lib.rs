//! Local cryptographic primitives for the experimental HIDE/0.1 format.
//!
//! Suite 1 is HPKE base mode with X-Wing, HKDF-SHA256, and ChaCha20-Poly1305.
//! This crate is unaudited and makes no anonymity or forward-secrecy guarantee.

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInOut};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, ChaCha20Poly1305 as HpkeAead},
    kdf::HkdfSha256,
    kem::XWing,
};
use rand::{CryptoRng, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_LENGTH: usize = 32;
const TAG_LENGTH: usize = 16;
/// X-Wing public keys are ML-KEM-768 (1184) || X25519 (32).
const X25519_OFFSET: usize = 1184;

/// Curve25519 points of order < 8 (RFC 7748 §6.1); each forces an all-zero X25519
/// shared secret, so the classical half of the hybrid would contribute nothing.
const SMALL_ORDER_POINTS: [[u8; 32]; 7] = [
    [0; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141,
        235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0,
    ],
    [
        95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196,
        88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87,
    ],
    [
        236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ],
    [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ],
    [
        238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ],
];
const ENCAPSULATION_LENGTH: usize = 1120;
const WRAPPED_KEY_LENGTH: usize = 48;
const SUITE: [u8; 2] = 1_u16.to_be_bytes();
const INFO_PREFIX: &[u8] = b"HIDE/0.1 object-key";

type HpkeSecret = <XWing as Kem>::PrivateKey;
type HpkePublic = <XWing as Kem>::PublicKey;
type HpkeEncapsulation = <XWing as Kem>::EncappedKey;

/// An error that contains no secret key material or plaintext.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("cryptographic authentication failed")]
    Authentication,
    #[error("recipient public key is degenerate")]
    DegeneratePublicKey,
    #[error("invalid cryptographic parameter")]
    InvalidParameter,
    #[error("operating-system randomness failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("HPKE operation failed: {0}")]
    Hpke(#[from] hpke::HpkeError),
    #[error("invalid {name} length: expected {expected}, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
}

/// A zeroizing content-encryption key, intentionally not Debug or Clone.
///
/// ```compile_fail,E0277
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<hide_crypto::ContentKey>();
/// ```
///
/// ```compile_fail,E0277
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<hide_crypto::ContentKey>();
/// ```
pub struct ContentKey(Zeroizing<[u8; KEY_LENGTH]>);

impl ContentKey {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(Zeroizing::new(random_array()?)))
    }

    /// Imports known bytes for deterministic test inputs only.
    /// Production callers must use `generate`; this cannot erase caller copies.
    pub fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// A zeroizing raw X-Wing seed, not HPKE `DeriveKeyPair` input material.
///
/// ```compile_fail,E0277
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<hide_crypto::RecipientSecret>();
/// ```
///
/// ```compile_fail,E0277
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<hide_crypto::RecipientSecret>();
/// ```
pub struct RecipientSecret(Zeroizing<[u8; KEY_LENGTH]>);

impl RecipientSecret {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(Zeroizing::new(random_array()?)))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        require_length("recipient seed", KEY_LENGTH, bytes.len())?;
        let mut seed = Zeroizing::new([0; KEY_LENGTH]);
        seed.copy_from_slice(bytes);
        Ok(Self(seed))
    }

    pub fn public_key(&self) -> Result<RecipientPublic, CryptoError> {
        let secret = HpkeSecret::from_bytes(self.0.as_ref())?;
        Ok(RecipientPublic(XWing::sk_to_pk(&secret)))
    }

    /// Exposes the raw seed so it can be sealed for storage. Deliberately named
    /// to make a plaintext write of the result look wrong at the call site.
    pub fn expose_seed_for_sealing(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Explicit secret export for this experimental CLI only.
    /// The caller must protect the result and avoid logging or copying it.
    pub fn export_test_secret(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }
}

/// An HPKE-validated X-Wing recipient public key.
#[derive(Clone, Debug)]
pub struct RecipientPublic(HpkePublic);

impl RecipientPublic {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let public = Self(HpkePublic::from_bytes(bytes)?);
        let x25519: [u8; 32] = bytes
            .get(X25519_OFFSET..)
            .and_then(|tail| tail.try_into().ok())
            .ok_or(CryptoError::DegeneratePublicKey)?;
        if SMALL_ORDER_POINTS.contains(&x25519) {
            return Err(CryptoError::DegeneratePublicKey);
        }
        Ok(public)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// Suite-1 encapsulation and authenticated encryption of a 32-byte CEK.
pub struct WrappedKey {
    pub encapsulation: Vec<u8>,
    pub wrapped_cek: Vec<u8>,
}

pub fn wrap_cek(
    recipient: &RecipientPublic,
    cek: &ContentKey,
    object_id: &[u8; 32],
) -> Result<WrappedKey, CryptoError> {
    let seed = Zeroizing::new(random_array::<32>()?);
    let mut rng = StdRng::from_seed(*seed);
    wrap_with_rng(recipient, cek, object_id, &mut rng)
}

fn wrap_with_rng(
    recipient: &RecipientPublic,
    cek: &ContentKey,
    object_id: &[u8; 32],
    rng: &mut impl CryptoRng,
) -> Result<WrappedKey, CryptoError> {
    let (info, aad) = object_context(object_id);
    let (encapsulation, mut context) = hpke::setup_sender_with_rng::<HpkeAead, HkdfSha256, XWing>(
        &OpModeS::Base,
        &recipient.0,
        &info,
        rng,
    )?;
    let mut ciphertext = Zeroizing::new(*cek.0);
    let tag = context.seal_inout_detached(ciphertext.as_mut_slice().into(), &aad)?;
    let mut wrapped_cek = Vec::with_capacity(WRAPPED_KEY_LENGTH);
    wrapped_cek.extend_from_slice(ciphertext.as_ref());
    wrapped_cek.extend_from_slice(&tag.to_bytes());
    Ok(WrappedKey {
        encapsulation: encapsulation.to_bytes().to_vec(),
        wrapped_cek,
    })
}

pub fn unwrap_cek(
    secret: &RecipientSecret,
    object_id: &[u8; 32],
    encapsulation: &[u8],
    wrapped_cek: &[u8],
) -> Result<ContentKey, CryptoError> {
    require_length("encapsulation", ENCAPSULATION_LENGTH, encapsulation.len())?;
    require_length("wrapped CEK", WRAPPED_KEY_LENGTH, wrapped_cek.len())?;
    let private_key = HpkeSecret::from_bytes(secret.0.as_ref())?;
    let encapsulation = HpkeEncapsulation::from_bytes(encapsulation)?;
    let (info, aad) = object_context(object_id);
    let mut context = hpke::setup_receiver::<HpkeAead, HkdfSha256, XWing>(
        &OpModeR::Base,
        &private_key,
        &encapsulation,
        &info,
    )?;
    let mut plaintext = Zeroizing::new([0; KEY_LENGTH]);
    plaintext.copy_from_slice(&wrapped_cek[..KEY_LENGTH]);
    let tag = AeadTag::<HpkeAead>::from_bytes(&wrapped_cek[KEY_LENGTH..])?;
    context.open_inout_detached(plaintext.as_mut_slice().into(), &aad, &tag)?;
    Ok(ContentKey(plaintext))
}

fn object_context(object_id: &[u8; 32]) -> (Vec<u8>, [u8; 34]) {
    let mut aad = [0; 34];
    aad[..32].copy_from_slice(object_id);
    aad[32..].copy_from_slice(&SUITE);
    let mut info = Vec::with_capacity(INFO_PREFIX.len() + aad.len());
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(&aad);
    (info, aad)
}

fn require_length(name: &'static str, expected: usize, actual: usize) -> Result<(), CryptoError> {
    if actual != expected {
        return Err(CryptoError::InvalidLength {
            name,
            expected,
            actual,
        });
    }
    Ok(())
}

pub fn random_array<const LENGTH: usize>() -> Result<[u8; LENGTH], CryptoError> {
    let mut bytes = Zeroizing::new([0; LENGTH]);
    getrandom::fill(bytes.as_mut_slice())?;
    Ok(*bytes)
}

/// A purpose-bound key derived from the content key; not Debug or Clone.
///
/// ```compile_fail,E0277
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<hide_crypto::DerivedKey>();
/// ```
///
/// ```compile_fail,E0277
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<hide_crypto::DerivedKey>();
/// ```
pub struct DerivedKey(Zeroizing<[u8; KEY_LENGTH]>);

/// Keeps one expanded AEAD instance so streaming does not rekey per chunk.
pub struct ChunkCipher(ChaCha20Poly1305);

impl ChunkCipher {
    pub fn new(key: &DerivedKey) -> Result<Self, CryptoError> {
        Ok(Self(
            ChaCha20Poly1305::new_from_slice(key.0.as_ref())
                .map_err(|_| CryptoError::InvalidParameter)?,
        ))
    }

    /// Encrypts `buffer[..length]` in place and appends the tag, returning the ciphertext length.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        length: usize,
    ) -> Result<usize, CryptoError> {
        let (plaintext, tail) = buffer
            .split_at_mut_checked(length)
            .ok_or(CryptoError::InvalidParameter)?;
        let tag = self
            .0
            .encrypt_inout_detached(nonce.into(), aad, plaintext.into())
            .map_err(|_| CryptoError::Authentication)?;
        tail.get_mut(..TAG_LENGTH)
            .ok_or(CryptoError::InvalidParameter)?
            .copy_from_slice(&tag);
        Ok(length + TAG_LENGTH)
    }

    /// Decrypts `buffer` in place, returning the authenticated plaintext length.
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let length = buffer
            .len()
            .checked_sub(TAG_LENGTH)
            .ok_or(CryptoError::InvalidParameter)?;
        let (ciphertext, tag) = buffer.split_at_mut(length);
        let tag =
            chacha20poly1305::Tag::try_from(&tag[..]).map_err(|_| CryptoError::InvalidParameter)?;
        self.0
            .decrypt_inout_detached(nonce.into(), aad, ciphertext.into(), &tag)
            .map_err(|_| CryptoError::Authentication)?;
        Ok(length)
    }
}

pub fn derive_key(cek: &ContentKey, salt: &[u8], info: &[u8]) -> Result<DerivedKey, CryptoError> {
    let mut key = Zeroizing::new([0; KEY_LENGTH]);
    Hkdf::<Sha256>::new(Some(salt), cek.0.as_ref())
        .expand(info, key.as_mut_slice())
        .map_err(|_| CryptoError::InvalidParameter)?;
    Ok(DerivedKey(key))
}

pub fn seal(
    key: &DerivedKey,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| CryptoError::InvalidParameter)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LENGTH));
    buffer.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(nonce.into(), aad, &mut *buffer)
        .map_err(|_| CryptoError::Authentication)?;
    Ok(core::mem::take(&mut *buffer))
}

pub fn open(
    key: &DerivedKey,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| CryptoError::InvalidParameter)?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(nonce.into(), aad, &mut *buffer)
        .map_err(|_| CryptoError::Authentication)?;
    Ok(buffer)
}

fn mac_state(key: &DerivedKey, parts: &[&[u8]]) -> Result<Hmac<Sha256>, CryptoError> {
    let mut state = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.0.as_ref())
        .map_err(|_| CryptoError::InvalidParameter)?;
    for part in parts {
        state.update(part);
    }
    Ok(state)
}

pub fn mac(key: &DerivedKey, parts: &[&[u8]]) -> Result<[u8; 32], CryptoError> {
    Ok(mac_state(key, parts)?.finalize().into_bytes().into())
}

pub fn verify_mac(key: &DerivedKey, parts: &[&[u8]], tag: &[u8; 32]) -> Result<(), CryptoError> {
    mac_state(key, parts)?
        .verify_slice(tag)
        .map_err(|_| CryptoError::Authentication)
}

pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut state = Sha256::new();
    for part in parts {
        state.update(part);
    }
    state.finalize().into()
}

/// Incremental form of [`hash`], for data that arrives in pieces.
#[derive(Default)]
pub struct Hasher(Sha256);

impl Hasher {
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

#[cfg(feature = "test-vectors")]
pub fn wrap_cek_for_vector(
    recipient: &RecipientPublic,
    cek: &ContentKey,
    object_id: &[u8; 32],
    seed: [u8; 32],
) -> Result<WrappedKey, CryptoError> {
    wrap_with_rng(recipient, cek, object_id, &mut StdRng::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_recipient_context_and_tampering() -> Result<(), CryptoError> {
        let recipient = RecipientSecret::generate()?;
        let other = RecipientSecret::generate()?;
        let cek = ContentKey::generate()?;
        let mut wrapped = wrap_cek(&recipient.public_key()?, &cek, &[1; 32])?;
        assert!(
            unwrap_cek(
                &other,
                &[1; 32],
                &wrapped.encapsulation,
                &wrapped.wrapped_cek
            )
            .is_err()
        );
        assert!(
            unwrap_cek(
                &recipient,
                &[2; 32],
                &wrapped.encapsulation,
                &wrapped.wrapped_cek
            )
            .is_err()
        );
        wrapped.encapsulation[0] ^= 1;
        assert!(
            unwrap_cek(
                &recipient,
                &[1; 32],
                &wrapped.encapsulation,
                &wrapped.wrapped_cek
            )
            .is_err()
        );
        wrapped.encapsulation[0] ^= 1;
        wrapped.wrapped_cek[0] ^= 1;
        assert!(
            unwrap_cek(
                &recipient,
                &[1; 32],
                &wrapped.encapsulation,
                &wrapped.wrapped_cek
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rfc5869_hkdf_known_answer() -> Result<(), CryptoError> {
        let salt: Vec<u8> = (0..13).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut output = [0; 42];
        Hkdf::<Sha256>::new(Some(&salt), &[0x0b; 22])
            .expand(&info, &mut output)
            .map_err(|_| CryptoError::InvalidParameter)?;
        assert_eq!(
            output,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
        Ok(())
    }

    #[test]
    fn rfc4231_hmac_known_answer_and_bad_tag() -> Result<(), CryptoError> {
        let mut bytes = [0; 32];
        bytes[..20].fill(0x0b);
        let key = DerivedKey(Zeroizing::new(bytes));
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac(&key, &[b"Hi There"])?, expected);
        verify_mac(&key, &[b"Hi There"], &expected)?;
        assert!(verify_mac(&key, &[b"Hi there"], &expected).is_err());
        Ok(())
    }

    #[test]
    fn aead_authenticates_nonce_aad_and_ciphertext() -> Result<(), CryptoError> {
        let cek = ContentKey::generate()?;
        let key = derive_key(&cek, b"salt", b"purpose")?;
        let mut ciphertext = seal(&key, &[0; 12], b"aad", b"payload")?;
        assert_eq!(&*open(&key, &[0; 12], b"aad", &ciphertext)?, b"payload");
        assert!(open(&key, &[1; 12], b"aad", &ciphertext).is_err());
        assert!(open(&key, &[0; 12], b"other", &ciphertext).is_err());
        ciphertext[0] ^= 1;
        assert!(open(&key, &[0; 12], b"aad", &ciphertext).is_err());
        Ok(())
    }

    #[test]
    fn in_place_cipher_matches_allocating_api() -> Result<(), CryptoError> {
        let cek = ContentKey::generate()?;
        let key = derive_key(&cek, b"salt", b"purpose")?;
        let cipher = ChunkCipher::new(&key)?;
        for length in [0, 1, 64, 4096] {
            let plaintext = vec![0x33; length];
            let mut buffer = vec![0; length + TAG_LENGTH];
            buffer[..length].copy_from_slice(&plaintext);
            let sealed = cipher.seal_in_place(&[9; 12], b"aad", &mut buffer, length)?;
            assert_eq!(buffer[..sealed], *seal(&key, &[9; 12], b"aad", &plaintext)?);
            assert_eq!(
                cipher.open_in_place(&[9; 12], b"aad", &mut buffer[..sealed])?,
                length
            );
            assert_eq!(buffer[..length], *plaintext);
            assert!(
                cipher
                    .open_in_place(&[8; 12], b"aad", &mut buffer[..sealed])
                    .is_err()
            );
            assert!(
                cipher
                    .open_in_place(&[9; 12], b"bad", &mut buffer[..sealed])
                    .is_err()
            );
        }
        assert!(
            cipher
                .open_in_place(&[9; 12], b"aad", &mut [0; 15])
                .is_err()
        );
        assert!(
            cipher
                .seal_in_place(&[9; 12], b"aad", &mut [0; 8], 4)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_small_order_x25519_public_keys() -> Result<(), CryptoError> {
        let genuine = RecipientSecret::from_bytes(&[0x21; 32])?
            .public_key()?
            .to_bytes();
        assert!(RecipientPublic::from_bytes(&genuine).is_ok());
        for point in SMALL_ORDER_POINTS {
            let mut bytes = genuine.clone();
            bytes[X25519_OFFSET..].copy_from_slice(&point);
            assert!(
                matches!(
                    RecipientPublic::from_bytes(&bytes),
                    Err(CryptoError::DegeneratePublicKey)
                ),
                "accepted small-order point {point:?}"
            );
        }
        assert!(RecipientPublic::from_bytes(&genuine[..1215]).is_err());
        assert!(RecipientPublic::from_bytes(&[]).is_err());
        Ok(())
    }

    #[test]
    fn suite_sizes_and_random_roundtrip() -> Result<(), CryptoError> {
        assert_eq!(XWing::KEM_ID, 0x647a);
        assert_eq!(HpkeSecret::size(), 32);
        assert_eq!(HpkePublic::size(), 1216);
        assert_eq!(HpkeEncapsulation::size(), 1120);
        let recipient = RecipientSecret::generate()?;
        let public = RecipientPublic::from_bytes(&recipient.public_key()?.to_bytes())?;
        let cek = ContentKey::generate()?;
        let object_id = random_array()?;
        let wrapped = wrap_cek(&public, &cek, &object_id)?;
        assert_eq!(wrapped.encapsulation.len(), 1120);
        assert_eq!(wrapped.wrapped_cek.len(), 48);
        let opened = unwrap_cek(
            &recipient,
            &object_id,
            &wrapped.encapsulation,
            &wrapped.wrapped_cek,
        )?;
        assert_eq!(*cek.0, *opened.0);
        Ok(())
    }

    #[test]
    fn raw_seed_import_export() -> Result<(), CryptoError> {
        let seed = [0x42; 32];
        let recipient = RecipientSecret::from_bytes(&seed)?;
        let direct = HpkeSecret::from_bytes(&seed)?;
        assert_eq!(&*recipient.export_test_secret(), &seed);
        assert_eq!(
            recipient.public_key()?.to_bytes(),
            XWing::sk_to_pk(&direct).to_bytes().to_vec()
        );
        assert!(RecipientSecret::from_bytes(&seed[..31]).is_err());
        assert!(RecipientSecret::from_bytes(&[0; 33]).is_err());
        Ok(())
    }
}
