//! Password-protected storage for HIDE secret keys.
//!
//! `hide-crypto` deliberately knows nothing about files or passwords. This crate
//! adds the at-rest layer: Argon2id stretches a passphrase into a wrapping key,
//! which seals the 32-byte recipient seed with ChaCha20-Poly1305.
//!
//! This protects a key file at rest. It is not a hardware-backed vault: while a
//! key is in use it lives in ordinary process memory.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hide_crypto::{CryptoError, RecipientSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"HIDE-KEY";
/// Version 1 sealed a bare recipient seed. Version 2 adds a purpose byte, so a
/// signing key and an encryption key are no longer byte-indistinguishable.
const FORMAT_VERSION: u8 = 2;
const LEGACY_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;
const TAG_LEN: usize = 16;
const LEGACY_HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + SALT_LEN + NONCE_LEN;
const HEADER_LEN: usize = LEGACY_HEADER_LEN + 1;
const SEALED_LEN: usize = HEADER_LEN + SEED_LEN + TAG_LEN;
const LEGACY_SEALED_LEN: usize = LEGACY_HEADER_LEN + SEED_LEN + TAG_LEN;

/// OWASP's 2024 baseline for Argon2id. Stored per file so raising these later
/// does not orphan existing keys.
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

/// Refuse absurd parameters from a malicious file before allocating for them.
const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
/// And refuse parameters so weak the passphrase is effectively unprotected. The
/// header is authenticated, so this cannot be a downgrade of an honest file;
/// it stops a file written by a careless or hostile implementation from
/// opening without complaint. 8 MiB is the Argon2 RFC 9106 second recommended
/// configuration's floor for memory-constrained environments.
pub const MIN_MEMORY_KIB: u32 = 8 * 1024;
pub const MIN_ITERATIONS: u32 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyringError {
    #[error("not a HIDE key file")]
    NotAKeyFile,
    #[error("unsupported key file version {0}")]
    UnsupportedVersion(u8),
    #[error("key file is malformed")]
    Malformed,
    #[error("key file requests unreasonable Argon2 parameters")]
    UnreasonableParameters,
    #[error("incorrect passphrase, or the key file has been modified")]
    WrongPassphrase,
    #[error("passphrase must be at least {0} characters")]
    PassphraseTooShort(usize),
    #[error("this is a {found} key, but a {expected} key is required")]
    WrongPurpose {
        expected: KeyPurpose,
        found: KeyPurpose,
    },
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
}

/// What a sealed seed is for. Stored in the file so the wrong key cannot be
/// used silently against the right command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// A master seed from which both the encryption and signing keys derive.
    Identity,
    /// A bare recipient seed, as written by v0.4.0 and earlier.
    Encryption,
}

impl KeyPurpose {
    fn tag(self) -> u8 {
        match self {
            Self::Identity => 1,
            Self::Encryption => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Identity),
            2 => Some(Self::Encryption),
            _ => None,
        }
    }
}

impl core::fmt::Display for KeyPurpose {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Identity => "HIDE identity",
            Self::Encryption => "encryption-only",
        })
    }
}

impl From<CryptoError> for KeyringError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error.to_string())
    }
}

pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Whether a stored key needs a passphrase, so a caller can prompt only when needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    Protected,
    Raw,
}

pub fn inspect(bytes: &[u8]) -> KeyFormat {
    if bytes.starts_with(MAGIC) {
        KeyFormat::Protected
    } else {
        KeyFormat::Raw
    }
}

/// Seals `secret` under `passphrase` as an encryption-only key.
pub fn protect(secret: &RecipientSecret, passphrase: &str) -> Result<Vec<u8>, KeyringError> {
    protect_seed(
        secret.expose_seed_for_sealing(),
        passphrase,
        KeyPurpose::Encryption,
    )
}

/// Seals a master identity seed, from which both keys derive.
pub fn protect_identity(seed: &[u8; SEED_LEN], passphrase: &str) -> Result<Vec<u8>, KeyringError> {
    protect_seed(seed, passphrase, KeyPurpose::Identity)
}

fn protect_seed(
    seed: &[u8],
    passphrase: &str,
    purpose: KeyPurpose,
) -> Result<Vec<u8>, KeyringError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(KeyringError::PassphraseTooShort(MIN_PASSPHRASE_LEN));
    }
    if seed.len() != SEED_LEN {
        return Err(KeyringError::Malformed);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|error| KeyringError::Crypto(error.to_string()))?;
    getrandom::fill(&mut nonce).map_err(|error| KeyringError::Crypto(error.to_string()))?;

    let mut header = Vec::with_capacity(SEALED_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.push(PARALLELISM as u8);
    header.extend_from_slice(&MEMORY_KIB.to_be_bytes());
    header.extend_from_slice(&ITERATIONS.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.push(purpose.tag());
    debug_assert_eq!(header.len(), HEADER_LEN);

    let wrapping = derive(passphrase, &salt, MEMORY_KIB, ITERATIONS, PARALLELISM)?;
    let cipher = ChaCha20Poly1305::new((&*wrapping).into());
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: seed,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;

    let mut output = header;
    output.extend_from_slice(&sealed);
    Ok(output)
}

/// Opens a key file and returns the encryption key, whatever shape the file is.
///
/// Every surface must read a key file the same way. A raw file is a master
/// seed, exactly as the CLI writes it, so the encryption key is derived rather
/// than being the file's bytes; reading those bytes directly yields a
/// different key and silently breaks interoperability.
pub fn open(bytes: &[u8], passphrase: Option<&str>) -> Result<RecipientSecret, KeyringError> {
    match inspect(bytes) {
        KeyFormat::Raw => {
            let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
            if bytes.len() != SEED_LEN {
                return Err(KeyringError::Malformed);
            }
            seed.copy_from_slice(bytes);
            Identity::from_seed(seed).recipient_secret()
        }
        KeyFormat::Protected => {
            let passphrase = passphrase.ok_or(KeyringError::WrongPassphrase)?;
            let (seed, purpose) = unprotect_seed(bytes, passphrase)?;
            match purpose {
                // An identity holds both keys; asking for the encryption one is
                // not a purpose mismatch.
                KeyPurpose::Identity => Identity::from_seed(seed).recipient_secret(),
                KeyPurpose::Encryption => Ok(RecipientSecret::from_bytes(&seed[..])?),
            }
        }
    }
}

/// A master seed, and the two independent keys derived from it.
///
/// Derivation is one-way and domain-separated, so recovering the signing key
/// from the encryption key (or the reverse) is not possible without the master.
pub struct Identity {
    seed: Zeroizing<[u8; SEED_LEN]>,
}

const ENCRYPTION_INFO: &[u8] = b"HIDE/0.5 identity encryption";
const SIGNING_INFO: &[u8] = b"HIDE/0.5 identity signing";

impl Identity {
    pub fn generate() -> Result<Self, KeyringError> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::fill(&mut *seed).map_err(|error| KeyringError::Crypto(error.to_string()))?;
        Ok(Self { seed })
    }

    pub fn from_seed(seed: Zeroizing<[u8; SEED_LEN]>) -> Self {
        Self { seed }
    }

    pub fn expose_seed_for_sealing(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    pub fn recipient_secret(&self) -> Result<RecipientSecret, KeyringError> {
        let seed = self.derive(ENCRYPTION_INFO);
        Ok(RecipientSecret::from_bytes(&seed[..])?)
    }

    pub fn signing_seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        self.derive(SIGNING_INFO)
    }

    fn derive(&self, info: &[u8]) -> Zeroizing<[u8; SEED_LEN]> {
        let mut out = Zeroizing::new([0u8; SEED_LEN]);
        Hkdf::<Sha256>::from_prk(&*self.seed)
            .expect("32 bytes is a valid PRK for SHA-256")
            .expand(info, &mut *out)
            .expect("32 bytes is a valid HKDF output length");
        out
    }
}

pub fn unprotect(bytes: &[u8], passphrase: &str) -> Result<RecipientSecret, KeyringError> {
    let (seed, purpose) = unprotect_seed(bytes, passphrase)?;
    // A v1 file has no purpose byte and predates signing, so it is encryption-only.
    if purpose != KeyPurpose::Encryption {
        return Err(KeyringError::WrongPurpose {
            expected: KeyPurpose::Encryption,
            found: purpose,
        });
    }
    Ok(RecipientSecret::from_bytes(&seed[..])?)
}

/// Opens a sealed seed and reports what it is for, so a caller can refuse a key
/// of the wrong purpose with a message that names the mismatch.
pub fn unprotect_seed(
    bytes: &[u8],
    passphrase: &str,
) -> Result<(Zeroizing<[u8; SEED_LEN]>, KeyPurpose), KeyringError> {
    if !bytes.starts_with(MAGIC) {
        return Err(KeyringError::NotAKeyFile);
    }
    let version = *bytes.get(8).ok_or(KeyringError::Malformed)?;
    let (header_len, expected_len) = match version {
        FORMAT_VERSION => (HEADER_LEN, SEALED_LEN),
        LEGACY_VERSION => (LEGACY_HEADER_LEN, LEGACY_SEALED_LEN),
        other => return Err(KeyringError::UnsupportedVersion(other)),
    };
    if bytes.len() != expected_len {
        return Err(KeyringError::Malformed);
    }

    let parallelism = u32::from(bytes[9]);
    let memory = u32::from_be_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| KeyringError::Malformed)?,
    );
    let iterations = u32::from_be_bytes(
        bytes[14..18]
            .try_into()
            .map_err(|_| KeyringError::Malformed)?,
    );
    if parallelism == 0
        || !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory)
        || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
    {
        return Err(KeyringError::UnreasonableParameters);
    }

    let purpose = if version == LEGACY_VERSION {
        KeyPurpose::Encryption
    } else {
        KeyPurpose::from_tag(bytes[LEGACY_HEADER_LEN]).ok_or(KeyringError::Malformed)?
    };

    let salt = &bytes[18..18 + SALT_LEN];
    let nonce = &bytes[18 + SALT_LEN..18 + SALT_LEN + NONCE_LEN];
    let header = &bytes[..header_len];

    let wrapping = derive(passphrase, salt, memory, iterations, parallelism)?;
    let cipher = ChaCha20Poly1305::new((&*wrapping).into());
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KeyringError::Malformed)?;
    let seed = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &bytes[header_len..],
                aad: header,
            },
        )
        .map_err(|_| KeyringError::WrongPassphrase)?;

    let mut out = Zeroizing::new([0u8; SEED_LEN]);
    out.copy_from_slice(&Zeroizing::new(seed)[..]);
    Ok((out, purpose))
}

/// Base64 wrapper so a public key can be pasted into a message or a chat.
pub fn encode_public(bytes: &[u8]) -> String {
    let body = STANDARD.encode(bytes);
    let mut out = String::from("hide-public-key:");
    for (index, chunk) in body.as_bytes().chunks(64).enumerate() {
        out.push('\n');
        let _ = index;
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out.push('\n');
    out
}

pub fn decode_public(text: &str) -> Result<Vec<u8>, KeyringError> {
    let body: String = text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with("hide-public-key:"))
        .collect();
    STANDARD
        .decode(body.trim())
        .map_err(|_| KeyringError::Malformed)
}

fn derive(
    passphrase: &str,
    salt: &[u8],
    memory: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>, KeyringError> {
    let params = Params::new(memory, iterations, parallelism, Some(32))
        .map_err(|_| KeyringError::UnreasonableParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| KeyringError::UnreasonableParameters)?;
    Ok(key)
}

/// Silences an unused-import warning when the AEAD trait bounds change upstream.
const _: fn() = || {
    fn assert_aead<T: AeadCore>() {}
    assert_aead::<ChaCha20Poly1305>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> RecipientSecret {
        RecipientSecret::from_bytes(&[0x42; 32]).expect("seed")
    }

    /// Secrets deliberately do not implement `Debug`, so `unwrap_err` cannot be
    /// used on a `Result` carrying one.
    fn error_of<T>(result: Result<T, KeyringError>) -> KeyringError {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(error) => error,
        }
    }

    #[test]
    fn round_trips_under_the_correct_passphrase() -> Result<(), KeyringError> {
        let sealed = protect(&secret(), "correct horse battery")?;
        assert_eq!(inspect(&sealed), KeyFormat::Protected);
        assert_eq!(
            unprotect(&sealed, "correct horse battery")?.expose_seed_for_sealing(),
            secret().expose_seed_for_sealing()
        );
        Ok(())
    }

    #[test]
    fn wrong_passphrase_and_tampering_both_fail() -> Result<(), KeyringError> {
        let sealed = protect(&secret(), "correct horse battery")?;
        assert_eq!(
            error_of(unprotect(&sealed, "wrong horse battery")),
            KeyringError::WrongPassphrase
        );

        // Every byte is authenticated, including the Argon2 parameters.
        for index in 0..sealed.len() {
            let mut damaged = sealed.clone();
            damaged[index] ^= 0x01;
            assert!(
                unprotect(&damaged, "correct horse battery").is_err(),
                "accepted a mutation at byte {index}"
            );
        }
        Ok(())
    }

    #[test]
    fn each_file_is_unique_and_length_is_fixed() -> Result<(), KeyringError> {
        let first = protect(&secret(), "correct horse battery")?;
        let second = protect(&secret(), "correct horse battery")?;
        assert_ne!(first, second, "salt or nonce was reused");
        assert_eq!(first.len(), SEALED_LEN);
        assert_eq!(second.len(), SEALED_LEN);
        Ok(())
    }

    #[test]
    fn rejects_short_passphrases_and_foreign_files() {
        assert_eq!(
            protect(&secret(), "short").unwrap_err(),
            KeyringError::PassphraseTooShort(MIN_PASSPHRASE_LEN)
        );
        assert_eq!(
            error_of(unprotect(b"not a key file", "whatever")),
            KeyringError::NotAKeyFile
        );
        assert_eq!(
            error_of(unprotect(MAGIC, "whatever")),
            KeyringError::Malformed
        );
    }

    #[test]
    fn refuses_a_file_demanding_absurd_memory() -> Result<(), KeyringError> {
        let mut sealed = protect(&secret(), "correct horse battery")?;
        sealed[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            error_of(unprotect(&sealed, "correct horse battery")),
            KeyringError::UnreasonableParameters
        );
        Ok(())
    }

    // The header is authenticated, so an honest file cannot be downgraded; this
    // catches a file that was WRITTEN weak, which would otherwise open silently.
    #[test]
    fn refuses_a_file_written_with_too_little_memory() -> Result<(), KeyringError> {
        let mut sealed = protect(&secret(), "correct horse battery")?;
        sealed[10..14].copy_from_slice(&(MIN_MEMORY_KIB - 1).to_be_bytes());
        assert_eq!(
            error_of(unprotect(&sealed, "correct horse battery")),
            KeyringError::UnreasonableParameters
        );
        Ok(())
    }

    #[test]
    fn raw_keys_still_open_without_a_passphrase() -> Result<(), KeyringError> {
        let raw = secret().expose_seed_for_sealing().to_vec();
        let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
        seed.copy_from_slice(&raw);
        let expected = Identity::from_seed(seed).recipient_secret()?;
        assert_eq!(inspect(&raw), KeyFormat::Raw);
        // A raw file is a master seed, so the encryption key is derived from
        // it. Reading the bytes as the key itself is what broke CLI/SDK
        // interoperability: every surface must agree with the CLI here.
        assert_eq!(
            open(&raw, None)?.public_key()?.to_bytes(),
            expected.public_key()?.to_bytes()
        );
        assert_ne!(open(&raw, None)?.expose_seed_for_sealing(), raw);
        assert_eq!(
            error_of(open(&protect(&secret(), "correct horse battery")?, None)),
            KeyringError::WrongPassphrase
        );
        Ok(())
    }

    /// A key file written by v0.4.0 has no purpose byte. It must still open, or
    /// every existing user loses access to their encrypted data.
    #[test]
    fn v1_key_files_still_open_and_read_as_encryption_only() -> Result<(), KeyringError> {
        // Rebuild a v1 file exactly as the previous release wrote it.
        let seed = [0x31; SEED_LEN];
        let salt = [0x32; SALT_LEN];
        let nonce = [0x33; NONCE_LEN];
        let mut header = Vec::new();
        header.extend_from_slice(MAGIC);
        header.push(LEGACY_VERSION);
        header.push(PARALLELISM as u8);
        header.extend_from_slice(&MEMORY_KIB.to_be_bytes());
        header.extend_from_slice(&ITERATIONS.to_be_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        assert_eq!(header.len(), LEGACY_HEADER_LEN);

        let wrapping = derive(
            "correct horse battery",
            &salt,
            MEMORY_KIB,
            ITERATIONS,
            PARALLELISM,
        )?;
        let sealed = ChaCha20Poly1305::new((&*wrapping).into())
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &seed,
                    aad: &header,
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        let mut file = header;
        file.extend_from_slice(&sealed);
        assert_eq!(file.len(), LEGACY_SEALED_LEN);

        let (opened, purpose) = unprotect_seed(&file, "correct horse battery")?;
        assert_eq!(&opened[..], &seed);
        assert_eq!(purpose, KeyPurpose::Encryption);
        // And through the typed path that predates this change.
        unprotect(&file, "correct horse battery")?;
        Ok(())
    }

    #[test]
    fn an_identity_key_is_refused_where_an_encryption_key_is_required() -> Result<(), KeyringError>
    {
        let identity = Identity::generate()?;
        let file = protect_identity(identity.expose_seed_for_sealing(), "correct horse battery")?;
        assert_eq!(
            error_of(unprotect(&file, "correct horse battery")),
            KeyringError::WrongPurpose {
                expected: KeyPurpose::Encryption,
                found: KeyPurpose::Identity,
            }
        );
        Ok(())
    }

    #[test]
    fn an_identity_round_trips_and_derives_stable_keys() -> Result<(), KeyringError> {
        let identity = Identity::generate()?;
        let file = protect_identity(identity.expose_seed_for_sealing(), "correct horse battery")?;
        let (seed, purpose) = unprotect_seed(&file, "correct horse battery")?;
        assert_eq!(purpose, KeyPurpose::Identity);

        let reopened = Identity::from_seed(seed);
        assert_eq!(
            reopened.recipient_secret()?.public_key()?.to_bytes(),
            identity.recipient_secret()?.public_key()?.to_bytes()
        );
        assert_eq!(&*reopened.signing_seed(), &*identity.signing_seed());
        Ok(())
    }

    /// The point of deriving both from one master: neither derived key may equal
    /// the master, or each other, or the whole separation is decorative.
    #[test]
    fn the_two_derived_keys_are_independent_of_each_other_and_the_master()
    -> Result<(), KeyringError> {
        let identity = Identity::generate()?;
        let master = *identity.expose_seed_for_sealing();
        let signing = identity.signing_seed();
        let encryption = identity.derive(ENCRYPTION_INFO);

        assert_ne!(&*signing, &master);
        assert_ne!(&*encryption, &master);
        assert_ne!(&*signing, &*encryption);
        Ok(())
    }

    #[test]
    fn public_key_armor_round_trips() -> Result<(), KeyringError> {
        let public = secret().public_key()?.to_bytes();
        let armored = encode_public(&public);
        assert!(armored.starts_with("hide-public-key:"));
        assert!(armored.lines().skip(1).all(|line| line.len() <= 64));
        assert_eq!(decode_public(&armored)?, public);
        assert!(decode_public("hide-public-key:\n!!!not base64!!!").is_err());
        Ok(())
    }
}
