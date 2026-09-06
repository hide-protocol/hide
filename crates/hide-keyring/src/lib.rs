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
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"HIDE-KEY";
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + SALT_LEN + NONCE_LEN;
const SEALED_LEN: usize = HEADER_LEN + SEED_LEN + TAG_LEN;

/// OWASP's 2024 baseline for Argon2id. Stored per file so raising these later
/// does not orphan existing keys.
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;

/// Refuse absurd parameters from a malicious file before allocating for them.
const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;

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
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
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

/// Seals `secret` under `passphrase`.
pub fn protect(secret: &RecipientSecret, passphrase: &str) -> Result<Vec<u8>, KeyringError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(KeyringError::PassphraseTooShort(MIN_PASSPHRASE_LEN));
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
    debug_assert_eq!(header.len(), HEADER_LEN);

    let wrapping = derive(passphrase, &salt, MEMORY_KIB, ITERATIONS, PARALLELISM)?;
    let cipher = ChaCha20Poly1305::new((&*wrapping).into());
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret.expose_seed_for_sealing(),
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;

    let mut output = header;
    output.extend_from_slice(&sealed);
    Ok(output)
}

/// Opens a key file, with or without a passphrase depending on its format.
pub fn open(bytes: &[u8], passphrase: Option<&str>) -> Result<RecipientSecret, KeyringError> {
    match inspect(bytes) {
        KeyFormat::Raw => Ok(RecipientSecret::from_bytes(bytes)?),
        KeyFormat::Protected => {
            let passphrase = passphrase.ok_or(KeyringError::WrongPassphrase)?;
            unprotect(bytes, passphrase)
        }
    }
}

pub fn unprotect(bytes: &[u8], passphrase: &str) -> Result<RecipientSecret, KeyringError> {
    if !bytes.starts_with(MAGIC) {
        return Err(KeyringError::NotAKeyFile);
    }
    if bytes.len() != SEALED_LEN {
        return Err(KeyringError::Malformed);
    }
    let version = bytes[8];
    if version != FORMAT_VERSION {
        return Err(KeyringError::UnsupportedVersion(version));
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
    if parallelism == 0 || memory > MAX_MEMORY_KIB || iterations == 0 || iterations > MAX_ITERATIONS
    {
        return Err(KeyringError::UnreasonableParameters);
    }

    let salt = &bytes[18..18 + SALT_LEN];
    let nonce = &bytes[18 + SALT_LEN..HEADER_LEN];
    let header = &bytes[..HEADER_LEN];

    let wrapping = derive(passphrase, salt, memory, iterations, parallelism)?;
    let cipher = ChaCha20Poly1305::new((&*wrapping).into());
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KeyringError::Malformed)?;
    let seed = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &bytes[HEADER_LEN..],
                aad: header,
            },
        )
        .map_err(|_| KeyringError::WrongPassphrase)?;

    let seed = Zeroizing::new(seed);
    Ok(RecipientSecret::from_bytes(&seed)?)
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

    #[test]
    fn raw_keys_still_open_without_a_passphrase() -> Result<(), KeyringError> {
        let raw = secret().expose_seed_for_sealing().to_vec();
        assert_eq!(inspect(&raw), KeyFormat::Raw);
        assert_eq!(open(&raw, None)?.expose_seed_for_sealing(), raw);
        assert_eq!(
            error_of(open(&protect(&secret(), "correct horse battery")?, None)),
            KeyringError::WrongPassphrase
        );
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
