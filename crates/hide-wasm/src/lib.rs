//! WebAssembly bindings for HIDE.
//!
//! EXPERIMENTAL AND UNAUDITED. Beyond the protocol's own limits, a browser is a
//! weaker place to hold a key than a desktop: any script that runs on the page
//! shares the heap, so an XSS bug is equivalent to key theft. Prefer the CLI or
//! the desktop application for keys that matter.

use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_keyring::{KeyFormat, KeyPurpose};
use hide_object::Metadata;
use hide_sign::{ChallengeError, VerifyingIdentity};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

pub const PUBLIC_KEY_LEN: usize = 1216;
pub const SIGNATURE_LEN: usize = hide_sign::SIGNATURE_LENGTH;
pub const VERIFYING_KEY_LEN: usize = hide_sign::VERIFYING_KEY_LENGTH;

/// Messages are held in memory; this bounds what a hostile length can allocate.
const MAX_INPUT: usize = 64 * 1024 * 1024;

/// A challenge is a nonce, a short audience and two timestamps. Anything
/// larger is not one, and must be refused before it is parsed.
const MAX_CHALLENGE: usize = 4096;

fn error(message: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

/// A secret key. The bytes never cross into JavaScript.
#[wasm_bindgen]
pub struct SecretKey {
    inner: RecipientSecret,
}

#[wasm_bindgen]
impl SecretKey {
    /// Generates a key pair using the browser's CSPRNG.
    pub fn generate() -> Result<SecretKey, JsValue> {
        Ok(SecretKey {
            inner: RecipientSecret::generate().map_err(error)?,
        })
    }

    /// Loads a key file. Pass the passphrase for a protected key; a protected
    /// key without one fails rather than guessing.
    pub fn load(data: &[u8], passphrase: Option<String>) -> Result<SecretKey, JsValue> {
        if data.len() > 4096 {
            return Err(error("that file is too large to be a HIDE key"));
        }
        let inner = hide_keyring::open(data, passphrase.as_deref()).map_err(error)?;
        Ok(SecretKey { inner })
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<Vec<u8>, JsValue> {
        Ok(self.inner.public_key().map_err(error)?.to_bytes())
    }

    /// Seals this key with a passphrase, for storage. A forgotten passphrase
    /// cannot be recovered.
    pub fn protect(&self, passphrase: &str) -> Result<Vec<u8>, JsValue> {
        hide_keyring::protect(&self.inner, passphrase).map_err(error)
    }
}

/// A verified payload. Receiving this means it authenticated.
#[wasm_bindgen]
pub struct Decrypted {
    data: Vec<u8>,
    filename: Option<String>,
    media_type: Option<String>,
}

#[wasm_bindgen]
impl Decrypted {
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn filename(&self) -> Option<String> {
        self.filename.clone()
    }

    #[wasm_bindgen(getter, js_name = mediaType)]
    pub fn media_type(&self) -> Option<String> {
        self.media_type.clone()
    }
}

fn parse_recipients(recipients: &[u8]) -> Result<Vec<RecipientPublic>, JsValue> {
    if recipients.is_empty() || recipients.len() % PUBLIC_KEY_LEN != 0 {
        return Err(error("recipients must be whole public keys"));
    }
    let count = recipients.len() / PUBLIC_KEY_LEN;
    if count > 64 {
        return Err(error("there must be between 1 and 64 recipients"));
    }
    recipients
        .chunks_exact(PUBLIC_KEY_LEN)
        .map(|chunk| RecipientPublic::from_bytes(chunk).map_err(error))
        .collect()
}

/// Encrypts for 1..64 recipients, passed as their concatenated public keys.
#[wasm_bindgen]
pub fn encrypt(
    plaintext: &[u8],
    recipients: &[u8],
    filename: Option<String>,
    media_type: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    if plaintext.len() > MAX_INPUT {
        return Err(error("that payload is too large for the browser build"));
    }
    let keys = parse_recipients(recipients)?;
    let metadata = Metadata {
        filename,
        media_type,
        signature: None,
    };
    let mut container = Vec::new();
    hide_object::encrypt(&mut &*plaintext, &mut container, &keys, &metadata).map_err(error)?;
    Ok(container)
}

/// Decrypts and verifies. Nothing is returned unless the whole payload
/// authenticates.
///
/// The filename is attacker-controlled: never use it to build a path, and
/// escape it before putting it in the DOM.
#[wasm_bindgen]
pub fn decrypt(container: &[u8], secret: &SecretKey) -> Result<Decrypted, JsValue> {
    if container.len() > MAX_INPUT {
        return Err(error("that container is too large for the browser build"));
    }
    let mut plaintext = Zeroizing::new(Vec::new());
    let verified =
        hide_object::decrypt_to_staging(&mut &*container, &mut *plaintext, &secret.inner)
            .map_err(error)?;
    Ok(Decrypted {
        data: std::mem::take(&mut *plaintext),
        filename: verified.metadata.filename,
        media_type: verified.metadata.media_type,
    })
}

#[wasm_bindgen(js_name = armorPublicKey)]
pub fn armor_public_key(public_key: &[u8]) -> Result<String, JsValue> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(error("that is not a HIDE public key"));
    }
    Ok(hide_keyring::encode_public(public_key))
}

#[wasm_bindgen(js_name = dearmorPublicKey)]
pub fn dearmor_public_key(text: &str) -> Result<Vec<u8>, JsValue> {
    let bytes = hide_keyring::decode_public(text).map_err(error)?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(error("that is not a HIDE public key"));
    }
    Ok(bytes)
}

/// Reports `"raw"` or `"protected"` without needing the passphrase.
#[wasm_bindgen(js_name = inspectKey)]
pub fn inspect_key(data: &[u8]) -> String {
    match hide_keyring::inspect(data) {
        KeyFormat::Protected => "protected".into(),
        KeyFormat::Raw => "raw".into(),
    }
}

/// A signing key. The seed never crosses into JavaScript.
#[wasm_bindgen]
pub struct SigningIdentity {
    inner: hide_sign::SigningIdentity,
}

#[wasm_bindgen]
impl SigningIdentity {
    /// Creates an identity and returns the sealed key file to store. One seed
    /// backs both encryption and signing, so there is a single thing to back
    /// up. A forgotten passphrase cannot be recovered.
    pub fn generate(passphrase: &str) -> Result<Vec<u8>, JsValue> {
        let identity = hide_keyring::Identity::generate().map_err(error)?;
        hide_keyring::protect_identity(identity.expose_seed_for_sealing(), passphrase)
            .map_err(error)
    }

    /// Opens a key file for signing. A file written before signatures existed
    /// carries no signing seed, and fails rather than being downgraded.
    pub fn load(data: &[u8], passphrase: Option<String>) -> Result<SigningIdentity, JsValue> {
        if data.len() > 4096 {
            return Err(error("that file is too large to be a HIDE key"));
        }
        let seed = match hide_keyring::inspect(data) {
            // An unprotected file is a master seed, exactly as the CLI writes
            // it, so it carries both keys.
            KeyFormat::Raw => {
                let mut seed = Zeroizing::new([0_u8; 32]);
                if data.len() != seed.len() {
                    return Err(error("that file is not a HIDE key"));
                }
                seed.copy_from_slice(data);
                seed
            }
            KeyFormat::Protected => {
                let passphrase =
                    passphrase.ok_or_else(|| error("that key file needs its passphrase"))?;
                let (seed, purpose) =
                    hide_keyring::unprotect_seed(data, &passphrase).map_err(error)?;
                if purpose != KeyPurpose::Identity {
                    return Err(error(
                        "that key predates signatures and holds no signing key; create a new identity",
                    ));
                }
                seed
            }
        };
        let signing = hide_keyring::Identity::from_seed(seed).signing_seed();
        Ok(SigningIdentity {
            inner: hide_sign::SigningIdentity::from_bytes(&*signing).map_err(error)?,
        })
    }

    /// The shareable verifying key, for others to check signatures with.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.verifying_key().to_bytes().to_vec()
    }

    /// Signs `message` under `context`. The context separates uses of one
    /// identity; never let a remote party choose it.
    pub fn sign(&self, context: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
        if message.len() > MAX_INPUT {
            return Err(error("that message is too large for the browser build"));
        }
        Ok(self.inner.sign(context, message).to_vec())
    }

    /// Answers a challenge, proving possession to whoever issued it.
    pub fn answer(&self, challenge: &[u8]) -> Result<Vec<u8>, JsValue> {
        Ok(decode_challenge(challenge)?.answer(&self.inner).to_vec())
    }
}

fn decode_challenge(bytes: &[u8]) -> Result<hide_sign::Challenge, JsValue> {
    if bytes.len() > MAX_CHALLENGE {
        return Err(error("that is too large to be a HIDE challenge"));
    }
    hide_sign::Challenge::decode(bytes).map_err(error)
}

/// Throws unless both halves verify. Returns nothing on success rather than a
/// boolean, so a caller that forgets to check cannot read failure as a pass.
#[wasm_bindgen]
pub fn verify(
    public_key: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), JsValue> {
    if message.len() > MAX_INPUT {
        return Err(error("that message is too large for the browser build"));
    }
    VerifyingIdentity::from_bytes(public_key)
        .map_err(error)?
        .verify(context, message, signature)
        .map_err(error)
}

/// Creates a challenge for a prover to answer.
///
/// A detached signature proves possession at some point, to nobody in
/// particular, and can be replayed. A challenge binds a random nonce, an
/// audience and an expiry, so an answer is good once, here, now.
#[wasm_bindgen(js_name = newChallenge)]
pub fn new_challenge(audience: &str, now: u64, valid_for: u64) -> Result<Vec<u8>, JsValue> {
    Ok(hide_sign::Challenge::new(audience, now, valid_for)
        .map_err(error)?
        .encode())
}

/// The verifier's record of answered challenges.
///
/// Replay can only be caught here: a replayed answer is a genuine signature
/// and nothing about it is invalid on its own. This must therefore outlive a
/// single request.
#[wasm_bindgen]
pub struct SpentNonces {
    inner: hide_sign::SpentNonces,
}

impl Default for SpentNonces {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl SpentNonces {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SpentNonces {
        SpentNonces {
            inner: hide_sign::SpentNonces::new(),
        }
    }

    /// Accepts an answer exactly once. Throws `"replayed"` the second time,
    /// `"expired"` after the window, and a verification failure otherwise.
    pub fn accept(
        &mut self,
        challenge: &[u8],
        signature: &[u8],
        public_key: &[u8],
        now: u64,
    ) -> Result<(), JsValue> {
        let challenge = decode_challenge(challenge)?;
        let prover = VerifyingIdentity::from_bytes(public_key).map_err(error)?;
        self.inner
            .accept(&challenge, signature, &prover, now)
            .map_err(|failure| {
                error(match failure {
                    ChallengeError::NotSigned => "signature verification failed",
                    ChallengeError::Expired => "expired",
                    ChallengeError::Replayed => "replayed",
                })
            })
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.inner.len()
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn round_trips_in_a_browser() {
        let secret = SecretKey::generate().expect("keygen");
        let public = secret.public_key().expect("public key");
        assert_eq!(public.len(), PUBLIC_KEY_LEN);

        let container = encrypt(
            b"salariu 9000",
            &public,
            Some("note.txt".into()),
            Some("text/plain".into()),
        )
        .expect("encrypt");
        assert!(
            !container.windows(7).any(|window| window == b"salariu"),
            "plaintext leaked into the container"
        );

        let opened = decrypt(&container, &secret).expect("decrypt");
        assert_eq!(opened.data(), b"salariu 9000");
        assert_eq!(opened.filename().as_deref(), Some("note.txt"));
    }

    #[wasm_bindgen_test]
    fn tampering_and_wrong_keys_are_refused() {
        let secret = SecretKey::generate().expect("keygen");
        let other = SecretKey::generate().expect("keygen");
        let public = secret.public_key().expect("public key");
        let container = encrypt(b"confidential", &public, None, None).expect("encrypt");

        assert!(decrypt(&container, &other).is_err(), "wrong key decrypted");

        let mut damaged = container.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(decrypt(&damaged, &secret).is_err(), "tampering accepted");
        assert!(
            decrypt(&container[..container.len() - 1], &secret).is_err(),
            "truncation accepted"
        );
    }

    #[wasm_bindgen_test]
    fn protected_keys_need_their_passphrase() {
        let secret = SecretKey::generate().expect("keygen");
        let public = secret.public_key().expect("public key");
        let sealed = secret.protect("correct horse battery").expect("protect");

        assert_eq!(inspect_key(&sealed), "protected");
        assert!(SecretKey::load(&sealed, None).is_err());
        assert!(SecretKey::load(&sealed, Some("wrong".into())).is_err());

        let reopened =
            SecretKey::load(&sealed, Some("correct horse battery".into())).expect("reopen");
        assert_eq!(reopened.public_key().expect("public key"), public);
    }

    #[wasm_bindgen_test]
    fn armor_round_trips_and_recipients_are_bounded() {
        let secret = SecretKey::generate().expect("keygen");
        let public = secret.public_key().expect("public key");

        let text = armor_public_key(&public).expect("armor");
        assert!(text.starts_with("hide-public-key:"));
        assert_eq!(dearmor_public_key(&text).expect("dearmor"), public);
        assert!(dearmor_public_key("not a key").is_err());

        assert!(encrypt(b"x", &[], None, None).is_err(), "no recipients");
        assert!(
            encrypt(b"x", &public[..100], None, None).is_err(),
            "partial key accepted"
        );
    }

    fn identity(passphrase: &str) -> SigningIdentity {
        let sealed = SigningIdentity::generate(passphrase).expect("generate");
        SigningIdentity::load(&sealed, Some(passphrase.into())).expect("load")
    }

    #[wasm_bindgen_test]
    fn signs_and_verifies() {
        let signer = identity("correct horse battery");
        let public = signer.public_key();
        assert_eq!(public.len(), VERIFYING_KEY_LEN);

        let signature = signer.sign(b"hide/test", b"invoice 42").expect("sign");
        assert_eq!(signature.len(), SIGNATURE_LEN);
        verify(&public, b"hide/test", b"invoice 42", &signature).expect("verify");

        assert!(
            verify(&public, b"hide/test", b"invoice 43", &signature).is_err(),
            "a changed message verified"
        );
        assert!(
            verify(&public, b"hide/other", b"invoice 42", &signature).is_err(),
            "a different context verified"
        );

        let other = identity("a different passphrase");
        assert!(
            verify(&other.public_key(), b"hide/test", b"invoice 42", &signature).is_err(),
            "one identity was impersonated by another"
        );
    }

    #[wasm_bindgen_test]
    fn encryption_only_keys_cannot_sign() {
        let secret = SecretKey::generate().expect("keygen");
        let sealed = secret.protect("correct horse battery").expect("protect");
        assert!(
            SigningIdentity::load(&sealed, Some("correct horse battery".into())).is_err(),
            "an encryption-only key was accepted for signing"
        );
    }

    #[wasm_bindgen_test]
    fn a_challenge_is_answered_once() {
        let prover = identity("correct horse battery");
        let public = prover.public_key();
        let challenge = new_challenge("hide.example", 1_000, 60).expect("challenge");
        let answer = prover.answer(&challenge).expect("answer");

        let mut spent = SpentNonces::new();
        spent
            .accept(&challenge, &answer, &public, 1_010)
            .expect("first answer");
        assert!(
            spent.accept(&challenge, &answer, &public, 1_020).is_err(),
            "a replayed answer was accepted"
        );
    }

    #[wasm_bindgen_test]
    fn an_answer_after_the_window_expires() {
        let prover = identity("correct horse battery");
        let challenge = new_challenge("hide.example", 1_000, 60).expect("challenge");
        let answer = prover.answer(&challenge).expect("answer");

        let mut spent = SpentNonces::new();
        assert!(
            spent
                .accept(&challenge, &answer, &prover.public_key(), 2_000)
                .is_err(),
            "an expired answer was accepted"
        );
    }
}
