//! WebAssembly bindings for HIDE.
//!
//! EXPERIMENTAL AND UNAUDITED. Beyond the protocol's own limits, a browser is a
//! weaker place to hold a key than a desktop: any script that runs on the page
//! shares the heap, so an XSS bug is equivalent to key theft. Prefer the CLI or
//! the desktop application for keys that matter.

use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_keyring::KeyFormat;
use hide_object::Metadata;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

pub const PUBLIC_KEY_LEN: usize = 1216;

/// Messages are held in memory; this bounds what a hostile length can allocate.
const MAX_INPUT: usize = 64 * 1024 * 1024;

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
}
