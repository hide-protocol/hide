//! One passphrase-sealed file holding every live epoch secret.
//!
//! `hide-epoch` gives forward security by erasure, but only for as long as the
//! process lives: its secrets are deliberately not encodable. This store is the
//! at-rest half. It seals each epoch seed under a key stretched from a
//! passphrase, and erasing an epoch means resealing the file without it, so the
//! store that remains on disk holds no copy — readable or sealed — of that seed.
//!
//! Layout (implementation-defined; described in `spec/hide-1.md` §14):
//!
//! ```text
//! "HIDE-EPK" || version u8 = 1 || parallelism u8 || memory_kib u32be ||
//! iterations u32be || salt[16] || chain_head[32] || body_len u32be ||
//! body || trailer_nonce[12] || trailer_tag[16]
//! ```
//!
//! `header` is everything before `body`. `body` is a canonical CBOR array of
//! `[number, nonce bstr(12), sealed bstr(48)]`, strictly ascending by number.
//! Each `sealed` is ChaCha20-Poly1305 of the 32-byte seed under the Argon2id
//! key, with `header || u64be(number)` as associated data. The trailer is the
//! same AEAD over an empty plaintext with `header || body` as associated data.
//!
//! What this does not do: it cannot reach an older copy of the file. Every seal
//! uses a fresh salt, so an old copy needs its own old salt and the passphrase,
//! but a backup, a filesystem snapshot or an SSD's remapped blocks may still
//! hold one, and whoever has that copy and the passphrase has the epochs it
//! held. Erasure here is exactly as strong as the storage underneath.

use std::collections::BTreeMap;

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Tag, aead::AeadInOut};
use hide_crypto::RecipientSecret;
use zeroize::Zeroizing;

use crate::{Argon2Params, KeyringError, MIN_PASSPHRASE_LEN, PARAMS_LEN};

pub const MAGIC: &[u8; 8] = b"HIDE-EPK";
pub const VERSION: u8 = 1;

const SALT_LEN: usize = 16;
const HEAD_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;
const TAG_LEN: usize = 16;
const SEALED_LEN: usize = SEED_LEN + TAG_LEN;

const PARAMS_AT: usize = MAGIC.len() + 1;
const SALT_AT: usize = PARAMS_AT + PARAMS_LEN;
const HEAD_AT: usize = SALT_AT + SALT_LEN;
const BODY_LEN_AT: usize = HEAD_AT + HEAD_LEN;
/// Everything before the body, and the associated-data prefix of every seal.
pub const HEADER_LEN: usize = BODY_LEN_AT + 4;
pub const TRAILER_LEN: usize = NONCE_LEN + TAG_LEN;

/// Far beyond any honest retention window (a key per hour for seven years),
/// and small enough that a maximal file stays under 5 MiB.
pub const MAX_ENTRIES: usize = 65_536;

/// Smallest canonical entry: array(3), a one-byte number, bstr(12), bstr(48).
/// Only used to cap how much a declared count may pre-reserve.
const MIN_ENTRY_BYTES: usize = 1 + 1 + (1 + NONCE_LEN) + (2 + SEALED_LEN);
/// Largest canonical entry: the number takes nine bytes.
const MAX_ENTRY_BYTES: usize = 1 + 9 + (1 + NONCE_LEN) + (2 + SEALED_LEN);
/// A five-byte array header plus `MAX_ENTRIES` maximal entries.
const MAX_BODY_LEN: usize = 5 + MAX_ENTRIES * MAX_ENTRY_BYTES;
/// A reader can refuse anything larger without parsing it.
pub const MAX_FILE_LEN: usize = HEADER_LEN + MAX_BODY_LEN + TRAILER_LEN;

/// Every epoch secret a recipient still holds, plus the chain head they belong to.
///
/// Not `Debug`, `Clone` or serialisable: a copy is a second thing to erase.
/// Each seed lives in a `RecipientSecret`, which zeroizes on drop.
///
/// ```compile_fail,E0277
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<hide_keyring::EpochStore>();
/// ```
///
/// ```compile_fail,E0277
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<hide_keyring::EpochStore>();
/// ```
pub struct EpochStore {
    chain_head: [u8; HEAD_LEN],
    entries: BTreeMap<u64, RecipientSecret>,
}

impl EpochStore {
    /// An empty store for the chain whose latest link is `chain_head`.
    pub fn new(chain_head: [u8; HEAD_LEN]) -> Self {
        Self {
            chain_head,
            entries: BTreeMap::new(),
        }
    }

    /// Stores a copy of `secret` as epoch `number`, replacing any previous one.
    pub fn insert(&mut self, number: u64, secret: &RecipientSecret) -> Result<(), KeyringError> {
        if !self.entries.contains_key(&number) && self.entries.len() >= MAX_ENTRIES {
            return Err(KeyringError::TooManyEntries(MAX_ENTRIES));
        }
        let copy = RecipientSecret::from_bytes(secret.expose_seed_for_sealing())?;
        self.entries.insert(number, copy);
        Ok(())
    }

    /// Drops epoch `number`. It leaves storage only when the store is sealed
    /// again and that output replaces the old file.
    pub fn remove(&mut self, number: u64) -> bool {
        self.entries.remove(&number).is_some()
    }

    pub fn get(&self, number: u64) -> Option<&RecipientSecret> {
        self.entries.get(&number)
    }

    /// Held epoch numbers, ascending.
    pub fn numbers(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.keys().copied()
    }

    /// Held secrets, ascending by epoch.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &RecipientSecret)> + '_ {
        self.entries
            .iter()
            .map(|(number, secret)| (*number, secret))
    }

    /// Hands the secrets over without copying them, for rebuilding a chain.
    pub fn into_secrets(self) -> impl Iterator<Item = (u64, RecipientSecret)> {
        self.entries.into_iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn chain_head(&self) -> [u8; HEAD_LEN] {
        self.chain_head
    }

    pub fn set_chain_head(&mut self, chain_head: [u8; HEAD_LEN]) {
        self.chain_head = chain_head;
    }

    /// Seals the store under `passphrase`, with a fresh salt and fresh nonces.
    pub fn seal(&self, passphrase: &str) -> Result<Vec<u8>, KeyringError> {
        self.seal_with(passphrase, random()?, random)
    }

    fn seal_with(
        &self,
        passphrase: &str,
        salt: [u8; SALT_LEN],
        mut nonce: impl FnMut() -> Result<[u8; NONCE_LEN], KeyringError>,
    ) -> Result<Vec<u8>, KeyringError> {
        let passphrase = crate::normalize_passphrase(passphrase);
        if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
            return Err(KeyringError::PassphraseTooShort(MIN_PASSPHRASE_LEN));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(KeyringError::TooManyEntries(MAX_ENTRIES));
        }

        let nonces = self
            .entries
            .keys()
            .map(|_| nonce())
            .collect::<Result<Vec<_>, _>>()?;
        // The header carries the body length and every seal authenticates the
        // header, so the length must be known before anything is sealed. Only
        // the numbers vary in size, so encoding with placeholder ciphertext
        // gives the exact length.
        let placeholder = [0u8; SEALED_LEN];
        let sized = encode_body(
            self.entries
                .keys()
                .zip(&nonces)
                .map(|(number, iv)| (*number, iv, &placeholder[..])),
        )?;
        let body_len = u32::try_from(sized.len()).map_err(|_| KeyringError::Malformed)?;
        let header = encode_header(
            Argon2Params::WRITER,
            &salt,
            &self.chain_head,
            body_len.to_be_bytes(),
        );

        let kek = Argon2Params::WRITER.derive(&passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new((&*kek).into());
        let sealed = self
            .entries
            .iter()
            .zip(&nonces)
            .map(|((number, secret), iv)| seal_seed(&cipher, &header, *number, iv, secret))
            .collect::<Result<Vec<_>, _>>()?;
        let body = encode_body(
            self.entries
                .keys()
                .zip(&nonces)
                .zip(&sealed)
                .map(|((number, iv), bytes)| (*number, iv, &bytes[..])),
        )?;
        debug_assert_eq!(body.len(), sized.len());

        let mut out = header;
        out.extend_from_slice(&body);
        let trailer_nonce = nonce()?;
        let tag = cipher
            .encrypt_inout_detached((&trailer_nonce).into(), &out, (&mut [][..]).into())
            .map_err(|_| KeyringError::Crypto("sealing the epoch store failed".into()))?;
        out.extend_from_slice(&trailer_nonce);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Opens a sealed store. The whole file is parsed and bounded before the
    /// passphrase is stretched, and authenticated before any seed is decrypted.
    pub fn open(bytes: &[u8], passphrase: &str) -> Result<Self, KeyringError> {
        let layout = parse(bytes)?;
        let authenticated = &bytes[..HEADER_LEN + layout.body_len];
        let tag = Tag::try_from(layout.trailer_tag).map_err(|_| KeyringError::Malformed)?;
        // The trailer decides which spelling of the passphrase sealed the file
        // (spec §9.3: NFC now, raw UTF-8 before); entries use the same key.
        let mut chosen = None;
        for candidate in crate::passphrase_candidates(passphrase) {
            let kek = layout.params.derive(&candidate, &layout.salt)?;
            let cipher = ChaCha20Poly1305::new((&*kek).into());
            if cipher
                .decrypt_inout_detached(
                    (&layout.trailer_nonce).into(),
                    authenticated,
                    (&mut [][..]).into(),
                    &tag,
                )
                .is_ok()
            {
                chosen = Some(cipher);
                break;
            }
        }
        let cipher = chosen.ok_or(KeyringError::WrongPassphrase)?;

        let mut entries = BTreeMap::new();
        for entry in &layout.entries {
            let mut seed = Zeroizing::new([0u8; SEED_LEN]);
            seed.copy_from_slice(&entry.sealed[..SEED_LEN]);
            let tag =
                Tag::try_from(&entry.sealed[SEED_LEN..]).map_err(|_| KeyringError::Malformed)?;
            cipher
                .decrypt_inout_detached(
                    (&entry.nonce).into(),
                    &entry_aad(layout.header, entry.number),
                    seed.as_mut_slice().into(),
                    &tag,
                )
                .map_err(|_| KeyringError::WrongPassphrase)?;
            entries.insert(entry.number, RecipientSecret::from_bytes(&seed[..])?);
        }
        Ok(Self {
            chain_head: layout.chain_head,
            entries,
        })
    }
}

/// Parses without authenticating and re-encodes from the parsed fields. Exists
/// for the fuzzer, which asserts the result equals the input: any byte the
/// parser tolerates but the writer would not produce is a canonicality bug.
#[doc(hidden)]
pub fn reencode_unauthenticated(bytes: &[u8]) -> Result<Vec<u8>, KeyringError> {
    let layout = parse(bytes)?;
    let body = encode_body(
        layout
            .entries
            .iter()
            .map(|entry| (entry.number, &entry.nonce, entry.sealed)),
    )?;
    let body_len = u32::try_from(body.len()).map_err(|_| KeyringError::Malformed)?;
    let mut out = encode_header(
        layout.params,
        &layout.salt,
        &layout.chain_head,
        body_len.to_be_bytes(),
    );
    out.extend_from_slice(&body);
    out.extend_from_slice(&layout.trailer_nonce);
    out.extend_from_slice(layout.trailer_tag);
    Ok(out)
}

struct RawEntry<'a> {
    number: u64,
    nonce: [u8; NONCE_LEN],
    sealed: &'a [u8],
}

struct Layout<'a> {
    params: Argon2Params,
    salt: [u8; SALT_LEN],
    chain_head: [u8; HEAD_LEN],
    header: &'a [u8],
    body_len: usize,
    entries: Vec<RawEntry<'a>>,
    trailer_nonce: [u8; NONCE_LEN],
    trailer_tag: &'a [u8],
}

fn parse(bytes: &[u8]) -> Result<Layout<'_>, KeyringError> {
    if !bytes.starts_with(MAGIC) {
        return Err(KeyringError::NotAnEpochStore);
    }
    if bytes.len() > MAX_FILE_LEN {
        return Err(KeyringError::Malformed);
    }
    let version = *bytes.get(MAGIC.len()).ok_or(KeyringError::Malformed)?;
    if version != VERSION {
        return Err(KeyringError::UnsupportedVersion(version));
    }
    if bytes.len() < HEADER_LEN + TRAILER_LEN {
        return Err(KeyringError::Malformed);
    }
    let params = Argon2Params::parse(&bytes[PARAMS_AT..SALT_AT])?;
    let salt: [u8; SALT_LEN] = bytes[SALT_AT..HEAD_AT]
        .try_into()
        .map_err(|_| KeyringError::Malformed)?;
    let chain_head: [u8; HEAD_LEN] = bytes[HEAD_AT..BODY_LEN_AT]
        .try_into()
        .map_err(|_| KeyringError::Malformed)?;
    let declared: [u8; 4] = bytes[BODY_LEN_AT..HEADER_LEN]
        .try_into()
        .map_err(|_| KeyringError::Malformed)?;
    let body_len =
        usize::try_from(u32::from_be_bytes(declared)).map_err(|_| KeyringError::Malformed)?;
    if body_len > MAX_BODY_LEN {
        return Err(KeyringError::Malformed);
    }
    let expected = HEADER_LEN
        .checked_add(body_len)
        .and_then(|length| length.checked_add(TRAILER_LEN))
        .ok_or(KeyringError::Malformed)?;
    if bytes.len() != expected {
        return Err(KeyringError::Malformed);
    }

    let (header, rest) = bytes.split_at(HEADER_LEN);
    let (body, trailer) = rest.split_at(body_len);
    let (trailer_nonce, trailer_tag) = trailer.split_at(NONCE_LEN);
    Ok(Layout {
        params,
        salt,
        chain_head,
        header,
        body_len,
        entries: decode_body(body)?,
        trailer_nonce: trailer_nonce
            .try_into()
            .map_err(|_| KeyringError::Malformed)?,
        trailer_tag,
    })
}

fn decode_body(body: &[u8]) -> Result<Vec<RawEntry<'_>>, KeyringError> {
    let mut decoder = minicbor::Decoder::new(body);
    let declared = decoder
        .array()
        .map_err(|_| KeyringError::Malformed)?
        .ok_or(KeyringError::Malformed)?;
    let count = usize::try_from(declared).map_err(|_| KeyringError::TooManyEntries(MAX_ENTRIES))?;
    if count > MAX_ENTRIES {
        return Err(KeyringError::TooManyEntries(MAX_ENTRIES));
    }

    // The declared count is attacker-chosen; reserve only what the body could
    // actually hold.
    let mut entries = Vec::with_capacity(count.min(body.len() / MIN_ENTRY_BYTES));
    let mut previous: Option<u64> = None;
    for _ in 0..count {
        if decoder.array().map_err(|_| KeyringError::Malformed)? != Some(3) {
            return Err(KeyringError::Malformed);
        }
        let number = decoder.u64().map_err(|_| KeyringError::Malformed)?;
        // Strictly ascending: one store, one encoding, and no duplicate epoch
        // whose second copy could shadow the first.
        if previous.is_some_and(|last| number <= last) {
            return Err(KeyringError::Malformed);
        }
        let nonce: [u8; NONCE_LEN] = decoder
            .bytes()
            .map_err(|_| KeyringError::Malformed)?
            .try_into()
            .map_err(|_| KeyringError::Malformed)?;
        let sealed = decoder.bytes().map_err(|_| KeyringError::Malformed)?;
        if sealed.len() != SEALED_LEN {
            return Err(KeyringError::Malformed);
        }
        entries.push(RawEntry {
            number,
            nonce,
            sealed,
        });
        previous = Some(number);
    }
    if decoder.position() != body.len() {
        return Err(KeyringError::Malformed);
    }
    // CBOR admits several byte forms for one value; only the writer's is valid.
    let canonical = encode_body(
        entries
            .iter()
            .map(|entry| (entry.number, &entry.nonce, entry.sealed)),
    )?;
    if canonical != body {
        return Err(KeyringError::Malformed);
    }
    Ok(entries)
}

fn encode_header(
    params: Argon2Params,
    salt: &[u8; SALT_LEN],
    chain_head: &[u8; HEAD_LEN],
    body_len: [u8; 4],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&params.encode());
    header.extend_from_slice(salt);
    header.extend_from_slice(chain_head);
    header.extend_from_slice(&body_len);
    debug_assert_eq!(header.len(), HEADER_LEN);
    header
}

fn encode_body<'a>(
    entries: impl ExactSizeIterator<Item = (u64, &'a [u8; NONCE_LEN], &'a [u8])>,
) -> Result<Vec<u8>, KeyringError> {
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    encoder
        .array(entries.len() as u64)
        .map_err(|_| KeyringError::Malformed)?;
    for (number, nonce, sealed) in entries {
        encoder
            .array(3)
            .and_then(|e| e.u64(number))
            .and_then(|e| e.bytes(nonce))
            .and_then(|e| e.bytes(sealed))
            .map_err(|_| KeyringError::Malformed)?;
    }
    Ok(out)
}

/// Binds a sealed seed to this file's header and to its epoch number, so it
/// cannot be moved to another slot or another store.
fn entry_aad(header: &[u8], number: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 8);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&number.to_be_bytes());
    aad
}

fn seal_seed(
    cipher: &ChaCha20Poly1305,
    header: &[u8],
    number: u64,
    nonce: &[u8; NONCE_LEN],
    secret: &RecipientSecret,
) -> Result<[u8; SEALED_LEN], KeyringError> {
    let mut buffer = Zeroizing::new([0u8; SEED_LEN]);
    let seed = secret.expose_seed_for_sealing();
    if seed.len() != SEED_LEN {
        return Err(KeyringError::Malformed);
    }
    buffer.copy_from_slice(seed);
    let tag = cipher
        .encrypt_inout_detached(
            nonce.into(),
            &entry_aad(header, number),
            buffer.as_mut_slice().into(),
        )
        .map_err(|_| KeyringError::Crypto("sealing an epoch secret failed".into()))?;
    let mut out = [0u8; SEALED_LEN];
    out[..SEED_LEN].copy_from_slice(&*buffer);
    out[SEED_LEN..].copy_from_slice(&tag);
    Ok(out)
}

/// A random nonce per entry is safe because every seal derives a fresh key from
/// a fresh salt: at most 65 537 nonces ever meet one key, and a collision among
/// that many 96-bit values has probability below 2^-64.
fn random<const LENGTH: usize>() -> Result<[u8; LENGTH], KeyringError> {
    let mut bytes = [0u8; LENGTH];
    getrandom::fill(&mut bytes).map_err(|error| KeyringError::Crypto(error.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hide_crypto::{ContentKey, unwrap_cek, wrap_cek};

    const PASSPHRASE: &str = "correct horse battery";

    fn error_of<T>(result: Result<T, KeyringError>) -> KeyringError {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(error) => error,
        }
    }

    fn fixed_secret(byte: u8) -> RecipientSecret {
        RecipientSecret::from_bytes(&[byte; SEED_LEN]).expect("seed")
    }

    fn store_of(numbers: &[u64]) -> EpochStore {
        let mut store = EpochStore::new([0xAB; HEAD_LEN]);
        for number in numbers {
            store
                .insert(*number, &fixed_secret(0x10 + *number as u8))
                .expect("insert");
        }
        store
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Recomputes the trailer with the real key, so a test can show that the
    /// per-entry binding holds on its own and not only because the trailer
    /// covers everything.
    fn reauthenticate(bytes: &mut [u8]) {
        let layout = parse(bytes).expect("parses");
        let kek = layout.params.derive(PASSPHRASE, &layout.salt).expect("kek");
        let nonce = layout.trailer_nonce;
        let end = HEADER_LEN + layout.body_len;
        drop(layout);
        let tag = ChaCha20Poly1305::new((&*kek).into())
            .encrypt_inout_detached((&nonce).into(), &bytes[..end], (&mut [][..]).into())
            .expect("tag");
        bytes[end + NONCE_LEN..].copy_from_slice(&tag);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn a_store_survives_a_restart_and_still_decrypts_epoch_two() -> Result<(), KeyringError> {
        a_store_survives_a_restart_impl()
    }

    /// §15.5: a store sealed with an NFD passphrase opens with the NFC one.
    #[test]
    fn a_store_opens_under_either_normal_form() -> Result<(), KeyringError> {
        let nfd = "parola\u{0306} e\u{0301}te\u{0301} sigura\u{0306}";
        let nfc = "parol\u{0103} \u{00e9}t\u{00e9} sigur\u{0103}";
        let sealed = store_of(&[0, 1]).seal(nfd)?;
        for typed in [nfc, nfd] {
            assert_eq!(
                EpochStore::open(&sealed, typed)?.chain_head,
                [0xAB; HEAD_LEN]
            );
        }
        Ok(())
    }

    fn a_store_survives_a_restart_impl() -> Result<(), KeyringError> {
        let mut store = EpochStore::new([7; HEAD_LEN]);
        let secrets = [
            RecipientSecret::generate()?,
            RecipientSecret::generate()?,
            RecipientSecret::generate()?,
        ];
        for (number, secret) in secrets.iter().enumerate() {
            store.insert(number as u64, secret)?;
        }
        let object = [9u8; 32];
        let cek = ContentKey::generate()?;
        let wrapped = wrap_cek(&secrets[2].public_key()?, &cek, &object)?;

        let sealed = store.seal(PASSPHRASE)?;
        drop(store);
        let reopened = EpochStore::open(&sealed, PASSPHRASE)?;

        assert_eq!(reopened.chain_head(), [7; HEAD_LEN]);
        assert_eq!(reopened.numbers().collect::<Vec<_>>(), [0, 1, 2]);
        let held = reopened.get(2).expect("epoch 2 survives");
        assert_eq!(
            held.public_key()?.to_bytes(),
            secrets[2].public_key()?.to_bytes()
        );
        unwrap_cek(held, &object, &wrapped.encapsulation, &wrapped.wrapped_cek)?;
        Ok(())
    }

    #[test]
    fn a_removed_epoch_leaves_no_copy_in_the_resealed_store() -> Result<(), KeyringError> {
        let mut store = store_of(&[0, 1, 2, 3]);
        let seed_two = fixed_secret(0x12);
        let before = store.seal(PASSPHRASE)?;
        assert!(store.remove(2));
        assert!(!store.remove(2), "removing twice reports nothing removed");
        let after = store.seal(PASSPHRASE)?;

        assert!(!contains(&after, seed_two.expose_seed_for_sealing()));
        assert!(
            after.len() < before.len(),
            "the sealed entry itself is gone"
        );
        let reopened = EpochStore::open(&after, PASSPHRASE)?;
        assert!(reopened.get(2).is_none());
        assert_eq!(reopened.numbers().collect::<Vec<_>>(), [0, 1, 3]);
        Ok(())
    }

    #[test]
    fn swapping_two_sealed_entries_fails_authentication() -> Result<(), KeyringError> {
        let store = store_of(&[1, 2]);
        let mut bytes = store.seal(PASSPHRASE)?;
        let layout = parse(&bytes)?;
        let offset =
            |entry: &RawEntry<'_>| entry.sealed.as_ptr() as usize - bytes.as_ptr() as usize;
        let (first, second) = (offset(&layout.entries[0]), offset(&layout.entries[1]));
        drop(layout);
        let saved: Vec<u8> = bytes[first..first + SEALED_LEN].to_vec();
        bytes.copy_within(second..second + SEALED_LEN, first);
        bytes[second..second + SEALED_LEN].copy_from_slice(&saved);

        assert_eq!(
            error_of(EpochStore::open(&bytes, PASSPHRASE)),
            KeyringError::WrongPassphrase
        );
        // Even with the file-wide tag recomputed, the number in each seal's
        // associated data refuses the swap.
        reauthenticate(&mut bytes);
        assert_eq!(
            error_of(EpochStore::open(&bytes, PASSPHRASE)),
            KeyringError::WrongPassphrase
        );
        Ok(())
    }

    #[test]
    fn a_wrong_passphrase_is_refused() -> Result<(), KeyringError> {
        let bytes = store_of(&[0]).seal(PASSPHRASE)?;
        assert_eq!(
            error_of(EpochStore::open(&bytes, "wrong horse battery")),
            KeyringError::WrongPassphrase
        );
        Ok(())
    }

    /// Without the trailer an empty store would authenticate nothing: any
    /// passphrase would open it and its chain head could be edited freely.
    #[test]
    fn an_empty_store_still_checks_the_passphrase_and_head() -> Result<(), KeyringError> {
        let mut bytes = EpochStore::new([3; HEAD_LEN]).seal(PASSPHRASE)?;
        assert!(EpochStore::open(&bytes, PASSPHRASE)?.is_empty());
        assert_eq!(
            error_of(EpochStore::open(&bytes, "wrong horse battery")),
            KeyringError::WrongPassphrase
        );
        bytes[HEAD_AT] ^= 1;
        assert_eq!(
            error_of(EpochStore::open(&bytes, PASSPHRASE)),
            KeyringError::WrongPassphrase
        );
        Ok(())
    }

    #[test]
    fn a_single_bit_flip_anywhere_is_refused() -> Result<(), KeyringError> {
        let bytes = store_of(&[5]).seal(PASSPHRASE)?;
        for index in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[index] ^= 0x01;
            assert!(
                EpochStore::open(&damaged, PASSPHRASE).is_err(),
                "accepted a flip at byte {index}"
            );
        }
        Ok(())
    }

    #[test]
    fn truncation_and_trailing_bytes_are_refused() -> Result<(), KeyringError> {
        let bytes = store_of(&[0, 1]).seal(PASSPHRASE)?;
        for cut in 0..bytes.len() {
            assert!(
                parse(&bytes[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(error_of(parse(&longer)), KeyringError::Malformed);
        Ok(())
    }

    fn with_body(body: &[u8]) -> Vec<u8> {
        let mut out = encode_header(
            Argon2Params::WRITER,
            &[0; SALT_LEN],
            &[0; HEAD_LEN],
            u32::try_from(body.len()).unwrap().to_be_bytes(),
        );
        out.extend_from_slice(body);
        out.extend_from_slice(&[0; TRAILER_LEN]);
        out
    }

    #[test]
    fn a_count_above_the_limit_is_refused_before_allocating() {
        // Five bytes declaring MAX_ENTRIES + 1 entries, and nothing behind them.
        let mut body = Vec::new();
        minicbor::Encoder::new(&mut body)
            .array(MAX_ENTRIES as u64 + 1)
            .unwrap();
        assert_eq!(body.len(), 5);
        assert_eq!(
            error_of(EpochStore::open(&with_body(&body), PASSPHRASE)),
            KeyringError::TooManyEntries(MAX_ENTRIES)
        );
        // At the limit it is merely truncated.
        let mut body = Vec::new();
        minicbor::Encoder::new(&mut body)
            .array(MAX_ENTRIES as u64)
            .unwrap();
        assert_eq!(
            error_of(EpochStore::open(&with_body(&body), PASSPHRASE)),
            KeyringError::Malformed
        );
    }

    #[test]
    fn a_declared_body_beyond_the_ceiling_is_refused() {
        let mut bytes = with_body(&[0x80]);
        bytes[BODY_LEN_AT..HEADER_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(error_of(parse(&bytes)), KeyringError::Malformed);
    }

    #[test]
    fn argon2_memory_above_the_ceiling_is_refused() -> Result<(), KeyringError> {
        let mut bytes = store_of(&[0]).seal(PASSPHRASE)?;
        bytes[PARAMS_AT + 1..PARAMS_AT + 5]
            .copy_from_slice(&(crate::MAX_MEMORY_KIB + 1).to_be_bytes());
        assert_eq!(
            error_of(EpochStore::open(&bytes, PASSPHRASE)),
            KeyringError::UnreasonableParameters
        );
        Ok(())
    }

    #[test]
    fn non_canonical_and_unordered_bodies_are_refused() -> Result<(), KeyringError> {
        let bytes = store_of(&[1, 2]).seal(PASSPHRASE)?;
        let layout = parse(&bytes)?;
        let body = &bytes[HEADER_LEN..HEADER_LEN + layout.body_len];
        assert_eq!(body[0], 0x82);

        // The same array with a widened length prefix.
        let mut widened = vec![0x98, 0x02];
        widened.extend_from_slice(&body[1..]);
        assert_eq!(
            error_of(parse(&with_body(&widened))),
            KeyringError::Malformed
        );

        // Entries in descending order.
        let entry_len = (body.len() - 1) / 2;
        let mut reversed = vec![0x82];
        reversed.extend_from_slice(&body[1 + entry_len..]);
        reversed.extend_from_slice(&body[1..1 + entry_len]);
        assert_eq!(
            error_of(parse(&with_body(&reversed))),
            KeyringError::Malformed
        );

        // A duplicated epoch.
        let mut duplicated = vec![0x82];
        duplicated.extend_from_slice(&body[1..1 + entry_len]);
        duplicated.extend_from_slice(&body[1..1 + entry_len]);
        assert_eq!(
            error_of(parse(&with_body(&duplicated))),
            KeyringError::Malformed
        );
        Ok(())
    }

    #[test]
    fn foreign_files_and_versions_are_named() {
        assert_eq!(
            error_of(EpochStore::open(b"HIDE-KEY\x02", PASSPHRASE)),
            KeyringError::NotAnEpochStore
        );
        let mut bytes = with_body(&[0x80]);
        bytes[MAGIC.len()] = 2;
        assert_eq!(
            error_of(EpochStore::open(&bytes, PASSPHRASE)),
            KeyringError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn short_passphrases_are_refused_when_sealing() {
        assert_eq!(
            error_of(store_of(&[0]).seal("short")),
            KeyringError::PassphraseTooShort(MIN_PASSPHRASE_LEN)
        );
    }

    #[test]
    fn every_seal_uses_a_fresh_salt() -> Result<(), KeyringError> {
        let store = store_of(&[0]);
        let first = store.seal(PASSPHRASE)?;
        let second = store.seal(PASSPHRASE)?;
        assert_ne!(first[SALT_AT..HEAD_AT], second[SALT_AT..HEAD_AT]);
        Ok(())
    }

    #[test]
    fn the_fuzz_reencoder_reproduces_a_real_store() -> Result<(), KeyringError> {
        let bytes = store_of(&[0, 7, 300]).seal(PASSPHRASE)?;
        assert_eq!(reencode_unauthenticated(&bytes)?, bytes);
        Ok(())
    }

    /// Round trips are symmetric: a change made to writer and reader together
    /// passes them. These bytes pin the layout itself.
    #[test]
    fn a_deterministic_store_has_these_exact_bytes() -> Result<(), KeyringError> {
        let mut store = EpochStore::new([0xC4; HEAD_LEN]);
        store.insert(0, &fixed_secret(0x11))?;
        store.insert(2, &fixed_secret(0x22))?;
        let mut counter = 0u8;
        let bytes = store.seal_with(PASSPHRASE, [0x5A; SALT_LEN], || {
            counter += 1;
            Ok([counter; NONCE_LEN])
        })?;
        assert_eq!(hex(&bytes), PINNED.concat());
        let reopened = EpochStore::open(&bytes, PASSPHRASE)?;
        assert_eq!(
            reopened.get(2).expect("held").expose_seed_for_sealing(),
            [0x22; SEED_LEN]
        );
        Ok(())
    }

    const PINNED: [&str; 12] = [
        "484944452d45504b",                 // magic
        "01",                               // version
        "0100004c0000000002",               // p=1, m=19456 KiB, t=2
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", // salt
        "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4",
        "00000083", // body length
        "82",       // two entries
        "83004c0101010101010101010101015830\
         6a5c18b6c39d79bad25f5ac6086b3afb20c37bb5cb4914c4ed4ca3640634a539\
         aef3cdc6d6208ab9d89827f48ec47889",
        "83024c0202020202020202020202025830\
         c9c4a67d976523c7527a63cefd65ae7bb93f087edbf8c51df51cebbe6a9c61fc\
         849d3e327c66c24e4e97c1204afb76c9",
        "030303030303030303030303",         // trailer nonce
        "a95e7a90f457c2a8ee9c58cc6096bafe", // trailer tag
        "",
    ];
}
