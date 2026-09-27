use std::io::{self, Read, Write};

use hide_crypto::{
    ChunkCipher, ContentKey, CryptoError, DerivedKey, RecipientPublic, RecipientSecret,
};
use hide_format::{
    CHUNK_LEN, FormatError, MAX_RECIPIENTS, PREAMBLE_LEN, RecipientStanza, SUITE, SignatureStanza,
    TAG_LEN,
};
pub use hide_format::{Extension, Metadata, Preamble, ProtectedHeader, Stanza, UnknownStanza};
use hide_sign::{SigningIdentity, VerifyingIdentity};
use thiserror::Error;
use zeroize::Zeroizing;

const DATA: u8 = 1;
const FINAL: u8 = 2;
const MAX_CHUNKS: u64 = 1 << 32;
/// A signed encrypt must hold the whole plaintext to hash it, so it is the one
/// path that cannot stream. Unsigned encryption has no such limit.
pub const MAX_SIGNED_INPUT: u64 = 1 << 30;
const RECORD_LEN: usize = CHUNK_LEN + TAG_LEN;
const CHUNK_AAD_LEN: usize = 91;
const SIGNING_CONTEXT: &[u8] = b"HIDE/1.0 container";
/// HIDE/0.5–0.8 signed containers (preamble minor 2). Verified, never produced.
const LEGACY_SIGNING_CONTEXT: &[u8] = b"HIDE/0.5 container";

#[derive(Debug, Error)]
pub enum ObjectError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("I/O operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("no matching recipient or invalid header authentication")]
    NoMatchingRecipient,
    #[error("truncated payload")]
    TruncatedPayload,
    #[error("invalid payload record")]
    InvalidRecord,
    #[error("unexpected bytes after final record")]
    TrailingData,
    #[error("object exceeds the chunk limit")]
    ObjectTooLarge,
    #[error("recipient count must be between 1 and 64")]
    InvalidRecipients,
    #[error("signature does not verify")]
    InvalidSignature,
    #[error("container is signed but the reader was not asked to verify")]
    UnexpectedSignature,
    #[error("container is not signed")]
    MissingSignature,
}

/// Where a signature is written. Public signatures are readable by anyone
/// holding the file; confidential ones only by those who can already decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePlacement {
    /// In the unencrypted header. Reveals the signer to anyone with the file.
    Public,
    /// Inside the encrypted metadata. Hides the signer from non-recipients.
    Confidential,
    /// Signs, then discards the signature while leaving the preamble claiming
    /// to be signed. Exists only so tests can reach the stripped-signature check.
    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    Stripped,
    /// The HIDE/0.5 wire form: minor 2 and the legacy transcript. Exists only so
    /// tests and vectors can prove that such files are still read.
    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    LegacyPublic,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedObject {
    pub metadata: Metadata,
    pub plaintext_len: u64,
    /// The signer, if the container carried a signature that verified.
    pub signer: Option<VerifyingIdentity>,
}

struct ObjectMaterial {
    cek: ContentKey,
    object_id: [u8; 32],
    payload_salt: [u8; 16],
}

pub fn encrypt<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipients: &[RecipientPublic],
    metadata: &Metadata,
) -> Result<u64, ObjectError> {
    validate_recipients(recipients)?;
    let material = ObjectMaterial {
        cek: ContentKey::generate()?,
        object_id: hide_crypto::random_array()?,
        payload_salt: hide_crypto::random_array()?,
    };
    let stanzas = recipients
        .iter()
        .map(|recipient| {
            hide_crypto::wrap_cek(recipient, &material.cek, &material.object_id).map(|wrapped| {
                RecipientStanza {
                    encapsulation: wrapped.encapsulation,
                    wrapped_cek: wrapped.wrapped_cek,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    encrypt_with_material(input, output, metadata, material, stanzas)
}

fn validate_recipients(recipients: &[RecipientPublic]) -> Result<(), ObjectError> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(ObjectError::InvalidRecipients);
    }
    Ok(())
}

/// Encrypts and signs. Unlike [`encrypt`], this buffers the payload, because the
/// signature commits to the plaintext and so cannot be produced while streaming.
pub fn encrypt_signed<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipients: &[RecipientPublic],
    metadata: &Metadata,
    identity: &SigningIdentity,
    placement: SignaturePlacement,
) -> Result<u64, ObjectError> {
    validate_recipients(recipients)?;
    let material = ObjectMaterial {
        cek: ContentKey::generate()?,
        object_id: hide_crypto::random_array()?,
        payload_salt: hide_crypto::random_array()?,
    };
    let stanzas = recipients
        .iter()
        .map(|recipient| {
            hide_crypto::wrap_cek(recipient, &material.cek, &material.object_id).map(|wrapped| {
                RecipientStanza {
                    encapsulation: wrapped.encapsulation,
                    wrapped_cek: wrapped.wrapped_cek,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    encrypt_inner(
        input,
        output,
        metadata,
        material,
        stanzas,
        Some((identity, placement)),
        &VectorShape::default(),
    )
}

fn encrypt_with_material<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    metadata: &Metadata,
    material: ObjectMaterial,
    recipients: Vec<RecipientStanza>,
) -> Result<u64, ObjectError> {
    encrypt_inner(
        input,
        output,
        metadata,
        material,
        recipients,
        None,
        &VectorShape::default(),
    )
}

/// Wire features a HIDE/1.0 writer never emits but every reader must accept.
/// Production code always uses the default; the vector generator uses the rest
/// to freeze GREASE containers that prove readers skip what they do not know.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct VectorShape {
    pub minor: u8,
    pub header_extensions: Vec<hide_format::Extension>,
    pub leading_stanzas: Vec<Stanza>,
}

impl Default for VectorShape {
    fn default() -> Self {
        Self {
            minor: hide_format::CURRENT_MINOR,
            header_extensions: Vec::new(),
            leading_stanzas: Vec::new(),
        }
    }
}

/// Commits to the recipient set, the metadata and the plaintext. Binding only
/// the header would let any recipient re-encrypt different content under the
/// same header and keep the signature valid, since they hold the CEK and the
/// payload salt is public.
///
/// The metadata is bound as its *plaintext* signing base rather than via the
/// header's ciphertext: sealing is randomised and the confidential placement
/// reseals after signing, so the ciphertext a verifier sees is not the one that
/// existed when the signature was made.
///
/// HIDE/1.0 also binds the preamble's version and flags, every stanza's tag and
/// every field length (so unknown stanzas and a stanza boundary cannot be
/// shifted), and the header extensions, which the metadata base does not cover.
fn transcript(
    preamble: Preamble,
    header: &ProtectedHeader,
    metadata_base: &[u8],
    plaintext_hash: &[u8; 32],
    plaintext_len: u64,
) -> Vec<u8> {
    if preamble.is_legacy() {
        return legacy_transcript(header, metadata_base, plaintext_hash, plaintext_len);
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"HIDE/1.0 transcript");
    message.extend_from_slice(&preamble.signed_prefix());
    message.extend_from_slice(&SUITE.to_be_bytes());
    message.extend_from_slice(&header.object_id);
    message.extend_from_slice(&(header.recipients.len() as u64).to_be_bytes());
    for stanza in &header.recipients {
        let fields = stanza.fields();
        message.extend_from_slice(&u64::from(stanza.tag()).to_be_bytes());
        message.extend_from_slice(&(fields.len() as u64).to_be_bytes());
        for field in fields {
            message.extend_from_slice(&(field.len() as u64).to_be_bytes());
            message.extend_from_slice(field);
        }
    }
    message.extend_from_slice(&(header.extensions.len() as u64).to_be_bytes());
    for extension in &header.extensions {
        message.extend_from_slice(&extension.key.to_be_bytes());
        message.extend_from_slice(&(extension.value.len() as u64).to_be_bytes());
        message.extend_from_slice(&extension.value);
    }
    message.extend_from_slice(&(metadata_base.len() as u64).to_be_bytes());
    message.extend_from_slice(metadata_base);
    message.extend_from_slice(plaintext_hash);
    message.extend_from_slice(&plaintext_len.to_be_bytes());
    message
}

/// The HIDE/0.5 transcript. Only reachable for minor 2, which admits neither
/// extensions nor unknown stanzas, so every stanza here is X-Wing.
fn legacy_transcript(
    header: &ProtectedHeader,
    metadata_base: &[u8],
    plaintext_hash: &[u8; 32],
    plaintext_len: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"HIDE/0.5 transcript");
    message.extend_from_slice(&SUITE.to_be_bytes());
    message.extend_from_slice(&header.object_id);
    message.extend_from_slice(&(header.recipients.len() as u64).to_be_bytes());
    for stanza in header.recipients.iter().filter_map(Stanza::as_xwing) {
        message.extend_from_slice(&stanza.encapsulation);
        message.extend_from_slice(&stanza.wrapped_cek);
    }
    message.extend_from_slice(&(metadata_base.len() as u64).to_be_bytes());
    message.extend_from_slice(metadata_base);
    message.extend_from_slice(plaintext_hash);
    message.extend_from_slice(&plaintext_len.to_be_bytes());
    message
}

fn signing_context(preamble: Preamble) -> &'static [u8] {
    if preamble.is_legacy() {
        LEGACY_SIGNING_CONTEXT
    } else {
        SIGNING_CONTEXT
    }
}

fn encrypt_inner<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    metadata: &Metadata,
    material: ObjectMaterial,
    recipients: Vec<RecipientStanza>,
    signer: Option<(&SigningIdentity, SignaturePlacement)>,
    shape: &VectorShape,
) -> Result<u64, ObjectError> {
    // Signing needs the plaintext hash, which is only known once the payload has
    // been consumed, so the container is built in memory and written at the end.
    // Bounded, because a signed encrypt is the one path that cannot stream.
    let mut plaintext = Zeroizing::new(Vec::new());
    let (metadata, plaintext_hash, plaintext_len) = match signer {
        None => (metadata.clone(), None, None),
        Some(_) => {
            input
                .take(MAX_SIGNED_INPUT + 1)
                .read_to_end(&mut plaintext)?;
            if plaintext.len() as u64 > MAX_SIGNED_INPUT {
                return Err(ObjectError::ObjectTooLarge);
            }
            let hash = hide_crypto::hash(&[&plaintext]);
            (metadata.clone(), Some(hash), Some(plaintext.len() as u64))
        }
    };

    let metadata_key =
        hide_crypto::derive_key(&material.cek, &material.object_id, b"HIDE/0.1 metadata")?;

    // The signing base is the metadata without any signature; both placements
    // commit to it. It is only hashed into the transcript, never sealed on its
    // own: the metadata key and its fixed nonce must encrypt exactly one thing.
    let base_metadata = Zeroizing::new(metadata.signing_base()?);
    let mut header = ProtectedHeader {
        object_id: material.object_id,
        recipients: shape
            .leading_stanzas
            .iter()
            .cloned()
            .chain(recipients.into_iter().map(Stanza::from))
            .collect(),
        encrypted_metadata: Vec::new(),
        signatures: Vec::new(),
        extensions: shape.header_extensions.clone(),
    };

    // The signed prefix does not include header_len, so the preamble the
    // transcript binds can be fixed before the header is sized.
    #[cfg(feature = "test-vectors")]
    let legacy = matches!(signer, Some((_, SignaturePlacement::LegacyPublic)));
    #[cfg(not(feature = "test-vectors"))]
    let legacy = false;
    let preamble_for = |length: usize| -> Result<Preamble, FormatError> {
        if legacy {
            Preamble::legacy_signed(length)
        } else {
            let flags = if signer.is_some() {
                hide_format::FLAG_SIGNED
            } else {
                0
            };
            Preamble::from_parts(length, shape.minor, flags)
        }
    };

    let mut metadata = metadata;
    if let Some((identity, placement)) = signer {
        let provisional = preamble_for(1)?;
        let message = transcript(
            provisional,
            &header,
            &base_metadata,
            &plaintext_hash.expect("set when signing"),
            plaintext_len.expect("set when signing"),
        );
        let stanza = SignatureStanza {
            verifying_key: identity.verifying_key().to_bytes().to_vec(),
            signature: identity
                .sign(signing_context(provisional), &message)
                .to_vec(),
        };
        match placement {
            SignaturePlacement::Public => header.signatures.push(stanza),
            SignaturePlacement::Confidential => metadata.signature = Some(stanza),
            #[cfg(feature = "test-vectors")]
            SignaturePlacement::Stripped => drop(stanza),
            #[cfg(feature = "test-vectors")]
            SignaturePlacement::LegacyPublic => header.signatures.push(stanza),
        }
    }

    // Exactly one seal under the metadata key, whichever placement was chosen.
    let final_metadata = Zeroizing::new(metadata.encode()?);
    header.encrypted_metadata = hide_crypto::seal(
        &metadata_key,
        &[0; 12],
        &metadata_aad(&material.object_id),
        &final_metadata,
    )?;

    let signed = signer.is_some();
    let protected = header.encode()?;
    let header_length = hide_format::encode_header(&protected, &[0; 32])?.len();
    let preamble = preamble_for(header_length)?.encode();
    let mac_key =
        hide_crypto::derive_key(&material.cek, &material.object_id, b"HIDE/0.1 header-mac")?;
    let mac = hide_crypto::mac(&mac_key, &[&preamble, &protected])?;
    output.write_all(&preamble)?;
    output.write_all(&hide_format::encode_header(&protected, &mac)?)?;
    output.write_all(&material.payload_salt)?;
    let key = payload_key(&material.cek, &material.object_id, &material.payload_salt)?;
    let header_hash = hide_crypto::hash(&[&protected]);
    if signed {
        encrypt_records(
            &mut plaintext.as_slice(),
            output,
            &key,
            &material.object_id,
            &header_hash,
        )
    } else {
        encrypt_records(input, output, &key, &material.object_id, &header_hash)
    }
}

/// Writes provisional plaintext. The writer must be private staging storage, not a
/// published file or stdout. Commit it only after this function returns Ok.
/// Integrity does not authenticate the sender or verify a human identity.
pub fn decrypt_to_staging<R: Read, W: Write>(
    input: &mut R,
    staging: &mut W,
    secret: &RecipientSecret,
) -> Result<VerifiedObject, ObjectError> {
    let mut preamble_bytes = [0; PREAMBLE_LEN];
    input.read_exact(&mut preamble_bytes)?;
    let preamble = Preamble::decode(&preamble_bytes)?;
    let mut header_bytes = vec![0; preamble.header_len()];
    input.read_exact(&mut header_bytes)?;
    let (protected, mac) = hide_format::decode_header(&header_bytes)?;
    let header = ProtectedHeader::decode(&protected)?;
    // The legacy transcript binds neither extensions nor stanza tags, so a
    // minor-2 container carrying either could have them added after signing.
    if preamble.is_legacy()
        && (!header.extensions.is_empty()
            || header.recipients.iter().any(|s| s.as_xwing().is_none()))
    {
        return Err(FormatError::MalformedHeader.into());
    }
    let cek = recover_cek(secret, &header, &preamble_bytes, &protected, &mac)?;
    let metadata_key = hide_crypto::derive_key(&cek, &header.object_id, b"HIDE/0.1 metadata")?;
    let metadata_plaintext = hide_crypto::open(
        &metadata_key,
        &[0; 12],
        &metadata_aad(&header.object_id),
        &header.encrypted_metadata,
    )?;
    let metadata = Metadata::decode(&metadata_plaintext)?;
    if preamble.is_legacy() && !metadata.extensions.is_empty() {
        return Err(FormatError::InvalidMetadata.into());
    }
    let mut salt = [0; 16];
    read_payload(input, &mut salt)?;
    let key = payload_key(&cek, &header.object_id, &salt)?;

    // The signature commits to the plaintext, so it can only be checked once the
    // payload has been read. Hash it on the way past rather than buffering.
    let mut hasher = PlaintextHasher::new(staging);
    let plaintext_len = decrypt_records(
        input,
        &mut hasher,
        &key,
        &header.object_id,
        &hide_crypto::hash(&[&protected]),
    )?;
    let plaintext_hash = hasher.finish();

    let signer = verify_signature(preamble, &header, &metadata, &plaintext_hash, plaintext_len)?;
    Ok(VerifiedObject {
        metadata,
        plaintext_len,
        signer,
    })
}

/// Returns the signer when the container carries a signature that verifies, and
/// refuses the object otherwise. Called before the caller may publish plaintext.
fn verify_signature(
    preamble: Preamble,
    header: &ProtectedHeader,
    metadata: &Metadata,
    plaintext_hash: &[u8; 32],
    plaintext_len: u64,
) -> Result<Option<VerifyingIdentity>, ObjectError> {
    let preamble_says_signed = preamble.is_signed();
    let stanza = match (header.signatures.first(), metadata.signature.as_ref()) {
        (Some(_), Some(_)) => return Err(ObjectError::InvalidSignature),
        (Some(stanza), None) | (None, Some(stanza)) => stanza,
        (None, None) => {
            // A preamble claiming to be signed with no signature is a stripped
            // signature, not an unsigned object.
            return if preamble_says_signed {
                Err(ObjectError::MissingSignature)
            } else {
                Ok(None)
            };
        }
    };
    if !preamble_says_signed {
        return Err(ObjectError::UnexpectedSignature);
    }

    let identity = VerifyingIdentity::from_bytes(&stanza.verifying_key)
        .map_err(|_| ObjectError::InvalidSignature)?;
    let message = transcript(
        preamble,
        header,
        &metadata.signing_base()?,
        plaintext_hash,
        plaintext_len,
    );
    identity
        .verify(signing_context(preamble), &message, &stanza.signature)
        .map_err(|_| ObjectError::InvalidSignature)?;
    Ok(Some(identity))
}

fn recover_cek(
    secret: &RecipientSecret,
    header: &ProtectedHeader,
    preamble: &[u8],
    protected: &[u8],
    mac: &[u8; 32],
) -> Result<ContentKey, ObjectError> {
    // Unknown stanza types are skipped, not refused: a later recipient type must
    // not lock out the recipients a file already had.
    for stanza in header.recipients.iter().filter_map(Stanza::as_xwing) {
        if let Ok(cek) = hide_crypto::unwrap_cek(
            secret,
            &header.object_id,
            &stanza.encapsulation,
            &stanza.wrapped_cek,
        ) {
            let key = hide_crypto::derive_key(&cek, &header.object_id, b"HIDE/0.1 header-mac")?;
            if hide_crypto::verify_mac(&key, &[preamble, protected], mac).is_ok() {
                return Ok(cek);
            }
        }
    }
    Err(ObjectError::NoMatchingRecipient)
}

/// Hashes plaintext as it streams to staging, so verifying a signature over the
/// content does not require buffering the whole object.
struct PlaintextHasher<'a, W: Write> {
    inner: &'a mut W,
    hasher: hide_crypto::Hasher,
}

impl<'a, W: Write> PlaintextHasher<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: hide_crypto::Hasher::new(),
        }
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finish()
    }
}

impl<W: Write> Write for PlaintextHasher<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn metadata_aad(object_id: &[u8; 32]) -> Vec<u8> {
    [
        b"HIDE/0.1 metadata".as_slice(),
        object_id,
        &SUITE.to_be_bytes(),
    ]
    .concat()
}

fn payload_key(
    cek: &ContentKey,
    object_id: &[u8; 32],
    salt: &[u8; 16],
) -> Result<DerivedKey, CryptoError> {
    hide_crypto::derive_key(
        cek,
        salt,
        &[b"HIDE/0.1 payload".as_slice(), object_id].concat(),
    )
}

fn nonce(counter: u64, kind: u8) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[3..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(kind == FINAL);
    nonce
}

fn chunk_aad(
    object_id: &[u8; 32],
    header_hash: &[u8; 32],
    counter: u64,
    kind: u8,
    length: usize,
) -> [u8; CHUNK_AAD_LEN] {
    let mut aad = [0; CHUNK_AAD_LEN];
    aad[..14].copy_from_slice(b"HIDE/0.1 chunk");
    aad[14..46].copy_from_slice(object_id);
    aad[46..78].copy_from_slice(header_hash);
    aad[78..86].copy_from_slice(&counter.to_be_bytes());
    aad[86] = kind;
    aad[87..].copy_from_slice(&(length as u32).to_be_bytes());
    aad
}

fn read_chunk<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, io::Error> {
    let mut length = 0;
    while length < buffer.len() {
        match reader.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(length)
}

fn encrypt_records<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    key: &DerivedKey,
    object_id: &[u8; 32],
    header_hash: &[u8; 32],
) -> Result<u64, ObjectError> {
    let cipher = ChunkCipher::new(key)?;
    let mut current = Zeroizing::new(vec![0; RECORD_LEN]);
    let mut next = Zeroizing::new(vec![0; RECORD_LEN]);
    let mut length = read_chunk(input, &mut current[..CHUNK_LEN])?;
    let mut counter = 0;
    let mut total = 0;
    loop {
        if counter >= MAX_CHUNKS {
            return Err(ObjectError::ObjectTooLarge);
        }
        let next_length = read_chunk(input, &mut next[..CHUNK_LEN])?;
        let kind = if next_length == 0 { FINAL } else { DATA };
        let aad = chunk_aad(object_id, header_hash, counter, kind, length);
        let sealed = cipher.seal_in_place(&nonce(counter, kind), &aad, &mut current, length)?;
        let mut record = [0; 5];
        record[0] = kind;
        record[1..].copy_from_slice(&(sealed as u32).to_be_bytes());
        output.write_all(&record)?;
        output.write_all(&current[..sealed])?;
        total += length as u64;
        if kind == FINAL {
            return Ok(total);
        }
        core::mem::swap(&mut current, &mut next);
        length = next_length;
        counter += 1;
    }
}

fn decrypt_records<R: Read, W: Write>(
    input: &mut R,
    staging: &mut W,
    key: &DerivedKey,
    object_id: &[u8; 32],
    header_hash: &[u8; 32],
) -> Result<u64, ObjectError> {
    let cipher = ChunkCipher::new(key)?;
    let mut buffer = Zeroizing::new(vec![0; RECORD_LEN]);
    let mut total = 0;
    for counter in 0..MAX_CHUNKS {
        let mut record = [0; 5];
        read_payload(input, &mut record)?;
        let kind = record[0];
        let ciphertext_len =
            u32::from_be_bytes([record[1], record[2], record[3], record[4]]) as usize;
        let length = record_length(kind, ciphertext_len, counter)?;
        let ciphertext = &mut buffer[..ciphertext_len];
        read_payload(input, ciphertext)?;
        let aad = chunk_aad(object_id, header_hash, counter, kind, length);
        let opened = cipher.open_in_place(&nonce(counter, kind), &aad, ciphertext)?;
        if kind == FINAL {
            let mut extra = [0; 1];
            if read_chunk(input, &mut extra)? != 0 {
                return Err(ObjectError::TrailingData);
            }
        }
        staging.write_all(&buffer[..opened])?;
        total += opened as u64;
        if kind == FINAL {
            return Ok(total);
        }
    }
    Err(ObjectError::ObjectTooLarge)
}

fn record_length(kind: u8, ciphertext_len: usize, counter: u64) -> Result<usize, ObjectError> {
    if !(TAG_LEN..=CHUNK_LEN + TAG_LEN).contains(&ciphertext_len) {
        return Err(ObjectError::InvalidRecord);
    }
    let length = ciphertext_len - TAG_LEN;
    match kind {
        DATA if length == CHUNK_LEN => Ok(length),
        FINAL if length > 0 || counter == 0 => Ok(length),
        _ => Err(ObjectError::InvalidRecord),
    }
}

fn read_payload<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), ObjectError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ObjectError::TruncatedPayload
        } else {
            ObjectError::Io(error)
        }
    })
}

/// Writes a container whose preamble claims to be signed while carrying no
/// signature: the shape an attacker produces by stripping one. Test-only.
#[cfg(feature = "test-vectors")]
pub fn encrypt_stripped_signature_for_test<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipients: &[RecipientPublic],
    metadata: &Metadata,
    identity: &SigningIdentity,
) -> Result<u64, ObjectError> {
    validate_recipients(recipients)?;
    let material = ObjectMaterial {
        cek: ContentKey::generate()?,
        object_id: hide_crypto::random_array()?,
        payload_salt: hide_crypto::random_array()?,
    };
    let stanzas = recipients
        .iter()
        .map(|recipient| {
            hide_crypto::wrap_cek(recipient, &material.cek, &material.object_id).map(|wrapped| {
                RecipientStanza {
                    encapsulation: wrapped.encapsulation,
                    wrapped_cek: wrapped.wrapped_cek,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    encrypt_inner(
        input,
        output,
        metadata,
        material,
        stanzas,
        Some((identity, SignaturePlacement::Stripped)),
        &VectorShape::default(),
    )
}

/// Mounts the forgery a signature must prevent: keep the container's header
/// byte-for-byte, then re-encrypt different plaintext with the CEK the
/// recipient already holds. Exposed only for tests, because it exists purely to
/// prove the signature binds the payload and not merely the header.
#[cfg(feature = "test-vectors")]
pub fn forge_payload_for_test(
    container: &[u8],
    secret: &RecipientSecret,
    replacement: &[u8],
) -> Result<Vec<u8>, ObjectError> {
    let preamble = Preamble::decode(&container[..PREAMBLE_LEN])?;
    let header_end = PREAMBLE_LEN + preamble.header_len();
    let (protected, mac) = hide_format::decode_header(&container[PREAMBLE_LEN..header_end])?;
    let header = ProtectedHeader::decode(&protected)?;
    let cek = recover_cek(
        secret,
        &header,
        &container[..PREAMBLE_LEN],
        &protected,
        &mac,
    )?;

    let salt: [u8; 16] = container[header_end..header_end + 16]
        .try_into()
        .map_err(|_| ObjectError::TruncatedPayload)?;
    let key = payload_key(&cek, &header.object_id, &salt)?;

    let mut forged = container[..header_end + 16].to_vec();
    encrypt_records(
        &mut &replacement[..],
        &mut forged,
        &key,
        &header.object_id,
        &hide_crypto::hash(&[&protected]),
    )?;
    Ok(forged)
}

#[cfg(feature = "test-vectors")]
pub fn encrypt_for_vector<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipient: &RecipientPublic,
    metadata: &Metadata,
) -> Result<u64, ObjectError> {
    encrypt_for_vector_inner(
        input,
        output,
        recipient,
        metadata,
        None,
        &VectorShape::default(),
    )
}

/// Everything a recipient can do to a container: open it, change the header
/// (and optionally the minor), then recompute the header MAC and re-encrypt
/// the payload so every authenticator a recipient controls is valid again.
/// What survives this is exactly what a signature must catch. Test-only; it is
/// also how the rejection vectors that need an authentic MAC are produced.
#[cfg(feature = "test-vectors")]
pub fn rewrite_header_for_test(
    container: &[u8],
    secret: &RecipientSecret,
    minor: Option<u8>,
    edit: impl FnOnce(&mut ProtectedHeader),
) -> Result<Vec<u8>, ObjectError> {
    rewrite_for_test(container, secret, minor, None, edit, |_| {})
}

/// As [`rewrite_header_for_test`], and also sets the flags byte and edits the
/// decrypted metadata before resealing it.
#[cfg(feature = "test-vectors")]
pub fn rewrite_for_test(
    container: &[u8],
    secret: &RecipientSecret,
    minor: Option<u8>,
    flags: Option<u8>,
    edit: impl FnOnce(&mut ProtectedHeader),
    edit_metadata: impl FnOnce(&mut Vec<u8>),
) -> Result<Vec<u8>, ObjectError> {
    let preamble = Preamble::decode(&container[..PREAMBLE_LEN])?;
    let header_end = PREAMBLE_LEN + preamble.header_len();
    let (protected, mac) = hide_format::decode_header(&container[PREAMBLE_LEN..header_end])?;
    let mut header = ProtectedHeader::decode(&protected)?;
    let cek = recover_cek(
        secret,
        &header,
        &container[..PREAMBLE_LEN],
        &protected,
        &mac,
    )?;
    let mut plaintext = Vec::new();
    decrypt_to_staging(&mut &container[..], &mut plaintext, secret)?;

    let metadata_key = hide_crypto::derive_key(&cek, &header.object_id, b"HIDE/0.1 metadata")?;
    let aad = metadata_aad(&header.object_id);
    let mut metadata =
        hide_crypto::open(&metadata_key, &[0; 12], &aad, &header.encrypted_metadata)?;
    edit_metadata(&mut metadata);
    header.encrypted_metadata = hide_crypto::seal(&metadata_key, &[0; 12], &aad, &metadata)?;
    edit(&mut header);

    // Encoded by hand where the edit left the header outside what encode()
    // accepts would defeat the purpose; every edit used here stays encodable.
    let protected = header.encode()?;
    let length = hide_format::encode_header(&protected, &[0; 32])?.len();
    let mut bytes = Preamble::decode(&container[..PREAMBLE_LEN])?.encode();
    bytes[9] = minor.unwrap_or(bytes[9]);
    bytes[11] = flags.unwrap_or(bytes[11]);
    bytes[12..].copy_from_slice(&(length as u32).to_be_bytes());
    let mac_key = hide_crypto::derive_key(&cek, &header.object_id, b"HIDE/0.1 header-mac")?;
    let mac = hide_crypto::mac(&mac_key, &[&bytes, &protected])?;
    let salt: [u8; 16] = container[header_end..header_end + 16]
        .try_into()
        .map_err(|_| ObjectError::TruncatedPayload)?;

    let mut out = bytes.to_vec();
    out.extend_from_slice(&hide_format::encode_header(&protected, &mac)?);
    out.extend_from_slice(&salt);
    let key = payload_key(&cek, &header.object_id, &salt)?;
    encrypt_records(
        &mut plaintext.as_slice(),
        &mut out,
        &key,
        &header.object_id,
        &hide_crypto::hash(&[&protected]),
    )?;
    Ok(out)
}

/// Swaps in `protected` verbatim, which may be bytes `encode()` refuses, and
/// re-authenticates everything a recipient controls around it. Lets the vector
/// generator prove a reader refuses a malformed header for that reason alone,
/// not because the MAC failed first. Test-only.
#[cfg(feature = "test-vectors")]
pub fn replace_protected_for_test(
    container: &[u8],
    secret: &RecipientSecret,
    protected: &[u8],
) -> Result<Vec<u8>, ObjectError> {
    let preamble = Preamble::decode(&container[..PREAMBLE_LEN])?;
    let header_end = PREAMBLE_LEN + preamble.header_len();
    let (original, mac) = hide_format::decode_header(&container[PREAMBLE_LEN..header_end])?;
    let header = ProtectedHeader::decode(&original)?;
    let cek = recover_cek(secret, &header, &container[..PREAMBLE_LEN], &original, &mac)?;
    let mut plaintext = Vec::new();
    decrypt_to_staging(&mut &container[..], &mut plaintext, secret)?;

    let length = hide_format::encode_header(protected, &[0; 32])?.len();
    let mut bytes = preamble.encode();
    bytes[12..].copy_from_slice(&(length as u32).to_be_bytes());
    let mac_key = hide_crypto::derive_key(&cek, &header.object_id, b"HIDE/0.1 header-mac")?;
    let mac = hide_crypto::mac(&mac_key, &[&bytes, protected])?;
    let salt = &container[header_end..header_end + 16];
    let mut out = bytes.to_vec();
    out.extend_from_slice(&hide_format::encode_header(protected, &mac)?);
    out.extend_from_slice(salt);
    let salt: [u8; 16] = salt.try_into().map_err(|_| ObjectError::TruncatedPayload)?;
    let key = payload_key(&cek, &header.object_id, &salt)?;
    encrypt_records(
        &mut plaintext.as_slice(),
        &mut out,
        &key,
        &header.object_id,
        &hide_crypto::hash(&[protected]),
    )?;
    Ok(out)
}

/// Deterministic signed container, so the vectors are reproducible.
#[cfg(feature = "test-vectors")]
pub fn encrypt_signed_for_vector<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipient: &RecipientPublic,
    metadata: &Metadata,
    identity: &SigningIdentity,
    placement: SignaturePlacement,
) -> Result<u64, ObjectError> {
    encrypt_for_vector_inner(
        input,
        output,
        recipient,
        metadata,
        Some((identity, placement)),
        &VectorShape::default(),
    )
}

/// Deterministic container with an explicit wire shape (GREASE, other minors),
/// signed or not. The vector generator is the only caller.
#[cfg(feature = "test-vectors")]
pub fn encrypt_shaped_for_vector<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipient: &RecipientPublic,
    metadata: &Metadata,
    signer: Option<(&SigningIdentity, SignaturePlacement)>,
    shape: &VectorShape,
) -> Result<u64, ObjectError> {
    encrypt_for_vector_inner(input, output, recipient, metadata, signer, shape)
}

#[cfg(feature = "test-vectors")]
fn encrypt_for_vector_inner<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    recipient: &RecipientPublic,
    metadata: &Metadata,
    signer: Option<(&SigningIdentity, SignaturePlacement)>,
    shape: &VectorShape,
) -> Result<u64, ObjectError> {
    let material = ObjectMaterial {
        cek: ContentKey::from_bytes([0x11; 32]),
        object_id: [0x22; 32],
        payload_salt: [0x33; 16],
    };
    let wrapped = hide_crypto::wrap_cek_for_vector(
        recipient,
        &material.cek,
        &material.object_id,
        [0x44; 32],
    )?;
    encrypt_inner(
        input,
        output,
        metadata,
        material,
        vec![RecipientStanza {
            encapsulation: wrapped.encapsulation,
            wrapped_cek: wrapped.wrapped_cek,
        }],
        signer,
        shape,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypt_bytes(plaintext: &[u8], secret: &RecipientSecret) -> Result<Vec<u8>, ObjectError> {
        let mut ciphertext = Vec::new();
        encrypt(
            &mut &*plaintext,
            &mut ciphertext,
            &[secret.public_key()?],
            &Metadata::default(),
        )?;
        Ok(ciphertext)
    }

    #[test]
    fn boundary_sizes_roundtrip() -> Result<(), ObjectError> {
        let secret = RecipientSecret::generate()?;
        for size in [
            0,
            1,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            2 * CHUNK_LEN,
            3 * CHUNK_LEN + 17,
        ] {
            let plaintext = vec![0x5a; size];
            let ciphertext = encrypt_bytes(&plaintext, &secret)?;
            let mut output = Vec::new();
            let verified = decrypt_to_staging(&mut ciphertext.as_slice(), &mut output, &secret)?;
            assert_eq!(verified.plaintext_len, size as u64);
            assert_eq!(output, plaintext);
        }
        Ok(())
    }

    #[test]
    fn multiple_recipients_share_one_payload() -> Result<(), ObjectError> {
        let alice = RecipientSecret::generate()?;
        let bob = RecipientSecret::generate()?;
        let mut ciphertext = Vec::new();
        let metadata = Metadata {
            filename: Some("hello.txt".into()),
            media_type: Some("text/plain".into()),
            signature: None,
            extensions: Vec::new(),
        };
        encrypt(
            &mut b"Hello HIDE\n".as_slice(),
            &mut ciphertext,
            &[alice.public_key()?, bob.public_key()?],
            &metadata,
        )?;
        for secret in [&alice, &bob] {
            let mut output = Vec::new();
            let verified = decrypt_to_staging(&mut ciphertext.as_slice(), &mut output, secret)?;
            assert_eq!(output, b"Hello HIDE\n");
            assert_eq!(verified.metadata, metadata);
        }
        assert!(!ciphertext.windows(9).any(|window| window == b"hello.txt"));
        Ok(())
    }

    #[test]
    fn rejects_tampering_in_every_container_region() -> Result<(), ObjectError> {
        let secret = RecipientSecret::generate()?;
        let ciphertext = encrypt_bytes(&vec![7; CHUNK_LEN + 1], &secret)?;
        let header_end = PREAMBLE_LEN + Preamble::decode(&ciphertext[..PREAMBLE_LEN])?.header_len();
        for offset in [
            8,
            11,
            15,
            30,
            80,
            header_end - 1,
            header_end,
            header_end + 16,
            header_end + 20,
            header_end + 30,
            ciphertext.len() - 1,
        ] {
            let mut damaged = ciphertext.clone();
            damaged[offset] ^= 1;
            assert!(
                decrypt_to_staging(&mut damaged.as_slice(), &mut Vec::new(), &secret).is_err(),
                "offset {offset}"
            );
        }
        let other = RecipientSecret::generate()?;
        assert!(decrypt_to_staging(&mut ciphertext.as_slice(), &mut Vec::new(), &other).is_err());
        Ok(())
    }

    #[test]
    fn rejects_missing_final_reordered_duplicate_and_extra_records() -> Result<(), ObjectError> {
        let secret = RecipientSecret::generate()?;
        let ciphertext = encrypt_bytes(&vec![7; 2 * CHUNK_LEN + 1], &secret)?;
        let payload_start =
            PREAMBLE_LEN + Preamble::decode(&ciphertext[..PREAMBLE_LEN])?.header_len() + 16;
        let record_len = 5 + CHUNK_LEN + TAG_LEN;
        let mut reordered = ciphertext.clone();
        reordered[payload_start..payload_start + record_len].copy_from_slice(
            &ciphertext[payload_start + record_len..payload_start + 2 * record_len],
        );
        let mut duplicated = ciphertext.clone();
        duplicated.splice(
            payload_start..payload_start,
            ciphertext[payload_start..payload_start + record_len]
                .iter()
                .copied(),
        );
        let mut extra = ciphertext.clone();
        extra.push(0);
        for damaged in [
            ciphertext[..payload_start + 2 * record_len].to_vec(),
            reordered,
            duplicated,
            extra,
            ciphertext[..ciphertext.len() - 1].to_vec(),
        ] {
            assert!(decrypt_to_staging(&mut damaged.as_slice(), &mut Vec::new(), &secret).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_empty_final_and_large_record() {
        assert!(record_length(FINAL, 16, 1).is_err());
        assert!(record_length(DATA, 16, 0).is_err());
        assert!(record_length(FINAL, usize::MAX, 0).is_err());
        assert!(record_length(3, 17, 0).is_err());
    }

    #[test]
    fn chunk_binding_covers_every_field_exactly() {
        let aad = chunk_aad(
            &[0xa1; 32],
            &[0xb2; 32],
            0x0102_0304_0506_0708,
            DATA,
            0x1234,
        );
        assert_eq!(&aad[..14], b"HIDE/0.1 chunk");
        assert_eq!(&aad[14..46], &[0xa1; 32]);
        assert_eq!(&aad[46..78], &[0xb2; 32]);
        assert_eq!(&aad[78..86], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(aad[86], DATA);
        assert_eq!(&aad[87..], &[0, 0, 0x12, 0x34]);

        let mut contexts = std::collections::HashSet::new();
        for kind in [DATA, FINAL] {
            for counter in [0, 1, 2, u32::MAX as u64] {
                let context = (
                    chunk_aad(&[0; 32], &[0; 32], counter, kind, 7).to_vec(),
                    nonce(counter, kind),
                );
                assert!(
                    contexts.insert(context),
                    "nonce/AAD reuse at {counter}/{kind}"
                );
            }
        }
        assert_ne!(
            chunk_aad(&[0; 32], &[0; 32], 0, DATA, 7),
            chunk_aad(&[0; 32], &[0; 32], 0, FINAL, 7)
        );
        assert_eq!(nonce(1, DATA), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(nonce(1, FINAL), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]);
        assert_eq!(
            nonce(u32::MAX as u64, DATA)[3..11],
            [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn metadata_binding_covers_object_and_suite() {
        let aad = metadata_aad(&[0xc3; 32]);
        assert_eq!(&aad[..17], b"HIDE/0.1 metadata");
        assert_eq!(&aad[17..49], &[0xc3; 32]);
        assert_eq!(&aad[49..], &[0, 1]);
        assert_ne!(metadata_aad(&[1; 32]), metadata_aad(&[2; 32]));
    }
}
