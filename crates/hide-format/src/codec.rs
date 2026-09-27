use minicbor::{Decoder, Encoder};

use crate::{
    FIRST_IGNORABLE_KEY, FormatError, MAX_EXTENSION_LEN, MAX_EXTENSIONS, MAX_HEADER_LEN,
    MAX_METADATA_LEN, MAX_RECIPIENTS, MAX_SIGNATURES, MAX_STANZA_ITEMS, SUITE, TAG_LEN,
};

/// Stanza tag of the one recipient type HIDE/1.0 defines.
const XWING_TAG: u64 = 1;
const ENCAPSULATION_LEN: usize = 1120;
const WRAPPED_CEK_LEN: usize = 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientStanza {
    pub encapsulation: Vec<u8>,
    pub wrapped_cek: Vec<u8>,
}

/// A recipient stanza of a type this implementation does not know. It is kept
/// so the header re-encodes canonically and a signature can cover it, and it is
/// skipped when looking for a key: a future recipient type must not make the
/// file unreadable to the recipients it already had.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownStanza {
    pub tag: u16,
    pub fields: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stanza {
    XWing(RecipientStanza),
    Unknown(UnknownStanza),
}

impl Stanza {
    pub fn tag(&self) -> u16 {
        match self {
            Self::XWing(_) => XWING_TAG as u16,
            Self::Unknown(stanza) => stanza.tag,
        }
    }

    /// The byte-string items after the tag, in wire order.
    pub fn fields(&self) -> Vec<&[u8]> {
        match self {
            Self::XWing(stanza) => vec![&stanza.encapsulation, &stanza.wrapped_cek],
            Self::Unknown(stanza) => stanza.fields.iter().map(Vec::as_slice).collect(),
        }
    }

    pub fn as_xwing(&self) -> Option<&RecipientStanza> {
        match self {
            Self::XWing(stanza) => Some(stanza),
            Self::Unknown(_) => None,
        }
    }
}

impl From<RecipientStanza> for Stanza {
    fn from(stanza: RecipientStanza) -> Self {
        Self::XWing(stanza)
    }
}

/// An ignorable map entry: key 64..=65535, value an opaque byte string. A reader
/// that does not know the key skips it; it is still authenticated and signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub key: u16,
    pub value: Vec<u8>,
}

/// A public signature over the container, readable by anyone holding the file.
/// Confidential signatures live inside the encrypted metadata instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureStanza {
    pub verifying_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub const VERIFYING_KEY_LEN: usize = 1984;
pub const SIGNATURE_LEN: usize = 3373;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedHeader {
    pub object_id: [u8; 32],
    pub recipients: Vec<Stanza>,
    pub encrypted_metadata: Vec<u8>,
    /// Occupies the slot reserved as an empty array in v0.1. Empty here encodes
    /// byte-for-byte as a v0.1 header, which is what keeps old files readable.
    pub signatures: Vec<SignatureStanza>,
    /// Ignorable keys after 5, ascending. Empty encodes exactly as HIDE/0.1.
    pub extensions: Vec<Extension>,
}

impl ProtectedHeader {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.encode_with_signatures(true)
    }

    /// The exact bytes a signature covers: the header with the signature slot
    /// empty. Signing the slot that holds the signature would be circular.
    pub fn signing_base(&self) -> Result<Vec<u8>, FormatError> {
        self.encode_with_signatures(false)
    }

    fn encode_with_signatures(&self, include: bool) -> Result<Vec<u8>, FormatError> {
        if self.recipients.is_empty() || self.recipients.len() > MAX_RECIPIENTS {
            return Err(FormatError::MalformedHeader);
        }
        if !(TAG_LEN..=MAX_METADATA_LEN + TAG_LEN).contains(&self.encrypted_metadata.len()) {
            return Err(FormatError::InvalidMetadata);
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(FormatError::MalformedHeader);
        }
        check_extensions(&self.extensions).map_err(|_| FormatError::MalformedHeader)?;
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .map(5 + self.extensions.len() as u64)?
            .u8(1)?
            .u16(SUITE)?
            .u8(2)?
            .bytes(&self.object_id)?;
        encoder.u8(3)?.array(self.recipients.len() as u64)?;
        for stanza in &self.recipients {
            encode_stanza(&mut encoder, stanza)?;
        }
        encoder.u8(4)?.bytes(&self.encrypted_metadata)?.u8(5)?;
        let signatures: &[SignatureStanza] = if include { &self.signatures } else { &[] };
        encoder.array(signatures.len() as u64)?;
        for stanza in signatures {
            if stanza.verifying_key.len() != VERIFYING_KEY_LEN
                || stanza.signature.len() != SIGNATURE_LEN
            {
                return Err(FormatError::MalformedHeader);
            }
            encoder
                .array(3)?
                .u8(1)?
                .bytes(&stanza.verifying_key)?
                .bytes(&stanza.signature)?;
        }
        for extension in &self.extensions {
            encoder.u16(extension.key)?.bytes(&extension.value)?;
        }
        let bytes = encoder.into_writer();
        check_header_len(bytes.len())?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        check_header_len(bytes.len())?;
        let mut decoder = Decoder::new(bytes);
        let entries = decoder.map()?.ok_or(FormatError::MalformedHeader)?;
        if !(5..=5 + MAX_EXTENSIONS as u64).contains(&entries) {
            return Err(FormatError::MalformedHeader);
        }
        key(&mut decoder, 1)?;
        if decoder.u16()? != SUITE {
            return Err(FormatError::UnsupportedSuite);
        }
        key(&mut decoder, 2)?;
        let object_id = decoder
            .bytes()?
            .try_into()
            .map_err(|_| FormatError::MalformedHeader)?;
        key(&mut decoder, 3)?;
        let count = decoder.array()?.ok_or(FormatError::MalformedHeader)?;
        if count == 0 || count > MAX_RECIPIENTS as u64 {
            return Err(FormatError::MalformedHeader);
        }
        let mut recipients = Vec::with_capacity(count as usize);
        for _ in 0..count {
            recipients.push(decode_stanza(&mut decoder)?);
        }
        key(&mut decoder, 4)?;
        let metadata = decoder.bytes()?;
        if !(TAG_LEN..=MAX_METADATA_LEN + TAG_LEN).contains(&metadata.len()) {
            return Err(FormatError::InvalidMetadata);
        }
        key(&mut decoder, 5)?;
        let signature_count = decoder.array()?.ok_or(FormatError::MalformedHeader)?;
        if signature_count > MAX_SIGNATURES as u64 {
            return Err(FormatError::MalformedHeader);
        }
        let mut signatures = Vec::with_capacity(signature_count as usize);
        for _ in 0..signature_count {
            signatures.push(decode_signature(&mut decoder)?);
        }
        let extensions =
            decode_extensions(&mut decoder, entries - 5, 5).map_err(|error| match error {
                FormatError::UnsupportedFeature => error,
                _ => FormatError::MalformedHeader,
            })?;
        let header = Self {
            object_id,
            recipients,
            encrypted_metadata: metadata.to_vec(),
            signatures,
            extensions,
        };
        canonical(bytes, decoder.position(), &header.encode()?)?;
        Ok(header)
    }
}

fn encode_stanza(encoder: &mut Encoder<Vec<u8>>, stanza: &Stanza) -> Result<(), FormatError> {
    match stanza {
        Stanza::XWing(stanza) => {
            if stanza.encapsulation.len() != ENCAPSULATION_LEN
                || stanza.wrapped_cek.len() != WRAPPED_CEK_LEN
            {
                return Err(FormatError::MalformedHeader);
            }
            encoder
                .array(3)?
                .u64(XWING_TAG)?
                .bytes(&stanza.encapsulation)?
                .bytes(&stanza.wrapped_cek)?;
        }
        Stanza::Unknown(stanza) => {
            if u64::from(stanza.tag) <= XWING_TAG
                || stanza.fields.len() >= MAX_STANZA_ITEMS
                || stanza.fields.iter().any(|f| f.len() > MAX_EXTENSION_LEN)
            {
                return Err(FormatError::MalformedHeader);
            }
            encoder
                .array(1 + stanza.fields.len() as u64)?
                .u16(stanza.tag)?;
            for field in &stanza.fields {
                encoder.bytes(field)?;
            }
        }
    }
    Ok(())
}

fn decode_stanza(decoder: &mut Decoder<'_>) -> Result<Stanza, FormatError> {
    let items = decoder.array()?.ok_or(FormatError::MalformedHeader)?;
    if !(1..=MAX_STANZA_ITEMS as u64).contains(&items) {
        return Err(FormatError::MalformedHeader);
    }
    let tag = decoder.u64()?;
    if tag == XWING_TAG {
        if items != 3 {
            return Err(FormatError::MalformedHeader);
        }
        let encapsulation = decoder.bytes()?;
        let wrapped_cek = decoder.bytes()?;
        if encapsulation.len() != ENCAPSULATION_LEN || wrapped_cek.len() != WRAPPED_CEK_LEN {
            return Err(FormatError::MalformedHeader);
        }
        return Ok(Stanza::XWing(RecipientStanza {
            encapsulation: encapsulation.to_vec(),
            wrapped_cek: wrapped_cek.to_vec(),
        }));
    }
    let tag = u16::try_from(tag).map_err(|_| FormatError::MalformedHeader)?;
    if tag == 0 {
        return Err(FormatError::MalformedHeader);
    }
    let mut fields = Vec::new();
    for _ in 1..items {
        let field = decoder.bytes()?;
        if field.len() > MAX_EXTENSION_LEN {
            return Err(FormatError::MalformedHeader);
        }
        fields.push(field.to_vec());
    }
    Ok(Stanza::Unknown(UnknownStanza { tag, fields }))
}

/// Every rule an extension list must satisfy, on the way out as on the way in.
fn check_extensions(extensions: &[Extension]) -> Result<(), FormatError> {
    if extensions.len() > MAX_EXTENSIONS {
        return Err(FormatError::MalformedHeader);
    }
    let mut previous = 0;
    for extension in extensions {
        let key = u64::from(extension.key);
        if key < FIRST_IGNORABLE_KEY || key <= previous || extension.value.len() > MAX_EXTENSION_LEN
        {
            return Err(FormatError::MalformedHeader);
        }
        previous = key;
    }
    Ok(())
}

/// Reads `count` map entries after the core keys, the last of which was
/// `last_core`. A key in the critical range 6..=63 is refused as
/// `UnsupportedFeature`: 1.0 defines none, so no reader can honour one.
fn decode_extensions(
    decoder: &mut Decoder<'_>,
    count: u64,
    last_core: u64,
) -> Result<Vec<Extension>, FormatError> {
    let mut extensions = Vec::new();
    let mut previous = last_core;
    for _ in 0..count {
        let key = decoder.u64()?;
        if key <= previous {
            return Err(FormatError::MalformedHeader);
        }
        if key < FIRST_IGNORABLE_KEY {
            return Err(FormatError::UnsupportedFeature);
        }
        let key = u16::try_from(key).map_err(|_| FormatError::MalformedHeader)?;
        let value = decoder.bytes()?;
        if value.len() > MAX_EXTENSION_LEN {
            return Err(FormatError::MalformedHeader);
        }
        previous = u64::from(key);
        extensions.push(Extension {
            key,
            value: value.to_vec(),
        });
    }
    Ok(extensions)
}

fn decode_signature(decoder: &mut Decoder<'_>) -> Result<SignatureStanza, FormatError> {
    if decoder.array()? != Some(3) || decoder.u8()? != 1 {
        return Err(FormatError::UnsupportedFeature);
    }
    let verifying_key = decoder.bytes()?;
    let signature = decoder.bytes()?;
    if verifying_key.len() != VERIFYING_KEY_LEN || signature.len() != SIGNATURE_LEN {
        return Err(FormatError::MalformedHeader);
    }
    Ok(SignatureStanza {
        verifying_key: verifying_key.to_vec(),
        signature: signature.to_vec(),
    })
}

pub fn encode_header(protected: &[u8], mac: &[u8; 32]) -> Result<Vec<u8>, FormatError> {
    check_header_len(protected.len())?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(2)?.bytes(protected)?.bytes(mac)?;
    let bytes = encoder.into_writer();
    check_header_len(bytes.len())?;
    Ok(bytes)
}

pub fn decode_header(bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), FormatError> {
    check_header_len(bytes.len())?;
    let mut decoder = Decoder::new(bytes);
    if decoder.array()? != Some(2) {
        return Err(FormatError::MalformedHeader);
    }
    let protected = decoder.bytes()?;
    let mac = decoder
        .bytes()?
        .try_into()
        .map_err(|_| FormatError::MalformedHeader)?;
    canonical(bytes, decoder.position(), &encode_header(protected, &mac)?)?;
    Ok((protected.to_vec(), mac))
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub filename: Option<String>,
    pub media_type: Option<String>,
    /// A signature visible only to recipients. Excluded from the signing base,
    /// because it cannot cover itself.
    pub signature: Option<SignatureStanza>,
    /// Ignorable keys 64..=65535, ascending. Part of the signing base.
    pub extensions: Vec<Extension>,
}

impl Metadata {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.encode_with_signature(true)
    }

    /// The metadata as it looked before a signature was attached.
    pub fn signing_base(&self) -> Result<Vec<u8>, FormatError> {
        self.encode_with_signature(false)
    }

    fn encode_with_signature(&self, include: bool) -> Result<Vec<u8>, FormatError> {
        let signature = if include {
            self.signature.as_ref()
        } else {
            None
        };
        let mut encoder = Encoder::new(Vec::new());
        check_extensions(&self.extensions).map_err(|_| FormatError::InvalidMetadata)?;
        encoder.map(
            u64::from(self.filename.is_some())
                + u64::from(self.media_type.is_some())
                + u64::from(signature.is_some())
                + self.extensions.len() as u64,
        )?;
        if let Some(filename) = &self.filename {
            validate_filename(filename)?;
            encoder.u8(1)?.str(filename)?;
        }
        if let Some(media_type) = &self.media_type {
            if media_type.is_empty()
                || media_type.len() > 255
                || !media_type.bytes().all(|byte| (32..=126).contains(&byte))
            {
                return Err(FormatError::InvalidMetadata);
            }
            encoder.u8(2)?.str(media_type)?;
        }
        if let Some(stanza) = signature {
            if stanza.verifying_key.len() != VERIFYING_KEY_LEN
                || stanza.signature.len() != SIGNATURE_LEN
            {
                return Err(FormatError::InvalidMetadata);
            }
            encoder
                .u8(3)?
                .array(3)?
                .u8(1)?
                .bytes(&stanza.verifying_key)?
                .bytes(&stanza.signature)?;
        }
        for extension in &self.extensions {
            encoder.u16(extension.key)?.bytes(&extension.value)?;
        }
        Ok(encoder.into_writer())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_METADATA_LEN {
            return Err(FormatError::InvalidMetadata);
        }
        let mut decoder = Decoder::new(bytes);
        let count = decoder.map()?.ok_or(FormatError::InvalidMetadata)?;
        if count > 3 + MAX_EXTENSIONS as u64 {
            return Err(FormatError::InvalidMetadata);
        }
        let mut metadata = Self::default();
        let mut previous = 0;
        let mut remaining = count;
        while remaining > 0 {
            // Peek: a key past 3 starts the extension run, which must be last.
            let mut probe = decoder.clone();
            let field = probe.u64()?;
            if field > 3 {
                break;
            }
            decoder.u64()?;
            remaining -= 1;
            if field <= previous || field == 0 {
                return Err(FormatError::InvalidMetadata);
            }
            previous = field;
            if field == 3 {
                metadata.signature =
                    Some(decode_signature(&mut decoder).map_err(|_| FormatError::InvalidMetadata)?);
                continue;
            }
            let text = decoder.str()?;
            if text.len() > 255 {
                return Err(FormatError::InvalidMetadata);
            }
            match field {
                1 => metadata.filename = Some(text.to_owned()),
                2 => metadata.media_type = Some(text.to_owned()),
                _ => return Err(FormatError::InvalidMetadata),
            }
        }
        metadata.extensions =
            decode_extensions(&mut decoder, remaining, previous).map_err(|error| match error {
                FormatError::UnsupportedFeature => error,
                _ => FormatError::InvalidMetadata,
            })?;
        canonical(bytes, decoder.position(), &metadata.encode()?)?;
        Ok(metadata)
    }
}

fn validate_filename(filename: &str) -> Result<(), FormatError> {
    let stem = filename
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && (b'1'..=b'9').contains(&stem.as_bytes()[3]));
    if filename.is_empty()
        || filename.len() > 255
        || matches!(filename, "." | "..")
        || filename.ends_with(['.', ' '])
        || reserved
        || filename
            .chars()
            .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
    {
        return Err(FormatError::InvalidMetadata);
    }
    Ok(())
}

fn key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), FormatError> {
    if decoder.u8()? != expected {
        return Err(FormatError::MalformedHeader);
    }
    Ok(())
}

fn check_header_len(length: usize) -> Result<(), FormatError> {
    if length == 0 || length > MAX_HEADER_LEN {
        return Err(FormatError::HeaderTooLarge);
    }
    Ok(())
}

fn canonical(original: &[u8], consumed: usize, encoded: &[u8]) -> Result<(), FormatError> {
    if consumed != original.len() || original != encoded {
        return Err(FormatError::NonCanonical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> ProtectedHeader {
        ProtectedHeader {
            object_id: [1; 32],
            recipients: vec![Stanza::XWing(RecipientStanza {
                encapsulation: vec![2; 1120],
                wrapped_cek: vec![3; 48],
            })],
            encrypted_metadata: vec![4; 17],
            signatures: Vec::new(),
            extensions: Vec::new(),
        }
    }

    #[test]
    fn header_roundtrip_preserves_authenticated_bytes() -> Result<(), FormatError> {
        let protected = header().encode()?;
        assert_eq!(ProtectedHeader::decode(&protected)?, header());
        assert_eq!(
            decode_header(&encode_header(&protected, &[5; 32])?)?,
            (protected, [5; 32])
        );
        Ok(())
    }

    fn signed_header() -> ProtectedHeader {
        ProtectedHeader {
            signatures: vec![SignatureStanza {
                verifying_key: vec![6; VERIFYING_KEY_LEN],
                signature: vec![7; SIGNATURE_LEN],
            }],
            ..header()
        }
    }

    /// The compatibility invariant: an unsigned header must be byte-identical to
    /// what v0.1 wrote, or every existing container stops opening.
    #[test]
    fn an_unsigned_header_still_ends_with_the_v0_1_empty_slot() -> Result<(), FormatError> {
        let encoded = header().encode()?;
        // 0x05 = key 5, 0x80 = CBOR array of length 0.
        assert_eq!(&encoded[encoded.len() - 2..], &[0x05, 0x80]);
        assert_eq!(header().signing_base()?, encoded);
        Ok(())
    }

    #[test]
    fn a_signed_header_survives_encoding() -> Result<(), FormatError> {
        let encoded = signed_header().encode()?;
        assert_eq!(ProtectedHeader::decode(&encoded)?, signed_header());
        Ok(())
    }

    /// The signature covers the header with the slot empty, so adding a
    /// signature must not disturb what earlier signers committed to.
    #[test]
    fn the_signing_base_excludes_the_signatures() -> Result<(), FormatError> {
        assert_eq!(signed_header().signing_base()?, header().encode()?);
        Ok(())
    }

    #[test]
    fn a_malformed_signature_stanza_is_refused() {
        for (key_len, sig_len) in [
            (VERIFYING_KEY_LEN - 1, SIGNATURE_LEN),
            (VERIFYING_KEY_LEN, SIGNATURE_LEN + 1),
        ] {
            let header = ProtectedHeader {
                signatures: vec![SignatureStanza {
                    verifying_key: vec![6; key_len],
                    signature: vec![7; sig_len],
                }],
                ..header()
            };
            assert_eq!(header.encode(), Err(FormatError::MalformedHeader));
        }
    }

    #[test]
    fn too_many_signatures_are_refused() {
        let header = ProtectedHeader {
            signatures: vec![
                SignatureStanza {
                    verifying_key: vec![6; VERIFYING_KEY_LEN],
                    signature: vec![7; SIGNATURE_LEN],
                };
                MAX_SIGNATURES + 1
            ],
            ..header()
        };
        assert_eq!(header.encode(), Err(FormatError::MalformedHeader));
    }

    // Only the first stanza is ever verified, so a second one on the wire would
    // be a signature nobody checks. The decoder must refuse it, not skip it.
    #[test]
    fn a_second_signature_stanza_is_refused_on_the_wire() -> Result<(), FormatError> {
        let stanza = SignatureStanza {
            verifying_key: vec![6; VERIFYING_KEY_LEN],
            signature: vec![7; SIGNATURE_LEN],
        };
        let one = ProtectedHeader {
            signatures: vec![stanza.clone()],
            ..header()
        }
        .encode()?;
        assert!(ProtectedHeader::decode(&one).is_ok());

        // The signature array is the last field, so its CBOR head is the last
        // `array(1)` marker before the stanza. Rewrite it to `array(2)` and
        // append a copy of the stanza, which is what encode() refuses to do.
        let mut single = Encoder::new(Vec::new());
        single
            .array(3)?
            .u8(1)?
            .bytes(&stanza.verifying_key)?
            .bytes(&stanza.signature)?;
        let encoded_stanza = single.into_writer();
        let stanza_at = one.len() - encoded_stanza.len();
        assert_eq!(&one[stanza_at..], encoded_stanza.as_slice());
        assert_eq!(
            one[stanza_at - 1],
            0x81,
            "array(1) head precedes the stanza"
        );
        let mut two = one.clone();
        two[stanza_at - 1] = 0x82;
        two.extend_from_slice(&encoded_stanza);

        assert_eq!(
            ProtectedHeader::decode(&two),
            Err(FormatError::MalformedHeader)
        );
        Ok(())
    }

    #[test]
    fn metadata_has_exact_encoding() -> Result<(), FormatError> {
        let metadata = Metadata {
            filename: Some("hello.txt".into()),
            ..Metadata::default()
        };
        assert_eq!(metadata.encode()?, b"\xa1\x01\x69hello.txt");
        assert_eq!(Metadata::decode(b"\xa1\x01\x69hello.txt")?, metadata);
        assert_eq!(Metadata::default().encode()?, [0xa0]);
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_duplicate_unknown_and_indefinite() -> Result<(), FormatError> {
        for bytes in [
            b"\xa1\x18\x01\x61a".as_slice(),
            b"\xbf\xff",
            b"\xa2\x01\x61a\x01\x61b",
            b"\xa1\x03\x61a",
            b"\xa0\x00",
            b"\xa1\x01\x7f\xff",
            b"\xa1\x01\xc0\x61a",
        ] {
            assert!(Metadata::decode(bytes).is_err(), "{bytes:?}");
        }
        let original = header().encode()?;
        let mut nonminimal = original.clone();
        nonminimal.splice(2..3, [0x18, 1]);
        assert_eq!(
            ProtectedHeader::decode(&nonminimal),
            Err(FormatError::NonCanonical)
        );
        let mut duplicate = original;
        duplicate[3] = 1;
        assert!(ProtectedHeader::decode(&duplicate).is_err());
        Ok(())
    }

    #[test]
    fn rejects_hostile_counts_and_every_truncated_header() -> Result<(), FormatError> {
        let bytes = header().encode()?;
        for length in 0..bytes.len() {
            assert!(ProtectedHeader::decode(&bytes[..length]).is_err());
        }
        let mut oversized = header();
        oversized.recipients = vec![oversized.recipients[0].clone(); MAX_RECIPIENTS + 1];
        assert!(oversized.encode().is_err());
        assert!(decode_header(&vec![0; MAX_HEADER_LEN + 1]).is_err());
        assert!(ProtectedHeader::decode(b"\xa5\x01\x01\x02\x58\xff").is_err());
        Ok(())
    }

    #[test]
    fn rejects_nonportable_filenames() {
        for filename in [
            "",
            ".",
            "..",
            "../a",
            "a/b",
            "a\\b",
            "C:a",
            "NUL.txt",
            "com1",
            "LPT9.pdf",
            "file.",
            "file ",
            "line\nname",
            "a*b",
        ] {
            assert!(
                Metadata {
                    filename: Some(filename.into()),
                    ..Metadata::default()
                }
                .encode()
                .is_err(),
                "{filename:?}"
            );
        }
    }
}
