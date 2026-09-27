use thiserror::Error;

mod codec;
pub use codec::{
    Extension, Metadata, ProtectedHeader, RecipientStanza, SIGNATURE_LEN, SignatureStanza, Stanza,
    UnknownStanza, VERIFYING_KEY_LEN, decode_header, encode_header,
};

pub const MAGIC: [u8; 8] = *b"HIDE\r\n\x1a\n";
pub const PREAMBLE_LEN: usize = 16;
pub const MAX_HEADER_LEN: usize = 1024 * 1024;
pub const CHUNK_LEN: usize = 65_536;
pub const SUITE: u16 = 1;
pub const MAX_RECIPIENTS: usize = 64;
/// Exactly one signer is verified, so exactly one stanza is admitted. Allowing
/// more would let a recipient append stanzas nobody checks.
pub const MAX_SIGNATURES: usize = 1;
pub const MAX_METADATA_LEN: usize = 262_144;
pub const TAG_LEN: usize = 16;
/// The one flag HIDE/1.0 defines. Every flag bit is critical: a reader that
/// does not know a set bit must refuse the container, never ignore the bit.
pub const FLAG_SIGNED: u8 = 0x01;
/// HIDE/0.5 through 0.8 marked a signed container by minor 2. Still read,
/// never written, and only valid with no flags set.
pub const LEGACY_SIGNED_MINOR: u8 = 2;
/// The minor a HIDE/1.0 writer emits. A minor is a non-breaking revision, so
/// readers accept every minor except 0 and the legacy 2.
pub const CURRENT_MINOR: u8 = 1;
/// Ignorable extensions: at most this many per map, each value at most this long.
pub const MAX_EXTENSIONS: usize = 16;
pub const MAX_EXTENSION_LEN: usize = 65_536;
/// Keys below this are core (1..=5) or critical (6..=63); at or above it,
/// up to `u16::MAX`, a reader that does not know the key skips it.
pub const FIRST_IGNORABLE_KEY: u64 = 64;
/// A recipient stanza is a tag followed by at most seven byte strings.
pub const MAX_STANZA_ITEMS: usize = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("malformed HIDE header")]
    MalformedHeader,
    #[error("noncanonical CBOR encoding")]
    NonCanonical,
    #[error("unsupported cryptographic suite")]
    UnsupportedSuite,
    #[error("invalid file metadata")]
    InvalidMetadata,
    #[error("invalid HIDE container")]
    InvalidContainer,
    #[error("unsupported HIDE version")]
    UnsupportedVersion,
    #[error("unsupported HIDE object kind or flags")]
    UnsupportedFeature,
    #[error("header length is outside protocol limits")]
    HeaderTooLarge,
}

impl From<minicbor::decode::Error> for FormatError {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::MalformedHeader
    }
}

impl From<minicbor::encode::Error<core::convert::Infallible>> for FormatError {
    fn from(_: minicbor::encode::Error<core::convert::Infallible>) -> Self {
        Self::MalformedHeader
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preamble {
    header_len: u32,
    minor: u8,
    flags: u8,
}

impl Preamble {
    pub fn new(header_len: usize) -> Result<Self, FormatError> {
        Self::with_signed(header_len, false)
    }

    /// A signed container sets the critical SIGNED flag, so a reader that does
    /// not implement signatures refuses it rather than ignoring the signature.
    pub fn with_signed(header_len: usize, signed: bool) -> Result<Self, FormatError> {
        let flags = if signed { FLAG_SIGNED } else { 0 };
        Self::from_parts(header_len, CURRENT_MINOR, flags)
    }

    /// The HIDE/0.5 form of a signed container. Readers still accept it; only
    /// test code writes it, to prove that they do.
    pub fn legacy_signed(header_len: usize) -> Result<Self, FormatError> {
        Self::from_parts(header_len, LEGACY_SIGNED_MINOR, 0)
    }

    /// Validates exactly as [`Preamble::decode`] does.
    pub fn from_parts(header_len: usize, minor: u8, flags: u8) -> Result<Self, FormatError> {
        if minor == 0 {
            return Err(FormatError::UnsupportedVersion);
        }
        if flags & !FLAG_SIGNED != 0 || (minor == LEGACY_SIGNED_MINOR && flags != 0) {
            return Err(FormatError::UnsupportedFeature);
        }
        if header_len == 0 || header_len > MAX_HEADER_LEN {
            return Err(FormatError::HeaderTooLarge);
        }
        Ok(Self {
            header_len: header_len as u32,
            minor,
            flags,
        })
    }

    pub fn header_len(self) -> usize {
        self.header_len as usize
    }

    pub fn minor(self) -> u8 {
        self.minor
    }

    pub fn flags(self) -> u8 {
        self.flags
    }

    pub fn is_signed(self) -> bool {
        self.is_legacy() || self.flags & FLAG_SIGNED != 0
    }

    /// A HIDE/0.5–0.8 signed container: legacy transcript, no extensions.
    pub fn is_legacy(self) -> bool {
        self.minor == LEGACY_SIGNED_MINOR
    }

    /// Magic, major, minor, kind and flags: everything but the header length,
    /// which a signature cannot cover because the signature is in the header.
    pub fn signed_prefix(self) -> [u8; 12] {
        let mut prefix = [0; 12];
        prefix.copy_from_slice(&self.encode()[..12]);
        prefix
    }

    pub fn encode(self) -> [u8; PREAMBLE_LEN] {
        let mut bytes = [0; PREAMBLE_LEN];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[9] = self.minor;
        bytes[10] = 1;
        bytes[11] = self.flags;
        bytes[12..].copy_from_slice(&self.header_len.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() != PREAMBLE_LEN || bytes[..8] != MAGIC {
            return Err(FormatError::InvalidContainer);
        }
        if bytes[8] != 0 {
            return Err(FormatError::UnsupportedVersion);
        }
        if bytes[10] != 1 {
            return Err(FormatError::UnsupportedFeature);
        }
        let length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let length = usize::try_from(length).map_err(|_| FormatError::HeaderTooLarge)?;
        Self::from_parts(length, bytes[9], bytes[11])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_has_exact_wire_encoding() -> Result<(), FormatError> {
        let preamble = Preamble::new(0x1234)?;
        assert_eq!(
            preamble.encode(),
            [
                0x48, 0x49, 0x44, 0x45, 13, 10, 26, 10, 0, 1, 1, 0, 0, 0, 0x12, 0x34
            ]
        );
        assert_eq!(Preamble::decode(&preamble.encode())?, preamble);
        Ok(())
    }

    #[test]
    fn rejects_every_truncated_preamble() -> Result<(), FormatError> {
        let bytes = Preamble::new(128)?.encode();
        for length in 0..PREAMBLE_LEN {
            assert_eq!(
                Preamble::decode(&bytes[..length]),
                Err(FormatError::InvalidContainer)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_unknown_version_kind_flags_and_bad_magic() -> Result<(), FormatError> {
        let original = Preamble::new(128)?.encode();
        // Byte 9, the minor, is left out: a minor is a non-breaking revision and
        // flipping its high bit yields a minor every reader must accept.
        for offset in (0..12).filter(|&offset| offset != 9) {
            let mut bytes = original;
            bytes[offset] ^= 0x80;
            assert!(Preamble::decode(&bytes).is_err(), "offset {offset}");
        }
        Ok(())
    }

    fn with(minor: u8, flags: u8) -> [u8; PREAMBLE_LEN] {
        let mut bytes = Preamble::new(128).expect("valid length").encode();
        bytes[9] = minor;
        bytes[11] = flags;
        bytes
    }

    #[test]
    fn every_minor_but_zero_is_a_readable_revision() -> Result<(), FormatError> {
        for minor in [1, 3, 7, 0x80, 0xff] {
            let preamble = Preamble::decode(&with(minor, 0))?;
            assert_eq!(preamble.minor(), minor);
            assert!(
                !preamble.is_signed() && !preamble.is_legacy(),
                "minor {minor}"
            );
        }
        assert_eq!(
            Preamble::decode(&with(0, 0)),
            Err(FormatError::UnsupportedVersion)
        );
        Ok(())
    }

    /// Every flag is critical. An unknown bit, or any flag on the legacy minor,
    /// must refuse the container rather than be ignored.
    #[test]
    fn flags_are_critical_and_signed_is_the_only_known_one() -> Result<(), FormatError> {
        let signed = Preamble::decode(&with(1, FLAG_SIGNED))?;
        assert!(signed.is_signed() && !signed.is_legacy());
        assert!(Preamble::decode(&with(9, FLAG_SIGNED))?.is_signed());
        for flags in [0x02, 0x04, 0x80, 0x03, 0xff] {
            assert_eq!(
                Preamble::decode(&with(1, flags)),
                Err(FormatError::UnsupportedFeature),
                "flags {flags:#04x}"
            );
        }
        assert_eq!(
            Preamble::decode(&with(LEGACY_SIGNED_MINOR, FLAG_SIGNED)),
            Err(FormatError::UnsupportedFeature)
        );
        Ok(())
    }

    #[test]
    fn legacy_minor_two_reads_as_signed_and_is_never_written() -> Result<(), FormatError> {
        let legacy = Preamble::decode(&with(LEGACY_SIGNED_MINOR, 0))?;
        assert!(legacy.is_signed() && legacy.is_legacy());
        let written = Preamble::with_signed(128, true)?.encode();
        assert_eq!((written[9], written[11]), (CURRENT_MINOR, FLAG_SIGNED));
        // Unsigned 1.0 output stays byte-identical to HIDE/0.1.
        assert_eq!(&Preamble::new(128)?.encode()[8..12], &[0, 1, 1, 0]);
        Ok(())
    }

    #[test]
    fn rejects_hostile_length_before_allocation() -> Result<(), FormatError> {
        assert!(Preamble::new(MAX_HEADER_LEN).is_ok());
        assert_eq!(Preamble::new(0), Err(FormatError::HeaderTooLarge));
        assert_eq!(
            Preamble::new(MAX_HEADER_LEN + 1),
            Err(FormatError::HeaderTooLarge)
        );
        let mut bytes = Preamble::new(128)?.encode();
        bytes[12..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Preamble::decode(&bytes), Err(FormatError::HeaderTooLarge));
        Ok(())
    }
}
