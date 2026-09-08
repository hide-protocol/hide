use thiserror::Error;

mod codec;
pub use codec::{
    Metadata, ProtectedHeader, RecipientStanza, SIGNATURE_LEN, SignatureStanza, VERIFYING_KEY_LEN,
    decode_header, encode_header,
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
    signed: bool,
}

impl Preamble {
    pub fn new(header_len: usize) -> Result<Self, FormatError> {
        Self::with_signed(header_len, false)
    }

    /// Signed containers advertise minor 2, so a v0.1 reader refuses them rather
    /// than opening them with the signature silently ignored.
    pub fn with_signed(header_len: usize, signed: bool) -> Result<Self, FormatError> {
        if header_len == 0 || header_len > MAX_HEADER_LEN {
            return Err(FormatError::HeaderTooLarge);
        }
        Ok(Self {
            header_len: header_len as u32,
            signed,
        })
    }

    pub fn header_len(self) -> usize {
        self.header_len as usize
    }

    pub fn is_signed(self) -> bool {
        self.signed
    }

    pub fn encode(self) -> [u8; PREAMBLE_LEN] {
        let mut bytes = [0; PREAMBLE_LEN];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[9] = if self.signed { 2 } else { 1 };
        bytes[10] = 1;
        bytes[12..].copy_from_slice(&self.header_len.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() != PREAMBLE_LEN || bytes[..8] != MAGIC {
            return Err(FormatError::InvalidContainer);
        }
        if bytes[8] != 0 || !matches!(bytes[9], 1 | 2) {
            return Err(FormatError::UnsupportedVersion);
        }
        if bytes[10] != 1 || bytes[11] != 0 {
            return Err(FormatError::UnsupportedFeature);
        }
        let length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        Self::with_signed(length as usize, bytes[9] == 2)
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
        for offset in 0..12 {
            let mut bytes = original;
            bytes[offset] ^= 0x80;
            assert!(Preamble::decode(&bytes).is_err(), "offset {offset}");
        }
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
