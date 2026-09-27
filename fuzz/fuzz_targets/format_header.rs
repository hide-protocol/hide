#![no_main]
//! The CBOR header parser sees attacker bytes before any key is involved. The
//! properties: never panic, never allocate from an unchecked length, and a
//! header that decodes must re-encode to the same bytes (canonical form).
//! The same holds for the preamble: the minor version and flags byte are
//! extension points, so an accepted preamble must be exactly what `from_parts`
//! would build from its own fields, and must re-encode byte for byte.

use hide_format::{Metadata, PREAMBLE_LEN, Preamble, ProtectedHeader, decode_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Preamble::decode(data);

    // Decode demands exactly 16 bytes; slicing lets every container-shaped
    // corpus entry (the vectors) reach the field checks, not only 16-byte inputs.
    if let Some(prefix) = data.get(..PREAMBLE_LEN) {
        if let Ok(preamble) = Preamble::decode(prefix) {
            let rebuilt =
                Preamble::from_parts(preamble.header_len(), preamble.minor(), preamble.flags())
                    .expect("from_parts accepts what decode accepted");
            assert_eq!(rebuilt, preamble, "from_parts disagrees with decode");
            assert_eq!(preamble.encode(), prefix, "non-canonical preamble accepted");
            assert_eq!(
                preamble.is_signed(),
                preamble.is_legacy() || preamble.flags() != 0,
                "signed flag and legacy minor disagree"
            );
        }
    }

    if let Ok((protected, _mac)) = decode_header(data) {
        if let Ok(header) = ProtectedHeader::decode(&protected) {
            let again = header.encode().expect("a decoded header re-encodes");
            assert_eq!(again, protected, "decode is not the inverse of encode");
        }
    }

    if let Ok(header) = ProtectedHeader::decode(data) {
        assert_eq!(header.encode().unwrap(), data, "non-canonical header accepted");
    }

    if let Ok(metadata) = Metadata::decode(data) {
        assert_eq!(metadata.encode().unwrap(), data, "non-canonical metadata accepted");
    }
});
