#![no_main]
//! The CBOR header parser sees attacker bytes before any key is involved. The
//! properties: never panic, never allocate from an unchecked length, and a
//! header that decodes must re-encode to the same bytes (canonical form).

use hide_format::{Metadata, Preamble, ProtectedHeader, decode_header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Preamble::decode(data);

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
