use hide_format::{
    FormatError, MAX_HEADER_LEN, MAX_METADATA_LEN, MAX_RECIPIENTS, Metadata, PREAMBLE_LEN,
    Preamble, ProtectedHeader, RecipientStanza, decode_header, encode_header,
};
use proptest::prelude::*;

fn stanza() -> impl Strategy<Value = RecipientStanza> {
    (any::<u8>(), any::<u8>()).prop_map(|(first, second)| RecipientStanza {
        encapsulation: vec![first; 1120],
        wrapped_cek: vec![second; 48],
    })
}

fn header() -> impl Strategy<Value = ProtectedHeader> {
    (
        any::<[u8; 32]>(),
        prop::collection::vec(stanza(), 1..=4),
        16usize..600,
    )
        .prop_map(|(object_id, recipients, metadata_len)| ProtectedHeader {
            object_id,
            recipients,
            encrypted_metadata: vec![0x2b; metadata_len],
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bytes_never_panic_and_never_over_allocate(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = ProtectedHeader::decode(&bytes);
        let _ = decode_header(&bytes);
        let _ = Metadata::decode(&bytes);
        if bytes.len() >= PREAMBLE_LEN {
            if let Ok(preamble) = Preamble::decode(&bytes[..PREAMBLE_LEN]) {
                prop_assert!(preamble.header_len() <= MAX_HEADER_LEN);
            }
        }
    }

    #[test]
    fn header_roundtrip_is_canonical(header in header()) {
        let encoded = header.encode()?;
        prop_assert_eq!(ProtectedHeader::decode(&encoded)?, header);
        prop_assert_eq!(ProtectedHeader::decode(&encoded)?.encode()?, encoded);
    }

    #[test]
    fn single_bit_flips_in_header_are_rejected_or_change_value(header in header(), index in any::<prop::sample::Index>(), bit in 0u32..8) {
        let encoded = header.encode()?;
        let mut damaged = encoded.clone();
        let position = index.index(damaged.len());
        damaged[position] ^= 1 << bit;
        prop_assume!(damaged != encoded);
        if let Ok(decoded) = ProtectedHeader::decode(&damaged) {
            prop_assert_ne!(decoded, header);
        }
    }

    #[test]
    fn truncated_header_never_decodes(header in header(), index in any::<prop::sample::Index>()) {
        let encoded = header.encode()?;
        let cut = index.index(encoded.len());
        prop_assert!(ProtectedHeader::decode(&encoded[..cut]).is_err());
    }

    #[test]
    fn envelope_preserves_exact_protected_bytes(payload in prop::collection::vec(any::<u8>(), 1..512), mac in any::<[u8; 32]>()) {
        let encoded = encode_header(&payload, &mac)?;
        let (recovered, recovered_mac) = decode_header(&encoded)?;
        prop_assert_eq!(recovered, payload);
        prop_assert_eq!(recovered_mac, mac);
    }

    #[test]
    fn metadata_roundtrip_or_rejects_unsafe_names(filename in ".{0,40}", media_type in ".{0,40}") {
        let metadata = Metadata {
            filename: Some(filename),
            media_type: Some(media_type),
        };
        match metadata.encode() {
            Ok(encoded) => {
                prop_assert_eq!(Metadata::decode(&encoded)?, metadata.clone());
                let name = metadata.filename.unwrap_or_default();
                prop_assert!(!name.contains(['/', '\\', ':']));
                prop_assert!(name != "." && name != "..");
                prop_assert!(!name.ends_with('.') && !name.ends_with(' '));
                prop_assert!(!name.chars().any(char::is_control));
            }
            Err(error) => prop_assert_eq!(error, FormatError::InvalidMetadata),
        }
    }

    #[test]
    fn oversized_structures_are_refused(count in (MAX_RECIPIENTS + 1)..=(MAX_RECIPIENTS + 8), metadata_len in (MAX_METADATA_LEN + 17)..(MAX_METADATA_LEN + 64)) {
        let base = RecipientStanza { encapsulation: vec![1; 1120], wrapped_cek: vec![2; 48] };
        let too_many = ProtectedHeader { object_id: [0; 32], recipients: vec![base.clone(); count], encrypted_metadata: vec![0; 32] };
        prop_assert!(too_many.encode().is_err());
        let too_large = ProtectedHeader { object_id: [0; 32], recipients: vec![base], encrypted_metadata: vec![0; metadata_len] };
        prop_assert!(too_large.encode().is_err());
    }
}
