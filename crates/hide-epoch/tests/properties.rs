//! Properties an epoch-history decoder must hold (spec §15.4, §16.4).
//!
//! `fuzz/fuzz_targets/epoch_chain.rs` explores this surface freely; this suite
//! pins the statements a change must not break. Canonicality is a property here
//! and not a single case because it is the rule this project had to repair in
//! this very decoder: an empty array written with a four-byte length
//! (`9a 00 00 00 00`) decoded cleanly and re-encoded to `80`, so one history had
//! two byte forms and a transparency log would have hashed them as two leaves.

use hide_epoch::{EpochChain, EpochRecord, decode_records, encode_records, recipient_for};
use proptest::prelude::*;
use std::sync::LazyLock;

/// The X-Wing encapsulation key length a real record carries. `decode_records`
/// deliberately does not check it — only `EpochChain::verify` does — so both
/// sides of that boundary are generated here.
const PUBLIC_KEY_LENGTH: usize = 1216;

/// A record exactly as a chain published by someone else has it. Every field is
/// attacker-chosen: a chain is public data fetched from wherever the identity
/// lives, and nothing about it is trustworthy until `EpochChain::verify` has
/// checked the links.
fn record() -> impl Strategy<Value = EpochRecord> {
    (
        any::<u64>(),
        prop_oneof![
            3 => prop::collection::vec(any::<u8>(), 0..64),
            1 => prop::collection::vec(any::<u8>(), PUBLIC_KEY_LENGTH),
        ],
        any::<[u8; 32]>(),
    )
        .prop_map(|(number, public_key, link)| EpochRecord {
            number,
            public_key,
            link,
        })
}

/// A real chain, built once. `advance` generates its own X-Wing key pair, which
/// is the expensive part, so every case re-encodes or damages one history.
static CHAIN: LazyLock<EpochChain> = LazyLock::new(|| {
    let mut chain = EpochChain::new().expect("a chain starts at epoch zero");
    chain.advance().expect("advancing mints an epoch");
    chain.advance().expect("advancing mints an epoch");
    chain
});

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A chain is fetched, not trusted. Whatever the bytes say, decoding,
    /// verification and restoration must return Ok or Err and never panic —
    /// including for a header that declares a million entries in five bytes.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(records) = decode_records(&bytes) {
            let _ = EpochChain::verify(&records);
            let _ = EpochChain::restore(records.clone(), std::iter::empty());
            for record in &records {
                let _ = recipient_for(&records, record.number);
            }
        }
    }

    /// One chain, one encoding. A published history must re-encode to exactly
    /// the bytes it arrived as, or two implementations hash the same history
    /// differently and a transparency log sees two leaves where there is one.
    #[test]
    fn decoded_records_re_encode_to_the_same_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        if let Ok(records) = decode_records(&bytes) {
            prop_assert_eq!(encode_records(&records)?, bytes);
        }
    }

    /// The same statement from the writing side: anything this encoder writes
    /// decodes back to the same records, and re-encodes to the same bytes.
    #[test]
    fn record_histories_round_trip(records in prop::collection::vec(record(), 0..6)) {
        let encoded = encode_records(&records)?;
        prop_assert_eq!(decode_records(&encoded)?, records);
        prop_assert_eq!(encode_records(&decode_records(&encoded)?)?, encoded);
    }

    /// A history that was cut short, or that carries bytes after its last
    /// record, is not a shorter or longer history — it is refused. Truncation is
    /// what a partial write or an interrupted transfer looks like.
    #[test]
    fn truncation_and_trailing_bytes_are_refused(
        records in prop::collection::vec(record(), 0..6),
        index in any::<prop::sample::Index>(),
        suffix in prop::collection::vec(any::<u8>(), 1..8),
    ) {
        let encoded = encode_records(&records)?;
        let cut = index.index(encoded.len());
        prop_assert!(decode_records(&encoded[..cut]).is_err(), "accepted a {cut} byte prefix");
        let mut extended = encoded.clone();
        extended.extend_from_slice(&suffix);
        prop_assert!(decode_records(&extended).is_err());
    }

    /// A declared count is a claim, not a length. Whatever it says, the decoder
    /// must fail on the missing body rather than reserve — or loop — for entries
    /// the input cannot hold.
    #[test]
    fn a_declared_count_beyond_the_input_is_refused(count in 1u64..=u64::MAX) {
        let mut bytes = Vec::new();
        minicbor::Encoder::new(&mut bytes)
            .array(count)
            .expect("an array header");
        prop_assert!(
            decode_records(&bytes).is_err(),
            "accepted a header claiming {count} entries with no body"
        );
    }

    /// The real thing: a chain this crate built. Its own bytes are the only
    /// bytes it accepts back, it verifies against itself, every epoch is
    /// reachable for a sender, and one damaged byte must leave a chain that
    /// either fails to decode or fails to verify — never a chain that verifies
    /// with different contents.
    #[test]
    fn a_real_chain_is_canonical_and_damage_never_verifies(
        index in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let encoded = encode_records(CHAIN.records())?;
        let decoded = decode_records(&encoded)?;
        prop_assert_eq!(encode_records(&decoded)?, encoded.clone());
        prop_assert!(EpochChain::verify(&decoded).is_ok());
        for number in 0..decoded.len() as u64 {
            prop_assert!(recipient_for(&decoded, number).is_ok());
        }

        let mut damaged = encoded.clone();
        let position = index.index(damaged.len());
        damaged[position] = damaged[position].wrapping_add(delta);
        if let Ok(records) = decode_records(&damaged) {
            prop_assert!(
                EpochChain::verify(&records).is_err(),
                "a damaged chain verified after byte {position} changed"
            );
        }
    }
}
