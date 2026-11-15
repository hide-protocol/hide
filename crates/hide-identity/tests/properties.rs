//! Properties anything that reads identity material from an untrusted source
//! must hold (spec §10, §16.1, §16.4).
//!
//! `fuzz/fuzz_targets/identity_log.rs` and `identity_bindings.rs` explore the
//! same surface freely; this suite pins the statements a change must not break.
//! Canonicality is a property here and not a single case because it is the rule
//! this project has had to repair twice: CBOR admits several byte forms for one
//! value, and a log's exact bytes are hashed into a transparency log, so a
//! second encoding is a second identity.

use hide_epoch::EpochChain;
use hide_identity::{
    EPOCH_BINDING_LENGTH, Entry, EpochBinding, Event, IdentityLog, RECOVERY_BINDING_LENGTH,
    RecoveryBinding, decode, device_id, encode,
};
use hide_sign::{SIGNATURE_LENGTH, SigningIdentity, VERIFYING_KEY_LENGTH, VerifyingIdentity};
use proptest::prelude::*;
use std::sync::LazyLock;

fn seed(byte: u8) -> SigningIdentity {
    SigningIdentity::from_bytes(&[byte; 32]).expect("32 bytes is a seed")
}

/// The recovery key `LOG` names, and the two devices that sign for it. ML-DSA
/// key derivation is the expensive part of this suite, so each happens once per
/// test binary and every case reuses the result.
static RECOVERY: LazyLock<VerifyingIdentity> = LazyLock::new(|| seed(0x63).verifying_key());
static FOUNDER: LazyLock<SigningIdentity> = LazyLock::new(|| seed(0x61));
static LAPTOP: LazyLock<SigningIdentity> = LazyLock::new(|| seed(0x62));

/// A real, fully signed log: two devices and one revocation. This is the shape
/// that actually reaches a peer, so the damage properties run against these
/// bytes rather than a synthetic stand-in.
static LOG: LazyLock<IdentityLog> = LazyLock::new(|| {
    let mut log =
        IdentityLog::create(&FOUNDER, "founder", &RECOVERY).expect("the founder creates the log");
    log.enrol(&FOUNDER, &LAPTOP.verifying_key(), "laptop")
        .expect("the founder enrols a second device");
    // A device may revoke itself, and one device remains, so this is allowed.
    log.revoke(&FOUNDER, device_id(&FOUNDER.verifying_key()))
        .expect("revoking itself leaves the laptop");
    log
});

/// A real epoch chain, so the binding that commits to one can be built and
/// checked for real (§16.4).
static CHAIN: LazyLock<EpochChain> = LazyLock::new(|| {
    let mut chain = EpochChain::new().expect("a chain starts at epoch zero");
    chain.advance().expect("advancing mints an epoch");
    chain
});

/// A device key as a `Create`/`Enrol`/`Recover` payload carries it. Decoding
/// accepts any length there — only `Revoke` needs exactly 32 bytes — so the
/// properties must hold for arbitrary material, with the real 1984-byte length
/// generated deliberately rather than hoped for.
fn device() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => prop::collection::vec(any::<u8>(), 0..64),
        1 => prop::collection::vec(any::<u8>(), VERIFYING_KEY_LENGTH),
    ]
}

/// ASCII of a controlled byte length, so the label limit is exercised exactly.
fn ascii(range: std::ops::Range<usize>) -> impl Strategy<Value = String> {
    prop::collection::vec(0x20u8..0x7f, range)
        .prop_map(|bytes| String::from_utf8(bytes).expect("ASCII is UTF-8"))
}

/// Labels on both sides of the 256-byte limit: below it must round-trip, above
/// it must be refused rather than truncated. Multi-byte characters are included
/// so the limit is not mistaken for a character count.
fn label() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => ascii(0..40),
        1 => ascii(250..300),
        1 => prop::collection::vec(any::<char>(), 0..12)
            .prop_map(|chars| chars.into_iter().collect::<String>()),
    ]
}

fn event() -> impl Strategy<Value = Event> {
    prop_oneof![
        (device(), label()).prop_map(|(device, label)| Event::Create { device, label }),
        (device(), label()).prop_map(|(device, label)| Event::Enrol { device, label }),
        any::<[u8; 32]>().prop_map(|device| Event::Revoke { device }),
        (device(), label()).prop_map(|(device, label)| Event::Recover { device, label }),
    ]
}

/// One entry with every field attacker-chosen. This encoder writes whatever it
/// is handed, so a history built from these is exactly what a hostile peer sends.
fn entry() -> impl Strategy<Value = Entry> {
    (
        any::<u64>(),
        event(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        prop::collection::vec(any::<u8>(), SIGNATURE_LENGTH),
    )
        .prop_map(|(sequence, event, signer, link, signature)| Entry {
            sequence,
            event,
            signer,
            link,
            signature,
        })
}

/// Byte strings that cluster on the two accepted binding lengths: a uniform
/// length would reach the accept path about once in five thousand cases.
fn binding_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        8 => Just(RECOVERY_BINDING_LENGTH),
        8 => Just(EPOCH_BINDING_LENGTH),
        1 => 0usize..(RECOVERY_BINDING_LENGTH + 8),
    ]
    .prop_flat_map(|length| prop::collection::vec(any::<u8>(), length))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A log arrives from a peer or a directory this process does not control.
    /// Whatever the bytes, decoding, replaying and parsing the bindings must
    /// return Ok or Err and never panic.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(entries) = decode(&bytes) {
            let _ = IdentityLog::verify(&entries, &RECOVERY);
            let _ = IdentityLog::from_entries(entries, RECOVERY.clone());
        }
        let _ = RecoveryBinding::decode(&bytes);
        let _ = EpochBinding::decode(&bytes);
    }

    /// One history, one encoding: whatever has to be written is exactly what
    /// comes back. Not every hand-built entry is a legal log — an over-long
    /// label is refused, because this encoder serialises and does not validate —
    /// but every log that decodes must re-encode to the bytes it arrived as.
    #[test]
    fn encoded_logs_decode_to_the_same_bytes(entries in prop::collection::vec(entry(), 0..4)) {
        let encoded = encode(&entries)?;
        if let Ok(decoded) = decode(&encoded) {
            prop_assert_eq!(encode(&decoded)?, encoded);
        }
    }

    /// The same statement for bytes nobody wrote with this encoder. A legacy
    /// (0.6–0.8) framing is read and re-encodes in its own framing, so the
    /// exact-bytes form is per framing; what must hold for any input is that
    /// decoding does not drift — the value it yields has one canonical encoding,
    /// and decoding that encoding gives the value back.
    #[test]
    fn decoding_never_drifts(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(entries) = decode(&bytes) {
            let canonical = encode(&entries)?;
            prop_assert_eq!(decode(&canonical)?, entries);
        }
    }

    /// Every strict prefix of a valid encoding, and a valid encoding with bytes
    /// appended, must be refused. Truncation is how an interrupted transfer
    /// presents itself; trailing bytes are how a payload smuggled past the last
    /// entry presents itself.
    #[test]
    fn truncation_and_trailing_bytes_are_refused(
        entries in prop::collection::vec(entry(), 0..4),
        index in any::<prop::sample::Index>(),
        suffix in prop::collection::vec(any::<u8>(), 1..8),
    ) {
        let encoded = encode(&entries)?;
        let cut = index.index(encoded.len());
        prop_assert!(decode(&encoded[..cut]).is_err(), "accepted a {cut} byte prefix");
        let mut extended = encoded.clone();
        extended.extend_from_slice(&suffix);
        prop_assert!(decode(&extended).is_err());
    }

    /// The non-canonical CBOR length prefix is the bug class this project has hit
    /// twice: an array written with a four-byte length instead of one byte
    /// decodes cleanly and re-encodes to something else. No count may be written
    /// non-minimally; here the body is absent as well, so either reason must
    /// refuse it.
    #[test]
    fn non_minimal_array_headers_are_refused(count in 0u32..8) {
        let mut bytes = vec![0x9a];
        bytes.extend_from_slice(&count.to_be_bytes());
        prop_assert!(decode(&bytes).is_err());
    }

    /// A signature is a fixed length (§10). A log whose signature is any other
    /// length is refused when it is decoded, not at first verification.
    #[test]
    fn a_signature_of_the_wrong_length_is_refused(
        length in prop_oneof![0usize..SIGNATURE_LENGTH, (SIGNATURE_LENGTH + 1)..=(SIGNATURE_LENGTH + 8)],
    ) {
        let entry = Entry {
            sequence: 0,
            event: Event::Revoke { device: [0u8; 32] },
            signer: [0u8; 32],
            link: [0u8; 32],
            signature: vec![0u8; length],
        };
        prop_assert!(decode(&encode(&[entry])?).is_err());
    }

    /// Both bindings are fixed-length, so an accepted input is exactly the bytes
    /// the encoder writes: there is no room for a second encoding to exist.
    #[test]
    fn binding_decoders_are_canonical(bytes in binding_bytes()) {
        if let Ok(binding) = RecoveryBinding::decode(&bytes) {
            prop_assert_eq!(binding.encode(), bytes.clone());
        }
        if let Ok(binding) = EpochBinding::decode(&bytes) {
            prop_assert_eq!(binding.encode(), bytes);
        }
    }

    /// The real thing, end to end: a signed log, the binding that names its
    /// recovery key (§16.1) and the binding a trusted device signs over the
    /// epoch chain (§16.4). Each round-trips and verifies, and a single damaged
    /// byte leaves something that either fails to decode or fails to verify —
    /// never a different history that passes for the original.
    #[test]
    fn real_log_and_bindings_survive_damage(
        index in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let encoded = encode(LOG.entries())?;
        let decoded = decode(&encoded)?;
        prop_assert_eq!(encode(&decoded)?, encoded.clone());
        prop_assert!(IdentityLog::verify(&decoded, &RECOVERY).is_ok());

        let binding = RecoveryBinding::create(&LOG, &FOUNDER)?;
        let binding_bytes = binding.encode();
        prop_assert_eq!(RecoveryBinding::decode(&binding_bytes)?.encode(), binding_bytes.clone());
        prop_assert!(binding.verify(decoded.clone()).is_ok());

        let chain = EpochBinding::create(&LOG, &LAPTOP, CHAIN.records())?;
        let chain_bytes = chain.encode();
        prop_assert_eq!(EpochBinding::decode(&chain_bytes)?.encode(), chain_bytes.clone());
        prop_assert!(chain.verify(&LOG, CHAIN.records()).is_ok());
        // A chain edited anywhere is a different chain, and the hash linkage is
        // what says so: this must fail without needing a signature check.
        let mut edited = CHAIN.records().to_vec();
        let at = index.index(edited.len());
        edited[at].link[0] ^= 0xff;
        prop_assert!(chain.verify(&LOG, &edited).is_err(), "an edited chain was accepted");
        prop_assert!(chain.verify(&LOG, &[]).is_err());

        // Damage the log...
        let mut damaged = encoded.clone();
        let position = index.index(damaged.len());
        damaged[position] = damaged[position].wrapping_add(delta);
        if let Ok(entries) = decode(&damaged) {
            prop_assert!(
                IdentityLog::verify(&entries, &RECOVERY).is_err(),
                "a log damaged at byte {position} still verified"
            );
        }

        // ...the recovery binding...
        let mut damaged = binding_bytes.clone();
        let position = index.index(damaged.len());
        damaged[position] = damaged[position].wrapping_add(delta);
        if let Ok(damaged) = RecoveryBinding::decode(&damaged) {
            prop_assert!(
                damaged.verify(LOG.entries().to_vec()).is_err(),
                "a recovery binding damaged at byte {position} still verified"
            );
        }

        // ...and the epoch binding.
        let mut damaged = chain_bytes.clone();
        let position = index.index(damaged.len());
        damaged[position] = damaged[position].wrapping_add(delta);
        if let Ok(damaged) = EpochBinding::decode(&damaged) {
            prop_assert!(
                damaged.verify(&LOG, CHAIN.records()).is_err(),
                "an epoch binding damaged at byte {position} still verified"
            );
        }
    }
}
