//! The frozen identity vectors in `conformance/vectors/subsystems/`, which every
//! SDK also reads. The legacy (0.6-0.8) files must keep opening exactly as
//! before; the current ones must be well-formed CBOR to a reader that knows
//! nothing about HIDE.

use hide_identity::{IdentityError, IdentityLog, decode, device_id, encode};
use hide_sign::VerifyingIdentity;
use std::error::Error;
use std::path::PathBuf;

fn vector(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/subsystems")
        .join(name);
    Ok(std::fs::read(path)?)
}

fn key(name: &str) -> Result<VerifyingIdentity, Box<dyn Error>> {
    Ok(VerifyingIdentity::from_bytes(&vector(name)?)?)
}

/// Whether a generic CBOR reader, skipping the top-level item, lands exactly
/// on the end of the input. It does only if every array header counts its
/// items honestly.
fn a_generic_reader_consumes_it_exactly(bytes: &[u8]) -> bool {
    let mut decoder = minicbor::Decoder::new(bytes);
    decoder.skip().is_ok() && decoder.position() == bytes.len()
}

fn assert_expected_membership(bytes: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    let recovery = key("identity-recovery.bin")?;
    let phone = device_id(&key("identity-device-phone.bin")?);
    let laptop = device_id(&key("identity-device-laptop.bin")?);

    let log = IdentityLog::from_entries(decode(bytes)?, recovery)?;
    let membership = log.membership();
    // create desktop, enrol phone, enrol laptop, revoke laptop
    assert_eq!(log.entries().len(), 4);
    assert_eq!(membership.len(), 2);
    assert!(membership.contains(&phone));
    assert!(!membership.contains(&laptop));
    assert_eq!(membership.revoked_at(&laptop), Some(3));
    Ok(log.head())
}

#[test]
fn the_current_log_is_array_of_seven_framed() -> Result<(), Box<dyn Error>> {
    let bytes = vector("identity-log.bin")?;
    // array(4), array(7), sequence 0, tag 1 (create), bytes(1984)
    assert_eq!(
        &bytes[..8],
        &[0x84, 0x87, 0x00, 0x01, 0x59, 0x07, 0xc0, 0x60]
    );
    assert!(a_generic_reader_consumes_it_exactly(&bytes));
    Ok(())
}

#[test]
fn the_current_log_verifies_to_the_published_head() -> Result<(), Box<dyn Error>> {
    let head = assert_expected_membership(&vector("identity-log.bin")?)?;
    assert_eq!(head.as_slice(), vector("identity-head.bin")?.as_slice());
    Ok(())
}

/// The 0.6-0.8 framing is still read, verifies exactly as before, and names
/// the same history: the framing was never signed or linked.
#[test]
fn the_legacy_log_still_opens_with_the_same_head() -> Result<(), Box<dyn Error>> {
    let legacy = vector("identity-log-legacy.bin")?;
    assert_eq!(&legacy[..6], &[0x84, 0x86, 0x00, 0x01, 0x59, 0x07]);
    // The bug this file preserves: a generic reader cannot parse it.
    assert!(!a_generic_reader_consumes_it_exactly(&legacy));

    let head = assert_expected_membership(&legacy)?;
    assert_eq!(head.as_slice(), vector("identity-head.bin")?.as_slice());
    // Same entries as the current vector, and writing them upgrades the framing.
    let entries = decode(&legacy)?;
    assert_eq!(entries, decode(&vector("identity-log.bin")?)?);
    assert_eq!(encode(&entries)?, vector("identity-log.bin")?);
    Ok(())
}

#[test]
fn both_tampered_logs_decode_and_are_refused() -> Result<(), Box<dyn Error>> {
    let recovery = key("identity-recovery.bin")?;
    for name in ["identity-tampered.bin", "identity-tampered-legacy.bin"] {
        let entries = decode(&vector(name)?)?;
        assert!(
            matches!(
                IdentityLog::verify(&entries, &recovery),
                Err(IdentityError::BrokenLink(3))
            ),
            "{name} verified"
        );
    }
    Ok(())
}

/// One entry re-framed inside an otherwise legacy vector: a second encoding of
/// the same history, which the canonical check exists to refuse.
#[test]
fn a_vector_with_one_entry_reframed_is_refused() -> Result<(), Box<dyn Error>> {
    let mut mixed = vector("identity-log-legacy.bin")?;
    assert_eq!(mixed[1], 0x86);
    mixed[1] = 0x87;
    assert_eq!(decode(&mixed), Err(IdentityError::Malformed));

    let mut mixed = vector("identity-log.bin")?;
    mixed[1] = 0x86;
    assert_eq!(decode(&mixed), Err(IdentityError::Malformed));
    Ok(())
}
