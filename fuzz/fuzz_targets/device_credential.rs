#![no_main]
//! The device binding an MLS credential carries. A credential travels with a
//! message from a delivery service that is not trusted, so every field in it is
//! attacker-chosen: the length, the device id, the hybrid verifying key, and the
//! agreement between the id and the key.
//!
//! The parser only inspects a fixed-size layout, so a random-length input would
//! almost always be refused by the length check and never reach a field. The
//! input is cycled into that exact layout on purpose, which is what makes the
//! corpus worth accumulating.

use hide_mls::validate_device_credential;
use hide_sign::{SIGNATURE_LENGTH, VERIFYING_KEY_LENGTH};
use libfuzzer_sys::fuzz_target;

/// `device_id(32) || hide_verifying_key || signature`, the layout §11 defines.
const CREDENTIAL_LEN: usize = 32 + VERIFYING_KEY_LENGTH + SIGNATURE_LENGTH;

fuzz_target!(|data: &[u8]| {
    let mut credential = vec![0_u8; CREDENTIAL_LEN];
    for (slot, byte) in credential.iter_mut().zip(data.iter().cycle()) {
        *slot = *byte;
    }
    let _ = validate_device_credential(&credential);

    // The length check itself: a truncated or overlong credential must be
    // refused rather than indexed.
    let _ = validate_device_credential(data);
});
