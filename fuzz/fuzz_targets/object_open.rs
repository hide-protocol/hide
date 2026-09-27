#![no_main]
//! Decrypting an attacker-controlled container with a fixed secret. The
//! property is: never panic. Staging may hold verified chunks of a container
//! that later fails; the API contract is that the CALLER publishes nothing
//! until `Ok`, which is what the CLI's stage-and-rename enforces.
//!
//! The secret is the frozen vector key, not an arbitrary one: the corpus is
//! seeded with the vectors, and with a key that matches no recipient every
//! input stops at recipient matching, so stanza unwrapping, the header MAC,
//! extensions, signatures and chunk decryption would never be reached.

use hide_crypto::RecipientSecret;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static SECRET: LazyLock<RecipientSecret> = LazyLock::new(|| {
    RecipientSecret::from_bytes(include_bytes!(
        "../../conformance/vectors/recipient.test-secret"
    ))
    .expect("the frozen vector key is 32 bytes")
});

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    if let Ok(verified) = hide_object::decrypt_to_staging(&mut &*data, &mut out, &SECRET) {
        assert_eq!(out.len() as u64, verified.plaintext_len);
    }
});
