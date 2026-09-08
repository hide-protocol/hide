#![no_main]
//! Decrypting an attacker-controlled container with a fixed secret. The
//! property is: never panic. Staging may hold verified chunks of a container
//! that later fails; the API contract is that the CALLER publishes nothing
//! until `Ok`, which is what the CLI's stage-and-rename enforces. A fixed seed
//! keeps the corpus reproducible.

use hide_crypto::RecipientSecret;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static SECRET: LazyLock<RecipientSecret> =
    LazyLock::new(|| RecipientSecret::from_bytes(&[7u8; 32]).expect("32 bytes is a seed"));

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::new();
    if let Ok(verified) = hide_object::decrypt_to_staging(&mut &*data, &mut out, &SECRET) {
        assert_eq!(out.len() as u64, verified.plaintext_len);
    }
});
