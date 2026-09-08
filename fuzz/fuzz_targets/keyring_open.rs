#![no_main]
//! Key files come from disk and from other people. Argon2 parameters are the
//! interesting field: a hostile file must be refused BEFORE the memory it asks
//! for is allocated, and no parameter combination may panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hide_keyring::open(data, None);
    let _ = hide_keyring::open(data, Some("fuzz"));
    let _ = hide_keyring::unprotect(data, "fuzz");
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(bytes) = hide_keyring::decode_public(text) {
            let again = hide_keyring::encode_public(&bytes);
            assert_eq!(hide_keyring::decode_public(&again).unwrap(), bytes);
        }
    }
});
