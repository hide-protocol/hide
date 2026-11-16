#![no_main]
//! The armored public key is text: it is pasted from a chat message, a web page
//! or a key server, so the decoder is fed whatever a stranger sent. Two things
//! must hold for every input the decoder accepts: it must not panic, and the
//! armor round trip must lose nothing — `decode(encode(k))` is `k`, or a key
//! that survives a paste could become a different key.

use hide_keyring::{decode_public, encode_public};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The decoder takes `&str`; only a valid UTF-8 tail reaches the base64.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(key) = decode_public(text) else {
        return;
    };
    let armored = encode_public(&key);
    assert_eq!(
        decode_public(&armored).ok().as_deref(),
        Some(key.as_slice()),
        "the armor round trip changed the key it decodes"
    );
});
