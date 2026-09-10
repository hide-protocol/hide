#![no_main]
//! Group messages arrive from a delivery service that is not trusted and from
//! members who may be hostile. The size bound must be checked before any
//! parsing work, and the TLS-syntax decoder underneath must never panic on a
//! crafted message.

use hide_mls::decode_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_message(data);
});
