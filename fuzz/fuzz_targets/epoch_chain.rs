#![no_main]
//! An epoch history is public and is fetched from wherever the identity lives.
//! Decoding must never panic and must be canonical; verification must refuse a
//! broken link rather than crash on it.

use hide_epoch::{EpochChain, decode_records, encode_records};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(records) = decode_records(data) {
        assert_eq!(encode_records(&records).unwrap(), data, "non-canonical chain accepted");
        let _ = EpochChain::verify(&records);
    }
});
