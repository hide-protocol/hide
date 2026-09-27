#![no_main]
//! An epoch store is read back from disk, where anything may have replaced it.
//! Parsing must never panic, must refuse hostile Argon2 parameters and entry
//! counts before allocating, and must accept only the writer's exact bytes.
//! `open` is exercised too: under `cfg(fuzzing)` Argon2 runs at its floor, so
//! the authentication paths are reached at a useful rate.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(again) = hide_keyring::epoch_store::reencode_unauthenticated(data) {
        assert_eq!(again, data, "non-canonical epoch store accepted");
        let _ = hide_keyring::EpochStore::open(data, "fuzz passphrase");
    }
});
