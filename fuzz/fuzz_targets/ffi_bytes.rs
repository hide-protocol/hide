#![no_main]
//! The C ABI's byte-taking entry points, driven with attacker-shaped bytes.
//!
//! Every SDK reaches the core through these, so they are the widest attack
//! surface in the project: a bug here is reachable from eight languages at
//! once. The bodies are thin guards around the Rust decoders (which have their
//! own targets), so what this target adds is the boundary itself — the pointer
//! and length arithmetic, the fixed-width checks, and the out-parameter
//! handling, each of which is only exercised through the ABI.
//!
//! Anything that returns a buffer or a handle is released on success only: a
//! failed call did not write the out-parameter, and freeing memory the library
//! never allocated would be undefined behaviour in the target rather than a
//! finding in the code.

use std::ffi::CString;
use std::ptr;

use hide_sign::{SIGNATURE_LENGTH, VERIFYING_KEY_LENGTH};
use libfuzzer_sys::fuzz_target;

/// Pads `data` to exactly `len` bytes by cycling it. Fixed-width entry points
/// refuse anything else, so without this the corpus would only ever test the
/// length checks.
fn padded(data: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    for (slot, byte) in out.iter_mut().zip(data.iter().cycle()) {
        *slot = *byte;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let (head, tail) = data.split_at(data.len() / 2);
    let key = padded(data, VERIFYING_KEY_LENGTH);
    let signature = padded(tail, SIGNATURE_LENGTH);
    let root = padded(data, 32);

    // Key sniffing: any bytes at all, and it must not allocate.
    let mut kind = 0_i32;
    let _ = unsafe { hide_ffi::hide_inspect_key(data.as_ptr(), data.len(), &mut kind) };

    // Armor text arrives as a C string, so an interior NUL never reaches it.
    if !data.contains(&0) {
        if let Ok(text) = CString::new(data.to_vec()) {
            let mut armored = hide_ffi::hide_buffer_empty();
            if unsafe { hide_ffi::hide_public_key_dearmor(text.as_ptr(), &mut armored) }
                == hide_ffi::HIDE_OK
            {
                unsafe { hide_ffi::hide_buffer_free(&mut armored) };
            }
        }
    }

    // A protected key file: the header decides the Argon2 cost, so this is the
    // path where a bound is the only thing between 95 bytes and gigabytes.
    let mut secret = ptr::null_mut();
    if unsafe {
        hide_ffi::hide_secret_key_open(data.as_ptr(), data.len(), ptr::null(), &mut secret)
    } == hide_ffi::HIDE_OK
    {
        unsafe { hide_ffi::hide_secret_key_free(secret) };
    }

    // Signature verification, with both widths forced so the hybrid parse runs.
    let _ = unsafe {
        hide_ffi::hide_verify_message(
            key.as_ptr(),
            key.len(),
            head.as_ptr(),
            head.len(),
            tail.as_ptr(),
            tail.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };

    // An identity log with its recovery key.
    let mut devices = 0_usize;
    let _ = unsafe {
        hide_ffi::hide_identity_verify(
            data.as_ptr(),
            data.len(),
            key.as_ptr(),
            key.len(),
            &mut devices,
        )
    };
    let mut trusted = 0_i32;
    let _ = unsafe {
        hide_ffi::hide_identity_trusts_device(
            data.as_ptr(),
            data.len(),
            key.as_ptr(),
            key.len(),
            key.as_ptr(),
            key.len(),
            &mut trusted,
        )
    };
    let mut pinned_devices = 0_usize;
    let _ = unsafe {
        hide_ffi::hide_identity_verify_pinned(
            data.as_ptr(),
            data.len(),
            tail.as_ptr(),
            tail.len(),
            root.as_ptr(),
            root.len(),
            &mut pinned_devices,
        )
    };

    // An epoch chain bound to a pinned identity.
    let mut epochs = 0_usize;
    let _ = unsafe {
        hide_ffi::hide_epoch_verify_bound(
            data.as_ptr(),
            data.len(),
            tail.as_ptr(),
            tail.len(),
            root.as_ptr(),
            root.len(),
            head.as_ptr(),
            head.len(),
            tail.as_ptr(),
            tail.len(),
            &mut epochs,
        )
    };

    // The RFC 6962 proofs, whose widths the ABI checks before parsing.
    let paths = padded(tail, tail.len().min(64 * 32));
    let _ = unsafe {
        hide_ffi::hide_transparency_verify_inclusion(
            root.as_ptr(),
            root.len(),
            data.len() as u64,
            tail.len() as u64,
            paths.as_ptr(),
            paths.len(),
            root.as_ptr(),
            root.len(),
        )
    };
    let _ = unsafe {
        hide_ffi::hide_transparency_verify_consistency(
            head.len() as u64,
            tail.len() as u64,
            paths.as_ptr(),
            paths.len(),
            root.as_ptr(),
            root.len(),
            root.as_ptr(),
            root.len(),
        )
    };

    // A signed checkpoint note from a log named by `origin`.
    let mut size = 0_u64;
    let mut note_root = hide_ffi::hide_buffer_empty();
    // `origin` is a C string; the note is not, so only the former needs a NUL.
    if let Ok(origin) = CString::new("fuzz.invalid") {
        if unsafe {
            hide_ffi::hide_checkpoint_verify(
                data.as_ptr(),
                data.len(),
                origin.as_ptr(),
                key.as_ptr(),
                key.len(),
                &mut size,
                &mut note_root,
            )
        } == hide_ffi::HIDE_OK
        {
            unsafe { hide_ffi::hide_buffer_free(&mut note_root) };
        }
    }
});
