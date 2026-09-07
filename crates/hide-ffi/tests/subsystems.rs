//! The identity, epoch and transparency entry points, called the way a binding
//! calls them: raw pointers, lengths, and an integer return.
//!
//! Every SDK reaches these functions, so a mistake here is a mistake in eight
//! languages at once.

use hide_epoch::EpochChain;
use hide_identity::{IdentityLog, device_id};
use hide_sign::SigningIdentity;
use hide_transparency::{TransparencyLog, leaf_hash};

const HIDE_OK: i32 = 0;
const HIDE_ERR_INVALID_ARGUMENT: i32 = 1;
const HIDE_ERR_AUTHENTICATION: i32 = 4;
const HIDE_ERR_MALFORMED: i32 = 6;

unsafe extern "C" {
    fn hide_identity_verify(
        log: *const u8,
        log_len: usize,
        recovery: *const u8,
        recovery_len: usize,
        out_devices: *mut usize,
    ) -> i32;
    fn hide_identity_trusts_device(
        log: *const u8,
        log_len: usize,
        recovery: *const u8,
        recovery_len: usize,
        device_public: *const u8,
        device_public_len: usize,
        out_trusted: *mut i32,
    ) -> i32;
    fn hide_epoch_verify(chain: *const u8, chain_len: usize, out_epochs: *mut usize) -> i32;
    fn hide_epoch_public_key(
        chain: *const u8,
        chain_len: usize,
        epoch: u64,
        out: *mut hide_ffi::HideBuffer,
    ) -> i32;
    fn hide_transparency_verify_inclusion(
        leaf: *const u8,
        leaf_len: usize,
        index: u64,
        size: u64,
        path: *const u8,
        path_len: usize,
        root: *const u8,
        root_len: usize,
    ) -> i32;
    fn hide_transparency_verify_consistency(
        old_size: u64,
        new_size: u64,
        path: *const u8,
        path_len: usize,
        old_root: *const u8,
        old_root_len: usize,
        new_root: *const u8,
        new_root_len: usize,
    ) -> i32;
    fn hide_buffer_free(buffer: *mut hide_ffi::HideBuffer);
}

fn identity() -> (Vec<u8>, Vec<u8>, SigningIdentity, SigningIdentity) {
    let laptop = SigningIdentity::generate().unwrap();
    let phone = SigningIdentity::generate().unwrap();
    let recovery = SigningIdentity::generate().unwrap();
    let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    log.enrol(&laptop, &phone.verifying_key(), "phone").unwrap();
    (
        hide_identity::encode(log.entries()).unwrap(),
        recovery.verifying_key().to_bytes().to_vec(),
        laptop,
        phone,
    )
}

fn flatten(path: &[[u8; 32]]) -> Vec<u8> {
    path.iter().flat_map(|hash| hash.iter().copied()).collect()
}

#[test]
fn an_identity_log_verifies_over_the_abi() {
    let (log, recovery, _, _) = identity();
    let mut devices = 0usize;
    let code = unsafe {
        hide_identity_verify(
            log.as_ptr(),
            log.len(),
            recovery.as_ptr(),
            recovery.len(),
            &mut devices,
        )
    };
    assert_eq!(code, HIDE_OK);
    assert_eq!(devices, 2);
}

/// A caller must be able to tell corruption from forgery, because the two mean
/// different things: retry versus do not trust this peer.
#[test]
fn a_corrupt_log_and_an_invalid_log_report_differently() {
    let (log, recovery, _, _) = identity();

    let garbage = [0xFFu8; 32];
    let mut devices = 0usize;
    let code = unsafe {
        hide_identity_verify(
            garbage.as_ptr(),
            garbage.len(),
            recovery.as_ptr(),
            recovery.len(),
            &mut devices,
        )
    };
    assert_eq!(code, HIDE_ERR_MALFORMED);

    // Decodes, but a signature no longer matches.
    let mut tampered = log.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    let code = unsafe {
        hide_identity_verify(
            tampered.as_ptr(),
            tampered.len(),
            recovery.as_ptr(),
            recovery.len(),
            &mut devices,
        )
    };
    assert!(
        code == HIDE_ERR_AUTHENTICATION || code == HIDE_ERR_MALFORMED,
        "unexpected code {code}"
    );
}

#[test]
fn a_null_out_pointer_is_refused() {
    let (log, recovery, _, _) = identity();
    let code = unsafe {
        hide_identity_verify(
            log.as_ptr(),
            log.len(),
            recovery.as_ptr(),
            recovery.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(code, HIDE_ERR_INVALID_ARGUMENT);
}

#[test]
fn device_trust_is_reported_over_the_abi() {
    let (log, recovery, laptop, phone) = identity();

    for (device, expected) in [(&laptop, 1), (&phone, 1)] {
        let key = device.verifying_key().to_bytes();
        let mut trusted = -1i32;
        let code = unsafe {
            hide_identity_trusts_device(
                log.as_ptr(),
                log.len(),
                recovery.as_ptr(),
                recovery.len(),
                key.as_ptr(),
                key.len(),
                &mut trusted,
            )
        };
        assert_eq!(code, HIDE_OK);
        assert_eq!(trusted, expected);
    }

    let stranger = SigningIdentity::generate()
        .unwrap()
        .verifying_key()
        .to_bytes();
    let mut trusted = -1i32;
    let code = unsafe {
        hide_identity_trusts_device(
            log.as_ptr(),
            log.len(),
            recovery.as_ptr(),
            recovery.len(),
            stranger.as_ptr(),
            stranger.len(),
            &mut trusted,
        )
    };
    assert_eq!(code, HIDE_OK);
    assert_eq!(trusted, 0);
}

/// The property a binding most needs to expose: revocation is visible.
#[test]
fn a_revoked_device_is_reported_as_untrusted() {
    let laptop = SigningIdentity::generate().unwrap();
    let phone = SigningIdentity::generate().unwrap();
    let recovery = SigningIdentity::generate().unwrap();
    let mut log = IdentityLog::create(&laptop, "laptop", &recovery.verifying_key()).unwrap();
    log.enrol(&laptop, &phone.verifying_key(), "phone").unwrap();
    log.revoke(&laptop, device_id(&phone.verifying_key()))
        .unwrap();

    let encoded = hide_identity::encode(log.entries()).unwrap();
    let recovery_bytes = recovery.verifying_key().to_bytes();
    let key = phone.verifying_key().to_bytes();

    let mut trusted = -1i32;
    let code = unsafe {
        hide_identity_trusts_device(
            encoded.as_ptr(),
            encoded.len(),
            recovery_bytes.as_ptr(),
            recovery_bytes.len(),
            key.as_ptr(),
            key.len(),
            &mut trusted,
        )
    };
    assert_eq!(code, HIDE_OK);
    assert_eq!(trusted, 0, "a revoked device was reported as trusted");
}

#[test]
fn an_epoch_chain_verifies_over_the_abi() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    let encoded = hide_epoch::encode_records(chain.records()).unwrap();

    let mut epochs = 0usize;
    let code = unsafe { hide_epoch_verify(encoded.as_ptr(), encoded.len(), &mut epochs) };
    assert_eq!(code, HIDE_OK);
    assert_eq!(epochs, 2);
}

#[test]
fn an_epoch_public_key_is_returned_and_matches() {
    let chain = EpochChain::new().unwrap();
    let encoded = hide_epoch::encode_records(chain.records()).unwrap();

    let mut buffer = hide_ffi::hide_buffer_empty();
    let code = unsafe { hide_epoch_public_key(encoded.as_ptr(), encoded.len(), 0, &mut buffer) };
    assert_eq!(code, HIDE_OK);

    let returned = unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) };
    assert_eq!(returned, chain.public_key(0).unwrap());
    unsafe { hide_buffer_free(&mut buffer) };
}

#[test]
fn an_epoch_beyond_the_chain_is_refused() {
    let chain = EpochChain::new().unwrap();
    let encoded = hide_epoch::encode_records(chain.records()).unwrap();
    let mut buffer = hide_ffi::hide_buffer_empty();
    let code = unsafe { hide_epoch_public_key(encoded.as_ptr(), encoded.len(), 99, &mut buffer) };
    assert_eq!(code, HIDE_ERR_INVALID_ARGUMENT);
}

#[test]
fn a_tampered_chain_is_refused() {
    let chain = EpochChain::new().unwrap();
    let mut encoded = hide_epoch::encode_records(chain.records()).unwrap();
    let middle = encoded.len() / 2;
    encoded[middle] ^= 1;

    let mut epochs = 0usize;
    let code = unsafe { hide_epoch_verify(encoded.as_ptr(), encoded.len(), &mut epochs) };
    assert!(code != HIDE_OK, "a tampered chain verified");
}

#[test]
fn an_inclusion_proof_verifies_over_the_abi() {
    let mut log = TransparencyLog::new();
    for i in 0..9u64 {
        log.append(format!("entry {i}").as_bytes());
    }
    let root = log.root();
    let proof = log.prove_inclusion(3, 9).unwrap();
    let path = flatten(&proof.path);
    let leaf = leaf_hash(b"entry 3");

    let code = unsafe {
        hide_transparency_verify_inclusion(
            leaf.as_ptr(),
            leaf.len(),
            proof.index,
            proof.size,
            path.as_ptr(),
            path.len(),
            root.as_ptr(),
            root.len(),
        )
    };
    assert_eq!(code, HIDE_OK);

    // The wrong leaf must not verify.
    let other = leaf_hash(b"entry 4");
    let code = unsafe {
        hide_transparency_verify_inclusion(
            other.as_ptr(),
            other.len(),
            proof.index,
            proof.size,
            path.as_ptr(),
            path.len(),
            root.as_ptr(),
            root.len(),
        )
    };
    assert_eq!(code, HIDE_ERR_AUTHENTICATION);
}

#[test]
fn a_path_that_is_not_a_multiple_of_32_is_refused() {
    let leaf = [0u8; 32];
    let root = [0u8; 32];
    let path = [0u8; 33];
    let code = unsafe {
        hide_transparency_verify_inclusion(
            leaf.as_ptr(),
            leaf.len(),
            0,
            1,
            path.as_ptr(),
            path.len(),
            root.as_ptr(),
            root.len(),
        )
    };
    assert_eq!(code, HIDE_ERR_INVALID_ARGUMENT);
}

#[test]
fn a_consistency_proof_verifies_over_the_abi() {
    let mut log = TransparencyLog::new();
    for i in 0..13u64 {
        log.append(format!("entry {i}").as_bytes());
    }
    let old_root = log.root_at(6).unwrap();
    let new_root = log.root();
    let proof = log.prove_consistency(6, 13).unwrap();
    let path = flatten(&proof.path);

    let code = unsafe {
        hide_transparency_verify_consistency(
            proof.old_size,
            proof.new_size,
            path.as_ptr(),
            path.len(),
            old_root.as_ptr(),
            old_root.len(),
            new_root.as_ptr(),
            new_root.len(),
        )
    };
    assert_eq!(code, HIDE_OK);

    // A rewritten history must not.
    let mut forged = TransparencyLog::new();
    for i in 0..13u64 {
        if i == 2 {
            forged.append(b"substituted");
        } else {
            forged.append(format!("entry {i}").as_bytes());
        }
    }
    let forged_root = forged.root();
    let forged_proof = forged.prove_consistency(6, 13).unwrap();
    let forged_path = flatten(&forged_proof.path);

    let code = unsafe {
        hide_transparency_verify_consistency(
            6,
            13,
            forged_path.as_ptr(),
            forged_path.len(),
            old_root.as_ptr(),
            old_root.len(),
            forged_root.as_ptr(),
            forged_root.len(),
        )
    };
    assert_eq!(
        code, HIDE_ERR_AUTHENTICATION,
        "a rewritten log proved consistent"
    );
}
