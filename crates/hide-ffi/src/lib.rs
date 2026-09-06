//! C ABI for HIDE. Every language binding calls this; none reimplements the
//! cryptography, so there is exactly one implementation to review.
//!
//! Rules this boundary keeps:
//!
//! - Nothing crossing the boundary is trusted: every pointer is checked for
//!   null and every length is validated before use.
//! - Secret keys never leave Rust. Callers hold an opaque handle; there is no
//!   function that exports key material.
//! - Buffers allocated here are freed here (`hide_buffer_free`), because a
//!   caller freeing Rust memory with libc `free` is undefined behaviour.
//! - No function unwinds across the boundary. A panic in Rust crossing into C
//!   is undefined behaviour, so every entry point catches it.

use std::{
    ffi::{CStr, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

use hide_crypto::{RecipientPublic, RecipientSecret};
use hide_keyring::KeyFormat;
use hide_object::Metadata;
use zeroize::Zeroizing;

/// Status codes. Zero is success; everything else is a failure the caller must
/// handle. Values are stable across versions: bindings switch on them.
pub const HIDE_OK: i32 = 0;
pub const HIDE_ERR_INVALID_ARGUMENT: i32 = 1;
pub const HIDE_ERR_WRONG_PASSPHRASE: i32 = 2;
pub const HIDE_ERR_NOT_A_KEY: i32 = 3;
pub const HIDE_ERR_AUTHENTICATION: i32 = 4;
pub const HIDE_ERR_NO_MATCHING_RECIPIENT: i32 = 5;
pub const HIDE_ERR_MALFORMED: i32 = 6;
pub const HIDE_ERR_TOO_LARGE: i32 = 7;
pub const HIDE_ERR_PANIC: i32 = 98;
pub const HIDE_ERR_INTERNAL: i32 = 99;

/// Key file kinds reported by [`hide_inspect_key`].
pub const HIDE_KEY_RAW: i32 = 0;
pub const HIDE_KEY_PROTECTED: i32 = 1;

pub const HIDE_PUBLIC_KEY_LEN: usize = 1216;
pub const HIDE_MIN_PASSPHRASE_LEN: usize = hide_keyring::MIN_PASSPHRASE_LEN;

/// Bounds every allocation driven by a caller-supplied length.
const MAX_INPUT: usize = 1 << 30;
const MAX_KEY_FILE: usize = 4096;

/// An owned buffer handed to the caller. Free it with [`hide_buffer_free`].
#[repr(C)]
pub struct HideBuffer {
    pub data: *mut u8,
    pub len: usize,
    /// Kept so the exact original allocation can be reconstructed on free.
    capacity: usize,
}

impl HideBuffer {
    fn from_vec(mut bytes: Vec<u8>) -> Self {
        let buffer = Self {
            data: bytes.as_mut_ptr(),
            len: bytes.len(),
            capacity: bytes.capacity(),
        };
        std::mem::forget(bytes);
        buffer
    }
}

/// An empty buffer, for initialising a local before passing its address in.
/// Callers must start from this rather than from uninitialised memory, because
/// [`hide_buffer_free`] reads the pointer it is given.
#[unsafe(no_mangle)]
pub extern "C" fn hide_buffer_empty() -> HideBuffer {
    HideBuffer {
        data: ptr::null_mut(),
        len: 0,
        capacity: 0,
    }
}

/// An opaque secret key. The caller only ever holds this pointer; there is no
/// accessor that returns the underlying bytes.
pub struct HideSecretKey(RecipientSecret);

/// Reads a caller-provided slice, refusing null and absurd lengths.
///
/// # Safety
/// `data` must be valid for `len` bytes, or null when `len` is zero.
unsafe fn borrow<'a>(data: *const u8, len: usize, limit: usize) -> Option<&'a [u8]> {
    if len > limit {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    if data.is_null() {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(data, len) })
}

/// # Safety
/// `text` must be null or a valid NUL-terminated C string.
unsafe fn borrow_str<'a>(text: *const c_char) -> Option<Option<&'a str>> {
    if text.is_null() {
        return Some(None);
    }
    match unsafe { CStr::from_ptr(text) }.to_str() {
        Ok(value) => Some(Some(value)),
        Err(_) => None,
    }
}

fn object_error_code(error: &hide_object::ObjectError) -> i32 {
    use hide_object::ObjectError;
    match error {
        ObjectError::NoMatchingRecipient => HIDE_ERR_NO_MATCHING_RECIPIENT,
        ObjectError::Crypto(_) => HIDE_ERR_AUTHENTICATION,
        ObjectError::ObjectTooLarge => HIDE_ERR_TOO_LARGE,
        _ => HIDE_ERR_MALFORMED,
    }
}

fn keyring_error_code(error: &hide_keyring::KeyringError) -> i32 {
    use hide_keyring::KeyringError;
    match error {
        KeyringError::WrongPassphrase => HIDE_ERR_WRONG_PASSPHRASE,
        KeyringError::NotAKeyFile | KeyringError::UnsupportedVersion(_) => HIDE_ERR_NOT_A_KEY,
        KeyringError::PassphraseTooShort(_) => HIDE_ERR_INVALID_ARGUMENT,
        _ => HIDE_ERR_MALFORMED,
    }
}

/// Runs `body`, converting a panic into a status code rather than unwinding
/// into C, which would be undefined behaviour.
fn guard(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(HIDE_ERR_PANIC)
}

/// Human-readable text for a status code. The returned string is static and
/// must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn hide_error_message(code: i32) -> *const c_char {
    let text: &[u8] = match code {
        HIDE_OK => b"success\0",
        HIDE_ERR_INVALID_ARGUMENT => b"invalid argument\0",
        HIDE_ERR_WRONG_PASSPHRASE => b"incorrect passphrase, or the key file was modified\0",
        HIDE_ERR_NOT_A_KEY => b"not a HIDE key file\0",
        HIDE_ERR_AUTHENTICATION => b"authentication failed; the data was altered\0",
        HIDE_ERR_NO_MATCHING_RECIPIENT => b"no matching recipient for this key\0",
        HIDE_ERR_MALFORMED => b"malformed or corrupt input\0",
        HIDE_ERR_TOO_LARGE => b"input is too large\0",
        HIDE_ERR_PANIC => b"internal error (panic)\0",
        _ => b"internal error\0",
    };
    text.as_ptr().cast()
}

/// The library version, as a static NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn hide_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Frees a buffer produced by this library.
///
/// # Safety
/// `buffer` must come from this library and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_buffer_free(buffer: *mut HideBuffer) {
    if buffer.is_null() {
        return;
    }
    let buffer = unsafe { &mut *buffer };
    if buffer.data.is_null() {
        return;
    }
    // Reconstruct the exact allocation, then zeroize: a freed buffer may still
    // hold plaintext.
    let mut bytes = unsafe { Vec::from_raw_parts(buffer.data, buffer.len, buffer.capacity) };
    bytes.iter_mut().for_each(|byte| *byte = 0);
    drop(bytes);
    buffer.data = ptr::null_mut();
    buffer.len = 0;
    buffer.capacity = 0;
}

/// Generates a key pair. The secret is returned as an opaque handle; the public
/// key is returned as bytes, which are safe to share.
///
/// # Safety
/// Both out-pointers must be valid and non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_keypair_generate(
    out_secret: *mut *mut HideSecretKey,
    out_public: *mut HideBuffer,
) -> i32 {
    guard(|| {
        if out_secret.is_null() || out_public.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Ok(secret) = RecipientSecret::generate() else {
            return HIDE_ERR_INTERNAL;
        };
        let Ok(public) = secret.public_key() else {
            return HIDE_ERR_INTERNAL;
        };
        unsafe {
            *out_public = HideBuffer::from_vec(public.to_bytes());
            *out_secret = Box::into_raw(Box::new(HideSecretKey(secret)));
        }
        HIDE_OK
    })
}

/// Reports whether a key file is raw or passphrase-protected, without needing
/// the passphrase.
///
/// # Safety
/// `data` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_inspect_key(data: *const u8, len: usize, out_kind: *mut i32) -> i32 {
    guard(|| {
        if out_kind.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Some(bytes) = (unsafe { borrow(data, len, MAX_KEY_FILE) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        let kind = match hide_keyring::inspect(bytes) {
            KeyFormat::Raw => HIDE_KEY_RAW,
            KeyFormat::Protected => HIDE_KEY_PROTECTED,
        };
        unsafe { *out_kind = kind };
        HIDE_OK
    })
}

/// Loads a secret key from a file's bytes. Pass `passphrase = NULL` for a raw
/// key; a protected key without a passphrase fails rather than guessing.
///
/// # Safety
/// `data` must be valid for `len` bytes; `passphrase` must be null or a valid
/// C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_secret_key_open(
    data: *const u8,
    len: usize,
    passphrase: *const c_char,
    out_secret: *mut *mut HideSecretKey,
) -> i32 {
    guard(|| {
        if out_secret.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Some(bytes) = (unsafe { borrow(data, len, MAX_KEY_FILE) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        let Some(passphrase) = (unsafe { borrow_str(passphrase) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        match hide_keyring::open(bytes, passphrase) {
            Ok(secret) => {
                unsafe { *out_secret = Box::into_raw(Box::new(HideSecretKey(secret))) };
                HIDE_OK
            }
            Err(error) => keyring_error_code(&error),
        }
    })
}

/// Seals a secret key with a passphrase, producing the bytes to store on disk.
///
/// # Safety
/// `secret` must come from this library; `passphrase` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_secret_key_protect(
    secret: *const HideSecretKey,
    passphrase: *const c_char,
    out: *mut HideBuffer,
) -> i32 {
    guard(|| {
        if secret.is_null() || out.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Some(Some(passphrase)) = (unsafe { borrow_str(passphrase) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        let secret = unsafe { &*secret };
        match hide_keyring::protect(&secret.0, passphrase) {
            Ok(sealed) => {
                unsafe { *out = HideBuffer::from_vec(sealed) };
                HIDE_OK
            }
            Err(error) => keyring_error_code(&error),
        }
    })
}

/// Derives the public key belonging to a secret key.
///
/// # Safety
/// `secret` must come from this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_secret_key_public(
    secret: *const HideSecretKey,
    out: *mut HideBuffer,
) -> i32 {
    guard(|| {
        if secret.is_null() || out.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let secret = unsafe { &*secret };
        match secret.0.public_key() {
            Ok(public) => {
                unsafe { *out = HideBuffer::from_vec(public.to_bytes()) };
                HIDE_OK
            }
            Err(_) => HIDE_ERR_INTERNAL,
        }
    })
}

/// Releases a secret key. The key material is zeroized.
///
/// # Safety
/// `secret` must come from this library and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_secret_key_free(secret: *mut HideSecretKey) {
    if secret.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(secret) });
}

/// Encrypts a buffer for one or more recipients.
///
/// `recipients` is a flat array of `recipient_count` public keys, each exactly
/// `HIDE_PUBLIC_KEY_LEN` bytes.
///
/// # Safety
/// All pointers must be valid for the stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    recipients: *const u8,
    recipient_count: usize,
    filename: *const c_char,
    media_type: *const c_char,
    out: *mut HideBuffer,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        if recipient_count == 0 || recipient_count > 64 {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Some(plaintext) = (unsafe { borrow(plaintext, plaintext_len, MAX_INPUT) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        let Some(keys) =
            (unsafe { borrow(recipients, recipient_count * HIDE_PUBLIC_KEY_LEN, MAX_INPUT) })
        else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };

        let mut parsed = Vec::with_capacity(recipient_count);
        for chunk in keys.chunks_exact(HIDE_PUBLIC_KEY_LEN) {
            match RecipientPublic::from_bytes(chunk) {
                Ok(key) => parsed.push(key),
                Err(_) => return HIDE_ERR_INVALID_ARGUMENT,
            }
        }

        let (Some(filename), Some(media_type)) = (unsafe { borrow_str(filename) }, unsafe {
            borrow_str(media_type)
        }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        let metadata = Metadata {
            filename: filename.map(str::to_owned),
            media_type: media_type.map(str::to_owned),
        };

        let mut container = Vec::new();
        match hide_object::encrypt(&mut &*plaintext, &mut container, &parsed, &metadata) {
            Ok(_) => {
                unsafe { *out = HideBuffer::from_vec(container) };
                HIDE_OK
            }
            Err(error) => object_error_code(&error),
        }
    })
}

/// Decrypts a container. Nothing is written to `out` unless the whole payload
/// authenticates, so a caller cannot act on unverified plaintext.
///
/// Metadata is returned as length-prefixed buffers rather than C strings:
/// the values are attacker-controlled, and a length is not something a caller
/// can get wrong by scanning for a terminator. Free them like any buffer.
///
/// # Safety
/// All pointers must be valid for the stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_decrypt(
    container: *const u8,
    container_len: usize,
    secret: *const HideSecretKey,
    out: *mut HideBuffer,
    out_filename: *mut HideBuffer,
    out_media_type: *mut HideBuffer,
) -> i32 {
    guard(|| {
        if secret.is_null() || out.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Some(container) = (unsafe { borrow(container, container_len, MAX_INPUT) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        let secret = unsafe { &*secret };

        // Held in a zeroizing buffer so a failed decryption leaves no plaintext.
        let mut plaintext = Zeroizing::new(Vec::new());
        let verified =
            match hide_object::decrypt_to_staging(&mut &*container, &mut *plaintext, &secret.0) {
                Ok(verified) => verified,
                Err(error) => return object_error_code(&error),
            };

        if !out_filename.is_null() {
            let value = verified.metadata.filename.unwrap_or_default();
            unsafe { *out_filename = HideBuffer::from_vec(value.into_bytes()) };
        }
        if !out_media_type.is_null() {
            let value = verified.metadata.media_type.unwrap_or_default();
            unsafe { *out_media_type = HideBuffer::from_vec(value.into_bytes()) };
        }

        unsafe { *out = HideBuffer::from_vec(std::mem::take(&mut *plaintext)) };
        HIDE_OK
    })
}

/// Encodes a public key as pasteable armored text, returned as UTF-8 bytes.
///
/// # Safety
/// `data` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_public_key_armor(
    data: *const u8,
    len: usize,
    out: *mut HideBuffer,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Some(bytes) = (unsafe { borrow(data, len, MAX_KEY_FILE) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        if bytes.len() != HIDE_PUBLIC_KEY_LEN {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let armored = hide_keyring::encode_public(bytes);
        unsafe { *out = HideBuffer::from_vec(armored.into_bytes()) };
        HIDE_OK
    })
}

/// Decodes armored public-key text back into bytes.
///
/// # Safety
/// `text` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hide_public_key_dearmor(text: *const c_char, out: *mut HideBuffer) -> i32 {
    guard(|| {
        if out.is_null() {
            return HIDE_ERR_INVALID_ARGUMENT;
        }
        let Some(Some(text)) = (unsafe { borrow_str(text) }) else {
            return HIDE_ERR_INVALID_ARGUMENT;
        };
        match hide_keyring::decode_public(text) {
            Ok(bytes) if bytes.len() == HIDE_PUBLIC_KEY_LEN => {
                unsafe { *out = HideBuffer::from_vec(bytes) };
                HIDE_OK
            }
            Ok(_) => HIDE_ERR_INVALID_ARGUMENT,
            Err(error) => keyring_error_code(&error),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    /// Drives the API exactly as a C caller would, pointers and all.
    unsafe fn keypair() -> (*mut HideSecretKey, HideBuffer) {
        let mut secret = ptr::null_mut();
        let mut public = hide_buffer_empty();
        assert_eq!(
            unsafe { hide_keypair_generate(&mut secret, &mut public) },
            HIDE_OK
        );
        assert_eq!(public.len, HIDE_PUBLIC_KEY_LEN);
        (secret, public)
    }

    #[test]
    fn round_trips_through_the_c_api() {
        unsafe {
            let (secret, public) = keypair();
            let message = b"nume,suma\nAna,9000\n";

            let mut container = hide_buffer_empty();
            assert_eq!(
                hide_encrypt(
                    message.as_ptr(),
                    message.len(),
                    public.data,
                    1,
                    c"salarii.csv".as_ptr(),
                    ptr::null(),
                    &mut container,
                ),
                HIDE_OK
            );
            assert!(container.len > message.len());

            let mut plaintext = hide_buffer_empty();
            let mut filename = hide_buffer_empty();
            assert_eq!(
                hide_decrypt(
                    container.data,
                    container.len,
                    secret,
                    &mut plaintext,
                    &mut filename,
                    ptr::null_mut(),
                ),
                HIDE_OK
            );
            assert_eq!(
                slice::from_raw_parts(plaintext.data, plaintext.len),
                message
            );
            assert_eq!(
                slice::from_raw_parts(filename.data, filename.len),
                b"salarii.csv"
            );

            hide_buffer_free(&mut filename);
            hide_buffer_free(&mut plaintext);
            hide_buffer_free(&mut container);
            hide_buffer_free(&mut { public });
            hide_secret_key_free(secret);
        }
    }

    #[test]
    fn a_freed_buffer_is_cleared_and_safe_to_free_twice() {
        unsafe {
            let (secret, mut public) = keypair();
            let mut container = hide_buffer_empty();
            hide_encrypt(
                b"x".as_ptr(),
                1,
                public.data,
                1,
                ptr::null(),
                ptr::null(),
                &mut container,
            );
            hide_buffer_free(&mut container);
            assert!(container.data.is_null(), "freed buffer kept its pointer");
            // A second free must be a no-op rather than a double free.
            hide_buffer_free(&mut container);
            hide_buffer_free(&mut public);
            hide_secret_key_free(secret);
        }
    }

    #[test]
    fn tampering_is_refused_and_yields_no_plaintext() {
        unsafe {
            let (secret, mut public) = keypair();
            let mut container = hide_buffer_empty();
            hide_encrypt(
                b"confidential".as_ptr(),
                12,
                public.data,
                1,
                ptr::null(),
                ptr::null(),
                &mut container,
            );

            let mut damaged = slice::from_raw_parts(container.data, container.len).to_vec();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;

            let mut plaintext = hide_buffer_empty();
            let code = hide_decrypt(
                damaged.as_ptr(),
                damaged.len(),
                secret,
                &mut plaintext,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            assert_ne!(code, HIDE_OK);
            assert!(plaintext.data.is_null(), "published unverified plaintext");

            hide_buffer_free(&mut container);
            hide_buffer_free(&mut public);
            hide_secret_key_free(secret);
        }
    }

    #[test]
    fn the_wrong_key_cannot_decrypt() {
        unsafe {
            let (secret, mut public) = keypair();
            let (other, mut other_public) = keypair();
            let mut container = hide_buffer_empty();
            hide_encrypt(
                b"secret".as_ptr(),
                6,
                public.data,
                1,
                ptr::null(),
                ptr::null(),
                &mut container,
            );

            let mut plaintext = hide_buffer_empty();
            assert_eq!(
                hide_decrypt(
                    container.data,
                    container.len,
                    other,
                    &mut plaintext,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                HIDE_ERR_NO_MATCHING_RECIPIENT
            );

            hide_buffer_free(&mut container);
            hide_buffer_free(&mut public);
            hide_buffer_free(&mut other_public);
            hide_secret_key_free(secret);
            hide_secret_key_free(other);
        }
    }

    #[test]
    fn null_and_absurd_arguments_are_rejected_rather_than_crashing() {
        unsafe {
            let mut out = hide_buffer_empty();
            let mut secret = ptr::null_mut();

            assert_eq!(
                hide_keypair_generate(ptr::null_mut(), &mut out),
                HIDE_ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                hide_keypair_generate(&mut secret, ptr::null_mut()),
                HIDE_ERR_INVALID_ARGUMENT
            );
            // A non-null length with a null pointer must not be dereferenced.
            assert_eq!(
                hide_encrypt(
                    ptr::null(),
                    10,
                    ptr::null(),
                    1,
                    ptr::null(),
                    ptr::null(),
                    &mut out
                ),
                HIDE_ERR_INVALID_ARGUMENT
            );
            // A length that would over-allocate must be refused up front.
            assert_eq!(
                hide_encrypt(
                    b"x".as_ptr(),
                    usize::MAX,
                    ptr::null(),
                    1,
                    ptr::null(),
                    ptr::null(),
                    &mut out
                ),
                HIDE_ERR_INVALID_ARGUMENT
            );
            assert_eq!(
                hide_decrypt(
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut out,
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                HIDE_ERR_INVALID_ARGUMENT
            );
            let mut kind = -1;
            assert_eq!(
                hide_inspect_key(ptr::null(), 32, &mut kind),
                HIDE_ERR_INVALID_ARGUMENT
            );
            // Freeing null is a no-op, not a crash.
            hide_buffer_free(ptr::null_mut());
            hide_secret_key_free(ptr::null_mut());
        }
    }

    #[test]
    fn protected_keys_round_trip_and_reject_a_wrong_passphrase() {
        unsafe {
            let (secret, mut public) = keypair();
            let mut sealed = hide_buffer_empty();
            assert_eq!(
                hide_secret_key_protect(secret, c"correct horse".as_ptr(), &mut sealed),
                HIDE_OK
            );

            let mut kind = -1;
            assert_eq!(
                hide_inspect_key(sealed.data, sealed.len, &mut kind),
                HIDE_OK
            );
            assert_eq!(kind, HIDE_KEY_PROTECTED);

            let mut reopened = ptr::null_mut();
            assert_eq!(
                hide_secret_key_open(sealed.data, sealed.len, c"wrong".as_ptr(), &mut reopened),
                HIDE_ERR_WRONG_PASSPHRASE
            );
            assert_eq!(
                hide_secret_key_open(sealed.data, sealed.len, ptr::null(), &mut reopened),
                HIDE_ERR_WRONG_PASSPHRASE
            );
            assert_eq!(
                hide_secret_key_open(
                    sealed.data,
                    sealed.len,
                    c"correct horse".as_ptr(),
                    &mut reopened
                ),
                HIDE_OK
            );

            // The reopened key must be the same one.
            let mut derived = hide_buffer_empty();
            assert_eq!(hide_secret_key_public(reopened, &mut derived), HIDE_OK);
            assert_eq!(
                slice::from_raw_parts(derived.data, derived.len),
                slice::from_raw_parts(public.data, public.len)
            );

            hide_buffer_free(&mut derived);
            hide_buffer_free(&mut sealed);
            hide_buffer_free(&mut public);
            hide_secret_key_free(reopened);
            hide_secret_key_free(secret);
        }
    }

    #[test]
    fn armor_round_trips_and_rejects_rubbish() {
        unsafe {
            let (secret, mut public) = keypair();
            let mut armored = hide_buffer_empty();
            assert_eq!(
                hide_public_key_armor(public.data, public.len, &mut armored),
                HIDE_OK
            );

            // The armored form must survive a trip through a C string.
            let text =
                CString::new(slice::from_raw_parts(armored.data, armored.len)).expect("no NUL");
            let mut decoded = hide_buffer_empty();
            assert_eq!(
                hide_public_key_dearmor(text.as_ptr(), &mut decoded),
                HIDE_OK
            );
            assert_eq!(
                slice::from_raw_parts(decoded.data, decoded.len),
                slice::from_raw_parts(public.data, public.len)
            );
            assert_ne!(
                hide_public_key_dearmor(c"not a key".as_ptr(), &mut decoded),
                HIDE_OK
            );

            hide_buffer_free(&mut decoded);
            hide_buffer_free(&mut armored);
            hide_buffer_free(&mut public);
            hide_secret_key_free(secret);
        }
    }
}
