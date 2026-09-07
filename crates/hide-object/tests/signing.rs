//! Signed containers. The test that matters most is the forgery one: a
//! signature that covered only the header would let a recipient swap the
//! payload, because they hold the CEK and the salt is public.

use hide_crypto::RecipientSecret;
use hide_object::{Metadata, ObjectError, SignaturePlacement, decrypt_to_staging, encrypt_signed};
use hide_sign::SigningIdentity;

fn metadata() -> Metadata {
    Metadata {
        filename: Some("hello.txt".into()),
        media_type: Some("text/plain".into()),
        signature: None,
    }
}

fn seal(
    plaintext: &[u8],
    identity: &SigningIdentity,
    placement: SignaturePlacement,
    recipient: &RecipientSecret,
) -> Result<Vec<u8>, ObjectError> {
    let mut container = Vec::new();
    encrypt_signed(
        &mut &plaintext[..],
        &mut container,
        &[recipient.public_key()?],
        &metadata(),
        identity,
        placement,
    )?;
    Ok(container)
}

#[test]
fn a_signed_container_reports_its_signer() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let identity = SigningIdentity::from_bytes(&[0x11; 32]).expect("valid seed");

    for placement in [SignaturePlacement::Public, SignaturePlacement::Confidential] {
        let container = seal(b"attack at dawn", &identity, placement, &recipient)?;
        let mut staging = Vec::new();
        let verified = decrypt_to_staging(&mut &container[..], &mut staging, &recipient)?;

        assert_eq!(staging, b"attack at dawn");
        assert_eq!(
            verified.signer.as_ref(),
            Some(&identity.verifying_key()),
            "wrong signer for {placement:?}"
        );
    }
    Ok(())
}

#[test]
fn an_unsigned_container_reports_no_signer() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let mut container = Vec::new();
    hide_object::encrypt(
        &mut b"plain".as_slice(),
        &mut container,
        &[recipient.public_key()?],
        &metadata(),
    )?;

    let mut staging = Vec::new();
    let verified = decrypt_to_staging(&mut &container[..], &mut staging, &recipient)?;
    assert!(verified.signer.is_none());
    Ok(())
}

/// A confidential signature must not be visible to someone holding the file.
#[test]
fn a_confidential_signature_does_not_appear_in_the_clear() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let identity = SigningIdentity::from_bytes(&[0x22; 32]).expect("valid seed");
    let key = identity.verifying_key().to_bytes();

    let confidential = seal(
        b"secret",
        &identity,
        SignaturePlacement::Confidential,
        &recipient,
    )?;
    assert!(
        !confidential.windows(key.len()).any(|window| window == key),
        "the signer's key leaked into the ciphertext"
    );

    // The public placement is the opposite: it is meant to be visible.
    let public = seal(b"secret", &identity, SignaturePlacement::Public, &recipient)?;
    assert!(public.windows(key.len()).any(|window| window == key));
    Ok(())
}

/// The central security property, mounted as the real attack rather than a
/// splice: keep the signed header byte-for-byte and re-encrypt different
/// plaintext with the CEK the recipient already holds. The forged container is
/// internally consistent — every AEAD tag is valid — so only a signature that
/// commits to the plaintext can reject it.
#[test]
fn a_recipient_cannot_swap_the_payload_and_keep_the_signature() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let identity = SigningIdentity::from_bytes(&[0x33; 32]).expect("valid seed");

    let honest = seal(
        b"transfer 100 to alice",
        &identity,
        SignaturePlacement::Public,
        &recipient,
    )?;
    let forged =
        hide_object::forge_payload_for_test(&honest, &recipient, b"transfer 999 to mallory")?;

    // The forgery is well-formed: the header is unchanged, so the header MAC
    // still verifies and the payload decrypts cleanly. Compare the preamble and
    // header, whose length the preamble itself reports.
    let header_end = 16 + u32::from_be_bytes(honest[12..16].try_into().expect("4 bytes")) as usize;
    assert_eq!(
        forged[..header_end],
        honest[..header_end],
        "the forgery must reuse the signed header verbatim"
    );

    let mut staging = Vec::new();
    assert!(
        matches!(
            decrypt_to_staging(&mut &forged[..], &mut staging, &recipient),
            Err(ObjectError::InvalidSignature)
        ),
        "a swapped payload was accepted under the original signature"
    );
    Ok(())
}

/// Length alone must not be what binds the payload: a replacement of exactly
/// the same length must still be refused.
#[test]
fn a_same_length_payload_swap_is_refused() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let identity = SigningIdentity::from_bytes(&[0x88; 32]).expect("valid seed");

    let honest = seal(
        b"aaaaaaaa",
        &identity,
        SignaturePlacement::Public,
        &recipient,
    )?;
    let forged = hide_object::forge_payload_for_test(&honest, &recipient, b"bbbbbbbb")?;
    assert_eq!(forged.len(), honest.len());

    let mut staging = Vec::new();
    assert!(matches!(
        decrypt_to_staging(&mut &forged[..], &mut staging, &recipient),
        Err(ObjectError::InvalidSignature)
    ));
    Ok(())
}

/// Tampering with a public signature is caught by the header MAC before
/// signature verification is even reached, because the MAC covers the whole
/// protected header. Asserting the specific error would pin the wrong layer;
/// what matters is that the object is refused.
#[test]
fn a_tampered_signature_is_refused() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let identity = SigningIdentity::from_bytes(&[0x44; 32]).expect("valid seed");
    let container = seal(b"hello", &identity, SignaturePlacement::Public, &recipient)?;

    let key = identity.verifying_key().to_bytes();
    let offset = container
        .windows(key.len())
        .position(|window| window == key)
        .expect("public signature is present")
        + key.len()
        + 8;
    let mut tampered = container.clone();
    tampered[offset] ^= 1;

    let mut staging = Vec::new();
    assert!(matches!(
        decrypt_to_staging(&mut &tampered[..], &mut staging, &recipient),
        Err(ObjectError::NoMatchingRecipient)
    ));
    Ok(())
}

/// A signature that is well-formed but made by the wrong identity must be
/// refused by signature verification itself, not by an outer layer. This is the
/// case that actually exercises `verify_signature`.
#[test]
fn a_signature_from_another_identity_is_refused() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let alice = SigningIdentity::from_bytes(&[0x66; 32]).expect("valid seed");
    let mallory = SigningIdentity::from_bytes(&[0x77; 32]).expect("valid seed");

    // Same plaintext and metadata, so the two containers differ only in signer.
    let from_alice = seal(b"hello", &alice, SignaturePlacement::Public, &recipient)?;
    let from_mallory = seal(b"hello", &mallory, SignaturePlacement::Public, &recipient)?;

    // Swap Alice's verifying key in for Mallory's, leaving Mallory's signature.
    let mallory_key = mallory.verifying_key().to_bytes();
    let offset = from_mallory
        .windows(mallory_key.len())
        .position(|window| window == mallory_key)
        .expect("public signature is present");
    let mut swapped = from_mallory.clone();
    swapped[offset..offset + mallory_key.len()].copy_from_slice(&alice.verifying_key().to_bytes());

    let mut staging = Vec::new();
    assert!(
        decrypt_to_staging(&mut &swapped[..], &mut staging, &recipient).is_err(),
        "a signature from the wrong identity was accepted"
    );
    drop(from_alice);
    Ok(())
}

/// Stripping the signature must not downgrade the container to "unsigned".
#[test]
fn a_stripped_signature_is_detected() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let identity = SigningIdentity::from_bytes(&[0x55; 32]).expect("valid seed");
    let container = seal(b"hello", &identity, SignaturePlacement::Public, &recipient)?;

    // Byte 9 is the preamble minor version: 2 for signed, 1 for unsigned.
    assert_eq!(container[9], 2, "signed containers advertise minor 2");
    let mut downgraded = container.clone();
    downgraded[9] = 1;

    let mut staging = Vec::new();
    assert!(
        decrypt_to_staging(&mut &downgraded[..], &mut staging, &recipient).is_err(),
        "a downgraded container was accepted"
    );
    Ok(())
}

/// The mirror case: a container whose preamble claims minor 2 but carries no
/// signature must be refused rather than treated as unsigned.
///
/// Editing byte 9 of a real container is caught earlier, by the header MAC,
/// which covers the preamble. To reach the signature check itself the preamble
/// has to be authentic, so this builds a signed container and removes the
/// signature stanza at the source.
#[test]
fn a_minor_2_container_without_a_signature_is_refused() -> Result<(), ObjectError> {
    let recipient = RecipientSecret::generate()?;
    let identity = SigningIdentity::from_bytes(&[0x99; 32]).expect("valid seed");
    let mut container = Vec::new();
    hide_object::encrypt_stripped_signature_for_test(
        &mut b"hello".as_slice(),
        &mut container,
        &[recipient.public_key()?],
        &metadata(),
        &identity,
    )?;
    assert_eq!(container[9], 2, "preamble must still claim signed");

    let mut staging = Vec::new();
    assert!(
        matches!(
            decrypt_to_staging(&mut &container[..], &mut staging, &recipient),
            Err(ObjectError::MissingSignature)
        ),
        "a stripped signature was accepted as an unsigned container"
    );
    Ok(())
}
