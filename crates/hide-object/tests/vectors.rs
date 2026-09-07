use std::{error::Error, fs, path::PathBuf};

use hide_crypto::RecipientSecret;
use hide_object::{Metadata, decrypt_to_staging};

#[test]
fn frozen_vectors_decrypt_and_match_recorded_bytes() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let secret = RecipientSecret::from_bytes(&fs::read(directory.join("recipient.test-secret"))?)?;
    assert_eq!(
        secret.public_key()?.to_bytes(),
        fs::read(directory.join("recipient.test-public"))?
    );
    for name in ["hello", "empty"] {
        let container = fs::read(directory.join(format!("{name}.hide")))?;
        let mut plaintext = Vec::new();
        let verified = decrypt_to_staging(&mut container.as_slice(), &mut plaintext, &secret)?;
        assert_eq!(plaintext, fs::read(directory.join(format!("{name}.txt")))?);
        assert_eq!(
            verified.metadata,
            Metadata {
                filename: Some(format!("{name}.txt")),
                media_type: Some("text/plain".into()),
                signature: None
            }
        );
        assert_eq!(verified.plaintext_len, plaintext.len() as u64);
    }
    Ok(())
}

/// The v0.1 containers predate signatures entirely. That they still open, and
/// report no signer, is the compatibility guarantee for every existing file.
#[test]
fn frozen_unsigned_vectors_still_report_no_signer() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let secret = RecipientSecret::from_bytes(&fs::read(directory.join("recipient.test-secret"))?)?;
    for name in ["hello", "empty"] {
        let container = fs::read(directory.join(format!("{name}.hide")))?;
        // Byte 9 is the preamble minor version; v0.1 containers must stay at 1.
        assert_eq!(container[9], 1, "{name} is no longer a v0.1 container");
        let mut plaintext = Vec::new();
        let verified = decrypt_to_staging(&mut container.as_slice(), &mut plaintext, &secret)?;
        assert!(verified.signer.is_none());
    }
    Ok(())
}

#[test]
fn frozen_signed_vectors_verify_against_the_recorded_signer() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let secret = RecipientSecret::from_bytes(&fs::read(directory.join("recipient.test-secret"))?)?;
    let expected = fs::read(directory.join("signed.test-public"))?;

    for name in ["signed-public", "signed-confidential"] {
        let container = fs::read(directory.join(format!("{name}.hide")))?;
        assert_eq!(container[9], 2, "{name} must advertise minor 2");
        let mut plaintext = Vec::new();
        let verified = decrypt_to_staging(&mut container.as_slice(), &mut plaintext, &secret)?;
        assert_eq!(plaintext, fs::read(directory.join(format!("{name}.txt")))?);
        let signer = verified.signer.expect("signed vector reports a signer");
        assert_eq!(signer.to_bytes()[..], expected[..]);

        // The confidential placement must not expose the signer in the file.
        let exposed = container
            .windows(expected.len())
            .any(|window| window == expected);
        assert_eq!(exposed, name == "signed-public", "{name} visibility");
    }
    Ok(())
}

#[test]
fn frozen_vectors_reject_truncation_and_tampering() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let secret = RecipientSecret::from_bytes(&fs::read(directory.join("recipient.test-secret"))?)?;
    let container = fs::read(directory.join("hello.hide"))?;
    for offset in 0..container.len() {
        let mut damaged = container.clone();
        damaged[offset] ^= 0x40;
        assert!(
            decrypt_to_staging(&mut damaged.as_slice(), &mut Vec::new(), &secret).is_err(),
            "offset {offset}"
        );
    }
    assert!(
        decrypt_to_staging(
            &mut &container[..container.len() - 1],
            &mut Vec::new(),
            &secret
        )
        .is_err()
    );
    Ok(())
}
