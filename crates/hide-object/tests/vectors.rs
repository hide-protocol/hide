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
                media_type: Some("text/plain".into())
            }
        );
        assert_eq!(verified.plaintext_len, plaintext.len() as u64);
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
