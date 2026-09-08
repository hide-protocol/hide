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

/// The vectors above predate identities: their secret file IS the recipient
/// key, so they exercise a path no surface takes any more. This one is opened
/// the way the CLI and every SDK open an unprotected key file — as a master
/// seed the encryption key is derived from.
#[test]
fn the_seed_vector_opens_the_way_every_surface_loads_a_key_file() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let file = fs::read(directory.join("identity.test-seed"))?;
    let secret = hide_keyring::open(&file, None)?;
    assert_eq!(
        secret.public_key()?.to_bytes(),
        fs::read(directory.join("identity.test-public"))?
    );

    let container = fs::read(directory.join("identity.hide"))?;
    let mut plaintext = Vec::new();
    decrypt_to_staging(&mut container.as_slice(), &mut plaintext, &secret)?;
    assert_eq!(plaintext, fs::read(directory.join("identity.txt"))?);

    // Reading the file as the key itself is the regression this vector exists
    // to catch: it must NOT open the container.
    let literal = RecipientSecret::from_bytes(&file)?;
    let mut wrong = Vec::new();
    assert!(decrypt_to_staging(&mut container.as_slice(), &mut wrong, &literal).is_err());
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

/// The frozen negative vectors: every file that `rejections.txt` names must
/// fail, and the reason column must stay in step with the files, so an
/// independent implementation can assert the same list.
#[test]
fn every_frozen_rejection_vector_is_refused() -> Result<(), Box<dyn Error>> {
    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let directory = vectors.join("rejections");
    let secret = RecipientSecret::from_bytes(&fs::read(vectors.join("recipient.test-secret"))?)?;

    let index = fs::read_to_string(directory.join("rejections.txt"))?;
    let mut listed = 0;
    for line in index
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (name, reason) = line.split_once('\t').expect("name<TAB>reason");
        assert!(!reason.is_empty(), "{name} has no reason");
        listed += 1;
        if name.ends_with(".test-public") {
            let bytes = fs::read(directory.join(name))?;
            assert!(
                hide_crypto::RecipientPublic::from_bytes(&bytes).is_err(),
                "{name} must be refused as a recipient key: {reason}"
            );
            continue;
        }
        let container = fs::read(directory.join(format!("{name}.hide")))?;
        let mut out = Vec::new();
        assert!(
            decrypt_to_staging(&mut container.as_slice(), &mut out, &secret).is_err(),
            "{name} must be refused: {reason}"
        );
    }

    // Every file on disk is listed, so a vector cannot be added without a reason.
    let on_disk = fs::read_dir(&directory)?
        .filter_map(Result::ok)
        .filter(|e| e.file_name() != "rejections.txt")
        .count();
    assert_eq!(on_disk, listed, "rejections.txt and the directory disagree");
    assert!(listed >= 9, "expected the full set of rejection vectors");
    Ok(())
}
