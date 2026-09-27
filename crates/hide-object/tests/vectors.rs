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
                signature: None,
                extensions: Vec::new(),
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
        if name.ends_with(".test-secret") {
            // A key file, not a container: the cost parameters in its header
            // are attacker-chosen and must be refused before Argon2 allocates.
            let bytes = fs::read(directory.join(name))?;
            assert!(
                hide_keyring::unprotect(&bytes, "passphrase").is_err(),
                "{name} must be refused: {reason}"
            );
            continue;
        }
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
        let result = decrypt_to_staging(&mut container.as_slice(), &mut out, &secret);
        let error = match result {
            Ok(_) => panic!("{name} must be refused: {reason}"),
            Err(error) => error,
        };
        // The 0.9 vectors re-authenticate everything a recipient controls, so
        // they must fail for their stated reason, not at the MAC. Pinning the
        // error is what keeps a later refactor from passing them by accident.
        if let Some(expected) = expected_error(name) {
            let got = format!("{error:?}");
            assert!(
                got.contains(expected),
                "{name}: refused as {got}, expected {expected} ({reason})"
            );
        }
    }

    // Every file on disk is listed, so a vector cannot be added without a reason.
    let on_disk = fs::read_dir(&directory)?
        .filter_map(Result::ok)
        .filter(|e| e.file_name() != "rejections.txt")
        .count();
    assert_eq!(on_disk, listed, "rejections.txt and the directory disagree");
    assert!(listed >= 30, "expected the full set of rejection vectors");
    Ok(())
}

/// The refusal each 0.9 rejection vector exists to trigger. The pre-0.9 ones
/// were written before errors were pinned and are only required to fail.
fn expected_error(name: &str) -> Option<&'static str> {
    Some(match name {
        "unknown-flag" | "legacy-minor-with-flag" | "critical-header-key" => "UnsupportedFeature",
        "critical-metadata-key" | "reserved-metadata-key" | "unknown-signature-tag" => {
            "UnsupportedFeature"
        }
        "minor-zero" => "UnsupportedVersion",
        "stripped-signature" => "MissingSignature",
        "unexpected-signature" => "UnexpectedSignature",
        "signature-extension-rewritten" | "signature-unknown-stanza-removed" => "InvalidSignature",
        "legacy-minor2-with-extension" | "header-key-over-u16" | "ignorable-ext-oversize" => {
            "MalformedHeader"
        }
        "ignorable-ext-not-bstr" | "too-many-extensions" | "two-signatures" => "MalformedHeader",
        "only-unknown-stanzas" => "NoMatchingRecipient",
        "filename-dotdot" => "InvalidMetadata",
        "non-canonical-metadata" => "NonCanonical",
        _ => return None,
    })
}

/// What 0.9.0 added to the wire, and what a 1.0 reader must accept: the SIGNED
/// flag with the 1.0 transcript, and GREASE — an ignorable header key, an
/// ignorable metadata key, an unknown recipient stanza, a newer minor.
#[test]
fn frozen_v1_and_grease_vectors_open() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let secret = RecipientSecret::from_bytes(&fs::read(directory.join("recipient.test-secret"))?)?;
    let signer = fs::read(directory.join("signed.test-public"))?;
    for (name, minor, flags, signed, extensions) in [
        ("v1-signed", 1, 1, true, 0),
        ("v1-signed-confidential", 1, 1, true, 0),
        ("grease", 1, 0, false, 1),
        ("grease-signed", 1, 1, true, 1),
        ("grease-minor", 7, 0, false, 0),
    ] {
        let container = fs::read(directory.join(format!("{name}.hide")))?;
        assert_eq!((container[9], container[11]), (minor, flags), "{name}");
        let mut plaintext = Vec::new();
        let verified = decrypt_to_staging(&mut container.as_slice(), &mut plaintext, &secret)?;
        assert_eq!(plaintext, fs::read(directory.join(format!("{name}.txt")))?);
        assert_eq!(verified.metadata.extensions.len(), extensions, "{name}");
        match verified.signer {
            Some(key) => assert!(signed && key.to_bytes()[..] == signer[..], "{name}"),
            None => assert!(!signed, "{name} lost its signature"),
        }
    }
    Ok(())
}

/// The manifest is what a non-Rust implementation runs from, so it must name
/// every file on disk and carry each one's current hash.
#[test]
fn the_manifest_names_every_vector_with_its_hash() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/vectors");
    let manifest = fs::read_to_string(directory.join("manifest.json"))?;
    let mut files = Vec::new();
    let mut stack = vec![directory.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    let mut named = 0;
    for path in files {
        let relative = path
            .strip_prefix(&directory)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "manifest.json" || relative.ends_with(".txt") || relative.ends_with(".md") {
            continue;
        }
        let sha: String = hide_crypto::hash(&[&fs::read(&path)?])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let entry = format!("\"path\": \"{relative}\"");
        let line = manifest
            .lines()
            .find(|l| l.contains(&entry))
            .unwrap_or_else(|| panic!("{relative} is not in manifest.json"));
        assert!(line.contains(&sha), "{relative}: manifest hash is stale");
        named += 1;
    }
    assert_eq!(
        manifest.matches("\"path\"").count(),
        named,
        "manifest names a file that does not exist"
    );
    Ok(())
}
