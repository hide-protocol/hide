//! CLI signing. The tests that matter are the negative ones: a signature must
//! fail when the file changes, when the signer is wrong, and when a detached
//! signature is replayed against a different file.

use std::{
    error::Error,
    fs,
    path::Path,
    process::{Command, Output},
};

fn hide(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hide"))
        .current_dir(directory)
        .args(args)
        .output()
        .expect("test binary runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `--insecure-plaintext` writes a raw master seed, which the CLI reads as a
/// full identity, so signing works without a passphrase prompt.
fn identity(directory: &Path, name: &str) {
    let result = hide(
        directory,
        &[
            "--experimental",
            "--quiet",
            "keygen",
            "--secret",
            &format!("{name}.test-secret"),
            "--public",
            &format!("{name}.test-public"),
            "--insecure-plaintext",
        ],
    );
    assert!(result.status.success(), "{}", stderr(&result));
}

#[test]
fn keygen_writes_an_encryption_and_a_signing_public_key() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");

    assert_eq!(
        fs::metadata(directory.path().join("alice.test-secret"))?.len(),
        32,
        "the secret is one master seed"
    );
    assert_eq!(
        fs::metadata(directory.path().join("alice.test-public"))?.len(),
        1216
    );
    assert_eq!(
        fs::metadata(directory.path().join("alice.test-public.sign"))?.len(),
        1984
    );
    Ok(())
}

#[test]
fn signs_and_verifies_a_detached_signature() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("contract.txt"), b"pay 100 RON")?;

    let signed = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "sign",
            "contract.txt",
            "--secret",
            "alice.test-secret",
        ],
    );
    assert!(signed.status.success(), "{}", stderr(&signed));
    assert!(
        directory.path().join("contract.txt.hide-sig").exists(),
        "signature was not written beside the file"
    );

    let verified = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "verify",
            "contract.txt",
            "--signer",
            "alice.test-public.sign",
        ],
    );
    assert!(verified.status.success(), "{}", stderr(&verified));
    assert!(stderr(&verified).contains("Signature is valid"));
    // A signature must never be reported as proof of who someone is.
    assert!(stderr(&verified).contains("not the identity of a person"));
    Ok(())
}

#[test]
fn a_changed_file_fails_verification() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("contract.txt"), b"pay 100 RON")?;
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "sign",
            "contract.txt",
            "--secret",
            "alice.test-secret",
        ],
    );

    // Same length, so only the content differs.
    fs::write(directory.path().join("contract.txt"), b"pay 900 RON")?;
    let verified = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "verify",
            "contract.txt",
            "--signer",
            "alice.test-public.sign",
        ],
    );
    assert!(!verified.status.success(), "a changed file verified");
    assert!(stderr(&verified).contains("hide:"));
    Ok(())
}

#[test]
fn a_signature_from_another_signer_is_named_and_refused() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    identity(directory.path(), "mallory");
    fs::write(directory.path().join("contract.txt"), b"pay 100 RON")?;
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "sign",
            "contract.txt",
            "--secret",
            "mallory.test-secret",
        ],
    );

    let verified = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "verify",
            "contract.txt",
            "--signer",
            "alice.test-public.sign",
        ],
    );
    assert!(!verified.status.success(), "the wrong signer was accepted");
    assert!(
        stderr(&verified).contains("not"),
        "the error should name the mismatch: {}",
        stderr(&verified)
    );
    Ok(())
}

/// Truncation must be caught. The digest alone would not notice a prefix if the
/// length were omitted from the signed message.
#[test]
fn a_truncated_file_fails_verification() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(
        directory.path().join("contract.txt"),
        b"pay 100 RON exactly",
    )?;
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "sign",
            "contract.txt",
            "--secret",
            "alice.test-secret",
        ],
    );

    fs::write(directory.path().join("contract.txt"), b"pay 100 RON")?;
    let verified = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "verify",
            "contract.txt",
            "--signer",
            "alice.test-public.sign",
        ],
    );
    assert!(!verified.status.success(), "a truncated file verified");
    Ok(())
}

/// A container signature and a detached signature must live in separate
/// domains, or one could be presented as the other.
#[test]
fn a_container_signature_is_not_a_valid_detached_signature() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    let plaintext = b"quarterly numbers";
    fs::write(directory.path().join("report.txt"), plaintext)?;

    // Sign the file publicly inside a container, then lift that signature out
    // and present it as a detached signature over the same plaintext.
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "report.txt",
            "--recipient",
            "alice.test-public",
            "-o",
            "report.hide",
            "--sign",
            "alice.test-secret",
            "--public-signature",
        ],
    );

    let container = fs::read(directory.path().join("report.hide"))?;
    let key = fs::read(directory.path().join("alice.test-public.sign"))?;
    let at = container
        .windows(key.len())
        .position(|window| window == key)
        .expect("a public signature carries the key in the clear");
    let lifted = &container[at..at + key.len() + 3373];
    fs::write(directory.path().join("report.txt.hide-sig"), lifted)?;

    let verified = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "verify",
            "report.txt",
            "--signer",
            "alice.test-public.sign",
        ],
    );
    assert!(
        !verified.status.success(),
        "a container signature was accepted as a detached one"
    );
    Ok(())
}

/// A detached signature must not transfer to a different file of the same size.
#[test]
fn a_signature_cannot_be_moved_to_another_file() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("real.txt"), b"pay 100 RON")?;
    fs::write(directory.path().join("fake.txt"), b"pay 900 RON")?;
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "sign",
            "real.txt",
            "--secret",
            "alice.test-secret",
        ],
    );
    fs::copy(
        directory.path().join("real.txt.hide-sig"),
        directory.path().join("fake.txt.hide-sig"),
    )?;

    let verified = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "verify",
            "fake.txt",
            "--signer",
            "alice.test-public.sign",
        ],
    );
    assert!(
        !verified.status.success(),
        "a transplanted signature verified"
    );
    Ok(())
}

#[test]
fn encrypt_sign_and_open_reports_the_signer() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("report.txt"), b"quarterly numbers")?;

    for (label, extra) in [
        ("confidential", vec![]),
        ("public", vec!["--public-signature"]),
    ] {
        let output = format!("{label}.hide");
        let recovered = format!("{label}.txt");
        let mut args = vec![
            "--experimental",
            "--quiet",
            "encrypt",
            "report.txt",
            "--recipient",
            "alice.test-public",
            "-o",
            &output,
            "--sign",
            "alice.test-secret",
        ];
        args.extend(extra);
        let encrypted = hide(directory.path(), &args);
        assert!(encrypted.status.success(), "{}", stderr(&encrypted));

        let opened = hide(
            directory.path(),
            &[
                "--experimental",
                "--quiet",
                "open",
                &output,
                "--secret",
                "alice.test-secret",
                "-o",
                &recovered,
            ],
        );
        assert!(opened.status.success(), "{}", stderr(&opened));
        assert_eq!(
            fs::read(directory.path().join(&recovered))?,
            b"quarterly numbers"
        );
        assert!(
            stderr(&opened).contains("Signed by key"),
            "{label}: signer not reported: {}",
            stderr(&opened)
        );
        assert!(
            !stderr(&opened).contains("Sender is not authenticated"),
            "{label}: a signed container claimed no authentication"
        );
    }
    Ok(())
}

/// The confidential placement must not put the signer's key in the file.
#[test]
fn a_confidential_signature_is_not_visible_in_the_container() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("report.txt"), b"quarterly numbers")?;
    let signing_key = fs::read(directory.path().join("alice.test-public.sign"))?;

    for (name, extra) in [
        ("hidden.hide", vec![]),
        ("shown.hide", vec!["--public-signature"]),
    ] {
        let mut args = vec![
            "--experimental",
            "--quiet",
            "encrypt",
            "report.txt",
            "--recipient",
            "alice.test-public",
            "-o",
            name,
            "--sign",
            "alice.test-secret",
        ];
        args.extend(extra.clone());
        assert!(hide(directory.path(), &args).status.success());

        let container = fs::read(directory.path().join(name))?;
        let exposed = container
            .windows(signing_key.len())
            .any(|window| window == signing_key);
        assert_eq!(
            exposed,
            !extra.is_empty(),
            "{name}: wrong signer visibility"
        );
    }
    Ok(())
}

#[test]
fn unsigned_containers_still_say_the_sender_is_not_authenticated() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("report.txt"), b"quarterly numbers")?;
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "report.txt",
            "--recipient",
            "alice.test-public",
            "-o",
            "plain.hide",
        ],
    );

    let opened = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "open",
            "plain.hide",
            "--secret",
            "alice.test-secret",
            "-o",
            "plain.txt",
        ],
    );
    assert!(opened.status.success(), "{}", stderr(&opened));
    assert!(stderr(&opened).contains("Sender is not authenticated"));
    Ok(())
}

#[test]
fn public_signature_requires_sign() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("report.txt"), b"x")?;

    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "report.txt",
            "--recipient",
            "alice.test-public",
            "-o",
            "out.hide",
            "--public-signature",
        ],
    );
    assert!(!result.status.success());
    assert!(!directory.path().join("out.hide").exists());
    Ok(())
}

#[test]
fn info_recognises_signing_keys_signatures_and_signed_containers() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path(), "alice");
    fs::write(directory.path().join("report.txt"), b"x")?;
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "sign",
            "report.txt",
            "--secret",
            "alice.test-secret",
        ],
    );
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "report.txt",
            "--recipient",
            "alice.test-public",
            "-o",
            "signed.hide",
            "--sign",
            "alice.test-secret",
        ],
    );

    let key = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "info",
            "alice.test-public.sign",
        ],
    );
    assert!(String::from_utf8_lossy(&key.stdout).contains("signing public key"));

    let signature = hide(
        directory.path(),
        &["--experimental", "--quiet", "info", "report.txt.hide-sig"],
    );
    assert!(String::from_utf8_lossy(&signature.stdout).contains("detached signature"));

    let container = hide(
        directory.path(),
        &["--experimental", "--quiet", "info", "signed.hide"],
    );
    let text = String::from_utf8_lossy(&container.stdout);
    assert!(text.contains("signed: yes"), "{text}");
    assert!(text.contains("format version: 0.2"), "{text}");
    Ok(())
}
