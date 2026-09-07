//! The identity and epoch commands, exercised as a user would: separate
//! processes, real files on disk. A revoked device must be refused by the
//! binary, not merely by the library.

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

fn keypair(directory: &Path, name: &str) {
    let result = hide(
        directory,
        &[
            "--experimental",
            "--quiet",
            "keygen",
            "--insecure-plaintext",
            "--secret",
            &format!("{name}.sec"),
            "--public",
            &format!("{name}.pub"),
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

/// An identity with a laptop, a phone and an offline recovery key.
fn identity(directory: &Path) {
    keypair(directory, "laptop");
    keypair(directory, "phone");
    keypair(directory, "recovery");

    let created = hide(
        directory,
        &[
            "--experimental",
            "--quiet",
            "identity-create",
            "--secret",
            "laptop.sec",
            "--recovery",
            "recovery.pub.sign",
            "--label",
            "laptop",
            "--output",
            "id.log",
        ],
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );

    let enrolled = hide(
        directory,
        &[
            "--experimental",
            "--quiet",
            "identity-enrol",
            "--log",
            "id.log",
            "--secret",
            "laptop.sec",
            "--device",
            "phone.pub.sign",
            "--label",
            "phone",
            "--recovery",
            "recovery.pub.sign",
        ],
    );
    assert!(
        enrolled.status.success(),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
}

fn show(directory: &Path) -> String {
    let result = hide(
        directory,
        &[
            "--experimental",
            "--quiet",
            "identity-show",
            "--log",
            "id.log",
            "--recovery",
            "recovery.pub.sign",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stdout).into_owned()
}

#[test]
fn an_identity_grows_across_processes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path());

    let listing = show(directory.path());
    assert!(listing.contains("devices 2"), "{listing}");
    assert!(listing.contains("laptop"), "{listing}");
    assert!(listing.contains("phone"), "{listing}");
    Ok(())
}

#[test]
fn a_revoked_device_is_refused_by_the_binary() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path());

    let revoked = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "identity-revoke",
            "--log",
            "id.log",
            "--secret",
            "laptop.sec",
            "--device",
            "phone.pub.sign",
            "--recovery",
            "recovery.pub.sign",
        ],
    );
    assert!(revoked.status.success());
    assert!(show(directory.path()).contains("devices 1"));

    // The revoked phone must not be able to enrol anything.
    let attempt = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "identity-enrol",
            "--log",
            "id.log",
            "--secret",
            "phone.sec",
            "--device",
            "recovery.pub.sign",
            "--label",
            "intruder",
            "--recovery",
            "recovery.pub.sign",
        ],
    );
    assert!(
        !attempt.status.success(),
        "a revoked device enrolled a new one"
    );
    // And the log was not modified by the failed attempt.
    assert!(show(directory.path()).contains("devices 1"));
    Ok(())
}

#[test]
fn a_tampered_log_is_refused() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    identity(directory.path());

    let path = directory.path().join("id.log");
    let mut bytes = fs::read(&path)?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&path, &bytes)?;

    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "identity-show",
            "--log",
            "id.log",
            "--recovery",
            "recovery.pub.sign",
        ],
    );
    assert!(!result.status.success(), "a tampered log was accepted");
    Ok(())
}

#[test]
fn a_log_shown_with_the_wrong_recovery_key_after_recovery_is_refused() -> Result<(), Box<dyn Error>>
{
    // Without a Recover entry the recovery key is not consulted, so this checks
    // the ordinary case still works with an unrelated key.
    let directory = tempfile::tempdir()?;
    identity(directory.path());
    keypair(directory.path(), "other");

    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "identity-show",
            "--log",
            "id.log",
            "--recovery",
            "other.pub.sign",
        ],
    );
    assert!(result.status.success());
    Ok(())
}

#[test]
fn an_epoch_chain_is_created_and_verified() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;

    let created = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-init",
            "--output",
            "epochs.bin",
        ],
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );

    let shown = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-show",
            "--chain",
            "epochs.bin",
        ],
    );
    assert!(shown.status.success());
    assert!(String::from_utf8_lossy(&shown.stdout).contains("epochs 1"));
    Ok(())
}

#[test]
fn a_tampered_epoch_chain_is_refused() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-init",
            "--output",
            "epochs.bin",
        ],
    );

    let path = directory.path().join("epochs.bin");
    let mut bytes = fs::read(&path)?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&path, &bytes)?;

    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-show",
            "--chain",
            "epochs.bin",
        ],
    );
    assert!(!result.status.success(), "a tampered chain was accepted");
    Ok(())
}

/// Every command must still refuse to run without the acknowledgement.
#[test]
fn the_new_commands_require_experimental() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    for args in [
        vec!["identity-show", "--log", "x", "--recovery", "y"],
        vec!["epoch-show", "--chain", "x"],
        vec!["epoch-init", "--output", "x"],
    ] {
        let result = hide(directory.path(), &args);
        assert!(
            !result.status.success(),
            "{:?} ran without --experimental",
            args
        );
    }
    Ok(())
}
