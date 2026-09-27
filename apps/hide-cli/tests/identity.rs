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

/// `epoch-init` seals secrets and so needs a terminal for the passphrase; a
/// published history is public, so tests that only read one build it with the
/// library. The sealed-store flow itself is covered by `epoch_tests` in main.rs.
fn published_chain(directory: &Path, epochs: usize) -> Result<(), Box<dyn Error>> {
    let mut chain = hide_epoch::EpochChain::new()?;
    for _ in 1..epochs {
        chain.advance()?;
    }
    fs::write(
        directory.join("epochs.bin"),
        hide_epoch::encode_records(chain.records())?,
    )?;
    Ok(())
}

#[test]
fn an_epoch_chain_is_verified_and_its_keys_exported() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    published_chain(directory.path(), 2)?;

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
    assert!(String::from_utf8_lossy(&shown.stdout).contains("epochs 2"));

    let exported = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-public",
            "--chain",
            "epochs.bin",
            "--output",
            "current.pub",
        ],
    );
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let records = hide_epoch::decode_records(&fs::read(directory.path().join("epochs.bin"))?)?;
    assert_eq!(
        fs::read(directory.path().join("current.pub"))?,
        records[1].public_key,
        "the default is the current epoch"
    );

    // A sender can encrypt to the exported key with the ordinary command.
    fs::write(directory.path().join("memo"), b"hello")?;
    let encrypted = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "memo",
            "--recipient",
            "current.pub",
            "--output",
            "memo.hide",
        ],
    );
    assert!(encrypted.status.success());

    let unknown = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-public",
            "7",
            "--chain",
            "epochs.bin",
            "--output",
            "seven.pub",
        ],
    );
    assert!(!unknown.status.success());
    assert!(!directory.path().join("seven.pub").exists());
    Ok(())
}

/// Every epoch command that touches secrets must refuse a piped passphrase,
/// and must do so without leaving a history that names an unsaved key.
#[test]
fn epoch_commands_refuse_a_passphrase_from_a_pipe() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let init = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-init",
            "--output",
            "epochs.bin",
            "--store",
            "epochs.store",
        ],
    );
    assert!(!init.status.success());
    assert!(String::from_utf8_lossy(&init.stderr).contains("not a terminal"));
    assert!(!directory.path().join("epochs.bin").exists());
    assert!(!directory.path().join("epochs.store").exists());

    published_chain(directory.path(), 2)?;
    fs::write(directory.path().join("epochs.store"), b"HIDE-EPK")?;
    fs::write(directory.path().join("memo.hide"), b"x")?;
    for args in [
        vec![
            "epoch-advance",
            "--chain",
            "epochs.bin",
            "--store",
            "epochs.store",
        ],
        vec![
            "epoch-erase",
            "0",
            "--chain",
            "epochs.bin",
            "--store",
            "epochs.store",
        ],
        vec![
            "open",
            "memo.hide",
            "--epoch-store",
            "epochs.store",
            "--output",
            "memo.out",
        ],
    ] {
        let mut full = vec!["--experimental", "--quiet"];
        full.extend(&args);
        let result = hide(directory.path(), &full);
        assert!(!result.status.success(), "{args:?} succeeded");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("not a terminal"),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert!(!directory.path().join("memo.out").exists());
    Ok(())
}

#[test]
fn open_takes_exactly_one_key_source() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    for args in [
        vec!["open", "memo.hide", "--output", "memo.out"],
        vec![
            "open",
            "memo.hide",
            "--secret",
            "a.sec",
            "--epoch-store",
            "epochs.store",
            "--output",
            "memo.out",
        ],
    ] {
        let mut full = vec!["--experimental", "--quiet"];
        full.extend(&args);
        assert!(!hide(directory.path(), &full).status.success(), "{args:?}");
    }
    Ok(())
}

#[test]
fn a_tampered_epoch_chain_is_refused() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    published_chain(directory.path(), 1)?;

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
        vec!["epoch-init", "--output", "x", "--store", "y"],
        vec!["epoch-advance", "--chain", "x", "--store", "y"],
        vec!["epoch-erase", "0", "--chain", "x", "--store", "y"],
        vec!["epoch-public", "--chain", "x", "--output", "y"],
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
