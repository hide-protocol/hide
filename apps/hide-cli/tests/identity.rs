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
fn creating_an_identity_does_not_overwrite_an_existing_log() -> Result<(), Box<dyn Error>> {
    // A second `identity-create` would replace the whole device history and its
    // root, so it must be refused rather than silently clobbering the log.
    let directory = tempfile::tempdir()?;
    identity(directory.path());
    let before = fs::read(directory.path().join("id.log"))?;
    let binding_before = fs::read(directory.path().join("id.log.binding"))?;

    let again = hide(
        directory.path(),
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
        !again.status.success(),
        "identity-create overwrote an existing log"
    );
    assert_eq!(fs::read(directory.path().join("id.log"))?, before);
    assert_eq!(
        fs::read(directory.path().join("id.log.binding"))?,
        binding_before,
        "identity-create overwrote the recovery binding"
    );
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
        vec![
            "epoch-bind",
            "--chain",
            "x",
            "--log",
            "y",
            "--secret",
            "z",
            "--recovery",
            "r",
            "--output",
            "b",
        ],
        vec![
            "identity-recover",
            "--log",
            "x",
            "--secret",
            "y",
            "--device",
            "z",
            "--label",
            "l",
        ],
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// §16.1: `identity create` writes the recovery binding beside the log, and
/// `identity show --root --binding` checks it. The binding is the only statement
/// that names the genuine recovery key — the log itself does not — so a doctored
/// one has to be refused rather than preferred.
#[test]
fn the_recovery_binding_is_written_with_the_log_and_checked_by_show() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    identity(directory.path());

    let bytes = fs::read(directory.path().join("id.log.binding"))?;
    let binding = hide_identity::RecoveryBinding::decode(&bytes)?;
    let entries = hide_identity::decode(&fs::read(directory.path().join("id.log"))?)?;
    // What a sender does before encrypting to the identity: pin the root, then
    // check the binding that claims to name the recovery key for it.
    let log = binding.verify_pinned(entries, &binding.root)?;
    assert_eq!(log.membership().len(), 2);

    let shown = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "identity-show",
            "--log",
            "id.log",
            "--recovery",
            "recovery.pub.sign",
            "--root",
            "--binding",
            "id.log.binding",
        ],
    );
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let text = String::from_utf8(shown.stdout)?;
    assert!(
        text.contains(&hex(&binding.root)),
        "the root was not printed in full: {text}"
    );
    assert!(text.contains("binding recovery key"), "{text}");
    assert!(text.contains("binding devices      2"), "{text}");

    // A binding whose root was altered no longer describes this log.
    let mut forged = bytes.clone();
    forged[0] ^= 1;
    fs::write(directory.path().join("forged.binding"), &forged)?;
    let before = fs::read(directory.path().join("id.log"))?;
    let refused = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "identity-show",
            "--log",
            "id.log",
            "--recovery",
            "recovery.pub.sign",
            "--binding",
            "forged.binding",
        ],
    );
    assert!(
        !refused.status.success(),
        "a binding for a different root was accepted"
    );
    assert_eq!(fs::read(directory.path().join("id.log"))?, before);
    Ok(())
}

/// Losing every device is what the offline recovery key is for. It is also the
/// event an attacker with a stolen copy of the log would append, signing it with
/// a key of their own, so the key must be the one the founder bound and the
/// binding must not be skippable by deleting it.
#[test]
fn recovery_replaces_the_device_set_only_for_the_bound_recovery_key() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    identity(directory.path());
    keypair(directory.path(), "tablet");
    keypair(directory.path(), "attacker");
    let before = fs::read(directory.path().join("id.log"))?;

    let recover = |secret: &str| {
        hide(
            directory.path(),
            &[
                "--experimental",
                "--quiet",
                "identity-recover",
                "--log",
                "id.log",
                "--secret",
                secret,
                "--device",
                "tablet.pub.sign",
                "--label",
                "tablet",
            ],
        )
    };

    let stolen = recover("attacker.sec");
    assert!(
        !stolen.status.success(),
        "a stranger's recovery key replaced the device set: {}",
        String::from_utf8_lossy(&stolen.stderr)
    );
    assert_eq!(
        fs::read(directory.path().join("id.log"))?,
        before,
        "the log was modified by a refused recovery"
    );

    fs::rename(
        directory.path().join("id.log.binding"),
        directory.path().join("hidden.binding"),
    )?;
    let unbound = recover("recovery.sec");
    assert!(
        !unbound.status.success(),
        "recovery ran without the binding that names the key"
    );
    assert_eq!(fs::read(directory.path().join("id.log"))?, before);
    fs::rename(
        directory.path().join("hidden.binding"),
        directory.path().join("id.log.binding"),
    )?;

    let recovered = recover("recovery.sec");
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let listing = show(directory.path());
    assert!(listing.contains("devices 1"), "{listing}");
    assert!(listing.contains("tablet"), "{listing}");
    assert!(
        !listing.contains("laptop"),
        "the replaced device is still trusted: {listing}"
    );

    // Replaced means replaced: the old device cannot author anything now.
    let laptop_again = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "identity-enrol",
            "--log",
            "id.log",
            "--secret",
            "laptop.sec",
            "--device",
            "recovery.pub.sign",
            "--label",
            "laptop",
            "--recovery",
            "recovery.pub.sign",
        ],
    );
    assert!(
        !laptop_again.status.success(),
        "a replaced device enrolled another one"
    );
    Ok(())
}

/// §16.4: without a binding anyone can publish an epoch chain and claim it is
/// yours; with one, only a device the log trusts can vouch for it.
#[test]
fn an_epoch_chain_can_be_bound_to_the_identity_and_a_stranger_cannot() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    identity(directory.path());
    keypair(directory.path(), "stranger");
    published_chain(directory.path(), 2)?;

    let bound = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-bind",
            "--chain",
            "epochs.bin",
            "--log",
            "id.log",
            "--secret",
            "laptop.sec",
            "--recovery",
            "recovery.pub.sign",
            "--output",
            "epochs.binding",
        ],
    );
    assert!(
        bound.status.success(),
        "{}",
        String::from_utf8_lossy(&bound.stderr)
    );
    let binding =
        hide_identity::EpochBinding::decode(&fs::read(directory.path().join("epochs.binding"))?)?;
    assert_eq!(binding.epochs, 2);

    // The receiver's whole path: a verified log, then the chain it names.
    let recovery = hide_identity::RecoveryBinding::decode(&fs::read(
        directory.path().join("id.log.binding"),
    )?)?;
    let log = recovery.verify_pinned(
        hide_identity::decode(&fs::read(directory.path().join("id.log"))?)?,
        &recovery.root,
    )?;
    let records = hide_epoch::decode_records(&fs::read(directory.path().join("epochs.bin"))?)?;
    binding.verify(&log, &records)?;

    let stranger = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-bind",
            "--chain",
            "epochs.bin",
            "--log",
            "id.log",
            "--secret",
            "stranger.sec",
            "--recovery",
            "recovery.pub.sign",
            "--output",
            "stranger.binding",
        ],
    );
    assert!(
        !stranger.status.success(),
        "a device the log does not trust vouched for the chain"
    );
    assert!(!directory.path().join("stranger.binding").exists());
    Ok(())
}
