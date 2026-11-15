//! "The CLI never overwrites an existing file when it writes a container, a
//! plaintext, a key or a new identity log" — the root README's claim, checked
//! rather than assumed.
//!
//! The exceptions it names are the ones that change by design: an identity log
//! on enrol, revoke and recover (`identity.rs`), an epoch store on advance and
//! erase, and a key file on `passwd` (`key_tests` in `main.rs`). What is checked
//! here is the half that must refuse: a container, a plaintext, a detached
//! signature and an exported epoch key.
//!
//! Each case writes something *different* the second time, so "unchanged" cannot
//! pass by accident.

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

fn keys(directory: &Path) {
    let result = hide(
        directory,
        &[
            "--experimental",
            "--quiet",
            "test-keygen",
            "--secret",
            "alice.test-secret",
            "--public",
            "alice.test-public",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Asserts the second run failed, said why, and left the file byte-identical.
fn refused_and_unchanged(second: &Output, path: &Path, before: &[u8], what: &str) {
    assert!(
        !second.status.success(),
        "{what} overwrote an existing file"
    );
    assert!(
        stderr(second).contains("already exists"),
        "{what} failed for another reason: {}",
        stderr(second)
    );
    assert_eq!(
        fs::read(path).expect("the file still exists"),
        before,
        "{what} modified the file it refused to overwrite"
    );
}

#[test]
fn encrypt_refuses_to_overwrite_its_output() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("first.txt"), b"first")?;
    fs::write(directory.path().join("second.txt"), b"a longer second file")?;
    let output = directory.path().join("memo.hide");

    let first = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "first.txt",
            "--recipient",
            "alice.test-public",
            "--output",
            "memo.hide",
        ],
    );
    assert!(first.status.success(), "{}", stderr(&first));
    let before = fs::read(&output)?;

    let second = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "second.txt",
            "--recipient",
            "alice.test-public",
            "--output",
            "memo.hide",
        ],
    );
    refused_and_unchanged(&second, &output, &before, "encrypt");
    Ok(())
}

#[test]
fn open_refuses_to_overwrite_its_output() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    for (plain, container) in [("first.txt", "first.hide"), ("second.txt", "second.hide")] {
        fs::write(directory.path().join(plain), plain.as_bytes())?;
        let encrypted = hide(
            directory.path(),
            &[
                "--experimental",
                "--quiet",
                "encrypt",
                plain,
                "--recipient",
                "alice.test-public",
                "--output",
                container,
            ],
        );
        assert!(encrypted.status.success(), "{}", stderr(&encrypted));
    }
    let output = directory.path().join("opened.txt");
    let first = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "open",
            "first.hide",
            "--secret",
            "alice.test-secret",
            "--output",
            "opened.txt",
        ],
    );
    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(fs::read(&output)?, b"first.txt");
    let before = fs::read(&output)?;

    let second = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "open",
            "second.hide",
            "--secret",
            "alice.test-secret",
            "--output",
            "opened.txt",
        ],
    );
    refused_and_unchanged(&second, &output, &before, "open");
    Ok(())
}

#[test]
fn sign_refuses_to_overwrite_its_signature() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("first.txt"), b"first")?;
    fs::write(directory.path().join("second.txt"), b"a longer second file")?;

    for (input, signature) in [("first.txt", "first.sig"), ("second.txt", "second.sig")] {
        let signed = hide(
            directory.path(),
            &[
                "--experimental",
                "--quiet",
                "sign",
                input,
                "--secret",
                "alice.test-secret",
                "--output",
                signature,
            ],
        );
        assert!(signed.status.success(), "{}", stderr(&signed));
    }
    let output = directory.path().join("reused.sig");
    fs::copy(directory.path().join("first.sig"), &output)?;
    let before = fs::read(&output)?;

    let second = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "sign",
            "second.txt",
            "--secret",
            "alice.test-secret",
            "--output",
            "reused.sig",
        ],
    );
    refused_and_unchanged(&second, &output, &before, "sign");
    // And the signature that is still there is the first file's.
    let verified = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "verify",
            "first.txt",
            "--signer",
            "alice.test-public.sign",
            "--signature",
            "reused.sig",
        ],
    );
    assert!(verified.status.success(), "{}", stderr(&verified));
    Ok(())
}

#[test]
fn epoch_public_refuses_to_overwrite_its_output() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    // `epoch-init` needs a terminal for the passphrase; a published history is
    // public, so the chain is built with the library, as `identity.rs` does.
    let mut chain = hide_epoch::EpochChain::new()?;
    chain.advance()?;
    fs::write(
        directory.path().join("epochs.bin"),
        hide_epoch::encode_records(chain.records())?,
    )?;
    let output = directory.path().join("epoch.pub");

    let first = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-public",
            "0",
            "--chain",
            "epochs.bin",
            "--output",
            "epoch.pub",
        ],
    );
    assert!(first.status.success(), "{}", stderr(&first));
    let before = fs::read(&output)?;
    assert_eq!(before, chain.records()[0].public_key);

    // Epoch 1's key is a different key, so a silent overwrite would be visible.
    let records = hide_epoch::decode_records(&fs::read(directory.path().join("epochs.bin"))?)?;
    assert_ne!(records[0].public_key, records[1].public_key);

    let second = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "epoch-public",
            "1",
            "--chain",
            "epochs.bin",
            "--output",
            "epoch.pub",
        ],
    );
    refused_and_unchanged(&second, &output, &before, "epoch-public");
    Ok(())
}
