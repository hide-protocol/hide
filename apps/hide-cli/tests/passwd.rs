//! `passwd` as a process.
//!
//! The command reads passphrases only from a terminal, deliberately, so a test
//! cannot drive it end to end: a test that could would have to feed the
//! passphrase through a pipe, which is the thing it refuses. What is testable
//! here is the refusal and its side effects — with no terminal the command fails
//! and leaves the key byte-identical, which is the part a bug would damage.
//!
//! The property it cannot exercise, that re-sealing keeps the key a file stands
//! for (an unprotected master seed, a protected identity key, and a legacy v1
//! file) is covered where the passphrase can be passed directly: `key_tests` in
//! `main.rs`.

use std::{
    error::Error,
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};

fn hide(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hide"))
        .current_dir(directory)
        .args(args)
        // A pipe, not a terminal: what a script or a CI job gives it.
        .stdin(Stdio::piped())
        .output()
        .expect("test binary runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn passwd_refuses_an_unprotected_key_without_a_terminal_and_changes_nothing()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let keygen = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "keygen",
            "--insecure-plaintext",
            "--secret",
            "me.sec",
            "--public",
            "me.pub",
        ],
    );
    assert!(keygen.status.success(), "{}", stderr(&keygen));

    let before = fs::read(directory.path().join("me.sec"))?;
    let result = hide(
        directory.path(),
        &["--experimental", "--quiet", "passwd", "--secret", "me.sec"],
    );
    assert!(
        !result.status.success(),
        "passwd ran without a terminal: {}",
        stderr(&result)
    );
    assert!(
        stderr(&result).contains("not a terminal"),
        "unexpected error: {}",
        stderr(&result)
    );
    assert_eq!(
        fs::read(directory.path().join("me.sec"))?,
        before,
        "the key file changed even though the command failed"
    );
    Ok(())
}

/// A protected key file, which is the shape that would otherwise be rewritten in
/// place. It is only *shaped* like one: a genuinely sealed key cannot be produced
/// without a terminal either, and `inspect` decides on the magic, which is the
/// branch this is here to cover.
#[test]
fn passwd_refuses_a_protected_key_without_a_terminal_and_changes_nothing()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let sealed = directory.path().join("sealed.sec");
    let mut bytes = b"HIDE-KEY".to_vec();
    bytes.push(2);
    bytes.extend_from_slice(&[0x11; 88]);
    fs::write(&sealed, &bytes)?;

    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "passwd",
            "--secret",
            "sealed.sec",
        ],
    );
    assert!(
        !result.status.success(),
        "passwd ran without a terminal: {}",
        stderr(&result)
    );
    assert!(
        stderr(&result).contains("not a terminal"),
        "unexpected error: {}",
        stderr(&result)
    );
    assert_eq!(
        fs::read(&sealed)?,
        bytes,
        "a protected key file was rewritten by a failed passwd"
    );
    Ok(())
}
