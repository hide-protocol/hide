//! The staged-plaintext sweep, as a process.
//!
//! Every publish path writes into a same-directory temporary file first, so a
//! process that is killed — a SIGINT, or `TerminateProcess` — leaves partial,
//! unauthenticated plaintext behind: no destructor runs, and `tempfile`'s named
//! files are not delete-on-close on Windows. Each command therefore sweeps the
//! directory it is about to write to before it starts.

use std::{
    error::Error,
    fs,
    path::Path,
    process::{Command, Output},
    time::{Duration, SystemTime},
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

#[test]
fn staged_plaintext_from_an_interrupted_run_is_removed_at_start_up() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("memo.txt"), b"memo")?;

    let abandoned = directory.path().join(".hide-staging-abandoned");
    fs::write(&abandoned, b"partial, unauthenticated plaintext")?;
    // A run could still be writing this one, so it must survive.
    let in_flight = directory.path().join(".hide-staging-in-flight");
    fs::write(&in_flight, b"a run may still be writing this")?;
    // The append-only-log staging name is a near miss on purpose: the prefix is
    // matched exactly, so this one is none of the sweep's business.
    let other_prefix = directory.path().join(".hide-log-keep");
    fs::write(&other_prefix, b"an append-only log's staging name")?;
    fs::write(directory.path().join("keep.txt"), b"a user's own file")?;

    // Age one file past the point where no run can still be working on it.
    let two_hours_ago = SystemTime::now()
        .checked_sub(Duration::from_secs(2 * 60 * 60))
        .expect("a representable time");
    fs::File::options()
        .write(true)
        .open(&abandoned)?
        .set_modified(two_hours_ago)?;

    let encrypted = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "memo.txt",
            "--recipient",
            "alice.test-public",
            "--output",
            "memo.hide",
        ],
    );
    assert!(
        encrypted.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypted.stderr)
    );
    assert!(
        !abandoned.exists(),
        "staged plaintext from an interrupted run was left on disk"
    );
    assert!(
        String::from_utf8_lossy(&encrypted.stderr).contains("interrupted run"),
        "the removal was not reported: {}",
        String::from_utf8_lossy(&encrypted.stderr)
    );
    assert!(
        in_flight.exists(),
        "a staging file a run may still be writing was removed"
    );
    assert!(
        other_prefix.exists(),
        "a file without the exact staging prefix was removed"
    );
    assert!(directory.path().join("keep.txt").exists());
    assert!(directory.path().join("memo.hide").exists());
    Ok(())
}

/// The sweep is limited to the directory this command writes into, so a stale
/// file somewhere else is left for the command that owns that directory.
#[test]
fn a_stale_staging_file_elsewhere_is_left_alone() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("memo.txt"), b"memo")?;
    fs::create_dir(directory.path().join("other"))?;
    let elsewhere = directory.path().join("other/.hide-staging-abandoned");
    fs::write(&elsewhere, b"another directory's problem")?;
    let two_hours_ago = SystemTime::now()
        .checked_sub(Duration::from_secs(2 * 60 * 60))
        .expect("a representable time");
    fs::File::options()
        .write(true)
        .open(&elsewhere)?
        .set_modified(two_hours_ago)?;

    let encrypted = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "encrypt",
            "memo.txt",
            "--recipient",
            "alice.test-public",
            "--output",
            "memo.hide",
        ],
    );
    assert!(encrypted.status.success());
    assert!(
        elsewhere.exists(),
        "a directory the command does not write to was swept"
    );
    Ok(())
}
