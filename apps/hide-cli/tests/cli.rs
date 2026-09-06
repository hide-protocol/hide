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
fn encrypt_and_open_in_separate_processes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    let payload = vec![0x5a; 131_079];
    fs::write(directory.path().join("report.txt"), &payload)?;
    let encrypted = hide(
        directory.path(),
        &[
            "--experimental",
            "encrypt",
            "report.txt",
            "--recipient",
            "alice.test-public",
            "--output",
            "report.hide",
        ],
    );
    assert!(
        encrypted.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypted.stderr)
    );
    let opened = hide(
        directory.path(),
        &[
            "--experimental",
            "open",
            "report.hide",
            "--secret",
            "alice.test-secret",
            "--output",
            "result.txt",
        ],
    );
    assert!(
        opened.status.success(),
        "{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    assert_eq!(fs::read(directory.path().join("result.txt"))?, payload);
    assert!(opened.stdout.is_empty());
    Ok(())
}

#[test]
fn corrupt_final_does_not_publish_plaintext_or_leave_staging() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("report.txt"), vec![7; 131_079])?;
    assert!(
        hide(
            directory.path(),
            &[
                "--experimental",
                "encrypt",
                "report.txt",
                "--recipient",
                "alice.test-public",
                "--output",
                "report.hide"
            ]
        )
        .status
        .success()
    );
    let path = directory.path().join("report.hide");
    let mut ciphertext = fs::read(&path)?;
    ciphertext.pop();
    fs::write(&path, ciphertext)?;
    let opened = hide(
        directory.path(),
        &[
            "--experimental",
            "open",
            "report.hide",
            "--secret",
            "alice.test-secret",
            "--output",
            "result.txt",
        ],
    );
    assert!(!opened.status.success());
    assert!(!directory.path().join("result.txt").exists());
    assert!(opened.stdout.is_empty());
    for entry in fs::read_dir(directory.path())? {
        assert!(
            !entry?
                .file_name()
                .to_string_lossy()
                .starts_with(".hide-staging-")
        );
    }
    Ok(())
}

#[test]
fn refuses_implicit_experiment_and_overwrite() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    assert!(
        !hide(
            directory.path(),
            &["test-keygen", "--secret", "secret", "--public", "public"]
        )
        .status
        .success()
    );
    assert!(!directory.path().join("secret").exists());
    keys(directory.path());
    let before = fs::read(directory.path().join("alice.test-secret"))?;
    assert!(
        !hide(
            directory.path(),
            &[
                "--experimental",
                "test-keygen",
                "--secret",
                "alice.test-secret",
                "--public",
                "alice.test-public"
            ]
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(directory.path().join("alice.test-secret"))?,
        before
    );
    Ok(())
}

#[test]
fn rejects_malformed_key_files_and_missing_inputs() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("report.txt"), b"data")?;
    fs::write(directory.path().join("short.test-public"), [0; 1215])?;
    fs::write(directory.path().join("long.test-public"), [0; 1217])?;
    fs::write(directory.path().join("zero.test-public"), [0; 1216])?;
    fs::write(directory.path().join("short.test-secret"), [0; 31])?;
    for arguments in [
        vec![
            "encrypt",
            "report.txt",
            "--recipient",
            "short.test-public",
            "--output",
            "a.hide",
        ],
        vec![
            "encrypt",
            "report.txt",
            "--recipient",
            "long.test-public",
            "--output",
            "b.hide",
        ],
        vec![
            "encrypt",
            "report.txt",
            "--recipient",
            "zero.test-public",
            "--output",
            "c.hide",
        ],
        vec![
            "encrypt",
            "report.txt",
            "--recipient",
            "missing.test-public",
            "--output",
            "d.hide",
        ],
        vec![
            "encrypt",
            "absent.txt",
            "--recipient",
            "alice.test-public",
            "--output",
            "e.hide",
        ],
        vec![
            "open",
            "report.txt",
            "--secret",
            "alice.test-secret",
            "--output",
            "f.txt",
        ],
        vec![
            "open",
            "report.txt",
            "--secret",
            "short.test-secret",
            "--output",
            "g.txt",
        ],
    ] {
        let result = hide(
            directory.path(),
            &[vec!["--experimental"], arguments.clone()].concat(),
        );
        assert!(!result.status.success(), "accepted {arguments:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("hide:"),
            "no diagnostic for {arguments:?}"
        );
    }
    for leftover in [
        "a.hide", "b.hide", "c.hide", "d.hide", "e.hide", "f.txt", "g.txt",
    ] {
        assert!(
            !directory.path().join(leftover).exists(),
            "{leftover} was created"
        );
    }
    Ok(())
}

#[test]
fn handles_empty_file_and_exact_chunk_multiples() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    for (name, size) in [
        ("empty", 0),
        ("one", 1),
        ("exact", 65_536),
        ("double", 131_072),
    ] {
        let source = format!("{name}.bin");
        fs::write(directory.path().join(&source), vec![0x3c; size])?;
        let sealed = format!("{name}.hide");
        let opened = format!("{name}.out");
        assert!(
            hide(
                directory.path(),
                &[
                    "--experimental",
                    "encrypt",
                    &source,
                    "--recipient",
                    "alice.test-public",
                    "--output",
                    &sealed
                ]
            )
            .status
            .success()
        );
        assert!(
            hide(
                directory.path(),
                &[
                    "--experimental",
                    "open",
                    &sealed,
                    "--secret",
                    "alice.test-secret",
                    "--output",
                    &opened
                ]
            )
            .status
            .success()
        );
        assert_eq!(fs::read(directory.path().join(&opened))?, vec![0x3c; size]);
    }
    Ok(())
}

#[test]
fn decrypted_filename_never_selects_the_output_path() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("payload.txt"), b"data")?;
    assert!(
        hide(
            directory.path(),
            &[
                "--experimental",
                "encrypt",
                "payload.txt",
                "--recipient",
                "alice.test-public",
                "--output",
                "payload.hide"
            ]
        )
        .status
        .success()
    );
    assert!(
        hide(
            directory.path(),
            &[
                "--experimental",
                "open",
                "payload.hide",
                "--secret",
                "alice.test-secret",
                "--output",
                "chosen.txt"
            ]
        )
        .status
        .success()
    );
    assert!(directory.path().join("chosen.txt").exists());
    assert_eq!(fs::read(directory.path().join("chosen.txt"))?, b"data");
    Ok(())
}

#[test]
fn seals_and_unseals_a_text_message_through_the_armored_form() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    let message = "transfer 100 RON to Ana\nsecond line";

    let sealed = hide(
        directory.path(),
        &[
            "--experimental",
            "seal",
            message,
            "--recipient",
            "alice.test-public",
        ],
    );
    assert!(sealed.status.success());
    let armored = String::from_utf8(sealed.stdout)?;
    assert!(armored.starts_with("----- BEGIN HIDE MESSAGE -----"));
    assert!(!armored.contains("transfer"), "plaintext leaked into armor");
    fs::write(directory.path().join("note.txt"), &armored)?;

    let opened = hide(
        directory.path(),
        &[
            "--experimental",
            "unseal",
            "note.txt",
            "--secret",
            "alice.test-secret",
        ],
    );
    assert!(opened.status.success());
    assert_eq!(String::from_utf8(opened.stdout)?.trim_end(), message);
    Ok(())
}

#[test]
fn a_tampered_message_body_is_refused() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    let sealed = hide(
        directory.path(),
        &[
            "--experimental",
            "seal",
            "confidential",
            "--recipient",
            "alice.test-public",
        ],
    );
    let armored = String::from_utf8(sealed.stdout)?;
    let lines: Vec<&str> = armored.lines().collect();
    let mut body = lines[1].to_owned();
    // Flip one base64 character in the ciphertext.
    let flipped = if body.starts_with('A') { 'B' } else { 'A' };
    body.replace_range(0..1, &flipped.to_string());
    let tampered = format!("{}\n{}\n{}\n", lines[0], body, lines[lines.len() - 1]);
    fs::write(directory.path().join("bad.txt"), tampered)?;

    let opened = hide(
        directory.path(),
        &[
            "--experimental",
            "unseal",
            "bad.txt",
            "--secret",
            "alice.test-secret",
        ],
    );
    assert!(!opened.status.success(), "tampered message was accepted");
    assert!(opened.stdout.is_empty(), "published unauthenticated output");
    Ok(())
}

#[test]
fn info_reports_kinds_without_revealing_contents() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    fs::write(directory.path().join("salary.txt"), b"top secret")?;
    let encrypted = hide(
        directory.path(),
        &[
            "--experimental",
            "encrypt",
            "salary.txt",
            "--recipient",
            "alice.test-public",
            "--output",
            "salary.hide",
        ],
    );
    assert!(encrypted.status.success());

    let public = hide(
        directory.path(),
        &["--experimental", "info", "alice.test-public"],
    );
    assert!(String::from_utf8(public.stdout)?.contains("public key"));

    let secret = hide(
        directory.path(),
        &["--experimental", "info", "alice.test-secret"],
    );
    assert!(String::from_utf8(secret.stdout)?.contains("UNENCRYPTED"));

    let container = hide(directory.path(), &["--experimental", "info", "salary.hide"]);
    let text = String::from_utf8(container.stdout)?;
    assert!(text.contains("HIDE container"));
    assert!(!text.contains("salary.txt"), "info revealed the filename");
    Ok(())
}

#[test]
fn armored_public_keys_are_accepted_as_recipients() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    keys(directory.path());
    let shared = hide(
        directory.path(),
        &["--experimental", "share", "alice.test-public"],
    );
    assert!(shared.status.success());
    let armored = String::from_utf8(shared.stdout)?;
    assert!(armored.starts_with("hide-public-key:"));
    fs::write(directory.path().join("alice.pub.txt"), &armored)?;

    fs::write(directory.path().join("memo.txt"), b"hello")?;
    let encrypted = hide(
        directory.path(),
        &[
            "--experimental",
            "encrypt",
            "memo.txt",
            "--recipient",
            "alice.pub.txt",
            "--output",
            "memo.hide",
        ],
    );
    assert!(
        encrypted.status.success(),
        "{}",
        String::from_utf8_lossy(&encrypted.stderr)
    );

    let opened = hide(
        directory.path(),
        &[
            "--experimental",
            "open",
            "memo.hide",
            "--secret",
            "alice.test-secret",
            "--output",
            "memo.out",
        ],
    );
    assert!(opened.status.success());
    assert_eq!(fs::read(directory.path().join("memo.out"))?, b"hello");
    Ok(())
}

#[test]
fn refuses_to_read_a_passphrase_from_a_pipe() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "keygen",
            "--secret",
            "bob.key",
            "--public",
            "bob.pub",
        ],
    );
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("not a terminal"),
        "expected a refusal to read a passphrase non-interactively"
    );
    assert!(
        !directory.path().join("bob.key").exists(),
        "left a partial key"
    );
    Ok(())
}
