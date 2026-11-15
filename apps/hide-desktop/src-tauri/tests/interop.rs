//! The desktop app and the CLI must remain one format. A change to either that
//! breaks the other is a protocol break, and this test is what catches it.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use hide_crypto::RecipientSecret;

/// Absolute, because the working directory of a test binary is not guaranteed.
fn cli() -> Option<std::path::PathBuf> {
    // Built by `cargo build -p hide-cli` in the main workspace, whose target
    // directory is three levels above this crate.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for candidate in [
        "target/debug/hide.exe",
        "target/debug/hide",
        "target/release/hide.exe",
        "target/release/hide",
    ] {
        let path = root.join(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// The CLI, or nothing when this checkout simply has not built it.
///
/// A skipped interoperability test proves nothing, so a CI run without the CLI
/// fails instead of passing quietly. The skip notice keeps its exact wording:
/// the desktop job greps the log for it and treats it as an error.
fn require_cli() -> Option<PathBuf> {
    if let Some(path) = cli() {
        return Some(path);
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "CI is set, so the interoperability tests must run, but the hide CLI has not been built"
    );
    eprintln!("skipping: the hide CLI has not been built");
    None
}

/// Runs the CLI and insists that it succeeded.
fn hide(cli: &Path, directory: &Path, args: &[&str]) -> Output {
    let output = Command::new(cli)
        .current_dir(directory)
        .args(["--experimental", "--quiet"])
        .args(args)
        .output()
        .expect("the CLI runs");
    assert!(
        output.status.success(),
        "hide {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../conformance/vectors")
}

/// Every key file written by `keygen` for these tests.
const SIGNING_KEY: &str = "ana.sign-pub";

/// The passphrase the protected-key test uses; long enough for the keyring.
const PASSPHRASE: &str = "o fraza secreta, dar lunga";

fn desktop_keygen(cli: &Path, root: &Path) {
    hide(
        cli,
        root,
        &[
            "keygen",
            "--secret",
            "ana.hide-key",
            "--public",
            "ana.hide-pub",
            "--signing-public",
            SIGNING_KEY,
            "--insecure-plaintext",
        ],
    );
}

fn path_in(root: &Path, name: &str) -> String {
    root.join(name).display().to_string()
}

/// The shared format is only shared if a file one surface writes is a file the
/// other opens, so both directions are exercised on real files, not messages.
#[test]
fn the_two_surfaces_exchange_encrypted_files_in_both_directions() {
    let Some(cli) = require_cli() else {
        return;
    };
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path();
    let payload = b"nume,suma\nAna,9000\n";

    hide_desktop_lib::generate_keys_for_tests(root.display().to_string(), "ana".into(), None)
        .expect("the desktop generates keys");
    fs::write(root.join("salarii.csv"), payload).expect("write");

    // The CLI encrypts a file; the desktop opens it.
    hide(
        &cli,
        root,
        &[
            "encrypt",
            "salarii.csv",
            "--recipient",
            "ana.hide-pub",
            "-o",
            "from-cli.hide",
        ],
    );
    let opened = hide_desktop_lib::decrypt_file_for_tests(
        path_in(root, "from-cli.hide"),
        path_in(root, "ana.hide-key"),
        None,
        path_in(root, "from-cli.csv"),
    )
    .expect("the desktop opens a container the CLI sealed");
    assert_eq!(opened.filename.as_deref(), Some("salarii.csv"));
    assert_eq!(opened.plaintext_len, payload.len() as u64);
    assert!(
        opened.signer.is_none(),
        "an unsigned container must not name a signer"
    );
    assert_eq!(fs::read(root.join("from-cli.csv")).expect("read"), payload);

    // The desktop encrypts a file; the CLI opens it.
    hide_desktop_lib::encrypt_file_for_tests(
        path_in(root, "salarii.csv"),
        vec![path_in(root, "ana.hide-pub")],
        path_in(root, "from-desktop.hide"),
    )
    .expect("the desktop encrypts");
    hide(
        &cli,
        root,
        &[
            "open",
            "from-desktop.hide",
            "--secret",
            "ana.hide-key",
            "-o",
            "from-desktop.csv",
        ],
    );
    assert_eq!(
        fs::read(root.join("from-desktop.csv")).expect("read"),
        payload
    );
}

/// A signature is either visible to anyone holding the container or readable
/// only by its recipients; both placements must survive the desktop's decrypt
/// path and must still name the key that made them.
#[test]
fn a_signed_container_names_its_signer_in_both_placements() {
    let Some(cli) = require_cli() else {
        return;
    };
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path();
    let payload = b"al doilea rand\n";

    desktop_keygen(&cli, root);
    fs::write(root.join("nota.txt"), payload).expect("write");
    let expected = hide_desktop_lib::fingerprint_for_tests(
        &fs::read(root.join(SIGNING_KEY)).expect("the signing public key"),
    );

    for (placement, flag) in [
        ("confidential", None),
        ("public", Some("--public-signature")),
    ] {
        let container = format!("signed-{placement}.hide");
        let mut args: Vec<&str> = vec![
            "encrypt",
            "nota.txt",
            "--recipient",
            "ana.hide-pub",
            "--sign",
            "ana.hide-key",
            "-o",
        ];
        args.push(&container);
        if let Some(flag) = flag {
            args.push(flag);
        }
        hide(&cli, root, &args);

        let plain = format!("opened-{placement}.txt");
        let opened = hide_desktop_lib::decrypt_file_for_tests(
            path_in(root, &container),
            path_in(root, "ana.hide-key"),
            None,
            path_in(root, &plain),
        )
        .unwrap_or_else(|error| panic!("the desktop opens the {placement} container: {error}"));
        assert_eq!(
            opened.signer.as_deref(),
            Some(expected.as_str()),
            "the {placement} signature was dropped"
        );
        assert_eq!(fs::read(root.join(&plain)).expect("read"), payload);
    }
}

/// The frozen vectors are the format's definition. Opening them through the
/// same path the window uses is the strongest thing this test can say: the
/// bytes are not ours to adjust when they disagree.
#[test]
fn the_frozen_containers_open_through_the_desktop_decrypt_path() {
    let vectors = vectors();
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path();

    // identity.hide is sealed to the key derived from a master seed, which is
    // exactly what a .hide-key file holds.
    fs::write(
        root.join("identity.hide-key"),
        fs::read(vectors.join("identity.test-seed")).expect("the identity seed"),
    )
    .expect("write");
    let opened = hide_desktop_lib::decrypt_file_for_tests(
        vectors.join("identity.hide").display().to_string(),
        path_in(root, "identity.hide-key"),
        None,
        path_in(root, "identity.out"),
    )
    .expect("identity.hide opens");
    assert!(opened.signer.is_none(), "identity.hide is not signed");
    assert_eq!(
        fs::read(root.join("identity.out")).expect("read"),
        fs::read(vectors.join("identity.txt")).expect("the expected plaintext"),
    );

    // The other positive containers are sealed to a 0.1.0 recipient key. That
    // file is the X-Wing secret itself and is not a master seed, so the only
    // key file that carries it is the protected, encryption-only one.
    let secret = RecipientSecret::from_bytes(
        &fs::read(vectors.join("recipient.test-secret")).expect("the recipient secret"),
    )
    .expect("a recipient secret");
    fs::write(
        root.join("recipient.hide-key"),
        hide_keyring::protect(&secret, PASSPHRASE).expect("protect the recipient key"),
    )
    .expect("write");

    let signer = hide_desktop_lib::fingerprint_for_tests(
        &fs::read(vectors.join("signed.test-public")).expect("the verifying key"),
    );
    let unsigned = ["hello", "empty", "grease", "grease-minor"];
    let signed = [
        "signed-public",
        "signed-confidential",
        "v1-signed",
        "v1-signed-confidential",
        "grease-signed",
    ];

    for name in unsigned.iter().chain(signed.iter()) {
        let output = format!("{name}.out");
        let opened = hide_desktop_lib::decrypt_file_for_tests(
            vectors.join(format!("{name}.hide")).display().to_string(),
            path_in(root, "recipient.hide-key"),
            Some(PASSPHRASE.into()),
            path_in(root, &output),
        )
        .unwrap_or_else(|error| panic!("{name}.hide opens: {error}"));
        assert_eq!(
            fs::read(root.join(&output)).expect("read"),
            fs::read(vectors.join(format!("{name}.txt"))).expect("the expected plaintext"),
            "{name}.hide decrypted to the wrong plaintext"
        );
        if signed.contains(name) {
            assert_eq!(
                opened.signer.as_deref(),
                Some(signer.as_str()),
                "{name}.hide must name the key that signed it"
            );
        } else {
            assert!(opened.signer.is_none(), "{name}.hide is not signed");
        }
    }
}

/// A passphrase-protected key file is the default the CLI writes and the one
/// the desktop offers, so both must read the same file the same way.
#[test]
fn a_passphrase_protected_key_file_is_read_the_same_way_by_both() {
    let Some(cli) = require_cli() else {
        return;
    };
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path();

    let created = hide_desktop_lib::generate_keys_for_tests(
        root.display().to_string(),
        "ana".into(),
        Some(PASSPHRASE.into()),
    )
    .expect("the desktop generates a protected key");
    assert!(created.protected);

    // The CLI looks at the file the desktop wrote and agrees about its shape.
    let info = Command::new(&cli)
        .current_dir(root)
        .args(["--experimental", "--quiet", "info", "ana.hide-key"])
        .output()
        .expect("cli runs");
    assert!(
        info.status.success(),
        "hide info failed: {}",
        String::from_utf8_lossy(&info.stderr)
    );
    let described = String::from_utf8_lossy(&info.stdout);
    assert!(
        described.contains("passphrase-protected"),
        "the CLI does not see what the desktop wrote: {described}"
    );

    // And a message sealed by the CLI opens, but only with the passphrase.
    let sealed = hide(
        &cli,
        root,
        &[
            "seal",
            "din linia de comanda",
            "--recipient",
            "ana.hide-pub",
        ],
    );
    let armored = String::from_utf8(sealed.stdout).expect("utf8");
    let opened = hide_desktop_lib::unseal_with_signer_for_tests(
        armored.clone(),
        path_in(root, "ana.hide-key"),
        Some(PASSPHRASE.into()),
    )
    .expect("the desktop opens it with the passphrase");
    assert_eq!(opened.text, "din linia de comanda");
    assert!(opened.signer.is_none(), "seal does not sign");

    let refused =
        hide_desktop_lib::unseal_message_for_tests(armored, path_in(root, "ana.hide-key"), None)
            .expect_err("opened a protected key without its passphrase");
    assert!(refused.contains("passphrase"), "{refused}");
}
#[test]
fn the_desktop_app_opens_what_the_cli_sealed() {
    let Some(cli) = require_cli() else {
        return;
    };
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path();

    let keygen = Command::new(&cli)
        .current_dir(root)
        .args([
            "--experimental",
            "--quiet",
            "keygen",
            "--secret",
            "a.key",
            "--public",
            "a.pub",
            "--insecure-plaintext",
        ])
        .output()
        .expect("cli runs");
    assert!(
        keygen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    let sealed = Command::new(&cli)
        .current_dir(root)
        .args([
            "--experimental",
            "--quiet",
            "seal",
            "from the command line",
            "--recipient",
            "a.pub",
        ])
        .output()
        .expect("cli runs");
    assert!(
        sealed.status.success(),
        "seal failed: {}",
        String::from_utf8_lossy(&sealed.stderr)
    );
    let armored = String::from_utf8(sealed.stdout).expect("utf8");

    let opened = hide_desktop_lib::unseal_message_for_tests(
        armored,
        root.join("a.key").display().to_string(),
        None,
    )
    .expect("the desktop app opens a CLI message");
    assert_eq!(opened, "from the command line");
}

#[test]
fn the_cli_opens_what_the_desktop_app_sealed() {
    let Some(cli) = require_cli() else {
        return;
    };
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path();

    // Keys generated by the desktop command this time.
    hide_desktop_lib::generate_keys_for_tests(root.display().to_string(), "ana".into(), None)
        .expect("the desktop command generates keys");
    let armored = hide_desktop_lib::seal_message_for_tests(
        "from the desktop application".into(),
        vec![root.join("ana.hide-pub").display().to_string()],
    )
    .expect("seal");
    std::fs::write(root.join("message.txt"), &armored).expect("write");

    let opened = Command::new(&cli)
        .current_dir(root)
        .args([
            "--experimental",
            "--quiet",
            "unseal",
            "message.txt",
            "--secret",
            "ana.hide-key",
        ])
        .output()
        .expect("cli runs");
    assert!(
        opened.status.success(),
        "{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    assert_eq!(
        String::from_utf8(opened.stdout).expect("utf8").trim_end(),
        "from the desktop application"
    );
}
