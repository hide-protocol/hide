//! The ssh-agent command, exercised as a process. The point of these tests is
//! the fail-closed edges: an agent that cannot ask for confirmation must not
//! start, and on Windows an unconfirmed agent is not offered at all.

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
        // A pipe, not a terminal: the situation a socket peer could arrange.
        .stdin(Stdio::piped())
        .output()
        .expect("test binary runs")
}

fn keypair(directory: &Path) {
    let result = hide(
        directory,
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
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn an_agent_that_cannot_ask_refuses_to_start() {
    let directory = tempfile::tempdir().expect("tempdir");
    keypair(directory.path());
    let endpoint = if cfg!(windows) {
        r"\\.\pipe\hide-agent-test-no-tty".to_string()
    } else {
        directory
            .path()
            .join("sock/agent.sock")
            .display()
            .to_string()
    };

    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "agent",
            "--secret",
            "me.sec",
            "--endpoint",
            &endpoint,
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "agent started: {stderr}");
    assert!(
        stderr.contains("cannot start the agent") && stderr.contains("not a terminal"),
        "unexpected error: {stderr}"
    );
    // It must have refused before listening, not after.
    #[cfg(unix)]
    assert!(!directory.path().join("sock").exists());
}

#[cfg(windows)]
#[test]
fn no_confirm_is_refused_on_windows() {
    let directory = tempfile::tempdir().expect("tempdir");
    keypair(directory.path());
    let result = hide(
        directory.path(),
        &[
            "--experimental",
            "agent",
            "--secret",
            "me.sec",
            "--endpoint",
            r"\\.\pipe\hide-agent-test-no-confirm",
            "--no-confirm",
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "agent started: {stderr}");
    assert!(
        stderr.contains("--no-confirm is not available on Windows"),
        "unexpected error: {stderr}"
    );
}

/// The Unix socket is created inside a directory that is private from birth.
#[cfg(unix)]
#[test]
fn the_socket_lives_in_a_private_directory() {
    use std::{
        io::Read,
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };

    let directory = tempfile::tempdir().expect("tempdir");
    keypair(directory.path());
    let socket_dir = directory.path().join("private");
    let socket = socket_dir.join("agent.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hide"))
        .current_dir(directory.path())
        .args([
            "--experimental",
            "agent",
            "--secret",
            "me.sec",
            "--endpoint",
            &socket.display().to_string(),
            "--no-confirm",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("agent spawns");

    // The agent announces its endpoint on stderr just before it binds, so a
    // few short polls are enough; the total wait is bounded well under a second.
    let deadline = Instant::now() + Duration::from_millis(900);
    while !socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let bound = socket.exists();
    let dir_mode = std::fs::metadata(&socket_dir).map(|m| m.permissions().mode());
    let sock_mode = std::fs::metadata(&socket).map(|m| m.permissions().mode());
    let _ = child.kill();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let _ = child.wait();

    assert!(bound, "socket never appeared: {stderr}");
    assert_eq!(dir_mode.expect("dir") & 0o777, 0o700, "{stderr}");
    assert_eq!(sock_mode.expect("sock") & 0o777, 0o600, "{stderr}");
}

/// The 32-byte Ed25519 public key the agent would advertise for a raw identity
/// key file, derived here rather than taken from the CLI, so the comparison is
/// not the CLI against itself.
fn advertised_public_key(directory: &Path) -> [u8; 32] {
    let seed: [u8; 32] = fs::read(directory.join("me.sec"))
        .expect("the key file")
        .try_into()
        .expect("a raw identity key is 32 bytes");
    let identity = hide_keyring::Identity::from_seed(zeroize::Zeroizing::new(seed));
    let signing =
        hide_sign::SigningIdentity::from_bytes(&*identity.signing_seed()).expect("a signing key");
    *hide_cli::agent::Agent::new(&signing, "unused".to_string()).public()
}

/// `ssh-key` prints the one line a user pastes into `authorized_keys` or GitHub.
/// It must be the blob the agent advertises, because that is the key a server
/// will end up checking, and `--comment` must change nothing but the comment.
#[test]
fn ssh_key_prints_the_authorized_keys_line_for_the_identity() -> Result<(), Box<dyn Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let directory = tempfile::tempdir()?;
    keypair(directory.path());
    let public = advertised_public_key(directory.path());

    let printed = hide(
        directory.path(),
        &["--experimental", "--quiet", "ssh-key", "--secret", "me.sec"],
    );
    assert!(
        printed.status.success(),
        "{}",
        String::from_utf8_lossy(&printed.stderr)
    );
    let line = String::from_utf8(printed.stdout)?;
    assert_eq!(line.lines().count(), 1, "{line}");
    let (key_type, rest) = line
        .trim_end()
        .split_once(' ')
        .ok_or("the printed line has no key type")?;
    assert_eq!(key_type, "ssh-ed25519");
    let (blob, comment) = rest
        .split_once(' ')
        .ok_or("the printed line has no comment")?;
    assert_eq!(
        comment, "hide:me.sec",
        "the default comment names the key file"
    );
    assert_eq!(
        STANDARD.decode(blob)?,
        hide_cli::agent::public_key_blob(&public),
        "the printed key is not the one the agent would offer"
    );
    let stderr = String::from_utf8_lossy(&printed.stderr);
    assert!(
        stderr.contains(&hide_cli::agent::fingerprint(&public)),
        "the fingerprint was not reported: {stderr}"
    );

    let commented = hide(
        directory.path(),
        &[
            "--experimental",
            "--quiet",
            "ssh-key",
            "--secret",
            "me.sec",
            "--comment",
            "dragos@laptop",
        ],
    );
    assert!(commented.status.success());
    let commented = String::from_utf8(commented.stdout)?;
    assert!(
        commented.trim_end().ends_with(" dragos@laptop"),
        "{commented}"
    );
    let (_, rest) = commented.trim_end().split_once(' ').ok_or("no key type")?;
    let (commented_blob, _) = rest.split_once(' ').ok_or("no comment")?;
    assert_eq!(
        commented_blob, blob,
        "the comment must be the only difference between the two lines"
    );
    Ok(())
}

/// The `[lib]` target exists so a fuzz target — which lives in `fuzz/`, a
/// separate workspace that cannot link a `[[bin]]` — can reach the agent's
/// request decoder. This calls it from *outside* the crate, through exactly the
/// public path such a target would use, and asserts it answers rather than
/// panicking on inputs a socket can carry.
#[test]
fn the_request_decoder_is_reachable_from_a_foreign_crate() {
    let signing = hide_sign::SigningIdentity::from_bytes(&[7u8; 32]).expect("a valid seed");
    let agent = hide_cli::agent::Agent::new(&signing, "reachability".to_string());

    // Length-prefixed strings, the way RFC 4251 carries them.
    fn string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut identities = vec![11];
    string(&mut identities, b"an unused payload");
    let mut sign_request = vec![13];
    string(
        &mut sign_request,
        &hide_cli::agent::public_key_blob(agent.public()),
    );
    string(&mut sign_request, b"an SSH userauth payload");
    sign_request.extend_from_slice(&0u32.to_be_bytes());

    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0],
        vec![11],
        vec![13],
        vec![13, 0, 0, 0],
        vec![13, 0xff, 0xff, 0xff, 0xff],
        vec![255],
        identities.clone(),
        sign_request.clone(),
    ];
    // Every truncation of both honest requests, which is the shape a client that
    // dies mid-write, or a hostile peer, actually produces.
    for request in [&identities, &sign_request] {
        for length in 0..request.len() {
            cases.push(request[..length].to_vec());
        }
    }

    for case in &cases {
        let response = agent.respond(case, &mut hide_cli::agent::ApproveEverything);
        assert!(
            !response.is_empty(),
            "an empty response is not an answer: {case:02x?}"
        );
        // Anything unrecognised, malformed or refused is the one-byte FAILURE.
        if response.len() > 1 {
            assert!(
                matches!(response[0], 12 | 14),
                "an answer that is not an identities or sign reply: {response:02x?}"
            );
        }
    }
    // The honest requests are answered, so the loop above is not only refusals.
    assert_ne!(
        agent.respond(&identities, &mut hide_cli::agent::ApproveEverything),
        vec![5]
    );
    assert_ne!(
        agent.respond(&sign_request, &mut hide_cli::agent::ApproveEverything),
        vec![5]
    );

    // The framing around the decoder is public too: a peer that declares a
    // length it does not send must produce an error, never a panic or a hang.
    let mut lying = 64u32.to_be_bytes().to_vec();
    lying.push(11);
    let mut stream = std::io::Cursor::new(lying);
    assert!(
        hide_cli::agent::serve(&agent, &mut stream, &mut hide_cli::agent::ApproveEverything)
            .is_err(),
        "a length prefix longer than the body was accepted"
    );
    let mut clean = 1u32.to_be_bytes().to_vec();
    clean.push(11);
    let mut stream = std::io::Cursor::new(clean);
    hide_cli::agent::serve(&agent, &mut stream, &mut hide_cli::agent::ApproveEverything)
        .expect("a request followed by end of stream is a clean disconnect");
}
