//! The ssh-agent command, exercised as a process. The point of these tests is
//! the fail-closed edges: an agent that cannot ask for confirmation must not
//! start, and on Windows an unconfirmed agent is not offered at all.

use std::{
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
