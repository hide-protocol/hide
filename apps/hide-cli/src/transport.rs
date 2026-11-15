//! Where the agent listens. The two platforms disagree about what an
//! ssh-agent endpoint even is: Unix clients open a filesystem socket named by
//! `SSH_AUTH_SOCK`, Windows clients open a named pipe. The protocol above is
//! identical, so only the listener differs.

use crate::Result;
use crate::agent::{Agent, Approver, serve};

/// The Windows named pipe cannot be restricted to the current user without
/// hand-built security descriptors, so it stays open to every local process.
/// Confirmation on the terminal is then the only thing standing between another
/// local user and a signature; refusing `--no-confirm` keeps it standing.
pub fn check_no_confirm_allowed() -> Result<()> {
    if cfg!(windows) {
        return Err(
            "--no-confirm is not available on Windows: the named pipe cannot be restricted to the current user, so every signature must be confirmed on the terminal"
                .into(),
        );
    }
    Ok(())
}

/// What a client must be told to reach this agent.
pub fn advice(endpoint: &str) -> String {
    // OpenSSH for Windows 9.5p2 ignores -o IdentityAgent, so both platforms
    // are told to use the environment variable.
    if cfg!(windows) {
        format!("set SSH_AUTH_SOCK to {endpoint} (PowerShell: $env:SSH_AUTH_SOCK = '{endpoint}')")
    } else {
        format!("export SSH_AUTH_SOCK={endpoint}")
    }
}

pub fn default_endpoint() -> String {
    if cfg!(windows) {
        r"\\.\pipe\hide-agent".to_string()
    } else {
        format!(
            "{}/hide-agent/agent.sock",
            std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string())
        )
    }
}

/// Creates the socket's parent directory with mode 0700 in one step. The
/// socket itself is born `0666 & ~umask` and only tightened afterwards, which
/// leaves a window; a directory's mode is applied at creation, so binding
/// inside one closes it. Refuses a directory that already exists with a wider
/// mode or that is not owned by us, rather than quietly widening the gate.
#[cfg(unix)]
pub(crate) fn create_private_dir(directory: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is not a directory",
            directory.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        // Pre-existing from an older release, or created by someone else.
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    if metadata.uid() != current_uid()? {
        return Err(std::io::Error::other(format!(
            "{} is owned by another user",
            directory.display()
        )));
    }
    Ok(())
}

/// Our own uid without libc: a file we have just created carries it.
#[cfg(unix)]
fn current_uid() -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    let probe = tempfile::tempfile()?;
    Ok(probe.metadata()?.uid())
}

#[cfg(unix)]
pub fn listen(agent: &Agent, endpoint: &str, approver: &mut dyn Approver) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    // The socket is a signing oracle; nobody else on this Unix machine may
    // connect. The parent directory is the real gate (see create_private_dir);
    // the socket mode is belt-and-braces. Windows is a different story: see
    // check_no_confirm_allowed.
    let endpoint_path = Path::new(endpoint);
    let parent = endpoint_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    create_private_dir(parent)?;
    // A stale socket from a crashed run would otherwise make bind fail forever;
    // anything else at this path belongs to someone else and is refused.
    remove_stale_socket(endpoint_path)?;
    let listener = UnixListener::bind(endpoint)?;
    std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600))?;

    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = serve(agent, &mut stream, approver) {
            eprintln!("hide agent: connection ended: {error}");
        }
    }
    Ok(())
}

/// Clears the way for `bind`, and only when the path is genuinely dead.
///
/// A socket left behind by a crashed run would make `bind` fail forever, so it
/// has to go. Two other things at that path must not go: a *regular file*, which
/// the caller chose to name and which was never ours to delete, and a socket a
/// live agent is still answering on, removing which would let this process steal
/// its endpoint. Both are refused with an error instead.
#[cfg(unix)]
fn remove_stale_socket(endpoint: &std::path::Path) -> Result<()> {
    use std::io::ErrorKind;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;

    let metadata = match std::fs::symlink_metadata(endpoint) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() {
        // A directory, a symlink, a regular file: all of them are someone
        // else's, and a symlink in particular would let the path point at a file
        // we would then unlink.
        return Err(format!(
            "{} already exists and is not a socket; refusing to remove it",
            endpoint.display()
        )
        .into());
    }
    match UnixStream::connect(endpoint) {
        Ok(_) => Err(format!(
            "another agent is already listening on {}",
            endpoint.display()
        )
        .into()),
        // Nobody accepts on it, so it is a leftover from a run that died.
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
            std::fs::remove_file(endpoint)?;
            Ok(())
        }
        // Anything else leaves the question open (permissions, a race with an
        // owner removing it, a socket of the wrong type). Guessing here could
        // delete a live endpoint, so refuse and say so.
        Err(error) => Err(format!(
            "cannot tell whether {} still has an agent on it: {error}",
            endpoint.display()
        )
        .into()),
    }
}

#[cfg(windows)]
pub fn listen(agent: &Agent, endpoint: &str, approver: &mut dyn Approver) -> Result<()> {
    use interprocess::os::windows::named_pipe::PipeListenerOptions;
    use interprocess::os::windows::named_pipe::pipe_mode;
    use std::path::Path;

    let listener = PipeListenerOptions::new()
        .path(Path::new(endpoint))
        .create_duplex::<pipe_mode::Bytes>()?;

    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = serve(agent, &mut stream, approver) {
            eprintln!("hide agent: connection ended: {error}");
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_socket_directory_is_private_from_birth() {
        let root = tempfile::tempdir().expect("tempdir");
        let directory = root.path().join("hide-agent");
        create_private_dir(&directory).expect("created");
        let mode = std::fs::metadata(&directory)
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "mode was {mode:o}");
    }

    #[test]
    fn a_pre_existing_wide_directory_is_tightened() {
        let root = tempfile::tempdir().expect("tempdir");
        let directory = root.path().join("hide-agent");
        std::fs::create_dir(&directory).expect("created");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        create_private_dir(&directory).expect("accepted");
        let mode = std::fs::metadata(&directory)
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "mode was {mode:o}");
    }

    #[test]
    fn a_file_in_the_way_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let not_a_directory = root.path().join("hide-agent");
        std::fs::write(&not_a_directory, b"").expect("written");
        assert!(create_private_dir(&not_a_directory).is_err());
    }

    #[test]
    fn a_missing_endpoint_needs_no_removal() {
        let root = tempfile::tempdir().expect("tempdir");
        remove_stale_socket(&root.path().join("nothing-here.sock")).expect("nothing to do");
    }

    /// The endpoint path is chosen by the caller, so a regular file that happens
    /// to sit there is not ours to delete. It used to be removed unconditionally.
    #[test]
    fn a_regular_file_at_the_endpoint_is_refused_and_left_alone() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("important.txt");
        std::fs::write(&path, b"not a socket").expect("written");

        let error = remove_stale_socket(&path)
            .expect_err("a regular file must not be treated as a stale socket")
            .to_string();
        assert!(error.contains("not a socket"), "{error}");
        assert_eq!(
            std::fs::read(&path).expect("the file must still be there"),
            b"not a socket"
        );
    }

    /// Both halves of the decision: a socket nobody answers on is a leftover and
    /// must go, or `bind` can never succeed again; a socket a live agent holds
    /// must stay, or this process would take over its endpoint.
    #[test]
    fn a_dead_socket_is_removed_and_a_live_one_is_kept() {
        let root = tempfile::tempdir().expect("tempdir");

        let dead = root.path().join("dead.sock");
        // Dropping the listener closes the socket but leaves its name behind,
        // which is exactly what a killed agent leaves.
        drop(std::os::unix::net::UnixListener::bind(&dead).expect("bind"));
        assert!(dead.exists());
        remove_stale_socket(&dead).expect("a socket nobody answers on is stale");
        assert!(!dead.exists(), "the stale socket was not cleared");

        let live = root.path().join("live.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&live).expect("bind");
        let error = remove_stale_socket(&live)
            .expect_err("a socket that answers must not be removed")
            .to_string();
        assert!(error.contains("already listening"), "{error}");
        assert!(live.exists(), "a live agent's endpoint was removed");
    }
}
