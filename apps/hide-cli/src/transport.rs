//! Where the agent listens. The two platforms disagree about what an
//! ssh-agent endpoint even is: Unix clients open a filesystem socket named by
//! `SSH_AUTH_SOCK`, Windows clients open a named pipe. The protocol above is
//! identical, so only the listener differs.

use crate::Result;
use crate::agent::{Agent, Approver, serve};

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

/// The endpoint used when the caller does not name one.
pub fn default_endpoint() -> String {
    if cfg!(windows) {
        r"\\.\pipe\hide-agent".to_string()
    } else {
        format!(
            "{}/hide-agent.sock",
            std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string())
        )
    }
}

#[cfg(unix)]
pub fn listen(agent: &Agent, endpoint: &str, approver: &mut dyn Approver) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    // A stale socket from a crashed run would otherwise make bind fail forever.
    let _ = std::fs::remove_file(endpoint);
    let listener = UnixListener::bind(endpoint)?;
    // The socket is a signing oracle; nobody else on the machine may connect.
    std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600))?;

    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = serve(agent, &mut stream, approver) {
            eprintln!("hide agent: connection ended: {error}");
        }
    }
    Ok(())
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
