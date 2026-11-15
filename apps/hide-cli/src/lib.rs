//! Library face of the `hide` binary.
//!
//! The binary is the whole product; this target exists so the pieces that decode
//! bytes from an untrusted source can be reached by a test harness. `fuzz/` is a
//! separate workspace and cannot link a `[[bin]]`, so without a `lib` target the
//! ssh-agent's request decoder has no fuzz target, which the project's rule
//! ("every decoder of untrusted bytes gets one") requires.
//!
//! Nothing here is new code: `agent` and `transport` are the same modules
//! `main.rs` drives, moved behind a `lib` target unchanged.
//!
//! A fuzz target calls, for the request path:
//!
//! ```text
//! hide_cli::agent::Agent::new(&signing_identity, "fuzz".into())
//!     .respond(bytes, &mut hide_cli::agent::ApproveEverything)
//! ```
//!
//! and, for the RFC 4251 framing around it (length prefix, `MAX_MESSAGE` bound,
//! loop until EOF), `hide_cli::agent::serve` with any `Read + Write`, e.g.
//! `std::io::Cursor<Vec<u8>>`.
//!
//! `Agent::respond` never panics on a truncated or malformed request: anything
//! it cannot parse, and anything it refuses, becomes a single `FAILURE` byte.

/// A command's failure is a message for a person, not a typed condition for a
/// caller, so errors cross this boundary as a boxed trait object.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub mod agent;
pub mod transport;
