#![no_main]
//! The ssh-agent request decoder reads length-prefixed strings off a socket, and
//! those prefixes are chosen by whoever connected. It has to answer — never
//! panic, and never allocate what a prefix claims rather than what the message
//! contains — and it has to refuse a HIDE-shaped payload instead of handing a
//! caller the classical half of a hybrid signature (§8.5).
//!
//! `hide-cli` is a binary by product; its `[lib]` target exists so this can reach
//! the same code the binary serves (see `apps/hide-cli/src/lib.rs`).

use hide_cli::agent::{Agent, ApproveEverything};
use hide_sign::SigningIdentity;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::sync::OnceLock;

fn agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        // A fixed key: this fuzzes the decoder, not the key agreement.
        let identity = SigningIdentity::from_bytes(&[0x51; 32]).expect("seed");
        Agent::new(&identity, "fuzz".to_string())
    })
}

fuzz_target!(|data: &[u8]| {
    // The request decoder. Whatever arrives, it answers: a reply is never empty,
    // because a caller has to be able to tell one request from the next.
    let response = agent().respond(data, &mut ApproveEverything);
    assert!(!response.is_empty(), "no answer for {data:02x?}");

    // Deterministic: the same request is the same answer, so nothing here depends
    // on state a peer could steer.
    assert_eq!(
        response,
        agent().respond(data, &mut ApproveEverything),
        "two answers for one request"
    );

    // The RFC 4251 framing around it. `Cursor<Vec<u8>>` is the smallest thing that
    // is both Read and Write; a declared length larger than the input, zero, or
    // over MAX_MESSAGE must come back as an error or a clean disconnect.
    let mut stream = Cursor::new(data.to_vec());
    let _ = hide_cli::agent::serve(agent(), &mut stream, &mut ApproveEverything);
});
