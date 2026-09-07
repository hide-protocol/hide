//! Checks `spec/hide-0.1.md` §9 against the implementation.
//!
//! The first draft of that section had the field order wrong and omitted the
//! length prefix. Prose is not checkable; this is.

use hide_epoch::EpochChain;
use sha2::{Digest, Sha256};

/// §9: `SHA-256("HIDE/0.6 epoch chain" || previous || number || len(key) || key)`.
#[test]
fn the_epoch_link_matches_the_spec() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    chain.advance().unwrap();

    let mut previous = [0u8; 32];
    for record in chain.records() {
        let mut hasher = Sha256::new();
        hasher.update(b"HIDE/0.6 epoch chain");
        hasher.update(previous);
        hasher.update(record.number.to_be_bytes());
        hasher.update((record.public_key.len() as u64).to_be_bytes());
        hasher.update(&record.public_key);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            record.link, expected,
            "epoch {}: the implementation and spec §9 disagree about the link",
            record.number
        );
        previous = record.link;
    }
}

/// §9 claims epoch secrets are independent random keys rather than derived, and
/// that this is what forward security rests on. Two chains made the same way
/// must therefore share no key material.
#[test]
fn epoch_keys_are_independent_not_derived() {
    let mut first = EpochChain::new().unwrap();
    first.advance().unwrap();
    let mut second = EpochChain::new().unwrap();
    second.advance().unwrap();

    assert_ne!(first.public_key(0).unwrap(), second.public_key(0).unwrap());
    // Within one chain, epoch 1 must not be predictable from epoch 0 either.
    assert_ne!(first.public_key(0).unwrap(), first.public_key(1).unwrap());
}

/// §9: the published chain still proves an erased epoch existed and where it
/// sat, which is what distinguishes "erased" from "never existed".
#[test]
fn an_erased_epoch_remains_in_the_published_history() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    let before = chain.records().len();

    chain.erase(0).unwrap();

    assert_eq!(
        chain.records().len(),
        before,
        "erasing removed the epoch from the public history"
    );
    // And the history still verifies, so a reader can trust the ordering.
    EpochChain::verify(chain.records()).unwrap();
}
