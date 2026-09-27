//! A chain rebuilt after a restart must behave exactly like the one that was
//! persisted, and must refuse secrets that do not belong to its history.

use hide_crypto::{ContentKey, RecipientSecret, unwrap_cek, wrap_cek};
use hide_epoch::{EpochChain, EpochError, recipient_for};

const OBJECT: [u8; 32] = [5u8; 32];

/// What a store hands back on open: owned secrets, as fresh copies.
fn persisted(chain: &EpochChain) -> Vec<(u64, RecipientSecret)> {
    chain
        .secrets()
        .map(|(number, secret)| {
            (
                number,
                RecipientSecret::from_bytes(secret.expose_seed_for_sealing()).unwrap(),
            )
        })
        .collect()
}

fn error_of(result: Result<EpochChain, EpochError>) -> EpochError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error,
    }
}

#[test]
fn a_restored_chain_opens_what_the_original_could() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    chain.advance().unwrap();
    let cek = ContentKey::generate().unwrap();
    let wrapped = wrap_cek(&recipient_for(chain.records(), 2).unwrap(), &cek, &OBJECT).unwrap();

    let restored = EpochChain::restore(chain.records().to_vec(), persisted(&chain)).unwrap();
    drop(chain);

    assert_eq!(restored.current(), 2);
    unwrap_cek(
        restored.secret(2).unwrap(),
        &OBJECT,
        &wrapped.encapsulation,
        &wrapped.wrapped_cek,
    )
    .unwrap();
}

#[test]
fn an_epoch_missing_from_the_store_restores_as_erased() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    chain.erase(0).unwrap();

    let restored = EpochChain::restore(chain.records().to_vec(), persisted(&chain)).unwrap();
    assert_eq!(restored.secret(0).err(), Some(EpochError::Erased(0)));
    assert!(restored.is_readable(1));
    assert_eq!(restored.head(), chain.head());
}

#[test]
fn secrets_from_another_chain_are_refused() {
    let mut ours = EpochChain::new().unwrap();
    ours.advance().unwrap();
    let mut theirs = EpochChain::new().unwrap();
    theirs.advance().unwrap();

    // A store sealed for one chain opened against another's history: the
    // heads differ, and restore notices through the keys themselves.
    assert_ne!(ours.head(), theirs.head());
    assert_eq!(
        error_of(EpochChain::restore(
            ours.records().to_vec(),
            persisted(&theirs)
        )),
        EpochError::SecretMismatch(0)
    );
}

#[test]
fn a_secret_filed_under_the_wrong_epoch_is_refused() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    let mut secrets = persisted(&chain);
    secrets[0].0 = 1;
    secrets[1].0 = 0;
    assert_eq!(
        error_of(EpochChain::restore(chain.records().to_vec(), secrets)),
        EpochError::SecretMismatch(1)
    );
}

#[test]
fn a_secret_beyond_the_history_is_refused() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    // The published history lost its latest epoch, but the store did not.
    let truncated = chain.records()[..1].to_vec();
    assert_eq!(
        error_of(EpochChain::restore(truncated, persisted(&chain))),
        EpochError::UnknownEpoch(1)
    );
    assert_eq!(
        error_of(EpochChain::restore(
            chain.records().to_vec(),
            [(u64::MAX, RecipientSecret::generate().unwrap())]
        )),
        EpochError::UnknownEpoch(u64::MAX)
    );
}

#[test]
fn a_duplicated_secret_is_refused() {
    let chain = EpochChain::new().unwrap();
    let mut secrets = persisted(&chain);
    secrets.extend(persisted(&chain));
    assert_eq!(
        error_of(EpochChain::restore(chain.records().to_vec(), secrets)),
        EpochError::DuplicateSecret(0)
    );
}

#[test]
fn a_broken_history_is_refused_before_any_secret_is_looked_at() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();
    let mut records = chain.records().to_vec();
    records.swap(0, 1);
    assert!(matches!(
        error_of(EpochChain::restore(records, persisted(&chain))),
        EpochError::BrokenLink { .. }
    ));
    assert_eq!(
        error_of(EpochChain::restore(Vec::new(), Vec::new())),
        EpochError::Malformed
    );
}

#[test]
fn a_restored_chain_keeps_advancing_from_its_head() {
    let chain = EpochChain::new().unwrap();
    let mut restored = EpochChain::restore(chain.records().to_vec(), persisted(&chain)).unwrap();
    assert_eq!(restored.advance().unwrap(), 1);
    EpochChain::verify(restored.records()).unwrap();
    assert_eq!(restored.records()[0], chain.records()[0]);
}
