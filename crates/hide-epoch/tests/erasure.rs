//! The claim this crate exists to make: a container written to an erased epoch
//! cannot be opened again, by anyone, using anything that still exists.
//!
//! These tests go through the real KEM rather than asserting on bookkeeping, so
//! they fail if erasure is ever reduced to a flag that hides a live key.

use hide_crypto::{ContentKey, WrappedKey, unwrap_cek, wrap_cek};
use hide_epoch::{EpochChain, EpochError, recipient_for};

/// A stand-in for the object being protected. Real containers bind their own id.
const OBJECT: [u8; 32] = [7u8; 32];

/// `ContentKey` deliberately exposes no bytes, so equality is shown the way it
/// matters in practice: both keys derive to the same subkey.
fn same_key(recovered: &ContentKey, original: &ContentKey) -> bool {
    let salt = [1u8; 16];
    let a = hide_crypto::derive_key(recovered, &salt, b"epoch test").unwrap();
    let b = hide_crypto::derive_key(original, &salt, b"epoch test").unwrap();
    hide_crypto::mac(&a, &[b"probe"]).unwrap() == hide_crypto::mac(&b, &[b"probe"]).unwrap()
}

fn open(chain: &EpochChain, epoch: u64, wrapped: &WrappedKey) -> Option<ContentKey> {
    unwrap_cek(
        chain.secret(epoch).ok()?,
        &OBJECT,
        &wrapped.encapsulation,
        &wrapped.wrapped_cek,
    )
    .ok()
}

#[test]
fn a_message_to_a_live_epoch_opens() {
    let chain = EpochChain::new().unwrap();
    let cek = ContentKey::generate().unwrap();
    let wrapped = wrap_cek(&recipient_for(chain.records(), 0).unwrap(), &cek, &OBJECT).unwrap();

    assert!(same_key(&open(&chain, 0, &wrapped).unwrap(), &cek));
}

#[test]
fn a_message_to_an_erased_epoch_is_lost_forever() {
    let mut chain = EpochChain::new().unwrap();
    let cek = ContentKey::generate().unwrap();
    let wrapped = wrap_cek(&recipient_for(chain.records(), 0).unwrap(), &cek, &OBJECT).unwrap();

    // Rotate, then let the retention window close on epoch 0.
    chain.advance().unwrap();
    chain.erase(0).unwrap();

    // The recipient themselves can no longer open it.
    assert_eq!(chain.secret(0).err(), Some(EpochError::Erased(0)));

    // Nor does the current epoch's secret help: the keys are independent.
    assert!(
        open(&chain, 1, &wrapped).is_none(),
        "a later epoch opened a message addressed to an earlier one"
    );
}

#[test]
fn rotation_alone_does_not_lose_data() {
    // Erasure is what forfeits access; advancing must not, or every rotation
    // would silently destroy mail in flight.
    let mut chain = EpochChain::new().unwrap();
    let cek = ContentKey::generate().unwrap();
    let wrapped = wrap_cek(&recipient_for(chain.records(), 0).unwrap(), &cek, &OBJECT).unwrap();

    for _ in 0..5 {
        chain.advance().unwrap();
    }

    assert!(same_key(&open(&chain, 0, &wrapped).unwrap(), &cek));
}

#[test]
fn each_epoch_opens_only_its_own_messages() {
    let mut chain = EpochChain::new().unwrap();
    chain.advance().unwrap();

    let cek = ContentKey::generate().unwrap();
    let to_zero = wrap_cek(&recipient_for(chain.records(), 0).unwrap(), &cek, &OBJECT).unwrap();
    let to_one = wrap_cek(&recipient_for(chain.records(), 1).unwrap(), &cek, &OBJECT).unwrap();

    assert!(open(&chain, 0, &to_zero).is_some());
    assert!(open(&chain, 1, &to_one).is_some());
    assert!(open(&chain, 1, &to_zero).is_none());
    assert!(open(&chain, 0, &to_one).is_none());
}

#[test]
fn the_published_history_is_enough_to_encrypt_to() {
    // A sender holds only the public chain, never the recipient's object.
    let chain = EpochChain::new().unwrap();
    let published = hide_epoch::encode_records(chain.records()).unwrap();

    let records = hide_epoch::decode_records(&published).unwrap();
    EpochChain::verify(&records).unwrap();

    let cek = ContentKey::generate().unwrap();
    let wrapped = wrap_cek(&recipient_for(&records, 0).unwrap(), &cek, &OBJECT).unwrap();

    assert!(same_key(&open(&chain, 0, &wrapped).unwrap(), &cek));
}
