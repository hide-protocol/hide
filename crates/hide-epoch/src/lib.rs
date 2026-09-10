//! Forward security by erasure, for data that is already at rest.
//!
//! # What this can and cannot do
//!
//! For a *single* stored ciphertext, forward secrecy is impossible. The message
//! key must be recoverable from the recipient's secret; if that secret still
//! exists when an attacker who already copied the ciphertext obtains it, the
//! ciphertext falls. No protocol avoids this — a sender's ephemeral key buys
//! authentication, not forward secrecy.
//!
//! What *is* achievable is forward security in the Canetti–Halevi–Katz sense:
//! give the recipient a sequence of keys, one per epoch, and let them erase each
//! secret once its window closes. A ciphertext written to epoch *n* becomes
//! permanently unreadable — by anyone, including the recipient — the moment
//! epoch *n*'s secret is erased. Compromise tomorrow does not reach it.
//!
//! The guarantee is therefore entirely about **erasure**, and it is only as good
//! as the erasure is. This crate zeroizes its own copy; it cannot promise
//! anything about backups, swap files, filesystem snapshots or an SSD's
//! wear-levelling. Those are the honest limits, and callers must be told them.
//!
//! # Why epochs are not derived from the master seed
//!
//! The obvious design — derive epoch *n* from the identity seed — provides no
//! forward security at all: anyone who later obtains the seed re-derives every
//! epoch, erased or not. So epoch secrets here are **independent random keys**.
//! The chain stores only public keys and a hash chain that binds them in order,
//! so a recipient can prove which key was current at a given epoch without being
//! able to recover an erased one.

use hide_crypto::{CryptoError, RecipientPublic, RecipientSecret};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

/// Epoch numbering starts at zero and only ever increases.
pub type EpochNumber = u64;

/// A chain never grows without bound in practice, but a malicious encoding could
/// claim it does. Refuse before allocating.
const MAX_CHAIN_ENTRIES: usize = 1_000_000;

/// Smallest possible CBOR encoding of one record: a 3-element array header
/// plus a one-byte number and two byte strings. Used only to bound how much a
/// declared count may pre-reserve, so an underestimate is safe.
const MIN_RECORD_BYTES: usize = 4;

const CHAIN_INFO: &[u8] = b"HIDE/0.6 epoch chain";

/// X-Wing encapsulation key length, per draft-connolly-cfrg-xwing-kem.
const PUBLIC_KEY_LENGTH: usize = 1216;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EpochError {
    #[error("epoch {0} has been erased and can never be recovered")]
    Erased(EpochNumber),
    #[error("epoch {0} is not in this chain")]
    UnknownEpoch(EpochNumber),
    #[error("epoch chain is malformed")]
    Malformed,
    #[error("epoch chain claims {0} entries, which exceeds the limit")]
    TooManyEntries(usize),
    #[error("epoch {expected} was expected but the chain links to {found}")]
    BrokenLink {
        expected: EpochNumber,
        found: EpochNumber,
    },
    #[error("the chain's hash linkage does not verify at epoch {0}")]
    BrokenHash(EpochNumber),
    #[error("epoch {number} carries a {actual}-byte key; {expected} expected")]
    WrongKeyLength {
        number: EpochNumber,
        expected: usize,
        actual: usize,
    },
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
}

impl From<CryptoError> for EpochError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error.to_string())
    }
}

/// One epoch's secret, held only while the epoch is live.
///
/// Deliberately not `Clone`: a copy is a second thing to erase, and erasure is
/// the entire guarantee.
struct EpochSecret {
    number: EpochNumber,
    secret: Option<RecipientSecret>,
}

impl EpochSecret {
    /// Drops the secret. There is no way back: the key was random, not derived.
    fn erase(&mut self) {
        self.secret = None;
    }
}

/// The public, shareable record of one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRecord {
    pub number: EpochNumber,
    pub public_key: Vec<u8>,
    /// Binds this entry to every entry before it, so a chain cannot be silently
    /// reordered or have an epoch spliced out.
    pub link: [u8; 32],
}

/// Hashes an entry together with the previous link. Domain-separated so a link
/// can never be confused with any other hash in the protocol.
fn link_for(previous: &[u8; 32], number: EpochNumber, public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_INFO);
    hasher.update(previous);
    hasher.update(number.to_be_bytes());
    // Every preceding field is fixed-width and the key is last, so the boundary
    // cannot move and this prefix is defence-in-depth, not load-bearing. It is
    // kept so that adding a field after the key stays safe by default.
    hasher.update((public_key.len() as u64).to_be_bytes());
    hasher.update(public_key);
    hasher.finalize().into()
}

/// The recipient's own view: public history plus whichever secrets survive.
pub struct EpochChain {
    records: Vec<EpochRecord>,
    secrets: Vec<EpochSecret>,
}

impl EpochChain {
    /// Starts a chain at epoch zero.
    pub fn new() -> Result<Self, EpochError> {
        let mut chain = Self {
            records: Vec::new(),
            secrets: Vec::new(),
        };
        chain.advance()?;
        Ok(chain)
    }

    /// Mints the next epoch. The previous epoch's secret is kept until erased
    /// explicitly, so a message in flight during a rotation is still readable.
    pub fn advance(&mut self) -> Result<EpochNumber, EpochError> {
        let number = self.records.len() as EpochNumber;
        if self.records.len() >= MAX_CHAIN_ENTRIES {
            return Err(EpochError::TooManyEntries(self.records.len()));
        }

        let secret = RecipientSecret::generate()?;
        let public_key = secret.public_key()?.to_bytes();
        let previous = self.records.last().map_or([0u8; 32], |record| record.link);

        self.records.push(EpochRecord {
            number,
            link: link_for(&previous, number, &public_key),
            public_key,
        });
        self.secrets.push(EpochSecret {
            number,
            secret: Some(secret),
        });
        Ok(number)
    }

    /// The epoch a sender should encrypt to.
    pub fn current(&self) -> EpochNumber {
        (self.records.len() as EpochNumber).saturating_sub(1)
    }

    /// The public key for an epoch, for a sender to encrypt to.
    pub fn public_key(&self, number: EpochNumber) -> Result<&[u8], EpochError> {
        self.records
            .get(number as usize)
            .map(|record| record.public_key.as_slice())
            .ok_or(EpochError::UnknownEpoch(number))
    }

    /// The secret for an epoch, if it has not been erased.
    pub fn secret(&self, number: EpochNumber) -> Result<&RecipientSecret, EpochError> {
        let held = self
            .secrets
            .get(number as usize)
            .ok_or(EpochError::UnknownEpoch(number))?;
        held.secret.as_ref().ok_or(EpochError::Erased(number))
    }

    /// Erases one epoch's secret. Irreversible, and that is the point.
    pub fn erase(&mut self, number: EpochNumber) -> Result<(), EpochError> {
        let held = self
            .secrets
            .get_mut(number as usize)
            .ok_or(EpochError::UnknownEpoch(number))?;
        held.erase();
        Ok(())
    }

    /// Erases every epoch before `keep_from`, the usual retention policy.
    pub fn erase_before(&mut self, keep_from: EpochNumber) -> usize {
        let mut erased = 0;
        for held in &mut self.secrets {
            if held.number < keep_from && held.secret.is_some() {
                held.erase();
                erased += 1;
            }
        }
        erased
    }

    /// Whether an epoch can still be read.
    pub fn is_readable(&self, number: EpochNumber) -> bool {
        self.secrets
            .get(number as usize)
            .is_some_and(|held| held.secret.is_some())
    }

    /// The public history, safe to publish.
    pub fn records(&self) -> &[EpochRecord] {
        &self.records
    }

    /// Checks that a chain is internally consistent: contiguous numbering from
    /// zero, and every link matching what its contents hash to.
    pub fn verify(records: &[EpochRecord]) -> Result<(), EpochError> {
        if records.len() > MAX_CHAIN_ENTRIES {
            return Err(EpochError::TooManyEntries(records.len()));
        }
        let mut previous = [0u8; 32];
        for (index, record) in records.iter().enumerate() {
            let expected = index as EpochNumber;
            if record.number != expected {
                return Err(EpochError::BrokenLink {
                    expected,
                    found: record.number,
                });
            }
            // A decoded chain carries attacker-chosen lengths; a key that is
            // not a real X-Wing key can never be used, so refuse it here rather
            // than at first use.
            if record.public_key.len() != PUBLIC_KEY_LENGTH {
                return Err(EpochError::WrongKeyLength {
                    number: record.number,
                    expected: PUBLIC_KEY_LENGTH,
                    actual: record.public_key.len(),
                });
            }
            let link = link_for(&previous, record.number, &record.public_key);
            if link != record.link {
                return Err(EpochError::BrokenHash(record.number));
            }
            previous = record.link;
        }
        Ok(())
    }
}

impl Drop for EpochChain {
    fn drop(&mut self) {
        for held in &mut self.secrets {
            held.erase();
        }
    }
}

/// Encodes the public history. Secrets are never encodable — there is no method
/// that could serialise one, so a chain cannot be backed up into a form that
/// silently defeats erasure.
pub fn encode_records(records: &[EpochRecord]) -> Result<Vec<u8>, EpochError> {
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    encoder
        .array(records.len() as u64)
        .map_err(|_| EpochError::Malformed)?;
    for record in records {
        encoder
            .array(3)
            .and_then(|e| e.u64(record.number))
            .and_then(|e| e.bytes(&record.public_key))
            .and_then(|e| e.bytes(&record.link))
            .map_err(|_| EpochError::Malformed)?;
    }
    Ok(out)
}

pub fn decode_records(bytes: &[u8]) -> Result<Vec<EpochRecord>, EpochError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder
        .array()
        .map_err(|_| EpochError::Malformed)?
        .ok_or(EpochError::Malformed)?;
    // Check the claimed length before reserving anything for it.
    if count > MAX_CHAIN_ENTRIES as u64 {
        return Err(EpochError::TooManyEntries(count as usize));
    }

    // The declared count is attacker-controlled and the ceiling above is a
    // million, so reserving from it lets five bytes of input claim tens of
    // megabytes. Reserve only what the remaining input could actually hold.
    let mut records = Vec::with_capacity((count as usize).min(bytes.len() / MIN_RECORD_BYTES));
    for _ in 0..count {
        let fields = decoder
            .array()
            .map_err(|_| EpochError::Malformed)?
            .ok_or(EpochError::Malformed)?;
        if fields != 3 {
            return Err(EpochError::Malformed);
        }
        let number = decoder.u64().map_err(|_| EpochError::Malformed)?;
        let public_key = decoder.bytes().map_err(|_| EpochError::Malformed)?.to_vec();
        let link_bytes = decoder.bytes().map_err(|_| EpochError::Malformed)?;
        let link: [u8; 32] = link_bytes.try_into().map_err(|_| EpochError::Malformed)?;
        records.push(EpochRecord {
            number,
            public_key,
            link,
        });
    }
    if decoder.position() != bytes.len() {
        return Err(EpochError::Malformed);
    }
    // One history, one encoding: CBOR admits several byte forms for the same
    // value (an empty array is 0x80 or 0x9a00000000), and a transparency log
    // would hash them as different leaves. Found by the epoch_chain fuzz target.

    if encode_records(&records)? != bytes {
        return Err(EpochError::Malformed);
    }
    Ok(records)
}

/// Convenience for a sender: the epoch to encrypt to and the key to use.
pub fn recipient_for(
    records: &[EpochRecord],
    number: EpochNumber,
) -> Result<RecipientPublic, EpochError> {
    let record = records
        .get(number as usize)
        .ok_or(EpochError::UnknownEpoch(number))?;
    Ok(RecipientPublic::from_bytes(&record.public_key)?)
}

/// Zeroizes a buffer that held epoch material. Exposed so callers handling raw
/// bytes have the same erasure discipline available.
pub fn erase_bytes(buffer: &mut [u8]) {
    buffer.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_chain_starts_at_epoch_zero() {
        let chain = EpochChain::new().unwrap();
        assert_eq!(chain.current(), 0);
        assert!(chain.is_readable(0));
    }

    /// A five-byte input may claim a million records. Decoding must fail on
    /// the truncated body rather than reserving tens of megabytes first.
    #[test]
    fn a_huge_declared_count_reserves_nothing() {
        // CBOR array header declaring 999_999 elements, then nothing.
        let mut bytes = Vec::new();
        minicbor::Encoder::new(&mut bytes).array(999_999).unwrap();
        assert_eq!(decode_records(&bytes), Err(EpochError::Malformed));
        // Above the ceiling it is refused outright, also without reserving.
        let mut huge = Vec::new();
        minicbor::Encoder::new(&mut huge).array(u64::MAX).unwrap();
        assert!(matches!(
            decode_records(&huge),
            Err(EpochError::TooManyEntries(_))
        ));
    }

    #[test]
    fn advancing_keeps_the_previous_epoch_readable() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        assert_eq!(chain.current(), 1);
        // A message in flight during rotation must still open.
        assert!(chain.is_readable(0));
        assert!(chain.is_readable(1));
    }

    #[test]
    fn erasure_is_irreversible() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        chain.erase(0).unwrap();

        assert!(!chain.is_readable(0));
        assert_eq!(chain.secret(0).err(), Some(EpochError::Erased(0)));
        // The public record survives, so history is still verifiable.
        assert!(chain.public_key(0).is_ok());
        // Advancing again must not resurrect it.
        chain.advance().unwrap();
        assert_eq!(chain.secret(0).err(), Some(EpochError::Erased(0)));
    }

    #[test]
    fn each_epoch_has_a_distinct_key() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        chain.advance().unwrap();
        let zero = chain.public_key(0).unwrap().to_vec();
        let one = chain.public_key(1).unwrap().to_vec();
        let two = chain.public_key(2).unwrap().to_vec();
        assert_ne!(zero, one);
        assert_ne!(one, two);
        assert_ne!(zero, two);
    }

    /// The property that makes this forward-secure rather than theatre: an
    /// erased epoch must not be recoverable from anything that remains.
    #[test]
    fn an_erased_epoch_is_not_derivable_from_later_ones() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();

        let erased_public = chain.public_key(0).unwrap().to_vec();
        chain.erase(0).unwrap();

        // Everything still held: the later secret and the whole public history.
        let later = chain.secret(1).unwrap().export_test_secret();
        let records = chain.records().to_vec();

        // Neither reproduces the erased secret, because it was never derived
        // from them — it was independent randomness.
        let public_from_later = RecipientSecret::from_bytes(&later)
            .unwrap()
            .public_key()
            .unwrap()
            .to_bytes();
        assert_ne!(public_from_later, erased_public);
        for record in &records {
            if record.number == 0 {
                continue;
            }
            assert_ne!(record.public_key, erased_public);
        }
    }

    #[test]
    fn erase_before_keeps_the_retention_window() {
        let mut chain = EpochChain::new().unwrap();
        for _ in 0..4 {
            chain.advance().unwrap();
        }
        let erased = chain.erase_before(3);
        assert_eq!(erased, 3);
        assert!(!chain.is_readable(0));
        assert!(!chain.is_readable(2));
        assert!(chain.is_readable(3));
        assert!(chain.is_readable(4));
    }

    #[test]
    fn erase_before_is_idempotent() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        assert_eq!(chain.erase_before(1), 1);
        // Already erased, so nothing further to erase.
        assert_eq!(chain.erase_before(1), 0);
    }

    #[test]
    fn a_chain_verifies_against_itself() {
        let mut chain = EpochChain::new().unwrap();
        for _ in 0..3 {
            chain.advance().unwrap();
        }
        EpochChain::verify(chain.records()).unwrap();
    }

    #[test]
    fn a_reordered_chain_is_refused() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        let mut records = chain.records().to_vec();
        records.swap(0, 1);
        assert!(EpochChain::verify(&records).is_err());
    }

    #[test]
    fn a_spliced_out_epoch_is_refused() {
        let mut chain = EpochChain::new().unwrap();
        for _ in 0..3 {
            chain.advance().unwrap();
        }
        let mut records = chain.records().to_vec();
        records.remove(1);
        assert!(EpochChain::verify(&records).is_err());
    }

    /// Numbering alone is not enough: without hashing the predecessor, a link
    /// would depend only on its own contents, and any entry could be lifted
    /// from one chain into another at the same position. Mutation-verified —
    /// removing `previous` from `link_for` must fail this test.
    #[test]
    fn an_entry_cannot_be_transplanted_from_another_chain() {
        let mut ours = EpochChain::new().unwrap();
        ours.advance().unwrap();
        let mut theirs = EpochChain::new().unwrap();
        theirs.advance().unwrap();

        // Same position, same numbering, different history behind it.
        let mut records = ours.records().to_vec();
        records[1] = theirs.records()[1].clone();

        assert_eq!(
            EpochChain::verify(&records).unwrap_err(),
            EpochError::BrokenHash(1)
        );
    }

    /// Two chains that happen to agree on epoch 0 must still diverge at their
    /// links, because each link commits to everything before it.
    #[test]
    fn links_differ_even_for_the_same_epoch_number() {
        let ours = EpochChain::new().unwrap();
        let theirs = EpochChain::new().unwrap();
        assert_ne!(ours.records()[0].link, theirs.records()[0].link);
    }

    /// A different key must give a different link. Note that the length prefix
    /// in `link_for` is deliberately NOT load-bearing today: `number` is a
    /// fixed 8 bytes and the key is the last field, so no boundary can shift,
    /// and removing the prefix survives this suite. It is kept as
    /// defence-in-depth for whenever a field is added after the key.
    #[test]
    fn a_different_key_gives_a_different_link() {
        let mut key_a = vec![0u8; PUBLIC_KEY_LENGTH];
        key_a[0] = 0xFF;
        let key_b = vec![0u8; PUBLIC_KEY_LENGTH];
        assert_ne!(
            link_for(&[0u8; 32], 0, &key_a),
            link_for(&[0u8; 32], 0, &key_b)
        );
    }

    #[test]
    fn a_different_epoch_number_gives_a_different_link() {
        let key = vec![0u8; PUBLIC_KEY_LENGTH];
        assert_ne!(link_for(&[0u8; 32], 0, &key), link_for(&[0u8; 32], 1, &key));
    }

    #[test]
    fn a_wrong_length_key_never_reaches_hashing() {
        let short = vec![0xAB; PUBLIC_KEY_LENGTH - 1];
        let records = vec![EpochRecord {
            number: 0,
            link: link_for(&[0u8; 32], 0, &short),
            public_key: short.clone(),
        }];
        assert_eq!(
            EpochChain::verify(&records).unwrap_err(),
            EpochError::WrongKeyLength {
                number: 0,
                expected: PUBLIC_KEY_LENGTH,
                actual: short.len(),
            }
        );
    }

    #[test]
    fn a_real_chain_carries_full_length_keys() {
        let chain = EpochChain::new().unwrap();
        assert_eq!(chain.public_key(0).unwrap().len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn a_substituted_key_is_refused() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        let mut records = chain.records().to_vec();
        let other = RecipientSecret::generate()
            .unwrap()
            .public_key()
            .unwrap()
            .to_bytes();
        records[1].public_key = other;
        assert_eq!(
            EpochChain::verify(&records).unwrap_err(),
            EpochError::BrokenHash(1)
        );
    }

    #[test]
    fn an_appended_forgery_is_refused() {
        let mut chain = EpochChain::new().unwrap();
        let mut records = chain.records().to_vec();
        chain.advance().unwrap();
        // A forged entry whose link was not computed from the real predecessor.
        records.push(EpochRecord {
            number: 1,
            public_key: RecipientSecret::generate()
                .unwrap()
                .public_key()
                .unwrap()
                .to_bytes(),
            link: [0u8; 32],
        });
        assert_eq!(
            EpochChain::verify(&records).unwrap_err(),
            EpochError::BrokenHash(1)
        );
    }

    #[test]
    fn records_round_trip_through_cbor() {
        let mut chain = EpochChain::new().unwrap();
        for _ in 0..3 {
            chain.advance().unwrap();
        }
        let encoded = encode_records(chain.records()).unwrap();
        let decoded = decode_records(&encoded).unwrap();
        assert_eq!(decoded, chain.records());
        EpochChain::verify(&decoded).unwrap();
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let chain = EpochChain::new().unwrap();
        let mut encoded = encode_records(chain.records()).unwrap();
        encoded.push(0);
        assert_eq!(decode_records(&encoded).unwrap_err(), EpochError::Malformed);
    }

    #[test]
    fn a_non_canonical_encoding_is_refused() {
        // The exact input the epoch_chain fuzz target found: an empty array
        // written with a four-byte length (0x9a 00000000) instead of 0x80.
        // It decoded cleanly and re-encoded to a different byte string.
        assert_eq!(
            decode_records(&[0x9a, 0, 0, 0, 0]).unwrap_err(),
            EpochError::Malformed
        );

        // The same property on a real chain: widen the outer length prefix.
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        let canonical = encode_records(chain.records()).unwrap();
        assert_eq!(canonical[0], 0x82, "two records encode as a short array");
        let mut widened = vec![0x98, 0x02];
        widened.extend_from_slice(&canonical[1..]);
        assert_eq!(decode_records(&widened).unwrap_err(), EpochError::Malformed);
        assert_eq!(decode_records(&canonical).unwrap().len(), 2);
    }

    #[test]
    fn a_truncated_encoding_is_refused() {
        let mut chain = EpochChain::new().unwrap();
        chain.advance().unwrap();
        let encoded = encode_records(chain.records()).unwrap();
        for cut in 1..encoded.len() {
            assert!(
                decode_records(&encoded[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
    }

    #[test]
    fn an_absurd_entry_count_is_refused_before_allocating() {
        // A header claiming four billion entries, with no data behind it.
        let mut out = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut out);
        encoder.array(u32::MAX as u64).unwrap();
        assert!(matches!(
            decode_records(&out).unwrap_err(),
            EpochError::TooManyEntries(_)
        ));
    }

    #[test]
    fn an_unknown_epoch_is_named_in_the_error() {
        let chain = EpochChain::new().unwrap();
        assert_eq!(chain.secret(9).err(), Some(EpochError::UnknownEpoch(9)));
        assert_eq!(
            chain.public_key(9).unwrap_err(),
            EpochError::UnknownEpoch(9)
        );
    }
}
