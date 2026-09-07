//! An append-only log whose history cannot be rewritten without detection.
//!
//! A signature proves who wrote something; it cannot prove that everyone was
//! shown the *same* something. That is what this is for. The log publishes one
//! 32-byte root per size, and answers two questions:
//!
//! - **Inclusion**: "is this entry in the log of size *n*?" — an audit path of
//!   about log₂(n) hashes.
//! - **Consistency**: "is the log of size *m* a prefix of the log of size *n*?"
//!   — the proof that nothing already published was altered or removed.
//!
//! Consistency is the one that matters. Without it a server can show one
//! history to a victim and another to everyone else; with it, doing so requires
//! producing two roots for one size, which is permanent, transferable evidence
//! of misbehaviour.
//!
//! The hashing follows RFC 6962: leaves are prefixed `0x00` and internal nodes
//! `0x01`, so a leaf can never be reinterpreted as a node — the second-preimage
//! attack that an unprefixed Merkle tree allows.
//!
//! # What a log cannot do by itself
//!
//! It cannot detect a *split view* on its own: two divergent logs are each
//! internally consistent. Catching that needs witnesses — independent parties
//! who gossip roots and refuse to sign two roots for one size. Nothing here
//! implements witnessing, and a log without it is a promise, not a proof.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// RFC 6962 domain separators.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Refuse an absurd proof before allocating for it. A path longer than this
/// implies a log with more entries than could ever be built.
const MAX_PROOF_LEN: usize = 64;

pub type Hash = [u8; 32];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LogError {
    #[error("the log is empty")]
    Empty,
    #[error("entry {index} is not in a log of size {size}")]
    OutOfRange { index: u64, size: u64 },
    #[error("a log of size {old} cannot be a prefix of one of size {new}")]
    NotAPrefix { old: u64, new: u64 },
    #[error("the proof does not verify")]
    BadProof,
    #[error("a proof of {0} hashes exceeds the limit")]
    ProofTooLong(usize),
    #[error("the encoding is malformed")]
    Malformed,
}

/// Hashes a leaf. The prefix is what stops a leaf being read as a node.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The root of a subtree covering `leaves`, per RFC 6962 §2.1.
fn root_of(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        // The empty tree is the hash of nothing, so an empty log still has a
        // well-defined root rather than a special case at every call site.
        0 => Sha256::digest(b"").into(),
        1 => leaves[0],
        n => {
            let split = largest_power_of_two_below(n);
            node_hash(&root_of(&leaves[..split]), &root_of(&leaves[split..]))
        }
    }
}

/// RFC 6962 splits at the largest power of two strictly less than `n`, which is
/// what makes a tree's shape depend only on its size.
fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut split = 1;
    while split << 1 < n {
        split <<= 1;
    }
    split
}

/// Proof that one entry is in the log at a given size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u64,
    pub size: u64,
    pub path: Vec<Hash>,
}

/// Proof that a smaller log is a prefix of a larger one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub path: Vec<Hash>,
}

/// The log itself. Holds leaf hashes only: the entries are the caller's.
#[derive(Debug, Default, Clone)]
pub struct TransparencyLog {
    leaves: Vec<Hash>,
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an entry, returning its index.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash(data));
        index
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The root commitment for the whole log.
    pub fn root(&self) -> Hash {
        root_of(&self.leaves)
    }

    /// The root the log had when it held `size` entries. A log can always
    /// re-derive its own past roots, which is what lets it answer an audit.
    pub fn root_at(&self, size: u64) -> Result<Hash, LogError> {
        if size > self.len() {
            return Err(LogError::OutOfRange {
                index: size,
                size: self.len(),
            });
        }
        Ok(root_of(&self.leaves[..size as usize]))
    }

    /// An audit path for `index` in the log as it stands at `size`.
    pub fn prove_inclusion(&self, index: u64, size: u64) -> Result<InclusionProof, LogError> {
        if size > self.len() || index >= size {
            return Err(LogError::OutOfRange { index, size });
        }
        let mut path = Vec::new();
        collect_inclusion(&self.leaves[..size as usize], index as usize, &mut path);
        Ok(InclusionProof { index, size, path })
    }

    /// A proof that the log of `old_size` is a prefix of the log of `new_size`.
    pub fn prove_consistency(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, LogError> {
        if new_size > self.len() {
            return Err(LogError::OutOfRange {
                index: new_size,
                size: self.len(),
            });
        }
        if old_size > new_size || old_size == 0 {
            return Err(LogError::NotAPrefix {
                old: old_size,
                new: new_size,
            });
        }
        let mut path = Vec::new();
        collect_consistency(
            &self.leaves[..new_size as usize],
            old_size as usize,
            true,
            &mut path,
        );
        Ok(ConsistencyProof {
            old_size,
            new_size,
            path,
        })
    }
}

fn collect_inclusion(leaves: &[Hash], index: usize, path: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let split = largest_power_of_two_below(leaves.len());
    if index < split {
        collect_inclusion(&leaves[..split], index, path);
        path.push(root_of(&leaves[split..]));
    } else {
        collect_inclusion(&leaves[split..], index - split, path);
        path.push(root_of(&leaves[..split]));
    }
}

/// RFC 6962 §2.1.2. `complete` tracks whether the old tree is exactly the
/// subtree being considered, which decides whether its root must be sent.
fn collect_consistency(leaves: &[Hash], old: usize, complete: bool, path: &mut Vec<Hash>) {
    if old == leaves.len() {
        if !complete {
            path.push(root_of(leaves));
        }
        return;
    }
    let split = largest_power_of_two_below(leaves.len());
    if old <= split {
        collect_consistency(&leaves[..split], old, complete, path);
        path.push(root_of(&leaves[split..]));
    } else {
        collect_consistency(&leaves[split..], old - split, false, path);
        path.push(root_of(&leaves[..split]));
    }
}

/// Checks an audit path against a root. The verifier holds only the root, the
/// entry, and the proof — never the log.
pub fn verify_inclusion(proof: &InclusionProof, leaf: &Hash, root: &Hash) -> Result<(), LogError> {
    if proof.path.len() > MAX_PROOF_LEN {
        return Err(LogError::ProofTooLong(proof.path.len()));
    }
    if proof.index >= proof.size {
        return Err(LogError::OutOfRange {
            index: proof.index,
            size: proof.size,
        });
    }

    // Descend to the leaf first, recording which side each step took. The
    // prover pushes siblings on the way back up, so the path is deepest-first
    // and must be consumed in that order.
    let mut turns = Vec::new();
    let mut index = proof.index;
    let mut size = proof.size;
    while size > 1 {
        let split = largest_power_of_two_below(size as usize) as u64;
        if index < split {
            turns.push(true);
            size = split;
        } else {
            turns.push(false);
            index -= split;
            size -= split;
        }
    }

    if turns.len() != proof.path.len() {
        return Err(LogError::BadProof);
    }

    let mut hash = *leaf;
    for (sibling, went_left) in proof.path.iter().zip(turns.iter().rev()) {
        hash = if *went_left {
            node_hash(&hash, sibling)
        } else {
            node_hash(sibling, &hash)
        };
    }

    if hash != *root {
        return Err(LogError::BadProof);
    }
    Ok(())
}

/// Checks that `old_root` really is the root the log had before it grew to
/// `new_root`. This is the check that catches a rewritten history.
pub fn verify_consistency(
    proof: &ConsistencyProof,
    old_root: &Hash,
    new_root: &Hash,
) -> Result<(), LogError> {
    if proof.path.len() > MAX_PROOF_LEN {
        return Err(LogError::ProofTooLong(proof.path.len()));
    }
    if proof.old_size == 0 || proof.old_size > proof.new_size {
        return Err(LogError::NotAPrefix {
            old: proof.old_size,
            new: proof.new_size,
        });
    }

    // Nothing grew, so the roots must simply match and no path is needed.
    if proof.old_size == proof.new_size {
        return if proof.path.is_empty() && old_root == new_root {
            Ok(())
        } else {
            Err(LogError::BadProof)
        };
    }

    // Record the descent, mirroring how the prover recurses, so the two walks
    // agree on which sibling belongs at which level. `complete` says whether
    // the old log is exactly this subtree, in which case its root is not sent.
    let mut turns = Vec::new();
    let mut old_size = proof.old_size;
    let mut new_size = proof.new_size;
    let mut complete = true;
    while old_size != new_size {
        let split = largest_power_of_two_below(new_size as usize) as u64;
        if old_size <= split {
            turns.push(true);
            new_size = split;
        } else {
            turns.push(false);
            old_size -= split;
            new_size -= split;
            complete = false;
        }
    }

    // The prover pushes the subtree root here only when the old log is not a
    // complete subtree of the new one.
    let expected = turns.len() + usize::from(!complete);
    if proof.path.len() != expected {
        return Err(LogError::BadProof);
    }

    let mut path = proof.path.iter();
    let seed = if complete {
        *old_root
    } else {
        *path.next().ok_or(LogError::BadProof)?
    };
    let mut old_hash = seed;
    let mut new_hash = seed;

    for (sibling, went_left) in path.zip(turns.iter().rev()) {
        if *went_left {
            new_hash = node_hash(&new_hash, sibling);
        } else {
            old_hash = node_hash(sibling, &old_hash);
            new_hash = node_hash(sibling, &new_hash);
        }
    }

    if old_hash != *old_root || new_hash != *new_root {
        return Err(LogError::BadProof);
    }
    Ok(())
}

/// Encodes a root for publication: size and hash together, because a hash with
/// no size is not a commitment to anything checkable.
pub fn encode_checkpoint(size: u64, root: &Hash) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(root);
    out
}

pub fn decode_checkpoint(bytes: &[u8]) -> Result<(u64, Hash), LogError> {
    if bytes.len() != 40 {
        return Err(LogError::Malformed);
    }
    let size = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| LogError::Malformed)?);
    let root: Hash = bytes[8..].try_into().map_err(|_| LogError::Malformed)?;
    Ok((size, root))
}
