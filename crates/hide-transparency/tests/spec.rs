//! Checks `spec/hide-0.1.md` §10 against the implementation, and against
//! RFC 6962 itself where the RFC gives a concrete value.

use hide_transparency::{TransparencyLog, decode_checkpoint, encode_checkpoint, leaf_hash};
use sha2::{Digest, Sha256};

/// §10 and RFC 6962 §2.1: a leaf is `SHA-256(0x00 || data)`.
#[test]
fn the_leaf_hash_matches_rfc_6962() {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(b"payload");
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(leaf_hash(b"payload"), expected);
}

/// RFC 6962 §2.1: the empty tree's root is the hash of the empty string. This
/// is a fixed constant, so it can be asserted literally.
#[test]
fn the_empty_root_matches_rfc_6962() {
    let expected: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(TransparencyLog::new().root(), expected);
}

/// §10 and RFC 6962 §2.1: an interior node is `SHA-256(0x01 || left || right)`.
#[test]
fn the_node_hash_matches_rfc_6962() {
    let mut log = TransparencyLog::new();
    log.append(b"a");
    log.append(b"b");

    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(leaf_hash(b"a"));
    hasher.update(leaf_hash(b"b"));
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(log.root(), expected);
}

/// §10: a subtree of n leaves splits at the largest power of two strictly below
/// n. Asserted through the shape of a 3-leaf tree, where the split must be 2
/// and not 1 — the case that distinguishes RFC 6962 from a naive pairing.
#[test]
fn the_split_matches_rfc_6962_for_an_odd_tree() {
    let mut log = TransparencyLog::new();
    for name in [b"a".as_slice(), b"b", b"c"] {
        log.append(name);
    }

    // ((a,b),c), not (a,(b,c)).
    let mut left = Sha256::new();
    left.update([0x01]);
    left.update(leaf_hash(b"a"));
    left.update(leaf_hash(b"b"));
    let left: [u8; 32] = left.finalize().into();

    let mut root = Sha256::new();
    root.update([0x01]);
    root.update(left);
    root.update(leaf_hash(b"c"));
    let expected: [u8; 32] = root.finalize().into();

    assert_eq!(log.root(), expected, "the tree split at the wrong point");
}

/// §10: a checkpoint is `size(u64be) || root(32)`.
#[test]
fn the_checkpoint_layout_matches_the_spec() {
    let mut log = TransparencyLog::new();
    for i in 0..5u64 {
        log.append(&i.to_be_bytes());
    }

    let encoded = encode_checkpoint(log.len(), &log.root());
    assert_eq!(encoded.len(), 40);
    assert_eq!(&encoded[..8], &5u64.to_be_bytes());
    assert_eq!(&encoded[8..], &log.root());

    let (size, root) = decode_checkpoint(&encoded).unwrap();
    assert_eq!(size, 5);
    assert_eq!(root, log.root());
}

/// §10 states the prefixes exist so a leaf cannot be reinterpreted as a node.
/// Assert the two hashes of the same bytes actually differ.
#[test]
fn a_leaf_and_a_node_over_the_same_bytes_differ() {
    let a = leaf_hash(b"a");
    let b = leaf_hash(b"b");

    let mut node = Sha256::new();
    node.update([0x01]);
    node.update(a);
    node.update(b);
    let node: [u8; 32] = node.finalize().into();

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&a);
    concatenated.extend_from_slice(&b);

    assert_ne!(node, leaf_hash(&concatenated));
}
