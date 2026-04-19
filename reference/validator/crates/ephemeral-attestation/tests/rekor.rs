//! Tests for Rekor Merkle inclusion proofs (feature = "rekor").

#![cfg(feature = "rekor")]
#![allow(clippy::doc_markdown)]

use ephemeral_attestation::rekor::{verify_rekor_inclusion, RekorEntry};
use ephemeral_attestation::AttestError;
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers to build a deterministic 4-leaf Merkle tree
// ─────────────────────────────────────────────────────────────────────────────

/// RFC 9162 §2.1.1 leaf hash: SHA-256(0x00 || data)
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(data);
    h.finalize().into()
}

/// RFC 9162 §2.1.1 inner hash: SHA-256(0x01 || left || right)
fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left.as_slice());
    h.update(right.as_slice());
    h.finalize().into()
}

/// Build a balanced 4-leaf tree and return (root, leaf_hashes).
///
/// Tree structure:
/// ```
///       root
///      /    \
///    h01    h23
///   /  \   /  \
///  L0  L1 L2  L3
/// ```
fn build_4leaf_tree() -> ([u8; 32], [[u8; 32]; 4]) {
    let leaves: [[u8; 32]; 4] = [
        leaf_hash(b"leaf-0"),
        leaf_hash(b"leaf-1"),
        leaf_hash(b"leaf-2"),
        leaf_hash(b"leaf-3"),
    ];
    let h01 = inner_hash(&leaves[0], &leaves[1]);
    let h23 = inner_hash(&leaves[2], &leaves[3]);
    let root = inner_hash(&h01, &h23);
    (root, leaves)
}

// ── 1. happy inclusion proof ──────────────────────────────────────────────────

#[test]
fn happy_inclusion_verifies() {
    let (root, leaves) = build_4leaf_tree();
    let h01 = inner_hash(&leaves[0], &leaves[1]);
    let h23 = inner_hash(&leaves[2], &leaves[3]);

    // Inclusion proof for leaf index 2 (L2):
    // sibling at depth 0: L3 (right sibling, so index bit = 0 → left node)
    // sibling at depth 1: h01 (left sibling)
    // index=2, tree_size=4
    let entry = RekorEntry {
        leaf_hash: leaves[2],
        proof_path: vec![leaves[3], h01],
        index: 2,
        tree_size: 4,
    };

    verify_rekor_inclusion(&entry, &leaves[2], &root)
        .expect("valid inclusion proof should verify");

    // Also verify leaf index 1 (L1):
    // sibling: L0 (left sibling)
    // then: h23 (right sibling)
    let entry1 = RekorEntry {
        leaf_hash: leaves[1],
        proof_path: vec![leaves[0], h23],
        index: 1,
        tree_size: 4,
    };
    verify_rekor_inclusion(&entry1, &leaves[1], &root)
        .expect("valid inclusion proof for index 1 should verify");
}

// ── 2. tampered leaf rejected ─────────────────────────────────────────────────

#[test]
fn tampered_leaf_rejected() {
    let (root, leaves) = build_4leaf_tree();
    let h01 = inner_hash(&leaves[0], &leaves[1]);

    let mut tampered_leaf = leaves[2];
    tampered_leaf[0] ^= 0x01; // flip one bit

    let entry = RekorEntry {
        leaf_hash: tampered_leaf,
        proof_path: vec![leaves[3], h01],
        index: 2,
        tree_size: 4,
    };

    // payload_hash is still the real leaf — mismatch triggers error
    let err = verify_rekor_inclusion(&entry, &leaves[2], &root).unwrap_err();
    assert!(
        matches!(err, AttestError::RekorProofInvalid { .. }),
        "expected RekorProofInvalid, got {err:?}"
    );
}
