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

    verify_rekor_inclusion(&entry, &leaves[2], &root).expect("valid inclusion proof should verify");

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

// ── 3. unbalanced trees verify (RFC 9162 §2.1.3.2 cross-check) ───────────────
//
// Independently reconstructs the RFC-left-deep tree layout for every
// tree_size in {3, 5, 6, 7} and every leaf index, then hands the proof
// to [`verify_rekor_inclusion`]. The pre-fix naive parity walk failed on
// every right-edge orphan case (index 2 for n=3, index 4 for n=5, index
// 6 for n=7, etc.); this test is the integration-level regression guard.

/// Build the full leaf-hash list for `n` leaves with the helper above.
fn leaves_for(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
        .collect()
}

/// Recursive RFC 9162 §2.1.1 subtree root over `leaves[start..start+len]`.
fn subtree_root(leaves: &[[u8; 32]], start: usize, len: usize) -> [u8; 32] {
    if len == 1 {
        return leaves[start];
    }
    // k = largest power of 2 strictly less than len.
    let k = 1usize << (len - 1).ilog2();
    let left = subtree_root(leaves, start, k);
    let right = subtree_root(leaves, start + k, len - k);
    inner_hash(&left, &right)
}

/// Recursive RFC 9162 §2.1.1 PATH(m, D[n]) proof builder.
fn build_proof(leaves: &[[u8; 32]], start: usize, len: usize, m: usize) -> Vec<[u8; 32]> {
    if len <= 1 {
        return Vec::new();
    }
    let k = 1usize << (len - 1).ilog2();
    if m < k {
        // Descend left; sibling is the right subtree root.
        let mut inner = build_proof(leaves, start, k, m);
        inner.push(subtree_root(leaves, start + k, len - k));
        inner
    } else {
        // Descend right; sibling is the left subtree root.
        let mut inner = build_proof(leaves, start + k, len - k, m - k);
        inner.push(subtree_root(leaves, start, k));
        inner
    }
}

#[test]
fn unbalanced_trees_verify() {
    for &n in &[3usize, 5, 6, 7] {
        let leaves = leaves_for(n);
        let root = subtree_root(&leaves, 0, n);

        for m in 0..n {
            let proof = build_proof(&leaves, 0, n, m);
            let entry = RekorEntry {
                leaf_hash: leaves[m],
                proof_path: proof,
                index: m as u64,
                tree_size: n as u64,
            };
            verify_rekor_inclusion(&entry, &leaves[m], &root)
                .unwrap_or_else(|e| panic!("n={n}, m={m} must verify: {e:?}"));
        }
    }
}
