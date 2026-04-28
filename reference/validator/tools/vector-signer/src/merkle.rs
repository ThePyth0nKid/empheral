//! RFC 9162 §2.1.1 Merkle Hash Tree — reference implementation used by
//! the `gen-phase-c2-5` subcommand to manufacture deterministic inclusion
//! proofs for the eight Phase C.2.5 transparency-log reject vectors.
//!
//! # Why re-implement instead of reusing `ephemeral_attestation::rekor`?
//!
//! The vector-signer is the *producer* of proofs that
//! `ephemeral_attestation::rekor::verify_rekor_inclusion` then *consumes*.
//! Keeping the producer self-contained (no path dep back up into the
//! validator's public API, no shared "merkle helpers" crate) means the
//! two implementations are independent cross-checks: a bug that sneaks
//! into one is unlikely to mirror into the other, so a proptest roundtrip
//! (`generate_proof` → `verify_rekor_inclusion` → `Ok(())`) catches both.
//!
//! # Hash conventions
//!
//! - Leaf:  `SHA-256(0x00 || leaf_content)`
//! - Inner: `SHA-256(0x01 || left || right)`
//!
//! # Tree layout
//!
//! RFC 9162 §2.1 is *left-deep*: for `D[n]` with `n > 1`, split at
//! `k = largest power of 2 strictly less than n`, recurse on `D[0..k]`
//! and `D[k..n]`, and combine their roots. That is the shape both
//! `build_tree` and `generate_proof` reproduce.

use sha2::{Digest, Sha256};

/// RFC 9162 §2.1.1 leaf hash: `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(data);
    h.finalize().into()
}

/// RFC 9162 §2.1.1 inner hash: `SHA-256(0x01 || left || right)`.
pub fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left.as_slice());
    h.update(right.as_slice());
    h.finalize().into()
}

/// Compute the RFC 9162 §2.1.1 Merkle tree head (MTH) over `leaves`.
///
/// - `leaves.len() == 0` is a programming error: the caller asked for the
///   root of an empty tree, which RFC 9162 does not define. We panic here
///   because the vector-signer is the sole caller and always has at least
///   one leaf; validators receiving `tree_size == 0` reject before calling
///   anything.
/// - `leaves.len() == 1` returns `leaf_hash(&leaves[0])`.
///
/// Only compiled for `#[cfg(test)]` because production vector building goes
/// through [`generate_proof`] (which returns the root alongside the audit
/// path); the unit tests exercise the MTH derivation directly.
///
/// # Panics
///
/// Panics if `leaves` is empty.
#[cfg(test)]
pub fn build_tree(leaves: &[Vec<u8>]) -> [u8; 32] {
    assert!(
        !leaves.is_empty(),
        "build_tree: empty leaves not defined by RFC 9162"
    );
    let hashed: Vec<[u8; 32]> = leaves.iter().map(|d| leaf_hash(d)).collect();
    subtree_root(&hashed)
}

/// Compute the MTH over a slice of already-hashed leaves.
fn subtree_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split_point(leaves.len());
    let left = subtree_root(&leaves[..k]);
    let right = subtree_root(&leaves[k..]);
    inner_hash(&left, &right)
}

/// Largest power of two strictly less than `n` (RFC 9162 split point `k`).
///
/// Caller must ensure `n >= 2`.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2, "split_point requires n >= 2");
    // `ilog2` floors the log, so `1 << (n-1).ilog2()` gives the largest
    // power of two that is <= n-1, which equals the largest power of two
    // strictly less than n for all n >= 2.
    1usize << (n - 1).ilog2()
}

/// Generate an RFC 9162 §2.1.3 `PATH(index, D\[n\])` inclusion proof for
/// the leaf at `index`, plus the tree's root (for convenience).
///
/// Returns `(audit_path, root)` where `audit_path` is ordered from
/// leaf-level to root-level (deepest sibling first), matching the order
/// consumed by [`ephemeral_attestation::rekor::verify_rekor_inclusion`].
///
/// # Panics
///
/// - `leaves` empty: root undefined.
/// - `index >= leaves.len() as u64`: index out of bounds.
pub fn generate_proof(leaves: &[Vec<u8>], index: u64) -> (Vec<[u8; 32]>, [u8; 32]) {
    assert!(
        !leaves.is_empty(),
        "generate_proof: leaves must be non-empty"
    );
    let idx_usize = usize::try_from(index).expect("index fits in usize on this host");
    assert!(
        idx_usize < leaves.len(),
        "generate_proof: index {} out of range for tree_size {}",
        idx_usize,
        leaves.len()
    );

    let hashed: Vec<[u8; 32]> = leaves.iter().map(|d| leaf_hash(d)).collect();
    let mut path = Vec::new();
    build_path(&hashed, idx_usize, &mut path);
    let root = subtree_root(&hashed);
    (path, root)
}

/// Recursive `PATH(m, D\[n\])` builder. Mirrors RFC 9162 §2.1.3:
///
/// - If `leaves.len() == 1`: proof is empty.
/// - Else split at `k = split_point(n)`. If `m < k`, descend left and
///   append the right subtree's root; otherwise descend right (with
///   `m -= k`) and append the left subtree's root.
///
/// Appending *after* the recursive call yields the leaf→root ordering
/// consumed by the verifier.
fn build_path(leaves: &[[u8; 32]], m: usize, out: &mut Vec<[u8; 32]>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split_point(leaves.len());
    if m < k {
        build_path(&leaves[..k], m, out);
        out.push(subtree_root(&leaves[k..]));
    } else {
        build_path(&leaves[k..], m - k, out);
        out.push(subtree_root(&leaves[..k]));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_and_inner_hash_known_values() {
        // Known vector: leaf_hash(b"") == SHA-256(0x00).
        let lh_empty = leaf_hash(b"");
        let mut h = Sha256::new();
        h.update([0x00u8]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(lh_empty, expected);

        // Inner hash of two all-zero children.
        let zero = [0u8; 32];
        let ih = inner_hash(&zero, &zero);
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(zero);
        h.update(zero);
        let expected_ih: [u8; 32] = h.finalize().into();
        assert_eq!(ih, expected_ih);
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let leaves = vec![b"solo".to_vec()];
        assert_eq!(build_tree(&leaves), leaf_hash(b"solo"));
    }

    #[test]
    fn two_leaf_tree_balanced() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec()];
        let expected = inner_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        assert_eq!(build_tree(&leaves), expected);
    }

    #[test]
    fn three_leaf_tree_left_deep() {
        // RFC layout: root = inner(inner(L0, L1), L2).
        let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let la = leaf_hash(b"a");
        let lb = leaf_hash(b"b");
        let lc = leaf_hash(b"c");
        let expected = inner_hash(&inner_hash(&la, &lb), &lc);
        assert_eq!(build_tree(&leaves), expected);
    }

    #[test]
    fn generate_proof_three_leaf_right_edge() {
        // The orphan-right-edge case that exposed the Block A bug.
        let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let la = leaf_hash(b"a");
        let lb = leaf_hash(b"b");
        let h_ab = inner_hash(&la, &lb);

        let (path, root) = generate_proof(&leaves, 2);
        assert_eq!(path, vec![h_ab]);
        assert_eq!(root, inner_hash(&h_ab, &leaf_hash(b"c")));
    }

    #[test]
    fn generate_proof_seven_leaf_sample_indices() {
        // Exercises every branch of the split-point recursion.
        let leaves: Vec<Vec<u8>> = (0..7).map(|i| format!("leaf-{i}").into_bytes()).collect();
        let hashed: Vec<[u8; 32]> = leaves.iter().map(|d| leaf_hash(d)).collect();
        let h01 = inner_hash(&hashed[0], &hashed[1]);
        let h23 = inner_hash(&hashed[2], &hashed[3]);
        let h45 = inner_hash(&hashed[4], &hashed[5]);
        let h0_3 = inner_hash(&h01, &h23);
        let h4_6 = inner_hash(&h45, &hashed[6]);
        let root = inner_hash(&h0_3, &h4_6);

        assert_eq!(build_tree(&leaves), root);

        let (p3, r) = generate_proof(&leaves, 3);
        assert_eq!(p3, vec![hashed[2], h01, h4_6]);
        assert_eq!(r, root);

        let (p6, r) = generate_proof(&leaves, 6);
        assert_eq!(p6, vec![h45, h0_3]);
        assert_eq!(r, root);
    }

    // ── Roundtrip proptest: generate_proof ↔ verify_rekor_inclusion ──────────

    use ephemeral_attestation::rekor::{verify_rekor_inclusion, RekorEntry};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            .. ProptestConfig::default()
        })]

        /// For every tree_size in [1, 64] and every leaf index, the proof
        /// generated by this module MUST verify against the independent
        /// RFC 9162 §2.1.3.2 walk in `ephemeral_attestation::rekor`.
        #[test]
        fn generate_proof_roundtrips_through_verifier(
            (tree_size, index, seeds) in merkle_input_strategy(),
        ) {
            let leaves: Vec<Vec<u8>> = (0..tree_size)
                .map(|i| {
                    // Make leaves unique and collision-free across cases.
                    let mut v = Vec::with_capacity(16);
                    v.extend_from_slice(&seeds);
                    v.extend_from_slice(&i.to_be_bytes());
                    v
                })
                .collect();

            let (proof, root) = generate_proof(&leaves, index);
            let idx_usize = usize::try_from(index).expect("index fits in usize");
            let leaf = leaf_hash(&leaves[idx_usize]);
            let entry = RekorEntry {
                leaf_hash: leaf,
                proof_path: proof,
                index,
                tree_size: u64::from(tree_size),
            };

            prop_assert!(
                verify_rekor_inclusion(&entry, &leaf, &root).is_ok(),
                "roundtrip failed for tree_size={tree_size} index={index}"
            );
        }
    }

    /// Strategy yielding `(tree_size, index, per-case random seed bytes)`
    /// with `tree_size ∈ [1, 64]` and `index ∈ [0, tree_size)`.
    fn merkle_input_strategy() -> impl Strategy<Value = (u32, u64, [u8; 8])> {
        (1u32..=64).prop_flat_map(|tree_size| {
            (
                Just(tree_size),
                0u64..u64::from(tree_size),
                any::<[u8; 8]>(),
            )
        })
    }
}
