//! Rekor Merkle inclusion proof verification (feature = "rekor").
//!
//! Implements RFC 9162 §2.1.1 inclusion proof algorithm for a Merkle Hash
//! Tree (MHT) using SHA-256.
//!
//! Leaf hashes: `SHA-256(0x00 || leaf_content)`
//! Inner hashes: `SHA-256(0x01 || left || right)`
//!
//! The ordering of siblings (left vs right) is determined by the bit of the
//! leaf index at the current proof depth.

#![cfg(feature = "rekor")]

use sha2::{Digest, Sha256};

use crate::error::{AttestError, RekorSource};

/// A Rekor log entry with its Merkle inclusion proof.
#[derive(Clone, Debug)]
pub struct RekorEntry {
    /// SHA-256 leaf hash as stored in the Merkle tree.
    pub leaf_hash: [u8; 32],
    /// Proof path: sibling hashes from leaf level to root (exclusive).
    pub proof_path: Vec<[u8; 32]>,
    /// 0-based index of this leaf in the tree.
    pub index: u64,
    /// Total number of leaves in the tree at time of proof.
    pub tree_size: u64,
}

/// Verify a Rekor Merkle inclusion proof per RFC 9162 §2.1.1.
///
/// # Checks
///
/// 1. `payload_hash == entry.leaf_hash` — rejects substituted leaf data.
/// 2. The proof path reconstructs `tree_root` starting from `leaf_hash`.
///
/// # Returns
///
/// `Ok(())` if the proof is valid; [`AttestError::RekorProofInvalid`] otherwise.
pub fn verify_rekor_inclusion(
    entry: &RekorEntry,
    payload_hash: &[u8; 32],
    tree_root: &[u8; 32],
) -> Result<(), AttestError> {
    // ── 1. payload_hash must match the leaf hash in the entry ─────────────────
    if entry.leaf_hash != *payload_hash {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("leaf hash does not match payload hash"),
        });
    }

    // ── 2. Walk the proof path ────────────────────────────────────────────────
    let mut current = entry.leaf_hash;
    let mut index = entry.index;

    for sibling in &entry.proof_path {
        if index & 1 == 0 {
            // current is a left child — sibling is on the right
            current = inner_hash(&current, sibling);
        } else {
            // current is a right child — sibling is on the left
            current = inner_hash(sibling, &current);
        }
        index >>= 1;
    }

    // ── 3. Compare reconstructed root ─────────────────────────────────────────
    if current != *tree_root {
        return Err(AttestError::RekorProofInvalid {
            source: RekorSource("reconstructed root does not match expected tree root"),
        });
    }

    Ok(())
}

/// RFC 9162 inner node hash: `SHA-256(0x01 || left || right)`.
fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left.as_slice());
    h.update(right.as_slice());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn leaf_hash_for(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(data);
        h.finalize().into()
    }

    #[test]
    fn single_leaf_tree_verifies() {
        // A tree with one leaf: root == leaf_hash
        let lh = leaf_hash_for(b"only-leaf");
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![],
            index: 0,
            tree_size: 1,
        };
        verify_rekor_inclusion(&entry, &lh, &lh).expect("single-leaf tree");
    }

    #[test]
    fn wrong_payload_hash_rejected() {
        let lh = leaf_hash_for(b"leaf");
        let mut wrong = lh;
        wrong[0] ^= 0xff;
        let entry = RekorEntry {
            leaf_hash: lh,
            proof_path: vec![],
            index: 0,
            tree_size: 1,
        };
        let err = verify_rekor_inclusion(&entry, &wrong, &lh).unwrap_err();
        assert!(matches!(err, AttestError::RekorProofInvalid { .. }));
    }
}
