//! Delegation chain cryptographic primitives (Phase C.1 MVP).
//!
//! Per-link COSE_Sign1 signature verification only. The chain's structural
//! invariants — parent→child linkage, role hierarchy, revocation,
//! scope-match — live in `ephemeral-core::suites::delegation` because they
//! are suite-specific. This crate supplies the crypto primitive that the
//! delegation executor calls once per link.

use crate::anchors::{AnchorRole, TrustAnchor, TrustAnchorSet};
use crate::error::CoseError;
use crate::verify::{verify_cose_sign1, VerifiedPayload};

/// Maximum delegation chain length per spec §7.3.1. Mirrors
/// `ephemeral-core::suites::delegation::MAX_CHAIN_LINKS`.
pub const MAX_CHAIN_DEPTH: usize = 3;

/// Verify a single delegation link's COSE_Sign1 against its parent anchor.
///
/// The parent anchor is the previous link's verified child key (or the
/// pinned root trust anchor for the first link). `aad` is the domain
/// separation tag (e.g. `b"delegation-link"`). `expected_role` is the
/// signer-role context enforced at kid lookup — delegation chains
/// always pass [`AnchorRole::DelegationSigner`], but the parameter is
/// kept explicit so the primitive documents its own role assumption
/// at the call site.
///
/// Callers build the per-link anchor from the verified payload of the
/// previous link; for the first link it's the root trust anchor set.
pub fn verify_chain_link(
    cose_bytes: &[u8],
    parent_anchor: &TrustAnchor,
    aad: &[u8],
    expected_role: AnchorRole,
) -> Result<VerifiedPayload, CoseError> {
    let mut set = TrustAnchorSet::new();
    set.insert(parent_anchor.clone())?;
    verify_cose_sign1(cose_bytes, &set, aad, expected_role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_depth_constant_matches_spec() {
        // Spec §7.3.1: at most 3 DelegationDocument entries (4 keys total:
        // root + up to 2 intermediates + terminal). Guard against
        // accidental constant drift.
        assert_eq!(MAX_CHAIN_DEPTH, 3);
    }
}
