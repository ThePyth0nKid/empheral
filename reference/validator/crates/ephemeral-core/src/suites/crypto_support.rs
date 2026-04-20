//! Shared glue for suites that run optional live COSE_Sign1 verification.
//!
//! Vectors may carry a `cose_sign1_bytes` (hex) field and a
//! `trust_anchor_keys` list. When both are present, the suite calls
//! [`verify_with_defs`] to perform real Ed25519 verification via the
//! `ephemeral-crypto` crate. When absent, the suite falls back to its
//! existing mock `signature_valid` boolean so the 515 mock-era vectors
//! stay green without modification.
//!
//! ## Role discrimination (Phase C.3-C)
//!
//! Each vector-supplied anchor carries an optional `role` field. When
//! present, it must parse to a variant of
//! [`AnchorRole`](ephemeral_crypto::AnchorRole). When absent, the
//! suite-supplied `default_role` is used — tariff passes
//! `AnchorRole::TariffSigner`, delegation passes
//! `AnchorRole::DelegationSigner`, classifier passes
//! `AnchorRole::ClassifierSigner`. This keeps the legacy vector JSON
//! (which never declared a role) valid while allowing newer vectors
//! to register cross-role anchors for negative tests.

use serde::Deserialize;

use ephemeral_crypto::{
    verify_cose_sign1, AnchorRole, CoseError, TrustAnchor, TrustAnchorSet, VerifiedPayload,
};

/// Per-anchor key record supplied by a vector. Deliberately flat so that
/// vectors read naturally:
///
/// ```json
/// "trust_anchor_keys": [
///   { "kid": "K_cust_root_pk_TEST", "alg": "ed25519", "pk_hex": "..." }
/// ]
/// ```
///
/// The optional `role` field (added in Phase C.3-C) overrides the
/// suite's default role when present. Unknown algorithms are rejected
/// at anchor-set assembly time — the live verify never gets a chance
/// to surface the mismatch downstream.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct TrustAnchorKeyDef {
    pub kid: String,
    pub alg: String,
    pub pk_hex: String,
    #[serde(default)]
    pub role: Option<String>,
}

/// Build a [`TrustAnchorSet`] from vector-supplied key records.
///
/// `default_role` is the caller-suite's role stamp applied to any
/// def that omits the optional `role` field. This preserves the
/// invariant that every anchor carries an explicit role while letting
/// legacy vectors (authored before Phase C.3-C) continue to parse
/// without rewriting their JSON.
///
/// Returns [`CoseError::UnknownAlgString`] on a non-Ed25519 alg label
/// (the offending string is carried, truncated to ≤ 64 bytes at a
/// char boundary so adversarial JSON cannot bloat the error surface),
/// [`CoseError::HexDecode`] on malformed `pk_hex`,
/// [`CoseError::InvalidAnchorRole`] on an unknown role string, and
/// whatever [`TrustAnchor::new_ed25519`] surfaces for bad key bytes
/// (wrong length, weak point).
pub(super) fn build_anchor_set(
    defs: &[TrustAnchorKeyDef],
    default_role: AnchorRole,
) -> Result<TrustAnchorSet, CoseError> {
    let mut set = TrustAnchorSet::new();
    for def in defs {
        if !def.alg.eq_ignore_ascii_case("ed25519") {
            // Carry the offending wire string verbatim (char-boundary
            // truncated to ≤ 64 bytes) rather than the old sentinel
            // `UnsupportedAlg { alg: 0 }` — downstream logs now tell
            // the vector author *which* alg label was rejected.
            let mut trimmed = String::new();
            for c in def.alg.chars() {
                if trimmed.len() + c.len_utf8() > 64 {
                    break;
                }
                trimmed.push(c);
            }
            return Err(CoseError::UnknownAlgString { label: trimmed });
        }
        let role = match def.role.as_deref() {
            Some(s) => AnchorRole::from_wire_str(s)?,
            None => default_role,
        };
        let pk_bytes = hex::decode(&def.pk_hex).map_err(|_| CoseError::HexDecode)?;
        let anchor = TrustAnchor::new_ed25519(def.kid.clone(), &pk_bytes, role)?;
        set.insert(anchor)?;
    }
    Ok(set)
}

/// Hex-decode a COSE_Sign1 blob, build the anchor set, and verify.
///
/// Convenience wrapper that merges the three-step dance into a single
/// call site so the tariff / delegation / classifier pipelines read
/// cleanly at their signature-check step. `expected_role` is the role
/// under which kid resolution happens in the verifier; it is also the
/// default role assigned to any def that omits an explicit `role`
/// field, so `trust_anchor_keys` in legacy vectors continue to work
/// unchanged.
pub(super) fn verify_with_defs(
    cose_hex: &str,
    anchor_defs: &[TrustAnchorKeyDef],
    aad: &[u8],
    expected_role: AnchorRole,
) -> Result<VerifiedPayload, CoseError> {
    let cose_bytes = hex::decode(cose_hex).map_err(|_| CoseError::HexDecode)?;
    let anchors = build_anchor_set(anchor_defs, expected_role)?;
    verify_cose_sign1(&cose_bytes, &anchors, aad, expected_role)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed Ed25519 public key — round-trip test vector from
    /// RFC 8032 §7.1. Using a known-good key avoids the need to spin up
    /// `ed25519-dalek` in dev-deps here (the test verifies role wiring,
    /// not the underlying crypto, which is already covered by
    /// `ephemeral-crypto`'s own test-suite).
    const TEST_PK_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    /// Reverse role-confusion: a vector JSON supplying a
    /// `role: "classifier-signer"` string registers the anchor as
    /// [`AnchorRole::ClassifierSigner`] in the set. Tariff step 6 looks
    /// up under [`AnchorRole::TariffSigner`], which cannot resolve a
    /// classifier-role anchor — the lookup returns `None` and the
    /// verification pipeline surfaces [`CoseError::UnknownKid`] so
    /// that role assignments stay unobservable to an attacker probing
    /// the anchor set.
    ///
    /// Mirrors the classifier-side test that asserts the forward
    /// direction (see `step_9_5_rejects_classifier_role_mismatch_in_anchor_def`
    /// in `suites::tariff`): neither pipeline accepts the other's
    /// role anchor.
    #[test]
    fn build_anchor_set_role_override_prevents_reverse_role_confusion() {
        let defs = vec![TrustAnchorKeyDef {
            kid: "K_dual_use_kid".to_string(),
            alg: "ed25519".to_string(),
            pk_hex: TEST_PK_HEX.to_string(),
            role: Some("classifier-signer".to_string()),
        }];

        // Default role = TariffSigner (simulating a tariff step-6 call
        // site). The explicit "classifier-signer" override must win,
        // landing the anchor under ClassifierSigner.
        let set = build_anchor_set(&defs, AnchorRole::TariffSigner)
            .expect("build_anchor_set accepts well-formed def");

        // Tariff-style lookup must NOT resolve — role mismatch.
        assert!(
            set.lookup_with_role("K_dual_use_kid", AnchorRole::TariffSigner)
                .is_none(),
            "classifier-role anchor must not resolve under tariff-role lookup"
        );

        // Classifier-style lookup DOES resolve — confirms the override
        // actually took effect (otherwise the test would tautologically
        // pass even if role-override were a no-op).
        assert!(
            set.lookup_with_role("K_dual_use_kid", AnchorRole::ClassifierSigner)
                .is_some(),
            "classifier-role anchor must resolve under classifier-role lookup"
        );
    }

    /// Complementary: unknown role strings surface as
    /// [`CoseError::InvalidAnchorRole`] with the offending string
    /// carried (truncated). Guards against a silent fallback to the
    /// default role for typos like `"classifier_signer"` (underscore
    /// instead of hyphen).
    #[test]
    fn build_anchor_set_rejects_unknown_role_string_with_verbatim_label() {
        let defs = vec![TrustAnchorKeyDef {
            kid: "K_test".to_string(),
            alg: "ed25519".to_string(),
            pk_hex: TEST_PK_HEX.to_string(),
            role: Some("classifier_signer".to_string()), // typo: underscore
        }];
        let err = build_anchor_set(&defs, AnchorRole::ClassifierSigner).unwrap_err();
        match err {
            CoseError::InvalidAnchorRole { role } => {
                assert_eq!(role, "classifier_signer");
            }
            other => panic!("expected InvalidAnchorRole, got {other:?}"),
        }
    }

    /// M-5 companion: the new `UnknownAlgString` variant carries the
    /// offending alg wire string (truncated) instead of the pre-fix
    /// sentinel `UnsupportedAlg { alg: 0 }`. Downstream logs can now
    /// identify the rejected alg label rather than seeing a confusing
    /// "alg label 0".
    #[test]
    fn build_anchor_set_rejects_unknown_alg_with_verbatim_label() {
        let defs = vec![TrustAnchorKeyDef {
            kid: "K_test".to_string(),
            alg: "es256".to_string(), // not yet supported
            pk_hex: TEST_PK_HEX.to_string(),
            role: None,
        }];
        let err = build_anchor_set(&defs, AnchorRole::TariffSigner).unwrap_err();
        match err {
            CoseError::UnknownAlgString { label } => {
                assert_eq!(label, "es256");
            }
            other => panic!("expected UnknownAlgString, got {other:?}"),
        }
    }

    /// Oversize alg strings must be truncated to ≤ 64 bytes at a
    /// char boundary (same contract as `AnchorRole::from_wire_str`).
    #[test]
    fn build_anchor_set_truncates_oversize_alg_label() {
        let huge = "x".repeat(10_000);
        let defs = vec![TrustAnchorKeyDef {
            kid: "K_test".to_string(),
            alg: huge,
            pk_hex: TEST_PK_HEX.to_string(),
            role: None,
        }];
        let err = build_anchor_set(&defs, AnchorRole::TariffSigner).unwrap_err();
        match err {
            CoseError::UnknownAlgString { label } => {
                assert!(label.len() <= 64, "label must be truncated to ≤ 64 bytes");
                assert!(label.chars().all(|c| c == 'x'));
            }
            other => panic!("expected UnknownAlgString, got {other:?}"),
        }
    }
}
