//! Shared glue for suites that run optional live COSE_Sign1 verification.
//!
//! Vectors may carry a `cose_sign1_bytes` (hex) field and a
//! `trust_anchor_keys` list. When both are present, the suite calls
//! [`verify_with_defs`] to perform real Ed25519 verification via the
//! `ephemeral-crypto` crate. When absent, the suite falls back to its
//! existing mock `signature_valid` boolean so the 515 mock-era vectors
//! stay green without modification.

use serde::Deserialize;

use ephemeral_crypto::{verify_cose_sign1, CoseError, TrustAnchor, TrustAnchorSet, VerifiedPayload};

/// Per-anchor key record supplied by a vector. Deliberately flat so that
/// vectors read naturally:
///
/// ```json
/// "trust_anchor_keys": [
///   { "kid": "K_cust_root_pk_TEST", "alg": "ed25519", "pk_hex": "..." }
/// ]
/// ```
///
/// Unknown algorithms are rejected at anchor-set assembly time — the
/// live verify never gets a chance to surface the mismatch downstream.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct TrustAnchorKeyDef {
    pub kid: String,
    pub alg: String,
    pub pk_hex: String,
}

/// Build a [`TrustAnchorSet`] from vector-supplied key records.
///
/// Returns [`CoseError::UnsupportedAlg`] on a non-Ed25519 alg label,
/// [`CoseError::HexDecode`] on malformed `pk_hex`, and whatever
/// [`TrustAnchor::new_ed25519`] surfaces for bad key bytes (wrong length,
/// weak point).
pub(super) fn build_anchor_set(
    defs: &[TrustAnchorKeyDef],
) -> Result<TrustAnchorSet, CoseError> {
    let mut set = TrustAnchorSet::new();
    for def in defs {
        if !def.alg.eq_ignore_ascii_case("ed25519") {
            // The integer label is unknown here (we only have the wire
            // string) — signal it with a sentinel `0` which downstream
            // callers never inspect.
            return Err(CoseError::UnsupportedAlg { alg: 0 });
        }
        let pk_bytes = hex::decode(&def.pk_hex).map_err(|_| CoseError::HexDecode)?;
        let anchor = TrustAnchor::new_ed25519(def.kid.clone(), &pk_bytes)?;
        set.insert(anchor)?;
    }
    Ok(set)
}

/// Hex-decode a COSE_Sign1 blob, build the anchor set, and verify.
///
/// Convenience wrapper that merges the three-step dance into a single
/// call site so the tariff / delegation pipelines read cleanly at
/// their signature-check step.
pub(super) fn verify_with_defs(
    cose_hex: &str,
    anchor_defs: &[TrustAnchorKeyDef],
    aad: &[u8],
) -> Result<VerifiedPayload, CoseError> {
    let cose_bytes = hex::decode(cose_hex).map_err(|_| CoseError::HexDecode)?;
    let anchors = build_anchor_set(anchor_defs)?;
    verify_cose_sign1(&cose_bytes, &anchors, aad)
}
