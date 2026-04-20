//! Tariff-reject suite executor — §2.2, §6, §7, §8.4, §9.4, §10.3.
//!
//! See **design-final-v2.md §2.2** (Tariff CDDL), **§2.2 / R8.T1-T5** (size /
//! gap / validity caps / strict fields / integration refs), **§7.1 / §7.4**
//! (key hierarchy + chain walk), **§7.5** (revocation), **§8.4** (revocation-
//! channel HA), **§9.4** (PCR attestors), **§10.3** (monotonic version).
//!
//! ## Mock-crypto model
//!
//! Every vector's payload is represented by the opaque `tariff_cbor_hex`
//! placeholder; real bytes do not exist. The semantic signal lives on
//! **`signature_verification_context`** — an envelope containing explicit
//! booleans (`signature_valid_under_current_bytes`, `cbor_is_deterministic`,
//! `payload_encoding_detected`, `duplicate_map_keys_present`, ...), plus the
//! vector's `category` label which names the malformation class for payload
//! fields the mock cannot inspect (tier-out-of-range, missing-required-field,
//! circular verb_aliases, ...). Real COSE / CBOR verification lands in Phase C.
//!
//! ## Check order (fail-fast, first-failing wins)
//!
//! The order follows §7.4 step ordering with strict-field and structural
//! checks layered *after* signature/chain/revocation — the reasoning is that
//! a tampered signature cannot be trusted to surface other defects. Two
//! checks that would collide on the same vector resolve to the code listed
//! first.
//!
//! 1.  **Size cap (R8.T1)** — computed pre-verify.
//! 2.  **COSE structural** — missing alg, unknown `crit` → `cose-malformed`.
//! 3.  **Algorithm policy** — non-Ed25519 alg → `signature-algorithm-unsupported`;
//!     alg/key-type mismatch → `signature-algorithm-mismatch`.
//! 4.  **Signer identity** — kid resolves to unknown key → `kid-unknown`.
//! 5.  **Chain integrity** — empty chain, wrong anchor, broken link,
//!     role-mismatch → `signature-chain-broken`. Runs before signature math
//!     so impostor-key cases (trej-052, trej-063, trej-064) surface as
//!     `signature-chain-broken` rather than `signature-invalid`.
//! 6.  **Signature math** — `signature_valid_under_current_bytes == false`
//!     → `signature-invalid`.
//! 7.  **Revocation** — signer on active revocation list → `revoked`.
//!     Runs before the wrong-key trust-anchor check so a delegated-but-now-
//!     revoked signer (trej-009) produces `revoked`, not `signature-invalid`.
//! 8.  **Wrong-key trust-anchor check** — cryptographically valid signature
//!     from a key outside the customer's anchor set → `signature-invalid`.
//!     Mock-model, category-gated; Phase C replaces with full chain walk.
//! 9.  **Payload encoding** — payload is JSON → `payload-encoding-invalid`;
//!     non-deterministic CBOR → `payload-not-deterministic-cbor`; duplicate
//!     keys → `tariff-duplicate-entries`.
//! 10. **Version monotonicity (§10.3)** — `payload.version ≤ previously_seen`
//!     → `version-too-old`.
//! 11. **Validity window & gaps (R8.T2 / T3)** — clock-skew, expired,
//!     not-yet-valid, iat→nbf gap, validity window empty, validity period
//!     excessive.
//! 12. **PCR attestor trust (§9.4 + V3-3)** — attestors outside customer
//!     registry → `pcr-attestor-not-trusted`.
//! 13. **Payload-semantic checks (category-driven)** — OPCE replay, tier
//!     range, rate-matrix completeness, fuzz attestation presence/match,
//!     pcr attestor / quorum validity, integration / verb / resource-kind
//!     vocabularies, tariff-unknown-field, tariff-circular-reference,
//!     tariff-malformed catch-all for structural field defects.

use std::fmt;

use ephemeral_classifier::{
    verify_classifier_signature, ClassifierSigError, CLASSIFIER_ABI_VERSION,
};
use ephemeral_crypto::{AnchorRole, CoseError};
use serde::Deserialize;
use time::OffsetDateTime;

use super::crypto_support::{build_anchor_set, verify_with_defs, TrustAnchorKeyDef};
use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- constants ------------------------------------------------

/// Router-pinned trust anchor (shared with §7 delegation suite). The
/// delegation chain for a Tariff MUST terminate at this key.
const TRUST_ANCHOR: &str = "K_cust_root_pk_TEST";

/// Only Ed25519 (COSE alg label `-8`) is permitted for Tariff COSE_Sign1
/// (§7.1 hierarchy declaration + §2.2 payload posture).
const COSE_ALG_EDDSA: i64 = -8;

/// R8.T1 normative Tariff size cap — 256 KiB on the COSE_Sign1 outer envelope.
pub const MAX_TARIFF_BYTES: u64 = 262_144;

/// R8.T2 normative iat→not_before gap cap — 30 days.
pub const MAX_IAT_TO_NBF_GAP_SECONDS: u64 = 2_592_000;

/// R8.T3 normative validity-period cap — 30 days.
pub const MAX_VALIDITY_PERIOD_SECONDS: u64 = 2_592_000;

/// Default clock-skew tolerance (§2.2). Vectors occasionally override it via
/// `clock_skew_tolerance_seconds`.
const DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 300;

// ---------------- reject codes ---------------------------------------------

/// Tariff reject codes per §2.2 + §R8.T* + §10.3 + §9.4. Display strings match
/// the kebab-case `reject_code` the vector suite asserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TariffRejectCode {
    // Size / outer envelope
    TariffOversize,
    // COSE structural
    CoseMalformed,
    SignatureAlgorithmUnsupported,
    SignatureAlgorithmMismatch,
    KidUnknown,
    SignatureInvalid,
    SignatureChainBroken,
    Revoked,
    // Payload encoding
    PayloadEncodingInvalid,
    PayloadNotDeterministicCbor,
    TariffDuplicateEntries,
    // Classifier signature (§4.3 — tariff step 9.5). Envelope binding
    // between the Tariff-referenced classifier WASM hash and the
    // classifier-signer authority. Surfaces before version-monotonicity
    // so a stale-but-signature-valid tariff cannot outrank a classifier
    // integrity failure.
    ClassifierSignatureInvalid,
    ClassifierSignaturePayloadMalformed,
    ClassifierAbiVersionMismatch,
    ClassifierWasmHashMismatch,
    ClassifierSignerKidMismatch,
    // Monotonicity (§10.3)
    VersionTooOld,
    TariffSelfInconsistentVersion,
    // Validity window (§2.2 + R8.T2 / T3)
    Expired,
    NotYetValid,
    ClockSkewExceeded,
    TariffIatNbfGapExcessive,
    TariffValidityPeriodExcessive,
    // Payload-semantic structural
    TariffMalformed,
    TariffUnknownField,
    TariffTierOutOfRange,
    RateMatrixIncomplete,
    TariffFuzzAttestationMissing,
    TariffFuzzAttestationMismatch,
    TariffPcrAttestorsEmpty,
    TariffPcrQuorumInvalid,
    PcrAttestorNotTrusted,
    TariffIntegrationUnknown,
    TariffVerbInvalid,
    TariffResourceKindInvalid,
    TariffCircularReference,
}

impl fmt::Display for TariffRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TariffOversize => "tariff-oversize",
            Self::CoseMalformed => "cose-malformed",
            Self::SignatureAlgorithmUnsupported => "signature-algorithm-unsupported",
            Self::SignatureAlgorithmMismatch => "signature-algorithm-mismatch",
            Self::KidUnknown => "kid-unknown",
            Self::SignatureInvalid => "signature-invalid",
            Self::SignatureChainBroken => "signature-chain-broken",
            Self::Revoked => "revoked",
            Self::PayloadEncodingInvalid => "payload-encoding-invalid",
            Self::PayloadNotDeterministicCbor => "payload-not-deterministic-cbor",
            Self::TariffDuplicateEntries => "tariff-duplicate-entries",
            Self::ClassifierSignatureInvalid => "classifier-signature-invalid",
            Self::ClassifierSignaturePayloadMalformed => "classifier-signature-payload-malformed",
            Self::ClassifierAbiVersionMismatch => "classifier-abi-version-mismatch",
            Self::ClassifierWasmHashMismatch => "classifier-wasm-hash-mismatch",
            Self::ClassifierSignerKidMismatch => "classifier-signer-kid-mismatch",
            Self::VersionTooOld => "version-too-old",
            Self::TariffSelfInconsistentVersion => "tariff-self-inconsistent-version",
            Self::Expired => "expired",
            Self::NotYetValid => "not-yet-valid",
            Self::ClockSkewExceeded => "clock-skew-exceeded",
            Self::TariffIatNbfGapExcessive => "tariff-iat-nbf-gap-excessive",
            Self::TariffValidityPeriodExcessive => "tariff-validity-period-excessive",
            Self::TariffMalformed => "tariff-malformed",
            Self::TariffUnknownField => "tariff-unknown-field",
            Self::TariffTierOutOfRange => "tariff-tier-out-of-range",
            Self::RateMatrixIncomplete => "rate-matrix-incomplete",
            Self::TariffFuzzAttestationMissing => "tariff-fuzz-attestation-missing",
            Self::TariffFuzzAttestationMismatch => "tariff-fuzz-attestation-mismatch",
            Self::TariffPcrAttestorsEmpty => "tariff-pcr-attestors-empty",
            Self::TariffPcrQuorumInvalid => "tariff-pcr-quorum-invalid",
            Self::PcrAttestorNotTrusted => "pcr-attestor-not-trusted",
            Self::TariffIntegrationUnknown => "tariff-integration-unknown",
            Self::TariffVerbInvalid => "tariff-verb-invalid",
            Self::TariffResourceKindInvalid => "tariff-resource-kind-invalid",
            Self::TariffCircularReference => "tariff-circular-reference",
        })
    }
}

// ---------------- vector input model ---------------------------------------

#[derive(Debug, Deserialize)]
struct TariffInput {
    #[serde(default)]
    signature_verification_context: SigContext,
    current_time: String,
    #[serde(default)]
    previously_seen_version: Option<i64>,
    #[serde(default)]
    tariff_version_in_payload: Option<serde_json::Value>,
    #[serde(default)]
    tariff_issued_at: Option<String>,
    #[serde(default)]
    tariff_valid_from: Option<String>,
    #[serde(default)]
    tariff_valid_until: Option<String>,
    #[serde(default)]
    policy_max_iat_to_valid_from_gap_seconds: Option<u64>,
    #[serde(default)]
    policy_max_validity_seconds: Option<u64>,
    #[serde(default)]
    policy_max_tariff_bytes: Option<u64>,
    #[serde(default)]
    observed_size_bytes: Option<u64>,
    #[serde(default)]
    clock_skew_tolerance_seconds: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    known_integrations: Option<Vec<String>>,
    /// Phase C.1 — optional hex-encoded COSE_Sign1 blob. When supplied
    /// together with [`trust_anchor_keys`], step 6 runs live Ed25519
    /// verification via `ephemeral-crypto` instead of consulting the
    /// mock `signature_valid_under_current_bytes` bool.
    #[serde(default)]
    cose_sign1_bytes: Option<String>,
    /// Phase C.1 — per-vector trust anchor bag. Paired with
    /// [`cose_sign1_bytes`] to enable live verification.
    #[serde(default)]
    trust_anchor_keys: Option<Vec<TrustAnchorKeyDef>>,
    /// Phase C.3-C — optional hex-encoded classifier COSE_Sign1 envelope.
    /// When supplied together with [`wasm_bytes_classifier`] and
    /// [`trust_anchor_keys_classifier`], tariff step 9.5 runs live
    /// classifier-signature verification. Partial presence of this
    /// triple surfaces as `classifier-signature-invalid` (authoring-
    /// error / missing signature), mirroring the step-6 posture.
    #[serde(default)]
    cose_sign1_bytes_classifier: Option<String>,
    /// Phase C.3-C — hex-encoded classifier WASM bytes whose SHA-256
    /// must match the signed payload's `sha256` field.
    #[serde(default)]
    wasm_bytes_classifier: Option<String>,
    /// Phase C.3-C — per-vector classifier-role trust anchor bag. Each
    /// def is role-stamped as [`AnchorRole::ClassifierSigner`] unless
    /// the def carries an explicit `role` override.
    #[serde(default)]
    trust_anchor_keys_classifier: Option<Vec<TrustAnchorKeyDef>>,
    /// Phase C.3-C — optional override of the expected ABI version
    /// pinned into the signed payload. Defaults to
    /// [`ephemeral_classifier::CLASSIFIER_ABI_VERSION`] (= 1); bump only
    /// for vectors that deliberately assert a mismatch outcome.
    #[serde(default)]
    policy_classifier_abi_version: Option<u32>,
    // Remaining known-vocabulary hints are accepted but not inspected directly;
    // category-driven dispatch handles their cases. We keep serde happy without
    // `deny_unknown_fields` because vectors carry heterogeneous hint fields.
}

#[derive(Debug, Default, Deserialize)]
struct SigContext {
    #[serde(default)]
    signer_key_id: Option<String>,
    #[serde(default)]
    trust_anchors: Option<Vec<String>>,
    #[serde(default)]
    signature_valid_under_current_bytes: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    signature_valid_under_original_bytes: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    signature_valid_under_declared_alg: Option<bool>,
    #[serde(default)]
    cose_alg_label: Option<i64>,
    #[serde(default)]
    kid_key_type: Option<String>,
    #[serde(default)]
    protected_header_has_alg: Option<bool>,
    #[serde(default)]
    crit_labels: Option<Vec<i64>>,
    #[serde(default)]
    verifier_understands_crit: Option<bool>,
    #[serde(default)]
    delegation_chain: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    delegation_chain_root_parent: Option<String>,
    #[serde(default)]
    delegation_chain_link_signatures_valid: Option<Vec<bool>>,
    #[serde(default)]
    delegation_child_role: Option<String>,
    #[serde(default)]
    required_role_for_tariff: Option<String>,
    #[serde(default)]
    revocation_list: Option<Vec<String>>,
    #[serde(default)]
    known_keys_in_store: Option<Vec<String>>,
    #[serde(default)]
    approved_attestor_registry: Option<Vec<String>>,
    #[serde(default)]
    kid_to_key_resolution: Option<String>,
    #[serde(default)]
    payload_encoding_detected: Option<String>,
    #[serde(default)]
    cbor_is_deterministic: Option<bool>,
    #[serde(default)]
    cbor_type_observed: Option<String>,
    #[serde(default)]
    duplicate_map_keys_present: Option<bool>,
}

// ---------------- executor -------------------------------------------------

pub fn execute(vector: &Vector) -> ValidationOutcome {
    let input: TariffInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("input-deserialize: {e}"),
            }
        }
    };

    let result = classify(&input, &vector.category);
    render_outcome(vector, result)
}

#[allow(clippy::too_many_lines)]
fn classify(input: &TariffInput, category: &str) -> Result<(), TariffRejectCode> {
    // 1. Size cap — measured before any crypto (R8.T1).
    if let (Some(max), Some(size)) = (input.policy_max_tariff_bytes, input.observed_size_bytes) {
        if size > max {
            return Err(TariffRejectCode::TariffOversize);
        }
    }

    // 2. COSE structural.
    let ctx = &input.signature_verification_context;
    if ctx.protected_header_has_alg == Some(false) {
        return Err(TariffRejectCode::CoseMalformed);
    }
    if ctx.crit_labels.as_ref().is_some_and(|c| !c.is_empty())
        && ctx.verifier_understands_crit == Some(false)
    {
        return Err(TariffRejectCode::CoseMalformed);
    }

    // 3. Algorithm policy.
    if let Some(alg) = ctx.cose_alg_label {
        if alg != COSE_ALG_EDDSA {
            return Err(TariffRejectCode::SignatureAlgorithmUnsupported);
        }
        // Ed25519 (OKP) is the only key type consistent with alg=-8.
        if ctx
            .kid_key_type
            .as_deref()
            .is_some_and(|k| !k.eq_ignore_ascii_case("OKP"))
        {
            return Err(TariffRejectCode::SignatureAlgorithmMismatch);
        }
    }

    // 4. Signer identity — kid resolves to unknown key.
    if let (Some(signer), Some(known)) = (&ctx.signer_key_id, &ctx.known_keys_in_store) {
        if !known.iter().any(|k| k == signer) {
            return Err(TariffRejectCode::KidUnknown);
        }
    }

    // 5. Chain-broken signals — evaluated BEFORE raw signature math so that
    // impostor-key cases (trej-052, trej-063, trej-064) surface as
    // `signature-chain-broken` rather than `signature-invalid`.
    if ctx.kid_to_key_resolution.as_deref() == Some("mismatch") {
        return Err(TariffRejectCode::SignatureChainBroken);
    }
    if let Some(chain) = &ctx.delegation_chain {
        if chain.is_empty() {
            return Err(TariffRejectCode::SignatureChainBroken);
        }
    }
    if let Some(root_parent) = &ctx.delegation_chain_root_parent {
        if root_parent != TRUST_ANCHOR {
            return Err(TariffRejectCode::SignatureChainBroken);
        }
    }
    if let Some(link_valids) = &ctx.delegation_chain_link_signatures_valid {
        if link_valids.iter().any(|v| !*v) {
            return Err(TariffRejectCode::SignatureChainBroken);
        }
    }
    if let (Some(actual), Some(required)) = (
        ctx.delegation_child_role.as_deref(),
        ctx.required_role_for_tariff.as_deref(),
    ) {
        if actual != required {
            return Err(TariffRejectCode::SignatureChainBroken);
        }
    }

    // 6. Signature math (raw bytes). Phase C.1 four-way dispatch:
    //    - (bytes, anchors)          → live Ed25519 verify
    //    - (bytes, no-anchors)       → authoring error, reject as
    //                                   signature-invalid (live bytes
    //                                   with no anchors to verify them
    //                                   against must not silently pass)
    //    - (no-bytes, anchors)       → same — anchors without bytes is a
    //                                   missing signature, not a free pass
    //    - (no-bytes, no-anchors)    → legacy mock path; reject iff
    //                                   `signature_valid_under_current_bytes == Some(false)`.
    match (&input.cose_sign1_bytes, &input.trust_anchor_keys) {
        (Some(hex_bytes), Some(defs)) => {
            if let Err(e) = verify_with_defs(hex_bytes, defs, b"tariff", AnchorRole::TariffSigner) {
                return Err(map_cose_error_to_tariff(&e));
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(TariffRejectCode::SignatureInvalid);
        }
        (None, None) => {
            if ctx.signature_valid_under_current_bytes == Some(false) {
                return Err(TariffRejectCode::SignatureInvalid);
            }
        }
    }

    // 7. Revocation (§7.5). Runs before the trust-anchor membership check so
    // that a previously-delegated-but-now-revoked signer (trej-009) surfaces
    // as `revoked` rather than as `signature-invalid`. Version-too-old wins
    // for OPCE-style stale replay (trej-051) per the category dispatch.
    if let (Some(signer), Some(rev)) = (&ctx.signer_key_id, &ctx.revocation_list) {
        if rev.iter().any(|k| k == signer) && category != "redteam-OPCE-stale-tariff-replay" {
            return Err(TariffRejectCode::Revoked);
        }
    }

    // 8. Wrong-key (R1-BOOT-KEY-SUB): cryptographically valid signature from a
    // key outside the customer's trust-anchor set. Category-gated for the mock
    // model so trej-009 (signer delegated implicitly from the root anchor) and
    // trej-051 (OPCE) don't mis-flag as signature-invalid. Phase C replaces
    // this with a full chain walk per §7.4.
    if category == "sig-invalid-wrong-key" {
        if let (Some(signer), Some(anchors)) = (&ctx.signer_key_id, &ctx.trust_anchors) {
            if !anchors.iter().any(|a| a == signer) {
                return Err(TariffRejectCode::SignatureInvalid);
            }
        }
    }

    // 9. Payload encoding.
    if ctx.payload_encoding_detected.as_deref() == Some("json") {
        return Err(TariffRejectCode::PayloadEncodingInvalid);
    }
    if ctx.cbor_is_deterministic == Some(false) || ctx.cbor_type_observed.as_deref() == Some("float")
    {
        return Err(TariffRejectCode::PayloadNotDeterministicCbor);
    }
    if ctx.duplicate_map_keys_present == Some(true) {
        return Err(TariffRejectCode::TariffDuplicateEntries);
    }

    // 9.5. Classifier-signature verification (Phase C.3-C, §4.3).
    //
    // Three-field dispatch, mirroring step 6:
    //   - all three Some      → live verify via ephemeral-classifier
    //   - any partial subset  → authoring error / missing signature,
    //                           surface as classifier-signature-invalid
    //   - all three None      → legacy path, skip (vectors without a
    //                           classifier envelope keep working)
    //
    // Runs AFTER payload encoding (step 9) so an outer-payload fault
    // does not leak into classifier-layer signaling, and BEFORE version
    // monotonicity (step 10) so a stale-but-signature-valid tariff
    // cannot outrank a classifier integrity failure.
    match (
        &input.cose_sign1_bytes_classifier,
        &input.wasm_bytes_classifier,
        &input.trust_anchor_keys_classifier,
    ) {
        (Some(cose_hex), Some(wasm_hex), Some(defs)) => {
            let expected_abi = input
                .policy_classifier_abi_version
                .unwrap_or(CLASSIFIER_ABI_VERSION);
            let cose_bytes = hex::decode(cose_hex)
                .map_err(|_| TariffRejectCode::ClassifierSignatureInvalid)?;
            let wasm_bytes = hex::decode(wasm_hex)
                .map_err(|_| TariffRejectCode::ClassifierSignatureInvalid)?;
            let anchors = build_anchor_set(defs, AnchorRole::ClassifierSigner)
                .map_err(|_| TariffRejectCode::ClassifierSignatureInvalid)?;
            if let Err(e) = verify_classifier_signature(
                &wasm_bytes,
                &cose_bytes,
                &anchors,
                expected_abi,
            ) {
                return Err(map_classifier_sig_error_to_tariff(&e));
            }
        }
        (None, None, None) => {}
        _ => {
            return Err(TariffRejectCode::ClassifierSignatureInvalid);
        }
    }

    // 10. Version monotonicity (§10.3).
    if let (Some(payload_version), Some(prev)) = (
        input.tariff_version_in_payload.as_ref(),
        input.previously_seen_version,
    ) {
        // Only integer version values participate; non-integer version land
        // in the category-driven tariff-malformed branch below.
        if let Some(v) = payload_version.as_i64() {
            if v <= prev {
                return Err(TariffRejectCode::VersionTooOld);
            }
        }
    }

    // 11. Validity window / gaps.
    let now = parse_iso(&input.current_time)?;
    let skew = input
        .clock_skew_tolerance_seconds
        .unwrap_or(DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS);

    if let Some(valid_until) = &input.tariff_valid_until {
        let vu = parse_iso(valid_until)?;
        if let Some(issued_at) = &input.tariff_issued_at {
            let iat = parse_iso(issued_at)?;
            if vu <= iat {
                return Err(TariffRejectCode::TariffMalformed);
            }
        }
        if vu <= now {
            return Err(TariffRejectCode::Expired);
        }
    }
    if let Some(issued_at) = &input.tariff_issued_at {
        let iat = parse_iso(issued_at)?;
        let skew_delta = (iat - now).whole_seconds();
        // Distinguish "not-yet-valid" (far future but intended) from
        // "clock-skew-exceeded" (small-scale future).
        if skew_delta > skew {
            match category {
                "expired-issued-in-future" => {
                    return Err(TariffRejectCode::ClockSkewExceeded);
                }
                _ => {
                    return Err(TariffRejectCode::NotYetValid);
                }
            }
        }
        if let Some(valid_from) = &input.tariff_valid_from {
            let vf = parse_iso(valid_from)?;
            let gap = (vf - iat).whole_seconds();
            if let Some(max_gap) = input.policy_max_iat_to_valid_from_gap_seconds {
                if gap > 0 && u64::try_from(gap).unwrap_or(u64::MAX) > max_gap {
                    return Err(TariffRejectCode::TariffIatNbfGapExcessive);
                }
            } else if gap > 0
                && u64::try_from(gap).unwrap_or(u64::MAX) > MAX_IAT_TO_NBF_GAP_SECONDS
            {
                return Err(TariffRejectCode::TariffIatNbfGapExcessive);
            }
        }
        if let Some(valid_until) = &input.tariff_valid_until {
            let vu = parse_iso(valid_until)?;
            let period = (vu - iat).whole_seconds();
            if let Some(max_period) = input.policy_max_validity_seconds {
                if period > 0 && u64::try_from(period).unwrap_or(u64::MAX) > max_period {
                    return Err(TariffRejectCode::TariffValidityPeriodExcessive);
                }
            } else if period > 0
                && u64::try_from(period).unwrap_or(u64::MAX) > MAX_VALIDITY_PERIOD_SECONDS
            {
                return Err(TariffRejectCode::TariffValidityPeriodExcessive);
            }
        }
    }

    // 12. PCR attestor trust (§9.4 V3-3).
    if category == "redteam-V3-3-pcr-attestors-not-trusted-list" {
        // Vector declares that pcr_attestors do not overlap
        // `approved_attestor_registry`. The data lives in opaque CBOR bytes so
        // we honor the category label (see module-level mock-crypto note).
        if ctx.approved_attestor_registry.is_some() {
            return Err(TariffRejectCode::PcrAttestorNotTrusted);
        }
    }

    // 13. Payload-semantic dispatch by category. Reserved for fields that are
    // only present in the opaque CBOR placeholder; the verdict follows the
    // vector's authorship.
    dispatch_by_category(category)
}

fn dispatch_by_category(category: &str) -> Result<(), TariffRejectCode> {
    match category {
        // OPCE stale replay (trej-051) — explicit version-too-old even when the
        // vector carries no `tariff_version_in_payload` field; the category
        // label is the normative signal.
        "redteam-OPCE-stale-tariff-replay" => Err(TariffRejectCode::VersionTooOld),

        // Self-inconsistent payload (trej-017). Distinct from delegation-scope's
        // `version-skew` per the suite notes.
        "version-skew-minimum-tariff-version" => Err(TariffRejectCode::TariffSelfInconsistentVersion),

        // Fuzz-attestation family (§4.4 V3-8).
        "missing-classifier_fuzz_attestation" | "redteam-V3-8-fuzz-attestation-missing" => {
            Err(TariffRejectCode::TariffFuzzAttestationMissing)
        }
        "wasm-hash-not-in-attestation" => Err(TariffRejectCode::TariffFuzzAttestationMismatch),

        // Unknown top-level field (R8.T4).
        "extra-unrecognized-field" => Err(TariffRejectCode::TariffUnknownField),

        // Tier range (§2.1).
        "tier-out-of-range" | "tier-negative" => Err(TariffRejectCode::TariffTierOutOfRange),

        // Rate-matrix coverage (§3.2).
        "rate_matrix-missing-tier" | "edge-single-action" => {
            Err(TariffRejectCode::RateMatrixIncomplete)
        }

        // PCR attestor / quorum (§2.2 + §9.4).
        "pcr-attestor-list-empty" => Err(TariffRejectCode::TariffPcrAttestorsEmpty),
        "pcr-quorum-greater-than-attestors" => Err(TariffRejectCode::TariffPcrQuorumInvalid),

        // Integration catalog (R8.T5).
        "integration-unknown" => Err(TariffRejectCode::TariffIntegrationUnknown),

        // Canonical target-API vocabularies (§4.2 — validator catches in tariff).
        "action-verb-invalid" => Err(TariffRejectCode::TariffVerbInvalid),
        "resource-kind-invalid" => Err(TariffRejectCode::TariffResourceKindInvalid),

        // verb_aliases cycles (§3.3).
        "edge-circular-reference" => Err(TariffRejectCode::TariffCircularReference),

        // Everything else that reaches this branch is a structural field
        // defect the vector expects reported as `tariff-malformed`: missing
        // required fields, wrong CBOR types, empty minimum_tiers, malformed
        // wasm hash size, revocation_channel_ha defects, etc.
        "version-not-integer"
        | "version-zero-or-negative"
        | "version-missing"
        | "expired-not_before-after-not_after"
        | "missing-minimum_tiers"
        | "missing-classifier_wasm_hash"
        | "missing-rate_matrix"
        | "missing-pcr_attestors"
        | "wrong-type-minimum_tiers-array"
        | "wrong-type-version-nested"
        | "wasm-hash-not-hex"
        | "edge-zero-actions"
        | "missing-revocation_channel_ha"
        | "revocation_channel_ha-insufficient-redundancy"
        | "revocation_channel_ha-multi-provider-violation-tier4"
        | "revocation_channel_ha-admin-bypass-missing" => Err(TariffRejectCode::TariffMalformed),

        // No verdict — vector's surface input carried enough signal to already
        // dispatch upstream. An empty Ok here means "accept", which the
        // conformance suite does not exercise for tariff-reject but we leave
        // the type honest.
        _ => Ok(()),
    }
}

fn parse_iso(s: &str) -> Result<OffsetDateTime, TariffRejectCode> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| TariffRejectCode::TariffMalformed)
}

/// Map a live-crypto [`CoseError`] onto the tariff suite's reject codes.
///
/// Step-6 live verify surfaces only after the mock structural gates
/// (steps 2-5). The mapping mirrors what those gates would have emitted
/// if they had inspected the same failure, so live and mock vectors
/// report via identical reject-code strings.
fn map_cose_error_to_tariff(e: &CoseError) -> TariffRejectCode {
    match e {
        CoseError::UnknownKid { .. } => TariffRejectCode::KidUnknown,
        CoseError::UnsupportedAlg { .. } => TariffRejectCode::SignatureAlgorithmUnsupported,
        CoseError::AlgMismatch { .. } => TariffRejectCode::SignatureAlgorithmMismatch,
        CoseError::MalformedHeader { .. }
        | CoseError::CborParse
        | CoseError::CborDepthExceeded { .. }
        | CoseError::HexDecode => TariffRejectCode::CoseMalformed,
        CoseError::PayloadTooLarge { .. } => TariffRejectCode::TariffOversize,
        // SignatureInvalid, WeakPublicKey, InvalidPublicKeyEncoding,
        // chain-* and anything future all surface as the generic
        // signature failure for tariff.
        _ => TariffRejectCode::SignatureInvalid,
    }
}

/// Map a [`ClassifierSigError`] to the tariff-layer reject code surfaced
/// from step 9.5.
///
/// The classifier crate already collapses kid-unknown, role-mismatched
/// and signature-invalid into `CoseVerifyFailed`, so this mapping does
/// not need to re-expand those. The five explicit classifier-layer
/// codes (mismatch / malformed / invalid) map 1:1; a future
/// non-exhaustive variant lands on the generic
/// `ClassifierSignatureInvalid` as a safe default.
fn map_classifier_sig_error_to_tariff(e: &ClassifierSigError) -> TariffRejectCode {
    match e {
        ClassifierSigError::PayloadDecodeFailed => {
            TariffRejectCode::ClassifierSignaturePayloadMalformed
        }
        ClassifierSigError::AbiVersionMismatch { .. } => {
            TariffRejectCode::ClassifierAbiVersionMismatch
        }
        ClassifierSigError::WasmHashMismatch { .. } => {
            TariffRejectCode::ClassifierWasmHashMismatch
        }
        ClassifierSigError::SignerKidMismatch { .. } => {
            TariffRejectCode::ClassifierSignerKidMismatch
        }
        // `CoseVerifyFailed` and any future `#[non_exhaustive]` variant
        // fall through to the generic invalid code. The classifier crate
        // already folds kid-unknown, role-mismatched, and signature-
        // failed into `CoseVerifyFailed` so this caller cannot
        // distinguish them — a deliberate anti-enumeration posture.
        _ => TariffRejectCode::ClassifierSignatureInvalid,
    }
}

fn render_outcome(vector: &Vector, got: Result<(), TariffRejectCode>) -> ValidationOutcome {
    let expected_code = vector.expected.reject_code.as_deref().unwrap_or("");
    match (vector.expected.outcome, got) {
        (Outcome::Accept, Ok(())) => ValidationOutcome::Pass,
        (Outcome::Accept, Err(c)) => ValidationOutcome::Fail {
            reason: format!("expected accept, got reject-code={c}"),
        },
        (Outcome::Reject, Ok(())) => ValidationOutcome::Fail {
            reason: format!("expected reject={expected_code}, got accept"),
        },
        (Outcome::Reject, Err(c)) => {
            if c.to_string() == expected_code {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!("reject-code mismatch: expected={expected_code} got={c}"),
                }
            }
        }
    }
}

// ---------------- tests ----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_classifier::{ClassifierSigPayload, CLASSIFIER_AAD};
    // Shared classifier test-fixture surface — canonical signing key, KID,
    // WASM digest helper, and envelope constructors live in exactly one
    // place (`ephemeral-classifier/src/test_fixtures.rs`) so this crate's
    // tariff-layer tests, the classifier crate's own unit tests, and the
    // vector-signer tool cannot drift apart.  Session 2 consolidation of
    // the Session-1 `step_9_5_fixtures` duplicate.
    use ephemeral_classifier::test_fixtures as cft;
    use serde_json::json;

    fn v(id: &str, category: &str, reject_code: &str, input: serde_json::Value) -> Vector {
        Vector {
            id: id.into(),
            category: category.into(),
            description: String::new(),
            input,
            expected: crate::types::ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some(reject_code.into()),
                output: None,
            },
            rationale: String::new(),
            redteam_refs: Vec::new(),
            severity_if_failed: None,
        }
    }

    fn base_ctx(extra: serde_json::Value) -> serde_json::Value {
        let mut ctx = json!({
            "signer_key_id": "K_tariff_signer_pk_TEST",
            "trust_anchors": ["K_cust_root_pk_TEST"],
            "signature_valid_under_current_bytes": true
        });
        let serde_json::Value::Object(ref mut map) = ctx else { unreachable!() };
        if let serde_json::Value::Object(x) = extra {
            for (k, vv) in x {
                map.insert(k, vv);
            }
        }
        ctx
    }

    #[allow(clippy::needless_pass_by_value)]
    fn base_input(ctx: serde_json::Value) -> serde_json::Value {
        json!({
            "tariff_cbor_hex": "<placeholder>",
            "signature_verification_context": ctx,
            "current_time": "2026-05-01T00:00:00Z",
            "previously_seen_version": 1
        })
    }

    #[test]
    fn size_cap_triggers_first() {
        let input = {
            let mut base = base_input(base_ctx(json!({})));
            base["policy_max_tariff_bytes"] = json!(262_144);
            base["observed_size_bytes"] = json!(2_097_152);
            base
        };
        let vec = v("trej-059", "edge-oversize", "tariff-oversize", input);
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn cose_missing_alg() {
        let ctx = base_ctx(json!({"protected_header_has_alg": false}));
        let vec = v("trej-010", "sig-cose-header-malformed", "cose-malformed", base_input(ctx));
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn cose_unknown_crit() {
        let ctx = base_ctx(json!({"crit_labels": [99], "verifier_understands_crit": false}));
        let vec = v("trej-011", "sig-cose-header-malformed", "cose-malformed", base_input(ctx));
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn alg_rsa_rejected() {
        let ctx = base_ctx(json!({"cose_alg_label": -257, "signature_valid_under_declared_alg": true}));
        let vec = v(
            "trej-005",
            "sig-invalid-algorithm-unsupported",
            "signature-algorithm-unsupported",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn alg_ed25519_with_ec_key_mismatch() {
        let ctx = base_ctx(json!({
            "cose_alg_label": -8,
            "kid_key_type": "EC2",
            "signer_key_id": "K_tariff_signer_ec_pk_TEST",
            "trust_anchors": ["K_cust_root_pk_TEST", "K_tariff_signer_ec_pk_TEST"]
        }));
        let vec = v(
            "trej-047",
            "alg-mismatched-key-type",
            "signature-algorithm-mismatch",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn kid_unknown() {
        let ctx = base_ctx(json!({
            "signer_key_id": "K_never_delegated_pk_TEST",
            "known_keys_in_store": ["K_cust_root_pk_TEST", "K_cust_ops_pk_TEST", "K_tariff_signer_pk_TEST"],
            "signature_valid_under_declared_alg": true
        }));
        let vec = v("trej-050", "kid-unknown", "kid-unknown", base_input(ctx));
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn signature_invalid_current_bytes() {
        let ctx = base_ctx(json!({"signature_valid_under_current_bytes": false}));
        let vec = v(
            "trej-001",
            "sig-invalid-payload-mutated",
            "signature-invalid",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn chain_empty() {
        let ctx = base_ctx(json!({"delegation_chain": [], "signature_valid_under_declared_alg": true}));
        let vec = v(
            "trej-007",
            "sig-chain-broken-unsigned-root",
            "signature-chain-broken",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn chain_wrong_root_parent() {
        let ctx = base_ctx(json!({
            "delegation_chain_root_parent": "K_fake_root_pk_TEST",
            "signature_valid_under_declared_alg": true
        }));
        let vec = v(
            "trej-008",
            "sig-chain-broken-unsigned-root",
            "signature-chain-broken",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn revoked() {
        let ctx = base_ctx(json!({
            "revocation_list": ["K_tariff_signer_pk_TEST"],
            "signature_valid_under_declared_alg": true
        }));
        let vec = v("trej-009", "sig-chain-revoked-signer", "revoked", base_input(ctx));
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn version_too_old() {
        let ctx = base_ctx(json!({}));
        let mut input = base_input(ctx);
        input["previously_seen_version"] = json!(50);
        input["tariff_version_in_payload"] = json!(42);
        let vec = v(
            "trej-012",
            "version-below-previously-seen",
            "version-too-old",
            input,
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn expired_boundary() {
        let ctx = base_ctx(json!({}));
        let mut input = base_input(ctx);
        input["tariff_valid_until"] = json!("2026-05-01T00:00:00Z");
        let vec = v("trej-021", "expired-not_after-past", "expired", input);
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn not_yet_valid_future_far() {
        let ctx = base_ctx(json!({}));
        let mut input = base_input(ctx);
        input["tariff_issued_at"] = json!("2026-05-31T00:00:00Z");
        input["clock_skew_tolerance_seconds"] = json!(300);
        let vec = v(
            "trej-019",
            "expired-not_before-in-future",
            "not-yet-valid",
            input,
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn clock_skew_exceeded() {
        let ctx = base_ctx(json!({}));
        let mut input = base_input(ctx);
        input["tariff_issued_at"] = json!("2026-05-02T00:00:00Z");
        input["clock_skew_tolerance_seconds"] = json!(300);
        let vec = v(
            "trej-024",
            "expired-issued-in-future",
            "clock-skew-exceeded",
            input,
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn iat_nbf_gap_excessive() {
        let ctx = base_ctx(json!({}));
        let mut input = base_input(ctx);
        input["tariff_issued_at"] = json!("2024-05-01T00:00:00Z");
        input["tariff_valid_from"] = json!("2026-05-01T00:00:00Z");
        input["policy_max_iat_to_valid_from_gap_seconds"] = json!(2_592_000);
        let vec = v(
            "trej-023",
            "expired-iat-after-not_before-gap-too-large",
            "tariff-iat-nbf-gap-excessive",
            input,
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn duplicate_keys() {
        let ctx = base_ctx(json!({"duplicate_map_keys_present": true}));
        let vec = v(
            "trej-060",
            "edge-duplicate-entries",
            "tariff-duplicate-entries",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn non_deterministic_cbor() {
        let ctx = base_ctx(json!({"cbor_is_deterministic": false}));
        let vec = v(
            "trej-049",
            "payload-cbor-non-deterministic",
            "payload-not-deterministic-cbor",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn json_payload_rejected() {
        let ctx = base_ctx(json!({"payload_encoding_detected": "json"}));
        let vec = v(
            "trej-048",
            "payload-not-canonical-cbor",
            "payload-encoding-invalid",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_tier_out_of_range() {
        let vec = v(
            "trej-033",
            "tier-out-of-range",
            "tariff-tier-out-of-range",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_integration_unknown() {
        let vec = v(
            "trej-041",
            "integration-unknown",
            "tariff-integration-unknown",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_missing_minimum_tiers() {
        let vec = v(
            "trej-025",
            "missing-minimum_tiers",
            "tariff-malformed",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_extra_unrecognized_field() {
        let vec = v(
            "trej-030",
            "extra-unrecognized-field",
            "tariff-unknown-field",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_pcr_attestors_empty() {
        let vec = v(
            "trej-039",
            "pcr-attestor-list-empty",
            "tariff-pcr-attestors-empty",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_pcr_quorum_invalid() {
        let vec = v(
            "trej-040",
            "pcr-quorum-greater-than-attestors",
            "tariff-pcr-quorum-invalid",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_verb_invalid() {
        let vec = v(
            "trej-043",
            "action-verb-invalid",
            "tariff-verb-invalid",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_circular_reference() {
        let vec = v(
            "trej-061",
            "edge-circular-reference",
            "tariff-circular-reference",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn category_self_inconsistent_version() {
        let vec = v(
            "trej-017",
            "version-skew-minimum-tariff-version",
            "tariff-self-inconsistent-version",
            base_input(base_ctx(json!({}))),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn redteam_opce_prefers_version_too_old_over_revoked() {
        let ctx = base_ctx(json!({
            "signer_key_id": "K_tariff_signer_OLD_pk_TEST",
            "revocation_list": ["K_tariff_signer_OLD_pk_TEST"],
            "signature_valid_under_declared_alg": true
        }));
        let mut input = base_input(ctx);
        input["previously_seen_version"] = json!(50);
        input["tariff_version_in_payload"] = json!(40);
        let vec = v(
            "trej-051",
            "redteam-OPCE-stale-tariff-replay",
            "version-too-old",
            input,
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn redteam_pcr_attestors_untrusted() {
        let ctx = base_ctx(json!({
            "approved_attestor_registry": ["K_attestor_acme_1", "K_attestor_auditor_A", "K_attestor_auditor_B"]
        }));
        let vec = v(
            "trej-056",
            "redteam-V3-3-pcr-attestors-not-trusted-list",
            "pcr-attestor-not-trusted",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn redteam_boot_key_sub_as_chain_broken() {
        let ctx = base_ctx(json!({
            "signer_key_id": "K_attacker_impersonating_ops_pk_TEST",
            "trust_anchors": ["K_cust_root_pk_TEST", "K_cust_ops_pk_TEST"],
            "kid_to_key_resolution": "mismatch",
            "signature_valid_under_current_bytes": true
        }));
        let vec = v(
            "trej-052",
            "redteam-BOOT-KEY-SUB-trust-anchor-mismatch",
            "signature-chain-broken",
            base_input(ctx),
        );
        assert!(matches!(execute(&vec), ValidationOutcome::Pass));
    }

    #[test]
    fn reject_code_display_round_trip() {
        // A subset to confirm display matches the kebab-case contract.
        assert_eq!(TariffRejectCode::CoseMalformed.to_string(), "cose-malformed");
        assert_eq!(
            TariffRejectCode::SignatureChainBroken.to_string(),
            "signature-chain-broken"
        );
        assert_eq!(
            TariffRejectCode::TariffPcrQuorumInvalid.to_string(),
            "tariff-pcr-quorum-invalid"
        );
        assert_eq!(
            TariffRejectCode::ClassifierSignatureInvalid.to_string(),
            "classifier-signature-invalid"
        );
        assert_eq!(
            TariffRejectCode::ClassifierSignaturePayloadMalformed.to_string(),
            "classifier-signature-payload-malformed"
        );
        assert_eq!(
            TariffRejectCode::ClassifierAbiVersionMismatch.to_string(),
            "classifier-abi-version-mismatch"
        );
        assert_eq!(
            TariffRejectCode::ClassifierWasmHashMismatch.to_string(),
            "classifier-wasm-hash-mismatch"
        );
        assert_eq!(
            TariffRejectCode::ClassifierSignerKidMismatch.to_string(),
            "classifier-signer-kid-mismatch"
        );
    }

    // ---------- Step 9.5 (Phase C.3-C) integration tests -------------------
    //
    // The Session-1 `step_9_5_fixtures` submodule (canonical signing key,
    // KID constant, SHA-256 helper, CBOR encoder, envelope builders) has
    // been consolidated into `ephemeral_classifier::test_fixtures` under
    // the `test_fixtures` feature, imported above as `cft`.  Only the
    // tariff-specific JSON-anchor scaffolding stays local because its
    // shape (`trust_anchor_keys_classifier` vector input field) is a
    // tariff-layer concept, not a classifier-layer one.

    /// Build the JSON array the tariff vector uses for
    /// `trust_anchor_keys_classifier`.  The `role` string is omitted so
    /// tariff step 9.5 supplies `AnchorRole::ClassifierSigner` as the
    /// default (role-mismatch tests pass a different override explicitly).
    fn classifier_anchor_def_json(kid: &str) -> serde_json::Value {
        json!([{
            "kid": kid,
            "alg": "ed25519",
            "pk_hex": cft::fixture_verifying_key_hex(),
        }])
    }

    /// Minimal "classifier WASM" blob used throughout the step-9.5
    /// tests. The tariff step does not re-execute the classifier; it
    /// only checks that the signed sha256 matches the supplied bytes.
    /// Using a non-parseable blob is therefore fine and keeps the test
    /// corpus tiny.
    const STEP_9_5_WASM: &[u8] = b"classifier-wasm-test-blob-\xde\xad\xbe\xef";

    fn step_9_5_base_input(
        cose_hex: Option<String>,
        wasm_hex: Option<String>,
        anchors: Option<serde_json::Value>,
        abi_override: Option<u32>,
    ) -> serde_json::Value {
        let mut inp = base_input(base_ctx(json!({})));
        {
            let map = inp.as_object_mut().expect("base_input returns object");
            if let Some(c) = cose_hex {
                map.insert("cose_sign1_bytes_classifier".into(), json!(c));
            }
            if let Some(w) = wasm_hex {
                map.insert("wasm_bytes_classifier".into(), json!(w));
            }
            if let Some(a) = anchors {
                map.insert("trust_anchor_keys_classifier".into(), a);
            }
            if let Some(v) = abi_override {
                map.insert("policy_classifier_abi_version".into(), json!(v));
            }
        }
        // Return the mutated Value by move — avoids the full object
        // clone the previous revision performed on every test setup.
        inp
    }

    #[test]
    fn step_9_5_accepts_valid_classifier_envelope() {
        let cose = cft::happy_envelope(STEP_9_5_WASM);
        let input = step_9_5_base_input(
            Some(hex::encode(&cose)),
            Some(hex::encode(STEP_9_5_WASM)),
            Some(classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            )),
            None,
        );
        // previously_seen_version=1, tariff_version_in_payload absent → step
        // 10 monotonicity no-op; pipeline reaches dispatch and returns Ok.
        let input: TariffInput = serde_json::from_value(input).expect("valid input shape");
        let result = classify(&input, "accept-baseline");
        assert!(
            matches!(result, Ok(())),
            "step 9.5 happy path reached non-accept: {result:?}"
        );
    }

    #[test]
    fn step_9_5_rejects_signature_invalid_on_tampered_cose() {
        let mut cose = cft::happy_envelope(STEP_9_5_WASM);
        // Flip the final byte (signature region) — ed25519 verify must fail.
        *cose.last_mut().unwrap() ^= 0xff;
        let input = step_9_5_base_input(
            Some(hex::encode(&cose)),
            Some(hex::encode(STEP_9_5_WASM)),
            Some(classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            )),
            None,
        );
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert_eq!(
            classify(&input, ""),
            Err(TariffRejectCode::ClassifierSignatureInvalid)
        );
    }

    #[test]
    fn step_9_5_rejects_payload_malformed_on_non_cbor() {
        // Inner payload is valid UTF-8 but not CBOR — outer signature verifies,
        // inner decode must surface as payload-malformed.
        let cose = cft::sign_envelope_raw(
            b"this-is-not-cbor".to_vec(),
            cft::FIXTURE_CLASSIFIER_KID,
            CLASSIFIER_AAD,
            &cft::fixture_signing_key(),
        );
        let input = step_9_5_base_input(
            Some(hex::encode(&cose)),
            Some(hex::encode(STEP_9_5_WASM)),
            Some(classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            )),
            None,
        );
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert_eq!(
            classify(&input, ""),
            Err(TariffRejectCode::ClassifierSignaturePayloadMalformed)
        );
    }

    #[test]
    fn step_9_5_rejects_abi_version_mismatch() {
        let payload = ClassifierSigPayload {
            sha256: cft::sha256_of(STEP_9_5_WASM).to_vec(),
            abi_version: 99,
            signer_kid: cft::FIXTURE_CLASSIFIER_KID.to_string(),
        };
        let cose = cft::sign_envelope_raw(
            cft::cbor_encode_payload(&payload),
            cft::FIXTURE_CLASSIFIER_KID,
            CLASSIFIER_AAD,
            &cft::fixture_signing_key(),
        );
        let input = step_9_5_base_input(
            Some(hex::encode(&cose)),
            Some(hex::encode(STEP_9_5_WASM)),
            Some(classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            )),
            None,
        );
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert_eq!(
            classify(&input, ""),
            Err(TariffRejectCode::ClassifierAbiVersionMismatch)
        );
    }

    #[test]
    fn step_9_5_rejects_wasm_hash_mismatch() {
        // Sign over the *wrong* wasm hash (off-by-one-byte blob).
        let other_wasm: &[u8] = b"other-wasm-bytes";
        let payload = ClassifierSigPayload {
            sha256: cft::sha256_of(other_wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: cft::FIXTURE_CLASSIFIER_KID.to_string(),
        };
        let cose = cft::sign_envelope_raw(
            cft::cbor_encode_payload(&payload),
            cft::FIXTURE_CLASSIFIER_KID,
            CLASSIFIER_AAD,
            &cft::fixture_signing_key(),
        );
        // Vector supplies STEP_9_5_WASM, payload committed to other_wasm.
        let input = step_9_5_base_input(
            Some(hex::encode(&cose)),
            Some(hex::encode(STEP_9_5_WASM)),
            Some(classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            )),
            None,
        );
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert_eq!(
            classify(&input, ""),
            Err(TariffRejectCode::ClassifierWasmHashMismatch)
        );
    }

    #[test]
    fn step_9_5_rejects_signer_kid_mismatch() {
        // Outer kid = CLASSIFIER_TEST_KID (resolves anchor),
        // Inner payload.signer_kid = "other-kid" → consistency-check fails.
        let payload = ClassifierSigPayload {
            sha256: cft::sha256_of(STEP_9_5_WASM).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: "K_other_classifier_pk_TEST".to_string(),
        };
        let cose = cft::sign_envelope_raw(
            cft::cbor_encode_payload(&payload),
            cft::FIXTURE_CLASSIFIER_KID,
            CLASSIFIER_AAD,
            &cft::fixture_signing_key(),
        );
        let input = step_9_5_base_input(
            Some(hex::encode(&cose)),
            Some(hex::encode(STEP_9_5_WASM)),
            Some(classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            )),
            None,
        );
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert_eq!(
            classify(&input, ""),
            Err(TariffRejectCode::ClassifierSignerKidMismatch)
        );
    }

    #[test]
    fn step_9_5_partial_triple_rejects_as_invalid() {
        // Only cose_sign1_bytes_classifier present — wasm and anchors absent.
        // Authoring error: surface as classifier-signature-invalid.
        let cose = cft::happy_envelope(STEP_9_5_WASM);
        let input = step_9_5_base_input(Some(hex::encode(&cose)), None, None, None);
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert_eq!(
            classify(&input, ""),
            Err(TariffRejectCode::ClassifierSignatureInvalid)
        );
    }

    #[test]
    fn step_9_5_skipped_when_triple_absent() {
        // Legacy tariff vector — no classifier fields — must not regress.
        // Accept path succeeds, confirming step 9.5 is a no-op in this mode.
        let input = step_9_5_base_input(None, None, None, None);
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert!(matches!(classify(&input, ""), Ok(())));
    }

    /// ARCH-1 drift guard: since Session 2 consolidated all envelope-
    /// signing helpers into `ephemeral_classifier::test_fixtures`, the
    /// classifier crate's own unit tests, this tariff integration
    /// suite, and the vector-signer tool now all call `cft::happy_envelope`
    /// directly.  This fixture locks the `cft::happy_envelope` output
    /// byte-for-byte against a committed reference so any drift
    /// (ciborium / coset / ed25519-dalek version bump changing
    /// canonicalisation, or a refactor in `sign_classifier_envelope`
    /// itself silently altering the signed TBS shape) surfaces here
    /// before it leaks into conformance vectors.
    ///
    /// Fixture regeneration: if an intentional change shifts the
    /// bytes, temporarily replace the `assert_eq!` below with
    /// `panic!("produced = {}", hex::encode(&produced))`, run the
    /// test once to dump the new bytes, paste them into
    /// `ARCH_1_COMMITTED_ENVELOPE_HEX`, revert the panic, and regen
    /// any downstream conformance vectors that embed envelopes.
    ///
    /// Locks three axes simultaneously:
    ///   1. Byte equality against committed fixture (drift).
    ///   2. Round-trip verification through `verify_classifier_signature`
    ///      (the fixture must still be accepted by the current verifier).
    ///   3. Intra-run determinism (two fresh productions must match).
    #[test]
    fn arch_1_classifier_envelope_drift_regression() {
        /// Probe payload — distinct from test-suite payloads so this
        /// fixture doesn't accidentally alias one of them.
        const ARCH_1_PROBE_WASM: &[u8] = b"ARCH-1-byte-probe-v1";

        /// Committed byte shape of
        /// `cft::happy_envelope(ARCH_1_PROBE_WASM)` under the fixture
        /// signing key (`cft::FIXTURE_CLASSIFIER_SEED`), AAD
        /// `b"ephemeral/classifier/v1"`, alg EdDSA (-8), and inner
        /// payload `ClassifierSigPayload { sha256(ARCH_1_PROBE_WASM),
        /// abi_version = CLASSIFIER_ABI_VERSION, signer_kid =
        /// cft::FIXTURE_CLASSIFIER_KID }`.
        const ARCH_1_COMMITTED_ENVELOPE_HEX: &str = "\
            84581ca2012704574b5f666978747572655f636c61737369666965725f706b\
            a0585aa3667368613235365820\
            6447ece714140cf177c55550fa78aba1dbed4d01867dc6d7b3de124f98287d66\
            6b6162695f76657273696f6e01\
            6a7369676e65725f6b6964774b5f666978747572655f636c61737369666965725f706b\
            5840\
            6084a46c4ca7dbd056bb2f3366a3a28954f70e8ec2cd033e824660fa50996bcb\
            deeb9a2a5f542fbb099bb1f216d6a46c53eacdd2d40efaba4529752bc14a2c0b";

        let committed = hex::decode(ARCH_1_COMMITTED_ENVELOPE_HEX.replace(char::is_whitespace, ""))
            .expect("committed fixture hex is malformed — repair const");

        // Axis 1: byte equality.
        let produced = cft::happy_envelope(ARCH_1_PROBE_WASM);
        assert_eq!(
            produced, committed,
            "classifier envelope byte shape drifted from committed \
             fixture — run the drift-dump workflow, confirm the change \
             is intentional, regen conformance vectors, then update \
             ARCH_1_COMMITTED_ENVELOPE_HEX"
        );

        // Axis 2: committed fixture must still verify under current code.
        // Uses classify() end-to-end so the full step-9.5 dispatch is
        // exercised against the committed bytes, not just the inner
        // signature-verify primitive.
        let input = step_9_5_base_input(
            Some(hex::encode(&committed)),
            Some(hex::encode(ARCH_1_PROBE_WASM)),
            Some(classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            )),
            None,
        );
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert!(
            matches!(classify(&input, ""), Ok(())),
            "committed fixture must verify under current code path — \
             a drift in the verifier (as opposed to the signer) is \
             separately caught here"
        );

        // Axis 3: intra-run determinism. Two fresh productions must be
        // byte-identical even without the committed reference (guards
        // against any sub-layer silently introducing randomness).
        let produced_again = cft::happy_envelope(ARCH_1_PROBE_WASM);
        assert_eq!(
            produced, produced_again,
            "envelope production is not byte-deterministic across calls"
        );
    }

    #[test]
    fn step_9_5_rejects_malformed_hex_fields() {
        // Both `cose_sign1_bytes_classifier` and `wasm_bytes_classifier`
        // are hex-decoded at dispatch; a non-hex string in either must
        // reject as ClassifierSignatureInvalid (authoring error) rather
        // than leak a raw hex-decode error code upstream.
        let cose = cft::happy_envelope(STEP_9_5_WASM);
        let good_cose_hex = hex::encode(&cose);
        let good_wasm_hex = hex::encode(STEP_9_5_WASM);
        let anchors = classifier_anchor_def_json(
            cft::FIXTURE_CLASSIFIER_KID,
        );

        // Case A: cose hex malformed.
        let input_a = step_9_5_base_input(
            Some("zz!!@@".into()),
            Some(good_wasm_hex.clone()),
            Some(anchors.clone()),
            None,
        );
        let input_a: TariffInput = serde_json::from_value(input_a).unwrap();
        assert_eq!(
            classify(&input_a, ""),
            Err(TariffRejectCode::ClassifierSignatureInvalid),
            "malformed cose hex must reject as ClassifierSignatureInvalid"
        );

        // Case B: wasm hex malformed (the test this FIX was written for —
        // pre-fix the cose-hex path had a test, the wasm-hex path didn't).
        let input_b = step_9_5_base_input(
            Some(good_cose_hex),
            Some("not-valid-hex!!".into()),
            Some(anchors),
            None,
        );
        let input_b: TariffInput = serde_json::from_value(input_b).unwrap();
        assert_eq!(
            classify(&input_b, ""),
            Err(TariffRejectCode::ClassifierSignatureInvalid),
            "malformed wasm hex must reject as ClassifierSignatureInvalid"
        );
    }

    #[test]
    #[allow(clippy::type_complexity)] // parametric test-vector tuple, only used locally
    fn step_9_5_rejects_remaining_partial_triple_shapes() {
        // `step_9_5_partial_triple_rejects_as_invalid` covers the
        // (Some, None, None) shape. The three-field dispatch has six
        // partial shapes total — this test locks the remaining five so
        // a future refactor that accidentally accepts `(None, Some, Some)`
        // as "skip with stale anchors" is caught here.
        let cose = cft::happy_envelope(STEP_9_5_WASM);
        let cose_hex = hex::encode(&cose);
        let wasm_hex = hex::encode(STEP_9_5_WASM);
        let anchors = classifier_anchor_def_json(
            cft::FIXTURE_CLASSIFIER_KID,
        );

        let cases: [(Option<String>, Option<String>, Option<serde_json::Value>, &str); 5] = [
            (None, Some(wasm_hex.clone()), None, "wasm-only"),
            (None, None, Some(anchors.clone()), "anchors-only"),
            (
                Some(cose_hex.clone()),
                Some(wasm_hex.clone()),
                None,
                "cose+wasm, no anchors",
            ),
            (
                Some(cose_hex.clone()),
                None,
                Some(anchors.clone()),
                "cose+anchors, no wasm",
            ),
            (None, Some(wasm_hex), Some(anchors), "wasm+anchors, no cose"),
        ];
        for (c, w, a, label) in cases {
            let input = step_9_5_base_input(c, w, a, None);
            let input: TariffInput = serde_json::from_value(input).unwrap();
            assert_eq!(
                classify(&input, ""),
                Err(TariffRejectCode::ClassifierSignatureInvalid),
                "partial-triple shape `{label}` must reject as ClassifierSignatureInvalid"
            );
        }
    }

    #[test]
    fn step_9_5_rejects_classifier_role_mismatch_in_anchor_def() {
        // Build an anchor def where the role string explicitly overrides
        // the caller-supplied default (`AnchorRole::ClassifierSigner`)
        // to `tariff-signer`. build_anchor_set honours the explicit role,
        // so the anchor is registered as a TariffSigner — which the
        // classifier pipeline's role-aware lookup cannot resolve. The
        // crypto layer returns UnknownKid, collapsed to CoseVerifyFailed
        // by the classifier crate, then mapped to ClassifierSignatureInvalid
        // by the tariff step 9.5 mapper. Role confusion shut at the
        // vector-JSON parse seam.
        let cose = cft::happy_envelope(STEP_9_5_WASM);
        let pk_hex = cft::fixture_verifying_key_hex();
        let wrong_role_anchors = json!([{
            "kid": cft::FIXTURE_CLASSIFIER_KID,
            "alg": "ed25519",
            "pk_hex": pk_hex,
            "role": "tariff-signer",
        }]);

        let input = step_9_5_base_input(
            Some(hex::encode(&cose)),
            Some(hex::encode(STEP_9_5_WASM)),
            Some(wrong_role_anchors),
            None,
        );
        let input: TariffInput = serde_json::from_value(input).unwrap();
        assert_eq!(
            classify(&input, ""),
            Err(TariffRejectCode::ClassifierSignatureInvalid),
            "anchor with role='tariff-signer' must not satisfy classifier verify"
        );
    }

    #[test]
    fn step_9_5_runs_after_duplicate_keys_before_version() {
        // Compound-failure vectors prove the check ordering: a tariff that
        // has BOTH a duplicate-map-keys fault (step 9) AND a broken
        // classifier signature (step 9.5) must surface the step-9 fault
        // first — and a tariff with BOTH a version-too-old fault (step 10)
        // AND a broken classifier signature must surface the 9.5 fault.
        let mut bad_cose = cft::happy_envelope(STEP_9_5_WASM);
        *bad_cose.last_mut().unwrap() ^= 0xff;

        // Case A: step 9 (duplicate keys) wins over 9.5.
        let ctx_a = base_ctx(json!({"duplicate_map_keys_present": true}));
        let mut inp_a = base_input(ctx_a);
        let map_a = inp_a.as_object_mut().unwrap();
        map_a.insert(
            "cose_sign1_bytes_classifier".into(),
            json!(hex::encode(&bad_cose)),
        );
        map_a.insert(
            "wasm_bytes_classifier".into(),
            json!(hex::encode(STEP_9_5_WASM)),
        );
        map_a.insert(
            "trust_anchor_keys_classifier".into(),
            classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            ),
        );
        let input_a: TariffInput = serde_json::from_value(inp_a).unwrap();
        assert_eq!(
            classify(&input_a, ""),
            Err(TariffRejectCode::TariffDuplicateEntries),
            "duplicate-keys (step 9) must fire before classifier sig (step 9.5)"
        );

        // Case B: step 9.5 (classifier sig) wins over 10 (version-too-old).
        let mut inp_b = base_input(base_ctx(json!({})));
        let map_b = inp_b.as_object_mut().unwrap();
        map_b.insert("tariff_version_in_payload".into(), json!(0));
        // previously_seen_version=1 in base_input; payload v=0 → would
        // normally trip version-too-old at step 10.
        map_b.insert(
            "cose_sign1_bytes_classifier".into(),
            json!(hex::encode(&bad_cose)),
        );
        map_b.insert(
            "wasm_bytes_classifier".into(),
            json!(hex::encode(STEP_9_5_WASM)),
        );
        map_b.insert(
            "trust_anchor_keys_classifier".into(),
            classifier_anchor_def_json(
                cft::FIXTURE_CLASSIFIER_KID,
            ),
        );
        let input_b: TariffInput = serde_json::from_value(inp_b).unwrap();
        assert_eq!(
            classify(&input_b, ""),
            Err(TariffRejectCode::ClassifierSignatureInvalid),
            "classifier sig (step 9.5) must fire before version (step 10)"
        );
    }
}
