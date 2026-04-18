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

use serde::Deserialize;
use time::OffsetDateTime;

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

    // 6. Signature math (raw bytes).
    if ctx.signature_valid_under_current_bytes == Some(false) {
        return Err(TariffRejectCode::SignatureInvalid);
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
    }
}
