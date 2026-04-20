//! PCR-attestation-reject suite executor — §2.2, §9.3, §9.4 + R8.P3/P6.
//!
//! Verifies the reproducible-build / measured-enclave attestation bundle that
//! accompanies every Signer image a Tariff authorizes. Defends V3-3 (REPRODUCIBLE
//! BUILD VERIFICATION GAP).
//!
//! ## Mock-crypto model
//!
//! `signature_valid` / `inclusion_proof_valid` are explicit booleans on each
//! attestation and on the transparency-log proof. PCR values are
//! `sha256:<label>` placeholder strings; **only byte-identical comparison
//! matters**, not the underlying bytes. Real COSE verification + Merkle-proof
//! replay lands in Phase C.
//!
//! ## Check order (fail-fast, first-failing wins)
//!
//! 1. **Bundle size cap (R8.P6)** — `declared_size_bytes > bundle_max_size_bytes`
//!    → `pcr-bundle-too-large`.
//! 2. **Bundle decode** — raw-hex present (bytes do not decode), empty bundle →
//!    `pcr-bundle-malformed`.
//! 3. **Tariff-PCR invariants** — missing `expected_pcrs`, `quorum == 0`,
//!    `quorum == 1` when Tariff's attestor set is ≥3 → `tariff-pcr-quorum-invalid`.
//! 4. **Bundle structural** — missing `attestor_id` / `iat`, PCR index outside
//!    `[0..23]`, strict-mode unknown fields → `pcr-bundle-malformed`.
//! 5. **Duplicate attestor** — same `attestor_id` appears twice →
//!    `pcr-attestor-duplicate`.
//! 6. **Per-attestor scans (first defect wins across attestors)**
//!    - `signature_valid == false` → `pcr-attestor-signature-invalid`.
//!    - `attestor_id` in revocation list → `pcr-attestor-revoked`.
//!    - `iat < attestor_validity.not_before` → `pcr-attestor-not-yet-valid`.
//! 7. **Freshness** — attestation expired (`iat + max_age < current_time`) →
//!    `pcr-attestation-expired`; iat in future → `pcr-attestation-future-dated`;
//!    iat predates Tariff `issued_at` → `pcr-attestation-predates-tariff`.
//! 8. **Nonce binding** — consumed-list contains current nonce →
//!    `pcr-attestation-nonce-reuse`; attestor nonce ≠ router nonce →
//!    `pcr-attestation-nonce-mismatch`.
//! 9. **Transparency log (R8.P3 + RFC 9162 §5.3 split-view defense)**
//!    - bundle lacks `transparency_log_proof` or `inclusion_proof` null →
//!      `pcr-attestation-transparency-missing`.
//!    - `inclusion_proof_valid == false` → `pcr-attestation-transparency-invalid`.
//!    - `root_age_seconds > transparency_log_max_root_age_seconds` →
//!      `pcr-attestation-transparency-stale`.
//!    - `log_id` ∉ Tariff `trusted_transparency_logs` →
//!      `pcr-attestation-transparency-log-unknown`.
//!    - `entry_index > sth_tree_size` →
//!      `pcr-attestation-transparency-not-yet-logged`.
//!    - `required_witness_cosignatures > 0` but bundle empty →
//!      `pcr-attestation-witness-cosignature-missing`.
//! 10. **Trust filter** — any attestor not in Tariff's `attestors` set →
//!     `pcr-attestor-not-trusted`.
//! 11. **Quorum count** — trusted-valid count `< quorum` →
//!     `pcr-attestation-quorum-short`.
//! 12. **Cross-attestor PCR consistency** — any divergence among signers on any
//!     declared PCR index → `pcr-attestation-mismatch`. Split-brain is always
//!     a reject; Router MUST NOT pick a majority.
//! 13. **Expected-value mismatch** — unanimous attestor value ≠ Tariff's
//!     `expected_pcrs[i]` → `pcr-expected-mismatch`.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- constants ------------------------------------------------

/// Default transparency-log STH freshness window — 24h, matching CT / Rekor.
const DEFAULT_MAX_ROOT_AGE_SECONDS: u64 = 86_400;

/// Default clock-skew tolerance for `attestation-in-future`.
const DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 300;

/// TPM 2.0 / Nitro PCR index range (inclusive).
const PCR_INDEX_MAX: u32 = 23;

// ---------------- reject codes ---------------------------------------------

/// PCR-attestation reject codes per §9.4 + R8.P3/P6. Display strings match
/// the kebab-case `reject_code` the vector suite asserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PcrRejectCode {
    // Bundle transport / structural
    PcrBundleTooLarge,
    PcrBundleMalformed,
    // Tariff-side defects
    TariffPcrQuorumInvalid,
    // Attestor identity & trust
    PcrAttestorNotTrusted,
    PcrAttestorRevoked,
    PcrAttestorNotYetValid,
    PcrAttestorSignatureInvalid,
    PcrAttestorDuplicate,
    // Quorum
    PcrAttestationQuorumShort,
    // PCR content
    PcrAttestationMismatch,
    PcrExpectedMismatch,
    // Transparency log
    PcrAttestationTransparencyMissing,
    PcrAttestationTransparencyInvalid,
    PcrAttestationTransparencyStale,
    PcrAttestationTransparencyLogUnknown,
    PcrAttestationTransparencyNotYetLogged,
    PcrAttestationWitnessCosignatureMissing,
    // Freshness / replay
    PcrAttestationExpired,
    PcrAttestationFutureDated,
    PcrAttestationPredatesTariff,
    PcrAttestationNonceReuse,
    PcrAttestationNonceMismatch,
    // Live-crypto (Phase C.2) cert / COSE defects — only emitted by the
    // `execute_live_nitro` dispatch path for vectors carrying
    // `cose_sign1_bytes`.
    PcrAttestationCertExpired,
    PcrAttestationCertChainInvalid,
    PcrAttestationUnsupportedCoseAlg,
}

impl fmt::Display for PcrRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PcrBundleTooLarge => "pcr-bundle-too-large",
            Self::PcrBundleMalformed => "pcr-bundle-malformed",
            Self::TariffPcrQuorumInvalid => "tariff-pcr-quorum-invalid",
            Self::PcrAttestorNotTrusted => "pcr-attestor-not-trusted",
            Self::PcrAttestorRevoked => "pcr-attestor-revoked",
            Self::PcrAttestorNotYetValid => "pcr-attestor-not-yet-valid",
            Self::PcrAttestorSignatureInvalid => "pcr-attestor-signature-invalid",
            Self::PcrAttestorDuplicate => "pcr-attestor-duplicate",
            Self::PcrAttestationQuorumShort => "pcr-attestation-quorum-short",
            Self::PcrAttestationMismatch => "pcr-attestation-mismatch",
            Self::PcrExpectedMismatch => "pcr-expected-mismatch",
            Self::PcrAttestationTransparencyMissing => "pcr-attestation-transparency-missing",
            Self::PcrAttestationTransparencyInvalid => "pcr-attestation-transparency-invalid",
            Self::PcrAttestationTransparencyStale => "pcr-attestation-transparency-stale",
            Self::PcrAttestationTransparencyLogUnknown => "pcr-attestation-transparency-log-unknown",
            Self::PcrAttestationTransparencyNotYetLogged => {
                "pcr-attestation-transparency-not-yet-logged"
            }
            Self::PcrAttestationWitnessCosignatureMissing => {
                "pcr-attestation-witness-cosignature-missing"
            }
            Self::PcrAttestationExpired => "pcr-attestation-expired",
            Self::PcrAttestationFutureDated => "pcr-attestation-future-dated",
            Self::PcrAttestationPredatesTariff => "pcr-attestation-predates-tariff",
            Self::PcrAttestationNonceReuse => "pcr-attestation-nonce-reuse",
            Self::PcrAttestationNonceMismatch => "pcr-attestation-nonce-mismatch",
            Self::PcrAttestationCertExpired => "pcr-attestation-cert-expired",
            Self::PcrAttestationCertChainInvalid => "pcr-attestation-cert-chain-invalid",
            Self::PcrAttestationUnsupportedCoseAlg => "pcr-attestation-unsupported-cose-alg",
        })
    }
}

// ---------------- vector input model ---------------------------------------

#[derive(Debug, Deserialize)]
struct PcrInput {
    tariff_pcr_requirement: TariffPcrRequirement,
    #[serde(default)]
    attestation_bundle: Option<AttestationBundle>,
    /// Raw hex form used for bundle-malformed vectors (arbitrary bytes) and
    /// empty-bundle (`""`). Presence of this field short-circuits to
    /// `pcr-bundle-malformed`.
    #[serde(default)]
    attestation_bundle_raw_hex: Option<String>,
    #[serde(default)]
    attestation_bundle_declared_size_bytes: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    attestation_bundle_summary: Option<String>,
    current_time: i64,
    router_nonce_issued: String,
    #[serde(default)]
    router_nonce_consumed: Option<Vec<String>>,
    #[serde(default)]
    revocation_list: Option<Vec<RevocationEntry>>,
}

#[derive(Debug, Deserialize)]
struct TariffPcrRequirement {
    attestors: Vec<String>,
    quorum: u32,
    #[serde(default)]
    expected_pcrs: Option<HashMap<String, String>>,
    #[serde(default)]
    attestor_validity: Option<HashMap<String, ValidityWindow>>,
    #[serde(default)]
    transparency_log_max_root_age_seconds: Option<u64>,
    #[serde(default)]
    trusted_transparency_logs: Option<Vec<TrustedLog>>,
    #[serde(default)]
    strict_mode: Option<bool>,
    #[serde(default)]
    attestation_max_age_seconds: Option<u64>,
    #[serde(default)]
    bundle_max_size_bytes: Option<u64>,
    #[serde(default)]
    required_witness_cosignatures: Option<u32>,
    #[serde(default)]
    issued_at: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    classifier_wasm_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidityWindow {
    not_before: i64,
    #[serde(default)]
    #[allow(dead_code)]
    not_after: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TrustedLog {
    log_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    public_key: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    key_alg: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    origin_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AttestationBundle {
    #[serde(default)]
    #[allow(dead_code)]
    commit_hash: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    declared_attestor_count: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)]
    target_tariff_version: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    attestation_order: Option<String>,
    #[serde(default)]
    attestations: Vec<Attestation>,
    #[serde(default)]
    transparency_log_proof: Option<TransparencyLogProof>,
}

#[derive(Debug, Deserialize)]
struct Attestation {
    #[serde(default)]
    attestor_id: Option<String>,
    #[serde(default)]
    pcrs: HashMap<String, String>,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    signature_valid: bool,
    /// Non-schema smuggle field — triggers `pcr-bundle-malformed` in
    /// strict-mode Tariffs (pcrrej-034).
    #[serde(default)]
    attestor_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransparencyLogProof {
    log_id: String,
    /// `Some(true)` / `Some(false)` drive the valid / invalid branches.
    /// Absent means "no claim about validity" — the pro-forma field was set
    /// without supplying the proof, equivalent to missing.
    #[serde(default)]
    inclusion_proof_valid: Option<bool>,
    /// Literal JSON `null` from pcrrej-020 arrives as `Some(Value::Null)`;
    /// absence arrives as `None`. Both are treated as missing proof.
    #[serde(default)]
    inclusion_proof: Option<serde_json::Value>,
    #[serde(default)]
    root_age_seconds: Option<u64>,
    #[serde(default)]
    entry_index: Option<u64>,
    #[serde(default)]
    sth_tree_size: Option<u64>,
    #[serde(default)]
    witness_cosignatures: Option<Vec<serde_json::Value>>,

    // ── Phase C.2.5 live-Rekor dispatch inputs ──────────────────────────────
    //
    // When ALL of `proof_path_hex`, `sth_signature_hex`, `sth_tree_root_hex`,
    // `log_pubkey_hex`, `entry_leaf_hash_hex`, `sth_timestamp`, and
    // `current_time` are present, `classify_transparency_log` dispatches to
    // the live verifier (`classify_live_rekor`) which performs real Ed25519
    // STH verification + RFC 9162 §2.1.1 Merkle-proof replay. The bool hint
    // `inclusion_proof_valid` is ignored on the live path except as a
    // contradiction signal (Some(false) + full evidence → Invalid, never Pass).
    //
    // Partial presence — some live fields supplied, others missing — is a
    // presence-level contradiction and classifies as TransparencyInvalid.
    // This prevents vector authors from accidentally leaving a verifier in
    // the weaker mock path while appearing to supply real evidence.
    #[serde(default)]
    proof_path_hex: Option<Vec<String>>,
    #[serde(default)]
    sth_signature_hex: Option<String>,
    #[serde(default)]
    sth_timestamp: Option<i64>,
    #[serde(default)]
    sth_tree_root_hex: Option<String>,
    #[serde(default)]
    log_pubkey_hex: Option<String>,
    #[serde(default)]
    entry_leaf_hash_hex: Option<String>,
    #[serde(default)]
    current_time: Option<i64>,
    // These four are consumed only on the live-Rekor path
    // (`classify_live_rekor`, gated behind `test-fixtures`). Under default
    // builds they round-trip through serde without ever being read — the
    // dead-code lint would otherwise fire.
    #[serde(default)]
    #[cfg_attr(not(feature = "test-fixtures"), allow(dead_code))]
    log_id_hex: Option<String>,
    #[serde(default)]
    #[cfg_attr(not(feature = "test-fixtures"), allow(dead_code))]
    log_key_valid_from: Option<i64>,
    #[serde(default)]
    #[cfg_attr(not(feature = "test-fixtures"), allow(dead_code))]
    log_key_valid_until: Option<i64>,
    #[serde(default)]
    #[cfg_attr(not(feature = "test-fixtures"), allow(dead_code))]
    max_root_age_seconds_override: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RevocationEntry {
    attestor_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    revoked_at: Option<i64>,
}

// ---------------- public entry point ---------------------------------------

/// Execute one `pcr-attestation-reject` vector. Every PCR vector has
/// `expected.outcome == reject`; we derive the reject code via the
/// crate-private `classify` function and compare to
/// `vector.expected.reject_code`.
///
/// Dispatch: vectors carrying a top-level `cose_sign1_bytes` field go through
/// the Phase C.2 live-crypto path (`classify_live_nitro`, gated behind the
/// `test-fixtures` feature). All other vectors use the mock-boolean
/// `classify` path.
pub fn execute(vector: &Vector) -> ValidationOutcome {
    // Phase C.2 dispatch: live COSE_Sign1 / X.509 / ES384 path.
    if vector.input.get("cose_sign1_bytes").is_some() {
        #[cfg(feature = "test-fixtures")]
        {
            return execute_live_nitro(vector);
        }
        #[cfg(not(feature = "test-fixtures"))]
        {
            return ValidationOutcome::Fail {
                reason: "vector carries cose_sign1_bytes but ephemeral-core was \
                         built without the `test-fixtures` feature; rebuild the \
                         conformance harness with --features test-fixtures"
                    .to_owned(),
            };
        }
    }

    let input: PcrInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("pcr-input deserialization failed: {e}"),
            };
        }
    };

    let produced = classify(&input, &vector.category);

    let expected = &vector.expected;
    match expected.outcome {
        Outcome::Reject => {
            let Some(expected_code) = expected.reject_code.as_deref() else {
                return ValidationOutcome::Fail {
                    reason: "vector declares reject but omits reject_code".to_owned(),
                };
            };
            if produced.to_string() == expected_code {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!(
                        "reject_code mismatch: produced {produced}, expected {expected_code}"
                    ),
                }
            }
        }
        Outcome::Accept => ValidationOutcome::Fail {
            reason: "pcr-attestation-reject suite has no accept vectors".to_owned(),
        },
    }
}

// ---------------- classification core --------------------------------------

fn classify(input: &PcrInput, category: &str) -> PcrRejectCode {
    // 1. Size cap (pcrrej-047).
    if let (Some(declared), Some(max)) = (
        input.attestation_bundle_declared_size_bytes,
        input.tariff_pcr_requirement.bundle_max_size_bytes,
    ) {
        if declared > max {
            return PcrRejectCode::PcrBundleTooLarge;
        }
    }

    // 2. Raw-hex / empty bundle (pcrrej-031, 046).
    if input.attestation_bundle_raw_hex.is_some() {
        return PcrRejectCode::PcrBundleMalformed;
    }

    // 3. Tariff-PCR invariants (pcrrej-006, 030, 048).
    if let Some(code) = classify_tariff_defects(&input.tariff_pcr_requirement) {
        return code;
    }

    // Bundle must exist from here on.
    let Some(bundle) = input.attestation_bundle.as_ref() else {
        return PcrRejectCode::PcrBundleMalformed;
    };

    // 4. Bundle structural (pcrrej-032, 033, 034, 035).
    if let Some(code) = classify_bundle_structural(bundle, &input.tariff_pcr_requirement) {
        return code;
    }

    // 5. Duplicate attestor (pcrrej-012).
    if let Some(code) = detect_duplicate_attestor(bundle) {
        return code;
    }

    // 6. Per-attestor scans (pcrrej-009, 010, 011).
    if let Some(code) = per_attestor_scans(
        bundle,
        &input.tariff_pcr_requirement,
        input.revocation_list.as_deref(),
    ) {
        return code;
    }

    // 7. Freshness (pcrrej-036, 037, 038, 039, 041).
    if let Some(code) = classify_freshness(bundle, &input.tariff_pcr_requirement, input.current_time)
    {
        return code;
    }

    // 8. Nonce binding (pcrrej-040, 042).
    if let Some(code) = classify_nonce(bundle, input) {
        return code;
    }

    // 9. Transparency log (pcrrej-019 - 024, 045).
    if let Some(code) = classify_transparency_log(bundle, &input.tariff_pcr_requirement) {
        return code;
    }

    // 10. Trusted-list filter (pcrrej-007, 008).
    if let Some(code) = classify_trust_filter(bundle, &input.tariff_pcr_requirement) {
        return code;
    }

    // 11. Quorum count (pcrrej-001..005, 044).
    let trusted_count = count_trusted_valid(bundle, &input.tariff_pcr_requirement);
    if trusted_count < input.tariff_pcr_requirement.quorum {
        return PcrRejectCode::PcrAttestationQuorumShort;
    }

    // 12. Cross-attestor PCR consistency (pcrrej-013..018, 043, 049).
    if cross_attestor_mismatch(bundle, &input.tariff_pcr_requirement) {
        return PcrRejectCode::PcrAttestationMismatch;
    }

    // 13. Expected-value mismatch (pcrrej-025..029).
    if expected_value_mismatch(bundle, &input.tariff_pcr_requirement) {
        return PcrRejectCode::PcrExpectedMismatch;
    }

    // Category fallback: derive from label. Reached only if semantic checks
    // above all said "fine". This keeps the executor honest about unmatched
    // vectors — the final judgment comes from the expected reject_code, and a
    // category-only mapping surfaces what the vector claims.
    category_to_code(category)
}

// ---------------- sub-classifiers ------------------------------------------

fn classify_tariff_defects(req: &TariffPcrRequirement) -> Option<PcrRejectCode> {
    // §2.2 baseline is "min 3 attestors; quorum 2-of-3". pcrrej-048 rejects
    // quorum=1 when attestor set is ≥3. Quorum=0 is always invalid (pcrrej-006).
    if req.quorum == 0 {
        return Some(PcrRejectCode::TariffPcrQuorumInvalid);
    }
    if req.quorum == 1 && req.attestors.len() >= 3 {
        return Some(PcrRejectCode::TariffPcrQuorumInvalid);
    }
    // pcrrej-030: `expected_pcrs` absent. The suite folds missing-PCR-map into
    // `tariff-pcr-quorum-invalid` per the vector's rationale: "Router cannot
    // verify arbitrary PCRs against an undefined expectation. Fail closed >
    // fail open." No dedicated missing-map reject code exists in the spec.
    if req.expected_pcrs.is_none() {
        return Some(PcrRejectCode::TariffPcrQuorumInvalid);
    }
    None
}

fn classify_bundle_structural(
    bundle: &AttestationBundle,
    req: &TariffPcrRequirement,
) -> Option<PcrRejectCode> {
    let strict = req.strict_mode.unwrap_or(false);
    for att in &bundle.attestations {
        // pcrrej-032: missing attestor_id.
        if att.attestor_id.is_none() {
            return Some(PcrRejectCode::PcrBundleMalformed);
        }
        // pcrrej-033: missing iat.
        if att.iat.is_none() {
            return Some(PcrRejectCode::PcrBundleMalformed);
        }
        // pcrrej-034: strict-mode unknown field.
        if strict && att.attestor_comment.is_some() {
            return Some(PcrRejectCode::PcrBundleMalformed);
        }
        // pcrrej-035: PCR index outside [0..23].
        for index in att.pcrs.keys() {
            if !pcr_index_valid(index) {
                return Some(PcrRejectCode::PcrBundleMalformed);
            }
        }
    }
    None
}

fn pcr_index_valid(key: &str) -> bool {
    let Some(num) = key.strip_prefix("PCR") else {
        return false;
    };
    match num.parse::<u32>() {
        Ok(n) => n <= PCR_INDEX_MAX,
        Err(_) => false,
    }
}

fn detect_duplicate_attestor(bundle: &AttestationBundle) -> Option<PcrRejectCode> {
    let mut seen = BTreeSet::new();
    for att in &bundle.attestations {
        if let Some(id) = att.attestor_id.as_deref() {
            if !seen.insert(id.to_owned()) {
                return Some(PcrRejectCode::PcrAttestorDuplicate);
            }
        }
    }
    None
}

fn per_attestor_scans(
    bundle: &AttestationBundle,
    req: &TariffPcrRequirement,
    revocation_list: Option<&[RevocationEntry]>,
) -> Option<PcrRejectCode> {
    for att in &bundle.attestations {
        if !att.signature_valid {
            return Some(PcrRejectCode::PcrAttestorSignatureInvalid);
        }
        let Some(id) = att.attestor_id.as_deref() else {
            continue;
        };
        if let Some(list) = revocation_list {
            if list.iter().any(|r| r.attestor_id == id) {
                return Some(PcrRejectCode::PcrAttestorRevoked);
            }
        }
        if let (Some(windows), Some(iat)) = (req.attestor_validity.as_ref(), att.iat) {
            if let Some(w) = windows.get(id) {
                if iat < w.not_before {
                    return Some(PcrRejectCode::PcrAttestorNotYetValid);
                }
            }
        }
    }
    None
}

fn classify_freshness(
    bundle: &AttestationBundle,
    req: &TariffPcrRequirement,
    current_time: i64,
) -> Option<PcrRejectCode> {
    for att in &bundle.attestations {
        let Some(iat) = att.iat else {
            continue;
        };
        // Expired (pcrrej-036, 037, 041).
        if let Some(max_age) = req.attestation_max_age_seconds {
            if current_time.saturating_sub(iat) > i64::try_from(max_age).unwrap_or(i64::MAX) {
                return Some(PcrRejectCode::PcrAttestationExpired);
            }
        }
        // Future-dated (pcrrej-038). Reject if iat exceeds current_time plus
        // tolerance.
        if iat > current_time.saturating_add(DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS) {
            return Some(PcrRejectCode::PcrAttestationFutureDated);
        }
        // Predates tariff (pcrrej-039).
        if let Some(issued_at) = req.issued_at {
            if iat < issued_at {
                return Some(PcrRejectCode::PcrAttestationPredatesTariff);
            }
        }
    }
    None
}

fn classify_nonce(bundle: &AttestationBundle, input: &PcrInput) -> Option<PcrRejectCode> {
    let issued = input.router_nonce_issued.as_str();
    // pcrrej-040: consumed set contains issued nonce.
    if let Some(consumed) = input.router_nonce_consumed.as_deref() {
        if consumed.iter().any(|n| n == issued) {
            return Some(PcrRejectCode::PcrAttestationNonceReuse);
        }
    }
    // pcrrej-042: any attestor carries a different nonce.
    for att in &bundle.attestations {
        if let Some(nonce) = att.nonce.as_deref() {
            if nonce != issued {
                return Some(PcrRejectCode::PcrAttestationNonceMismatch);
            }
        }
    }
    None
}

fn classify_transparency_log(
    bundle: &AttestationBundle,
    req: &TariffPcrRequirement,
) -> Option<PcrRejectCode> {
    let Some(proof) = bundle.transparency_log_proof.as_ref() else {
        return Some(PcrRejectCode::PcrAttestationTransparencyMissing);
    };
    // pcrrej-020: inclusion_proof literal null.
    if matches!(&proof.inclusion_proof, Some(serde_json::Value::Null)) {
        return Some(PcrRejectCode::PcrAttestationTransparencyMissing);
    }

    // ── Phase C.2.5 presence-based dispatch ─────────────────────────────────
    //
    // When the vector supplies any live-Rekor field, the verifier runs the
    // real Ed25519 + Merkle path. Partial presence (some fields set, others
    // missing) is itself a reject — it signals a vector authored to exercise
    // live verification that arrives with insufficient evidence. We use
    // TransparencyInvalid for this case rather than BundleMalformed because
    // the structure IS well-formed JSON; what's wrong is the cryptographic
    // claim, and an adversary presenting partial evidence is attempting to
    // bypass the log.
    let live_presence = live_rekor_presence(proof);
    match live_presence {
        LiveRekorPresence::None => {
            // Fall through to the mock-bool classifier below.
        }
        LiveRekorPresence::Partial => {
            return Some(PcrRejectCode::PcrAttestationTransparencyInvalid);
        }
        LiveRekorPresence::Full => {
            // If the vector additionally stamps `inclusion_proof_valid: false`
            // it is declaring the proof adversarial — do not spend CPU cycles
            // attempting to verify, and never let a Pass-producing verifier
            // accept a proof the vector author flagged as invalid.
            if matches!(proof.inclusion_proof_valid, Some(false)) {
                return Some(PcrRejectCode::PcrAttestationTransparencyInvalid);
            }
            #[cfg(feature = "test-fixtures")]
            {
                // `Ok(())` → `None` → outer pipeline proceeds past
                // transparency into quorum / cross-attestor / expected-value.
                // `Err(code)` → `Some(code)` → that precise reject fires.
                return classify_live_rekor(proof, req).err();
            }
            #[cfg(not(feature = "test-fixtures"))]
            {
                // Vector carries live-Rekor evidence but the crate was built
                // without the `test-fixtures` feature. Mirror execute()'s
                // cose_sign1 handling: emit a Pass-blocker rather than silently
                // falling into the mock-bool classifier, which would produce a
                // misleadingly green result.
                return Some(PcrRejectCode::PcrAttestationTransparencyInvalid);
            }
        }
    }

    // ── Mock-bool path (legacy pcrrej-020..024 + 045) ──────────────────────
    //
    // pcrrej-021: proof declared invalid.
    if matches!(proof.inclusion_proof_valid, Some(false)) {
        return Some(PcrRejectCode::PcrAttestationTransparencyInvalid);
    }
    // pcrrej-022: stale root.
    if let Some(age) = proof.root_age_seconds {
        let max = req
            .transparency_log_max_root_age_seconds
            .unwrap_or(DEFAULT_MAX_ROOT_AGE_SECONDS);
        if age > max {
            return Some(PcrRejectCode::PcrAttestationTransparencyStale);
        }
    }
    // pcrrej-023: log_id not in trusted set.
    //
    // Fail-closed (H-1): a missing Tariff `trusted_transparency_logs` list
    // is itself a reject (TransparencyLogUnknown). An absent trust anchor
    // cannot accept any log; allowing the check to be skipped when the
    // list is absent is a permissive default that would let a Tariff which
    // forgot to pin its logs accept arbitrary Rekor-like claims.
    //
    // On this mock-bool path `t.log_id == proof.log_id` is a plain string
    // comparison — a free-form identifier, not a cryptographic commitment.
    // The branch is only reachable when
    // `live_rekor_presence(proof) == LiveRekorPresence::None`; a live-Rekor
    // vector (presence == Full) routes through `classify_live_rekor`, which
    // canonicalises the log identity to its 32-byte `log_id_bytes` form
    // (bound into the STH signing payload) and matches against the same
    // Tariff `trusted_transparency_logs` list on those bytes — closing the
    // string-vs-bytes split-view hazard. A second, lower fail-closed net
    // (`ALLOWED_LOG_IDS` in `ephemeral_attestation::rekor`) rejects any
    // `log_id` not on the hard-coded allow-list regardless of Tariff input.
    let Some(trusted) = req.trusted_transparency_logs.as_deref() else {
        return Some(PcrRejectCode::PcrAttestationTransparencyLogUnknown);
    };
    if !trusted.iter().any(|t| t.log_id == proof.log_id) {
        return Some(PcrRejectCode::PcrAttestationTransparencyLogUnknown);
    }
    // pcrrej-024: entry_index beyond tree head.
    if let (Some(idx), Some(size)) = (proof.entry_index, proof.sth_tree_size) {
        if idx > size {
            return Some(PcrRejectCode::PcrAttestationTransparencyNotYetLogged);
        }
    }
    // pcrrej-045: required witness cosignatures missing.
    if let Some(required) = req.required_witness_cosignatures {
        if required > 0 {
            let present = proof
                .witness_cosignatures
                .as_ref()
                .map_or(0, Vec::len);
            if u32::try_from(present).unwrap_or(u32::MAX) < required {
                return Some(PcrRejectCode::PcrAttestationWitnessCosignatureMissing);
            }
        }
    }
    None
}

/// Classification of the live-Rekor evidence fields supplied by a vector.
///
/// - `None`   → no live fields present; legacy mock-bool classifier applies.
/// - `Partial`→ some live fields but not the minimum set; treat as adversarial.
/// - `Full`   → every field needed to run real verification is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveRekorPresence {
    None,
    Partial,
    Full,
}

/// Names of the seven JSON fields on a `TransparencyLogProof` whose *joint*
/// presence routes a vector to the live-Rekor classifier. Kept as a single
/// source of truth so external tooling (e.g. the CLI transparency summary)
/// can classify raw-JSON proofs without re-declaring the field list.
///
/// Changing this list is a semver-equivalent event for the live-dispatch
/// boundary: add a field here and the validator starts refusing to run the
/// live path for vectors that were previously `Full`. Keep in lock-step with
/// the typed [`live_rekor_presence`] flag array.
const LIVE_REKOR_PROOF_FIELDS: [&str; 7] = [
    "proof_path_hex",
    "sth_signature_hex",
    "sth_timestamp",
    "sth_tree_root_hex",
    "log_pubkey_hex",
    "entry_leaf_hash_hex",
    "current_time",
];

/// Returns `true` iff `proof` (a JSON node matching the
/// `TransparencyLogProof` shape) carries every one of the seven live-Rekor
/// fields with a non-null value — i.e. would classify as `Full` under the
/// crate-private typed classifier `live_rekor_presence`.
///
/// Intended for external harnesses that only have the raw JSON (the CLI
/// transparency summary, for example). Partial or absent presence returns
/// `false`; callers that need to distinguish the three states must use
/// the typed classifier inside this crate.
///
/// Non-object inputs return `false` — a consistent safe default for any
/// walker that can't guarantee it hands us a proof object.
#[must_use]
pub fn is_live_rekor_proof(proof: &Value) -> bool {
    LIVE_REKOR_PROOF_FIELDS
        .iter()
        .all(|field| proof.get(*field).is_some_and(|v| !v.is_null()))
}

fn live_rekor_presence(proof: &TransparencyLogProof) -> LiveRekorPresence {
    // Only live-exclusive fields participate in presence detection. Legacy
    // mock-bool vectors set `entry_index` / `sth_tree_size` / `log_id`
    // without implying a live proof — those flow through the mock-bool path
    // (pcrrej-024 is the canonical example: entry_index > sth_tree_size →
    // NotYetLogged).
    //
    // The flag array order mirrors `LIVE_REKOR_PROOF_FIELDS` so the typed
    // classifier and the JSON-side [`is_live_rekor_proof`] stay in lock-step.
    let flags = [
        proof.proof_path_hex.is_some(),
        proof.sth_signature_hex.is_some(),
        proof.sth_timestamp.is_some(),
        proof.sth_tree_root_hex.is_some(),
        proof.log_pubkey_hex.is_some(),
        proof.entry_leaf_hash_hex.is_some(),
        proof.current_time.is_some(),
    ];
    let set = flags.iter().filter(|b| **b).count();
    if set == 0 {
        LiveRekorPresence::None
    } else if set == flags.len() {
        LiveRekorPresence::Full
    } else {
        LiveRekorPresence::Partial
    }
}

fn classify_trust_filter(
    bundle: &AttestationBundle,
    req: &TariffPcrRequirement,
) -> Option<PcrRejectCode> {
    for att in &bundle.attestations {
        let Some(id) = att.attestor_id.as_deref() else {
            continue;
        };
        if !req.attestors.iter().any(|a| a == id) {
            return Some(PcrRejectCode::PcrAttestorNotTrusted);
        }
    }
    None
}

fn count_trusted_valid(bundle: &AttestationBundle, req: &TariffPcrRequirement) -> u32 {
    let mut seen = BTreeSet::new();
    for att in &bundle.attestations {
        if !att.signature_valid {
            continue;
        }
        if let Some(id) = att.attestor_id.as_deref() {
            if req.attestors.iter().any(|a| a == id) {
                seen.insert(id.to_owned());
            }
        }
    }
    u32::try_from(seen.len()).unwrap_or(u32::MAX)
}

fn cross_attestor_mismatch(bundle: &AttestationBundle, req: &TariffPcrRequirement) -> bool {
    let Some(expected) = req.expected_pcrs.as_ref() else {
        return false;
    };
    // For each declared PCR index in the Tariff, every signing trusted attestor
    // MUST report the same value. Split-brain → reject.
    for index in expected.keys() {
        let mut value: Option<&String> = None;
        for att in &bundle.attestations {
            if !att.signature_valid {
                continue;
            }
            let Some(id) = att.attestor_id.as_deref() else {
                continue;
            };
            if !req.attestors.iter().any(|a| a == id) {
                continue;
            }
            if let Some(v) = att.pcrs.get(index) {
                match value {
                    None => value = Some(v),
                    Some(prev) if prev != v => return true,
                    _ => {}
                }
            }
        }
    }
    false
}

fn expected_value_mismatch(bundle: &AttestationBundle, req: &TariffPcrRequirement) -> bool {
    let Some(expected) = req.expected_pcrs.as_ref() else {
        return false;
    };
    // We already know cross-attestor consistency holds; pick the first trusted,
    // signature-valid attestor's PCR for each declared index and compare.
    for (index, want) in expected {
        let got = bundle
            .attestations
            .iter()
            .find(|att| {
                att.signature_valid
                    && att
                        .attestor_id
                        .as_deref()
                        .is_some_and(|id| req.attestors.iter().any(|a| a == id))
                    && att.pcrs.contains_key(index)
            })
            .and_then(|att| att.pcrs.get(index));
        match got {
            None => return true,
            Some(v) if v != want => return true,
            _ => {}
        }
    }
    false
}

/// Fallback: derive reject code from the vector's `category` label. Only
/// reached when no structural check fires; used so rare vectors whose defects
/// are entirely encoded in the category (rather than observable input state)
/// still classify consistently.
#[allow(clippy::match_same_arms)]
fn category_to_code(category: &str) -> PcrRejectCode {
    match category {
        "quorum-short-by-one"
        | "quorum-short-majority-missing"
        | "quorum-all-missing"
        | "quorum-wrong-count"
        | "adversary-signed-by-stolen-attestor-key" => PcrRejectCode::PcrAttestationQuorumShort,
        "quorum-threshold-zero-in-tariff"
        | "pcr-expected-missing-in-tariff"
        | "bundle-with-one-attestor-quorum-one" => PcrRejectCode::TariffPcrQuorumInvalid,
        "attestor-not-in-trusted-list" => PcrRejectCode::PcrAttestorNotTrusted,
        "attestor-key-revoked" => PcrRejectCode::PcrAttestorRevoked,
        "attestor-key-not-yet-valid" => PcrRejectCode::PcrAttestorNotYetValid,
        "attestor-signature-invalid" => PcrRejectCode::PcrAttestorSignatureInvalid,
        "attestor-duplicate-in-bundle" => PcrRejectCode::PcrAttestorDuplicate,
        "pcr-mismatch-minor-single-pcr"
        | "pcr-mismatch-systematic-multiple-pcrs"
        | "pcr-mismatch-subset-of-attestors-agree"
        | "pcr-mismatch-one-attestor-all-zeros"
        | "pcr-mismatch-expected-deviation-allowed"
        | "adversary-pcr-rehydration-attack"
        | "bundle-attestor-list-order-matters" => PcrRejectCode::PcrAttestationMismatch,
        "pcr-expected-mismatch-PCR8-payload"
        | "pcr-expected-mismatch-PCR0-firmware"
        | "pcr-expected-mismatch-PCR4-kernel"
        | "pcr-expected-match-but-stale-tariff-expected-hash" => PcrRejectCode::PcrExpectedMismatch,
        "transparency-log-missing-inclusion-proof" => {
            PcrRejectCode::PcrAttestationTransparencyMissing
        }
        "transparency-log-invalid-proof" => PcrRejectCode::PcrAttestationTransparencyInvalid,
        "transparency-log-stale-root" => PcrRejectCode::PcrAttestationTransparencyStale,
        "transparency-log-unknown-log" => PcrRejectCode::PcrAttestationTransparencyLogUnknown,
        "transparency-log-not-published-yet" => {
            PcrRejectCode::PcrAttestationTransparencyNotYetLogged
        }
        "adversary-transparency-log-split-view" => {
            PcrRejectCode::PcrAttestationWitnessCosignatureMissing
        }
        "bundle-malformed-cbor"
        | "bundle-missing-required-field"
        | "bundle-unknown-additional-fields"
        | "bundle-incorrect-pcr-indexing"
        | "empty-bundle" => PcrRejectCode::PcrBundleMalformed,
        "enormous-bundle" => PcrRejectCode::PcrBundleTooLarge,
        "attestation-too-old" | "adversary-replayed-old-attestation" => {
            PcrRejectCode::PcrAttestationExpired
        }
        "attestation-in-future" => PcrRejectCode::PcrAttestationFutureDated,
        "attestation-predates-tariff" => PcrRejectCode::PcrAttestationPredatesTariff,
        "attestation-nonce-reuse" => PcrRejectCode::PcrAttestationNonceReuse,
        "adversary-attestation-bundle-for-different-nonce" => {
            PcrRejectCode::PcrAttestationNonceMismatch
        }
        _ => PcrRejectCode::PcrBundleMalformed,
    }
}

// ---------------- Phase C.2: live Nitro path -------------------------------
//
// Vectors with top-level `cose_sign1_bytes` drive real ES384 / X.509 /
// COSE_Sign1 verification via the `ephemeral-attestation` crate. The mock
// classifier is bypassed entirely on this branch.

#[cfg(feature = "test-fixtures")]
use ephemeral_attestation::{
    rekor::{
        verify_rekor_inclusion, verify_rekor_sth, RekorEntry, RekorKeySet, RekorSignedTreeHead,
        VerifyingKey as RekorVerifyingKey, MAX_INCLUSION_DEPTH, MAX_STH_AGE_SECONDS,
    },
    verify_nitro_attestation, verify_pcr_set, AttestError, NitroRootSet,
};

/// Upper bound on `trusted_roots_der_hex` entries per live-Nitro vector.
///
/// AWS Nitro attestations chain through a Root + Intermediate; a sensible
/// conformance vector carries at most a handful of pinned roots. Capping
/// prevents a pathological or adversarial vector from forcing the decoder
/// through thousands of DER parses before any other check runs.
#[cfg(feature = "test-fixtures")]
const MAX_TRUSTED_ROOTS: usize = 8;

/// Vector input shape for Phase C.2 live-crypto vectors.
///
/// The fields are disjoint from [`PcrInput`] — dispatch between the two lives
/// in [`execute`] via the presence of `cose_sign1_bytes`.
#[cfg(feature = "test-fixtures")]
#[derive(Debug, Deserialize)]
struct LiveNitroInput {
    /// Hex-encoded CBOR `d2 84 …` COSE_Sign1 attestation document.
    cose_sign1_bytes: String,
    /// DER-encoded trusted root certificates, hex-encoded.
    trusted_roots_der_hex: Vec<String>,
    /// Optional expected nonce, hex-encoded. `null` means no freshness check.
    #[serde(default)]
    expected_nonce_hex: Option<String>,
    /// Expected PCR map: `"PCR<n>"` → hex-encoded hash bytes.
    expected_pcrs: HashMap<String, String>,
    /// Caller clock — used for cert validity (`not_before` / `not_after`).
    current_time: i64,
}

#[cfg(feature = "test-fixtures")]
fn execute_live_nitro(vector: &Vector) -> ValidationOutcome {
    let input: LiveNitroInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("live-nitro input deserialization failed: {e}"),
            };
        }
    };

    let classification = classify_live_nitro(&input);

    let expected = &vector.expected;
    match (expected.outcome, classification) {
        (Outcome::Reject, Err(produced)) => {
            let Some(expected_code) = expected.reject_code.as_deref() else {
                return ValidationOutcome::Fail {
                    reason: "vector declares reject but omits reject_code".to_owned(),
                };
            };
            if produced.to_string() == expected_code {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!(
                        "reject_code mismatch: produced {produced}, expected {expected_code}"
                    ),
                }
            }
        }
        (Outcome::Reject, Ok(())) => ValidationOutcome::Fail {
            reason: "live-nitro verify succeeded but vector expected reject".to_owned(),
        },
        (Outcome::Accept, _) => ValidationOutcome::Fail {
            reason: "pcr-attestation-reject suite has no accept vectors".to_owned(),
        },
    }
}

/// Run the live-Nitro verification pipeline for one conformance vector.
///
/// Returns `Ok(())` when every check (COSE signature, cert chain, nonce, PCRs)
/// passes. Returns `Err(code)` with the specific reject code that fired first.
/// The reject-only corpus expects an `Err` for every vector; `Ok(())` is a
/// surfaceable condition that [`execute_live_nitro`] turns into a failure
/// message rather than hiding under a synthetic reject code.
#[cfg(feature = "test-fixtures")]
fn classify_live_nitro(input: &LiveNitroInput) -> Result<(), PcrRejectCode> {
    // 1. Decode hex payload.
    let cose_bytes = hex::decode(&input.cose_sign1_bytes)
        .map_err(|_| PcrRejectCode::PcrBundleMalformed)?;

    // 2. Build NitroRootSet from supplied hex roots. The test-fixtures insert
    //    path accepts roots without fingerprint pinning; production builds do
    //    not expose this method.  Cap the list so an adversarial vector
    //    cannot force arbitrary DER-parse work before any other check.
    if input.trusted_roots_der_hex.len() > MAX_TRUSTED_ROOTS {
        return Err(PcrRejectCode::PcrBundleMalformed);
    }
    let mut roots = NitroRootSet::new();
    for h in &input.trusted_roots_der_hex {
        let der = hex::decode(h).map_err(|_| PcrRejectCode::PcrBundleMalformed)?;
        roots
            .insert_trusted_der_for_test(&der)
            .map_err(|_| PcrRejectCode::PcrBundleMalformed)?;
    }

    // 3. Optional nonce.
    let nonce_bytes: Option<Vec<u8>> = match input.expected_nonce_hex.as_deref() {
        Some(h) => Some(hex::decode(h).map_err(|_| PcrRejectCode::PcrBundleMalformed)?),
        None => None,
    };

    // 4. Run live verify.
    let claims = verify_nitro_attestation(
        &cose_bytes,
        &roots,
        nonce_bytes.as_deref(),
        input.current_time,
    )
    .map_err(|e| map_attest_error(&e))?;

    // 5. PCR check: decode expected_pcrs into (u8, Vec<u8>) pairs, then call
    //    verify_pcr_set. Allocation of the owned hash buffers has to live
    //    across the call because verify_pcr_set takes slice references.
    let mut expected_owned: Vec<(u8, Vec<u8>)> = Vec::with_capacity(input.expected_pcrs.len());
    for (key, value) in &input.expected_pcrs {
        let id_str = key
            .strip_prefix("PCR")
            .ok_or(PcrRejectCode::PcrBundleMalformed)?;
        let id = id_str
            .parse::<u8>()
            .map_err(|_| PcrRejectCode::PcrBundleMalformed)?;
        let hash = hex::decode(value).map_err(|_| PcrRejectCode::PcrBundleMalformed)?;
        expected_owned.push((id, hash));
    }
    let expected_refs: Vec<(u8, &[u8])> =
        expected_owned.iter().map(|(i, h)| (*i, h.as_slice())).collect();

    verify_pcr_set(&claims, &expected_refs).map_err(|e| map_attest_error(&e))?;

    Ok(())
}

/// Map an `AttestError` to the corresponding PCR reject code.
///
/// Defensive: mappings for variants not exercised by current c2-live vectors
/// (Rekor, PayloadTooLarge, CertNotYetValid, …) still produce a defensible
/// code rather than panicking.
///
/// The explicit arms that map to the same reject code as the wildcard are
/// kept deliberately — they document which variants have been audited and
/// intentionally fold into `PcrBundleMalformed`, as opposed to novel
/// `#[non_exhaustive]` variants caught by the final wildcard.
#[cfg(feature = "test-fixtures")]
#[allow(clippy::match_same_arms)]
fn map_attest_error(e: &AttestError) -> PcrRejectCode {
    match e {
        AttestError::SignatureInvalid { .. } => PcrRejectCode::PcrAttestorSignatureInvalid,
        AttestError::NonceMismatch => PcrRejectCode::PcrAttestationNonceMismatch,
        AttestError::PcrMismatch { .. } => PcrRejectCode::PcrAttestationMismatch,
        AttestError::CertExpired { .. } | AttestError::CertNotYetValid { .. } => {
            PcrRejectCode::PcrAttestationCertExpired
        }
        AttestError::CaChainInvalid { .. } | AttestError::CaChainTooLong { .. } => {
            PcrRejectCode::PcrAttestationCertChainInvalid
        }
        AttestError::UntrustedRoot { .. } => PcrRejectCode::PcrAttestorNotTrusted,
        AttestError::UnsupportedAlg { .. } => PcrRejectCode::PcrAttestationUnsupportedCoseAlg,
        AttestError::DuplicatePcrId { .. }
        | AttestError::PcrIndexOutOfRange { .. }
        | AttestError::WeakHashAlg { .. }
        | AttestError::MalformedDoc { .. }
        | AttestError::PayloadTooLarge { .. }
        | AttestError::CborDepthExceeded { .. } => PcrRejectCode::PcrBundleMalformed,
        // Rekor variants: mapped to the existing transparency-log codes.
        // Not exercised by c2-live yet; kept here so map_attest_error is total.
        AttestError::RekorProofInvalid { .. } => PcrRejectCode::PcrAttestationTransparencyInvalid,
        AttestError::RekorSthStale { .. } => PcrRejectCode::PcrAttestationTransparencyStale,
        AttestError::RekorLogUntrusted { .. } => {
            PcrRejectCode::PcrAttestationTransparencyLogUnknown
        }
        // #[non_exhaustive] safety net — any new AttestError variant must
        // pick an explicit code above. Falling through to malformed is the
        // safest fail-closed default.
        _ => PcrRejectCode::PcrBundleMalformed,
    }
}

// ---------------- Phase C.2.5: live Rekor path -----------------------------
//
// A `TransparencyLogProof` with every `*_hex` field populated drives real
// Ed25519 STH verification + RFC 9162 §2.1.1 Merkle-proof replay. The
// presence-based dispatch in `classify_transparency_log` is the gatekeeper;
// this function assumes it was called with full evidence.

/// Hex-decode helper. Returns `PcrAttestationTransparencyInvalid` on error
/// — malformed hex inside live-Rekor fields is adversarial, not a generic
/// bundle-structure bug. The field layout itself is well-formed JSON.
#[cfg(feature = "test-fixtures")]
fn decode_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], PcrRejectCode> {
    let bytes = hex::decode(s).map_err(|_| PcrRejectCode::PcrAttestationTransparencyInvalid)?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| PcrRejectCode::PcrAttestationTransparencyInvalid)
}

#[cfg(feature = "test-fixtures")]
fn decode_hex_var(s: &str) -> Result<Vec<u8>, PcrRejectCode> {
    hex::decode(s).map_err(|_| PcrRejectCode::PcrAttestationTransparencyInvalid)
}

/// Run the live-Rekor verification pipeline for one transparency-log proof.
///
/// Returns `Ok(())` when the proof is cryptographically valid and every
/// Tariff policy check passes. Returns `Err(code)` with the precise reject
/// code on first failure — these are the codes the conformance vectors
/// pcrrej-110..117 target.
///
/// The dispatch site (`classify_transparency_log`) collapses `Ok(())` into
/// `None` so the outer `execute()` pipeline proceeds to quorum,
/// cross-attestor, and expected-value checks. A vector authored as a
/// reject on some *other* basis (e.g., a bad quorum) still rejects at the
/// correct downstream step. A vector where every verifier check passes
/// will produce a Pass; the harness flags a `reject_code mismatch:
/// produced pass, expected ...`, which is the correct signal for a
/// vector-authorship error rather than a verifier bug.
///
/// Checks in order:
///
/// 1. Decode the fixed-width hex fields (log_id, keys, roots, leaf hash).
///    Malformed hex → `TransparencyInvalid` (adversarial framing).
/// 2. Ed25519 `VerifyingKey::from_bytes` on `log_pubkey_hex`.
/// 3. Policy: `log_id_bytes` must match a 32-byte-hex entry in Tariff's
///    `trusted_transparency_logs` (canonical identity: 32-byte STH-bound
///    form, closing the string-vs-bytes split-view hazard).
/// 4. Policy: STH timestamp age must be ≤ effective max-root-age
///    (`max_root_age_seconds_override` on the proof precedes the Tariff
///    value) → `PcrAttestationTransparencyStale`.
/// 5. Build a `RekorKeySet` via `insert_trusted_key_for_test`.
/// 6. `verify_rekor_sth` — Ed25519 strict signature + caller-clock freshness.
/// 7. `verify_rekor_inclusion` — RFC 9162 Merkle proof replay.
/// 8. Policy: witness cosignatures (`required_witness_cosignatures`).
#[cfg(feature = "test-fixtures")]
#[allow(clippy::too_many_lines)]
fn classify_live_rekor(
    proof: &TransparencyLogProof,
    req: &TariffPcrRequirement,
) -> Result<(), PcrRejectCode> {
    // ── 1. Decode hex fields ────────────────────────────────────────────────
    //
    // `let Some` destructuring is guarded-redundant: the dispatch gate
    // (`live_rekor_presence == Full`) already verified every field is
    // `Some`. Kept as belt-and-braces against future refactors of the gate.
    let Some(proof_path_hex) = proof.proof_path_hex.as_ref() else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(sth_sig_hex) = proof.sth_signature_hex.as_deref() else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(sth_timestamp) = proof.sth_timestamp else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(sth_tree_root_hex) = proof.sth_tree_root_hex.as_deref() else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(log_pubkey_hex) = proof.log_pubkey_hex.as_deref() else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(leaf_hash_hex) = proof.entry_leaf_hash_hex.as_deref() else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(current_time) = proof.current_time else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(tree_size) = proof.sth_tree_size else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };
    let Some(entry_index) = proof.entry_index else {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    };

    // DoS cap: bound proof-path decoding before we touch a single hex byte.
    // Mirrors MAX_INCLUSION_DEPTH in verify_rekor_inclusion; duplicated here
    // so we never allocate up to a million [u8;32]s for an adversarial vector
    // before the crate-level check gets to reject them.
    if proof_path_hex.len() > MAX_INCLUSION_DEPTH {
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    }

    let tree_root: [u8; 32] = decode_hex_fixed(sth_tree_root_hex)?;
    let leaf_hash: [u8; 32] = decode_hex_fixed(leaf_hash_hex)?;
    let pubkey_bytes: [u8; 32] = decode_hex_fixed(log_pubkey_hex)?;
    let sig_bytes = decode_hex_var(sth_sig_hex)?;

    // log_id may be supplied either as 32-byte hex (preferred, binds into
    // the STH signing payload) or as the string `log_id` field repurposed
    // as hex. Prefer the explicit hex form; fall back to parsing `log_id`.
    // The fallback's map_err converts hex-decode failure into the
    // adversarial-framing reject code: the live path requires a 32-byte
    // log_id because it is bound into the STH signature.
    let log_id_bytes: [u8; 32] = if let Some(h) = proof.log_id_hex.as_deref() {
        decode_hex_fixed(h)?
    } else {
        decode_hex_fixed::<32>(&proof.log_id)
            .map_err(|_| PcrRejectCode::PcrAttestationTransparencyInvalid)?
    };

    // Proof path: decode each sibling as a 32-byte fixed-width hash.
    let mut proof_path: Vec<[u8; 32]> = Vec::with_capacity(proof_path_hex.len());
    for p in proof_path_hex {
        proof_path.push(decode_hex_fixed(p)?);
    }

    // ── 2. Parse Ed25519 VerifyingKey ───────────────────────────────────────
    let verifying_key = RekorVerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| PcrRejectCode::PcrAttestationTransparencyInvalid)?;

    // ── 3. Policy: log_id must be in Tariff's trusted set ───────────────────
    //
    // Checked BEFORE cryptographic verification so an unknown-log attack
    // (spending verifier CPU on a key the Tariff does not even trust) is
    // rejected before we verify the Ed25519 signature.
    //
    // Fail-closed (H-1): a missing `trusted_transparency_logs` list is
    // itself a reject (TransparencyLogUnknown). An absent trust anchor
    // cannot accept any log; allowing the check to be skipped when the
    // list is None would let a Tariff that forgot to pin its logs accept
    // arbitrary log keys that pass verify_rekor_sth's local gate only.
    //
    // Canonical identity on the live path is the 32-byte STH-bound
    // `log_id_bytes` (already decoded above), NOT the free-form
    // `proof.log_id` string. Comparing the string form would expose a
    // split-view hazard: an adversary could set `proof.log_id = "rekor-v1"`
    // to satisfy a Tariff trust-entry that still carries the legacy
    // human-readable identifier while supplying a `log_id_hex` that signs
    // a completely different STH. Instead, every Tariff trust entry is
    // decoded as 32-byte hex and byte-compared against `log_id_bytes`.
    // Trust entries that cannot be decoded as 32-byte hex are treated as
    // non-live-log entries and contribute no trust (fail-closed).
    let trusted = req
        .trusted_transparency_logs
        .as_deref()
        .ok_or(PcrRejectCode::PcrAttestationTransparencyLogUnknown)?;
    let trust_hit = trusted
        .iter()
        .any(|t| decode_hex_fixed::<32>(&t.log_id).is_ok_and(|b| b == log_id_bytes));
    if !trust_hit {
        return Err(PcrRejectCode::PcrAttestationTransparencyLogUnknown);
    }

    // ── 4. Policy: Tariff freshness window ──────────────────────────────────
    //
    // Two freshness boundaries apply:
    //   (a) Tariff's `transparency_log_max_root_age_seconds` — policy-level,
    //       this is the "how fresh must this STH be for this Tariff" window.
    //   (b) MAX_STH_AGE_SECONDS — crate-level hard cap inside verify_rekor_sth,
    //       preventing any verifier from accepting a week-old STH even if
    //       the Tariff were reckless enough to ask for it.
    //
    // We enforce (a) here explicitly so the reject code is
    // TransparencyStale (not TransparencyInvalid that would come out of
    // verify_rekor_sth's crate-level cap).
    //
    // `max_root_age_seconds_override` on the proof can only tighten the
    // Tariff freshness window, never loosen it (H-2). The effective max is
    // `min(override, base)`: if the override is larger than the Tariff
    // value, the Tariff value wins; if smaller, the override wins. This
    // prevents an attestor-supplied proof from relaxing the Tariff's
    // freshness policy by presenting a larger tolerance. Test vectors that
    // want to drive the Stale path with a tighter window than the live
    // Tariff would normally permit still work, because tightening is
    // allowed. Production callers do not populate the override; the Tariff
    // value wins by default.
    let base = req
        .transparency_log_max_root_age_seconds
        .unwrap_or(DEFAULT_MAX_ROOT_AGE_SECONDS);
    let tariff_max_age = proof
        .max_root_age_seconds_override
        .map_or(base, |o| o.min(base));
    let age_secs = current_time.saturating_sub(sth_timestamp);
    if age_secs < 0 {
        // STH from the future — cryptographic gate would catch this too,
        // but classifying as Invalid here produces a better vector mapping.
        return Err(PcrRejectCode::PcrAttestationTransparencyInvalid);
    }
    let age_u = u64::try_from(age_secs).unwrap_or(u64::MAX);
    if age_u > tariff_max_age {
        return Err(PcrRejectCode::PcrAttestationTransparencyStale);
    }

    // ── 5. Build a RekorKeySet covering (log_id, timestamp) ─────────────────
    let (key_valid_from, key_valid_until) = (
        proof.log_key_valid_from.unwrap_or(sth_timestamp),
        proof.log_key_valid_until.unwrap_or(sth_timestamp),
    );
    let mut keys = RekorKeySet::new();
    keys.insert_trusted_key_for_test(
        log_id_bytes,
        verifying_key,
        key_valid_from,
        key_valid_until,
    )
    .map_err(|_| PcrRejectCode::PcrAttestationTransparencyInvalid)?;

    // ── 6. Verify STH signature + crate-level freshness ─────────────────────
    let sth = RekorSignedTreeHead {
        tree_root,
        tree_size,
        timestamp: sth_timestamp,
        log_id: log_id_bytes,
        signature: sig_bytes,
    };
    verify_rekor_sth(&sth, &keys, current_time, MAX_STH_AGE_SECONDS)
        .map_err(|e| map_attest_error(&e))?;

    // ── 7. Verify Merkle inclusion proof ────────────────────────────────────
    let entry = RekorEntry {
        leaf_hash,
        proof_path,
        index: entry_index,
        tree_size,
    };
    verify_rekor_inclusion(&entry, &leaf_hash, &tree_root)
        .map_err(|e| map_attest_error(&e))?;

    // ── 8. Policy: witness cosignatures ─────────────────────────────────────
    if let Some(required) = req.required_witness_cosignatures {
        if required > 0 {
            let present = proof.witness_cosignatures.as_ref().map_or(0, Vec::len);
            if u32::try_from(present).unwrap_or(u32::MAX) < required {
                return Err(PcrRejectCode::PcrAttestationWitnessCosignatureMissing);
            }
        }
    }

    // All verifier policy checks passed. The dispatch site collapses
    // `Ok(())` into `None`, letting `execute()` proceed through the rest
    // of the pipeline.
    Ok(())
}

// ---------------- unit tests -----------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_input() -> serde_json::Value {
        json!({
            "tariff_pcr_requirement": {
                "attestors": ["A1", "A2", "A3"],
                "quorum": 2,
                "expected_pcrs": {"PCR0": "sha256:fw", "PCR4": "sha256:k", "PCR8": "sha256:app"},
                "trusted_transparency_logs": [{"log_id": "rekor-v1"}]
            },
            "attestation_bundle": {
                "commit_hash": "abc",
                "attestations": [
                    {"attestor_id": "A1", "pcrs": {"PCR0": "sha256:fw", "PCR4": "sha256:k", "PCR8": "sha256:app"}, "iat": 1_714_521_600_i64, "nonce": "r1", "signature_valid": true},
                    {"attestor_id": "A2", "pcrs": {"PCR0": "sha256:fw", "PCR4": "sha256:k", "PCR8": "sha256:app"}, "iat": 1_714_521_610_i64, "nonce": "r1", "signature_valid": true}
                ],
                "transparency_log_proof": {"log_id": "rekor-v1", "inclusion_proof_valid": true, "root_age_seconds": 100}
            },
            "current_time": 1_714_525_200_i64,
            "router_nonce_issued": "r1"
        })
    }

    fn classify_from(input: serde_json::Value, category: &str) -> PcrRejectCode {
        let p: PcrInput = serde_json::from_value(input).unwrap();
        classify(&p, category)
    }

    #[test]
    fn bundle_too_large_first() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["bundle_max_size_bytes"] = json!(1_048_576);
        v["attestation_bundle_declared_size_bytes"] = json!(10_485_760);
        assert_eq!(
            classify_from(v, "enormous-bundle"),
            PcrRejectCode::PcrBundleTooLarge
        );
    }

    #[test]
    fn raw_hex_triggers_malformed() {
        let v = json!({
            "tariff_pcr_requirement": {
                "attestors": ["A1", "A2", "A3"],
                "quorum": 2,
                "expected_pcrs": {"PCR0": "sha256:fw"}
            },
            "attestation_bundle_raw_hex": "ff7f80deadbeef",
            "current_time": 1_714_525_200_i64,
            "router_nonce_issued": "r31"
        });
        assert_eq!(
            classify_from(v, "bundle-malformed-cbor"),
            PcrRejectCode::PcrBundleMalformed
        );
    }

    #[test]
    fn quorum_zero_is_tariff_invalid() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["quorum"] = json!(0);
        assert_eq!(
            classify_from(v, "quorum-threshold-zero-in-tariff"),
            PcrRejectCode::TariffPcrQuorumInvalid
        );
    }

    #[test]
    fn quorum_one_with_three_attestors_is_tariff_invalid() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["quorum"] = json!(1);
        v["attestation_bundle"]["attestations"].as_array_mut().unwrap().pop();
        assert_eq!(
            classify_from(v, "bundle-with-one-attestor-quorum-one"),
            PcrRejectCode::TariffPcrQuorumInvalid
        );
    }

    #[test]
    fn missing_expected_pcrs_is_tariff_invalid() {
        let mut v = base_input();
        v["tariff_pcr_requirement"].as_object_mut().unwrap().remove("expected_pcrs");
        assert_eq!(
            classify_from(v, "pcr-expected-missing-in-tariff"),
            PcrRejectCode::TariffPcrQuorumInvalid
        );
    }

    #[test]
    fn missing_attestor_id_is_bundle_malformed() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][0]
            .as_object_mut()
            .unwrap()
            .remove("attestor_id");
        assert_eq!(
            classify_from(v, "bundle-missing-required-field"),
            PcrRejectCode::PcrBundleMalformed
        );
    }

    #[test]
    fn missing_iat_is_bundle_malformed() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][0]
            .as_object_mut()
            .unwrap()
            .remove("iat");
        assert_eq!(
            classify_from(v, "bundle-missing-required-field"),
            PcrRejectCode::PcrBundleMalformed
        );
    }

    #[test]
    fn strict_mode_rejects_unknown_field() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["strict_mode"] = json!(true);
        v["attestation_bundle"]["attestations"][0]["attestor_comment"] = json!("ignore");
        assert_eq!(
            classify_from(v, "bundle-unknown-additional-fields"),
            PcrRejectCode::PcrBundleMalformed
        );
    }

    #[test]
    fn pcr99_is_bundle_malformed() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][0]["pcrs"]["PCR99"] = json!("sha256:extra");
        assert_eq!(
            classify_from(v, "bundle-incorrect-pcr-indexing"),
            PcrRejectCode::PcrBundleMalformed
        );
    }

    #[test]
    fn duplicate_attestor() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][1]["attestor_id"] = json!("A1");
        assert_eq!(
            classify_from(v, "attestor-duplicate-in-bundle"),
            PcrRejectCode::PcrAttestorDuplicate
        );
    }

    #[test]
    fn signature_invalid_fires_before_quorum_short() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][1]["signature_valid"] = json!(false);
        assert_eq!(
            classify_from(v, "attestor-signature-invalid"),
            PcrRejectCode::PcrAttestorSignatureInvalid
        );
    }

    #[test]
    fn revocation_fires_before_quorum_short() {
        let mut v = base_input();
        v["revocation_list"] = json!([{"attestor_id": "A2", "revoked_at": 1_714_500_000_i64}]);
        assert_eq!(
            classify_from(v, "attestor-key-revoked"),
            PcrRejectCode::PcrAttestorRevoked
        );
    }

    #[test]
    fn attestor_not_yet_valid() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["attestor_validity"] =
            json!({"A2": {"not_before": 1_714_530_000_i64}});
        assert_eq!(
            classify_from(v, "attestor-key-not-yet-valid"),
            PcrRejectCode::PcrAttestorNotYetValid
        );
    }

    #[test]
    fn attestation_expired() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["attestation_max_age_seconds"] = json!(86_400);
        v["attestation_bundle"]["attestations"][0]["iat"] = json!(1_714_352_400_i64);
        v["attestation_bundle"]["attestations"][1]["iat"] = json!(1_714_352_410_i64);
        assert_eq!(
            classify_from(v, "attestation-too-old"),
            PcrRejectCode::PcrAttestationExpired
        );
    }

    #[test]
    fn attestation_future_dated() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][0]["iat"] = json!(1_714_611_600_i64);
        v["attestation_bundle"]["attestations"][1]["iat"] = json!(1_714_611_700_i64);
        assert_eq!(
            classify_from(v, "attestation-in-future"),
            PcrRejectCode::PcrAttestationFutureDated
        );
    }

    #[test]
    fn attestation_predates_tariff() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["issued_at"] = json!(1_714_400_000_i64);
        v["attestation_bundle"]["attestations"][0]["iat"] = json!(1_714_000_000_i64);
        v["attestation_bundle"]["attestations"][1]["iat"] = json!(1_714_000_100_i64);
        assert_eq!(
            classify_from(v, "attestation-predates-tariff"),
            PcrRejectCode::PcrAttestationPredatesTariff
        );
    }

    #[test]
    fn nonce_reuse() {
        let mut v = base_input();
        v["router_nonce_consumed"] = json!(["r1"]);
        assert_eq!(
            classify_from(v, "attestation-nonce-reuse"),
            PcrRejectCode::PcrAttestationNonceReuse
        );
    }

    #[test]
    fn nonce_mismatch() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][0]["nonce"] = json!("other-nonce");
        v["attestation_bundle"]["attestations"][1]["nonce"] = json!("other-nonce");
        assert_eq!(
            classify_from(v, "adversary-attestation-bundle-for-different-nonce"),
            PcrRejectCode::PcrAttestationNonceMismatch
        );
    }

    #[test]
    fn transparency_missing_when_field_absent() {
        let mut v = base_input();
        v["attestation_bundle"].as_object_mut().unwrap().remove("transparency_log_proof");
        assert_eq!(
            classify_from(v, "transparency-log-missing-inclusion-proof"),
            PcrRejectCode::PcrAttestationTransparencyMissing
        );
    }

    #[test]
    fn transparency_missing_when_inclusion_proof_null() {
        let mut v = base_input();
        v["attestation_bundle"]["transparency_log_proof"]["inclusion_proof"] =
            serde_json::Value::Null;
        assert_eq!(
            classify_from(v, "transparency-log-missing-inclusion-proof"),
            PcrRejectCode::PcrAttestationTransparencyMissing
        );
    }

    #[test]
    fn transparency_invalid() {
        let mut v = base_input();
        v["attestation_bundle"]["transparency_log_proof"]["inclusion_proof_valid"] = json!(false);
        assert_eq!(
            classify_from(v, "transparency-log-invalid-proof"),
            PcrRejectCode::PcrAttestationTransparencyInvalid
        );
    }

    #[test]
    fn transparency_stale() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["transparency_log_max_root_age_seconds"] = json!(86_400);
        v["attestation_bundle"]["transparency_log_proof"]["root_age_seconds"] = json!(172_800);
        assert_eq!(
            classify_from(v, "transparency-log-stale-root"),
            PcrRejectCode::PcrAttestationTransparencyStale
        );
    }

    #[test]
    fn transparency_log_unknown() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["trusted_transparency_logs"] =
            json!([{"log_id": "rekor-v1"}]);
        v["attestation_bundle"]["transparency_log_proof"]["log_id"] = json!("rogue-log-v1");
        assert_eq!(
            classify_from(v, "transparency-log-unknown-log"),
            PcrRejectCode::PcrAttestationTransparencyLogUnknown
        );
    }

    #[test]
    fn transparency_not_yet_logged() {
        let mut v = base_input();
        v["attestation_bundle"]["transparency_log_proof"]["entry_index"] = json!(98_765_u64);
        v["attestation_bundle"]["transparency_log_proof"]["sth_tree_size"] = json!(50_000_u64);
        assert_eq!(
            classify_from(v, "transparency-log-not-published-yet"),
            PcrRejectCode::PcrAttestationTransparencyNotYetLogged
        );
    }

    #[test]
    fn witness_cosignature_missing() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["required_witness_cosignatures"] = json!(2);
        v["attestation_bundle"]["transparency_log_proof"]["witness_cosignatures"] = json!([]);
        assert_eq!(
            classify_from(v, "adversary-transparency-log-split-view"),
            PcrRejectCode::PcrAttestationWitnessCosignatureMissing
        );
    }

    #[test]
    fn attestor_not_trusted() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][1]["attestor_id"] = json!("A99");
        assert_eq!(
            classify_from(v, "attestor-not-in-trusted-list"),
            PcrRejectCode::PcrAttestorNotTrusted
        );
    }

    #[test]
    fn quorum_short() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["quorum"] = json!(3);
        assert_eq!(
            classify_from(v, "quorum-short-by-one"),
            PcrRejectCode::PcrAttestationQuorumShort
        );
    }

    #[test]
    fn cross_attestor_pcr_mismatch() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][0]["pcrs"]["PCR8"] = json!("sha256:app-A");
        v["attestation_bundle"]["attestations"][1]["pcrs"]["PCR8"] = json!("sha256:app-B");
        assert_eq!(
            classify_from(v, "pcr-mismatch-minor-single-pcr"),
            PcrRejectCode::PcrAttestationMismatch
        );
    }

    #[test]
    fn expected_value_mismatch_all_attestors_agree_wrong_value() {
        let mut v = base_input();
        v["attestation_bundle"]["attestations"][0]["pcrs"]["PCR8"] = json!("sha256:app-ACTUAL");
        v["attestation_bundle"]["attestations"][1]["pcrs"]["PCR8"] = json!("sha256:app-ACTUAL");
        v["tariff_pcr_requirement"]["expected_pcrs"]["PCR8"] = json!("sha256:app-EXPECTED");
        assert_eq!(
            classify_from(v, "pcr-expected-mismatch-PCR8-payload"),
            PcrRejectCode::PcrExpectedMismatch
        );
    }

    #[test]
    fn reject_code_displays_kebab() {
        assert_eq!(
            PcrRejectCode::PcrAttestationQuorumShort.to_string(),
            "pcr-attestation-quorum-short"
        );
        assert_eq!(
            PcrRejectCode::TariffPcrQuorumInvalid.to_string(),
            "tariff-pcr-quorum-invalid"
        );
    }

    // ── Phase C.2.5 Block C — live-Rekor dispatch tests ────────────────────

    /// A proof with zero live fields is classified `None`.
    #[test]
    fn live_presence_none_for_mock_bool_proof() {
        let proof = TransparencyLogProof {
            log_id: "rekor-v1".into(),
            inclusion_proof_valid: Some(true),
            inclusion_proof: None,
            root_age_seconds: Some(100),
            entry_index: Some(1),
            sth_tree_size: Some(2),
            witness_cosignatures: None,
            proof_path_hex: None,
            sth_signature_hex: None,
            sth_timestamp: None,
            sth_tree_root_hex: None,
            log_pubkey_hex: None,
            entry_leaf_hash_hex: None,
            current_time: None,
            log_id_hex: None,
            log_key_valid_from: None,
            log_key_valid_until: None,
            max_root_age_seconds_override: None,
        };
        assert_eq!(live_rekor_presence(&proof), LiveRekorPresence::None);
    }

    /// `entry_index` + `sth_tree_size` alone must NOT trigger live dispatch;
    /// they are shared fields used by the mock-bool NotYetLogged check
    /// (pcrrej-024).
    #[test]
    fn live_presence_ignores_shared_entry_index_and_tree_size() {
        let proof = TransparencyLogProof {
            log_id: "rekor-v1".into(),
            inclusion_proof_valid: Some(true),
            inclusion_proof: None,
            root_age_seconds: None,
            entry_index: Some(98_765),
            sth_tree_size: Some(50_000),
            witness_cosignatures: None,
            proof_path_hex: None,
            sth_signature_hex: None,
            sth_timestamp: None,
            sth_tree_root_hex: None,
            log_pubkey_hex: None,
            entry_leaf_hash_hex: None,
            current_time: None,
            log_id_hex: None,
            log_key_valid_from: None,
            log_key_valid_until: None,
            max_root_age_seconds_override: None,
        };
        assert_eq!(live_rekor_presence(&proof), LiveRekorPresence::None);
    }

    /// A proof with some (but not all) live fields is `Partial` — adversarial
    /// framing that attempts to evade the live verifier with incomplete
    /// evidence.
    #[test]
    fn live_presence_partial_triggers_invalid() {
        let proof = TransparencyLogProof {
            log_id: "rekor-v1".into(),
            inclusion_proof_valid: None,
            inclusion_proof: None,
            root_age_seconds: None,
            entry_index: None,
            sth_tree_size: None,
            witness_cosignatures: None,
            proof_path_hex: Some(vec![]),
            sth_signature_hex: Some("00".into()),
            sth_timestamp: Some(1_000_000),
            sth_tree_root_hex: None,
            log_pubkey_hex: None,
            entry_leaf_hash_hex: None,
            current_time: None,
            log_id_hex: None,
            log_key_valid_from: None,
            log_key_valid_until: None,
            max_root_age_seconds_override: None,
        };
        assert_eq!(live_rekor_presence(&proof), LiveRekorPresence::Partial);
    }

    /// All seven live-exclusive fields set → `Full`.
    #[test]
    fn live_presence_full_when_all_live_fields_set() {
        let proof = TransparencyLogProof {
            log_id: "rekor-v1".into(),
            inclusion_proof_valid: None,
            inclusion_proof: None,
            root_age_seconds: None,
            entry_index: Some(0),
            sth_tree_size: Some(1),
            witness_cosignatures: None,
            proof_path_hex: Some(vec![]),
            sth_signature_hex: Some("aa".into()),
            sth_timestamp: Some(1_714_500_000),
            sth_tree_root_hex: Some("bb".into()),
            log_pubkey_hex: Some("cc".into()),
            entry_leaf_hash_hex: Some("dd".into()),
            current_time: Some(1_714_500_000),
            log_id_hex: None,
            log_key_valid_from: None,
            log_key_valid_until: None,
            max_root_age_seconds_override: None,
        };
        assert_eq!(live_rekor_presence(&proof), LiveRekorPresence::Full);
    }

    /// The JSON-side [`is_live_rekor_proof`] returns `true` exactly when
    /// every live-exclusive field is present and non-null — the same
    /// condition under which the typed [`live_rekor_presence`] classifier
    /// returns [`LiveRekorPresence::Full`]. This guards the invariant that
    /// `LIVE_REKOR_PROOF_FIELDS` and the typed flag array stay in lock-step.
    #[test]
    fn is_live_rekor_proof_full_when_every_field_present() {
        let full = serde_json::json!({
            "proof_path_hex": ["aa"],
            "sth_signature_hex": "bb",
            "sth_timestamp": 1_714_500_000_i64,
            "sth_tree_root_hex": "cc",
            "log_pubkey_hex": "dd",
            "entry_leaf_hash_hex": "ee",
            "current_time": 1_714_500_000_i64,
        });
        assert!(is_live_rekor_proof(&full));
    }

    /// `is_live_rekor_proof` must return `false` for non-object inputs
    /// (safe default for walkers that may traverse arbitrary JSON).
    #[test]
    fn is_live_rekor_proof_rejects_non_objects() {
        assert!(!is_live_rekor_proof(&Value::Null));
        assert!(!is_live_rekor_proof(&Value::Bool(true)));
        assert!(!is_live_rekor_proof(&serde_json::json!("string")));
        assert!(!is_live_rekor_proof(&serde_json::json!([1, 2, 3])));
        assert!(!is_live_rekor_proof(&serde_json::json!({})));
    }

    /// A JSON proof with any live field explicitly set to `null` must not
    /// count as present — closes the split-view hazard where `"x": null`
    /// and missing-key versions of the same vector classify differently.
    #[test]
    fn is_live_rekor_proof_treats_null_as_absent() {
        let base = serde_json::json!({
            "proof_path_hex": ["aa"],
            "sth_signature_hex": "bb",
            "sth_timestamp": 1_714_500_000_i64,
            "sth_tree_root_hex": "cc",
            "log_pubkey_hex": "dd",
            "entry_leaf_hash_hex": "ee",
            "current_time": 1_714_500_000_i64,
        });
        assert!(is_live_rekor_proof(&base));
        for field in &LIVE_REKOR_PROOF_FIELDS {
            let mut damaged = base.clone();
            damaged[*field] = Value::Null;
            assert!(
                !is_live_rekor_proof(&damaged),
                "null value for `{field}` must not count as present"
            );
        }
    }

    /// A JSON proof with any live field missing entirely must not count as
    /// present — partial framing (the V4 Block E adversarial case) stays in
    /// the mock-bool dispatch.
    #[test]
    fn is_live_rekor_proof_treats_missing_as_absent() {
        let base = serde_json::json!({
            "proof_path_hex": ["aa"],
            "sth_signature_hex": "bb",
            "sth_timestamp": 1_714_500_000_i64,
            "sth_tree_root_hex": "cc",
            "log_pubkey_hex": "dd",
            "entry_leaf_hash_hex": "ee",
            "current_time": 1_714_500_000_i64,
        });
        for field in &LIVE_REKOR_PROOF_FIELDS {
            let mut damaged = base.clone();
            damaged.as_object_mut().unwrap().remove(*field);
            assert!(
                !is_live_rekor_proof(&damaged),
                "missing `{field}` must not count as present"
            );
        }
    }

    /// End-to-end: a proof with partial live evidence dispatched through
    /// `classify_transparency_log` → `TransparencyInvalid`.
    #[test]
    fn classify_transparency_log_dispatches_partial_to_invalid() {
        let mut v = base_input();
        v["attestation_bundle"]["transparency_log_proof"]["proof_path_hex"] = json!([]);
        v["attestation_bundle"]["transparency_log_proof"]["sth_signature_hex"] = json!("00");
        // Missing: the other 5 live-exclusive hex fields.
        assert_eq!(
            classify_from(v, "transparency-log-live-partial-evidence"),
            PcrRejectCode::PcrAttestationTransparencyInvalid
        );
    }

    /// End-to-end: `inclusion_proof_valid == false` combined with a Full live
    /// proof short-circuits to `TransparencyInvalid` without spending
    /// verifier cycles. The vector author is asserting adversarial intent;
    /// the verifier MUST NOT accept it.
    #[test]
    fn classify_transparency_log_false_bool_with_full_live_returns_invalid() {
        let mut v = base_input();
        let proof = &mut v["attestation_bundle"]["transparency_log_proof"];
        proof["inclusion_proof_valid"] = json!(false);
        proof["proof_path_hex"] = json!([]);
        proof["sth_signature_hex"] = json!("00");
        proof["sth_timestamp"] = json!(1_714_500_000_i64);
        proof["sth_tree_root_hex"] = json!("00");
        proof["log_pubkey_hex"] = json!("00");
        proof["entry_leaf_hash_hex"] = json!("00");
        proof["current_time"] = json!(1_714_500_000_i64);
        proof["entry_index"] = json!(0);
        proof["sth_tree_size"] = json!(1);
        assert_eq!(
            classify_from(v, "transparency-log-live-adversarial-flagged"),
            PcrRejectCode::PcrAttestationTransparencyInvalid
        );
    }

    /// pcrrej-024 regression: legacy mock-bool NotYetLogged path must survive
    /// the addition of the live-dispatch branch.
    #[test]
    fn legacy_not_yet_logged_still_fires_under_new_dispatch() {
        let mut v = base_input();
        v["attestation_bundle"]["transparency_log_proof"]["entry_index"] = json!(98_765_u64);
        v["attestation_bundle"]["transparency_log_proof"]["sth_tree_size"] = json!(50_000_u64);
        assert_eq!(
            classify_from(v, "transparency-log-not-published-yet"),
            PcrRejectCode::PcrAttestationTransparencyNotYetLogged
        );
    }

    // ── Phase C.2.5 Commit D — H-1 / H-2 regression tests ──────────────────
    //
    // These exercise the fail-closed invariants introduced by Commit D.
    //
    // H-1: a missing (`None`) or empty (`Some(vec![])`) Tariff
    // `trusted_transparency_logs` list must reject with
    // `TransparencyLogUnknown` on both the mock-bool and live paths. Before
    // the fix, `None` was permissive — any log would pass the trust check.
    //
    // H-2: the proof-side `max_root_age_seconds_override` may only tighten
    // the Tariff freshness window (`min(override, base)`), never loosen it.
    // Before the fix, `override.or(base)` let a larger override relax the
    // Tariff policy.

    /// H-1 mock-bool path: `trusted_transparency_logs` missing from the
    /// Tariff → `TransparencyLogUnknown`.
    #[test]
    fn trusted_transparency_logs_none_mock_fails_closed() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]
            .as_object_mut()
            .unwrap()
            .remove("trusted_transparency_logs");
        assert_eq!(
            classify_from(v, "h1-regression-mock-none"),
            PcrRejectCode::PcrAttestationTransparencyLogUnknown
        );
    }

    /// H-1 mock-bool path: empty `trusted_transparency_logs` (explicit
    /// `[]`) → `TransparencyLogUnknown`. No trust entry can match, so the
    /// iter-find returns false and the check fails closed.
    #[test]
    fn trusted_transparency_logs_empty_mock_fails_closed() {
        let mut v = base_input();
        v["tariff_pcr_requirement"]["trusted_transparency_logs"] = json!([]);
        assert_eq!(
            classify_from(v, "h1-regression-mock-empty"),
            PcrRejectCode::PcrAttestationTransparencyLogUnknown
        );
    }

    // The live-path regression tests below are gated behind `test-fixtures`
    // because they exercise `classify_live_rekor`, whose implementation is
    // itself gated (the live Ed25519/Merkle verifier only exists when that
    // feature is enabled). CI covers them via `cargo test --all-features`.

    /// RFC 8032 §7.1 test vector 1 public key. Deterministic, publicly
    /// documented, and a valid Ed25519 compressed Edwards point so
    /// `VerifyingKey::from_bytes` succeeds. Used only to get the pre-trust
    /// decoding steps of `classify_live_rekor` past the parse guard.
    #[cfg(feature = "test-fixtures")]
    const TEST_LOG_PUBKEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    /// 32-byte hex used as both the STH-bound `log_id_hex` and the matching
    /// `trusted_transparency_logs[0].log_id` in the live H-2 tests below.
    /// Value is arbitrary; it just has to decode to 32 bytes so the
    /// byte-compare trust check succeeds.
    #[cfg(feature = "test-fixtures")]
    const TEST_LIVE_LOG_ID_HEX: &str =
        "0202020202020202020202020202020202020202020202020202020202020202";

    /// Overlay `base_input()` with Full live-Rekor presence. Timestamps are
    /// driven by the caller via `sth_timestamp_offset` (seconds subtracted
    /// from `current_time` = 1_714_525_200). All other live-path fields are
    /// minimal but well-formed — proof-path empty, tree size 1, signature
    /// 64 bytes of zero. The STH signature cannot verify, but the tests
    /// below expect failure *before* signature verification (either at the
    /// trust check or at the stale check).
    #[cfg(feature = "test-fixtures")]
    fn live_presence_input(sth_timestamp_offset: i64) -> serde_json::Value {
        let mut v = base_input();
        let current = 1_714_525_200_i64;
        v["current_time"] = json!(current);
        // The mock-bool `root_age_seconds` field no longer drives freshness
        // on the live path, but leaving it set would be misleading. Remove
        // it to keep the vector honest.
        let proof = v["attestation_bundle"]["transparency_log_proof"]
            .as_object_mut()
            .unwrap();
        proof.remove("root_age_seconds");
        proof.insert("log_id".into(), json!(TEST_LIVE_LOG_ID_HEX));
        proof.insert("log_id_hex".into(), json!(TEST_LIVE_LOG_ID_HEX));
        proof.insert("proof_path_hex".into(), json!(Vec::<String>::new()));
        proof.insert("sth_signature_hex".into(), json!("00".repeat(64)));
        proof.insert("sth_timestamp".into(), json!(current - sth_timestamp_offset));
        proof.insert("sth_tree_root_hex".into(), json!("00".repeat(32)));
        proof.insert("log_pubkey_hex".into(), json!(TEST_LOG_PUBKEY_HEX));
        proof.insert("entry_leaf_hash_hex".into(), json!("00".repeat(32)));
        proof.insert("current_time".into(), json!(current));
        proof.insert("entry_index".into(), json!(0_u64));
        proof.insert("sth_tree_size".into(), json!(1_u64));
        // Upgrade the Tariff trust entry from the mock-bool "rekor-v1"
        // string form to the 32-byte hex form the live path compares on.
        v["tariff_pcr_requirement"]["trusted_transparency_logs"] =
            json!([{"log_id": TEST_LIVE_LOG_ID_HEX}]);
        v
    }

    /// H-1 live path: `trusted_transparency_logs` missing from the Tariff
    /// → `TransparencyLogUnknown`, fired before any STH cryptographic
    /// verification.
    #[cfg(feature = "test-fixtures")]
    #[test]
    fn trusted_transparency_logs_none_live_fails_closed() {
        let mut v = live_presence_input(60);
        v["tariff_pcr_requirement"]
            .as_object_mut()
            .unwrap()
            .remove("trusted_transparency_logs");
        assert_eq!(
            classify_from(v, "h1-regression-live-none"),
            PcrRejectCode::PcrAttestationTransparencyLogUnknown
        );
    }

    /// H-2 live path: `max_root_age_seconds_override = 3_600` must not
    /// loosen a Tariff `transparency_log_max_root_age_seconds = 60`. STH
    /// age 120 s must classify as `Stale` (120 > clamped 60), not pass
    /// through to the signature check (120 < 3_600).
    #[cfg(feature = "test-fixtures")]
    #[test]
    fn max_root_age_override_cannot_loosen() {
        let mut v = live_presence_input(120);
        v["tariff_pcr_requirement"]["transparency_log_max_root_age_seconds"] =
            json!(60_u64);
        v["attestation_bundle"]["transparency_log_proof"]
            ["max_root_age_seconds_override"] = json!(3_600_u64);
        assert_eq!(
            classify_from(v, "h2-regression-override-loosen"),
            PcrRejectCode::PcrAttestationTransparencyStale
        );
    }

    /// H-2 live path: `max_root_age_seconds_override = 30` tightens a
    /// Tariff `transparency_log_max_root_age_seconds = 60` to 30. STH
    /// age 45 s → `Stale` (45 > 30).
    #[cfg(feature = "test-fixtures")]
    #[test]
    fn max_root_age_override_can_tighten() {
        let mut v = live_presence_input(45);
        v["tariff_pcr_requirement"]["transparency_log_max_root_age_seconds"] =
            json!(60_u64);
        v["attestation_bundle"]["transparency_log_proof"]
            ["max_root_age_seconds_override"] = json!(30_u64);
        assert_eq!(
            classify_from(v, "h2-regression-override-tighten"),
            PcrRejectCode::PcrAttestationTransparencyStale
        );
    }

    /// H-2 live path: `max_root_age_seconds_override` absent → Tariff
    /// base (`transparency_log_max_root_age_seconds = 60`) applies. STH
    /// age 100 s → `Stale` (100 > 60).
    #[cfg(feature = "test-fixtures")]
    #[test]
    fn max_root_age_override_none_uses_base() {
        let mut v = live_presence_input(100);
        v["tariff_pcr_requirement"]["transparency_log_max_root_age_seconds"] =
            json!(60_u64);
        // Override deliberately absent.
        assert_eq!(
            classify_from(v, "h2-regression-override-none"),
            PcrRejectCode::PcrAttestationTransparencyStale
        );
    }
}
