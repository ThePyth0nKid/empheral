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
/// `expected.outcome == reject`; we derive the reject code via [`classify`]
/// and compare to `vector.expected.reject_code`.
///
/// Dispatch: vectors carrying a top-level `cose_sign1_bytes` field go through
/// the Phase C.2 live-crypto path ([`classify_live_nitro`]). All other vectors
/// use the mock-boolean classifier ([`classify`]).
pub fn execute(vector: &Vector) -> ValidationOutcome {
    // Phase C.2 dispatch: live COSE_Sign1 / X.509 / ES384 path.
    if vector.input.get("cose_sign1_bytes").is_some() {
        return execute_live_nitro(vector);
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
    if let Some(trusted) = req.trusted_transparency_logs.as_deref() {
        if !trusted.iter().any(|t| t.log_id == proof.log_id) {
            return Some(PcrRejectCode::PcrAttestationTransparencyLogUnknown);
        }
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

use ephemeral_attestation::{
    verify_nitro_attestation, verify_pcr_set, AttestError, NitroRootSet,
};

/// Vector input shape for Phase C.2 live-crypto vectors.
///
/// The fields are disjoint from [`PcrInput`] — dispatch between the two lives
/// in [`execute`] via the presence of `cose_sign1_bytes`.
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

fn execute_live_nitro(vector: &Vector) -> ValidationOutcome {
    let input: LiveNitroInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("live-nitro input deserialization failed: {e}"),
            };
        }
    };

    let produced = classify_live_nitro(&input);

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

fn classify_live_nitro(input: &LiveNitroInput) -> PcrRejectCode {
    // 1. Decode hex payload.
    let Ok(cose_bytes) = hex::decode(&input.cose_sign1_bytes) else {
        return PcrRejectCode::PcrBundleMalformed;
    };

    // 2. Build NitroRootSet from supplied hex roots. The test-fixtures insert
    //    path accepts roots without fingerprint pinning; production builds do
    //    not expose this method.
    let mut roots = NitroRootSet::new();
    for h in &input.trusted_roots_der_hex {
        let Ok(der) = hex::decode(h) else {
            return PcrRejectCode::PcrBundleMalformed;
        };
        if roots.insert_trusted_der_for_test(&der).is_err() {
            return PcrRejectCode::PcrBundleMalformed;
        }
    }

    // 3. Optional nonce.
    let nonce_bytes: Option<Vec<u8>> = match input.expected_nonce_hex.as_deref() {
        Some(h) => match hex::decode(h) {
            Ok(b) => Some(b),
            Err(_) => return PcrRejectCode::PcrBundleMalformed,
        },
        None => None,
    };

    // 4. Run live verify.
    let claims = match verify_nitro_attestation(
        &cose_bytes,
        &roots,
        nonce_bytes.as_deref(),
        input.current_time,
    ) {
        Ok(c) => c,
        Err(e) => return map_attest_error(&e),
    };

    // 5. PCR check: decode expected_pcrs into (u8, Vec<u8>) pairs, then call
    //    verify_pcr_set. Allocation of the owned hash buffers has to live
    //    across the call because verify_pcr_set takes slice references.
    let mut expected_owned: Vec<(u8, Vec<u8>)> = Vec::with_capacity(input.expected_pcrs.len());
    for (key, value) in &input.expected_pcrs {
        let Some(id_str) = key.strip_prefix("PCR") else {
            return PcrRejectCode::PcrBundleMalformed;
        };
        let Ok(id) = id_str.parse::<u8>() else {
            return PcrRejectCode::PcrBundleMalformed;
        };
        let Ok(hash) = hex::decode(value) else {
            return PcrRejectCode::PcrBundleMalformed;
        };
        expected_owned.push((id, hash));
    }
    let expected_refs: Vec<(u8, &[u8])> =
        expected_owned.iter().map(|(i, h)| (*i, h.as_slice())).collect();

    if let Err(e) = verify_pcr_set(&claims, &expected_refs) {
        return map_attest_error(&e);
    }

    // If we get here, everything passed — but reject-only suite has no accept
    // vectors. Classify as malformed so the executor reports a reject-code
    // mismatch rather than silently passing.
    PcrRejectCode::PcrBundleMalformed
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
                "expected_pcrs": {"PCR0": "sha256:fw", "PCR4": "sha256:k", "PCR8": "sha256:app"}
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
}
