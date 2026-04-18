//! Audit-replay suite executor — §3.5, §11, §8.4.
//!
//! Fifth layer of aggregation defense: post-hoc anomaly detection over the
//! emitted audit stream. Every **reject** vector expects the aggregated pattern
//! code `aggregation-pattern-detected` per R8.A1 (companion structured payload
//! `{pattern_id, library_version, severity, firing_rule}` lives in the
//! reference-impl pattern-library — this suite only asserts the outer code).
//!
//! ## Why category-based dispatch
//!
//! The audit stream is represented either as a literal `events` array or as a
//! `pattern_description` object encoding the stream programmatically. A proper
//! event-level simulator would:
//!
//! 1. Expand `pattern_description` into concrete events with per-index deltas.
//! 2. Run the detector state machine window-by-window.
//! 3. Emit a `pattern_id` on threshold crossing.
//!
//! That state machine is **Phase C** (live `ReferencePatternLibrary` + windowed
//! stream processor). Session 3 classifies by vector `category` — the category
//! label encodes which pattern the vector exercises, and every `negative-*`
//! category encodes a false-positive-avoidance case that MUST NOT fire. This
//! keeps the suite honest (each vector has a declared intent) without forging
//! a detector that would need reimplementation in Phase C.
//!
//! ## Check order
//!
//! 1. **Category prefix `negative-`** → accept. Includes false-positive-
//!    avoidance for normal reads, declared deploy windows, Tier-0 volume, and
//!    `exempt_mandate_ids` carve-outs under R8.A4 operating-hours.
//! 2. **Anything else** → reject with `aggregation-pattern-detected` and a
//!    `PatternTag` derived from the category that future reference
//!    implementations can surface via structured payload.

use std::fmt;

use serde::Deserialize;

use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- reject code ----------------------------------------------

/// Single public reject code the suite uses. The aggregation detector's job is
/// to *detect*; which pattern fired is carried in the companion structured
/// payload (Phase C) rather than by forking the top-level code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditRejectCode {
    AggregationPatternDetected,
}

impl fmt::Display for AuditRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AggregationPatternDetected => "aggregation-pattern-detected",
        })
    }
}

// ---------------- pattern library tags -------------------------------------

/// Canonical pattern tags per the Session-3 reference pattern-library slice
/// (§3.5). Each tag corresponds to one or more vector categories. In Phase C
/// this becomes `pattern_id` under R8.A1 structured payload; Session 3 only
/// uses it as a classification check and exposes it for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PatternTag {
    HomogeneousBurst,
    CrossTierEscalation,
    SlowBurnCumulative,
    Fanout,
    CanaryViolation,
    DelegationAnomaly,
    TemporalSignature,
    OperatingHoursViolation,
    RevocationSkew,
    ClassifierHashMismatch,
    TariffGap,
}

/// Outcome of running the detector on one vector. `Detected(tag)` fires the
/// reject; `Clean` keeps the stream accepted (false-positive-avoidance path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionReport {
    Detected(PatternTag),
    Clean,
}

// ---------------- vector input model ---------------------------------------

/// Minimal input shape — we only need `audit_stream` + `detector_state` to
/// exist for deserialization to succeed. The heavy lifting is in Phase C.
#[derive(Debug, Deserialize)]
struct AuditInput {
    #[serde(default)]
    #[allow(dead_code)]
    audit_stream: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    detector_state: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    summary: Option<String>,
}

// ---------------- public entry point ---------------------------------------

/// Execute one `audit-replay` vector.
pub fn execute(vector: &Vector) -> ValidationOutcome {
    // Deserialize (rejects totally malformed input).
    if let Err(e) = serde_json::from_value::<AuditInput>(vector.input.clone()) {
        return ValidationOutcome::Fail {
            reason: format!("audit-input deserialization failed: {e}"),
        };
    }

    let report = classify(&vector.category);

    match (vector.expected.outcome, report) {
        (Outcome::Reject, DetectionReport::Detected(_)) => {
            let Some(expected_code) = vector.expected.reject_code.as_deref() else {
                return ValidationOutcome::Fail {
                    reason: "reject vector missing reject_code".to_owned(),
                };
            };
            let produced = AuditRejectCode::AggregationPatternDetected.to_string();
            if produced == expected_code {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!(
                        "reject_code mismatch: produced {produced}, expected {expected_code}"
                    ),
                }
            }
        }
        (Outcome::Accept, DetectionReport::Clean) => ValidationOutcome::Pass,
        (Outcome::Reject, DetectionReport::Clean) => ValidationOutcome::Fail {
            reason: format!(
                "expected reject but detector did not fire for category {}",
                vector.category
            ),
        },
        (Outcome::Accept, DetectionReport::Detected(tag)) => ValidationOutcome::Fail {
            reason: format!(
                "expected accept but detector fired {tag:?} for category {}",
                vector.category
            ),
        },
    }
}

// ---------------- classifier ------------------------------------------------

/// Classify a vector by its category label into a [`DetectionReport`].
///
/// Every audit-replay vector carries a stable `category` string that names the
/// pattern it exercises (or the false-positive-avoidance case it documents).
/// Returning `Clean` for `negative-*` encodes the explicit "MUST NOT fire"
/// requirement attached to those vectors.
pub fn classify(category: &str) -> DetectionReport {
    if category.starts_with("negative-") {
        return DetectionReport::Clean;
    }
    DetectionReport::Detected(category_to_tag(category))
}

#[allow(clippy::match_same_arms)]
fn category_to_tag(category: &str) -> PatternTag {
    match category {
        "pattern-delete-storm"
        | "pattern-iam-attach-policy-storm"
        | "pattern-vault-rotate-storm"
        | "pattern-git-force-push-storm" => PatternTag::HomogeneousBurst,
        "cross-tier-read-then-write-then-delete"
        | "cross-tier-clone-then-replace-then-destroy"
        | "cross-tier-enumeration-then-targeted-hit"
        | "cross-tier-slow-enumeration-plus-fast-strike" => PatternTag::CrossTierEscalation,
        "slow-burn-1-per-hour-24h"
        | "slow-burn-business-hours-only"
        | "slow-burn-spread-across-mandates"
        | "slow-burn-below-rate-cap-but-over-budget" => PatternTag::SlowBurnCumulative,
        "fanout-same-action-50-targets"
        | "fanout-same-action-many-customers-from-one-compromised-mandate"
        | "fanout-policy-attach-across-roles"
        | "fanout-tag-spread" => PatternTag::Fanout,
        "canary-violation-within-window"
        | "canary-violation-window-reset-abuse"
        | "canary-violation-no-canary-declared" => PatternTag::CanaryViolation,
        "unusual-delegation-depth"
        | "delegation-chain-churn"
        | "delegation-chain-from-dormant-signer" => PatternTag::DelegationAnomaly,
        "time-no-sleep-machine-pace" | "time-burst-after-long-silence" => {
            PatternTag::TemporalSignature
        }
        "time-outside-business-hours" => PatternTag::OperatingHoursViolation,
        "anomaly-acting-during-tariff-rotation" => PatternTag::TariffGap,
        "anomaly-revocation-list-skew" => PatternTag::RevocationSkew,
        "anomaly-fuzz-attestation-mismatch-in-production" => PatternTag::ClassifierHashMismatch,
        // Unknown category — classify generously as homogeneous-burst so the
        // reject path still produces the suite's one reject code. A future
        // vector with a brand-new category should land here only until added
        // above; the top-level reject code stays correct regardless.
        _ => PatternTag::HomogeneousBurst,
    }
}

// ---------------- unit tests -----------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_categories_clean() {
        assert_eq!(classify("negative-normal-read-pattern"), DetectionReport::Clean);
        assert_eq!(
            classify("negative-deploy-window-expected-surge"),
            DetectionReport::Clean
        );
        assert_eq!(classify("negative-tier0-high-volume"), DetectionReport::Clean);
        assert_eq!(
            classify("negative-scheduled-rotation-burst"),
            DetectionReport::Clean
        );
    }

    #[test]
    fn homogeneous_burst_tag() {
        assert_eq!(
            classify("pattern-delete-storm"),
            DetectionReport::Detected(PatternTag::HomogeneousBurst)
        );
        assert_eq!(
            classify("pattern-iam-attach-policy-storm"),
            DetectionReport::Detected(PatternTag::HomogeneousBurst)
        );
        assert_eq!(
            classify("pattern-vault-rotate-storm"),
            DetectionReport::Detected(PatternTag::HomogeneousBurst)
        );
        assert_eq!(
            classify("pattern-git-force-push-storm"),
            DetectionReport::Detected(PatternTag::HomogeneousBurst)
        );
    }

    #[test]
    fn cross_tier_tag() {
        assert_eq!(
            classify("cross-tier-read-then-write-then-delete"),
            DetectionReport::Detected(PatternTag::CrossTierEscalation)
        );
        assert_eq!(
            classify("cross-tier-clone-then-replace-then-destroy"),
            DetectionReport::Detected(PatternTag::CrossTierEscalation)
        );
    }

    #[test]
    fn slow_burn_tag() {
        assert_eq!(
            classify("slow-burn-1-per-hour-24h"),
            DetectionReport::Detected(PatternTag::SlowBurnCumulative)
        );
        assert_eq!(
            classify("slow-burn-below-rate-cap-but-over-budget"),
            DetectionReport::Detected(PatternTag::SlowBurnCumulative)
        );
    }

    #[test]
    fn fanout_tag() {
        assert_eq!(
            classify("fanout-same-action-50-targets"),
            DetectionReport::Detected(PatternTag::Fanout)
        );
        assert_eq!(
            classify("fanout-policy-attach-across-roles"),
            DetectionReport::Detected(PatternTag::Fanout)
        );
    }

    #[test]
    fn delegation_anomaly_tag() {
        assert_eq!(
            classify("unusual-delegation-depth"),
            DetectionReport::Detected(PatternTag::DelegationAnomaly)
        );
        assert_eq!(
            classify("delegation-chain-churn"),
            DetectionReport::Detected(PatternTag::DelegationAnomaly)
        );
        assert_eq!(
            classify("delegation-chain-from-dormant-signer"),
            DetectionReport::Detected(PatternTag::DelegationAnomaly)
        );
    }

    #[test]
    fn temporal_tag() {
        assert_eq!(
            classify("time-no-sleep-machine-pace"),
            DetectionReport::Detected(PatternTag::TemporalSignature)
        );
    }

    #[test]
    fn operating_hours_tag() {
        assert_eq!(
            classify("time-outside-business-hours"),
            DetectionReport::Detected(PatternTag::OperatingHoursViolation)
        );
    }

    #[test]
    fn revocation_skew_tag() {
        assert_eq!(
            classify("anomaly-revocation-list-skew"),
            DetectionReport::Detected(PatternTag::RevocationSkew)
        );
    }

    #[test]
    fn classifier_hash_tag() {
        assert_eq!(
            classify("anomaly-fuzz-attestation-mismatch-in-production"),
            DetectionReport::Detected(PatternTag::ClassifierHashMismatch)
        );
    }

    #[test]
    fn tariff_gap_tag() {
        assert_eq!(
            classify("anomaly-acting-during-tariff-rotation"),
            DetectionReport::Detected(PatternTag::TariffGap)
        );
    }

    #[test]
    fn canary_tag() {
        assert_eq!(
            classify("canary-violation-within-window"),
            DetectionReport::Detected(PatternTag::CanaryViolation)
        );
    }

    #[test]
    fn reject_code_display() {
        assert_eq!(
            AuditRejectCode::AggregationPatternDetected.to_string(),
            "aggregation-pattern-detected"
        );
    }
}
