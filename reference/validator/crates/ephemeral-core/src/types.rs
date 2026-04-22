//! Shared value and report types.
//!
//! Every conformance vector file deserializes into [`SuiteFile`]. Each vector
//! inside then routes to its suite-specific executor. Results aggregate into
//! [`TestReport`] via [`SuiteReport`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::error::ValidatorError;

/// Top-level structure of a conformance vector file (`conformance/*.json`).
///
/// Field ordering and names follow `conformance/schema.json` exactly. Unknown
/// fields are **rejected** so that schema drift surfaces at deserialization
/// rather than silently at vector-execution time.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteFile {
    pub schema_version: String,
    pub vector_suite: VectorSuite,
    pub spec_reference: String,
    pub spec_version: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_summary: Option<BTreeMap<String, u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub vectors: Vec<Vector>,
}

/// Which of the six conformance suites a file encodes.
///
/// `#[non_exhaustive]` so Phase C additions (e.g., a future attestation-chain
/// suite) do not force source-compatible-but-behaviorally-wrong exhaustive
/// matches in downstream consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum VectorSuite {
    DelegationScope,
    Canonicalization,
    FuzzBaseline,
    TariffReject,
    PcrAttestationReject,
    AuditReplay,
    /// Phase C.4 Session 4 — anomaly-library envelope verification
    /// (Stages 1–8 per §3.5).  Suite executor lives in
    /// [`crate::suites::anomaly_library`].
    AnomalyLibraryReject,
    /// Phase C.4 Session 5-B — anomaly-detect stream replay exercising
    /// [`ephemeral_anomaly::DetectorState::evaluate_all`] firing rules
    /// (§3.5.3 primary/companion patterns, §11.2 AnomalyDetected
    /// emission).  Suite executor lives in
    /// [`crate::suites::anomaly_detect`].
    AnomalyDetect,
}

impl VectorSuite {
    /// Stable short name (matches the `vector_suite` string literal).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DelegationScope => "delegation-scope",
            Self::Canonicalization => "canonicalization",
            Self::FuzzBaseline => "fuzz-baseline",
            Self::TariffReject => "tariff-reject",
            Self::PcrAttestationReject => "pcr-attestation-reject",
            Self::AuditReplay => "audit-replay",
            Self::AnomalyLibraryReject => "anomaly-library-reject",
            Self::AnomalyDetect => "anomaly-detect",
        }
    }

    /// All eight suites, in documentation order.
    pub const ALL: [Self; 8] = [
        Self::DelegationScope,
        Self::Canonicalization,
        Self::FuzzBaseline,
        Self::TariffReject,
        Self::PcrAttestationReject,
        Self::AuditReplay,
        Self::AnomalyLibraryReject,
        Self::AnomalyDetect,
    ];
}

/// A single conformance vector. Shape matches `conformance/schema.json`
/// `$defs/vector`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    pub id: String,
    pub category: String,
    pub description: String,
    pub input: serde_json::Value,
    pub expected: ExpectedOutcome,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redteam_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_if_failed: Option<Severity>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOutcome {
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Verdict for a single vector execution.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationOutcome {
    /// Executor ran and matched `expected`.
    Pass,
    /// Executor ran and produced a different outcome/reject-code/output than
    /// `expected`. Semantic mismatch — the implementation under test (or the
    /// vector itself) is wrong.
    Fail { reason: String },
    /// Harness-internal failure. Not attributable to the vector.
    Error { source: ValidatorError },
    /// The suite executor is not available in the current session.
    Skipped { reason: SkipReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    SuiteNotImplementedThisSession,
    FilteredOut,
}

/// Aggregate report across every suite file loaded in one run.
#[derive(Debug)]
pub struct TestReport {
    pub per_suite: BTreeMap<VectorSuite, SuiteReport>,
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
}

impl TestReport {
    pub fn new(started_at: SystemTime) -> Self {
        Self {
            per_suite: BTreeMap::new(),
            started_at,
            finished_at: started_at,
        }
    }

    /// Total number of vectors that failed or errored across every suite.
    pub fn total_failing(&self) -> u32 {
        self.per_suite
            .values()
            .map(|s| s.fail + s.error)
            .sum()
    }

    pub fn total_pass(&self) -> u32 {
        self.per_suite.values().map(|s| s.pass).sum()
    }

    pub fn total_skipped(&self) -> u32 {
        self.per_suite.values().map(|s| s.skipped).sum()
    }

    /// Exit cleanly iff every vector either passed or was explicitly skipped.
    pub fn is_clean(&self) -> bool {
        self.total_failing() == 0
    }
}

/// Per-file / per-suite aggregate. In Phase B each file corresponds to one
/// suite; this struct exists per-file so a future multi-file-per-suite setup
/// does not break the report shape.
///
/// `schema_ok` distinguishes three states: `Some(true)` = validated clean,
/// `Some(false)` = validated with errors, `None` = never checked (file was
/// filtered out by `--suite` or failed to load before schema validation ran).
#[derive(Debug, Default)]
pub struct SuiteReport {
    pub file: PathBuf,
    pub schema_ok: Option<bool>,
    pub pass: u32,
    pub fail: u32,
    pub error: u32,
    pub skipped: u32,
    pub failures: Vec<VectorFailure>,
}

#[derive(Debug)]
pub struct VectorFailure {
    pub vector_id: String,
    pub category: String,
    pub severity: Option<Severity>,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_suite_str_roundtrip() {
        for suite in VectorSuite::ALL {
            let s = suite.as_str();
            let parsed: VectorSuite =
                serde_json::from_value(serde_json::Value::String(s.to_owned())).unwrap();
            assert_eq!(parsed, suite, "round-trip failed for {s}");
        }
    }

    #[test]
    fn outcome_string_matches_schema() {
        let accept: Outcome = serde_json::from_str("\"accept\"").unwrap();
        let reject: Outcome = serde_json::from_str("\"reject\"").unwrap();
        assert_eq!(accept, Outcome::Accept);
        assert_eq!(reject, Outcome::Reject);
    }

    #[test]
    fn severity_order() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let bad = serde_json::json!({
            "schema_version": "1.0.0",
            "vector_suite": "canonicalization",
            "spec_reference": "§4.2",
            "spec_version": "abcdef",
            "generated_at": "2026-04-18T12:00:00Z",
            "vectors": [],
            "bogus": 1,
        });
        let err = serde_json::from_value::<SuiteFile>(bad).unwrap_err();
        assert!(err.to_string().contains("bogus"), "got {err}");
    }

    #[test]
    fn total_failing_counts_fail_and_error() {
        let mut r = TestReport::new(SystemTime::UNIX_EPOCH);
        let s = SuiteReport {
            pass: 3,
            fail: 2,
            error: 1,
            skipped: 4,
            ..SuiteReport::default()
        };
        r.per_suite.insert(VectorSuite::Canonicalization, s);
        assert_eq!(r.total_failing(), 3);
        assert_eq!(r.total_pass(), 3);
        assert_eq!(r.total_skipped(), 4);
        assert!(!r.is_clean());
    }
}
