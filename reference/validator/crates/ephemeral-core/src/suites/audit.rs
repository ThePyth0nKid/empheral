//! Audit-replay suite executor — §3.5, §11.2 (Phase C.4 Session 5-B Commit C).
//!
//! Dispatches `vector_suite: "audit-replay"` vectors through the
//! multi-tenant [`ephemeral_anomaly::AuditOrchestrator`], closing the
//! last mock-crypto boundary in the reference validator.  Every vector
//! binds a real signed [`AnomalyPatternLibrary`] envelope, real
//! per-tenant [`DetectorState`]s behind the orchestrator, and compares
//! the emitted [`AnomalyDetectedRecord`] multiset against an
//! `expected.output.records` shape.  The Session-3 category-based
//! classifier (`PatternTag` / `DetectionReport`) is fully gone — no
//! mock heuristic decides what fires anymore; the verified library
//! does.
//!
//! ## Scope split with `anomaly-detect`
//!
//! - [`crate::suites::anomaly_detect`] exercises **single-tenant**
//!   [`DetectorState::evaluate_all`] firing rules; every fire attributes
//!   to one (unlabelled) tenant.
//! - This suite exercises the **multi-tenant** dispatch surface: cross-
//!   tenant isolation, library rotation (state-reset invariant), and
//!   tenant-keyed attribution on emitted records.
//!
//! ## Check order (per vector)
//!
//! 1. Deserialise `input` into [`AuditReplayInput`].
//! 2. Build the anchor set and decode the library-envelope hex.
//! 3. Optionally seed the [`InMemoryAnomalyLedger`] from
//!    `pre_ledger` before envelope verification (mirrors the
//!    `anomaly-detect` suite's contract).
//! 4. Verify the library envelope via
//!    [`verify_anomaly_library_signature_with_ledger`].
//! 5. Construct an [`AuditOrchestrator`] pinned to the verified
//!    library at `initial_time`.
//! 6. Walk `tenant_streams` in order.  For each entry: normalise the
//!    stream into `Vec<CanonicalizedEvent>`, then dispatch every event
//!    through [`AuditOrchestrator::observe_event`] keyed on
//!    `tenant_id`.  Emitted [`AnomalyDetectedRecord`]s accumulate.
//! 7. After the configured `rotate_after_stream_idx` (if any),
//!    verify the rotation envelope, swap the library, and continue
//!    dispatching the remaining `tenant_streams`.
//! 8. Render the observed record multiset against
//!    `expected.output.records`.  Comparison is a reduced projection
//!    on `(tenant_id, pattern_id, library_version, severity,
//!    firing_rule, match_scope)` — deliberately dropping
//!    `record_timestamp` so a vector author does not need to pin the
//!    detector clock.  The sort key is
//!    `(tenant_id, pattern_id, mandate_id, firing_rule_rank)`.
//!
//! ## Wire-code mapping
//!
//! - Fires non-empty → [`AGGREGATION_PATTERN_DETECTED_WIRE`] =
//!   `"aggregation-pattern-detected"` (spec §3.5 / R8.A1 literal).
//! - Stream normalise / ingest errors → `audit-replay-stream-*`
//!   kebab-case surfaces keyed on the [`StreamError`] variant.  The
//!   `audit-replay-stream-` prefix disambiguates from the
//!   `anomaly-detect-stream-*` surfaces so a cross-suite wire collision
//!   cannot misroute a diagnostic.
//!
//! ### `#[non_exhaustive]` wildcard
//!
//! [`StreamError`] is `#[non_exhaustive]`.  A wildcard arm buckets
//! unknown variants into `audit-replay-stream-unknown-variant` — a
//! stable wire code signalling "downstream harness upgrade required"
//! rather than a silent fall-through that would let a new variant leak
//! into a pre-existing wire bucket.  `#[allow(unreachable_patterns)]`
//! suppresses the within-crate Clippy warning.

use std::collections::BTreeMap;
use std::sync::Arc;

use ephemeral_anomaly::{
    verify_anomaly_library_signature_with_ledger, AnomalyDetectedRecord, AnomalyLedger as _,
    AuditOrchestrator, AuditStreamInput, FiringRule, InMemoryAnomalyLedger, MatchScope, Severity,
    StreamError,
};
use ephemeral_crypto::AnchorRole;
use serde::Deserialize;
use time::OffsetDateTime;

use super::crypto_support::{build_anchor_set, TrustAnchorKeyDef};
use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- public reject code --------------------------------

/// Single public reject code for this suite.  Retained from the
/// Session-3 mock so downstream callers that re-export
/// [`ephemeral_core::AuditRejectCode`] keep compiling; the Commit-C
/// rewrite now produces the code only when a verified library-driven
/// fire actually lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditRejectCode {
    AggregationPatternDetected,
}

impl std::fmt::Display for AuditRejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AggregationPatternDetected => AGGREGATION_PATTERN_DETECTED_WIRE,
        })
    }
}

/// Spec-literal reject code for a non-empty firing set under the
/// §3.5 / R8.A1 aggregation detector.
const AGGREGATION_PATTERN_DETECTED_WIRE: &str = "aggregation-pattern-detected";

// ---------------- vector input model ---------------------------------

/// Deserialised shape of a `vector.input` block for this suite.
///
/// Field names mirror the `anomaly-detect` suite's library-envelope
/// fields (`_anomaly_library` suffix) for parity: both suites verify
/// the same envelope under the same AAD, and a future multi-envelope
/// vector (library + tariff-chain) stays collision-free.
#[derive(Debug, Deserialize)]
struct AuditReplayInput {
    /// Hex-encoded COSE_Sign1 anomaly-library envelope.
    cose_sign1_bytes_anomaly_library: String,
    /// Trust anchors for the library envelope.  Role default inherits
    /// [`AnchorRole::AnomalyLibrarySigner`] via `build_anchor_set`.
    trust_anchor_keys_anomaly_library: Vec<TrustAnchorKeyDef>,
    /// ABI expectation passed through to the library verifier.
    expected_abi_version: u32,
    /// RFC-3339 timestamp used as "now" for Stage-6 time-bound
    /// checks (issued-at, expired).
    current_time: String,
    /// Optional pre-seeded replay-ledger state.  Keys are
    /// `library_id`, values are the strict HWM already observed.
    /// Seeded HWMs MUST stay **strictly below** the envelope's
    /// embedded `library_version`; a seed `>= library_version` will
    /// trip Stage 8 and surface as a library-envelope verify fail.
    #[serde(default)]
    pre_ledger: BTreeMap<String, u64>,
    /// RFC-3339 timestamp used as the orchestrator's
    /// [`AuditOrchestrator::initial_time`].  Every tenant lazily
    /// registered by `observe_event` starts its clock here.
    initial_time: String,
    /// Per-tenant audit streams, applied in order.  Each entry maps
    /// an operator-chosen `tenant_id` to a stream; the orchestrator
    /// dispatches every event through
    /// [`AuditOrchestrator::observe_event`].
    tenant_streams: Vec<TenantStream>,
    /// Optional library-rotation step.  `None` = no rotation.
    #[serde(default)]
    rotate_library: Option<RotateLibrary>,
}

/// One `(tenant_id, stream)` dispatch pair.  `tenant_id` is
/// operator-chosen; `stream` deserialises to the same
/// [`AuditStreamInput`] the `anomaly-detect` suite consumes so a
/// future shared-fixture generator can reuse stream shapes verbatim.
#[derive(Debug, Deserialize)]
struct TenantStream {
    tenant_id: String,
    stream: AuditStreamInput,
}

/// Optional library-rotation interleave.
///
/// `after_tenant_stream_idx` is the **zero-based** index of the last
/// stream applied against the **pre-rotation** library.  Stream
/// indices `>= after_tenant_stream_idx + 1` run against the rotated
/// library.  Setting `after_tenant_stream_idx = tenant_streams.len() - 1`
/// rotates after the whole batch (testing post-batch state-reset
/// semantics without producing any post-rotation fires).
#[derive(Debug, Deserialize)]
struct RotateLibrary {
    /// Zero-based index of the last pre-rotation stream.
    after_tenant_stream_idx: usize,
    /// Hex-encoded COSE_Sign1 envelope for the rotated library.
    cose_sign1_bytes_anomaly_library: String,
    /// RFC-3339 timestamp that becomes the new
    /// [`AuditOrchestrator::initial_time`] post-rotation.
    new_initial_time: String,
    /// ABI version the rotated envelope must declare.
    expected_abi_version: u32,
}

/// Deserialised shape of a vector's `expected.output` block.
///
/// Only one field — a `records` multiset that the observed set must
/// match under the reduced projection.  Missing / empty means the
/// vector expects zero records; the outer `expected.outcome`
/// independently pins accept vs. reject.
#[derive(Debug, Default, Deserialize)]
struct ExpectedOutput {
    #[serde(default)]
    records: Vec<ExpectedRecord>,
}

/// Reduced-projection record used for multiset comparison.
///
/// `record_timestamp` is deliberately omitted: it reflects the
/// detector's wall-clock after the last `advance_clock` and would
/// force vector authors to pin arithmetic against
/// `initial_time + per-event-offset` in JSON.  Every other field of
/// [`AnomalyDetectedRecord`] is load-bearing for the correctness
/// checks this suite makes.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct ExpectedRecord {
    tenant_id: String,
    pattern_id: String,
    library_version: u64,
    severity: Severity,
    firing_rule: FiringRule,
    #[serde(default)]
    match_scope: MatchScope,
}

impl ExpectedRecord {
    /// Project an observed [`AnomalyDetectedRecord`] onto the reduced
    /// shape used for multiset comparison.
    fn from_observed(rec: &AnomalyDetectedRecord) -> Self {
        Self {
            tenant_id: rec.tenant_id.clone(),
            pattern_id: rec.payload.pattern_id.clone(),
            library_version: rec.payload.library_version,
            severity: rec.payload.severity,
            firing_rule: rec.payload.firing_rule,
            match_scope: rec.payload.match_scope.clone(),
        }
    }
}

// ---------------- public entry point ---------------------------------

/// Execute one `audit-replay` vector.
///
/// Deliberately longer than the default clippy budget.  The executor
/// walks sequential fallible stages — input deserialize, anchor build,
/// hex decode, library verify, per-stream dispatch with optional
/// rotation, record-multiset compare — and each failure emits a
/// vector-specific diagnostic.  Extracting sub-functions would shuffle
/// identical boilerplate across call sites without reducing cognitive
/// load, and would force threading `vector.id` through four layers.
#[allow(clippy::too_many_lines)]
pub fn execute(vector: &Vector) -> ValidationOutcome {
    let input: AuditReplayInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("audit-replay vector {} input deserialize: {e}", vector.id),
            };
        }
    };

    // ─── Stage A: verify the initial library envelope ───────────────
    let anchors = match build_anchor_set(
        &input.trust_anchor_keys_anomaly_library,
        AnchorRole::AnomalyLibrarySigner,
    ) {
        Ok(a) => a,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("audit-replay vector {} anchor build: {e}", vector.id),
            };
        }
    };

    let cose_bytes = match hex::decode(&input.cose_sign1_bytes_anomaly_library) {
        Ok(b) => b,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "audit-replay vector {} cose_sign1_bytes_anomaly_library hex decode: {e}",
                    vector.id
                ),
            };
        }
    };

    let now_unix = match parse_iso_seconds(&input.current_time) {
        Ok(n) => n,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "audit-replay vector {} current_time not RFC-3339 ({}): {e}",
                    vector.id, input.current_time
                ),
            };
        }
    };

    let mut ledger = InMemoryAnomalyLedger::new();
    for (library_id, hwm) in &input.pre_ledger {
        if let Err(e) = ledger.observe(library_id, *hwm) {
            return ValidationOutcome::Fail {
                reason: format!(
                    "audit-replay vector {} pre_ledger seed failed: {e}",
                    vector.id
                ),
            };
        }
    }

    let verified = match verify_anomaly_library_signature_with_ledger(
        &cose_bytes,
        &anchors,
        input.expected_abi_version,
        now_unix,
        &mut ledger,
    ) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "audit-replay vector {} anomaly-library envelope verify failed: {e}",
                    vector.id
                ),
            };
        }
    };

    // ─── Stage B: construct orchestrator ───────────────────────────
    let initial_time = match parse_iso_seconds(&input.initial_time) {
        Ok(n) => n,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "audit-replay vector {} initial_time not RFC-3339 ({}): {e}",
                    vector.id, input.initial_time
                ),
            };
        }
    };

    let mut orch = AuditOrchestrator::new(Arc::new(verified), initial_time);
    let mut observed: Vec<AnomalyDetectedRecord> = Vec::new();
    let rotate_after: Option<usize> = input
        .rotate_library
        .as_ref()
        .map(|r| r.after_tenant_stream_idx);

    // ─── Stage C: per-stream dispatch with optional rotation ───────
    for (stream_idx, ts) in input.tenant_streams.iter().enumerate() {
        let events = match ts.stream.normalize() {
            Ok(e) => e,
            Err(e) => return stream_error_outcome(vector, stream_idx, "normalize", &e),
        };
        for event in events {
            match orch.observe_event(&ts.tenant_id, event) {
                Ok(fires) => observed.extend(fires),
                Err(e) => return stream_error_outcome(vector, stream_idx, "observe_event", &e),
            }
        }

        // Library rotation lands AFTER the stream at `rotate_after`
        // drains.  Any remaining streams run against the rotated
        // library; tenant state is cleared structurally by
        // `AuditOrchestrator::rotate_library`.
        if Some(stream_idx) == rotate_after {
            // Safe: `rotate_after` is derived from `input.rotate_library`
            // only when that option is `Some`.
            let rot = input
                .rotate_library
                .as_ref()
                .expect("rotate_after derived from Some(rotate_library); unreachable None");
            if let Err(fail) = apply_rotation(
                &mut orch,
                vector,
                rot,
                &input.trust_anchor_keys_anomaly_library,
            ) {
                return fail;
            }
        }
    }

    // ─── Stage D: render verdict against expected ──────────────────
    render_records_outcome(vector, &observed)
}

/// Apply a [`RotateLibrary`] step mid-run.  Verifies the rotation
/// envelope (fresh ledger — rotation is a separate replay chain per
/// §3.5.1), swaps the orchestrator's library, and updates the
/// per-tenant `initial_time`.
fn apply_rotation(
    orch: &mut AuditOrchestrator,
    vector: &Vector,
    rot: &RotateLibrary,
    anchor_defs: &[TrustAnchorKeyDef],
) -> Result<(), ValidationOutcome> {
    // Rebuild anchors from the same vector-supplied keys — rotation
    // models a library re-publish under the SAME signer.  A true
    // signer-change scenario belongs in the `anomaly-library-reject`
    // suite, not here.  The anchor_defs slice is threaded in from the
    // outer Stage-A deserialize so this function performs no redundant
    // parse of `vector.input`.
    let anchors = build_anchor_set(anchor_defs, AnchorRole::AnomalyLibrarySigner).map_err(|e| {
        ValidationOutcome::Fail {
            reason: format!(
                "audit-replay vector {} rotation anchor build: {e}",
                vector.id
            ),
        }
    })?;

    let cose_bytes = hex::decode(&rot.cose_sign1_bytes_anomaly_library).map_err(|e| {
        ValidationOutcome::Fail {
            reason: format!(
                "audit-replay vector {} rotation cose hex decode: {e}",
                vector.id
            ),
        }
    })?;

    let new_initial_time =
        parse_iso_seconds(&rot.new_initial_time).map_err(|e| ValidationOutcome::Fail {
            reason: format!(
                "audit-replay vector {} rotation new_initial_time not RFC-3339 ({}): {e}",
                vector.id, rot.new_initial_time
            ),
        })?;

    // Fresh ledger for the rotation verify step: the vector's
    // `pre_ledger` was already consumed at Stage A.  A production
    // rotation would persist the pre-rotation HWM; this suite keeps
    // replay testing single-envelope to avoid conflating Stage-8
    // concerns (covered by `anomaly-library-reject`) with the multi-
    // tenant dispatch surface this suite owns.
    let mut ledger = InMemoryAnomalyLedger::new();
    let verified = verify_anomaly_library_signature_with_ledger(
        &cose_bytes,
        &anchors,
        rot.expected_abi_version,
        // Use the rotation's `new_initial_time` as "now" — it is the
        // caller-declared rotation clock.  The production equivalent
        // would be the audit-worker's `SystemTime::now()` at rotation.
        new_initial_time,
        &mut ledger,
    )
    .map_err(|e| ValidationOutcome::Fail {
        reason: format!(
            "audit-replay vector {} rotation envelope verify failed: {e}",
            vector.id
        ),
    })?;

    orch.rotate_library(Arc::new(verified), new_initial_time);
    Ok(())
}

// ---------------- wire-code mapping ----------------------------------

/// Map a [`StreamError`] onto its kebab-case wire string.
///
/// Mirrors [`crate::suites::anomaly_detect::wire_code`] but with the
/// `audit-replay-stream-` prefix — cross-suite wire-code collisions
/// would misroute diagnostics, so each suite owns a disjoint prefix.
#[must_use]
pub(crate) fn wire_code(err: &StreamError) -> &'static str {
    #[allow(unreachable_patterns)]
    match err {
        StreamError::ExpansionExceeded { .. } => "audit-replay-stream-expansion-exceeded",
        StreamError::ClockSkewRejected { .. } => "audit-replay-stream-clock-skew-rejected",
        StreamError::TimestampParseFailed { .. } => "audit-replay-stream-timestamp-parse-failed",
        StreamError::PatternMissingIndexPlaceholder => {
            "audit-replay-stream-pattern-missing-index-placeholder"
        }
        StreamError::ZeroIntervalWithMultipleEvents => {
            "audit-replay-stream-zero-interval-with-multiple-events"
        }
        StreamError::PatternDescriptionCountZero => {
            "audit-replay-stream-pattern-description-count-zero"
        }
        StreamError::PerMandateCapReached { .. } => "audit-replay-stream-per-mandate-cap-reached",
        StreamError::ClockRegression { .. } => "audit-replay-stream-clock-regression",
        StreamError::PastDatedEventRejected { .. } => "audit-replay-stream-past-dated-event",
        _ => "audit-replay-stream-unknown-variant",
    }
}

fn parse_iso_seconds(s: &str) -> Result<i64, time::error::Parse> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
}

// ---------------- verdict rendering ----------------------------------

/// Produce the verdict for a stream-error-path vector.
fn stream_error_outcome(
    vector: &Vector,
    stream_idx: usize,
    stage: &'static str,
    err: &StreamError,
) -> ValidationOutcome {
    let got = wire_code(err);
    let expected_code = vector.expected.reject_code.as_deref().unwrap_or("");
    match vector.expected.outcome {
        Outcome::Accept => ValidationOutcome::Fail {
            reason: format!(
                "audit-replay vector {} stream[{stream_idx}] {stage} expected accept, got reject={got} ({err})",
                vector.id
            ),
        },
        Outcome::Reject => {
            if got == expected_code {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!(
                        "audit-replay vector {} stream[{stream_idx}] {stage} reject-code mismatch: expected={expected_code} got={got} ({err})",
                        vector.id
                    ),
                }
            }
        }
    }
}

/// Produce the verdict for a clean ingest path — dispatch went
/// through without a stream error, so the decision reduces to
/// "did we observe the expected record set?".
fn render_records_outcome(
    vector: &Vector,
    observed: &[AnomalyDetectedRecord],
) -> ValidationOutcome {
    let expected_output: ExpectedOutput = match vector.expected.output.as_ref() {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(eo) => eo,
            Err(e) => {
                return ValidationOutcome::Fail {
                    reason: format!(
                        "audit-replay vector {} expected.output deserialize: {e}",
                        vector.id
                    ),
                };
            }
        },
        None => ExpectedOutput::default(),
    };

    let expected_code = vector.expected.reject_code.as_deref().unwrap_or("");
    let observed_projected: Vec<ExpectedRecord> =
        observed.iter().map(ExpectedRecord::from_observed).collect();

    match vector.expected.outcome {
        Outcome::Accept => {
            if observed.is_empty() && expected_output.records.is_empty() {
                ValidationOutcome::Pass
            } else if !observed.is_empty() {
                ValidationOutcome::Fail {
                    reason: format!(
                        "audit-replay vector {} expected accept, got {} record(s)",
                        vector.id,
                        observed.len()
                    ),
                }
            } else {
                ValidationOutcome::Fail {
                    reason: format!(
                        "audit-replay vector {} expected accept but expected.output.records is non-empty ({} declared) — vector-authoring bug",
                        vector.id,
                        expected_output.records.len()
                    ),
                }
            }
        }
        Outcome::Reject => {
            if expected_code != AGGREGATION_PATTERN_DETECTED_WIRE {
                return ValidationOutcome::Fail {
                    reason: format!(
                        "audit-replay vector {} expected reject={expected_code} but ingest completed without stream error (observed {} record(s))",
                        vector.id,
                        observed.len()
                    ),
                };
            }
            if observed.is_empty() {
                return ValidationOutcome::Fail {
                    reason: format!(
                        "audit-replay vector {} expected reject=aggregation-pattern-detected but observed zero records",
                        vector.id
                    ),
                };
            }
            records_match_outcome(vector, &observed_projected, &expected_output.records)
        }
    }
}

/// Multiset comparison of observed vs. expected records.
fn records_match_outcome(
    vector: &Vector,
    observed: &[ExpectedRecord],
    expected: &[ExpectedRecord],
) -> ValidationOutcome {
    let mut a = observed.to_vec();
    let mut b = expected.to_vec();
    a.sort_by(sort_key);
    b.sort_by(sort_key);
    if a == b {
        ValidationOutcome::Pass
    } else {
        ValidationOutcome::Fail {
            reason: format!(
                "audit-replay vector {} record-set mismatch: observed={} expected={} (after sort: observed_ids={:?}, expected_ids={:?})",
                vector.id,
                observed.len(),
                expected.len(),
                a.iter().map(|r| (&r.tenant_id, &r.pattern_id)).collect::<Vec<_>>(),
                b.iter().map(|r| (&r.tenant_id, &r.pattern_id)).collect::<Vec<_>>(),
            ),
        }
    }
}

/// Stable sort key for record multiset comparison.
///
/// Sorts on `(tenant_id, pattern_id, mandate_id, firing_rule_rank)`
/// — `tenant_id` is the primary axis (multi-tenant isolation is this
/// suite's load-bearing invariant), `pattern_id` and `mandate_id`
/// identify each fire within a tenant, and `firing_rule_rank`
/// tie-breaks co-firing rules at the same scope.
///
/// `mandate_id` is optional: a missing mandate (`None` — only produced
/// when the firing `MatchScope` variant has no mandate anchor, e.g.
/// tenant-wide `CumulativeOverBaseline`) sorts as the empty string `""`,
/// which collates BEFORE every non-empty id.  This keeps cross-tenant /
/// mandate-less fires in a stable, deterministic bucket at the head of
/// the per-pattern group rather than interleaving non-deterministically
/// with named mandates.
fn sort_key(a: &ExpectedRecord, b: &ExpectedRecord) -> std::cmp::Ordering {
    a.tenant_id
        .cmp(&b.tenant_id)
        .then_with(|| a.pattern_id.cmp(&b.pattern_id))
        .then_with(|| {
            a.match_scope
                .mandate_id
                .as_deref()
                .unwrap_or("")
                .cmp(b.match_scope.mandate_id.as_deref().unwrap_or(""))
        })
        .then_with(|| firing_rule_rank(a.firing_rule).cmp(&firing_rule_rank(b.firing_rule)))
}

/// Total-order integer rank on [`FiringRule`] used as a sort tie-break.
///
/// Pinned explicitly rather than derived from `Debug` — a silent
/// rename upstream would destabilise the `format!("{:?}", …)` sort
/// without any test catching it.  [`FiringRule`] is `#[non_exhaustive]`
/// per upstream convention, so compile-time exhaustiveness is
/// unavailable; new variants land in the `_` arm with rank `u8::MAX`
/// (stable end-of-sort bucketing rather than undefined order).  The
/// module-level unit test `firing_rule_rank_pins_known_variants`
/// guards against two known variants silently collapsing.
fn firing_rule_rank(rule: FiringRule) -> u8 {
    use FiringRule::{CumulativeOverBaseline, FirstMatch, SequenceMatch};
    match rule {
        FirstMatch => 0,
        SequenceMatch => 1,
        CumulativeOverBaseline => 2,
        _ => u8::MAX,
    }
}

// ---------------- unit tests -----------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregation_pattern_detected_wire_matches_display() {
        assert_eq!(
            AuditRejectCode::AggregationPatternDetected.to_string(),
            "aggregation-pattern-detected"
        );
    }

    #[test]
    fn aggregation_wire_const_is_spec_literal() {
        assert_eq!(
            AGGREGATION_PATTERN_DETECTED_WIRE,
            "aggregation-pattern-detected"
        );
    }

    // ---------------- firing_rule_rank pins -------------------------

    #[test]
    fn firing_rule_rank_pins_known_variants() {
        let ranks = [
            firing_rule_rank(FiringRule::FirstMatch),
            firing_rule_rank(FiringRule::SequenceMatch),
            firing_rule_rank(FiringRule::CumulativeOverBaseline),
        ];
        assert_eq!(ranks, [0, 1, 2]);
        let mut sorted = ranks.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "ranks must be pairwise distinct");
    }

    // ---------------- wire_code mapping (9 variants + wildcard) -------

    #[test]
    fn wire_code_maps_expansion_exceeded() {
        assert_eq!(
            wire_code(&StreamError::ExpansionExceeded {
                requested: 1_000_000,
                cap: 100_000,
            }),
            "audit-replay-stream-expansion-exceeded"
        );
    }

    #[test]
    fn wire_code_maps_clock_skew_rejected() {
        assert_eq!(
            wire_code(&StreamError::ClockSkewRejected {
                event_id: "e-1".into(),
                skew_seconds: 60,
            }),
            "audit-replay-stream-clock-skew-rejected"
        );
    }

    #[test]
    fn wire_code_maps_timestamp_parse_failed() {
        assert_eq!(
            wire_code(&StreamError::TimestampParseFailed { reason: "bad iso" }),
            "audit-replay-stream-timestamp-parse-failed"
        );
    }

    #[test]
    fn wire_code_maps_pattern_missing_index_placeholder() {
        assert_eq!(
            wire_code(&StreamError::PatternMissingIndexPlaceholder),
            "audit-replay-stream-pattern-missing-index-placeholder"
        );
    }

    #[test]
    fn wire_code_maps_zero_interval_with_multiple_events() {
        assert_eq!(
            wire_code(&StreamError::ZeroIntervalWithMultipleEvents),
            "audit-replay-stream-zero-interval-with-multiple-events"
        );
    }

    #[test]
    fn wire_code_maps_pattern_description_count_zero() {
        assert_eq!(
            wire_code(&StreamError::PatternDescriptionCountZero),
            "audit-replay-stream-pattern-description-count-zero"
        );
    }

    #[test]
    fn wire_code_maps_per_mandate_cap_reached() {
        assert_eq!(
            wire_code(&StreamError::PerMandateCapReached {
                mandate_id: "m-1".into(),
                cap: 10_000,
            }),
            "audit-replay-stream-per-mandate-cap-reached"
        );
    }

    #[test]
    fn wire_code_maps_clock_regression() {
        assert_eq!(
            wire_code(&StreamError::ClockRegression { from: 100, to: 50 }),
            "audit-replay-stream-clock-regression"
        );
    }

    #[test]
    fn wire_code_maps_past_dated_event_rejected() {
        assert_eq!(
            wire_code(&StreamError::PastDatedEventRejected {
                event_id: "e-old".into(),
                age_seconds: 99_999,
                floor: 1_000_000,
            }),
            "audit-replay-stream-past-dated-event"
        );
    }

    #[test]
    fn parse_iso_seconds_accepts_rfc3339_utc() {
        let n = parse_iso_seconds("2026-05-01T00:00:00Z").unwrap();
        assert!(n > 1_577_836_800);
        assert!(n < 2_000_000_000);
    }

    #[test]
    fn parse_iso_seconds_rejects_non_rfc3339() {
        assert!(parse_iso_seconds("not a date").is_err());
        assert!(parse_iso_seconds("2026-05-01").is_err());
    }

    // ---------------- render_records_outcome accept guard --------------

    /// Accept-outcome vectors MUST NOT declare non-empty
    /// `expected.output.records` — such a vector is self-contradictory
    /// (accept means no `AnomalyDetectedRecord` should fire, so any
    /// declared expected record is dead data).  The
    /// `accept-but-expected-records-non-empty` arm in
    /// [`render_records_outcome`] catches this vector-authoring bug.
    /// The reviewer swarm flagged this branch as untested; this pins it.
    #[test]
    fn render_records_outcome_accept_with_non_empty_expected_records_fails() {
        use crate::types::{ExpectedOutcome, Outcome, Severity, Vector};
        use serde_json::json;

        let vector = Vector {
            id: "arep-test-accept-with-records".to_string(),
            category: "audit-replay".to_string(),
            description: "unit-test guard — accept vector with declared expected record"
                .to_string(),
            input: json!({}),
            expected: ExpectedOutcome {
                outcome: Outcome::Accept,
                reject_code: None,
                output: Some(json!({
                    "records": [{
                        "tenant_id": "t-ghost",
                        "pattern_id": "iam-attach-policy-storm",
                        "library_version": 1,
                        "severity": "high",
                        "firing_rule": "cumulative-over-baseline",
                        "match_scope": { "mandate_id": null },
                    }],
                })),
            },
            rationale: "unit-test fixture".to_string(),
            redteam_refs: Vec::new(),
            severity_if_failed: Some(Severity::Medium),
        };

        // Executor observed zero records — matching the Accept outcome —
        // but the vector itself declares a phantom expected record.
        let outcome = render_records_outcome(&vector, &[]);

        match outcome {
            ValidationOutcome::Fail { reason } => {
                assert!(
                    reason.contains("expected accept but expected.output.records is non-empty"),
                    "unexpected Fail reason: {reason}"
                );
                assert!(
                    reason.contains("arep-test-accept-with-records"),
                    "Fail reason must carry vector id: {reason}"
                );
                assert!(
                    reason.contains("vector-authoring bug"),
                    "Fail reason must flag this as an authoring bug: {reason}"
                );
            }
            other => panic!("expected Fail for accept+non-empty-records vector, got {other:?}"),
        }
    }
}
