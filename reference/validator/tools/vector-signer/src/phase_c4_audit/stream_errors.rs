//! Group 4: stream-normalizer / observe_event error paths
//! (arep-111..arep-113).
//!
//! These three vectors complete the wire-code surface for the top-3
//! stream-normalize / ingest failures.  The remaining six
//! [`ephemeral_anomaly::StreamError`] variants are covered by
//! `audit-replay-stream-*` unit tests in
//! `crates/ephemeral-core/src/suites/audit.rs` rather than here — a
//! vector-level duplicate would add zero coverage beyond the unit
//! test's direct enum exhaustion.

use serde_json::{json, Value};

use super::helpers::{
    build_reject_stream_vector, canonical_delete_event, literal_stream, template_event,
    tenant_stream,
};
use super::AUDIT_INITIAL_TIME;

pub(super) fn build_arep_111_clock_regression() -> Value {
    // Two events in tenant-A's stream where the second regresses the
    // clock.  Normalizer accepts the stream (literal events flow
    // through unchanged); failure surfaces at observe_event when
    // advance_clock sees the regression.
    let a_stream = literal_stream(vec![
        canonical_delete_event("ea-0", "m-a111", 100, 2, "pod", "pod/x"),
        canonical_delete_event("ea-1", "m-a111", 10, 2, "pod", "pod/x"),
    ]);

    build_reject_stream_vector(
        "arep-111",
        "audit-replay-clock-regression",
        "Tenant-A's stream contains an event whose timestamp regresses \
         relative to the previous event. The orchestrator's \
         observe_event forwards the regression as ClockRegression, \
         surfaced on the wire as audit-replay-stream-clock-regression.",
        "design-final.md §3.5.3 monotonic audit-stream clock invariant: \
         per-tenant clocks advance-only. The orchestrator must propagate \
         the per-tenant DetectorState's ClockRegression verbatim so \
         vector authors (and production operators) get a loud failure \
         rather than silent reordering.",
        vec![tenant_stream("t-a", a_stream)],
        "audit-replay-stream-clock-regression",
    )
}

pub(super) fn build_arep_112_pattern_description_count_zero() -> Value {
    let stream = json!({
        "pattern_description": {
            "start_time": AUDIT_INITIAL_TIME,
            "end_time": AUDIT_INITIAL_TIME,
            "count": 0,
            "interval_seconds": 0,
            "template_event": template_event("m-a112", 2, "pod", "delete"),
            "resource_ref_pattern": "pod/n-{i}",
        }
    });

    build_reject_stream_vector(
        "arep-112",
        "audit-replay-pattern-description-count-zero",
        "Pattern-description stream with count=0 for tenant-A. Expansion \
         rejects at normalize with PatternDescriptionCountZero, surfaced \
         on the wire as audit-replay-stream-pattern-description-count-\
         zero.",
        "design-final.md §3.5.3 stream expansion contract: zero-count \
         expansions are degenerate author mistakes. Accepting them \
         would silently produce empty streams and mask the bug.",
        vec![tenant_stream("t-a", stream)],
        "audit-replay-stream-pattern-description-count-zero",
    )
}

pub(super) fn build_arep_113_timestamp_parse_failed() -> Value {
    let stream = json!({
        "pattern_description": {
            "start_time": "not-a-real-iso-timestamp",
            "end_time": AUDIT_INITIAL_TIME,
            "count": 3,
            "interval_seconds": 1,
            "template_event": template_event("m-a113", 2, "pod", "delete"),
            "resource_ref_pattern": "pod/n-{i}",
        }
    });

    build_reject_stream_vector(
        "arep-113",
        "audit-replay-timestamp-parse-failed",
        "Pattern-description stream with start_time = \
         `not-a-real-iso-timestamp` for tenant-A. Normalize parses \
         start_time first; the parse failure surfaces as \
         TimestampParseFailed / audit-replay-stream-timestamp-parse-\
         failed.",
        "design-final.md §3.5.3: RFC-3339 is the normative interchange \
         format for audit event timestamps. A lenient fallback here \
         would open a stream-authoring ambiguity that spec'd \
         conformance explicitly closes.",
        vec![tenant_stream("t-a", stream)],
        "audit-replay-stream-timestamp-parse-failed",
    )
}
