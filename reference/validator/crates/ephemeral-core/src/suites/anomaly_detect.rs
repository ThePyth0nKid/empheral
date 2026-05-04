//! Anomaly-detection state-machine execution suite —
//! §§3.5.3 + 11.2 (Phase C.4 Session 5-B Commit B).
//!
//! Dispatches conformance vectors of `vector_suite: "anomaly-detect"`
//! through the Session 5-B firing-rule state machine:
//!
//! 1. Verify the pinned anomaly-library envelope (same gate the
//!    `anomaly-library-reject` suite uses — `verify_anomaly_library_
//!    signature_with_ledger` with a fresh [`InMemoryAnomalyLedger`]
//!    optionally pre-seeded from `pre_ledger`).
//! 2. Construct a [`DetectorState`] pinned to the verified library.
//! 3. Normalise every stream into a `Vec<CanonicalizedEvent>`,
//!    advance the detector clock monotonically for each event,
//!    ingest, then call [`DetectorState::evaluate_all`] after the
//!    stream drains.  Fires accumulate across streams.
//! 4. Compare the accumulated `AnomalyFire` multiset against the
//!    vector's `expected.output.fires` array (order-insensitive —
//!    both sides sort on `(pattern_id, match_scope.mandate_id)`
//!    before element-wise equality, so a stable refactor of the
//!    state machine's buffer iteration cannot regress this suite).
//!
//! ## Wire-code mapping
//!
//! [`wire_code`] is the externally-visible contract of this suite.
//! Changes here break third-party harnesses and MUST land with a
//! bump to the `schema_version` of `conformance/anomaly-detect.json`.
//!
//! - Fires non-empty → `anomaly-detected` (spec §11.2 literal).
//! - Stream normalise / ingest errors → `anomaly-detect-stream-*`
//!   kebab-case surfaces keyed on the [`StreamError`] variant.  The
//!   `anomaly-detect-stream-` prefix disambiguates from
//!   `anomaly-library-*` (library-envelope surfaces) and from
//!   `anomaly-detected` (the AnomalyDetected emission itself).
//!
//! ### `#[non_exhaustive]` wildcard
//!
//! [`StreamError`] is `#[non_exhaustive]`.  The wildcard arm keeps
//! the match exhaustive and buckets unknown variants into
//! `anomaly-detect-stream-unknown-variant` — a stable wire code
//! signalling "downstream harness upgrade required" rather than a
//! silent fall-through that would let a new variant leak into a
//! pre-existing wire bucket.  `#[allow(unreachable_patterns)]`
//! suppresses the within-crate Clippy warning.

use std::collections::BTreeMap;
use std::sync::Arc;

use ephemeral_anomaly::{
    verify_anomaly_library_signature_with_ledger, AnomalyFire, AnomalyLedger as _,
    AuditStreamInput, DetectorState, InMemoryAnomalyLedger, StreamError,
};
use ephemeral_crypto::AnchorRole;
use serde::Deserialize;
use time::OffsetDateTime;

use super::crypto_support::{build_anchor_set, TrustAnchorKeyDef};
use crate::types::{Outcome, ValidationOutcome, Vector};

/// Spec-literal wire code for a non-empty firing set (§11.2).
const ANOMALY_DETECTED_WIRE: &str = "anomaly-detected";

/// Deserialised shape of a `vector.input` block for this suite.
///
/// Reuses the `_anomaly_library`-suffixed envelope field names from
/// the library suite for parity: the two suites verify the SAME
/// envelope under the SAME AAD, and composition with a future multi-
/// envelope vector (library + tariff-chain) stays collision-free.
#[derive(Debug, Deserialize)]
struct AnomalyDetectInput {
    /// Hex-encoded COSE_Sign1 anomaly-library envelope.  Decoded at
    /// execute time.
    cose_sign1_bytes_anomaly_library: String,

    /// Trust anchors for the library envelope.  Role default inherits
    /// [`AnchorRole::AnomalyLibrarySigner`] via `build_anchor_set`.
    trust_anchor_keys_anomaly_library: Vec<TrustAnchorKeyDef>,

    /// ABI expectation passed through to the library verifier.
    expected_abi_version: u32,

    /// RFC-3339 timestamp used as "now" for the library envelope's
    /// time-bound checks (issued-at, expired).
    current_time: String,

    /// Optional pre-seeded replay-ledger state.  Empty (or absent)
    /// means a fresh ledger — the library envelope Stage 8 observes
    /// `FirstObservation`.
    ///
    /// Contract: keys are `library_id`, values are the strict HWM
    /// (`library_version`) already seen.  `BTreeMap` enforces key-
    /// uniqueness at deserialisation so duplicate seeds cannot
    /// reach `ledger.observe` and trigger the "monotone strict-
    /// greater-than" reject from within the seeding loop.  Seeded
    /// HWMs MUST stay **strictly below** the envelope's embedded
    /// `library_version`; a seed `>= library_version` will cause
    /// `verify_anomaly_library_signature_with_ledger` to reject at
    /// Stage 8 (replay), which the executor surfaces as a library-
    /// envelope verify failure — deliberately loud so a mis-seeded
    /// adet- vector does not silently shadow a firing-rule bug.
    ///
    /// Session 5-B Commit B ships 15 vectors all with empty
    /// `pre_ledger`; the seeding loop is therefore not exercised by
    /// the conformance corpus in this commit — exhaustiveness checks
    /// keep the branch live at type level, and the `observe` contract
    /// is covered directly in `ephemeral-anomaly`'s ledger tests.
    /// Future commits adding a ledger-advance vector MUST keep the
    /// seeded HWM below `library_version=1` or accept the verify-
    /// level reject.
    #[serde(default)]
    pre_ledger: BTreeMap<String, u64>,

    /// RFC-3339 timestamp used as the detector's initial clock
    /// ([`DetectorState::new`] `initial_time`).  Separate from
    /// `current_time` so a vector can verify an envelope at one wall
    /// clock and then run the detector at a different (later) wall
    /// clock — useful for past-dated-floor tests.
    initial_time: String,

    /// Streams ingested in order into the detector.  Each stream
    /// normalises into a `Vec<CanonicalizedEvent>`, events flow
    /// through `advance_clock + ingest_event`, and
    /// `evaluate_all()` is called after the stream drains.  Fires
    /// accumulate across streams in the observed firing set.
    streams: Vec<AuditStreamInput>,
}

/// Deserialised shape of a vector's `expected.output` block.
///
/// Only one field — a firing set that the observed multiset must
/// match.  Missing / empty means the vector expects zero fires; the
/// outer `expected.outcome` independently pins accept vs. reject.
#[derive(Debug, Default, Deserialize)]
struct ExpectedOutput {
    #[serde(default)]
    fires: Vec<AnomalyFire>,
}

/// Entry point called by [`crate::runner::run_file`] for every vector
/// in a `vector_suite: "anomaly-detect"` file.
///
/// Deliberately longer than the default 100-line clippy budget. The
/// executor walks sequential fallible stages — input deserialize,
/// anchor-set build, hex decode, library verify, per-stream normalize
/// and evaluate, fire-multiset compare — and every failure mode emits
/// a vector-specific diagnostic string. Extracting the stages into
/// sub-functions would shuffle the same boilerplate around without
/// reducing code size or cognitive load, and would force the caller to
/// thread a shared `vector.id` through four call sites.
#[allow(clippy::too_many_lines)]
pub fn execute(vector: &Vector) -> ValidationOutcome {
    let input: AnomalyDetectInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("anomaly-detect vector {} input deserialize: {e}", vector.id),
            };
        }
    };

    // ─── Stage A: verify the pinned library envelope ───────────────────
    let anchors = match build_anchor_set(
        &input.trust_anchor_keys_anomaly_library,
        AnchorRole::AnomalyLibrarySigner,
    ) {
        Ok(a) => a,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("anomaly-detect vector {} anchor build: {e}", vector.id),
            };
        }
    };

    let cose_bytes = match hex::decode(&input.cose_sign1_bytes_anomaly_library) {
        Ok(b) => b,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-detect vector {} cose_sign1_bytes_anomaly_library hex decode: {e}",
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
                    "anomaly-detect vector {} current_time not RFC-3339 ({}): {e}",
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
                    "anomaly-detect vector {} pre_ledger seed failed: {e}",
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
            // Library envelope verify failed — this suite presumes a
            // valid library; envelope-level rejects belong in the
            // `anomaly-library-reject` suite.  Surface as Fail so
            // vector-authoring bugs are loud instead of silently
            // shadowing Commit-B firing behaviour.
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-detect vector {} anomaly-library envelope verify failed: {e}",
                    vector.id
                ),
            };
        }
    };

    // ─── Stage B: construct detector, ingest streams ───────────────────
    let initial_time = match parse_iso_seconds(&input.initial_time) {
        Ok(n) => n,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-detect vector {} initial_time not RFC-3339 ({}): {e}",
                    vector.id, input.initial_time
                ),
            };
        }
    };

    // `DetectorState` is constructed ONCE per vector and is
    // INTENTIONALLY reused across every stream.  The dedup ledger
    // (`state.dedup_ledger()`) and the per-bucket event buffers
    // therefore retain state between streams, which is load-bearing
    // for vectors such as `adet-108` (stream 2 must be suppressed
    // because stream 1 already fired the same `(pattern_id,
    // match_scope)` key within the pattern's dedup window).  Do NOT
    // reset state between streams without simultaneously retagging
    // every cross-stream vector — the suppression vectors would
    // silently flip to two fires where one is expected.
    let mut state = DetectorState::new(Arc::new(verified), initial_time);
    let mut observed_fires: Vec<AnomalyFire> = Vec::new();

    for (stream_idx, stream) in input.streams.iter().enumerate() {
        let events = match stream.normalize() {
            Ok(e) => e,
            Err(e) => return stream_error_outcome(vector, stream_idx, "normalize", &e),
        };
        for event in events {
            if let Err(e) = state.advance_clock(event.timestamp) {
                return stream_error_outcome(vector, stream_idx, "advance_clock", &e);
            }
            if let Err(e) = state.ingest_event(event) {
                return stream_error_outcome(vector, stream_idx, "ingest_event", &e);
            }
        }
        match state.evaluate_all() {
            Ok(fires) => observed_fires.extend(fires),
            Err(e) => {
                let stream_err = StreamError::from(e);
                return stream_error_outcome(vector, stream_idx, "evaluate_all", &stream_err);
            }
        }
    }

    // ─── Stage C: render verdict against expected ──────────────────────
    render_fires_outcome(vector, &observed_fires)
}

/// Map a [`StreamError`] onto its kebab-case wire string.
///
/// The mapping is the suite's external contract for stream-shape
/// reject surfaces; see the module docblock.  A vector that expects
/// e.g. `anomaly-detect-stream-past-dated-event` drives a malformed
/// stream deliberately; positive-fire vectors never reach this map
/// (they pass ingest and the executor falls through to
/// [`render_fires_outcome`] with a non-empty firing set).
#[must_use]
pub(crate) fn wire_code(err: &StreamError) -> &'static str {
    #[allow(unreachable_patterns)]
    match err {
        StreamError::ExpansionExceeded { .. } => "anomaly-detect-stream-expansion-exceeded",
        StreamError::ClockSkewRejected { .. } => "anomaly-detect-stream-clock-skew-rejected",
        StreamError::TimestampParseFailed { .. } => "anomaly-detect-stream-timestamp-parse-failed",
        StreamError::PatternMissingIndexPlaceholder => {
            "anomaly-detect-stream-pattern-missing-index-placeholder"
        }
        StreamError::ZeroIntervalWithMultipleEvents => {
            "anomaly-detect-stream-zero-interval-with-multiple-events"
        }
        StreamError::PatternDescriptionCountZero => {
            "anomaly-detect-stream-pattern-description-count-zero"
        }
        StreamError::PerMandateCapReached { .. } => "anomaly-detect-stream-per-mandate-cap-reached",
        StreamError::ClockRegression { .. } => "anomaly-detect-stream-clock-regression",
        StreamError::PastDatedEventRejected { .. } => "anomaly-detect-stream-past-dated-event",
        StreamError::DedupLedgerFailure { .. } => "anomaly-detect-stream-dedup-ledger-failure",
        _ => "anomaly-detect-stream-unknown-variant",
    }
}

fn parse_iso_seconds(s: &str) -> Result<i64, time::error::Parse> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
}

/// Produce the verdict for a stream-error-path vector.
///
/// Stream rejects fire BEFORE any fires are collected, so we cannot
/// treat them as "accept" — the stream's author expected either a
/// specific stream-reject code (pass) or a fire-based outcome
/// (mismatch, fail).  The mapping is spelled out in the big match:
/// accept-expected + stream reject → Fail; reject-expected with the
/// right wire code → Pass; reject-expected with a different code →
/// Fail with a diagnostic.
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
                "anomaly-detect vector {} stream[{stream_idx}] {stage} expected accept, got reject={got} ({err})",
                vector.id
            ),
        },
        Outcome::Reject => {
            if got == expected_code {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!(
                        "anomaly-detect vector {} stream[{stream_idx}] {stage} reject-code mismatch: expected={expected_code} got={got} ({err})",
                        vector.id
                    ),
                }
            }
        }
    }
}

/// Produce the verdict for a clean ingest path — no stream error
/// fired, so the decision reduces to "did we observe the expected
/// firing set?".
///
/// The comparison is multiset-based: observed and expected are
/// sorted on `(pattern_id, match_scope.mandate_id)` before element-
/// wise equality.  That accommodates a future refactor that changes
/// buffer iteration order without regressing this suite; the fires
/// themselves are deep-equal-checked (including tier / verb / etc.)
/// because [`AnomalyFire`] derives `PartialEq`.
fn render_fires_outcome(vector: &Vector, observed: &[AnomalyFire]) -> ValidationOutcome {
    let expected_output: ExpectedOutput = match vector.expected.output.as_ref() {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(eo) => eo,
            Err(e) => {
                return ValidationOutcome::Fail {
                    reason: format!(
                        "anomaly-detect vector {} expected.output deserialize: {e}",
                        vector.id
                    ),
                };
            }
        },
        None => ExpectedOutput::default(),
    };

    let expected_code = vector.expected.reject_code.as_deref().unwrap_or("");

    match vector.expected.outcome {
        Outcome::Accept => {
            if observed.is_empty() && expected_output.fires.is_empty() {
                ValidationOutcome::Pass
            } else if !observed.is_empty() {
                ValidationOutcome::Fail {
                    reason: format!(
                        "anomaly-detect vector {} expected accept, got {} fire(s)",
                        vector.id,
                        observed.len()
                    ),
                }
            } else {
                ValidationOutcome::Fail {
                    reason: format!(
                        "anomaly-detect vector {} expected accept but expected.output.fires is non-empty ({} declared) — vector-authoring bug",
                        vector.id,
                        expected_output.fires.len()
                    ),
                }
            }
        }
        Outcome::Reject => {
            if expected_code != ANOMALY_DETECTED_WIRE {
                // The vector declared a stream-reject code but the
                // executor reached here, which means ingest completed
                // cleanly — the expected stream reject never fired.
                return ValidationOutcome::Fail {
                    reason: format!(
                        "anomaly-detect vector {} expected reject={expected_code} but ingest completed without stream error (observed {} fire(s))",
                        vector.id,
                        observed.len()
                    ),
                };
            }
            if observed.is_empty() {
                return ValidationOutcome::Fail {
                    reason: format!(
                        "anomaly-detect vector {} expected reject=anomaly-detected but observed zero fires",
                        vector.id
                    ),
                };
            }
            fires_match_outcome(vector, observed, &expected_output.fires)
        }
    }
}

/// Multiset comparison of observed vs. expected fires.
fn fires_match_outcome(
    vector: &Vector,
    observed: &[AnomalyFire],
    expected: &[AnomalyFire],
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
                "anomaly-detect vector {} firing-set mismatch: observed={} expected={} (after sort: observed_ids={:?}, expected_ids={:?})",
                vector.id,
                observed.len(),
                expected.len(),
                a.iter().map(|f| &f.pattern_id).collect::<Vec<_>>(),
                b.iter().map(|f| &f.pattern_id).collect::<Vec<_>>(),
            ),
        }
    }
}

/// Stable sort key for firing-set multiset comparison.
///
/// Sorts on `(pattern_id, mandate_id)` — the two dimensions that
/// identify every fire in the §11.2 `AnomalyDetected` contract.
/// Ties within that pair are broken by an explicit integer rank on
/// `firing_rule` so the order remains total across `FirstMatch` /
/// `SequenceMatch` / `CumulativeOverBaseline` triplets at the same
/// pattern.
///
/// The `mandate_id` comparison uses `as_deref().unwrap_or("")` so
/// `None` sorts before any `Some(_)` deterministically and a future
/// wildcard-scope pattern that emits a `None` mandate_id cannot
/// silently flip multiset ordering under a `Option::cmp` impl change.
///
/// The `firing_rule` tie-break uses [`firing_rule_rank`] rather than
/// `format!("{:?}", …)` — Debug formatting is not a stable API and a
/// silent rename (`FirstMatch` → `FirstMatched`, etc.) would destabil-
/// ise the sort without any test catching it, because the determinism
/// tripwires only pin the generator's dry-run hash, not the executor's
/// internal sort stability.
fn sort_key(a: &AnomalyFire, b: &AnomalyFire) -> std::cmp::Ordering {
    a.pattern_id
        .cmp(&b.pattern_id)
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
/// Pinned explicitly rather than derived from `Debug` formatting: a
/// silent `FirstMatch → FirstMatched` rename upstream would have
/// destabilised the `format!("{:?}", …)` sort without any test
/// catching it.  [`ephemeral_anomaly::FiringRule`] is
/// `#[non_exhaustive]` per upstream convention, so we cannot enforce
/// compile-time exhaustiveness here; new variants land in the `_`
/// arm with rank `u8::MAX` (stable end-of-sort bucketing rather than
/// undefined order).  The module-level unit test
/// `firing_rule_rank_pins_known_variants` guards against two known
/// variants silently collapsing to the same rank, and a new variant
/// WILL trip the `below_threshold`/ `firing-set` multiset compare in
/// any vector that emits it — forcing the executor author to pin a
/// rank here.
fn firing_rule_rank(rule: ephemeral_anomaly::FiringRule) -> u8 {
    use ephemeral_anomaly::FiringRule::{CumulativeOverBaseline, FirstMatch, SequenceMatch};
    match rule {
        FirstMatch => 0,
        SequenceMatch => 1,
        CumulativeOverBaseline => 2,
        // #[non_exhaustive]: new variants sort after all known ones
        // in insertion-stable order.  Add an explicit arm above
        // when such a variant lands.
        _ => u8::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- firing_rule_rank pins -------------------------------

    #[test]
    fn firing_rule_rank_pins_known_variants() {
        use ephemeral_anomaly::FiringRule;
        // Every known variant MUST resolve to a distinct rank so the
        // sort_key tie-break is a strict total order within a
        // (pattern_id, mandate_id) equivalence class.
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

    // ---------------- wire_code mapping (10 variants + wildcard) -----------

    #[test]
    fn wire_code_maps_expansion_exceeded() {
        assert_eq!(
            wire_code(&StreamError::ExpansionExceeded {
                requested: 1_000_000,
                cap: 100_000,
            }),
            "anomaly-detect-stream-expansion-exceeded"
        );
    }

    #[test]
    fn wire_code_maps_clock_skew_rejected() {
        assert_eq!(
            wire_code(&StreamError::ClockSkewRejected {
                event_id: "e-1".into(),
                skew_seconds: 60,
            }),
            "anomaly-detect-stream-clock-skew-rejected"
        );
    }

    #[test]
    fn wire_code_maps_timestamp_parse_failed() {
        assert_eq!(
            wire_code(&StreamError::TimestampParseFailed { reason: "bad iso" }),
            "anomaly-detect-stream-timestamp-parse-failed"
        );
    }

    #[test]
    fn wire_code_maps_pattern_missing_index_placeholder() {
        assert_eq!(
            wire_code(&StreamError::PatternMissingIndexPlaceholder),
            "anomaly-detect-stream-pattern-missing-index-placeholder"
        );
    }

    #[test]
    fn wire_code_maps_zero_interval_with_multiple_events() {
        assert_eq!(
            wire_code(&StreamError::ZeroIntervalWithMultipleEvents),
            "anomaly-detect-stream-zero-interval-with-multiple-events"
        );
    }

    #[test]
    fn wire_code_maps_pattern_description_count_zero() {
        assert_eq!(
            wire_code(&StreamError::PatternDescriptionCountZero),
            "anomaly-detect-stream-pattern-description-count-zero"
        );
    }

    #[test]
    fn wire_code_maps_per_mandate_cap_reached() {
        assert_eq!(
            wire_code(&StreamError::PerMandateCapReached {
                mandate_id: "m-1".into(),
                cap: 10_000,
            }),
            "anomaly-detect-stream-per-mandate-cap-reached"
        );
    }

    #[test]
    fn wire_code_maps_clock_regression() {
        assert_eq!(
            wire_code(&StreamError::ClockRegression { from: 100, to: 50 }),
            "anomaly-detect-stream-clock-regression"
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
            "anomaly-detect-stream-past-dated-event"
        );
    }

    #[test]
    fn wire_code_maps_dedup_ledger_failure() {
        assert_eq!(
            wire_code(&StreamError::DedupLedgerFailure {
                reason: "rocksdb: io error".into(),
            }),
            "anomaly-detect-stream-dedup-ledger-failure"
        );
    }

    // ---------------- parse_iso_seconds --------------------------------

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
}
