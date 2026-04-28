//! End-to-end integration tests for Session 5-B Commit A — firing-rule
//! evaluators wired through [`DetectorState::evaluate_all`].
//!
//! These tests exercise the full public API:
//!
//! 1. Assemble a library fixture via `ephemeral_anomaly::test_fixtures`.
//! 2. Construct a [`DetectorState`] pinned to that library.
//! 3. Ingest [`CanonicalizedEvent`] streams that do / do not cross the
//!    relevant firing threshold.
//! 4. Invoke [`DetectorState::evaluate_all`] and pin the observable
//!    [`AnomalyFire`] output (count, `pattern_id`, `match_scope`).
//!
//! Unit tests in `src/evaluators.rs` pin the per-evaluator logic in
//! isolation; this file pins the dispatch + eviction + dedup wiring.
//! A regression in the match arms of `DetectorState::evaluate_all`,
//! the buffer-eviction call before counting, or the `last_fired_at`
//! update after a successful fire surfaces here rather than silently
//! in prod.
//!
//! # Layered protection
//!
//! - `src/evaluators.rs` unit tests exercise each evaluator with
//!   hand-constructed `PatternBuffer` values (white-box).
//! - `tests/state_machine_skeleton.rs` pins the ingestion pipeline
//!   plus a single `FirstMatch` fixture walk-through.
//! - This file pins the three firing rules together, each with the
//!   fixture that §3.5.4 pairs the rule with.

#![allow(clippy::unreadable_literal)]

use std::sync::Arc;

use ephemeral_anomaly::test_fixtures::{
    cross_tier_escalation_pattern, delete_storm_pattern, fanout_distinct_resources_pattern,
    fixture_detector_library, machine_pace_pattern,
};
use ephemeral_anomaly::{CanonicalizedEvent, DetectorState, Outcome};

// -------------------------------------------------------------------
// Construction helpers
// -------------------------------------------------------------------

/// Clock anchor common to every test — arbitrary but fixed so ages
/// and windows are easy to reason about.
const ANCHOR: i64 = 1_800_000_000;

/// Delete event with per-call variation only in `event_id` and
/// `timestamp`.  Uses `delete`/`pod` to match `delete-storm` and
/// `kubernetes` integration.
fn delete_event(event_id: &str, mandate_id: &str, timestamp: i64) -> CanonicalizedEvent {
    CanonicalizedEvent::new_for_testing(
        event_id,
        timestamp,
        mandate_id,
        2,
        "kubernetes",
        "delete",
        "pod",
        "ns/app/pod-1",
        Outcome::Executed,
    )
}

/// Delete event with a caller-chosen `resource_ref` — used by the
/// fanout-distinct test to produce N distinct refs from a shared
/// mandate.
fn delete_event_with_ref(
    event_id: &str,
    mandate_id: &str,
    timestamp: i64,
    resource_ref: &str,
) -> CanonicalizedEvent {
    CanonicalizedEvent::new_for_testing(
        event_id,
        timestamp,
        mandate_id,
        2,
        "kubernetes",
        "delete",
        "pod",
        resource_ref,
        Outcome::Executed,
    )
}

/// Tier-parameterised event for the cross-tier-sequence test.  All
/// other fields are defaulted to match the `cross_tier_escalation`
/// scope predicate (which binds only on tier progression).
fn tiered_event(event_id: &str, mandate_id: &str, timestamp: i64, tier: u8) -> CanonicalizedEvent {
    CanonicalizedEvent::new_for_testing(
        event_id,
        timestamp,
        mandate_id,
        tier,
        "kubernetes",
        "read",
        "pod",
        "ns/app/pod-1",
        Outcome::Executed,
    )
}

/// `machine-pace` event — any tier ≥ 1, verb outside the read-only
/// category.  `delete` satisfies both.
fn pace_event(event_id: &str, mandate_id: &str, timestamp: i64) -> CanonicalizedEvent {
    CanonicalizedEvent::new_for_testing(
        event_id,
        timestamp,
        mandate_id,
        2,
        "kubernetes",
        "delete",
        "pod",
        "ns/app/pod-1",
        Outcome::Executed,
    )
}

// -------------------------------------------------------------------
// FirstMatch — Count (delete-storm)
// -------------------------------------------------------------------

#[test]
fn first_match_fires_at_count_threshold() {
    // delete-storm is FirstMatch / Count(5) / 60s window.  Scope:
    // VerbPredicate::AnyDestructive + resource_kind=None — a verb-
    // FAMILY predicate, so MatchScope.verb and .resource_kind are
    // BOTH None at fire time (per MatchScope field doc).  Only
    // mandate_id is bound via the bucket key.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    for i in 0..5_i64 {
        state
            .ingest_event(delete_event(&format!("e-{i}"), "m-1", ANCHOR + i))
            .expect("ingest");
    }

    let fires = state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests");
    assert_eq!(fires.len(), 1);
    assert_eq!(fires[0].pattern_id, "delete-storm");
    assert_eq!(fires[0].match_scope.mandate_id.as_deref(), Some("m-1"));
    // Family predicate does not pin verb or resource_kind in scope
    // projection — pinned by `build_match_scope` rules in evaluators.rs.
    assert_eq!(fires[0].match_scope.verb, None);
    assert_eq!(fires[0].match_scope.resource_kind, None);
}

#[test]
fn first_match_does_not_fire_below_threshold() {
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);
    for i in 0..4_i64 {
        state
            .ingest_event(delete_event(&format!("e-{i}"), "m-1", ANCHOR + i))
            .expect("ingest");
    }
    assert!(state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests")
        .is_empty());
}

// -------------------------------------------------------------------
// FirstMatch — DistinctCount (fanout-distinct-resources)
// -------------------------------------------------------------------

#[test]
fn first_match_distinct_count_fires_at_threshold() {
    // fanout-distinct-resources is FirstMatch / DistinctCount(10).
    // Ten events with distinct `resource_ref` values cross the
    // threshold; duplicates would not inflate the distinct count.
    let library = fixture_detector_library(vec![fanout_distinct_resources_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    for i in 0..10_i64 {
        state
            .ingest_event(delete_event_with_ref(
                &format!("e-{i}"),
                "m-fanout",
                ANCHOR + i,
                &format!("ns/app/pod-{i}"),
            ))
            .expect("ingest");
    }

    let fires = state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests");
    assert_eq!(fires.len(), 1);
    assert_eq!(fires[0].pattern_id, "fanout-distinct-resources");
    assert_eq!(fires[0].match_scope.mandate_id.as_deref(), Some("m-fanout"));
}

#[test]
fn first_match_distinct_count_ignores_duplicates() {
    // Nine distinct resource_refs plus one duplicate = distinct count
    // of 9, below the 10-threshold — must not fire.
    let library = fixture_detector_library(vec![fanout_distinct_resources_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    for i in 0..9_i64 {
        state
            .ingest_event(delete_event_with_ref(
                &format!("e-{i}"),
                "m-fanout",
                ANCHOR + i,
                &format!("ns/app/pod-{i}"),
            ))
            .expect("ingest");
    }
    // Duplicate of pod-0.
    state
        .ingest_event(delete_event_with_ref(
            "e-dup",
            "m-fanout",
            ANCHOR + 9,
            "ns/app/pod-0",
        ))
        .expect("ingest");

    assert!(
        state
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests")
            .is_empty(),
        "duplicate resource_refs must not inflate DistinctCount",
    );
}

// -------------------------------------------------------------------
// SequenceMatch — CrossTierSequence (cross-tier-escalation)
// -------------------------------------------------------------------

#[test]
fn sequence_match_fires_on_ordered_tier_walk() {
    // cross-tier-escalation: tier_progression = [0, 2, 3] — one
    // completion per 0 → 2 → 3 walk across the buffer.
    let library = fixture_detector_library(vec![cross_tier_escalation_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    state
        .ingest_event(tiered_event("e-0", "m-esc", ANCHOR, 0))
        .expect("ingest tier-0");
    state
        .ingest_event(tiered_event("e-1", "m-esc", ANCHOR + 1, 2))
        .expect("ingest tier-2");
    state
        .ingest_event(tiered_event("e-2", "m-esc", ANCHOR + 2, 3))
        .expect("ingest tier-3");

    let fires = state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests");
    assert_eq!(fires.len(), 1);
    assert_eq!(fires[0].pattern_id, "cross-tier-escalation");
    assert_eq!(fires[0].match_scope.mandate_id.as_deref(), Some("m-esc"));
}

#[test]
fn sequence_match_does_not_fire_on_partial_walk() {
    // Only the first two steps of the tier progression — no
    // completion, no fire.
    let library = fixture_detector_library(vec![cross_tier_escalation_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    state
        .ingest_event(tiered_event("e-0", "m-esc", ANCHOR, 0))
        .expect("ingest");
    state
        .ingest_event(tiered_event("e-1", "m-esc", ANCHOR + 1, 2))
        .expect("ingest");

    assert!(state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests")
        .is_empty());
}

// -------------------------------------------------------------------
// CumulativeOverBaseline — Count (machine-pace)
// -------------------------------------------------------------------

#[test]
fn cumulative_over_baseline_fires_at_count_threshold() {
    // machine-pace: CumulativeOverBaseline / Count(50) / 60s window.
    // Ingest 50 events spanning 50 seconds; keep the clock at the
    // FIRST event's timestamp so every later event is at most 49s
    // ahead of current_time — within `MAX_CLOCK_SKEW_SECONDS` (30s?)
    // would reject.  We advance the clock forward alongside ingestion
    // so every event timestamp equals the current clock.
    let library = fixture_detector_library(vec![machine_pace_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    for i in 0..50_i64 {
        let ts = ANCHOR + i;
        state.advance_clock(ts).expect("clock advance");
        state
            .ingest_event(pace_event(&format!("e-{i}"), "m-pace", ts))
            .expect("ingest");
    }

    let fires = state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests");
    assert_eq!(fires.len(), 1);
    assert_eq!(fires[0].pattern_id, "machine-pace");
    assert_eq!(fires[0].match_scope.mandate_id.as_deref(), Some("m-pace"));
    // MandatePace projects tier into the MatchScope scalar.
    assert_eq!(fires[0].match_scope.tier, Some(2));
}

// -------------------------------------------------------------------
// Dispatch-level cross-cutting pins
// -------------------------------------------------------------------

#[test]
fn evaluate_all_fires_independent_mandates_in_parallel() {
    // Two mandates cross the delete-storm threshold in the same tick.
    // Both fires appear in the returned Vec; dedup is mandate-scoped.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);
    for mid in ["m-a", "m-b"] {
        for i in 0..5_i64 {
            state
                .ingest_event(delete_event(&format!("e-{mid}-{i}"), mid, ANCHOR + i))
                .expect("ingest");
        }
    }
    let fires = state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests");
    assert_eq!(fires.len(), 2);
    // BTreeMap iteration is ordered — fires come back in mandate_id
    // lexicographic order.
    assert_eq!(fires[0].match_scope.mandate_id.as_deref(), Some("m-a"));
    assert_eq!(fires[1].match_scope.mandate_id.as_deref(), Some("m-b"));
}

#[test]
fn evaluate_all_dispatches_heterogeneous_library_patterns() {
    // A library mixing two firing rules fires each one independently
    // when their respective thresholds are crossed.
    let library = fixture_detector_library(vec![
        delete_storm_pattern(),
        cross_tier_escalation_pattern(),
    ]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    // Feed the storm — matches both delete-storm AND (at tier 2)
    // advances the cross-tier walker's second step.  To actually
    // complete the cross-tier sequence we need a tier-3 event after,
    // preceded by a tier-0 event (implicit: first tier-2 event does
    // not satisfy step 0 of [0, 2, 3] because 2 ≥ 0, so the walker
    // advances past step 0 on the first event).
    for i in 0..5_i64 {
        state
            .ingest_event(delete_event(&format!("e-{i}"), "m-mixed", ANCHOR + i))
            .expect("ingest");
    }
    // Tier-3 event completes [0, 2, 3] — the delete events at tier 2
    // satisfy steps 0 (2 ≥ 0) and 1 (2 ≥ 2); the tier-3 escalation
    // satisfies step 2.
    state
        .ingest_event(tiered_event("e-esc", "m-mixed", ANCHOR + 5, 3))
        .expect("ingest tier-3");

    let fires = state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests");
    assert_eq!(fires.len(), 2, "both patterns must fire independently");
    let pattern_ids: Vec<&str> = fires.iter().map(|f| f.pattern_id.as_str()).collect();
    // BTreeMap iteration order — buckets keyed on (pattern_id,
    // mandate_id, ...) — gives `cross-tier-escalation` before
    // `delete-storm` lexicographically.
    assert_eq!(pattern_ids, vec!["cross-tier-escalation", "delete-storm"]);
}

#[test]
fn evaluate_all_does_not_fire_unmatched_patterns() {
    // A library loaded with `machine-pace` (50 events in 60s); only
    // 10 events ingested — below threshold, no fire, and the
    // evaluator does not return a stale fire from an earlier call.
    let library = fixture_detector_library(vec![machine_pace_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);
    for i in 0..10_i64 {
        state
            .ingest_event(pace_event(&format!("e-{i}"), "m-pace", ANCHOR + i))
            .expect("ingest");
    }
    assert!(state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests")
        .is_empty());
    assert!(state.dedup_ledger().is_empty());
}
