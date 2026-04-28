//! Regression pins for the two residual risks Session 5-A documented
//! and Session 5-B Commit A resolves.
//!
//! Cross-reference: `src/state.rs` module doc §"Session 5-A → 5-B
//! residual-risk resolution".
//!
//! 1. **`per_mandate_counters` is session-monotonic by design** —
//!    the 5-A note worried the counter would undercount under
//!    sliding-window eviction.  5-B clarifies its role (`DoS`
//!    containment rate-limit, not a firing source) and pins the
//!    non-decrement invariant here so a future PR that attempts
//!    "clean-up" cannot silently re-introduce the drift risk.
//!
//! 2. **Past-dated event floor enforced** — 5-A accepted arbitrarily
//!    old events, which let a past-dated flood pack buckets that no
//!    sliding-window evaluator could ever drain.  5-B's
//!    `past_dated_floor` closes this; the pins below replay the
//!    attack shape (10-day-old backlog against a 60-s library) and
//!    assert it rejects at ingest rather than accumulating silently.
//!
//! Both risks are additionally covered by inline unit tests in
//! `src/state.rs::tests`; this file pins them at the integration
//! boundary so the behaviour is observable via the crate's PUBLIC
//! API, not an implementation detail.

#![allow(clippy::unreadable_literal)]

use std::sync::Arc;

use ephemeral_anomaly::test_fixtures::{delete_storm_pattern, fixture_detector_library};
use ephemeral_anomaly::{CanonicalizedEvent, DetectorState, Outcome, StreamError};

const ANCHOR: i64 = 1_800_000_000;

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

// -------------------------------------------------------------------
// Risk #1 — per_mandate_counters session-monotonic invariant
// -------------------------------------------------------------------

#[test]
fn per_mandate_counter_does_not_decrement_on_eviction() {
    // Ingest 5 events, fire, then evict via clock advance past the
    // 60-s delete-storm window.  `per_mandate_counters` MUST remain
    // at 5 — eviction of buffered events does not bleed down the
    // session rate-limit counter.  Its contract is lifetime DoS
    // containment, not sliding-window counting.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    for i in 0..5_i64 {
        state
            .ingest_event(delete_event(&format!("e-{i}"), "m-1", ANCHOR + i))
            .expect("ingest");
    }
    let _ = state.evaluate_all();
    assert_eq!(state.per_mandate_counters().get("m-1").copied(), Some(5));

    // Advance past the 60-s window and trigger a second evaluate_all.
    // Buckets evict; counter MUST stay at 5.
    state.advance_clock(ANCHOR + 120).expect("clock advance");
    let _ = state.evaluate_all();
    assert_eq!(
        state.per_mandate_counters().get("m-1").copied(),
        Some(5),
        "per_mandate_counters must not decrement on sliding-window eviction — \
         the counter is a session-lifetime DoS cap, not a per-window count"
    );
}

#[test]
fn firing_uses_buffer_length_not_session_counter() {
    // A mandate that has historically emitted 5 events (counter=5)
    // but has no LIVE events in the sliding window (all evicted) must
    // NOT fire — the firing source is `PatternBuffer::events.len()`
    // after eviction, NOT the monotonic session counter.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    for i in 0..5_i64 {
        state
            .ingest_event(delete_event(&format!("e-{i}"), "m-1", ANCHOR + i))
            .expect("ingest");
    }
    assert_eq!(
        state
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests")
            .len(),
        1
    );

    // Advance past window + grace; evict aged events; counter remains
    // at 5 but buffer empties.  A second call sees an empty bucket
    // and does not fire.
    state.advance_clock(ANCHOR + 120).expect("clock advance");
    assert!(
        state
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests")
            .is_empty(),
        "firing source is buffer length after eviction, not session counter"
    );
    assert_eq!(state.per_mandate_counters().get("m-1").copied(), Some(5));
}

// -------------------------------------------------------------------
// Risk #2 — past-dated event floor enforced
// -------------------------------------------------------------------

#[test]
fn past_dated_flood_rejects_before_buffering() {
    // Attack shape from the 5-A residual-risk note: flood the
    // detector with old events that no sliding-window pattern could
    // ever drain.  With the floor in place, events older than
    // `current_time - (max_window + grace)` reject at ingest —
    // buffers stay empty, counter stays at zero.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    // Library max window = 60s; grace = 86_400s (24h).  Floor =
    // ANCHOR - 60 - 86_400.  Anything older rejects.
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    let ten_days = 10 * 86_400_i64;
    for i in 0..20_i64 {
        let result = state.ingest_event(delete_event(
            &format!("old-{i}"),
            "m-flood",
            ANCHOR - ten_days + i,
        ));
        match result {
            Err(StreamError::PastDatedEventRejected { .. }) => {}
            other => panic!("expected PastDatedEventRejected, got {other:?}"),
        }
    }

    // No event made it past Stage 2 — buffers empty, counter zero.
    assert!(state.buffers().is_empty());
    assert!(state.per_mandate_counters().is_empty());
    assert!(state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests")
        .is_empty());
}

#[test]
fn past_dated_floor_accepts_fresh_events_interleaved_with_rejected_stale_ones() {
    // Realistic recovery scenario: a backlog replayer emits a mix of
    // stale (pre-floor) and fresh (post-floor) events.  Only fresh
    // events buffer; stale events reject without corrupting state.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    // Stale — rejects.
    let ten_days = 10 * 86_400_i64;
    let result = state.ingest_event(delete_event("stale-1", "m-mix", ANCHOR - ten_days));
    assert!(matches!(
        result,
        Err(StreamError::PastDatedEventRejected { .. })
    ));

    // Fresh (well within window) — accepts.
    for i in 0..5_i64 {
        state
            .ingest_event(delete_event(&format!("fresh-{i}"), "m-mix", ANCHOR + i))
            .expect("fresh event must accept");
    }

    // Fires on fresh events alone; the rejected stale event did not
    // inflate the bucket.
    let fires = state
        .evaluate_all()
        .expect("in-memory dedup ledger is infallible in tests");
    assert_eq!(fires.len(), 1);
    assert_eq!(fires[0].pattern_id, "delete-storm");
    assert_eq!(fires[0].match_scope.mandate_id.as_deref(), Some("m-mix"));
}

#[test]
fn past_dated_floor_sanitizes_attacker_controlled_event_id() {
    // Log-injection hardening: an attacker-controlled `event_id`
    // containing `\n` or `\r` passes through
    // `crate::errors::sanitize_log_string` before being wrapped into
    // the `PastDatedEventRejected` variant.  A regression that bound
    // the raw `event_id` would surface here.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), ANCHOR);

    let ten_days = 10 * 86_400_i64;
    let result = state.ingest_event(delete_event(
        "evil\nINJ\rADMIN",
        "m-evil",
        ANCHOR - ten_days,
    ));
    match result {
        Err(StreamError::PastDatedEventRejected { event_id, .. }) => {
            assert!(!event_id.contains('\n'), "newline must be sanitised");
            assert!(
                !event_id.contains('\r'),
                "carriage return must be sanitised"
            );
        }
        other => panic!("expected PastDatedEventRejected, got {other:?}"),
    }
}
