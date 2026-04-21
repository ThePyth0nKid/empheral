//! End-to-end integration tests for the Session 5-A state-machine
//! skeleton ([`DetectorState`], [`PatternBuffer`], [`SequenceTracker`]).
//!
//! Session 5-A deliverable (plan §18).  This file pins the PUBLIC
//! API surface every downstream consumer sees:
//!
//! - Construction via [`DetectorState::new`] with a pinned library.
//! - Per-event ingestion pipeline (clock-skew gate, per-mandate
//!   quota, scope routing, silent per-buffer ring eviction).
//! - Monotonic clock advancement via
//!   [`DetectorState::advance_clock`].
//! - The Session-5-A contract that [`DetectorState::evaluate_all`]
//!   returns an empty `Vec` even after ingestion — Session 5-B
//!   replaces this stub with per-pattern firing evaluators.
//!
//! # Layered protection
//!
//! 1. Inline `src/state.rs` unit tests pin the stage-by-stage
//!    ingestion logic and individual error-variant shapes.
//! 2. This file pins the cross-module integration: library fixture
//!    → `DetectorState` → ingest → `evaluate_all` produces the
//!    Session-5-A stub output.  A regression in the fixture, the
//!    `Arc<VerifiedAnomalyLibrarySignature>` sharing surface, or
//!    the `pub use` re-exports from `lib.rs` surfaces here rather
//!    than passing silently and breaking Session 5-B.
//! 3. The `test_fixtures` self-tests pin the fixture's structural
//!    shape; this file pins the state machine's OBSERVABLE effect
//!    on that fixture.

#![allow(clippy::unreadable_literal)]

use std::sync::Arc;

use ephemeral_anomaly::test_fixtures::{
    delete_storm_pattern, fixture_canary_stream, fixture_delete_storm_stream,
    fixture_detector_library, FIXTURE_DETECTOR_EXPIRES_AT, FIXTURE_DETECTOR_ISSUED_AT,
    FIXTURE_DETECTOR_LIBRARY_ID, FIXTURE_DETECTOR_LIBRARY_VERSION, FIXTURE_STORM_START_UNIX,
};
use ephemeral_anomaly::{
    CanonicalizedEvent, DetectorState, Outcome, StreamError, MAX_CLOCK_SKEW_SECONDS,
    MAX_EVENTS_PER_BUFFER, MAX_EVENTS_PER_MANDATE,
};

// -------------------------------------------------------------------
// Contract pin — the Session-5-A evaluator stub
// -------------------------------------------------------------------

/// Detector-clock anchor for tests that replay the full
/// `fixture_delete_storm_stream`.  The fixture spans
/// `[FIXTURE_STORM_START_UNIX, FIXTURE_STORM_START_UNIX + 54]`;
/// anchoring the detector at the end of the span keeps every
/// event past-dated relative to `current_time`, so none tripp the
/// positive-skew gate.  Realistic: the audit pipeline batches
/// already-landed events into the detector after the fact.
const POST_STORM_ANCHOR: i64 = FIXTURE_STORM_START_UNIX + 54;

#[test]
fn evaluate_all_returns_empty_vec_without_fire_logic() {
    // The load-bearing Session-5-A contract: no matter how many
    // events the detector has ingested, `evaluate_all` returns an
    // empty Vec.  Session 5-B replaces the stub with per-pattern
    // evaluators; downstream consumers relying on the stub until
    // then observe "no fires" as an intentional no-op, NOT a silent
    // mis-routing.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(Arc::clone(&library), POST_STORM_ANCHOR);

    // Feed the storm fixture — 10 events that WOULD fire delete-storm
    // at Session 5-B (5-in-60s threshold crossed twice over).
    for event in fixture_delete_storm_stream()
        .normalize()
        .expect("storm fixture normalises")
    {
        state
            .ingest_event(event)
            .expect("session-5-A ingest MUST accept the full delete-storm fixture");
    }

    // Pre-condition: the state machine HAS seen the events.
    assert_eq!(state.per_mandate_counters().get("m-storm"), Some(&10));

    // Contract pin: evaluate_all is the empty stub regardless of
    // ingestion state.
    let fires = state.evaluate_all();
    assert!(
        fires.is_empty(),
        "Session-5-A evaluate_all MUST be empty; observed {} fires \
         — firing-rule evaluation is Session-5-B work.",
        fires.len()
    );
}

#[test]
fn evaluate_all_is_empty_on_fresh_state() {
    // Symmetric pin: the stub returns empty BEFORE any ingestion,
    // too.  A regression that made evaluate_all depend on the
    // iteration order of an empty buffer map would surface here.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let state = DetectorState::new(library, FIXTURE_STORM_START_UNIX);
    assert!(state.evaluate_all().is_empty());
}

// -------------------------------------------------------------------
// Pinned-library shape
// -------------------------------------------------------------------

#[test]
fn detector_state_exposes_pinned_library_fields() {
    // Pins the `pinned_library` accessor: downstream audit-pipeline
    // workers consume the library header (library_id, version,
    // validity window) for provenance logging and cannot do so if
    // the accessor regresses.
    let library = fixture_detector_library(vec![]);
    let state = DetectorState::new(Arc::clone(&library), FIXTURE_DETECTOR_ISSUED_AT);

    let pinned = state.pinned_library();
    assert_eq!(pinned.library_id, FIXTURE_DETECTOR_LIBRARY_ID);
    assert_eq!(pinned.library_version, FIXTURE_DETECTOR_LIBRARY_VERSION);
    assert_eq!(pinned.issued_at, FIXTURE_DETECTOR_ISSUED_AT);
    assert_eq!(pinned.expires_at, FIXTURE_DETECTOR_EXPIRES_AT);
    assert!(pinned.patterns.is_empty());
}

#[test]
fn detector_state_shares_library_across_clones_via_arc() {
    // Two DetectorState instances built from the same Arc share the
    // underlying library allocation.  This is load-bearing: the
    // audit pipeline may spawn multiple per-tenant workers off one
    // verified library without a per-worker deep copy.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let a = DetectorState::new(Arc::clone(&library), FIXTURE_STORM_START_UNIX);
    let b = DetectorState::new(Arc::clone(&library), FIXTURE_STORM_START_UNIX);

    // Pointer equality on the inner Arc — NOT just structural eq —
    // pins that no deep clone happened.
    assert!(Arc::ptr_eq(a.pinned_library(), b.pinned_library()));
}

// -------------------------------------------------------------------
// Ingestion happy path
// -------------------------------------------------------------------

#[test]
fn ingestion_routes_delete_storm_events_to_matching_bucket() {
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(library, POST_STORM_ANCHOR);

    let events = fixture_delete_storm_stream()
        .normalize()
        .expect("storm fixture normalises");
    assert_eq!(events.len(), 10);

    for event in events {
        state.ingest_event(event).expect("happy-path ingest");
    }

    // Exactly one bucket — delete-storm pattern × m-storm mandate.
    assert_eq!(state.buffers().len(), 1);
    let (key, buffer) = state
        .buffers()
        .iter()
        .next()
        .expect("at least one bucket after ingestion");
    assert_eq!(key.pattern_id, "delete-storm");
    assert_eq!(key.mandate_id, "m-storm");
    assert_eq!(buffer.events().len(), 10);
    assert_eq!(buffer.pattern_id, "delete-storm");
}

#[test]
fn ingestion_with_empty_library_tracks_counter_but_creates_no_bucket() {
    // No patterns means no predicates match — the bucket map stays
    // empty — but the per-mandate counter MUST still advance so the
    // quota gate is unaffected by library contents.
    let library = fixture_detector_library(vec![]);
    let mut state = DetectorState::new(library, POST_STORM_ANCHOR);

    for event in fixture_delete_storm_stream().normalize().unwrap() {
        state.ingest_event(event).expect("ingest with empty lib");
    }

    assert!(state.buffers().is_empty());
    assert_eq!(state.per_mandate_counters().get("m-storm"), Some(&10));
}

#[test]
fn ingestion_does_not_cross_route_non_matching_events() {
    // Canary fixture uses verb="sign", resource_kind="attestation",
    // mandate_id="m-canary" — none of which match delete-storm
    // (AnyDestructive + kubernetes delete pattern).  The counter
    // still advances; the bucket map stays empty.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let mut state = DetectorState::new(library, FIXTURE_STORM_START_UNIX);

    for event in fixture_canary_stream().normalize().unwrap() {
        state.ingest_event(event).expect("canary ingest");
    }

    assert!(
        state.buffers().is_empty(),
        "canary stream must not route into delete-storm buckets"
    );
    assert_eq!(state.per_mandate_counters().get("m-canary"), Some(&3));
}

// -------------------------------------------------------------------
// Clock-skew rejection
// -------------------------------------------------------------------

#[test]
fn ingest_rejects_future_dated_event_beyond_skew_cap() {
    // An event timestamp MAX_CLOCK_SKEW_SECONDS+1 ahead of the
    // detector's current_time MUST reject.  This bounds deferred-
    // fire attacks where an adversary back-dates events into a
    // future window.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let now = FIXTURE_STORM_START_UNIX;
    let mut state = DetectorState::new(library, now);

    let future = CanonicalizedEvent::new_for_testing(
        "evt-future",
        now + MAX_CLOCK_SKEW_SECONDS + 1,
        "m-storm",
        2,
        "kubernetes",
        "delete",
        "pod",
        "ns/app/pod-future",
        Outcome::Executed,
    );
    let err = state.ingest_event(future).unwrap_err();
    match err {
        StreamError::ClockSkewRejected {
            event_id,
            skew_seconds,
        } => {
            assert_eq!(event_id, "evt-future");
            assert_eq!(skew_seconds, MAX_CLOCK_SKEW_SECONDS + 1);
        }
        other => panic!("expected ClockSkewRejected, got {other:?}"),
    }

    // Reject BEFORE any mutation — state stays clean.
    assert!(state.buffers().is_empty());
    assert!(state.per_mandate_counters().is_empty());
}

#[test]
fn ingest_accepts_event_at_exact_skew_boundary() {
    // timestamp = current_time + MAX_CLOCK_SKEW_SECONDS is the
    // boundary.  Must ACCEPT — rejection fires only for `> cap`.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let now = FIXTURE_STORM_START_UNIX;
    let mut state = DetectorState::new(library, now);

    let on_edge = CanonicalizedEvent::new_for_testing(
        "evt-edge",
        now + MAX_CLOCK_SKEW_SECONDS,
        "m-storm",
        2,
        "kubernetes",
        "delete",
        "pod",
        "ns/app/pod-edge",
        Outcome::Executed,
    );
    state.ingest_event(on_edge).expect("edge ingest accepted");
    assert_eq!(state.per_mandate_counters().get("m-storm"), Some(&1));
}

#[test]
fn ingest_accepts_past_dated_event_without_skew_check() {
    // Past-dated events ARE accepted — the cap only bounds positive
    // skew (deferred-fire attack surface).  Sliding-window eviction
    // in Session 5-B naturally ages out stale past events.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    let now = FIXTURE_STORM_START_UNIX + 1_000;
    let mut state = DetectorState::new(library, now);

    let past = CanonicalizedEvent::new_for_testing(
        "evt-past",
        FIXTURE_STORM_START_UNIX, // 1000s earlier
        "m-storm",
        2,
        "kubernetes",
        "delete",
        "pod",
        "ns/app/pod-past",
        Outcome::Executed,
    );
    state.ingest_event(past).expect("past-dated ingest accepted");
    assert_eq!(state.per_mandate_counters().get("m-storm"), Some(&1));
}

// -------------------------------------------------------------------
// Clock monotonicity
// -------------------------------------------------------------------

#[test]
fn advance_clock_rejects_regression_without_mutating_state() {
    let library = fixture_detector_library(vec![]);
    let mut state = DetectorState::new(library, FIXTURE_STORM_START_UNIX + 100);

    let err = state
        .advance_clock(FIXTURE_STORM_START_UNIX + 50)
        .unwrap_err();
    match err {
        StreamError::ClockRegression { from, to } => {
            assert_eq!(from, FIXTURE_STORM_START_UNIX + 100);
            assert_eq!(to, FIXTURE_STORM_START_UNIX + 50);
        }
        other => panic!("expected ClockRegression, got {other:?}"),
    }

    // Reject BEFORE mutation — clock pointer unchanged.
    assert_eq!(state.current_time(), FIXTURE_STORM_START_UNIX + 100);
}

#[test]
fn advance_clock_accepts_monotonic_forward_step() {
    let library = fixture_detector_library(vec![]);
    let mut state = DetectorState::new(library, FIXTURE_STORM_START_UNIX);

    state
        .advance_clock(FIXTURE_STORM_START_UNIX + 30)
        .expect("forward step");
    assert_eq!(state.current_time(), FIXTURE_STORM_START_UNIX + 30);

    state
        .advance_clock(FIXTURE_STORM_START_UNIX + 60)
        .expect("second forward step");
    assert_eq!(state.current_time(), FIXTURE_STORM_START_UNIX + 60);
}

#[test]
fn advance_clock_accepts_same_timestamp_idempotent_tick() {
    // `new_time == current_time` is NOT a regression — the monotonic
    // rule is "must not decrease", and an idempotent tick is
    // common when the audit pipeline batches events with the same
    // wall-clock second.
    let library = fixture_detector_library(vec![]);
    let mut state = DetectorState::new(library, FIXTURE_STORM_START_UNIX);
    state
        .advance_clock(FIXTURE_STORM_START_UNIX)
        .expect("same-timestamp tick accepted");
    assert_eq!(state.current_time(), FIXTURE_STORM_START_UNIX);
}

// -------------------------------------------------------------------
// Per-mandate quota
// -------------------------------------------------------------------

#[test]
fn per_mandate_cap_rejects_event_at_quota() {
    // Fill the counter to the cap via the internal accessor —
    // the test harness seeds past-dated events to avoid the
    // skew gate, then the cap+1st event MUST reject with the
    // dedicated variant.
    let library = fixture_detector_library(vec![]);
    let now = FIXTURE_STORM_START_UNIX + 100_000; // well past event timestamps
    let mut state = DetectorState::new(library, now);

    // Shortcut: push MAX_EVENTS_PER_MANDATE events at the same
    // past-dated timestamp (skew gate only bounds positive skew,
    // so this is accepted).  We keep the event_id unique per
    // ingest so the counter grows cleanly.
    for i in 0..MAX_EVENTS_PER_MANDATE {
        let event = CanonicalizedEvent::new_for_testing(
            format!("evt-{i}"),
            FIXTURE_STORM_START_UNIX,
            "m-flood",
            2,
            "kubernetes",
            "get",
            "pod",
            "ns/flood",
            Outcome::Executed,
        );
        state.ingest_event(event).expect("under-cap ingest");
    }
    assert_eq!(
        state.per_mandate_counters().get("m-flood"),
        Some(&MAX_EVENTS_PER_MANDATE)
    );

    // Cap + 1 rejects.
    let over = CanonicalizedEvent::new_for_testing(
        "evt-over",
        FIXTURE_STORM_START_UNIX,
        "m-flood",
        2,
        "kubernetes",
        "get",
        "pod",
        "ns/flood",
        Outcome::Executed,
    );
    match state.ingest_event(over).unwrap_err() {
        StreamError::PerMandateCapReached { mandate_id, cap } => {
            assert_eq!(mandate_id, "m-flood");
            assert_eq!(cap, MAX_EVENTS_PER_MANDATE);
        }
        other => panic!("expected PerMandateCapReached, got {other:?}"),
    }

    // Counter did NOT advance past the cap.
    assert_eq!(
        state.per_mandate_counters().get("m-flood"),
        Some(&MAX_EVENTS_PER_MANDATE)
    );
}

#[test]
fn per_mandate_cap_is_scoped_per_mandate_id() {
    // One mandate at the cap MUST NOT block a different mandate's
    // ingestion — the quota is a per-tenant fairness bound, not a
    // global ceiling.  This pins the keying on `mandate_id`.
    let library = fixture_detector_library(vec![]);
    let now = FIXTURE_STORM_START_UNIX + 100_000;
    let mut state = DetectorState::new(library, now);

    // Fill m-flood to the cap.
    for i in 0..MAX_EVENTS_PER_MANDATE {
        let event = CanonicalizedEvent::new_for_testing(
            format!("flood-{i}"),
            FIXTURE_STORM_START_UNIX,
            "m-flood",
            2,
            "kubernetes",
            "get",
            "pod",
            "ns/flood",
            Outcome::Executed,
        );
        state.ingest_event(event).expect("fill flood");
    }

    // Separate mandate still ingests.
    let fresh = CanonicalizedEvent::new_for_testing(
        "other-1",
        FIXTURE_STORM_START_UNIX,
        "m-other",
        2,
        "kubernetes",
        "get",
        "pod",
        "ns/other",
        Outcome::Executed,
    );
    state
        .ingest_event(fresh)
        .expect("unrelated mandate still accepts");
    assert_eq!(state.per_mandate_counters().get("m-other"), Some(&1));
}

// -------------------------------------------------------------------
// Per-buffer ring eviction
// -------------------------------------------------------------------

#[test]
fn per_buffer_cap_evicts_oldest_event_silently() {
    // Pushing MAX_EVENTS_PER_BUFFER+1 events into a single bucket
    // MUST silently evict the oldest.  Silent because firing
    // thresholds (5-30 per window) are orders of magnitude below the
    // cap; anything that hits the cap is already in a regime the
    // firing rule either caught long ago or never will.
    let library = fixture_detector_library(vec![delete_storm_pattern()]);
    // Clock at a far-future anchor so every event (same timestamp)
    // falls within the skew window.
    let now = FIXTURE_STORM_START_UNIX + 100_000;
    let mut state = DetectorState::new(library, now);

    for i in 0..=MAX_EVENTS_PER_BUFFER {
        let event = CanonicalizedEvent::new_for_testing(
            format!("evt-{i}"),
            FIXTURE_STORM_START_UNIX,
            "m-ring",
            2,
            "kubernetes",
            "delete",
            "pod",
            format!("ns/ring/pod-{i}"),
            Outcome::Executed,
        );
        state.ingest_event(event).expect("ring ingest");
    }

    assert_eq!(state.buffers().len(), 1);
    let (_, buffer) = state.buffers().iter().next().unwrap();
    // Bucket length saturates at the cap.
    assert_eq!(buffer.events().len(), MAX_EVENTS_PER_BUFFER);
    // Oldest event (evt-0) evicted; newest (evt-1000) retained.
    assert_eq!(buffer.events().front().unwrap().event_id, "evt-1");
    assert_eq!(
        buffer.events().back().unwrap().event_id,
        format!("evt-{MAX_EVENTS_PER_BUFFER}")
    );
    // Mandate counter counts EVERY ingestion (including evictions).
    let expected_counter = MAX_EVENTS_PER_BUFFER as u64 + 1;
    assert_eq!(
        state.per_mandate_counters().get("m-ring"),
        Some(&expected_counter)
    );
}

// -------------------------------------------------------------------
// Send + Sync surface
// -------------------------------------------------------------------

#[test]
fn detector_state_is_thread_shareable() {
    // Integration-side pin of the Send+Sync invariant — a regression
    // that wired a !Sync field (e.g. Rc<_>, RefCell<_>) into
    // DetectorState would surface here rather than only at the
    // point-of-use in the audit pipeline.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DetectorState>();
}
