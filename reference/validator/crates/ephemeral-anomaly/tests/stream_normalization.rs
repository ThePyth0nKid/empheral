//! End-to-end integration tests for [`AuditStreamInput::normalize`].
//!
//! Session 5-A deliverable (plan §18).  Each test here is built
//! against the crate's *public* API surface — the compilation of
//! this file is an implicit pin that
//! `AuditStreamInput`/`CanonicalizedEvent`/`PatternDescription`/
//! `Outcome`/`MAX_EXPANDED_EVENTS`/`StreamError` all remain `pub
//! use`-reachable from downstream consumers (the audit pipeline,
//! the classifier-side replay harness, and future Session 5-B
//! evaluators).
//!
//! # Layered protection
//!
//! 1. Inline `src/event.rs` unit tests pin the normaliser's internal
//!    logic.
//! 2. This file pins the fixture-level observable shape, the
//!    byte-determinism of `serde_json` encoding, and a SHA-256
//!    tripwire over the serialised expansion.  A regression in the
//!    CBOR encoder, the RFC-3339 parse path, the `event_id` format,
//!    or the fixture constants surfaces here as a hex-digest diff.
//! 3. The `test_fixtures` self-tests pin the fixture's shape — this
//!    file pins the normaliser's *output* on that fixture.
//!
//! The layering means the digest fires on the right layer: a
//! normaliser bug shows up here; a fixture-shape bug shows up in
//! `src/test_fixtures.rs`'s `self_test`; a fixture-signing-determinism
//! bug shows up in `tests/minimum_library.rs`.

#![allow(clippy::unreadable_literal)]

use ephemeral_anomaly::test_fixtures::{
    fixture_canary_stream, fixture_delete_storm_stream, FIXTURE_STORM_START_UNIX,
};
use ephemeral_anomaly::{
    AuditStreamInput, CanonicalizedEvent, Outcome, PatternDescription, StreamError, TemplateEvent,
    MAX_EXPANDED_EVENTS,
};
use sha2::{Digest, Sha256};

// -------------------------------------------------------------------
// Determinism tripwire
// -------------------------------------------------------------------

/// SHA-256 over the JSON-encoded expansion of
/// [`fixture_delete_storm_stream`].
///
/// Pinned via the first-commit self-observation — see the
/// `delete_storm_fixture_expansion_matches_sha256_tripwire` test.
/// Any bit-flip in the `event_id` format, timestamp-arithmetic
/// accumulator, field order, Unix-seconds projection of
/// `FIXTURE_STORM_START_TIME`, or the serde representation of
/// `Outcome`/`CanonicalizedEvent` surfaces here as a hex-digest
/// diff.
///
/// # How to update
///
/// If a legitimate fixture change requires new bytes:
/// 1. Run the failing test once with `cargo test` and observe the
///    printed digest on assertion failure (the test panics with a
///    message containing both expected and observed hex).
/// 2. Copy the observed digest into this const.
/// 3. Run the test again; it MUST pass.  If it still fails, the
///    change is not deterministic — investigate before pinning.
const DELETE_STORM_EXPANSION_SHA256: &str =
    "cecf4b2431760039ec790b1e297ae34ea24685cfcda292885a86b6ca604665a3";

// -------------------------------------------------------------------
// Happy paths
// -------------------------------------------------------------------

#[test]
fn delete_storm_fixture_normalises_to_ten_six_second_spaced_events() {
    let events = fixture_delete_storm_stream()
        .normalize()
        .expect("storm fixture MUST normalise");
    assert_eq!(events.len(), 10);
    for (i, e) in events.iter().enumerate() {
        let i_signed = i64::try_from(i).expect("enumerate index fits i64");
        assert_eq!(e.timestamp, FIXTURE_STORM_START_UNIX + i_signed * 6);
        assert_eq!(e.mandate_id, "m-storm");
        assert_eq!(e.verb, "delete");
        assert_eq!(e.resource_kind, "pod");
        assert_eq!(e.resource_ref, format!("ns/storm/pod-{i}"));
        assert_eq!(e.outcome, Outcome::Executed);
    }
}

#[test]
fn canary_fixture_literal_passthrough_preserves_order() {
    let events = fixture_canary_stream()
        .normalize()
        .expect("canary fixture MUST normalise");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_id, "canary-1");
    assert_eq!(events[1].event_id, "canary-2");
    assert_eq!(events[2].event_id, "canary-3");
    for e in &events {
        assert_eq!(e.tier, 3);
        assert_eq!(e.integration, "canary-signers");
    }
}

// -------------------------------------------------------------------
// Determinism
// -------------------------------------------------------------------

#[test]
fn normalize_is_deterministic_across_calls() {
    // Two independent normalisations MUST produce byte-identical
    // canonicalised-event vectors.  Any source of nondeterminism
    // (iterator reordering, wall-clock leak, random event_id) would
    // surface here.
    let a = fixture_delete_storm_stream().normalize().unwrap();
    let b = fixture_delete_storm_stream().normalize().unwrap();
    assert_eq!(a, b);

    let c = fixture_canary_stream().normalize().unwrap();
    let d = fixture_canary_stream().normalize().unwrap();
    assert_eq!(c, d);
}

#[test]
fn delete_storm_fixture_expansion_matches_sha256_tripwire() {
    let events = fixture_delete_storm_stream().normalize().unwrap();
    let encoded = serde_json::to_vec(&events).expect("serde_json encode of CanonicalizedEvent");
    let digest = Sha256::digest(&encoded);
    let observed_hex = hex::encode(digest);

    assert_eq!(
        observed_hex, DELETE_STORM_EXPANSION_SHA256,
        "SHA-256 tripwire fired on fixture_delete_storm_stream() expansion.\n\
         Observed digest: {observed_hex}\n\
         Expected digest: {DELETE_STORM_EXPANSION_SHA256}\n\
         If this change is intentional, update DELETE_STORM_EXPANSION_SHA256 to the observed value.\n\
         If not, investigate the normaliser, fixture constants, or event_id format."
    );
}

// -------------------------------------------------------------------
// Reject paths
// -------------------------------------------------------------------

#[test]
fn pattern_description_count_zero_rejects_with_dedicated_variant() {
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        0,
        1,
        canary_template(),
        "ns/x/{i}",
    ));
    let err = stream.normalize().unwrap_err();
    assert!(
        matches!(err, StreamError::PatternDescriptionCountZero),
        "expected PatternDescriptionCountZero, got {err:?}"
    );
}

#[test]
fn pattern_description_zero_interval_multi_count_rejects() {
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        3,
        0,
        canary_template(),
        "ns/x/{i}",
    ));
    let err = stream.normalize().unwrap_err();
    assert!(
        matches!(err, StreamError::ZeroIntervalWithMultipleEvents),
        "expected ZeroIntervalWithMultipleEvents, got {err:?}"
    );
}

#[test]
fn pattern_description_count_one_allows_zero_interval() {
    // A single-event expansion MUST succeed with interval=0 (the
    // value is irrelevant because no cadence is computed).  This
    // pins that the zero-interval check is gated on count > 1.
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        1,
        0,
        canary_template(),
        "ns/single", // no {i} needed for count=1
    ));
    let events = stream.normalize().expect("count=1 MUST succeed");
    assert_eq!(events.len(), 1);
}

#[test]
fn pattern_description_missing_placeholder_rejects_on_multi_count() {
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        5,
        1,
        canary_template(),
        "ns/no-placeholder", // missing {i}
    ));
    let err = stream.normalize().unwrap_err();
    assert!(
        matches!(err, StreamError::PatternMissingIndexPlaceholder),
        "expected PatternMissingIndexPlaceholder, got {err:?}"
    );
}

#[test]
fn pattern_description_expansion_cap_rejects_with_numeric_bounds() {
    // Request more events than the cap allows (count × max(interval,
    // 1) > MAX_EXPANDED_EVENTS).  Use interval=1, count=cap+1 so the
    // arithmetic is transparent.
    let over = MAX_EXPANDED_EVENTS + 1;
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        over,
        1,
        canary_template(),
        "ns/x-{i}",
    ));
    let err = stream.normalize().unwrap_err();
    match err {
        StreamError::ExpansionExceeded { requested, cap } => {
            assert_eq!(requested, over);
            assert_eq!(cap, MAX_EXPANDED_EVENTS);
        }
        other => panic!("expected ExpansionExceeded, got {other:?}"),
    }
}

#[test]
fn pattern_description_invalid_timestamp_surfaces_static_reason() {
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "not-a-date",
        "2026-01-01T00:00:00Z",
        1,
        0,
        canary_template(),
        "ns/x",
    ));
    let err = stream.normalize().unwrap_err();
    match err {
        StreamError::TimestampParseFailed { reason } => {
            // reason is &'static str by contract — pin that the
            // CLASS name surfaces (not the attacker-controlled
            // bytes).
            assert!(reason.contains("RFC-3339"));
        }
        other => panic!("expected TimestampParseFailed, got {other:?}"),
    }
}

#[test]
fn pattern_description_date_only_without_time_rejects() {
    // RFC-3339 requires a full time component.  Date-only "2026-01-01"
    // is NOT a valid RFC-3339 timestamp and MUST reject rather than
    // silently be interpreted as 00:00:00Z.
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-01-01",
        "2026-01-01T00:00:00Z",
        1,
        0,
        canary_template(),
        "ns/x",
    ));
    let err = stream.normalize().unwrap_err();
    assert!(matches!(err, StreamError::TimestampParseFailed { .. }));
}

#[test]
fn pattern_description_empty_start_time_rejects() {
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "",
        "2026-01-01T00:00:00Z",
        1,
        0,
        canary_template(),
        "ns/x",
    ));
    let err = stream.normalize().unwrap_err();
    assert!(matches!(err, StreamError::TimestampParseFailed { .. }));
}

// -------------------------------------------------------------------
// RFC-3339 boundary cases
// -------------------------------------------------------------------

#[test]
fn pattern_description_accepts_z_suffix_utc() {
    // The Z suffix is the canonical UTC form for RFC-3339 and is the
    // shape every fixture uses.  Pin that it parses correctly.
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-05-01T12:00:00Z",
        "2026-05-01T12:00:00Z",
        1,
        0,
        canary_template(),
        "ns/x",
    ));
    let events = stream.normalize().unwrap();
    assert_eq!(events[0].timestamp, FIXTURE_STORM_START_UNIX);
}

#[test]
fn pattern_description_accepts_explicit_offset_suffix() {
    // +00:00 is semantically identical to Z.  RFC-3339 accepts both;
    // so must the normaliser.
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-05-01T12:00:00+00:00",
        "2026-05-01T12:00:00+00:00",
        1,
        0,
        canary_template(),
        "ns/x",
    ));
    let events = stream.normalize().unwrap();
    assert_eq!(events[0].timestamp, FIXTURE_STORM_START_UNIX);
}

// -------------------------------------------------------------------
// Expansion cap boundary
// -------------------------------------------------------------------

#[test]
fn pattern_description_expansion_at_exact_cap_succeeds_when_interval_is_one() {
    // Small-count proxy for the cap boundary — the direct
    // cap-boundary is covered by the inline
    // `pattern_description_accepts_expansion_at_the_cap` test in
    // src/event.rs.  This integration-side pin confirms the cap
    // check does not fire for legitimate small expansions.
    let stream = AuditStreamInput::PatternDescription(PatternDescription::new_for_testing(
        "2026-05-01T12:00:00Z",
        "2026-05-01T12:00:03Z",
        3,
        1,
        canary_template(),
        "ns/x-{i}",
    ));
    let events = stream.normalize().unwrap();
    assert_eq!(events.len(), 3);
}

// -------------------------------------------------------------------
// Expansion properties across variants
// -------------------------------------------------------------------

#[test]
fn pattern_description_event_ids_are_distinct_within_expansion() {
    let events = fixture_delete_storm_stream().normalize().unwrap();
    let mut ids: Vec<_> = events.iter().map(|e| &e.event_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), events.len());
}

#[test]
fn literal_stream_events_roundtrip_through_json() {
    // A secondary determinism pin: the same expansion output MUST
    // serialise and deserialise through JSON without losing any
    // fields.  If a future refactor renames a CanonicalizedEvent
    // field, this surfaces both here AND in the digest tripwire —
    // two independent failure points for the same class of bug.
    let events = fixture_canary_stream().normalize().unwrap();
    let encoded = serde_json::to_string(&events).unwrap();
    let decoded: Vec<CanonicalizedEvent> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(events, decoded);
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

fn canary_template() -> TemplateEvent {
    TemplateEvent::new_for_testing("m-test", 1, "kubernetes", "get", "pod", Outcome::Executed)
}
