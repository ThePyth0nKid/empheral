//! Canonicalised audit-event representation + stream-normalisation.
//!
//! Session 5-A's foundation DTO.  The state machine in
//! [`crate::state`] ingests only [`CanonicalizedEvent`] values;
//! every external input shape first passes through
//! [`AuditStreamInput::normalize`] so the runtime never has to
//! branch on wire-shape inside the hot path.
//!
//! # Two wire shapes
//!
//! Production-style streams carry events literally via
//! [`AuditStreamInput::Literal`].  Conformance vectors and synthetic
//! test fixtures may emit a [`PatternDescription`] instead —
//! `conformance/audit-replay.json` uses this to express a 20-event
//! delete-storm as a handful of bytes (template + count + interval).
//! Both shapes flow through the SAME downstream code; the only
//! normalisation contract is that
//! `AuditStreamInput::normalize` returns a
//! `Vec<CanonicalizedEvent>` with timestamps already resolved from
//! RFC-3339 to `unix_seconds: i64`.
//!
//! # Canonicalisation scope for Session 5-A (plan §6)
//!
//! Session 5-A assumes upstream (the audit-service signer) has
//! already applied R7.C1 case-folding, R7.C3 NFC, and R7.C8
//! invisible-scrub to `verb`, `resource_kind`, and `resource_ref`.
//! The Session-5-A detector treats those fields byte-exactly — if
//! an event arrives mixed-case the scope predicate will simply miss
//! it, which is the correct failure mode for a producer violating
//! canonicalisation.
//!
//! The `RawEvent → CanonicalizedEvent` lifting stage is deferred
//! to Session 6+ when a non-test consumer exists.  For now, both
//! the production audit-service and the test harness emit
//! already-canonical events.
//!
//! # Memory bounds (plan §3.4)
//!
//! [`MAX_EXPANDED_EVENTS`] caps the number of events a single
//! `PatternDescription` may expand into.  The cap is enforced as
//! `count × max(interval_seconds, 1) <= MAX_EXPANDED_EVENTS`,
//! which bounds both the memory footprint and the time span — a
//! description spanning 100 000 seconds (~27 h) or producing
//! 100 000 events is already past any realistic conformance
//! replay.  Streams that exceed the cap reject at normalisation
//! time via [`StreamError::ExpansionExceeded`]; the state machine
//! never sees them.

use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[cfg(any(test, feature = "test_fixtures"))]
use serde::Serialize;

use crate::errors::StreamError;

/// Maximum number of events a single
/// [`PatternDescription::expand`] call may allocate.
///
/// Enforced as `count × max(interval_seconds, 1) <=
/// MAX_EXPANDED_EVENTS` — see the module-doc for the reasoning.
/// A pattern-description that would exceed this bound rejects with
/// [`StreamError::ExpansionExceeded`].
///
/// `u64` width is load-bearing: adversarial pattern-descriptions can
/// craft `count: u32::MAX` paired with large `interval_seconds`,
/// pushing the product past `u32::MAX`.  The runtime rejects in that
/// regime rather than wrapping.
pub const MAX_EXPANDED_EVENTS: u64 = 100_000;

/// Static-`&str` classifier for RFC-3339 parse failures.
///
/// The `reason` field of [`StreamError::TimestampParseFailed`] is
/// `&'static str` by design: it names the FAILURE CLASS without
/// echoing the attacker-controlled bytes.  A single classifier
/// string is sufficient operationally — the signer's fix is
/// "produce a well-formed RFC-3339 timestamp" regardless of which
/// sub-field was malformed.
const RFC3339_PARSE_REASON: &str =
    "not a valid RFC-3339 timestamp (expected YYYY-MM-DDTHH:MM:SS[.ffff]Z or with offset)";

/// Execution outcome of a single audit event.
///
/// Matches the `outcome` field of `conformance/audit-replay.json`
/// events (`executed` | `rejected` | `queued`) byte-exactly via
/// `serde(rename_all = "snake_case")`.
///
/// `#[non_exhaustive]` so a future spec revision can introduce new
/// outcome categories (e.g. `throttled`) without breaking
/// downstream exhaustive matches.  `Copy` because the whole value
/// is a single-byte discriminant — no allocation.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Outcome {
    /// Router accepted the mandate-bound action and dispatched it.
    Executed,
    /// Router rejected the mandate-bound action (e.g. on-tariff
    /// rate cap, classifier escalation).
    Rejected,
    /// Router queued the action behind a pending operator
    /// approval.  Present in the audit-replay corpus for
    /// `pattern-iam-attach-policy-storm` vectors.
    Queued,
}

/// A single audit event in its canonical post-normalisation shape.
///
/// Fields mirror the `conformance/audit-replay.json` event record
/// one-for-one; names are held stable across Sessions 5-A/B so the
/// vector suite, the state machine, and the fire-decision layer
/// share one DTO.
///
/// # Log-safety for `event_id`
///
/// `event_id` is attacker-controlled: the audit-service forwards
/// whatever identifier the Router embedded into the pre-
/// countersigned batch.  Every log-display site that renders
/// `event_id` MUST pass it through
/// [`crate::errors::sanitize_log_string`] first; the struct
/// itself stores the raw bytes.  The only built-in log surface is
/// [`StreamError::ClockSkewRejected`]'s `event_id` field, which
/// the construction helper already sanitises.
///
/// # Clone semantics (plan §15.4)
///
/// `Clone` is load-bearing: one event may fan out to multiple
/// [`crate::state::PatternBuffer`] entries when several patterns'
/// scopes match simultaneously.  `Copy` is impossible because of
/// the `String` fields.  A future V2 profile can swap the struct
/// into `Arc<CanonicalizedEvent>` fanout without disturbing the
/// public shape.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct CanonicalizedEvent {
    /// Stable event identifier.  Attacker-controlled — sanitise on
    /// log rendering (never at storage time — §4.2.2 preserves the
    /// byte-exact id for audit correlation).
    pub event_id: String,
    /// Unix epoch seconds.  Already resolved from RFC-3339 at
    /// normalisation time; the state machine never re-parses.
    pub timestamp: i64,
    /// Mandate id this event is attributed to.  Scope-bucket key.
    pub mandate_id: String,
    /// §2.1 impact tier (0 = low-blast, 4 = extreme-blast).
    pub tier: u8,
    /// §10.2 per-integration isolation namespace
    /// (e.g. `"kubernetes"`, `"aws-iam"`).
    pub integration: String,
    /// R7.C1 case-folded verb (e.g. `"delete"`).
    pub verb: String,
    /// R7.C1 case-folded resource kind (e.g. `"pod"`).
    pub resource_kind: String,
    /// Byte-preserved resource reference
    /// (e.g. `"ns/app/pod-7"`).
    pub resource_ref: String,
    /// Execution outcome.
    pub outcome: Outcome,
}

/// Template fields shared by every event produced from a single
/// [`PatternDescription`] expansion.
///
/// Matches the `template_event` sub-object of
/// `audit-replay.json` vectors — 6 fields that stay constant
/// across the expansion (the `event_id`, `timestamp`, and
/// `resource_ref` fields are filled in per-index by
/// [`PatternDescription::expand`]).
///
/// NOT `#[non_exhaustive]` because every field is required and
/// adding a new one would change the wire shape (the audit-
/// service signer side would need to be updated in lockstep).
/// A future addition would bump the pattern-description wire
/// version out-of-band.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TemplateEvent {
    /// Mandate binding for every expanded event.
    pub mandate_id: String,
    /// Impact tier applied to every expanded event.
    pub tier: u8,
    /// Integration namespace applied to every expanded event.
    pub integration: String,
    /// Verb applied to every expanded event.
    pub verb: String,
    /// Resource kind applied to every expanded event.
    pub resource_kind: String,
    /// Outcome applied to every expanded event.
    pub outcome: Outcome,
}

/// Condensed description of an audit stream used by the conformance
/// corpus.  Expands via [`PatternDescription::expand`] into a
/// `Vec<CanonicalizedEvent>`.
///
/// Byte-matches the `pattern_description` sub-object of
/// `conformance/audit-replay.json` — six required fields.  The
/// `end_time` field is carried for operator-auditability only; the
/// runtime does NOT cross-check it against `start_time + count *
/// interval` because that would force one canonical
/// interpretation of leap-second handling into the conformance
/// corpus.  Signers that want a cross-check can compute it
/// externally.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct PatternDescription {
    /// RFC-3339 timestamp at which the first event of the
    /// expanded stream fires.  Parsed to `unix_seconds: i64` at
    /// expansion time; malformed values reject via
    /// [`StreamError::TimestampParseFailed`].
    pub start_time: String,
    /// RFC-3339 timestamp at which the last event of the
    /// expanded stream fires.  Reference-only in Session 5-A (see
    /// the struct-doc above).
    pub end_time: String,
    /// Number of events to expand.  MUST be ≥ 1;
    /// [`StreamError::PatternDescriptionCountZero`] rejects the
    /// degenerate `count = 0` case at expansion time.
    pub count: u64,
    /// Seconds between successive events.  With `count > 1` this
    /// MUST be ≥ 1 — [`StreamError::ZeroIntervalWithMultipleEvents`]
    /// rejects the collision regime.  With `count = 1` the field
    /// is unused and MAY be 0.
    pub interval_seconds: u32,
    /// Shared template for every expanded event.
    pub template_event: TemplateEvent,
    /// Printf-style placeholder for the per-event `resource_ref`.
    /// MUST contain the literal substring `{i}` when `count > 1`
    /// so each expanded event gets a distinct resource reference
    /// ([`StreamError::PatternMissingIndexPlaceholder`] otherwise).
    /// `{i}` is substituted with the 0-based event index.
    pub resource_ref_pattern: String,
}

/// Discriminated input shape for [`AuditStreamInput::normalize`].
///
/// Wire form matches `conformance/audit-replay.json`:
/// `{"events": [...]}` for a literal stream, and
/// `{"pattern_description": {...}}` for a condensed stream.
/// `#[serde(rename_all = "snake_case")]` + the variant-tag shape
/// make the Rust enum and the JSON key line up without custom
/// deserialisation.
///
/// # Why a distinct enum, not just `Vec<CanonicalizedEvent>`
///
/// The normalisation call-site needs to distinguish the two
/// shapes to know whether expansion can fail at all (literal
/// streams are memory-bounded by the input, pattern descriptions
/// by [`MAX_EXPANDED_EVENTS`]) and to surface the right error
/// variant.  Hiding the shape behind a helper would force one
/// failure-class enum to cover both, losing operator clarity.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditStreamInput {
    /// Literal events already in canonical form.
    Literal {
        /// Canonicalised audit events in arrival order.
        events: Vec<CanonicalizedEvent>,
    },
    /// Condensed pattern description — one template + count +
    /// interval + start time.  Expanded into canonical events at
    /// normalisation time.
    PatternDescription(PatternDescription),
}

impl AuditStreamInput {
    /// Resolve this input shape into a flat
    /// `Vec<CanonicalizedEvent>`.
    ///
    /// For [`Self::Literal`] this is a byte-identical clone of the
    /// input events.  For [`Self::PatternDescription`] it runs the
    /// expansion pipeline:
    ///
    /// 1. Reject `count == 0`
    ///    ([`StreamError::PatternDescriptionCountZero`]).
    /// 2. Reject `count > 1 && interval_seconds == 0`
    ///    ([`StreamError::ZeroIntervalWithMultipleEvents`]).
    /// 3. Reject `count > 1` without `{i}` placeholder
    ///    ([`StreamError::PatternMissingIndexPlaceholder`]).
    /// 4. Reject expansion ≥ [`MAX_EXPANDED_EVENTS`]
    ///    ([`StreamError::ExpansionExceeded`]).
    /// 5. Parse RFC-3339 `start_time` to `unix_seconds`
    ///    ([`StreamError::TimestampParseFailed`]).
    /// 6. Emit `count` canonical events at
    ///    `start + i * interval`.
    ///
    /// The order of checks is deliberate: cheap structural rejects
    /// fire before allocation or timestamp parsing, so an
    /// adversarial stream that fails at step 4 doesn't spend
    /// resolver cycles on step 5 first.
    ///
    /// # Determinism
    ///
    /// The expansion is pure: same input → same bytes, always.
    /// `tests/stream_normalization.rs` pins this via a SHA-256
    /// tripwire over a reference MINIMUM expansion.
    pub fn normalize(&self) -> Result<Vec<CanonicalizedEvent>, StreamError> {
        match self {
            Self::Literal { events } => Ok(events.clone()),
            Self::PatternDescription(pd) => pd.expand(),
        }
    }
}

#[cfg(any(test, feature = "test_fixtures"))]
impl CanonicalizedEvent {
    /// Test-only constructor for [`CanonicalizedEvent`].
    ///
    /// `#[non_exhaustive]` blocks out-of-crate struct-literal
    /// construction.  Integration tests (and the `test_fixtures`
    /// feature) use this helper to mint events with a known
    /// `(event_id, timestamp, mandate_id, …)` shape.  Production
    /// events arrive via `AuditStreamInput::normalize` — this
    /// constructor must never be reached from prod code paths.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_testing(
        event_id: impl Into<String>,
        timestamp: i64,
        mandate_id: impl Into<String>,
        tier: u8,
        integration: impl Into<String>,
        verb: impl Into<String>,
        resource_kind: impl Into<String>,
        resource_ref: impl Into<String>,
        outcome: Outcome,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            timestamp,
            mandate_id: mandate_id.into(),
            tier,
            integration: integration.into(),
            verb: verb.into(),
            resource_kind: resource_kind.into(),
            resource_ref: resource_ref.into(),
            outcome,
        }
    }
}

#[cfg(any(test, feature = "test_fixtures"))]
impl TemplateEvent {
    /// Test-only constructor for [`TemplateEvent`].
    ///
    /// `#[non_exhaustive]` on [`PatternDescription`] hides its struct
    /// literal from out-of-crate call sites; integration tests that
    /// enable the `test_fixtures` feature use this helper to build a
    /// template without re-deriving the wire schema.  Prod call sites
    /// receive templates only via CBOR deserialisation and have no
    /// need for a literal constructor.
    #[must_use]
    pub fn new_for_testing(
        mandate_id: impl Into<String>,
        tier: u8,
        integration: impl Into<String>,
        verb: impl Into<String>,
        resource_kind: impl Into<String>,
        outcome: Outcome,
    ) -> Self {
        Self {
            mandate_id: mandate_id.into(),
            tier,
            integration: integration.into(),
            verb: verb.into(),
            resource_kind: resource_kind.into(),
            outcome,
        }
    }
}

#[cfg(any(test, feature = "test_fixtures"))]
impl PatternDescription {
    /// Test-only constructor for [`PatternDescription`].
    ///
    /// The struct is `#[non_exhaustive]` so out-of-crate literals are
    /// forbidden; integration tests use this helper to assemble the
    /// six required fields.  Production deserialises from CBOR and
    /// does not need a literal constructor.
    #[must_use]
    pub fn new_for_testing(
        start_time: impl Into<String>,
        end_time: impl Into<String>,
        count: u64,
        interval_seconds: u32,
        template_event: TemplateEvent,
        resource_ref_pattern: impl Into<String>,
    ) -> Self {
        Self {
            start_time: start_time.into(),
            end_time: end_time.into(),
            count,
            interval_seconds,
            template_event,
            resource_ref_pattern: resource_ref_pattern.into(),
        }
    }
}

impl PatternDescription {
    /// Expand the description into `count` canonicalised events.
    ///
    /// See [`AuditStreamInput::normalize`] for the full
    /// reject-then-emit pipeline.  This method is exposed
    /// separately so pattern-description fixtures can invoke
    /// expansion without wrapping the whole enum each time.
    pub fn expand(&self) -> Result<Vec<CanonicalizedEvent>, StreamError> {
        // Step 1 — reject degenerate count = 0 (plan §14.4).
        if self.count == 0 {
            return Err(StreamError::PatternDescriptionCountZero);
        }

        // Step 2 — reject zero-interval collision regime for
        // multi-event streams.  Single-event streams (count = 1)
        // ignore interval_seconds entirely, so a 0 here is valid.
        if self.count > 1 && self.interval_seconds == 0 {
            return Err(StreamError::ZeroIntervalWithMultipleEvents);
        }

        // Step 3 — require `{i}` placeholder when emitting > 1
        // events so each expanded event gets a distinct
        // resource_ref.  A single-event stream allows any pattern
        // (the placeholder is optional in that case).
        if self.count > 1 && !self.resource_ref_pattern.contains("{i}") {
            return Err(StreamError::PatternMissingIndexPlaceholder);
        }

        // Step 4 — memory/time-span cap.  `max(interval, 1)`
        // normalises the count = 1, interval = 0 case so the
        // bound is well-defined.  `checked_mul` catches the
        // adversarial `count: u64::MAX, interval: > 0` overflow
        // before it touches allocation.
        let interval_for_bound = u64::from(self.interval_seconds).max(1);
        let projected =
            self.count
                .checked_mul(interval_for_bound)
                .ok_or(StreamError::ExpansionExceeded {
                    requested: u64::MAX,
                    cap: MAX_EXPANDED_EVENTS,
                })?;
        if projected > MAX_EXPANDED_EVENTS {
            return Err(StreamError::ExpansionExceeded {
                requested: projected,
                cap: MAX_EXPANDED_EVENTS,
            });
        }

        // Step 5 — parse start_time to unix_seconds.  We only
        // parse `start_time` (end_time is reference-only; see
        // the struct-doc).
        let start = parse_rfc3339_seconds(&self.start_time)?;

        // Step 6 — emit canonical events.  The cap at line 445
        // guarantees `self.count <= MAX_EXPANDED_EVENTS` (100_000),
        // which is well below both `usize::MAX` (on every supported
        // target) and `i64::MAX`.  The `try_from` calls are therefore
        // infallible in practice; `expect` surfaces a descriptive
        // panic message if a future refactor ever loosens the cap
        // without revisiting this conversion.
        let count_usize = usize::try_from(self.count)
            .expect("count <= MAX_EXPANDED_EVENTS fits usize on every supported target");
        let mut out = Vec::with_capacity(count_usize);
        let interval = i64::from(self.interval_seconds);
        for i in 0..self.count {
            // Checked arithmetic: even though the cap bounds
            // `i * interval` structurally, defense-in-depth
            // guards against a future refactor that loosens the
            // cap without re-checking the timestamp arithmetic.
            let i_signed = i64::try_from(i)
                .expect("i < count <= MAX_EXPANDED_EVENTS fits i64 unconditionally");
            let offset = i_signed
                .checked_mul(interval)
                .and_then(|p| start.checked_add(p))
                .ok_or(StreamError::ExpansionExceeded {
                    // `projected` passed the cap gate above, so
                    // reaching this branch means timestamp arithmetic
                    // overflowed `i64`, not that the event count
                    // itself exceeded the cap.  Surface `u64::MAX` so
                    // the operator message ("…exceeds cap…") is not
                    // misleading (`requested == cap` would read as
                    // an at-cap count rather than a time-horizon
                    // overflow).
                    requested: u64::MAX,
                    cap: MAX_EXPANDED_EVENTS,
                })?;
            let event_id = format!("pd-{start}-{i}");
            let resource_ref = self.resource_ref_pattern.replace("{i}", &i.to_string());
            out.push(CanonicalizedEvent {
                event_id,
                timestamp: offset,
                mandate_id: self.template_event.mandate_id.clone(),
                tier: self.template_event.tier,
                integration: self.template_event.integration.clone(),
                verb: self.template_event.verb.clone(),
                resource_kind: self.template_event.resource_kind.clone(),
                resource_ref,
                outcome: self.template_event.outcome,
            });
        }
        Ok(out)
    }
}

/// Parse an RFC-3339 timestamp string to unix epoch seconds.
///
/// Used only at the pattern-description expansion boundary
/// (literal events arrive with a pre-parsed `i64 timestamp`
/// already).  Fails with
/// [`StreamError::TimestampParseFailed`] on any malformed
/// input; the `reason` field is a single `&'static str` so the
/// error surface cannot re-echo attacker bytes.
///
/// Thin wrapper over `time::OffsetDateTime::parse` —
/// ephemeral-core's `suites::anomaly_library::parse_iso_seconds`
/// uses the same primitive; the two are intentionally
/// independent copies to avoid introducing a cross-crate
/// edge just for a 3-line function.
fn parse_rfc3339_seconds(s: &str) -> Result<i64, StreamError> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|_| StreamError::TimestampParseFailed {
            reason: RFC3339_PARSE_REASON,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────
    // `Outcome` — wire-form stability.
    // ────────────────────────────────────────────────────────────

    #[test]
    fn outcome_snake_case_matches_conformance_corpus() {
        // Pin the wire form against the exact strings used by
        // `conformance/audit-replay.json`.  A serde refactor that
        // flipped to `kebab-case` would silently break every
        // committed vector; this test fails loudly.
        for (variant, wire) in [
            (Outcome::Executed, "\"executed\""),
            (Outcome::Rejected, "\"rejected\""),
            (Outcome::Queued, "\"queued\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), wire);
            let back: Outcome = serde_json::from_str(wire).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ────────────────────────────────────────────────────────────
    // `CanonicalizedEvent` — wire-form roundtrip.
    // ────────────────────────────────────────────────────────────

    fn example_event() -> CanonicalizedEvent {
        CanonicalizedEvent {
            event_id: "evt-001".into(),
            timestamp: 1_777_636_800, // 2026-05-01T12:00:00Z
            mandate_id: "m-42".into(),
            tier: 1,
            integration: "kubernetes".into(),
            verb: "delete".into(),
            resource_kind: "pod".into(),
            resource_ref: "ns/app/pod-0".into(),
            outcome: Outcome::Executed,
        }
    }

    #[test]
    fn canonicalized_event_roundtrips_through_json() {
        let ev = example_event();
        let encoded = serde_json::to_string(&ev).unwrap();
        let back: CanonicalizedEvent = serde_json::from_str(&encoded).unwrap();
        assert_eq!(ev, back);
    }

    // ────────────────────────────────────────────────────────────
    // `AuditStreamInput::Literal` — normalise is a passthrough.
    // ────────────────────────────────────────────────────────────

    #[test]
    fn literal_input_normalises_to_identical_events() {
        let events = vec![example_event()];
        let input = AuditStreamInput::Literal {
            events: events.clone(),
        };
        assert_eq!(input.normalize().unwrap(), events);
    }

    #[test]
    fn literal_input_preserves_event_order() {
        let mut events = Vec::new();
        for i in 0..5 {
            let mut ev = example_event();
            ev.event_id = format!("evt-{i}");
            ev.timestamp += i64::from(i);
            events.push(ev);
        }
        let input = AuditStreamInput::Literal {
            events: events.clone(),
        };
        let out = input.normalize().unwrap();
        // Byte-exact including order.  A reshuffle would defeat
        // sequence-match patterns (`cross-tier-escalation`).
        assert_eq!(out, events);
    }

    // ────────────────────────────────────────────────────────────
    // `PatternDescription` — reject paths.
    // ────────────────────────────────────────────────────────────

    fn minimal_pd(count: u64, interval: u32, pattern: &str) -> PatternDescription {
        PatternDescription {
            start_time: "2026-05-01T12:00:00Z".into(),
            end_time: "2026-05-01T12:00:57Z".into(),
            count,
            interval_seconds: interval,
            template_event: TemplateEvent {
                mandate_id: "m-42".into(),
                tier: 1,
                integration: "kubernetes".into(),
                verb: "delete".into(),
                resource_kind: "pod".into(),
                outcome: Outcome::Executed,
            },
            resource_ref_pattern: pattern.into(),
        }
    }

    #[test]
    fn pattern_description_rejects_count_zero() {
        let pd = minimal_pd(0, 3, "ns/app/pod-{i}");
        assert_eq!(
            pd.expand().unwrap_err(),
            StreamError::PatternDescriptionCountZero,
        );
    }

    #[test]
    fn pattern_description_rejects_multi_event_with_zero_interval() {
        let pd = minimal_pd(2, 0, "ns/app/pod-{i}");
        assert_eq!(
            pd.expand().unwrap_err(),
            StreamError::ZeroIntervalWithMultipleEvents,
        );
    }

    #[test]
    fn pattern_description_accepts_single_event_with_zero_interval() {
        // count=1 is a legal single-event stream regardless of
        // interval; the zero-interval reject only applies when
        // multiple events would collide onto the same timestamp.
        let pd = minimal_pd(1, 0, "ns/app/pod");
        let out = pd.expand().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].timestamp, 1_777_636_800);
    }

    #[test]
    fn pattern_description_rejects_multi_event_without_placeholder() {
        let pd = minimal_pd(5, 3, "ns/app/pod-no-placeholder");
        assert_eq!(
            pd.expand().unwrap_err(),
            StreamError::PatternMissingIndexPlaceholder,
        );
    }

    #[test]
    fn pattern_description_accepts_single_event_without_placeholder() {
        let pd = minimal_pd(1, 0, "ns/app/pod");
        let out = pd.expand().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].resource_ref, "ns/app/pod");
    }

    #[test]
    fn pattern_description_rejects_expansion_over_cap() {
        // `count × max(interval, 1) = MAX_EXPANDED_EVENTS + 1` →
        // rejects at the cap check, not at the timestamp parse.
        let pd = minimal_pd(MAX_EXPANDED_EVENTS + 1, 1, "ns/app/pod-{i}");
        match pd.expand().unwrap_err() {
            StreamError::ExpansionExceeded { requested, cap } => {
                assert!(requested > cap);
                assert_eq!(cap, MAX_EXPANDED_EVENTS);
            }
            other => panic!("expected ExpansionExceeded, got {other:?}"),
        }
    }

    #[test]
    fn pattern_description_rejects_count_interval_overflow() {
        // `count = u64::MAX, interval = 2` → checked_mul overflow
        // → ExpansionExceeded (not a silent wrap).
        let pd = minimal_pd(u64::MAX, 2, "ns/app/pod-{i}");
        match pd.expand().unwrap_err() {
            StreamError::ExpansionExceeded { cap, .. } => {
                assert_eq!(cap, MAX_EXPANDED_EVENTS);
            }
            other => panic!("expected ExpansionExceeded on overflow, got {other:?}"),
        }
    }

    #[test]
    fn pattern_description_rejects_malformed_timestamp() {
        let mut pd = minimal_pd(1, 0, "ns/app/pod");
        pd.start_time = "not-a-timestamp".into();
        match pd.expand().unwrap_err() {
            StreamError::TimestampParseFailed { reason } => {
                // `reason` is a `&'static str` — we can compare by
                // pointer identity via the constant.  This pins
                // that the classifier string does not leak the
                // attacker input.
                assert_eq!(reason, RFC3339_PARSE_REASON);
            }
            other => panic!("expected TimestampParseFailed, got {other:?}"),
        }
    }

    // ────────────────────────────────────────────────────────────
    // `PatternDescription` — happy path + determinism.
    // ────────────────────────────────────────────────────────────

    #[test]
    fn pattern_description_expands_with_correct_cardinality_and_offsets() {
        // Matches the shape of `arep-001` from audit-replay.json:
        // 20 events, 3s cadence, starting 2026-05-01T12:00:00Z.
        let pd = minimal_pd(20, 3, "ns/app/pod-{i}");
        let out = pd.expand().unwrap();
        assert_eq!(out.len(), 20);
        assert_eq!(out[0].timestamp, 1_777_636_800);
        assert_eq!(out[19].timestamp, 1_777_636_800 + 19 * 3);
        assert_eq!(out[0].resource_ref, "ns/app/pod-0");
        assert_eq!(out[19].resource_ref, "ns/app/pod-19");
        for event in &out {
            assert_eq!(event.mandate_id, "m-42");
            assert_eq!(event.verb, "delete");
            assert_eq!(event.resource_kind, "pod");
            assert_eq!(event.outcome, Outcome::Executed);
        }
    }

    #[test]
    fn pattern_description_expansion_is_deterministic() {
        // Same description → same bytes.  Integration-test tier
        // pins a SHA-256 hash over the full expansion; here we
        // confirm the simpler invariant that two expansions of
        // the same pd structurally equal.
        let pd = minimal_pd(50, 1, "ns/app/pod-{i}");
        let first = pd.expand().unwrap();
        let second = pd.expand().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn pattern_description_event_ids_are_distinct_within_expansion() {
        let pd = minimal_pd(100, 1, "ns/app/pod-{i}");
        let out = pd.expand().unwrap();
        let mut ids: Vec<&str> = out.iter().map(|e| e.event_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            100,
            "event_ids MUST be distinct within one expansion"
        );
    }

    #[test]
    fn pattern_description_accepts_expansion_at_the_cap() {
        // Boundary: `count × max(interval, 1) = MAX_EXPANDED_EVENTS`
        // → accepted.  Pins the '<=' semantics (not '<').
        let pd = minimal_pd(MAX_EXPANDED_EVENTS, 1, "ns/app/pod-{i}");
        let out = pd.expand().unwrap();
        assert_eq!(out.len() as u64, MAX_EXPANDED_EVENTS);
    }

    // ────────────────────────────────────────────────────────────
    // `parse_rfc3339_seconds` — format coverage.
    // ────────────────────────────────────────────────────────────

    #[test]
    fn parse_rfc3339_accepts_utc_z_suffix() {
        assert_eq!(
            parse_rfc3339_seconds("2026-05-01T12:00:00Z").unwrap(),
            1_777_636_800,
        );
    }

    #[test]
    fn parse_rfc3339_accepts_offset_suffix() {
        // +00:00 is equivalent to Z; time crate accepts either.
        assert_eq!(
            parse_rfc3339_seconds("2026-05-01T12:00:00+00:00").unwrap(),
            1_777_636_800,
        );
    }

    #[test]
    fn parse_rfc3339_rejects_date_only() {
        let err = parse_rfc3339_seconds("2026-05-01").unwrap_err();
        assert!(matches!(
            err,
            StreamError::TimestampParseFailed { reason: _ },
        ));
    }

    #[test]
    fn parse_rfc3339_rejects_empty() {
        let err = parse_rfc3339_seconds("").unwrap_err();
        assert!(matches!(
            err,
            StreamError::TimestampParseFailed { reason: _ },
        ));
    }

    #[test]
    fn parse_rfc3339_rejects_non_timestamp_string() {
        let err = parse_rfc3339_seconds("hello world").unwrap_err();
        assert!(matches!(
            err,
            StreamError::TimestampParseFailed { reason: _ },
        ));
    }
}
