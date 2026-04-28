//! Firing-rule evaluators for the Session 5-B state-machine.
//!
//! One `evaluate_*` function per [`FiringRule`] variant.  Each
//! evaluator reads a PRE-EVICTED [`PatternBuffer`] (the caller must
//! have called [`PatternBuffer::evict_aged_events`] for windowed
//! patterns before calling the evaluator — windowless patterns skip
//! eviction), decides whether the pattern's threshold has been
//! crossed, and on crossing emits a single [`AnomalyFire`] DTO
//! describing the fire.
//!
//! # Why separate module from `state.rs`
//!
//! The Session 5-B dispatch in [`crate::state::DetectorState::evaluate_all`]
//! iterates every bucket and hands each `(pattern, buffer,
//! bucket_key)` tuple to the matching evaluator.  Keeping the
//! evaluators out of `state.rs` limits the state-machine module to
//! ingestion + dispatch + dedup bookkeeping, which keeps that file
//! under the 400-line soft cap the project style prefers.
//!
//! # Fire-once dedup model (plan §5; Commit D upgrade)
//!
//! Evaluators are READ-ONLY with respect to the
//! [`crate::dedup_ledger::DedupLedger`] backend held by
//! [`crate::state::DetectorState`] — [`is_fire_suppressed`] dispatches
//! [`crate::dedup_ledger::DedupLedger::is_suppressed`] and short-circuits
//! the evaluator when the `(pattern_id, mandate_id)` pair is still
//! inside its dedup window.  The actual `observe(...)` call that
//! records a fresh fire lives in the dispatch layer
//! ([`crate::state::DetectorState::evaluate_all`]) so evaluators
//! cannot accidentally double-record or skip recording.
//!
//! Commit D widened the dedup surface from an inline
//! `BTreeMap<(pattern_id, mandate_id), fired_at>` to a swappable trait
//! (`Box<dyn DedupLedger>`); evaluators forward backend `Result`s via
//! `?` so a persistent backend's I/O failure surfaces at
//! [`crate::orchestrator::AuditOrchestrator::observe_event`] rather
//! than silently drop the suppression check.
//!
//! Dedup window selection:
//! - Windowed patterns use `pattern.window_seconds`.  The §3.5.4
//!   firing semantics already guarantee the threshold fires "at most
//!   once per window"; reusing the same window as dedup horizon keeps
//!   the fire cadence bounded without introducing a second
//!   configurable.
//! - Windowless patterns (e.g. `unusual-delegation-depth`) lack a
//!   natural horizon.  Those use
//!   [`crate::state::FALLBACK_FIRE_ONCE_WINDOW_SECONDS`] (1h by
//!   default), matching the audit-pipeline's §11.2 operator-level
//!   dedup convention.
//!
//! # Log-safety
//!
//! Evaluators construct [`AnomalyFire`] values carrying
//! attacker-derived strings (`pattern_id` from the signed library;
//! `mandate_id`, `verb`, `resource_kind`, `integration` from the
//! ingested event).  Strings are stored BYTE-EXACTLY; log-rendering
//! is downstream (Commit B `audit.rs`) and MUST route through
//! [`crate::errors::sanitize_log_string`].

use std::collections::BTreeSet;

use crate::dedup_ledger::{DedupLedger, DedupLedgerError};
use crate::event::CanonicalizedEvent;
use crate::fire::{AnomalyFire, MatchScope};
use crate::patterns::{FiringRule, PatternEntry, Threshold};
use crate::scope::{ScopePredicate, VerbPredicate};
use crate::state::{PatternBuffer, ScopeBucketKey, FALLBACK_FIRE_ONCE_WINDOW_SECONDS};

/// Returns `Ok(true)` iff this pattern has already fired for the
/// given bucket within its dedup window and should be suppressed.
///
/// Key = `(pattern_id, mandate_id)` — the 5-A bucketing granularity.
/// Dedup window = `pattern.window_seconds` for windowed patterns,
/// [`FALLBACK_FIRE_ONCE_WINDOW_SECONDS`] for windowless patterns.
///
/// Edge semantics: exactly-at-the-window re-fires (the previous fire
/// is at `current_time - window`; `saturating_sub` returns `window`
/// which is NOT `< window`).  This keeps dedup and sliding-window
/// eviction symmetric — the same boundary applies to both.
///
/// # Errors
///
/// Forwards any error raised by the underlying
/// [`DedupLedger::is_suppressed`] call (persistent backends only;
/// the in-memory default is infallible on this path).
pub(crate) fn is_fire_suppressed(
    pattern: &PatternEntry,
    bucket_key: &ScopeBucketKey,
    current_time: i64,
    dedup: &dyn DedupLedger,
) -> Result<bool, DedupLedgerError> {
    let window = pattern
        .window_seconds
        .unwrap_or(FALLBACK_FIRE_ONCE_WINDOW_SECONDS);
    dedup.is_suppressed(
        &pattern.pattern_id,
        &bucket_key.mandate_id,
        current_time,
        window,
    )
}

/// Build the [`AnomalyFire`] DTO for a pattern firing in a given
/// bucket.
///
/// `sample_event` is the event whose observed values populate the
/// bound dimensions of [`MatchScope`].  Callers conventionally pass
/// the MOST RECENT event (`buffer.events.back()`) so downstream log
/// correlation can anchor on a fresh `event_id`.
///
/// Used by every evaluator — one construction site keeps the wire
/// form uniform across `FirstMatch`, `SequenceMatch`, and
/// `CumulativeOverBaseline` fires.
pub(crate) fn build_anomaly_fire(
    pattern: &PatternEntry,
    bucket_key: &ScopeBucketKey,
    library_version: u64,
    sample_event: &CanonicalizedEvent,
) -> AnomalyFire {
    AnomalyFire {
        pattern_id: pattern.pattern_id.clone(),
        library_version,
        severity: pattern.severity,
        firing_rule: pattern.firing_rule,
        match_scope: build_match_scope(pattern, bucket_key, sample_event),
    }
}

/// Project the observed event values into a [`MatchScope`] per the
/// pattern's scope predicate.
///
/// Dimensions of [`MatchScope`]:
/// - `mandate_id`: ALWAYS `Some(bucket_key.mandate_id)` because the
///   bucketing layer keys on mandate regardless of whether the
///   predicate bound the mandate dimension.
/// - `verb`: `Some(event.verb)` iff the predicate bound on a single
///   verb ([`VerbPredicate::Exact`]); `None` for family / any-
///   destructive predicates (a family does not pin a specific verb
///   — per the [`MatchScope::verb`] field doc).
/// - `resource_kind`: `Some(event.resource_kind)` iff the predicate
///   bound on a specific kind.
/// - `integration_ref`: `Some(event.integration)` iff the
///   predicate's `mandate_scope.integration_ref` is bound.
/// - `operator_id`: always `None` — canonicalized events carry no
///   operator attribution at this layer.  A future session adding
///   operator to the event shape can flip this projection without
///   disturbing the MatchScope wire form.
/// - `tier`: `Some(event.tier)` for tier-scalar predicates
///   ([`ScopePredicate::MandatePace`]).  Tier-sequence predicates
///   ([`ScopePredicate::CrossTierSequence`]) span multiple tiers and
///   are NOT reported as a scalar.
fn build_match_scope(
    pattern: &PatternEntry,
    bucket_key: &ScopeBucketKey,
    sample_event: &CanonicalizedEvent,
) -> MatchScope {
    // Start with fully-unbound, then overlay each dimension the
    // predicate actually bound.  `mandate_id` is always bound by
    // bucketing — everything else depends on the predicate shape.
    let mut scope = MatchScope {
        mandate_id: Some(bucket_key.mandate_id.clone()),
        ..MatchScope::default()
    };

    match &pattern.scope {
        ScopePredicate::VerbResourceMandate {
            verb,
            resource_kind,
            mandate_scope,
        } => {
            // Exhaustive sub-match — a new VerbPredicate variant must
            // decide its MatchScope projection at this site (compile
            // error, not a silent `None`).
            match verb {
                VerbPredicate::Exact(_) => {
                    scope.verb = Some(sample_event.verb.clone());
                }
                VerbPredicate::Family(_) | VerbPredicate::AnyDestructive => {
                    // Family predicates do not pin a specific verb
                    // (per MatchScope::verb doc).
                }
            }
            if resource_kind.is_some() {
                // Copy from sample_event, NOT from the predicate's
                // literal `resource_kind: Some(literal)`.  This is
                // valid because the bucket-membership gate in
                // `ScopePredicate::matches` already enforced
                // `event.resource_kind == predicate.resource_kind`
                // before the event reached this projection site, so
                // the two strings are structurally equal and copying
                // from the event keeps the invariant "MatchScope
                // reflects observed event fields, not pattern literal
                // fields" from §11.2.
                scope.resource_kind = Some(sample_event.resource_kind.clone());
            }
            if mandate_scope.integration_ref.is_some() {
                scope.integration_ref = Some(sample_event.integration.clone());
            }
        }
        ScopePredicate::IamAttachFamily { mandate_scope, .. }
        | ScopePredicate::ProtectedBranches { mandate_scope, .. }
        | ScopePredicate::CrossTierSequence { mandate_scope, .. } => {
            if mandate_scope.integration_ref.is_some() {
                scope.integration_ref = Some(sample_event.integration.clone());
            }
        }
        ScopePredicate::MandatePace { .. } => {
            scope.tier = Some(sample_event.tier);
        }
        ScopePredicate::VerbFanout {
            verb,
            mandate_scope,
        } => {
            // Same exhaustive sub-match as VerbResourceMandate.
            match verb {
                VerbPredicate::Exact(_) => {
                    scope.verb = Some(sample_event.verb.clone());
                }
                VerbPredicate::Family(_) | VerbPredicate::AnyDestructive => {
                    // Family predicates do not pin a specific verb.
                }
            }
            if mandate_scope.integration_ref.is_some() {
                scope.integration_ref = Some(sample_event.integration.clone());
            }
        }
        ScopePredicate::SilenceThenBurst { .. }
        | ScopePredicate::CanaryWindow { .. }
        | ScopePredicate::DelegationDepth { .. } => {
            // No additional dimensions to project beyond mandate_id.
        }
    }

    scope
}

/// FirstMatch evaluator (§3.5.3): fires when `buffer.events.len() ≥
/// threshold` within the sliding window.
///
/// # Caller contract
///
/// - `buffer` MUST be pre-evicted for the pattern's sliding window
///   BEFORE this function is called — the evaluator reads the buffer
///   length verbatim.  An unevicted buffer would inflate the count
///   with aged events and trigger spurious fires.
/// - `pattern.firing_rule` MUST be [`FiringRule::FirstMatch`].
///   Non-FirstMatch patterns pass through unchanged (returns `None`)
///   so dispatch can route without pre-classifying.
/// - `pattern.threshold` MUST be [`Threshold::Count`].  Other
///   threshold shapes return `None` — FirstMatch is Count-only per
///   §3.5.3.
///
/// # Dedup
///
/// [`is_fire_suppressed`] gates the evaluator: if the pattern has
/// fired for this bucket within the last `window_seconds`, the
/// evaluator returns `None` even when the counter still crosses the
/// threshold.  The dispatch layer (not this function) calls
/// [`crate::dedup_ledger::DedupLedger::observe`] with the fresh fire
/// on a successful return.
///
/// # Returns
///
/// - `Ok(Some(AnomalyFire))` when the threshold is crossed AND dedup
///   does not suppress.
/// - `Ok(None)` otherwise (threshold not met, dedup-suppressed, wrong
///   firing rule / threshold shape, or the buffer is empty).
/// - `Err(DedupLedgerError)` only if a persistent dedup backend
///   raised an I/O failure during the suppression probe; the
///   in-memory default is infallible on this path.
pub(crate) fn evaluate_first_match(
    pattern: &PatternEntry,
    buffer: &PatternBuffer,
    bucket_key: &ScopeBucketKey,
    library_version: u64,
    current_time: i64,
    dedup: &dyn DedupLedger,
) -> Result<Option<AnomalyFire>, DedupLedgerError> {
    // Gate 1: firing-rule shape.  `FirstMatch` only.
    if !matches!(pattern.firing_rule, FiringRule::FirstMatch) {
        return Ok(None);
    }

    // Gate 2: dedup probe.  Runs BEFORE the threshold walk so a
    // suppressed bucket skips the potentially O(n) DistinctCount scan
    // entirely.  `?` forwards backend I/O failures.
    if is_fire_suppressed(pattern, bucket_key, current_time, dedup)? {
        return Ok(None);
    }

    // Gate 3: threshold.  `Count(_)` is the buffer length (saturating
    // to u32::MAX for buffers at MAX_EVENTS_PER_BUFFER — unreachable
    // at the configured cap).  `DistinctCount(_)` walks the buffer
    // once to count unique `resource_ref` strings.  Other threshold
    // shapes (Sequence, ChainDepth) pair with different firing rules
    // and fall through defensively.
    let (count, threshold) = match pattern.threshold {
        Threshold::Count(n) => (u32::try_from(buffer.events.len()).unwrap_or(u32::MAX), n),
        Threshold::DistinctCount(n) => (count_distinct_resource_refs(buffer), n),
        _ => return Ok(None),
    };
    if count < threshold {
        return Ok(None);
    }

    // Sample event for MatchScope projection.  Most recent event
    // anchors the downstream `event_id` for audit correlation.  A
    // threshold crossing with an empty buffer is contradictory (the
    // count check would have returned None), but we guard defensively
    // via the `let-else` so the absence is explicit.
    let Some(sample) = buffer.events.back() else {
        return Ok(None);
    };
    Ok(Some(build_anomaly_fire(
        pattern,
        bucket_key,
        library_version,
        sample,
    )))
}

/// SequenceMatch evaluator (§3.5.3): fires when `completions ≥
/// threshold` where a completion is defined per scope-predicate
/// shape:
///
/// - [`ScopePredicate::CrossTierSequence`] — one completion per
///   traversal of `tier_progression` across the buffered events in
///   order.  Each step matches any event whose tier is at least the
///   step's threshold; noise events below the current step's
///   threshold are skipped without resetting the walk.
/// - [`ScopePredicate::SilenceThenBurst`] — one completion per
///   silence-preceded burst: `silence_seconds` of no buffered events
///   followed by `burst_threshold` events all within
///   `burst_seconds`.  The first buffered event is treated as having
///   had infinite implicit silence (fresh-state start).
///
/// Other scope shapes paired with `SequenceMatch` at the library
/// layer are library-authoring bugs; the evaluator returns `None`
/// defensively (Stage-7 invariants already reject them upstream).
///
/// # Caller contract
///
/// Identical to [`evaluate_first_match`] — pre-evicted buffer,
/// `pattern.firing_rule == SequenceMatch`, `pattern.threshold ==
/// Sequence(_)`.  Dispatch routes mismatched shapes here only for
/// defense-in-depth.
///
/// # Stateless design
///
/// The evaluator walks `buffer.events` fresh on every call.  The
/// [`crate::state::SequenceTracker`] field on [`PatternBuffer`] is
/// reserved for a future incremental-tracking optimisation; at
/// Session 5-B Commit A it is not materialised.  Re-walking the
/// 1 000-event cap is cheap; correctness beats optimisation.
pub(crate) fn evaluate_sequence_match(
    pattern: &PatternEntry,
    buffer: &PatternBuffer,
    bucket_key: &ScopeBucketKey,
    library_version: u64,
    current_time: i64,
    dedup: &dyn DedupLedger,
) -> Result<Option<AnomalyFire>, DedupLedgerError> {
    if !matches!(pattern.firing_rule, FiringRule::SequenceMatch) {
        return Ok(None);
    }
    let Threshold::Sequence(threshold) = pattern.threshold else {
        return Ok(None);
    };
    if is_fire_suppressed(pattern, bucket_key, current_time, dedup)? {
        return Ok(None);
    }

    let completions = match &pattern.scope {
        ScopePredicate::CrossTierSequence {
            tier_progression, ..
        } => count_cross_tier_sequences(buffer, tier_progression),
        ScopePredicate::SilenceThenBurst {
            silence_seconds,
            burst_seconds,
            burst_threshold,
        } => count_silence_then_burst(buffer, *silence_seconds, *burst_seconds, *burst_threshold),
        // Other predicates have no sequence semantic.  Stage-7
        // invariants forbid pairing them with SequenceMatch at the
        // library layer; this arm is defense-in-depth.
        _ => return Ok(None),
    };

    if completions < threshold {
        return Ok(None);
    }

    let Some(sample) = buffer.events.back() else {
        return Ok(None);
    };
    Ok(Some(build_anomaly_fire(
        pattern,
        bucket_key,
        library_version,
        sample,
    )))
}

/// Count completed tier-progression traversals across the buffered
/// events in order.
///
/// Walk semantics:
/// - Step `k` matches any event with `event.tier >= tier_progression[k]`.
/// - On a step-match, advance to step `k+1`; on step `len`, record
///   one completion and reset to step 0.
/// - Events below the current step's threshold are skipped without
///   resetting the walker (a "noise" low-tier event between steps
///   does NOT interrupt the progression).
///
/// An empty `tier_progression` is treated as zero completions — a
/// degenerate shape that Stage-7 invariants reject upstream but the
/// evaluator handles defensively.
fn count_cross_tier_sequences(buffer: &PatternBuffer, tier_progression: &[u8]) -> u32 {
    if tier_progression.is_empty() {
        return 0;
    }
    let mut completions = 0_u32;
    let mut step = 0_usize;
    for event in &buffer.events {
        if event.tier >= tier_progression[step] {
            step += 1;
            if step == tier_progression.len() {
                completions = completions.saturating_add(1);
                step = 0;
            }
        }
    }
    completions
}

/// Count silence-then-burst completions across the buffered events
/// in order.
///
/// Definition of one completion:
/// 1. A "silence" interval of at least `silence_seconds` immediately
///    before an event `e_i` — either `i == 0` (fresh state, implicit
///    infinite silence) or `e_i.timestamp - e_{i-1}.timestamp ≥
///    silence_seconds`.
/// 2. Starting at `e_i`, the next `burst_threshold` events (including
///    `e_i`) all fall within `burst_seconds` of `e_i` (i.e.
///    `e_{i+burst_threshold-1}.timestamp - e_i.timestamp ≤
///    burst_seconds`).
///
/// After a completion the scan resumes AFTER the burst (index
/// `i + burst_threshold`), preventing a single burst from being
/// double-counted when it contains more than `burst_threshold`
/// events.  A zero-threshold burst is treated as zero completions
/// (degenerate; Stage-7 invariants reject upstream).
fn count_silence_then_burst(
    buffer: &PatternBuffer,
    silence_seconds: u32,
    burst_seconds: u32,
    burst_threshold: u32,
) -> u32 {
    if burst_threshold == 0 {
        return 0;
    }
    // `VecDeque` indexing is O(1); no intermediate `Vec<&…>` needed.
    let events = &buffer.events;
    let needed = usize::try_from(burst_threshold).unwrap_or(usize::MAX);
    if events.len() < needed {
        return 0;
    }

    let silence = i64::from(silence_seconds);
    let burst = i64::from(burst_seconds);
    let mut completions = 0_u32;
    let mut i = 0_usize;
    while i + needed <= events.len() {
        let silence_ok =
            i == 0 || events[i].timestamp.saturating_sub(events[i - 1].timestamp) >= silence;
        if !silence_ok {
            i += 1;
            continue;
        }
        let span = events[i + needed - 1]
            .timestamp
            .saturating_sub(events[i].timestamp);
        if span <= burst {
            completions = completions.saturating_add(1);
            i += needed;
        } else {
            i += 1;
        }
    }
    completions
}

/// CumulativeOverBaseline evaluator (§3.5.3): fires when rolling
/// count ≥ threshold at any evaluation step.
///
/// Supports two threshold shapes:
/// - [`Threshold::Count`] — total events in the pre-evicted buffer
///   ≥ threshold.  Matches the anti-walk-under backstop shape
///   (§3.5.3): a longer-window counterpart to a short-window
///   `FirstMatch` that catches below-threshold-per-window but
///   above-baseline-cumulative drift.
/// - [`Threshold::DistinctCount`] — distinct `resource_ref` values
///   in the pre-evicted buffer ≥ threshold.  Powers
///   `fanout-distinct-resources` and any future VerbFanout-style
///   pattern that measures cardinality rather than volume.
///
/// Other threshold shapes (`Sequence`, `ChainDepth`) are not
/// normative for CumulativeOverBaseline and return `None`
/// defensively.
///
/// # Caller contract
///
/// Identical to the other evaluators — pre-evicted buffer,
/// firing_rule gate, dedup gate, threshold check.
pub(crate) fn evaluate_cumulative_over_baseline(
    pattern: &PatternEntry,
    buffer: &PatternBuffer,
    bucket_key: &ScopeBucketKey,
    library_version: u64,
    current_time: i64,
    dedup: &dyn DedupLedger,
) -> Result<Option<AnomalyFire>, DedupLedgerError> {
    if !matches!(pattern.firing_rule, FiringRule::CumulativeOverBaseline) {
        return Ok(None);
    }
    if is_fire_suppressed(pattern, bucket_key, current_time, dedup)? {
        return Ok(None);
    }

    let (count, threshold) = match pattern.threshold {
        Threshold::Count(n) => {
            let c = u32::try_from(buffer.events.len()).unwrap_or(u32::MAX);
            (c, n)
        }
        Threshold::DistinctCount(n) => (count_distinct_resource_refs(buffer), n),
        // Sequence / ChainDepth do not pair with CumulativeOverBaseline.
        _ => return Ok(None),
    };
    if count < threshold {
        return Ok(None);
    }

    let Some(sample) = buffer.events.back() else {
        return Ok(None);
    };
    Ok(Some(build_anomaly_fire(
        pattern,
        bucket_key,
        library_version,
        sample,
    )))
}

/// Count the number of distinct `resource_ref` values across the
/// buffered events.
///
/// Uses [`BTreeSet`] (ordered) over `HashSet` for determinism — not
/// strictly required here since only the cardinality matters, but
/// consistent with the project's BTreeMap-over-HashMap convention
/// (see `DetectorState::buffers` doc).
fn count_distinct_resource_refs(buffer: &PatternBuffer) -> u32 {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for event in &buffer.events {
        seen.insert(event.resource_ref.as_str());
    }
    u32::try_from(seen.len()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    use crate::dedup_ledger::InMemoryDedupLedger;
    use crate::event::Outcome;
    use crate::patterns::{Action, FiringRule, PatternEntry, Severity, Threshold};
    use crate::scope::{MandateScope, ScopePredicate, VerbPredicate};

    /// Test-helper wrappers that unwrap the evaluator `Result` arm
    /// before returning the inner `Option<AnomalyFire>`.  All evaluator
    /// tests in this module exercise the in-memory dedup ledger which
    /// is infallible on every code path; a backend error here is a
    /// regression and should panic.  Centralising the unwrap keeps the
    /// per-test bodies focused on the semantic assertion.
    fn first_match(
        pattern: &PatternEntry,
        buffer: &PatternBuffer,
        bucket_key: &ScopeBucketKey,
        library_version: u64,
        current_time: i64,
        dedup: &dyn DedupLedger,
    ) -> Option<AnomalyFire> {
        evaluate_first_match(
            pattern,
            buffer,
            bucket_key,
            library_version,
            current_time,
            dedup,
        )
        .expect("in-memory dedup ledger is infallible in tests")
    }

    fn sequence_match(
        pattern: &PatternEntry,
        buffer: &PatternBuffer,
        bucket_key: &ScopeBucketKey,
        library_version: u64,
        current_time: i64,
        dedup: &dyn DedupLedger,
    ) -> Option<AnomalyFire> {
        evaluate_sequence_match(
            pattern,
            buffer,
            bucket_key,
            library_version,
            current_time,
            dedup,
        )
        .expect("in-memory dedup ledger is infallible in tests")
    }

    fn cumulative(
        pattern: &PatternEntry,
        buffer: &PatternBuffer,
        bucket_key: &ScopeBucketKey,
        library_version: u64,
        current_time: i64,
        dedup: &dyn DedupLedger,
    ) -> Option<AnomalyFire> {
        evaluate_cumulative_over_baseline(
            pattern,
            buffer,
            bucket_key,
            library_version,
            current_time,
            dedup,
        )
        .expect("in-memory dedup ledger is infallible in tests")
    }

    /// Convenience: an empty in-memory dedup ledger ready to be
    /// passed by reference.  Tests that need to seed prior fires use
    /// `let mut d = InMemoryDedupLedger::new(); d.observe(...).unwrap();`
    /// directly.
    fn empty_dedup() -> InMemoryDedupLedger {
        InMemoryDedupLedger::new()
    }

    /// Local evaluator-test fixture for `delete-storm`.
    ///
    /// INTENTIONALLY divergent from the MINIMUM library's
    /// `delete-storm` (see
    /// `ephemeral_anomaly::test_fixtures::delete_storm_pattern`,
    /// which uses `VerbPredicate::AnyDestructive` + `resource_kind:
    /// None`).  This local copy pins `Exact("delete")` +
    /// `resource_kind: Some("pod")` so the evaluator unit tests
    /// below can exercise the `VerbPredicate::Exact` and explicit-
    /// resource-kind projection paths in `build_match_scope` that
    /// the wildcard AnyDestructive/None shape would otherwise leave
    /// uncovered.  Keep the divergence — the EPHEMERAL conformance
    /// corpus exercises the MINIMUM library's shape end-to-end via
    /// `anomaly-detect.json`; the two fixtures complement rather
    /// than duplicate each other.
    fn delete_storm_pattern() -> PatternEntry {
        PatternEntry {
            pattern_id: "delete-storm".into(),
            window_seconds: Some(60),
            threshold: Threshold::Count(5),
            scope: ScopePredicate::VerbResourceMandate {
                verb: VerbPredicate::Exact("delete".into()),
                resource_kind: Some("pod".into()),
                mandate_scope: MandateScope::default(),
            },
            action: Action::AutoRevoke,
            severity: Severity::High,
            firing_rule: FiringRule::FirstMatch,
            firing_rule_companions: vec![],
        }
    }

    fn base_event(event_id: &str, mandate_id: &str, timestamp: i64) -> CanonicalizedEvent {
        CanonicalizedEvent {
            event_id: event_id.into(),
            timestamp,
            mandate_id: mandate_id.into(),
            tier: 2,
            integration: "kubernetes".into(),
            verb: "delete".into(),
            resource_kind: "pod".into(),
            resource_ref: "ns/app/pod-7".into(),
            outcome: Outcome::Executed,
        }
    }

    fn bucket_key_for(pattern_id: &str, mandate_id: &str) -> ScopeBucketKey {
        ScopeBucketKey {
            pattern_id: pattern_id.into(),
            mandate_id: mandate_id.into(),
            operator_id: None,
            integration_ref: None,
            resource_kind: None,
        }
    }

    fn buffer_with(pattern_id: &str, n: usize, base_ts: i64) -> PatternBuffer {
        // White-box construction: bypass `DetectorState::ingest_event`
        // so the evaluator is exercised in isolation from the
        // ingestion pipeline.  The buffer exposes `pub(crate)` events
        // within the crate, letting us populate it directly.
        let mut buf = PatternBuffer {
            pattern_id: pattern_id.into(),
            events: VecDeque::new(),
            sequence_tracker: None,
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        for i in 0..n {
            buf.events
                .push_back(base_event(&format!("e-{i}"), "m-42", base_ts + (i as i64)));
        }
        buf
    }

    // ----- Gate: non-FirstMatch returns None ---------------------------

    #[test]
    fn evaluate_first_match_returns_none_for_sequence_match_pattern() {
        // A caller dispatching to this evaluator for a SequenceMatch
        // pattern MUST get a clean `None` so the dispatcher does not
        // accidentally double-fire or misattribute.
        let mut pattern = delete_storm_pattern();
        pattern.firing_rule = FiringRule::SequenceMatch;
        let buffer = buffer_with(&pattern.pattern_id, 10, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn evaluate_first_match_returns_none_for_non_count_threshold() {
        // FirstMatch only fires on `Count(_)` per §3.5.3.  A
        // FirstMatch row carrying a `Sequence` threshold is a mis-
        // authored library — Stage-7 invariants would ordinarily
        // reject it; this test pins the evaluator's defense-in-depth
        // posture.
        let mut pattern = delete_storm_pattern();
        pattern.threshold = Threshold::Sequence(1);
        let buffer = buffer_with(&pattern.pattern_id, 10, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- Threshold crossing behaviour --------------------------------

    #[test]
    fn evaluate_first_match_fires_exactly_at_threshold() {
        // threshold=Count(5), buffer has 5 events → fire.
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 5, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = first_match(&pattern, &buffer, &key, 42, 1_700_000_100, &dedup);
        let fire = out.expect("exactly-at-threshold MUST fire");
        assert_eq!(fire.pattern_id, "delete-storm");
        assert_eq!(fire.library_version, 42);
    }

    #[test]
    fn evaluate_first_match_no_fire_one_below_threshold() {
        // threshold=Count(5), buffer has 4 events → no fire.  Pins
        // the `<` vs `<=` boundary semantics.
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 4, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn evaluate_first_match_fires_above_threshold() {
        // Sanity: buffer at threshold+1 still fires.
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 6, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_some());
    }

    #[test]
    fn evaluate_first_match_no_fire_on_empty_buffer() {
        // Defense-in-depth: an empty buffer never fires even if
        // threshold = 0 (which Stage 7 invariants forbid, but the
        // evaluator does not trust the library to be well-formed).
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 0, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- Fire-once dedup --------------------------------------------

    #[test]
    fn evaluate_first_match_suppresses_on_dedup_hit_within_window() {
        // The pattern previously fired at T-30s, window=60s, so the
        // dedup is still active (T - 30 < 60) and suppresses the
        // fresh fire even though the threshold is crossed.
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 10, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let mut dedup = empty_dedup();
        dedup
            .observe("delete-storm", "m-42", 1_700_000_070)
            .unwrap();
        let out = first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none(), "dedup MUST suppress re-fire");
    }

    #[test]
    fn evaluate_first_match_fires_after_dedup_window_elapses() {
        // Previous fire at T-60s, window=60s → dedup age == window →
        // fresh fire allowed (strict `<` semantics in
        // `is_fire_suppressed`).
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 10, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let mut dedup = empty_dedup();
        dedup
            .observe("delete-storm", "m-42", 1_700_000_040)
            .unwrap();
        let out = first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_some(), "boundary-of-window MUST allow re-fire");
    }

    #[test]
    fn evaluate_first_match_dedup_is_per_mandate_not_global() {
        // m-42 has fired recently; m-99 has not.  The m-99 bucket
        // must fire even though the pattern is "in dedup" for m-42.
        let pattern = delete_storm_pattern();
        let buffer_99 = buffer_with(&pattern.pattern_id, 10, 1_700_000_000);
        let key_99 = bucket_key_for(&pattern.pattern_id, "m-99");
        let mut dedup = empty_dedup();
        dedup
            .observe("delete-storm", "m-42", 1_700_000_070)
            .unwrap();
        let out = first_match(&pattern, &buffer_99, &key_99, 1, 1_700_000_100, &dedup);
        assert!(out.is_some());
    }

    // ----- MatchScope projection --------------------------------------

    #[test]
    fn evaluate_first_match_match_scope_binds_exact_verb_and_resource_kind() {
        // delete-storm binds on VerbPredicate::Exact("delete") +
        // resource_kind=Some("pod") + mandate_scope::default().
        // Expected MatchScope:
        //   mandate_id = Some("m-42")  (from bucket key)
        //   verb       = Some("delete") (Exact → event-observed)
        //   resource_kind = Some("pod")
        //   integration_ref = None (unbound)
        //   operator_id = None (5-A carries no operator)
        //   tier = None (not a MandatePace predicate)
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 5, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire =
            first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup).expect("should fire");
        assert_eq!(fire.match_scope.mandate_id.as_deref(), Some("m-42"));
        assert_eq!(fire.match_scope.verb.as_deref(), Some("delete"));
        assert_eq!(fire.match_scope.resource_kind.as_deref(), Some("pod"));
        assert!(fire.match_scope.integration_ref.is_none());
        assert!(fire.match_scope.operator_id.is_none());
        assert!(fire.match_scope.tier.is_none());
    }

    #[test]
    fn evaluate_first_match_match_scope_leaves_verb_none_for_family_predicate() {
        // When the predicate binds VerbPredicate::Family(_), the
        // MatchScope's verb field stays None per the fire.rs doc
        // ("`None` if the predicate bound on a verb-family").
        let mut pattern = delete_storm_pattern();
        pattern.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("destructive".into()),
            resource_kind: Some("pod".into()),
            mandate_scope: MandateScope::default(),
        };
        let buffer = buffer_with(&pattern.pattern_id, 5, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire =
            first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup).expect("should fire");
        assert!(
            fire.match_scope.verb.is_none(),
            "family predicate MUST NOT pin a specific verb"
        );
        assert_eq!(fire.match_scope.resource_kind.as_deref(), Some("pod"));
    }

    #[test]
    fn evaluate_first_match_match_scope_binds_integration_ref_when_predicate_binds_it() {
        // A predicate with `integration_ref = Some("kubernetes")`
        // forces every event in the bucket to carry that integration
        // (routing gate).  The MatchScope projection lifts that value
        // into the fire DTO.
        let mut pattern = delete_storm_pattern();
        pattern.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: None,
            mandate_scope: MandateScope {
                mandate_id: None,
                operator_id: None,
                integration_ref: Some("kubernetes".into()),
            },
        };
        let buffer = buffer_with(&pattern.pattern_id, 5, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire =
            first_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup).expect("should fire");
        assert_eq!(
            fire.match_scope.integration_ref.as_deref(),
            Some("kubernetes")
        );
        assert!(fire.match_scope.resource_kind.is_none());
    }

    // ----- AnomalyFire wire form --------------------------------------

    #[test]
    fn evaluate_first_match_fire_carries_pattern_severity_and_firing_rule() {
        // A Session 5-C log-rendering path reads these fields; pin
        // that the evaluator passes them through byte-exactly.
        let pattern = delete_storm_pattern();
        let buffer = buffer_with(&pattern.pattern_id, 5, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire =
            first_match(&pattern, &buffer, &key, 42, 1_700_000_100, &dedup).expect("should fire");
        assert_eq!(fire.severity, Severity::High);
        assert_eq!(fire.firing_rule, FiringRule::FirstMatch);
        assert_eq!(fire.library_version, 42);
    }

    // ----- is_fire_suppressed direct coverage --------------------------

    #[test]
    fn is_fire_suppressed_returns_false_when_no_prior_fire() {
        let pattern = delete_storm_pattern();
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        assert!(!is_fire_suppressed(&pattern, &key, 1_700_000_100, &dedup)
            .expect("in-memory dedup ledger is infallible"));
    }

    #[test]
    fn is_fire_suppressed_uses_fallback_window_for_windowless_pattern() {
        // Windowless pattern + fallback 1h dedup window.  Previous
        // fire at T-1799s → still suppressed; fire at T-3600s → allowed.
        let mut pattern = delete_storm_pattern();
        pattern.window_seconds = None;
        let key = bucket_key_for(&pattern.pattern_id, "m-42");

        let mut dedup = empty_dedup();
        dedup
            .observe("delete-storm", "m-42", 1_700_000_100 - 1799)
            .unwrap();
        assert!(is_fire_suppressed(&pattern, &key, 1_700_000_100, &dedup)
            .expect("in-memory dedup ledger is infallible"));

        // Overwrite the prior bookmark to land exactly at the fallback
        // window boundary; in-memory `observe` overwrites in place, so
        // this matches the BTreeMap::insert semantics the original test
        // relied on.
        dedup
            .observe(
                "delete-storm",
                "m-42",
                1_700_000_100 - i64::from(FALLBACK_FIRE_ONCE_WINDOW_SECONDS),
            )
            .unwrap();
        assert!(
            !is_fire_suppressed(&pattern, &key, 1_700_000_100, &dedup)
                .expect("in-memory dedup ledger is infallible"),
            "exactly-at-window MUST NOT suppress (strict `<`)"
        );
    }

    // =====================================================================
    // T5: SequenceMatch evaluator tests
    // =====================================================================

    /// Build a CrossTierSequence pattern with a given tier_progression.
    /// Default threshold = Sequence(1), firing_rule = SequenceMatch,
    /// severity = Medium + Alert so it passes the §3.5.2 invariant.
    fn cross_tier_sequence_pattern(tiers: Vec<u8>, threshold: u32) -> PatternEntry {
        PatternEntry {
            pattern_id: "cross-tier-escalation".into(),
            window_seconds: Some(300),
            threshold: Threshold::Sequence(threshold),
            scope: ScopePredicate::CrossTierSequence {
                mandate_scope: MandateScope::default(),
                tier_progression: tiers,
            },
            action: Action::Alert,
            severity: Severity::Medium,
            firing_rule: FiringRule::SequenceMatch,
            firing_rule_companions: vec![],
        }
    }

    /// Build a SilenceThenBurst pattern.
    fn silence_then_burst_pattern(
        silence_seconds: u32,
        burst_seconds: u32,
        burst_threshold: u32,
    ) -> PatternEntry {
        PatternEntry {
            pattern_id: "long-silence-before-burst".into(),
            window_seconds: Some(silence_seconds + burst_seconds),
            threshold: Threshold::Sequence(1),
            scope: ScopePredicate::SilenceThenBurst {
                silence_seconds,
                burst_seconds,
                burst_threshold,
            },
            action: Action::Alert,
            severity: Severity::Medium,
            firing_rule: FiringRule::SequenceMatch,
            firing_rule_companions: vec![],
        }
    }

    /// Build a PatternBuffer where each event `i` has tier=`tiers[i]`
    /// and timestamp=`base_ts + i * spacing`.
    fn tiered_buffer(pattern_id: &str, tiers: &[u8], base_ts: i64, spacing: i64) -> PatternBuffer {
        let mut buf = PatternBuffer {
            pattern_id: pattern_id.into(),
            events: VecDeque::new(),
            sequence_tracker: None,
        };
        for (i, &tier) in tiers.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ts = base_ts + (i as i64) * spacing;
            let mut event = base_event(&format!("e-{i}"), "m-42", ts);
            event.tier = tier;
            buf.events.push_back(event);
        }
        buf
    }

    /// Build a PatternBuffer with events at specified timestamps
    /// (tier = 2 for all, which is fine for SilenceThenBurst since
    /// that predicate does not tier-filter).
    fn timestamped_buffer(pattern_id: &str, timestamps: &[i64]) -> PatternBuffer {
        let mut buf = PatternBuffer {
            pattern_id: pattern_id.into(),
            events: VecDeque::new(),
            sequence_tracker: None,
        };
        for (i, &ts) in timestamps.iter().enumerate() {
            buf.events
                .push_back(base_event(&format!("e-{i}"), "m-42", ts));
        }
        buf
    }

    // ----- Gates ------------------------------------------------------

    #[test]
    fn evaluate_sequence_match_returns_none_for_first_match_pattern() {
        let mut pattern = cross_tier_sequence_pattern(vec![0, 2, 3], 1);
        pattern.firing_rule = FiringRule::FirstMatch;
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 2, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn evaluate_sequence_match_returns_none_for_non_sequence_threshold() {
        let mut pattern = cross_tier_sequence_pattern(vec![0, 2, 3], 1);
        pattern.threshold = Threshold::Count(5);
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 2, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn evaluate_sequence_match_returns_none_for_non_sequence_predicate() {
        // Mis-paired library: SequenceMatch + VerbResourceMandate is
        // rejected by Stage-7 invariants; evaluator defensively None.
        let mut pattern = cross_tier_sequence_pattern(vec![0, 2, 3], 1);
        pattern.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 2, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- CrossTierSequence path ------------------------------------

    #[test]
    fn cross_tier_sequence_fires_on_ordered_progression_threshold_one() {
        // Progression [0, 2, 3], events at tiers [0, 2, 3]: one
        // completion → threshold=1 satisfied → fire.
        let pattern = cross_tier_sequence_pattern(vec![0, 2, 3], 1);
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 2, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup)
            .expect("ordered progression MUST fire at threshold=1");
        assert_eq!(fire.pattern_id, "cross-tier-escalation");
        assert_eq!(fire.firing_rule, FiringRule::SequenceMatch);
    }

    #[test]
    fn cross_tier_sequence_no_fire_on_partial_progression() {
        // Only [0, 2] observed; step 3 never reached → 0 completions.
        let pattern = cross_tier_sequence_pattern(vec![0, 2, 3], 1);
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 2, 1], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn cross_tier_sequence_skips_low_tier_noise_without_resetting() {
        // Progression [2, 3].  Events [2, 1, 1, 3]: the two tier-1
        // events are below the current step-1 threshold (3) but
        // do not reset the walker, so step 3 is reached on the
        // final event → 1 completion.
        let pattern = cross_tier_sequence_pattern(vec![2, 3], 1);
        let buffer = tiered_buffer(&pattern.pattern_id, &[2, 1, 1, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(
            out.is_some(),
            "noise between steps MUST NOT reset the walker"
        );
    }

    #[test]
    fn cross_tier_sequence_threshold_two_requires_two_completions() {
        // Progression [0, 3].  Events [0, 3, 0, 3]: two completions.
        let pattern = cross_tier_sequence_pattern(vec![0, 3], 2);
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 3, 0, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_some());

        // One fewer event → only one completion → no fire.
        let buffer_short = tiered_buffer(&pattern.pattern_id, &[0, 3, 0], 1_700_000_000, 10);
        let out_short = sequence_match(&pattern, &buffer_short, &key, 1, 1_700_000_100, &dedup);
        assert!(out_short.is_none());
    }

    #[test]
    fn cross_tier_sequence_empty_progression_does_not_fire() {
        // Degenerate: empty tier_progression → 0 completions.
        let pattern = cross_tier_sequence_pattern(vec![], 1);
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 2, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- SilenceThenBurst path -------------------------------------

    #[test]
    fn silence_then_burst_fires_on_silence_plus_burst() {
        // silence=60s, burst_window=10s, burst_threshold=3.
        // Events: [10, 20, 30] — implicit silence before index 0, and
        // the three events span 20s... wait, 30-10=20s > 10s burst
        // window.  Adjust: [10, 11, 12] — span 2s < 10s, threshold 3.
        let pattern = silence_then_burst_pattern(60, 10, 3);
        let buffer = timestamped_buffer(
            &pattern.pattern_id,
            &[1_700_000_010, 1_700_000_011, 1_700_000_012],
        );
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup)
            .expect("implicit silence before index 0 + burst MUST fire");
        assert_eq!(fire.pattern_id, "long-silence-before-burst");
    }

    #[test]
    fn silence_then_burst_no_fire_on_burst_without_silence() {
        // Prior events immediately before the burst defeat the
        // silence precondition: events at [0, 5, 6, 7] — burst
        // [5,6,7] is preceded by only 5s gap from event at 0,
        // below silence_seconds=60.
        let pattern = silence_then_burst_pattern(60, 10, 3);
        let buffer = timestamped_buffer(
            &pattern.pattern_id,
            &[1_700_000_000, 1_700_000_005, 1_700_000_006, 1_700_000_007],
        );
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        // First burst attempt at index 0 has implicit silence but
        // only events 0+1+2=(0,5,6) span 6s; that's within burst.
        // Wait: implicit silence at index 0 + events [0, 5, 6] →
        // completion. Index advances to 3 (first-event + needed=3),
        // only event at index 3 remains → not enough for another
        // burst.  So we SHOULD get 1 completion → fires.
        //
        // To actually test the no-silence path, push the burst
        // *after* other events so index 1+ has no silence:
        let buffer_no_silence = timestamped_buffer(
            &pattern.pattern_id,
            &[
                1_700_000_000,
                1_700_000_001,
                1_700_000_002,
                1_700_000_003,
                1_700_000_004,
            ],
        );
        // At index 0: implicit silence + span=(0..2)=2s < 10s → 1 completion.
        // Scanner jumps to index 3.  Index 3 has prior event at index 2,
        // gap 1s < silence_seconds=60, so no completion there.
        // Total = 1 completion.
        let out_contiguous =
            sequence_match(&pattern, &buffer_no_silence, &key, 1, 1_700_000_100, &dedup);
        assert!(out_contiguous.is_some());
        // The first-burst already fires via implicit silence; this is
        // correct per spec.  To *actually* get no-silence-no-fire we
        // need a buffer where index 0's first burst FAILS span check,
        // then a subsequent index has no silence: [0, 20, 21, 22].
        // At index 0: span=0..2 = 21s > 10s → no fire.
        // Advance to index 1; silence from index 0 = 20s < 60s → no.
        // Index 2: silence = 1s → no.  Final: 0 completions → no fire.
        let buffer_fail = timestamped_buffer(
            &pattern.pattern_id,
            &[1_700_000_000, 1_700_000_020, 1_700_000_021, 1_700_000_022],
        );
        let out_fail = sequence_match(&pattern, &buffer_fail, &key, 1, 1_700_000_100, &dedup);
        assert!(out_fail.is_none());
        // Reference to satisfy clippy about `out` — it's the first,
        // informational call showing the shape-sensitive edge.
        let _ = out;
    }

    #[test]
    fn silence_then_burst_no_fire_when_not_enough_burst_events() {
        // silence_seconds=60, burst_threshold=5, but buffer has only
        // 3 events.  needed > events.len() → 0 completions.
        let pattern = silence_then_burst_pattern(60, 10, 5);
        let buffer = timestamped_buffer(
            &pattern.pattern_id,
            &[1_700_000_010, 1_700_000_011, 1_700_000_012],
        );
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn silence_then_burst_no_fire_when_burst_span_exceeds_window() {
        // silence_ok at index 0 (implicit), but the burst span
        // (events[threshold-1] - events[0]) exceeds burst_seconds.
        // Scanner advances through the buffer without a completion.
        let pattern = silence_then_burst_pattern(60, 5, 3);
        let buffer = timestamped_buffer(
            &pattern.pattern_id,
            &[
                1_700_000_010,
                1_700_000_020,
                1_700_000_030, // span 20s > burst_seconds=5
            ],
        );
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- Dedup for SequenceMatch -----------------------------------

    #[test]
    fn sequence_match_is_dedup_suppressed_within_window() {
        let pattern = cross_tier_sequence_pattern(vec![0, 3], 1);
        let buffer = tiered_buffer(&pattern.pattern_id, &[0, 3], 1_700_000_000, 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let mut dedup = empty_dedup();
        dedup
            .observe("cross-tier-escalation", "m-42", 1_700_000_050)
            .unwrap();
        let out = sequence_match(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none(), "dedup MUST suppress sequence re-fire");
    }

    // =====================================================================
    // T6: CumulativeOverBaseline evaluator tests
    // =====================================================================

    fn cumulative_count_pattern(threshold: u32, window_seconds: u32) -> PatternEntry {
        PatternEntry {
            pattern_id: "delete-storm-cumulative".into(),
            window_seconds: Some(window_seconds),
            threshold: Threshold::Count(threshold),
            scope: ScopePredicate::VerbResourceMandate {
                verb: VerbPredicate::Exact("delete".into()),
                resource_kind: Some("pod".into()),
                mandate_scope: MandateScope::default(),
            },
            action: Action::AutoRevoke,
            severity: Severity::High,
            firing_rule: FiringRule::CumulativeOverBaseline,
            firing_rule_companions: vec![],
        }
    }

    fn fanout_distinct_pattern(threshold: u32) -> PatternEntry {
        PatternEntry {
            pattern_id: "fanout-distinct-resources".into(),
            window_seconds: Some(600),
            threshold: Threshold::DistinctCount(threshold),
            scope: ScopePredicate::VerbFanout {
                verb: VerbPredicate::Exact("read".into()),
                mandate_scope: MandateScope::default(),
            },
            action: Action::Alert,
            severity: Severity::Medium,
            firing_rule: FiringRule::CumulativeOverBaseline,
            firing_rule_companions: vec![],
        }
    }

    fn buffer_with_resource_refs(pattern_id: &str, refs: &[&str]) -> PatternBuffer {
        let mut buf = PatternBuffer {
            pattern_id: pattern_id.into(),
            events: VecDeque::new(),
            sequence_tracker: None,
        };
        for (i, &r) in refs.iter().enumerate() {
            let mut event = base_event(
                &format!("e-{i}"),
                "m-42",
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                {
                    1_700_000_000_i64 + (i as i64)
                },
            );
            event.verb = "read".into();
            event.resource_ref = r.into();
            buf.events.push_back(event);
        }
        buf
    }

    // ----- Gates -----------------------------------------------------

    #[test]
    fn evaluate_cumulative_returns_none_for_first_match_pattern() {
        let mut pattern = cumulative_count_pattern(30, 3600);
        pattern.firing_rule = FiringRule::FirstMatch;
        let buffer = buffer_with(&pattern.pattern_id, 30, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn evaluate_cumulative_returns_none_for_sequence_threshold() {
        // CumulativeOverBaseline + Sequence is a non-normative pairing
        // Stage-7 would reject; evaluator returns None defensively.
        let mut pattern = cumulative_count_pattern(30, 3600);
        pattern.threshold = Threshold::Sequence(1);
        let buffer = buffer_with(&pattern.pattern_id, 30, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    #[test]
    fn evaluate_cumulative_returns_none_for_chain_depth_threshold() {
        let mut pattern = cumulative_count_pattern(30, 3600);
        pattern.threshold = Threshold::ChainDepth(4);
        let buffer = buffer_with(&pattern.pattern_id, 30, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- Count path -----------------------------------------------

    #[test]
    fn evaluate_cumulative_count_fires_exactly_at_threshold() {
        let pattern = cumulative_count_pattern(10, 3600);
        let buffer = buffer_with(&pattern.pattern_id, 10, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup)
            .expect("cumulative at-threshold MUST fire");
        assert_eq!(fire.pattern_id, "delete-storm-cumulative");
        assert_eq!(fire.firing_rule, FiringRule::CumulativeOverBaseline);
    }

    #[test]
    fn evaluate_cumulative_count_no_fire_below_threshold() {
        let pattern = cumulative_count_pattern(10, 3600);
        let buffer = buffer_with(&pattern.pattern_id, 9, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- DistinctCount path ---------------------------------------

    #[test]
    fn evaluate_cumulative_distinct_count_fires_at_threshold() {
        // Three distinct refs + threshold=3 → fire.
        let pattern = fanout_distinct_pattern(3);
        let buffer = buffer_with_resource_refs(&pattern.pattern_id, &["res-a", "res-b", "res-c"]);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let fire = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup)
            .expect("distinct-count at-threshold MUST fire");
        assert_eq!(fire.pattern_id, "fanout-distinct-resources");
    }

    #[test]
    fn evaluate_cumulative_distinct_count_duplicates_do_not_inflate() {
        // 10 events, but only 2 distinct refs → below threshold=3.
        let pattern = fanout_distinct_pattern(3);
        let mut refs = Vec::new();
        for _ in 0..5 {
            refs.push("res-a");
            refs.push("res-b");
        }
        let buffer = buffer_with_resource_refs(&pattern.pattern_id, &refs);
        assert_eq!(buffer.events.len(), 10);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none(), "duplicates MUST NOT inflate distinct count");
    }

    #[test]
    fn evaluate_cumulative_distinct_count_no_fire_below_threshold() {
        // 2 distinct refs below threshold=5.
        let pattern = fanout_distinct_pattern(5);
        let buffer = buffer_with_resource_refs(&pattern.pattern_id, &["res-a", "res-b"]);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let dedup = empty_dedup();
        let out = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none());
    }

    // ----- Dedup ----------------------------------------------------

    #[test]
    fn cumulative_is_dedup_suppressed_within_window() {
        let pattern = cumulative_count_pattern(10, 3600);
        let buffer = buffer_with(&pattern.pattern_id, 15, 1_700_000_000);
        let key = bucket_key_for(&pattern.pattern_id, "m-42");
        let mut dedup = empty_dedup();
        dedup
            .observe("delete-storm-cumulative", "m-42", 1_700_000_050)
            .unwrap();
        let out = cumulative(&pattern, &buffer, &key, 1, 1_700_000_100, &dedup);
        assert!(out.is_none(), "dedup MUST suppress cumulative re-fire");
    }
}
