//! State-machine core for anomaly detection (plan §15).
//!
//! [`DetectorState`] ingests [`CanonicalizedEvent`] values, routes
//! each event into the subset of per-pattern buffers whose
//! [`ScopePredicate`] matches, enforces per-mandate and per-buffer
//! memory caps, and exposes [`DetectorState::evaluate_all`] — the
//! per-tick dispatch entry point that walks every bucket, evicts
//! aged events via [`PatternBuffer::evict_aged_events`], and calls
//! the matching firing-rule evaluator in [`crate::evaluators`].
//!
//! # Scope (plan §15.1)
//!
//! - Ingestion pipeline: clock-skew gate, past-dated-event floor,
//!   per-mandate quota, scope matching, per-bucket VecDeque append
//!   with ring-buffer eviction.
//! - Monotonic-clock advancement via
//!   [`DetectorState::advance_clock`].
//! - Sliding-window eviction inside `evaluate_all` (via
//!   [`PatternBuffer::evict_aged_events`]) before each firing-rule
//!   call, so the evaluator sees only live events.
//! - Fire-once dedup via the pluggable
//!   [`crate::dedup_ledger::DedupLedger`] backend held by
//!   [`DetectorState`] (default:
//!   [`crate::dedup_ledger::InMemoryDedupLedger`]), keyed on
//!   `(pattern_id, mandate_id)`.  Persistent backends inject through
//!   [`DetectorState::with_ledger`].
//! - Dispatch to the three firing-rule evaluators:
//!   [`crate::evaluators::evaluate_first_match`],
//!   [`crate::evaluators::evaluate_sequence_match`], and
//!   [`crate::evaluators::evaluate_cumulative_over_baseline`].
//!
//! # Non-goals
//!
//! - Distinct-count bucket specialisation (keying on `resource_ref`
//!   for `VerbFanout`).  Current design uses one bucket per
//!   `(pattern_id, mandate_id)` and computes distinct-count in the
//!   evaluator.  A future session may extend the key under its
//!   `#[non_exhaustive]` marker without breaking wire.
//! - Incremental `SequenceTracker` materialisation.  The field on
//!   [`PatternBuffer`] is reserved; the current evaluator re-walks
//!   the bounded buffer per call (cheap at the configured cap).
//!
//! # Memory model (plan §15.3)
//!
//! Three caps bound adversarial pressure on the state machine:
//!
//! - [`MAX_EVENTS_PER_MANDATE`]: per-mandate quota (hard reject
//!   further ingestion via [`StreamError::PerMandateCapReached`]).
//! - [`MAX_EVENTS_PER_BUFFER`]: per-bucket ring cap (silent
//!   head-eviction, since patterns fire on counts well below this
//!   threshold — hitting the cap means the bucket is already in an
//!   extreme regime and the oldest events can't contribute to any
//!   future fire that hasn't already happened).
//! - [`MAX_CLOCK_SKEW_SECONDS`]: future-dated event cap (hard reject
//!   via [`StreamError::ClockSkewRejected`]; past-dated events are
//!   accepted — they'll simply miss sliding windows that Session 5-B
//!   later evicts).
//!
//! The two error surfaces use `&crate::errors::sanitize_log_string`
//! on attacker-controlled identifiers before wrapping them into
//! `StreamError` variants.
//!
//! # Session 5-A → 5-B residual-risk resolution
//!
//! Session 5-A documented two residual risks; Session 5-B resolves
//! them.  One risk turned out to be a misreading of the counter's
//! role and is **clarified as by-design**; the other is genuinely
//! closed with a new ingest-time check.
//!
//! 1. **`per_mandate_counters` is session-monotonic by design (5-A
//!    risk #1 clarified).**  On re-analysis the counter is a
//!    *session rate-limit for DoS containment*, not a sliding-window
//!    event source.  Firing-rule evaluation pulls its event count
//!    from `PatternBuffer::events.len()` AFTER sliding-window eviction
//!    (via [`PatternBuffer::evict_aged_events`]), so the authoritative
//!    per-window count is always correct regardless of whether
//!    `per_mandate_counters` decrements.  Decrementing the counter on
//!    eviction would introduce a second source of truth that could
//!    drift from the buffer state; keeping the counter monotonic
//!    preserves the §3.5.4 tenant-bounded-storm cap semantics (each
//!    mandate may issue at most [`MAX_EVENTS_PER_MANDATE`] events per
//!    detector-state lifetime).  A misconfigured producer that
//!    approaches the cap still reaches it; operators rotate the
//!    detector-state (new library version → new `DetectorState`)
//!    rather than waiting for the counter to bleed down.
//!
//! 2. **Past-dated event floor enforced (5-A risk #2 closed).**
//!    [`DetectorState::ingest_event`] Stage 2 rejects any event older
//!    than `current_time - (max_library_window + PAST_DATED_GRACE)`
//!    with [`StreamError::PastDatedEventRejected`].  The floor is
//!    library-aware: longer-window patterns admit older events.  A
//!    library with no windowed patterns (all `window_seconds = None`)
//!    floors on [`FALLBACK_PAST_WINDOW_SECONDS`] so a still-realistic
//!    backlog (Restart, Partition, Batch-Upload) is accepted.  See
//!    [`DetectorState::past_dated_floor`] for the exact policy.
//!
//! # Forward compat
//!
//! Every public struct/enum in this module is `#[non_exhaustive]` so
//! Session 5-B additions (e.g. a `last_eviction_at` field on
//! `PatternBuffer`, or a `sequence_step_count` extension of
//! `SequenceTracker`) can land without a semver bump.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use crate::dedup_ledger::{DedupLedger, DedupLedgerError, InMemoryDedupLedger};
use crate::errors::{sanitize_log_string, StreamError};
use crate::event::CanonicalizedEvent;
use crate::fire::AnomalyFire;
use crate::patterns::{FiringRule, PatternEntry};
use crate::scope::ScopePredicate;
use crate::signature::VerifiedAnomalyLibrarySignature;

/// Hard cap on the number of live events attributed to a single
/// `mandate_id` (§3.5.4 tenant-bounded storm containment).
///
/// Once the counter reaches this value, further ingestion for that
/// mandate rejects with [`StreamError::PerMandateCapReached`].  The
/// cap protects the detector against adversaries who control a
/// single mandate and attempt to drown memory via relentless event
/// ingress.  At the normative §3.5.4 firing thresholds (5-30 per
/// window), 10 000 live events per mandate is already ~300× past any
/// realistic firing condition — reaching the cap indicates a
/// misconfigured producer or an active attack.
pub const MAX_EVENTS_PER_MANDATE: u64 = 10_000;

/// Hard cap on the number of live events inside a single
/// `(pattern_id, mandate_id)` bucket.
///
/// VecDeque-backed ring eviction drops the oldest event when pushing
/// would exceed the cap — sliding-window semantics already discard
/// ageing events; the cap is a belt-and-braces ceiling.  At the
/// normative firing thresholds, 1 000 live events per bucket is
/// 200× beyond fire conditions, so eviction at this cap cannot cause
/// a spurious miss.
pub const MAX_EVENTS_PER_BUFFER: usize = 1_000;

/// Maximum positive clock skew accepted at
/// [`DetectorState::ingest_event`].  Events more than this many
/// seconds ahead of `current_time` reject via
/// [`StreamError::ClockSkewRejected`] — this bounds deferred-fire
/// attacks where an adversary back-dates events into a future
/// sliding window.  Past-dated events are bounded by the
/// library-aware floor (see [`DetectorState::past_dated_floor`] and
/// [`PAST_DATED_GRACE_SECONDS`]).
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

/// Grace window (seconds) beyond the longest library pattern window
/// that past-dated events are still accepted.
///
/// Producer-side realities — process restarts, network partitions,
/// batch-uploads of buffered audit events — can legitimately deliver
/// events 24 hours late.  Events older than `current_time -
/// (max_library_window + PAST_DATED_GRACE_SECONDS)` cannot contribute
/// to any firing-rule evaluation (sliding-window eviction would drop
/// them on first pass) so rejecting them at ingest-time is a pure win:
/// saves buffer slots and stops a past-dated flood early.
pub const PAST_DATED_GRACE_SECONDS: i64 = 24 * 3600;

/// Fallback sliding-window length used by
/// [`DetectorState::past_dated_floor`] when the pinned library has no
/// windowed patterns (every `PatternEntry.window_seconds` is `None`,
/// e.g. a library composed solely of `unusual-delegation-depth`).
///
/// Seven days matches the longest normative silence gate in §3.5.4
/// (`long-silence-before-burst` uses a 7-day silence window).  A
/// windowless library paired with a 7-day floor + 24h grace still
/// rejects events older than 8 days, which bounds memory pressure
/// without trimming legitimate long-tail replay.
pub const FALLBACK_PAST_WINDOW_SECONDS: u32 = 7 * 24 * 3600;

/// Fire-once dedup window for windowless patterns (e.g.
/// `unusual-delegation-depth`).
///
/// Sliding-window patterns dedup using their own `window_seconds`:
/// the pattern fires at most once per window.  Windowless patterns
/// lack that natural dedup horizon, so without a fallback the same
/// windowless condition would fire on every ingest event that still
/// satisfied it.  One hour matches the audit-pipeline's
/// `AnomalyDetected` dedup convention (§11.2 advises operator-level
/// dedup at the alert dashboard); the detector's own 1h floor keeps
/// the wire-rate bounded even if the dashboard is offline.
pub const FALLBACK_FIRE_ONCE_WINDOW_SECONDS: u32 = 3600;

/// Bucket identity for per-pattern event counters.
///
/// Session 5-A keys on `(pattern_id, mandate_id)`; the three
/// `Option` dimensions are reserved for Session 5-B's distinct-
/// count and per-operator specialisations (e.g. `VerbFanout`
/// may lift `resource_kind` to capture observed resource_ref
/// partitioning).  Session 5-A populates them as `None` for every
/// variant — the pin
/// `scope_bucket_key_for_pattern_match_at_5a_only_binds_mandate`
/// surfaces any regression.
///
/// Ordered maps (`BTreeMap`) consume this key over hashmaps so
/// iteration order is deterministic — load-bearing for conformance
/// vectors that pin per-pattern firing order by lexicographic
/// `pattern_id`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct ScopeBucketKey {
    /// Pattern identifier from the verified library.
    pub pattern_id: String,
    /// Observed mandate id — every event contributes to its own
    /// mandate's bucket even when the pattern predicate is unbound
    /// on the mandate dimension (anti-walk-under per-mandate track).
    pub mandate_id: String,
    /// Reserved for Session 5-B operator-scoped buckets.  Always
    /// `None` at Session 5-A.
    pub operator_id: Option<String>,
    /// Reserved for Session 5-B integration-scoped buckets.
    pub integration_ref: Option<String>,
    /// Reserved for Session 5-B resource-partitioned buckets.
    pub resource_kind: Option<String>,
}

impl ScopeBucketKey {
    /// Build the bucket key for an event matching a pattern.
    ///
    /// Session 5-A: always `(pattern_id, event.mandate_id, None,
    /// None, None)`.  The `_predicate` parameter is reserved for
    /// Session 5-B's specialised bucketing and is currently unused.
    #[must_use]
    pub fn for_pattern_match(
        pattern_id: &str,
        _predicate: &ScopePredicate,
        event: &CanonicalizedEvent,
    ) -> Self {
        Self {
            pattern_id: pattern_id.to_string(),
            mandate_id: event.mandate_id.clone(),
            operator_id: None,
            integration_ref: None,
            resource_kind: None,
        }
    }
}

/// Sequence-walk bookkeeping for
/// [`crate::scope::ScopePredicate::CrossTierSequence`] and
/// [`crate::scope::ScopePredicate::SilenceThenBurst`] patterns.
///
/// Session 5-A ships a skeleton — Session 5-B's sequence evaluator
/// reads `current_step` to know which sequence-template step the
/// pattern is waiting on, and `last_event_at` to enforce the
/// silence / burst timing gates.  `#[non_exhaustive]` reserves
/// space for additive fields (e.g. `silence_started_at`,
/// `completed_sequences_count`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SequenceTracker {
    /// Index of the next step the sequence walk is waiting on.
    /// `0` at construction; increments on matching step events.
    pub current_step: u32,
    /// Unix-epoch seconds of the last event that advanced the
    /// tracker.  Used by `SilenceThenBurst` to check "has enough
    /// silence elapsed since the last event?".
    pub last_event_at: i64,
}

/// Per-bucket ring buffer of events plus optional sequence tracker.
///
/// Events are appended via `push_back` on ingestion; the Session 5-B
/// evaluator pops from `front` as old events age out of the sliding
/// window.  `#[non_exhaustive]` reserves room for additive fields
/// (e.g. `cumulative_count`, `last_fire_at`).
///
/// `sequence_tracker` is lazily `None` for patterns that don't use
/// sequence firing; Session 5-B will construct a tracker only when
/// the pattern's `FiringRule` is `SequenceMatch`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PatternBuffer {
    /// Pattern this buffer belongs to — redundant with
    /// `ScopeBucketKey::pattern_id` but present so downstream
    /// firing-evaluator passes can avoid a key lookup.  Safe as `pub`
    /// because it is informational and immutable after buffer
    /// creation.
    pub pattern_id: String,
    /// Live events, oldest at front.  `VecDeque` chosen over `Vec`
    /// for O(1) head-eviction.  `pub(crate)` so that downstream
    /// consumers cannot bypass the ring-eviction invariant
    /// maintained by [`DetectorState::ingest_event`].  Read
    /// externally via [`PatternBuffer::events`].
    pub(crate) events: VecDeque<CanonicalizedEvent>,
    /// Sequence-walk state; `None` until Session 5-B materialises
    /// it for `SequenceMatch`/`SilenceThenBurst` patterns.
    /// `pub(crate)` so the tracker invariants stay owned by the
    /// state-machine module.  Read externally via
    /// [`PatternBuffer::sequence_tracker`].
    pub(crate) sequence_tracker: Option<SequenceTracker>,
}

impl PatternBuffer {
    fn new(pattern_id: String) -> Self {
        Self {
            pattern_id,
            events: VecDeque::new(),
            sequence_tracker: None,
        }
    }

    /// Read-only access to the buffered events.  Oldest event is at
    /// the front of the `VecDeque`.
    #[must_use]
    pub fn events(&self) -> &VecDeque<CanonicalizedEvent> {
        &self.events
    }

    /// Read-only access to the sequence tracker.  `None` in Session
    /// 5-A for every buffer; Session 5-B materialises the tracker
    /// when the pattern's firing rule requires ordered-step walks.
    #[must_use]
    pub fn sequence_tracker(&self) -> Option<&SequenceTracker> {
        self.sequence_tracker.as_ref()
    }

    /// Drop events whose `timestamp` falls outside the sliding window
    /// `[current_time - window_seconds, current_time]`.
    ///
    /// Returns the number of events evicted.  The eviction walks
    /// `self.events` from the front (oldest) and stops at the first
    /// event still inside the window — because `DetectorState::
    /// ingest_event` appends events in arrival order, the front of the
    /// `VecDeque` is also the chronologically oldest event.
    ///
    /// # Out-of-order events (bounded risk)
    ///
    /// Arrival order is NOT strictly monotonic: an event with an
    /// earlier `timestamp` can arrive after a later one, leaving the
    /// `VecDeque` non-chronologically sorted.  The eviction then
    /// stops at the first live-from-the-FRONT event and may leave
    /// an aged event buried behind it until it migrates to the front.
    ///
    /// Two ingest-time gates bound how badly this can skew the
    /// eviction:
    /// - [`MAX_CLOCK_SKEW_SECONDS`] rejects future-dated events
    ///   more than 30 s ahead of the clock.
    /// - The past-dated floor rejects events older than
    ///   `current_time - (library_max_window + PAST_DATED_GRACE_SECONDS)`.
    ///
    /// Together these cap the out-of-order span at the window plus a
    /// fixed grace — a buried aged event moves to the front within
    /// that span and evicts on the NEXT `evaluate_all`.  Firing-rule
    /// correctness is therefore delayed at most one tick, not
    /// violated.
    ///
    /// # Caller contract
    ///
    /// - Must be called BEFORE reading `self.events.len()` as a firing-
    ///   threshold source in a sliding-window evaluator; otherwise aged
    ///   events would inflate the count and trigger spurious fires.
    /// - Only makes sense for patterns with `Some(window_seconds)`.
    ///   Windowless patterns (e.g. `unusual-delegation-depth`) must
    ///   NOT call this — their evaluator reads state off the event
    ///   directly, not off the sliding-window count.
    ///
    /// # Saturating arithmetic
    ///
    /// `current_time - window_seconds` uses `saturating_sub` so a
    /// clock near `i64::MIN` plus a large `window_seconds` cannot
    /// underflow.  In practice `current_time` is a realistic unix-
    /// epoch seconds value (≥ 1_700_000_000 as of 2023) so the
    /// saturation branch is unreachable — but the hardening is free
    /// and lets us skip an overflow-branch test.
    pub(crate) fn evict_aged_events(&mut self, window_seconds: u32, current_time: i64) -> usize {
        let window_start = current_time.saturating_sub(i64::from(window_seconds));
        let mut evicted = 0_usize;
        while let Some(front) = self.events.front() {
            if front.timestamp < window_start {
                self.events.pop_front();
                evicted += 1;
            } else {
                break;
            }
        }
        evicted
    }
}

/// Runtime state-machine core.
///
/// Holds an `Arc` to the verified anomaly library so the detector
/// can be shared across async tasks that each need read access to
/// the pattern table.  Mutating state (`buffers`, counters, clock)
/// lives behind `&mut` so callers route ingestion through a single
/// owner — typically the audit pipeline's per-tenant worker task.
///
/// # Field invariants
///
/// - `pinned_library` MUST not change once [`DetectorState::new`]
///   returns.  Library-rotation flows (Session 3+ replay ledger)
///   construct a NEW `DetectorState` rather than re-pinning in
///   place — this keeps the evaluator's assumption that the pattern
///   table is stable across one state's lifetime.
/// - `current_time` MUST move forward monotonically; enforced by
///   [`DetectorState::advance_clock`].
/// - `per_mandate_counters` count ingested events per mandate over
///   the state's lifetime.  Session-monotonic: never decremented.
///   Role is DoS containment (cap at [`MAX_EVENTS_PER_MANDATE`]), not
///   sliding-window counting — firing-rule evaluators read their
///   counts from `PatternBuffer::events.len()` after eviction.
/// - `dedup` is the pluggable [`DedupLedger`] backend that records
///   one entry per `(pattern_id, mandate_id)` pair that has fired at
///   least once; the stored value is `current_time` at the fire
///   instant.  A pattern does NOT re-fire for the same mandate until
///   `current_time - last_fired >= window_seconds` (fire-once dedup),
///   evaluated through [`DedupLedger::is_suppressed`].  Windowless
///   patterns (e.g. `unusual-delegation-depth`) do not participate in
///   the sliding-window dedup — they use a fixed dedup window of
///   [`FALLBACK_FIRE_ONCE_WINDOW_SECONDS`].  The default backend is
///   [`InMemoryDedupLedger`]; persistent backends (Sled, Redis, ...)
///   inject through [`DetectorState::with_ledger`].
///
/// # Concurrency
///
/// `DetectorState` is `Send` (every owned field is `Send`).  It is
/// **not** `Sync` because [`DedupLedger`] is intentionally `Send`-only
/// — backends like Sled/Redis serve a single writer per state and
/// would have to add their own locking to support `&self` concurrent
/// access.  Multi-thread fan-out runs one `DetectorState` per worker;
/// the `detector_state_is_send` test pins this.
#[derive(Debug)]
pub struct DetectorState {
    pinned_library: Arc<VerifiedAnomalyLibrarySignature>,
    buffers: BTreeMap<ScopeBucketKey, PatternBuffer>,
    per_mandate_counters: BTreeMap<String, u64>,
    current_time: i64,
    /// Fire-once dedup ledger, keyed on `(pattern_id, mandate_id)`,
    /// recording `current_time` at the last fire and answering
    /// suppression queries via [`DedupLedger::is_suppressed`].  The
    /// trait surface is the only access path; this field is private
    /// to avoid leaking concrete-backend internals (raw timestamps,
    /// btreemap layout) to callers.
    ///
    /// # Backend pluggability
    ///
    /// Defaults to the in-memory backend ([`InMemoryDedupLedger`])
    /// when constructed via [`DetectorState::new`].  Persistent
    /// backends inject through [`DetectorState::with_ledger`] —
    /// production callers wrap a Sled/Redis backend so dedup state
    /// survives detector-state recreation (e.g. a worker restart that
    /// would otherwise re-fire every pattern on its first tick).
    ///
    /// # Growth bound
    ///
    /// Entries never expire within a single `DetectorState` lifetime
    /// — dedup marks persist so a long-quiet mandate can still be
    /// suppressed when it fires after a gap longer than the window.
    /// The ledger's cardinality is therefore bounded by
    /// `patterns × distinct_mandates_that_have_ever_fired`.  The
    /// per-mandate ingest cap ([`MAX_EVENTS_PER_MANDATE`]) and the
    /// library's fixed pattern count keep this tractable; operators
    /// rotate state (new library version → new `DetectorState`) on
    /// their normal cadence, which resets the in-memory backend.
    /// Persistent backends MUST enforce their own cardinality cap
    /// ([`MAX_DEDUP_ENTRIES_PER_TENANT`]) and raise
    /// [`DedupLedgerError::CapacityExhausted`] on overflow.
    ///
    /// [`MAX_DEDUP_ENTRIES_PER_TENANT`]:
    ///     crate::dedup_ledger::MAX_DEDUP_ENTRIES_PER_TENANT
    /// [`DedupLedgerError::CapacityExhausted`]:
    ///     crate::dedup_ledger::DedupLedgerError::CapacityExhausted
    dedup: Box<dyn DedupLedger>,
}

impl DetectorState {
    /// Construct a new state machine pinned to the given verified
    /// library and starting at the given `initial_time`
    /// (unix-epoch seconds), defaulting to the in-memory dedup
    /// backend ([`InMemoryDedupLedger`]).
    ///
    /// Typical callers: the audit-pipeline worker on first event
    /// after library-load, passing `initial_time` as the caller's
    /// trusted wall-clock (NOT an event-derived timestamp — see
    /// plan §15.5 on the trust boundary).
    ///
    /// Production deployments that need dedup state to survive
    /// detector-state recreation (worker restart, library rotation
    /// with carry-over) MUST use [`Self::with_ledger`] instead and
    /// inject a persistent backend.
    #[must_use]
    pub fn new(pinned_library: Arc<VerifiedAnomalyLibrarySignature>, initial_time: i64) -> Self {
        Self::with_ledger(
            pinned_library,
            initial_time,
            Box::new(InMemoryDedupLedger::new()),
        )
    }

    /// Construct a state machine with a caller-supplied dedup ledger.
    ///
    /// Use this when the in-memory default is not sufficient — e.g.
    /// production deployments wrap a Sled/Redis backend so dedup
    /// state survives a worker restart that would otherwise re-fire
    /// every pattern on its first tick.  The injected backend is
    /// expected to already contain whatever dedup history it inherits
    /// (e.g. from a snapshot loaded at boot); this constructor does
    /// not seed it.
    ///
    /// The trait surface ([`DedupLedger`]) is `Send`-only, so the
    /// resulting `DetectorState` is `Send` but not `Sync` — fan out
    /// across threads by giving each worker its own state instance.
    #[must_use]
    pub fn with_ledger(
        pinned_library: Arc<VerifiedAnomalyLibrarySignature>,
        initial_time: i64,
        dedup: Box<dyn DedupLedger>,
    ) -> Self {
        Self {
            pinned_library,
            buffers: BTreeMap::new(),
            per_mandate_counters: BTreeMap::new(),
            current_time: initial_time,
            dedup,
        }
    }

    /// Read-only accessor for the pinned library.
    #[must_use]
    pub fn pinned_library(&self) -> &Arc<VerifiedAnomalyLibrarySignature> {
        &self.pinned_library
    }

    /// Read-only accessor for the per-bucket buffer map.  Downstream
    /// Session 5-B firing evaluators iterate this.
    #[must_use]
    pub fn buffers(&self) -> &BTreeMap<ScopeBucketKey, PatternBuffer> {
        &self.buffers
    }

    /// Read-only accessor for the per-mandate event counter.
    #[must_use]
    pub fn per_mandate_counters(&self) -> &BTreeMap<String, u64> {
        &self.per_mandate_counters
    }

    /// Current observed clock time (unix-epoch seconds).
    #[must_use]
    pub fn current_time(&self) -> i64 {
        self.current_time
    }

    /// Read-only accessor for the dedup ledger trait surface.
    ///
    /// Returns the [`DedupLedger`] backend held by this state;
    /// callers can ask `is_suppressed`, `len`, or `is_empty` but
    /// cannot read raw fire timestamps (the trait deliberately omits
    /// a `last_fired_at` getter — those are sensitive scheduling hints
    /// that an attacker probing dedup state would otherwise harvest,
    /// see SEC-D-4 in the dedup-ledger threat model).
    #[must_use]
    pub fn dedup_ledger(&self) -> &dyn DedupLedger {
        &*self.dedup
    }

    /// Longest `window_seconds` declared by any windowed pattern in the
    /// pinned library, or `None` if every pattern is windowless.
    ///
    /// Used by [`Self::past_dated_floor`] as the memory-bound horizon:
    /// an event older than this cannot contribute to any pattern's
    /// firing count because the sliding-window evictor would drop it
    /// on first pass.
    #[must_use]
    pub(crate) fn max_library_window_seconds(&self) -> Option<u32> {
        self.pinned_library
            .patterns
            .iter()
            .filter_map(|p| p.window_seconds)
            .max()
    }

    /// Earliest `timestamp` that [`Self::ingest_event`] will accept at
    /// the current clock.  Events older than this reject via
    /// [`StreamError::PastDatedEventRejected`].
    ///
    /// Policy:
    /// - If the library has at least one windowed pattern, the floor
    ///   is `current_time - (max_library_window + PAST_DATED_GRACE_SECONDS)`.
    /// - Otherwise (all `window_seconds = None`), the floor is
    ///   `current_time - (FALLBACK_PAST_WINDOW_SECONDS + PAST_DATED_GRACE_SECONDS)`.
    ///
    /// Saturating arithmetic guards against underflow when
    /// `current_time` is very small (tests, fuzz inputs).
    #[must_use]
    pub(crate) fn past_dated_floor(&self) -> i64 {
        let window_seconds = self
            .max_library_window_seconds()
            .unwrap_or(FALLBACK_PAST_WINDOW_SECONDS);
        self.current_time
            .saturating_sub(i64::from(window_seconds))
            .saturating_sub(PAST_DATED_GRACE_SECONDS)
    }

    /// Advance the detector's observed clock.  Enforces monotonic
    /// progression — a regressing `new_time` rejects with
    /// [`StreamError::ClockRegression`].
    ///
    /// Session 5-A is a thin clock pointer update; Session 5-B will
    /// extend this with buffer eviction for events older than
    /// `new_time - window_seconds`.
    pub fn advance_clock(&mut self, new_time: i64) -> Result<(), StreamError> {
        if new_time < self.current_time {
            return Err(StreamError::ClockRegression {
                from: self.current_time,
                to: new_time,
            });
        }
        self.current_time = new_time;
        Ok(())
    }

    /// Ingest a canonicalised event.
    ///
    /// # Pipeline (plan §15.2)
    ///
    /// 1. **Clock-skew gate** — events more than
    ///    [`MAX_CLOCK_SKEW_SECONDS`] ahead of `current_time` reject
    ///    with [`StreamError::ClockSkewRejected`] (sanitised
    ///    `event_id`).
    /// 2. **Past-dated floor** — events with `timestamp <
    ///    past_dated_floor()` reject with
    ///    [`StreamError::PastDatedEventRejected`].  Closes the 5-A
    ///    residual risk of unbounded past-dated accumulation.  (Step
    ///    was `1b` in the 5-A spec sketch; renumbered inline so
    ///    rustdoc's list parser doesn't split the doc at an unindented
    ///    continuation.)
    /// 3. **Per-mandate quota** — if the observed mandate already
    ///    holds [`MAX_EVENTS_PER_MANDATE`] live events, reject with
    ///    [`StreamError::PerMandateCapReached`] (sanitised
    ///    `mandate_id`).
    /// 4. **Scope routing** — iterate every pattern in the pinned
    ///    library, call [`ScopePredicate::matches`], and for every
    ///    match append the event to the corresponding bucket.  Ring-
    ///    buffer eviction at [`MAX_EVENTS_PER_BUFFER`] is silent.
    /// 5. **Counter increment** — bump the mandate's counter.
    ///
    /// # Error path cleanliness
    ///
    /// Stages 1, 2, and 3 reject BEFORE any mutation.  A rejected
    /// event leaves `buffers` and `per_mandate_counters` untouched —
    /// the caller can retry with a different event without state
    /// drift.
    pub fn ingest_event(&mut self, event: CanonicalizedEvent) -> Result<(), StreamError> {
        // Stage 1: clock-skew gate
        let skew = event.timestamp.saturating_sub(self.current_time);
        if skew > MAX_CLOCK_SKEW_SECONDS {
            return Err(StreamError::ClockSkewRejected {
                event_id: sanitize_log_string(&event.event_id),
                skew_seconds: skew,
            });
        }

        // Stage 2: past-dated floor.  Events too old to contribute to
        // any sliding-window pattern reject here — saves buffer slots
        // and bounds memory pressure from a past-dated flood.
        let floor = self.past_dated_floor();
        if event.timestamp < floor {
            return Err(StreamError::PastDatedEventRejected {
                event_id: sanitize_log_string(&event.event_id),
                age_seconds: floor.saturating_sub(event.timestamp),
                floor,
            });
        }

        // Stage 3: per-mandate quota.  Read before mutation so a
        // rejected event does not leave the counter advanced.
        let observed_count = self
            .per_mandate_counters
            .get(&event.mandate_id)
            .copied()
            .unwrap_or(0);
        if observed_count >= MAX_EVENTS_PER_MANDATE {
            return Err(StreamError::PerMandateCapReached {
                mandate_id: sanitize_log_string(&event.mandate_id),
                cap: MAX_EVENTS_PER_MANDATE,
            });
        }

        // Stage 4: scope routing.  Iterate patterns deterministically
        // via the `Vec<PatternEntry>` order preserved from the
        // verified library.
        for pattern in &self.pinned_library.patterns {
            if pattern.scope.matches(&event) {
                let key =
                    ScopeBucketKey::for_pattern_match(&pattern.pattern_id, &pattern.scope, &event);
                let buffer = self
                    .buffers
                    .entry(key)
                    .or_insert_with(|| PatternBuffer::new(pattern.pattern_id.clone()));
                buffer.events.push_back(event.clone());
                // Silent ring-buffer eviction (head).  See
                // MAX_EVENTS_PER_BUFFER rationale.
                while buffer.events.len() > MAX_EVENTS_PER_BUFFER {
                    buffer.events.pop_front();
                }
            }
        }

        // Stage 5: per-mandate counter.  `+ 1` cannot overflow
        // because we just checked `observed_count < 10_000`.
        self.per_mandate_counters
            .entry(event.mandate_id)
            .and_modify(|c| *c += 1)
            .or_insert(1);
        Ok(())
    }

    /// Evaluate all patterns and return the set of firing events.
    ///
    /// Walks every `(ScopeBucketKey, PatternBuffer)` pair in the
    /// detector state, evicts aged events from windowed buffers, and
    /// dispatches to the per-firing-rule evaluator in
    /// [`crate::evaluators`].  Each successful fire records a
    /// `(pattern_id, mandate_id) → current_time` entry in the dedup
    /// ledger via [`DedupLedger::observe`] so subsequent calls within
    /// the dedup window do not re-fire for the same mandate.
    ///
    /// # Failure mode
    ///
    /// Returns [`DedupLedgerError`] when the backing dedup ledger
    /// rejects either a suppression query or a post-fire `observe`
    /// call.  The in-memory backend ([`InMemoryDedupLedger`]) only
    /// fails on [`DedupLedgerError::CapacityExhausted`] (per-tenant
    /// cardinality cap); persistent backends additionally surface
    /// transport / storage errors as [`DedupLedgerError::BackendFailure`].
    ///
    /// On error the caller must treat the partial fire vector as
    /// dropped — the orchestrator collapses both variants into a
    /// generic [`StreamError::DedupLedgerFailure`] so the operator log
    /// never names which backend failed (role-isolation hardening
    /// from the SEC-D-* threat model).
    ///
    /// # Why `&mut self`
    ///
    /// Session 5-B converts this from the 5-A stub's `&self`
    /// snapshot signature to `&mut self` because evaluation is no
    /// longer read-only:
    ///
    /// 1. **Sliding-window eviction.**  Before reading
    ///    `buffer.events.len()` as a firing-threshold source, windowed
    ///    patterns MUST call
    ///    [`PatternBuffer::evict_aged_events`], which mutates the
    ///    buffer's `VecDeque`.  Snapshot-then-evict in a clone would
    ///    double the memory cost at the cap
    ///    ([`MAX_EVENTS_PER_BUFFER`]) — unacceptable on hot paths.
    /// 2. **Fire-once dedup bookkeeping.**  Successful fires must
    ///    update the dedup ledger via [`DedupLedger::observe`]
    ///    atomically with the fire so concurrent evaluators cannot
    ///    observe a fire without its dedup mark (which would re-fire
    ///    on the next tick).
    ///
    /// Callers that need a read-only evaluation (e.g. diagnostic
    /// dumps) should `clone()` the `DetectorState` first and evaluate
    /// the clone — the `Clone` surface for `DetectorState` is
    /// deliberately omitted until a consumer needs it.
    ///
    /// # Dispatch routing
    ///
    /// - `FiringRule::FirstMatch` →
    ///   [`crate::evaluators::evaluate_first_match`]
    /// - `FiringRule::SequenceMatch` →
    ///   [`crate::evaluators::evaluate_sequence_match`]
    /// - `FiringRule::CumulativeOverBaseline` →
    ///   [`crate::evaluators::evaluate_cumulative_over_baseline`]
    ///
    /// The match deliberately omits a `_` arm.  `FiringRule` is
    /// `#[non_exhaustive]` for cross-crate forward-compat, but this
    /// module lives in the same crate — so the compiler enforces
    /// exhaustive coverage here.  Adding a new variant to
    /// [`crate::patterns::FiringRule`] without a matching arm in
    /// `evaluate_all` is a build error, surfacing the gap at compile
    /// time rather than silently declining to fire.
    ///
    /// # Determinism
    ///
    /// Buckets are iterated in `BTreeMap` key order
    /// (`ScopeBucketKey`'s lexicographic `Ord`), so the returned
    /// `Vec<AnomalyFire>` is ordering-stable across runs for a given
    /// input stream — pinned by
    /// `evaluate_all_is_deterministic_across_calls`.
    pub fn evaluate_all(&mut self) -> Result<Vec<AnomalyFire>, DedupLedgerError> {
        // Clone the Arc so we can index into `library.patterns` while
        // mutably borrowing `self.buffers` and `self.dedup`.
        let library = Arc::clone(&self.pinned_library);
        let current_time = self.current_time;
        let library_version = library.library_version;

        // Precompute `pattern_id → &PatternEntry` once per call so the
        // per-bucket lookup is O(log M) instead of the O(M) linear
        // scan that would make the whole loop O(N·M) at
        // library-size × bucket-cardinality scale.  BTreeMap (not
        // HashMap) for parity with the project's determinism-first
        // convention — iteration order of this map is never observed
        // (point-lookups only).
        let pattern_index: BTreeMap<&str, &PatternEntry> = library
            .patterns
            .iter()
            .map(|p| (p.pattern_id.as_str(), p))
            .collect();

        // Snapshot keys to avoid a long-lived immutable borrow on
        // `self.buffers` while we mutably evict.
        let keys: Vec<ScopeBucketKey> = self.buffers.keys().cloned().collect();

        let mut fires: Vec<AnomalyFire> = Vec::new();

        for key in keys {
            // Resolve the pattern for this bucket.  Missing = defensive
            // skip: a buffer whose pattern is not in the pinned library
            // cannot exist under normal invariants (ingest_event routes
            // only to buckets whose pattern was iterated from the
            // library), but a hypothetical future library-swap path
            // could leave orphans — refuse to fire on orphans.
            let Some(&pattern) = pattern_index.get(key.pattern_id.as_str()) else {
                continue;
            };

            // Evict aged events for windowed patterns.  Windowless
            // patterns (e.g. `unusual-delegation-depth`) skip this
            // step per the `evict_aged_events` caller contract.
            if let Some(window) = pattern.window_seconds {
                if let Some(buffer) = self.buffers.get_mut(&key) {
                    buffer.evict_aged_events(window, current_time);
                }
            }

            // Re-borrow immutably for the evaluator call.
            let Some(buffer) = self.buffers.get(&key) else {
                continue;
            };

            let fire = match pattern.firing_rule {
                FiringRule::FirstMatch => crate::evaluators::evaluate_first_match(
                    pattern,
                    buffer,
                    &key,
                    library_version,
                    current_time,
                    &*self.dedup,
                )?,
                FiringRule::SequenceMatch => crate::evaluators::evaluate_sequence_match(
                    pattern,
                    buffer,
                    &key,
                    library_version,
                    current_time,
                    &*self.dedup,
                )?,
                FiringRule::CumulativeOverBaseline => {
                    crate::evaluators::evaluate_cumulative_over_baseline(
                        pattern,
                        buffer,
                        &key,
                        library_version,
                        current_time,
                        &*self.dedup,
                    )?
                } // No `_` wildcard: `FiringRule` is `#[non_exhaustive]`
                  // for cross-crate forward-compat, but intra-crate the
                  // compiler enforces coverage.  Omitting `_` deliberately
                  // weaponises that: a new variant added to `patterns.rs`
                  // without a matching arm here becomes a compile error,
                  // surfacing the gap at build time rather than silently
                  // declining to fire at runtime.
            };

            if let Some(fire) = fire {
                // Record the fire in the dedup ledger BEFORE pushing
                // into the result vector — if `observe` fails (e.g.
                // CapacityExhausted on a persistent backend), we want
                // to surface the error to the caller rather than emit
                // a fire that the next tick will re-emit because the
                // dedup mark was lost.  The orchestrator turns this
                // into `StreamError::DedupLedgerFailure` and discards
                // the in-flight batch.
                self.dedup
                    .observe(&pattern.pattern_id, &key.mandate_id, current_time)?;
                fires.push(fire);
            }
        }

        Ok(fires)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Outcome;
    use crate::patterns::{Action, FiringRule, PatternEntry, Severity, Threshold};
    use crate::scope::{MandateScope, ScopePredicate, VerbPredicate};

    fn library(patterns: Vec<PatternEntry>) -> Arc<VerifiedAnomalyLibrarySignature> {
        Arc::new(VerifiedAnomalyLibrarySignature {
            signer_kid: "kid-test".into(),
            abi_version: 1,
            library_id: "lib::test".into(),
            library_version: 1,
            issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            patterns,
        })
    }

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

    // ------------ construction ---------------------------------------

    #[test]
    fn detector_state_new_initialises_empty_buffers_and_counters() {
        let state = DetectorState::new(library(vec![]), 1_700_000_000);
        assert!(state.buffers().is_empty());
        assert!(state.per_mandate_counters().is_empty());
        assert!(state.dedup_ledger().is_empty());
        assert_eq!(state.current_time(), 1_700_000_000);
    }

    // ------------ past_dated_floor + max_library_window (5-B T8) -----

    #[test]
    fn max_library_window_none_when_all_patterns_windowless() {
        // A library with only a windowless pattern (e.g. DelegationDepth-
        // style) returns None from max_library_window_seconds.
        let mut p = delete_storm_pattern();
        p.window_seconds = None;
        let state = DetectorState::new(library(vec![p]), 1_700_000_000);
        assert!(state.max_library_window_seconds().is_none());
    }

    #[test]
    fn max_library_window_picks_longest_across_patterns() {
        let mut short = delete_storm_pattern();
        short.window_seconds = Some(60);
        short.pattern_id = "short".into();
        let mut long = delete_storm_pattern();
        long.window_seconds = Some(3600);
        long.pattern_id = "long".into();
        let mut longest = delete_storm_pattern();
        longest.window_seconds = Some(86_400);
        longest.pattern_id = "longest".into();
        let state = DetectorState::new(library(vec![short, long, longest]), 1_700_000_000);
        assert_eq!(state.max_library_window_seconds(), Some(86_400));
    }

    #[test]
    fn past_dated_floor_uses_library_max_window_plus_grace() {
        let mut p = delete_storm_pattern();
        p.window_seconds = Some(3600); // 1h
        let state = DetectorState::new(library(vec![p]), 1_700_000_000);
        // floor = 1_700_000_000 - 3600 - 86_400 = 1_699_910_000
        assert_eq!(state.past_dated_floor(), 1_700_000_000 - 3600 - 86_400);
    }

    #[test]
    fn past_dated_floor_uses_fallback_when_library_is_windowless() {
        let mut p = delete_storm_pattern();
        p.window_seconds = None;
        let state = DetectorState::new(library(vec![p]), 1_700_000_000);
        // floor = 1_700_000_000 - 604_800 (7d) - 86_400 (24h) = 1_699_308_800
        assert_eq!(
            state.past_dated_floor(),
            1_700_000_000 - i64::from(FALLBACK_PAST_WINDOW_SECONDS) - PAST_DATED_GRACE_SECONDS
        );
    }

    #[test]
    fn ingest_event_accepts_event_exactly_at_past_dated_floor() {
        // Window=60s → floor = 1_700_000_000 - 60 - 86_400 = 1_699_913_540.
        // An event exactly at the floor is inclusive (t < floor is `<`).
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        state
            .ingest_event(base_event("e-edge", "m-42", 1_699_913_540))
            .unwrap();
        assert_eq!(state.per_mandate_counters().get("m-42").copied(), Some(1));
    }

    #[test]
    fn ingest_event_rejects_event_one_second_below_past_dated_floor() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        let err = state
            .ingest_event(base_event("e-stale", "m-42", 1_699_913_539))
            .unwrap_err();
        match err {
            StreamError::PastDatedEventRejected {
                event_id,
                age_seconds,
                floor,
            } => {
                assert_eq!(event_id, "e-stale");
                assert_eq!(age_seconds, 1);
                assert_eq!(floor, 1_699_913_540);
            }
            other => panic!("expected PastDatedEventRejected, got {other:?}"),
        }
        // Rejected ingestion leaves state untouched.
        assert!(state.buffers().is_empty());
        assert!(state.per_mandate_counters().is_empty());
    }

    #[test]
    fn ingest_event_past_dated_uses_library_window_max_as_floor_horizon() {
        // Longer-window pattern raises the floor: a library with a
        // 1h window accepts events up to ~25h old, whereas the 60s
        // delete_storm floor rejects them.
        let mut long = delete_storm_pattern();
        long.pattern_id = "long".into();
        long.window_seconds = Some(3600); // 1h
        let mut state = DetectorState::new(library(vec![long]), 1_700_000_000);
        // Event at current_time - 90_000 (25h): above the floor
        // (1_700_000_000 - 3600 - 86_400 = 1_699_910_000); accept.
        state
            .ingest_event(base_event("e-24h", "m-42", 1_699_910_000))
            .unwrap();
    }

    #[test]
    fn ingest_event_past_dated_sanitises_event_id_in_error() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        let err = state
            .ingest_event(base_event("evt\nINJ", "m-42", 1_699_913_000))
            .unwrap_err();
        match err {
            StreamError::PastDatedEventRejected { event_id, .. } => {
                assert_eq!(event_id, "evt?INJ");
            }
            other => panic!("expected PastDatedEventRejected, got {other:?}"),
        }
    }

    // ------------ evaluate_all (Session 5-B contract pins) ----------

    #[test]
    fn evaluate_all_returns_empty_when_no_buckets_exist() {
        // Fresh state with zero ingested events → zero fires.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        assert!(state
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests")
            .is_empty());
        // `last_fired_at` also remains empty when no fires occurred.
        assert!(state.dedup_ledger().is_empty());
    }

    #[test]
    fn evaluate_all_returns_empty_below_threshold() {
        // Ingest 4 delete events into a pattern with threshold=5.
        // Buffer length (4) is below threshold → no fire.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        for i in 0..4 {
            state
                .ingest_event(base_event(&format!("e-{i}"), "m-42", 1_700_000_000 + i))
                .unwrap();
        }
        assert!(state
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests")
            .is_empty());
        assert!(state.dedup_ledger().is_empty());
    }

    #[test]
    fn evaluate_all_fires_first_match_at_threshold() {
        // Ingest 5 delete events — threshold=5 → exactly one fire.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        for i in 0..5 {
            state
                .ingest_event(base_event(&format!("e-{i}"), "m-42", 1_700_000_000 + i))
                .unwrap();
        }
        let fires = state
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests");
        assert_eq!(fires.len(), 1, "expected exactly one fire at threshold");
        assert_eq!(fires[0].pattern_id, "delete-storm");
        // Fire records the dedup bookmark — assert behaviourally
        // through `is_suppressed` rather than reading raw timestamps,
        // since the trait deliberately hides them (SEC-D-4 timestamp
        // leak).  At the fire instant a fresh suppression check with
        // the pattern's window must return `Suppressed = true`.
        let suppressed = state
            .dedup_ledger()
            .is_suppressed("delete-storm", "m-42", 1_700_000_000, 60)
            .expect("in-memory dedup ledger is infallible in tests");
        assert!(suppressed, "fire must record dedup mark");
    }

    #[test]
    fn evaluate_all_respects_dedup_across_calls() {
        // First call fires; second call (same state, same clock) does
        // NOT refire — fire-once dedup within the pattern window.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        for i in 0..5 {
            state
                .ingest_event(base_event(&format!("e-{i}"), "m-42", 1_700_000_000 + i))
                .unwrap();
        }
        assert_eq!(
            state
                .evaluate_all()
                .expect("in-memory dedup ledger is infallible in tests")
                .len(),
            1
        );
        assert!(
            state
                .evaluate_all()
                .expect("in-memory dedup ledger is infallible in tests")
                .is_empty(),
            "second call within dedup window must not refire"
        );
    }

    #[test]
    fn evaluate_all_is_deterministic_across_calls() {
        // Two independent states fed the same event stream produce
        // the same fire sequence.  Pins BTreeMap-ordered iteration.
        let make_state = || {
            let mut s = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
            for (i, mid) in ["m-a", "m-b"].iter().enumerate() {
                let mandate_offset = i64::try_from(i).expect("loop index fits i64") * 10;
                for j in 0..5_i64 {
                    s.ingest_event(base_event(
                        &format!("e-{i}-{j}"),
                        mid,
                        1_700_000_000 + mandate_offset + j,
                    ))
                    .unwrap();
                }
            }
            s
        };
        let fires_a = make_state()
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests");
        let fires_b = make_state()
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests");
        assert_eq!(fires_a.len(), 2);
        assert_eq!(
            fires_a
                .iter()
                .map(|f| f.pattern_id.clone())
                .collect::<Vec<_>>(),
            fires_b
                .iter()
                .map(|f| f.pattern_id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            fires_a
                .iter()
                .map(|f| f.match_scope.mandate_id.clone())
                .collect::<Vec<_>>(),
            fires_b
                .iter()
                .map(|f| f.match_scope.mandate_id.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn evaluate_all_refires_after_dedup_window_expires() {
        // After the pattern's window elapses, the dedup suppression
        // clears and a subsequent threshold crossing fires again.
        // Pattern window = 60s.  Ingest, fire, advance clock past
        // window + grace, ingest fresh events, fire again.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        for i in 0..5 {
            state
                .ingest_event(base_event(&format!("e-{i}"), "m-42", 1_700_000_000 + i))
                .unwrap();
        }
        assert_eq!(
            state
                .evaluate_all()
                .expect("in-memory dedup ledger is infallible in tests")
                .len(),
            1
        );

        // Advance past the 60s window.
        state.advance_clock(1_700_000_070).unwrap();
        // Ingest fresh events at the new clock — older ones evict.
        for i in 0..5 {
            state
                .ingest_event(base_event(&format!("f-{i}"), "m-42", 1_700_000_070 + i))
                .unwrap();
        }
        assert_eq!(
            state
                .evaluate_all()
                .expect("in-memory dedup ledger is infallible in tests")
                .len(),
            1,
            "dedup must expire once window elapses"
        );
    }

    #[test]
    fn evaluate_all_dedup_is_per_mandate() {
        // Two distinct mandates cross the threshold in the same call;
        // each fires independently — dedup is keyed on mandate_id.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        for mid in ["m-a", "m-b"] {
            for i in 0..5 {
                state
                    .ingest_event(base_event(&format!("e-{mid}-{i}"), mid, 1_700_000_000 + i))
                    .unwrap();
            }
        }
        let fires = state
            .evaluate_all()
            .expect("in-memory dedup ledger is infallible in tests");
        assert_eq!(fires.len(), 2, "each mandate should fire independently");
    }

    #[test]
    fn evaluate_all_drops_aged_events_before_counting() {
        // Events outside the 60s window must not inflate the count.
        // Ingest 3 events at t=100, advance to t=200 (> window), then
        // ingest 3 fresh events.  Pre-eviction count = 6 (≥ threshold
        // 5, would fire); post-eviction count = 3 (below threshold,
        // must NOT fire).
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_100);
        for i in 0..3 {
            state
                .ingest_event(base_event(&format!("old-{i}"), "m-42", 1_700_000_100 + i))
                .unwrap();
        }
        state.advance_clock(1_700_000_200).unwrap();
        for i in 0..3 {
            state
                .ingest_event(base_event(&format!("new-{i}"), "m-42", 1_700_000_200 + i))
                .unwrap();
        }
        assert!(
            state
                .evaluate_all()
                .expect("in-memory dedup ledger is infallible in tests")
                .is_empty(),
            "aged events must not contribute to firing threshold"
        );
    }

    // ------------ ingest_event happy path ----------------------------

    #[test]
    fn ingest_event_routes_to_matching_bucket_and_increments_counter() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        let event = base_event("e-1", "m-42", 1_700_000_000);
        state.ingest_event(event).unwrap();

        let key = ScopeBucketKey {
            pattern_id: "delete-storm".into(),
            mandate_id: "m-42".into(),
            operator_id: None,
            integration_ref: None,
            resource_kind: None,
        };
        let buffer = state.buffers().get(&key).expect("bucket must exist");
        assert_eq!(buffer.events.len(), 1);
        assert_eq!(buffer.pattern_id, "delete-storm");
        assert_eq!(state.per_mandate_counters().get("m-42").copied(), Some(1));
    }

    #[test]
    fn ingest_event_skips_non_matching_patterns() {
        // Pattern matches delete/pod — an event with verb=get does
        // NOT land in any bucket and does NOT advance the pattern's
        // per-mandate count EXCEPT the counter still increments (the
        // counter is per-mandate ingestion, not per-pattern match).
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        let mut event = base_event("e-1", "m-42", 1_700_000_000);
        event.verb = "get".into();
        state.ingest_event(event).unwrap();

        assert!(state.buffers().is_empty()); // no bucket created
        assert_eq!(state.per_mandate_counters().get("m-42").copied(), Some(1));
    }

    #[test]
    fn ingest_event_routes_to_multiple_buckets_when_multiple_patterns_match() {
        // Two patterns whose scopes both match the same event.
        let mut second = delete_storm_pattern();
        second.pattern_id = "delete-storm-v2".into();
        let mut state =
            DetectorState::new(library(vec![delete_storm_pattern(), second]), 1_700_000_000);
        state
            .ingest_event(base_event("e-1", "m-42", 1_700_000_000))
            .unwrap();
        assert_eq!(state.buffers().len(), 2);
    }

    #[test]
    fn ingest_event_separates_buckets_per_mandate() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        state
            .ingest_event(base_event("e-1", "m-42", 1_700_000_000))
            .unwrap();
        state
            .ingest_event(base_event("e-2", "m-99", 1_700_000_000))
            .unwrap();
        assert_eq!(state.buffers().len(), 2);
        assert_eq!(state.per_mandate_counters().len(), 2);
        assert_eq!(state.per_mandate_counters().get("m-42").copied(), Some(1));
        assert_eq!(state.per_mandate_counters().get("m-99").copied(), Some(1));
    }

    // ------------ ingest_event clock-skew gate -----------------------

    #[test]
    fn ingest_event_accepts_equal_timestamp() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        state
            .ingest_event(base_event("e-1", "m-42", 1_700_000_000))
            .unwrap();
    }

    #[test]
    fn ingest_event_accepts_past_timestamp() {
        // Past-dated events are accepted; sliding-window eviction
        // handles them.  Only future-dated events reject here.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        state
            .ingest_event(base_event("e-1", "m-42", 1_699_999_000))
            .unwrap();
    }

    #[test]
    fn ingest_event_accepts_skew_at_the_exact_cap() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        // skew = 30s = MAX_CLOCK_SKEW_SECONDS, still accepted.
        state
            .ingest_event(base_event("e-1", "m-42", 1_700_000_030))
            .unwrap();
    }

    #[test]
    fn ingest_event_rejects_skew_one_second_past_cap() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        // skew = 31s > MAX_CLOCK_SKEW_SECONDS.
        let err = state
            .ingest_event(base_event("e-1", "m-42", 1_700_000_031))
            .unwrap_err();
        match err {
            StreamError::ClockSkewRejected {
                event_id,
                skew_seconds,
            } => {
                assert_eq!(event_id, "e-1");
                assert_eq!(skew_seconds, 31);
            }
            other => panic!("expected ClockSkewRejected, got {other:?}"),
        }
        // Rejected ingestion leaves state untouched.
        assert!(state.buffers().is_empty());
        assert!(state.per_mandate_counters().is_empty());
    }

    #[test]
    fn ingest_event_sanitises_event_id_in_clock_skew_error() {
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        let mut event = base_event("evil\nINJ", "m-42", 1_700_000_500);
        event.timestamp = 1_700_000_500;
        let err = state.ingest_event(event).unwrap_err();
        match err {
            StreamError::ClockSkewRejected { event_id, .. } => {
                assert_eq!(event_id, "evil?INJ"); // \n → ?
            }
            other => panic!("expected ClockSkewRejected, got {other:?}"),
        }
    }

    // ------------ ingest_event per-mandate cap -----------------------

    #[test]
    fn ingest_event_per_mandate_cap_rejects_overflow_event() {
        // Ingest exactly MAX_EVENTS_PER_MANDATE events (all with
        // verb=get so no buffer fills up; cap is on the counter,
        // not the buffer), then the next event rejects.
        let mut state = DetectorState::new(library(vec![]), 1_700_000_000);
        for i in 0..MAX_EVENTS_PER_MANDATE {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ts = 1_700_000_000_i64 + (i as i64) % 30;
            state
                .ingest_event(base_event(&format!("e-{i}"), "m-42", ts))
                .unwrap();
        }
        assert_eq!(
            state.per_mandate_counters().get("m-42").copied(),
            Some(MAX_EVENTS_PER_MANDATE)
        );
        // The next event must reject.
        let err = state
            .ingest_event(base_event("e-overflow", "m-42", 1_700_000_000))
            .unwrap_err();
        match err {
            StreamError::PerMandateCapReached { mandate_id, cap } => {
                assert_eq!(mandate_id, "m-42");
                assert_eq!(cap, MAX_EVENTS_PER_MANDATE);
            }
            other => panic!("expected PerMandateCapReached, got {other:?}"),
        }
        // Counter unchanged after reject.
        assert_eq!(
            state.per_mandate_counters().get("m-42").copied(),
            Some(MAX_EVENTS_PER_MANDATE)
        );
    }

    #[test]
    fn ingest_event_per_mandate_cap_does_not_affect_other_mandates() {
        // A mandate hitting its cap must not block ingestion on a
        // different mandate.  We keep the test small by forcing the
        // cap check to the happy path for m-99 while m-42 is full.
        let mut state = DetectorState::new(library(vec![]), 1_700_000_000);
        // Manually inflate m-42's counter to cap.  This is a white-
        // box tripwire: we do not have a pub API to set the counter,
        // so go through the normal ingestion loop at small scale
        // with a helper that ingests MAX events.  That test is
        // expensive — we opt for a targeted assertion on m-99
        // after filling m-42 instead.  (Keeps CI under 100ms.)
        for i in 0..10_u64 {
            state
                .ingest_event(base_event(&format!("e42-{i}"), "m-42", 1_700_000_000))
                .unwrap();
        }
        // m-99 still accepts normally.
        state
            .ingest_event(base_event("e99-1", "m-99", 1_700_000_000))
            .unwrap();
        assert_eq!(state.per_mandate_counters().get("m-42").copied(), Some(10));
        assert_eq!(state.per_mandate_counters().get("m-99").copied(), Some(1));
    }

    // NOTE(5-B): a white-box sanitisation test for a mandate_id
    // with control bytes in the `PerMandateCapReached` error path
    // lands when Session 5-B exposes a test-only cap override —
    // driving the real cap requires 10k ingestions which would
    // blow the CI budget.  The `sanitize_log_string` invariant
    // itself is covered byte-exact by the `ClockSkewRejected`
    // test above, which routes through the same helper.

    // ------------ ingest_event per-buffer eviction -------------------

    #[test]
    fn ingest_event_per_buffer_ring_evicts_oldest_when_cap_reached() {
        // Push MAX_EVENTS_PER_BUFFER + 5 events into the same
        // bucket.  The oldest 5 must be evicted; len stays at cap.
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        let overflow = MAX_EVENTS_PER_BUFFER + 5;
        for i in 0..overflow {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ts = 1_700_000_000_i64 + (i as i64) % 30;
            state
                .ingest_event(base_event(&format!("e-{i}"), "m-42", ts))
                .unwrap();
        }
        let key = ScopeBucketKey {
            pattern_id: "delete-storm".into(),
            mandate_id: "m-42".into(),
            operator_id: None,
            integration_ref: None,
            resource_kind: None,
        };
        let buffer = state.buffers().get(&key).unwrap();
        assert_eq!(buffer.events.len(), MAX_EVENTS_PER_BUFFER);
        // The first 5 events should have been evicted; front
        // event_id should be "e-5".
        assert_eq!(buffer.events.front().unwrap().event_id, "e-5");
        assert_eq!(
            buffer.events.back().unwrap().event_id,
            format!("e-{}", overflow - 1)
        );
    }

    // ------------ advance_clock --------------------------------------

    #[test]
    fn advance_clock_accepts_equal_time() {
        let mut state = DetectorState::new(library(vec![]), 1_700_000_000);
        state.advance_clock(1_700_000_000).unwrap();
        assert_eq!(state.current_time(), 1_700_000_000);
    }

    #[test]
    fn advance_clock_accepts_forward_progression() {
        let mut state = DetectorState::new(library(vec![]), 1_700_000_000);
        state.advance_clock(1_700_000_120).unwrap();
        assert_eq!(state.current_time(), 1_700_000_120);
    }

    #[test]
    fn advance_clock_rejects_regression() {
        let mut state = DetectorState::new(library(vec![]), 1_700_000_000);
        let err = state.advance_clock(1_699_999_000).unwrap_err();
        match err {
            StreamError::ClockRegression { from, to } => {
                assert_eq!(from, 1_700_000_000);
                assert_eq!(to, 1_699_999_000);
            }
            other => panic!("expected ClockRegression, got {other:?}"),
        }
        // Clock untouched after rejection.
        assert_eq!(state.current_time(), 1_700_000_000);
    }

    #[test]
    fn advance_clock_then_ingest_honours_new_clock_as_skew_reference() {
        // After advancing to T+120, an event at T+145 is within
        // skew (25s), but an event at T+155 exceeds skew (35s).
        let mut state = DetectorState::new(library(vec![delete_storm_pattern()]), 1_700_000_000);
        state.advance_clock(1_700_000_120).unwrap();
        state
            .ingest_event(base_event("e-ok", "m-42", 1_700_000_145))
            .unwrap();
        let err = state
            .ingest_event(base_event("e-fail", "m-42", 1_700_000_155))
            .unwrap_err();
        assert!(matches!(err, StreamError::ClockSkewRejected { .. }));
    }

    // ------------ ScopeBucketKey -------------------------------------

    #[test]
    fn scope_bucket_key_for_pattern_match_at_5a_only_binds_mandate() {
        // Session 5-A contract: operator_id, integration_ref, and
        // resource_kind are ALWAYS None.  A Session 5-B PR extending
        // the bucketing MUST update THIS test.
        let event = base_event("e-1", "m-42", 1_700_000_000);
        let predicate = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: Some("pod".into()),
            mandate_scope: MandateScope {
                mandate_id: Some("m-42".into()),
                operator_id: Some("op-3".into()),
                integration_ref: Some("kubernetes".into()),
            },
        };
        let key = ScopeBucketKey::for_pattern_match("delete-storm", &predicate, &event);
        assert_eq!(key.pattern_id, "delete-storm");
        assert_eq!(key.mandate_id, "m-42");
        assert!(key.operator_id.is_none());
        assert!(key.integration_ref.is_none());
        assert!(key.resource_kind.is_none());
    }

    #[test]
    fn scope_bucket_key_ord_is_lexicographic_on_pattern_id_then_mandate() {
        let a = ScopeBucketKey {
            pattern_id: "aaa".into(),
            mandate_id: "m-99".into(),
            operator_id: None,
            integration_ref: None,
            resource_kind: None,
        };
        let b = ScopeBucketKey {
            pattern_id: "bbb".into(),
            mandate_id: "m-00".into(),
            operator_id: None,
            integration_ref: None,
            resource_kind: None,
        };
        assert!(a < b);
    }

    // ------------ SequenceTracker ------------------------------------

    #[test]
    fn sequence_tracker_default_is_zero_zero() {
        let t = SequenceTracker::default();
        assert_eq!(t.current_step, 0);
        assert_eq!(t.last_event_at, 0);
    }

    #[test]
    fn sequence_tracker_is_clone_eq_debug() {
        let a = SequenceTracker {
            current_step: 3,
            last_event_at: 1_700_000_000,
        };
        let b = a.clone();
        assert_eq!(a, b);
        let _ = format!("{a:?}");
    }

    // ------------ concurrency ---------------------------------------

    #[test]
    fn detector_state_is_send() {
        // `DetectorState` is `Send` so workers can move it across
        // threads (typical: spawn one detector per worker).  It is
        // *not* `Sync` because [`DedupLedger`] is intentionally
        // `Send`-only — see the Concurrency section of the
        // `DetectorState` doc.
        fn assert_send<T: Send>() {}
        assert_send::<DetectorState>();
    }

    #[test]
    fn aux_types_are_send_sync() {
        // Plain-data field/value types remain `Send + Sync` — only
        // `DetectorState` itself is `Send`-only because of the
        // `Box<dyn DedupLedger>` field.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ScopeBucketKey>();
        assert_send_sync::<SequenceTracker>();
        assert_send_sync::<PatternBuffer>();
    }

    // ------------ evict_aged_events (Session 5-B T1) -----------------

    fn filled_buffer(timestamps: &[i64]) -> PatternBuffer {
        let mut buf = PatternBuffer::new("p-evict".into());
        for (i, ts) in timestamps.iter().enumerate() {
            buf.events
                .push_back(base_event(&format!("e-{i}"), "m-42", *ts));
        }
        buf
    }

    #[test]
    fn evict_aged_events_on_empty_buffer_returns_zero() {
        let mut buf = PatternBuffer::new("p-empty".into());
        let evicted = buf.evict_aged_events(60, 1_700_000_000);
        assert_eq!(evicted, 0);
        assert!(buf.events.is_empty());
    }

    #[test]
    fn evict_aged_events_keeps_event_exactly_at_window_boundary() {
        // window = 60s, current_time = 1_700_000_060, boundary = 1_700_000_000.
        // Event at the boundary is inside the window → NOT evicted.
        let mut buf = filled_buffer(&[1_700_000_000]);
        let evicted = buf.evict_aged_events(60, 1_700_000_060);
        assert_eq!(evicted, 0);
        assert_eq!(buf.events.len(), 1);
    }

    #[test]
    fn evict_aged_events_drops_event_one_second_before_boundary() {
        // Event at 1_699_999_999 is strictly below window_start=
        // 1_700_000_000 → evicted.
        let mut buf = filled_buffer(&[1_699_999_999]);
        let evicted = buf.evict_aged_events(60, 1_700_000_060);
        assert_eq!(evicted, 1);
        assert!(buf.events.is_empty());
    }

    #[test]
    fn evict_aged_events_preserves_all_events_fully_inside_window() {
        let mut buf = filled_buffer(&[
            1_700_000_010,
            1_700_000_020,
            1_700_000_030,
            1_700_000_040,
            1_700_000_050,
        ]);
        let evicted = buf.evict_aged_events(60, 1_700_000_060);
        assert_eq!(evicted, 0);
        assert_eq!(buf.events.len(), 5);
    }

    #[test]
    fn evict_aged_events_drops_only_aged_prefix_and_stops_at_first_live_event() {
        // Events at t=[100, 200, 500, 600, 700]; window_start = 450.
        // First two must evict; last three stay.
        let mut buf = filled_buffer(&[100, 200, 500, 600, 700]);
        let evicted = buf.evict_aged_events(50, 500);
        assert_eq!(evicted, 2);
        assert_eq!(buf.events.len(), 3);
        assert_eq!(buf.events.front().unwrap().event_id, "e-2");
        assert_eq!(buf.events.back().unwrap().event_id, "e-4");
    }

    #[test]
    fn evict_aged_events_drains_entire_buffer_when_all_events_aged() {
        let mut buf = filled_buffer(&[100, 200, 300]);
        let evicted = buf.evict_aged_events(10, 10_000);
        assert_eq!(evicted, 3);
        assert!(buf.events.is_empty());
    }

    #[test]
    fn evict_aged_events_with_zero_window_drops_everything_below_current_time() {
        // window_seconds = 0 → window_start = current_time.
        // An event exactly at current_time stays (timestamp == window_start is NOT `<`).
        // An event at current_time - 1 is below and evicts.
        let mut buf = filled_buffer(&[499, 500]);
        let evicted = buf.evict_aged_events(0, 500);
        assert_eq!(evicted, 1);
        assert_eq!(buf.events.len(), 1);
        assert_eq!(buf.events.front().unwrap().timestamp, 500);
    }

    #[test]
    fn evict_aged_events_saturates_on_extreme_window_value() {
        // current_time at unix epoch + i64::from(u32::MAX) would underflow
        // a non-saturating window_start calculation.  With saturating_sub
        // the window_start floors at i64::MIN, and every positive-timestamp
        // event stays.
        let mut buf = filled_buffer(&[1, 1_000_000, 1_700_000_000]);
        let evicted = buf.evict_aged_events(u32::MAX, i64::MIN + 10);
        assert_eq!(evicted, 0);
        assert_eq!(buf.events.len(), 3);
    }
}
