//! Fire-once dedup ledger trait + in-memory implementation.
//!
//! Phase C.4 Session 5-B Commit D — replaces the inline
//! `BTreeMap<(pattern_id, mandate_id), fired_at>` field that
//! [`crate::state::DetectorState`] held since Commit A with a swappable
//! trait backend.  The in-memory default ([`InMemoryDedupLedger`])
//! preserves Commit-A semantics byte-for-byte; persistent backends
//! (disk, RocksDB, Postgres) can implement the trait without disturbing
//! the state machine or evaluators.
//!
//! # Why a trait
//!
//! Commit A's inline field is process-local: a Router restart drops
//! every dedup mark and patterns may re-fire within their normal
//! window post-restart.  The orchestrator's downstream-consumer
//! contract (§11.2 duplicate-tolerance) accommodates this, but
//! deployments that need lower duplicate-fire rates after a restart
//! want a persistent ledger.  Lifting the field behind a trait makes
//! that swap a one-line change at construction time.
//!
//! # Trait design — security posture
//!
//! The trait surface is intentionally minimal:
//!
//! - [`DedupLedger::is_suppressed`] returns a boolean — never the
//!   stored `fired_at` timestamp.  Exposing the timestamp on the trait
//!   would let any holder of `&dyn DedupLedger` exfiltrate fire-timing
//!   metadata across tenant boundaries (a cross-tenant ledger is a
//!   plausible deployment).  Test introspection that needs the
//!   timestamp lives on the concrete [`InMemoryDedupLedger`] type via
//!   [`InMemoryDedupLedger::last_fired_at`], reachable only when the
//!   caller already holds the concrete (in-memory) backend — i.e. in
//!   tests, never in dyn-dispatch production paths.
//! - [`DedupLedger::observe`] is the only mutating operation that
//!   appends fire-data; it returns `Result` so persistence backends
//!   can surface I/O failures without panicking.
//! - [`DedupLedger::clear`] is the rotation hook (see §11.2 library-
//!   rotation contract — pattern-IDs are not guaranteed stable across
//!   rotations, so preserved entries could silently mis-suppress
//!   renamed patterns).
//!
//! Beyond the four security-load-bearing methods above, the trait
//! exposes an **observability tier** ([`DedupLedger::len`],
//! [`DedupLedger::is_empty`], [`DedupLedger::flush`],
//! [`DedupLedger::stats`]) intended for operator dashboards,
//! capacity-planning, and rotation post-conditions.  These are
//! default-implemented or `O(1)`-on-in-memory and MUST NOT be
//! called from the per-event evaluator hot path; persistent
//! backends MAY incur higher cost on the observability tier and
//! are required to document any divergence from the `O(1)`
//! in-memory contract on their own type-level docs.
//!
//! # SEC-D-4 — Snapshot replay
//!
//! A persistent backend that recovers from a snapshot taken before
//! the most recent `observe` will under-suppress: fires recorded
//! after the snapshot reappear as "never seen", and the next
//! [`is_suppressed`] returns `false` for them.  This degrades to the
//! Commit-A duplicate-tolerance contract (§11.2) — downstream
//! consumers MUST already be duplicate-tolerant.  A backend that
//! recovers from a snapshot taken AFTER an `observe` that the caller
//! considers durable is silently broken; backends MUST document
//! their durability semantics so callers can decide whether the
//! window matters for their threat model.
//!
//! # SEC-D-8 — Cardinality DoS
//!
//! An attacker controlling a tenant's `mandate_id` stream could grow
//! the ledger without bound: every distinct mandate that triggers a
//! fire allocates a new entry.  [`MAX_DEDUP_ENTRIES_PER_TENANT`] caps
//! the in-memory backend at 100k entries (~8 MB worst-case per
//! tenant); past the cap, [`DedupLedger::observe`] returns
//! [`DedupLedgerError::CapacityExhausted`] rather than over-allocating
//! or evicting (no LRU — eviction policy is a per-deployment choice
//! and would silently re-fire previously-deduped patterns).  The
//! orchestrator surfaces the error to the audit pipeline; operators
//! respond by rotating the library (which clears the ledger via
//! [`DedupLedger::clear`]).

use std::collections::BTreeMap;

use thiserror::Error;

/// Maximum distinct `(pattern_id, mandate_id)` entries the in-memory
/// dedup ledger will store before refusing further `observe` calls.
///
/// Bounded so a tenant whose mandate-id stream is attacker-influenced
/// cannot inflate the ledger's memory footprint without bound.  At
/// the cap (~80 bytes per entry) the in-memory backend uses ~8 MB —
/// well under any realistic per-tenant budget.  Past the cap the
/// [`InMemoryDedupLedger::observe`] call returns
/// [`DedupLedgerError::CapacityExhausted`]; the orchestrator policy
/// is to surface the failure rather than silently evict.
///
/// Persistent backends (disk, DB) define their own cap; the const
/// here scopes only the in-memory default.
pub const MAX_DEDUP_ENTRIES_PER_TENANT: usize = 100_000;

/// Failure surface for [`DedupLedger`] operations.
///
/// `#[non_exhaustive]` so future persistent backends can introduce
/// I/O / serialization variants without breaking downstream
/// exhaustive matches.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DedupLedgerError {
    /// The in-memory backend's per-instance entry cap is full.  The
    /// caller's choices are to rotate the pinned library (which
    /// clears the ledger via [`DedupLedger::clear`]) or to swap to a
    /// persistent backend with a larger cap.  Carries the cap value
    /// so the operator can size a custom backend without re-deriving
    /// it.
    #[error(
        "dedup ledger capacity exhausted at {cap} entries; rotate library \
         or swap to a higher-cap backend"
    )]
    CapacityExhausted {
        /// The cap that was reached.
        cap: usize,
    },

    /// A persistent backend's I/O or serialization layer failed.  The
    /// in-memory default ([`InMemoryDedupLedger`]) NEVER raises this —
    /// it is reserved for backends whose `observe`/`is_suppressed`
    /// can fail at the storage layer.  `reason` is opaque to callers;
    /// the backend supplies a human-readable description.
    ///
    /// Backends SHOULD construct this variant via
    /// [`DedupLedgerError::backend_failure`], which sanitises and
    /// caps `reason` at construction time so attacker-controlled
    /// bytes (e.g. an error message echoing a serialized key) cannot
    /// allocate unbounded memory before reaching the orchestrator
    /// boundary.  Direct struct-literal construction remains
    /// permitted for backends that have already sanitised; the
    /// orchestrator-boundary `From<DedupLedgerError> for
    /// crate::errors::StreamError` impl provides a 2nd line of
    /// defence by sanitising again at the audit-pipeline crossing.
    #[error("dedup ledger backend failure: {reason}")]
    BackendFailure {
        /// Backend-supplied description.
        reason: String,
    },
}

impl DedupLedgerError {
    /// Construct a [`Self::BackendFailure`] with `reason` sanitised
    /// through [`crate::errors::sanitize_log_string`] (256-byte cap,
    /// control bytes → `'?'`).  Preferred constructor for backends —
    /// see the variant doc for the defence-in-depth rationale.
    #[must_use]
    pub fn backend_failure(reason: impl AsRef<str>) -> Self {
        Self::BackendFailure {
            reason: crate::errors::sanitize_log_string(reason.as_ref()),
        }
    }
}

/// Fire-once dedup ledger consumed by
/// [`crate::state::DetectorState::evaluate_all`] and the per-rule
/// evaluators in [`crate::evaluators`].
///
/// Each `observe` records a successful fire; each `is_suppressed`
/// query asks "has this `(pattern, mandate)` pair fired within the
/// last `window_seconds`?".  Suppression is strict-less (`<`),
/// matching the Commit-A semantics in
/// [`crate::evaluators::is_fire_suppressed`] — at-the-window
/// re-fires are allowed.
///
/// # Object-safety
///
/// All methods take `&str` and primitive types; no generics.  Callers
/// can dispatch via `&mut dyn DedupLedger`.
///
/// # Supertraits
///
/// - `Send` — implementors MUST be `Send` so a `Box<dyn DedupLedger>`
///   lives inside [`crate::state::DetectorState`] and survives moves
///   across async tasks.  `Sync` is intentionally NOT required:
///   mutation is `&mut self`, and any cross-thread sharing supplies
///   its own mutex.  `DetectorState` is consequently `Send` but not
///   `Sync` — fan out across threads by giving each worker its own
///   state instance (see the Concurrency section in
///   [`crate::state::DetectorState`]).
/// - `Debug` — required so `DetectorState` (which holds a
///   `Box<dyn DedupLedger>`) can keep its `#[derive(Debug)]` for
///   diagnostics.  Persistent backends should redact secret fields
///   (e.g. credentials) in their custom `Debug` impl rather than
///   printing them raw.
pub trait DedupLedger: Send + std::fmt::Debug {
    /// Return `true` iff `(pattern_id, mandate_id)` last fired within
    /// the last `window_seconds`, evaluated at `current_time`.
    ///
    /// Semantics (parity with the Commit-A `is_fire_suppressed`):
    /// `current_time.saturating_sub(fired_at) < i64::from(window_seconds)`.
    /// Exactly-at-window re-fires (`==` returns `false` from this
    /// method).
    ///
    /// Returns `false` for any `(pattern_id, mandate_id)` the ledger
    /// has never seen.
    ///
    /// # Errors
    ///
    /// Persistent backends may surface
    /// [`DedupLedgerError::BackendFailure`].  The in-memory default
    /// is infallible on this path.
    fn is_suppressed(
        &self,
        pattern_id: &str,
        mandate_id: &str,
        current_time: i64,
        window_seconds: u32,
    ) -> Result<bool, DedupLedgerError>;

    /// Record a fresh fire for `(pattern_id, mandate_id)` at
    /// `fired_at` (unix epoch seconds, the detector's
    /// [`crate::state::DetectorState::current_time`] at the fire
    /// instant).
    ///
    /// Overwrites any existing entry for the same pair — only the
    /// most recent fire timestamp is retained, matching the Commit-A
    /// `BTreeMap::insert` semantics.
    ///
    /// # Errors
    ///
    /// - [`DedupLedgerError::CapacityExhausted`] when adding a NEW
    ///   pair would exceed the backend's per-instance cap.  Overwrites
    ///   to existing pairs DO NOT count against the cap.
    /// - [`DedupLedgerError::BackendFailure`] for persistent backends
    ///   whose I/O layer failed.
    fn observe(
        &mut self,
        pattern_id: &str,
        mandate_id: &str,
        fired_at: i64,
    ) -> Result<(), DedupLedgerError>;

    /// Drop every stored entry.
    ///
    /// Called by [`crate::orchestrator::AuditOrchestrator::rotate_library`]
    /// — pattern-IDs are not guaranteed stable across library
    /// rotations, so preserving entries could silently mis-suppress
    /// renamed patterns.
    ///
    /// # Errors
    ///
    /// Persistent backends may raise
    /// [`DedupLedgerError::BackendFailure`].  The in-memory default
    /// is infallible.
    fn clear(&mut self) -> Result<(), DedupLedgerError>;

    /// Number of distinct `(pattern_id, mandate_id)` entries currently
    /// stored.
    ///
    /// Lifted onto the trait (not just the concrete in-memory type) so
    /// callers holding `&dyn DedupLedger` — most importantly
    /// [`crate::state::DetectorState::dedup_ledger`] consumers — can
    /// introspect cardinality without downcast.  Cardinality is
    /// non-sensitive *relative to cross-tenant metadata* (no
    /// fire-timing, no per-key data exposed to other tenants); a
    /// tenant observing its own ledger's `len` learns only its own
    /// firing cardinality, which is already implicit in operator-side
    /// capacity logging on
    /// [`DedupLedgerError::CapacityExhausted`].  Exposing it on the
    /// trait therefore does not violate the cross-tenant metadata-leak
    /// constraint that keeps `last_fired_at` off the trait.
    ///
    /// # Performance contract
    ///
    /// The in-memory default ([`InMemoryDedupLedger`]) answers in
    /// `O(1)` (`BTreeMap::len` is a constant-time field read).
    /// Persistent backends (disk, RocksDB, Postgres) MAY answer in
    /// `O(n)` if they cannot maintain a constant-time count alongside
    /// their primary index — backends that diverge from `O(1)` MUST
    /// document the cost in their own type-level docs.
    ///
    /// Callers SHOULD treat `len` as a stat-collection / observability
    /// surface (operator dashboards, capacity-planning, post-mortem
    /// telemetry) rather than a per-event hot-path call.  The
    /// in-tree call sites — capacity logging on
    /// [`DedupLedgerError::CapacityExhausted`] surface and rotation
    /// post-conditions in [`crate::orchestrator::AuditOrchestrator`] —
    /// satisfy this contract; new call sites MUST NOT call `len` from
    /// inside the per-event evaluator path
    /// ([`crate::state::DetectorState::evaluate_all`] tight loop) where
    /// an `O(n)` backend would impose an `O(n × m)` cost on every
    /// stream tick.
    fn len(&self) -> usize;

    /// `true` iff [`Self::len`] is zero.
    ///
    /// Default impl in terms of [`Self::len`]; backends override only
    /// if they can answer cheaper than counting.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Force any buffered writes to durable storage.
    ///
    /// The default impl is a no-op returning `Ok(())` — appropriate
    /// for backends whose [`Self::observe`] writes are already durable
    /// at call return (the in-memory default ([`InMemoryDedupLedger`])
    /// has no buffer; the `BTreeMap::insert` is the durable surface).
    ///
    /// Persistent backends (disk, RocksDB, Postgres) MUST override
    /// this method whenever their `observe` defers the durable write
    /// — otherwise a process crash between `observe` and the next
    /// implicit flush (e.g. on rotation via [`Self::clear`]) silently
    /// loses fire-bookmarks, which downgrades the deployment to the
    /// Commit-A duplicate-tolerance contract (§11.2) without the
    /// caller having opted into that.  Backends that defer writes
    /// MUST document the durability semantics on their type-level
    /// docs so callers can reason about crash-window exposure.
    ///
    /// The "MUST override on a deferring backend" obligation is a
    /// **correctness / durability** concern, not a security control:
    /// a missing override only degrades dedup quality across a
    /// crash boundary (downstream consumers are already
    /// duplicate-tolerant per §11.2), and an attacker who can
    /// crash the process has crossed a more fundamental trust
    /// boundary already.  This is documented here so future
    /// auditors do not re-litigate the threat-model classification.
    ///
    /// Lifted onto the trait (default-impl-shielded) rather than
    /// added as a future-Commit so that downstream consumers binding
    /// against the C.4 trait shape do not have to re-compile when
    /// the first persistent backend lands; the surface is stable.
    ///
    /// # Errors
    ///
    /// Persistent backends may raise
    /// [`DedupLedgerError::BackendFailure`] if the durable write
    /// fails (disk full, fsync error, etc.).  The in-memory default
    /// is infallible.
    fn flush(&mut self) -> Result<(), DedupLedgerError> {
        Ok(())
    }

    /// Snapshot of operator-observable backend metrics.
    ///
    /// The default impl derives [`DedupLedgerStats::entry_count`]
    /// from [`Self::len`] — appropriate for backends whose only
    /// stat-of-interest is the entry count.  Persistent backends
    /// MAY override to surface backend-specific telemetry through
    /// the same struct (the `#[non_exhaustive]` posture on
    /// [`DedupLedgerStats`] permits additive fields without
    /// breaking downstream exhaustive matches; future fields would
    /// arrive alongside a `with_*` builder method on
    /// [`DedupLedgerStats`]).
    ///
    /// # Performance contract
    ///
    /// The default impl inherits [`Self::len`]'s performance
    /// contract — `O(1)` on the in-memory default, MAY be `O(n)`
    /// on persistent backends.  Persistent backends whose `len`
    /// is `O(n)` MUST override `stats` to maintain `O(1)` (e.g.
    /// by reading a counter the backend already maintains
    /// alongside its primary index).  Without that override,
    /// `stats` becomes a hidden `O(n)` per-call, which would
    /// surprise operators using it as a polling-rate dashboard
    /// metric.
    ///
    /// Like [`Self::len`], `stats` is intended for stat-collection
    /// and capacity-planning surfaces — operator dashboards,
    /// post-mortem telemetry, rotation post-conditions — never the
    /// per-event evaluator hot path.
    fn stats(&self) -> DedupLedgerStats {
        DedupLedgerStats::with_entry_count(self.len())
    }
}

/// Operator-observable snapshot of a [`DedupLedger`]'s backend
/// metrics.
///
/// Returned by [`DedupLedger::stats`].  `#[non_exhaustive]` so
/// future persistent backends can introduce additional metric
/// fields (e.g. `cache_hit_rate`, `bytes_on_disk`) without breaking
/// downstream exhaustive constructions or matches.  Cross-crate
/// callers construct via [`DedupLedgerStats::with_entry_count`];
/// tests within this crate may struct-literal-construct directly.
///
/// The `with_*`-prefixed constructor name is deliberate: as
/// additional metric fields land they will arrive as further
/// `with_<field>` chainable methods, mirroring the
/// [`InMemoryDedupLedger::with_cap`] pattern used elsewhere in
/// this module.  A bare `new(...)` taking a positional argument
/// list would be hostile to future-additivity — every field
/// addition would either rebreak the signature or strand callers
/// on a frozen-shape constructor next to the chainable surface.
///
/// `Eq` is intentionally **not** derived: `entry_count` is a
/// `usize` today, but adding any `f64` field in a future commit
/// (e.g. `cache_hit_rate`) would silently fail to compile `Eq`,
/// forcing its removal — a breaking change under semver.
/// Pre-emptive `PartialEq`-only avoids that forced removal.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DedupLedgerStats {
    /// Distinct `(pattern_id, mandate_id)` entries currently held
    /// by the backend.  Equivalent to [`DedupLedger::len`] for the
    /// default [`DedupLedger::stats`] implementation.
    pub entry_count: usize,
}

impl DedupLedgerStats {
    /// Construct a stats snapshot with the given `entry_count`.
    ///
    /// Cross-crate callers — primarily persistent-backend
    /// implementors overriding [`DedupLedger::stats`] — use this
    /// constructor because the `#[non_exhaustive]` posture forbids
    /// struct-literal construction from outside this crate.
    ///
    /// Future additive fields will arrive as further `with_*`
    /// chainable methods, leaving this constructor's signature
    /// stable.  Callers using only `with_entry_count` after such
    /// a field lands will see the new field default-initialised
    /// to its `Default` (e.g. `0` for numeric, `None` for option);
    /// operator-dashboard code that reads new fields MUST chain
    /// the corresponding `with_*` setter to surface accurate data
    /// rather than silent zeros.
    pub fn with_entry_count(entry_count: usize) -> Self {
        Self { entry_count }
    }
}

/// Default in-memory [`DedupLedger`].
///
/// State is a `BTreeMap<(pattern_id, mandate_id), fired_at>` keyed
/// on owned `String` pairs, mirroring the Commit-A field shape so
/// the migration in `state.rs` is mechanical.  `BTreeMap` (not
/// `HashMap`) keeps iteration deterministic should a future
/// diagnostic dump be added.
///
/// Process-local; not persistent.  Production deployments needing
/// dedup state across restarts implement [`DedupLedger`] over their
/// chosen storage and inject the impl at
/// [`crate::state::DetectorState`] construction.
///
/// `Default` returns an empty ledger sized at
/// [`MAX_DEDUP_ENTRIES_PER_TENANT`]; [`InMemoryDedupLedger::new`] is
/// the documented constructor and matches `Default`.  Tests that need
/// to exercise the [`DedupLedgerError::CapacityExhausted`] path use
/// [`InMemoryDedupLedger::with_cap`] to install a small budget.
#[derive(Debug)]
pub struct InMemoryDedupLedger {
    state: BTreeMap<(String, String), i64>,
    cap: usize,
}

impl Default for InMemoryDedupLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDedupLedger {
    /// Construct an empty in-memory ledger sized at
    /// [`MAX_DEDUP_ENTRIES_PER_TENANT`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(MAX_DEDUP_ENTRIES_PER_TENANT)
    }

    /// Construct an empty in-memory ledger with a custom cap.
    ///
    /// Production callers use [`Self::new`].  This constructor is
    /// retained so tests can exercise the
    /// [`DedupLedgerError::CapacityExhausted`] path on a tractable
    /// budget without allocating 100k synthetic entries.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            state: BTreeMap::new(),
            cap,
        }
    }

    /// Read the stored fire timestamp for `(pattern_id, mandate_id)`.
    ///
    /// Returns `None` if no fire has been observed for the pair.
    ///
    /// # Why this is on the concrete type, not the trait
    ///
    /// Exposing fire-timing on the [`DedupLedger`] trait would let
    /// any holder of `&dyn DedupLedger` exfiltrate metadata across
    /// tenant boundaries — see the SEC-posture section of the
    /// module-level docs.  Tests that need to assert progression of
    /// the dedup bookmark hold the concrete [`InMemoryDedupLedger`]
    /// directly (or `Arc<Mutex<InMemoryDedupLedger>>` for shared
    /// access) and call this method; production paths hold
    /// `Box<dyn DedupLedger>` and have no access to the timestamp.
    #[must_use]
    pub fn last_fired_at(&self, pattern_id: &str, mandate_id: &str) -> Option<i64> {
        self.state
            .get(&(pattern_id.to_owned(), mandate_id.to_owned()))
            .copied()
    }
}

impl DedupLedger for InMemoryDedupLedger {
    fn is_suppressed(
        &self,
        pattern_id: &str,
        mandate_id: &str,
        current_time: i64,
        window_seconds: u32,
    ) -> Result<bool, DedupLedgerError> {
        // Allocates two owned Strings per call to satisfy the BTreeMap
        // key shape; matches the Commit-A `is_fire_suppressed` cost
        // profile.  A future zero-alloc shape (BTreeMap with a
        // borrowed key wrapper, or split nested maps) is a perf
        // optimisation deferred until the read path shows up in a
        // profile — correctness and shape-parity beats it for D.
        let key = (pattern_id.to_owned(), mandate_id.to_owned());
        let Some(&fired_at) = self.state.get(&key) else {
            return Ok(false);
        };
        Ok(current_time.saturating_sub(fired_at) < i64::from(window_seconds))
    }

    fn observe(
        &mut self,
        pattern_id: &str,
        mandate_id: &str,
        fired_at: i64,
    ) -> Result<(), DedupLedgerError> {
        // Probe via `get_mut` so an overwrite to an existing pair
        // does NOT count against the cap.  Only NEW pairs trip the
        // cap check — otherwise a long-running tenant at-cap would
        // be unable to update its own existing dedup marks, which
        // would silently re-fire patterns the tenant already saw.
        let key = (pattern_id.to_owned(), mandate_id.to_owned());
        if let Some(slot) = self.state.get_mut(&key) {
            *slot = fired_at;
            return Ok(());
        }
        if self.state.len() >= self.cap {
            return Err(DedupLedgerError::CapacityExhausted { cap: self.cap });
        }
        self.state.insert(key, fired_at);
        Ok(())
    }

    fn clear(&mut self) -> Result<(), DedupLedgerError> {
        self.state.clear();
        Ok(())
    }

    fn len(&self) -> usize {
        self.state.len()
    }

    fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ledger_reports_empty_and_zero_len() {
        let ledger = InMemoryDedupLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn is_suppressed_returns_false_when_no_prior_observation() {
        let ledger = InMemoryDedupLedger::new();
        let suppressed = ledger
            .is_suppressed("delete-storm", "m-42", 1_700_000_100, 60)
            .expect("infallible");
        assert!(!suppressed);
    }

    #[test]
    fn observe_then_is_suppressed_true_within_window() {
        let mut ledger = InMemoryDedupLedger::new();
        ledger
            .observe("delete-storm", "m-42", 1_700_000_070)
            .unwrap();
        // current_time - fired_at = 30s < window=60s → suppressed
        let suppressed = ledger
            .is_suppressed("delete-storm", "m-42", 1_700_000_100, 60)
            .unwrap();
        assert!(suppressed);
        // last_fired_at helper exposes the bookmark for tests.
        assert_eq!(
            ledger.last_fired_at("delete-storm", "m-42"),
            Some(1_700_000_070)
        );
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn is_suppressed_false_at_exactly_window_boundary() {
        // Strict `<` semantics: `current_time - fired_at == window`
        // returns false (NOT suppressed).  Pinned by Commit-A
        // `is_fire_suppressed`; behaviour parity is load-bearing.
        let mut ledger = InMemoryDedupLedger::new();
        ledger
            .observe("delete-storm", "m-42", 1_700_000_040)
            .unwrap();
        let suppressed = ledger
            .is_suppressed("delete-storm", "m-42", 1_700_000_100, 60)
            .unwrap();
        assert!(!suppressed, "exactly-at-window MUST NOT suppress");
    }

    #[test]
    fn is_suppressed_false_after_window_elapsed() {
        let mut ledger = InMemoryDedupLedger::new();
        ledger
            .observe("delete-storm", "m-42", 1_700_000_000)
            .unwrap();
        // 100s elapsed > 60s window → fire allowed.
        let suppressed = ledger
            .is_suppressed("delete-storm", "m-42", 1_700_000_100, 60)
            .unwrap();
        assert!(!suppressed);
    }

    #[test]
    fn observe_overwrites_existing_entry_in_place() {
        let mut ledger = InMemoryDedupLedger::new();
        ledger
            .observe("delete-storm", "m-42", 1_700_000_000)
            .unwrap();
        ledger
            .observe("delete-storm", "m-42", 1_700_000_080)
            .unwrap();
        // Overwrite preserves single entry — no double-counting.
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.last_fired_at("delete-storm", "m-42"),
            Some(1_700_000_080)
        );
        // The new bookmark dictates suppression now: 100 - 80 = 20 < 60.
        let suppressed = ledger
            .is_suppressed("delete-storm", "m-42", 1_700_000_100, 60)
            .unwrap();
        assert!(suppressed);
    }

    #[test]
    fn clear_drops_all_entries_and_resets_suppression() {
        let mut ledger = InMemoryDedupLedger::new();
        ledger
            .observe("delete-storm", "m-42", 1_700_000_070)
            .unwrap();
        ledger
            .observe("ghost-rotate", "m-99", 1_700_000_080)
            .unwrap();
        assert_eq!(ledger.len(), 2);
        ledger.clear().unwrap();
        assert!(ledger.is_empty());
        // Post-clear, prior fires are gone — `is_suppressed` returns
        // false even though current_time - fired_at would still be
        // inside the window.
        let suppressed = ledger
            .is_suppressed("delete-storm", "m-42", 1_700_000_100, 60)
            .unwrap();
        assert!(!suppressed);
    }

    #[test]
    fn capacity_exhausted_when_cap_reached_for_new_pair() {
        // Custom cap=2 makes the failure tractable.  Two distinct
        // pairs fit; the third NEW pair returns CapacityExhausted
        // with the cap value carried.
        let mut ledger = InMemoryDedupLedger::with_cap(2);
        ledger.observe("p1", "m-a", 1_700_000_000).unwrap();
        ledger.observe("p1", "m-b", 1_700_000_001).unwrap();
        let err = ledger
            .observe("p1", "m-c", 1_700_000_002)
            .expect_err("third NEW pair MUST exceed cap=2");
        assert_eq!(err, DedupLedgerError::CapacityExhausted { cap: 2 });
        // Map is unchanged on rejection — no partial insert.
        assert_eq!(ledger.len(), 2);
        assert!(ledger.last_fired_at("p1", "m-c").is_none());
    }

    #[test]
    fn capacity_check_does_not_apply_to_overwrites() {
        // At-cap overwrites of EXISTING pairs MUST succeed — otherwise
        // a tenant whose ledger fills up could not update its own
        // dedup marks, silently re-firing patterns it already saw.
        let mut ledger = InMemoryDedupLedger::with_cap(2);
        ledger.observe("p1", "m-a", 1_700_000_000).unwrap();
        ledger.observe("p1", "m-b", 1_700_000_001).unwrap();
        // Ledger is at cap.  Overwrite of (p1, m-a) MUST succeed.
        ledger
            .observe("p1", "m-a", 1_700_000_500)
            .expect("overwrite at cap MUST succeed");
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.last_fired_at("p1", "m-a"), Some(1_700_000_500));
    }

    #[test]
    fn is_suppressed_distinguishes_pattern_id_and_mandate_id() {
        // Cross-key isolation: a fire for (p1, m-a) does NOT suppress
        // (p1, m-b), (p2, m-a), or (p2, m-b).  Pinned because the
        // dedup key is the (pattern, mandate) PAIR, not either field
        // alone.
        let mut ledger = InMemoryDedupLedger::new();
        ledger.observe("p1", "m-a", 1_700_000_070).unwrap();

        let suppressed_self = ledger
            .is_suppressed("p1", "m-a", 1_700_000_100, 60)
            .unwrap();
        assert!(suppressed_self);

        let cross_mandate = ledger
            .is_suppressed("p1", "m-b", 1_700_000_100, 60)
            .unwrap();
        assert!(
            !cross_mandate,
            "different mandate MUST NOT inherit suppression"
        );

        let cross_pattern = ledger
            .is_suppressed("p2", "m-a", 1_700_000_100, 60)
            .unwrap();
        assert!(
            !cross_pattern,
            "different pattern MUST NOT inherit suppression"
        );

        let cross_both = ledger
            .is_suppressed("p2", "m-b", 1_700_000_100, 60)
            .unwrap();
        assert!(!cross_both);
    }

    #[test]
    fn dedup_ledger_is_send_and_object_safe() {
        // Compile-time proofs: trait MUST be object-safe, the in-
        // memory impl MUST be Send, and a Box<dyn DedupLedger> MUST
        // be Send so the orchestrator can hold one inside its
        // Send-bound DetectorState across async tasks.
        fn assert_send<T: Send + ?Sized>() {}
        fn assert_object_safe(_: &mut dyn DedupLedger) {}

        assert_send::<InMemoryDedupLedger>();
        let mut ledger = InMemoryDedupLedger::new();
        assert_object_safe(&mut ledger);

        let mut boxed: Box<dyn DedupLedger> = Box::new(InMemoryDedupLedger::new());
        assert_send::<Box<dyn DedupLedger>>();
        // Smoke-test the dyn-dispatch path so a regression that broke
        // object-safety (e.g. accidentally adding a generic method)
        // is caught here as a compile error.
        boxed.observe("p1", "m-a", 1_700_000_000).unwrap();
        let suppressed = boxed.is_suppressed("p1", "m-a", 1_700_000_010, 60).unwrap();
        assert!(suppressed);
        boxed.clear().unwrap();
    }

    #[test]
    fn capacity_exhausted_error_display_carries_cap_value() {
        // Operator-facing message must name the cap so the operator
        // can size a higher-cap backend without re-deriving the
        // const.  Pinned because Display is the primary surface
        // ops sees.
        let err = DedupLedgerError::CapacityExhausted { cap: 100_000 };
        let display = format!("{err}");
        assert!(display.contains("100000"));
        assert!(display.contains("capacity exhausted"));
    }

    #[test]
    fn backend_failure_error_display_carries_reason() {
        // Reserved-for-future variant: pin the rendering shape so a
        // persistent backend's first integration does not have to
        // re-discover it.
        let err = DedupLedgerError::BackendFailure {
            reason: "rocksdb: io error".to_owned(),
        };
        let display = format!("{err}");
        assert!(display.contains("rocksdb: io error"));
        assert!(display.contains("backend failure"));
    }

    #[test]
    fn in_memory_flush_is_noop_ok_and_preserves_state() {
        // Default-impl `flush` on the in-memory backend MUST be a
        // no-op returning `Ok(())` — the BTreeMap insert in
        // `observe` is the durable surface, no buffer to drain.
        // A regression that overrode `flush` with a state-clearing
        // body would silently drop fire-bookmarks at every flush
        // point (rotation post-condition, end-of-stream tick, etc.)
        // and degrade dedup correctness without surfacing an error.
        let mut ledger = InMemoryDedupLedger::new();
        ledger
            .observe("delete-storm", "m-42", 1_700_000_070)
            .unwrap();
        assert_eq!(ledger.len(), 1);

        ledger.flush().expect("in-memory flush is infallible");

        // State preserved across flush (anti-clear regression pin).
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.last_fired_at("delete-storm", "m-42"),
            Some(1_700_000_070)
        );
        let suppressed = ledger
            .is_suppressed("delete-storm", "m-42", 1_700_000_100, 60)
            .unwrap();
        assert!(suppressed, "fire bookmark must survive flush");
    }

    #[test]
    fn in_memory_stats_entry_count_matches_len_across_lifecycle() {
        // Default-impl `stats` derives `entry_count` from `len`.
        // Pin the parity across the buffer's lifecycle (empty,
        // single, multi, post-clear) so a regression that diverges
        // the two — e.g. a future override that reads from a stale
        // cached counter — is caught.
        let mut ledger = InMemoryDedupLedger::new();

        // Empty
        assert_eq!(ledger.stats(), DedupLedgerStats::with_entry_count(0));
        assert_eq!(ledger.stats().entry_count, ledger.len());

        // Single
        ledger.observe("p1", "m-a", 1_700_000_000).unwrap();
        assert_eq!(ledger.stats(), DedupLedgerStats::with_entry_count(1));
        assert_eq!(ledger.stats().entry_count, ledger.len());

        // Multi (3 distinct keys)
        ledger.observe("p1", "m-b", 1_700_000_000).unwrap();
        ledger.observe("p2", "m-a", 1_700_000_000).unwrap();
        assert_eq!(ledger.stats(), DedupLedgerStats::with_entry_count(3));
        assert_eq!(ledger.stats().entry_count, ledger.len());

        // Overwrite of an existing key MUST NOT inflate entry_count
        ledger.observe("p1", "m-a", 1_700_000_050).unwrap();
        assert_eq!(ledger.stats(), DedupLedgerStats::with_entry_count(3));
        assert_eq!(ledger.stats().entry_count, ledger.len());

        // Post-clear
        ledger.clear().unwrap();
        assert_eq!(ledger.stats(), DedupLedgerStats::with_entry_count(0));
        assert_eq!(ledger.stats().entry_count, ledger.len());
    }

    #[test]
    fn dedup_ledger_stats_constructor_clone_partial_eq_round_trip() {
        // Cross-crate callers override `stats` and construct via
        // `DedupLedgerStats::with_entry_count` because
        // `#[non_exhaustive]` forbids struct-literal construction.
        // Pin Clone+PartialEq so a regression that diverges the
        // two — e.g. accidentally hand-rolling PartialEq with a
        // custom comparator — surfaces here, separate from the
        // Debug-surface pin below.
        let s = DedupLedgerStats::with_entry_count(42);
        assert_eq!(s.entry_count, 42);
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn dedup_ledger_stats_debug_surface_includes_struct_name_and_count() {
        // Operator dashboards / log lines render `DedupLedgerStats`
        // via `Debug`.  Pin both the struct-name and the count so
        // a regression that swapped to a tuple-struct or stripped
        // the field name would surface here.  Kept separate from
        // the Clone/PartialEq pin so a Debug-only regression does
        // not masquerade as an equality bug.
        let s = DedupLedgerStats::with_entry_count(42);
        let rendered = format!("{s:?}");
        assert!(rendered.contains("42"), "Debug must surface count");
        assert!(
            rendered.contains("DedupLedgerStats"),
            "Debug must name the struct"
        );
    }

    #[test]
    fn flush_and_stats_dispatch_through_box_dyn() {
        // Trait-object pin: both new methods MUST be reachable via
        // `Box<dyn DedupLedger>` so a persistent backend wrapped in
        // a Box at construction (the canonical
        // `DetectorState::with_ledger` injection path) can have
        // `flush` and `stats` called on it without downcast.  A
        // regression that accidentally added a generic parameter
        // to either method would break object-safety and fail this
        // test at compile time.
        let mut boxed: Box<dyn DedupLedger> = Box::new(InMemoryDedupLedger::new());
        boxed.observe("p1", "m-a", 1_700_000_000).unwrap();
        boxed.flush().expect("dispatch-via-dyn flush works");
        assert_eq!(boxed.stats(), DedupLedgerStats::with_entry_count(1));
    }

    #[test]
    fn backend_failure_helper_sanitises_and_caps_reason() {
        // Defence-in-depth: the helper constructor MUST sanitise so a
        // backend whose error message echoes attacker-controlled
        // bytes cannot reach the orchestrator-boundary `From` impl
        // with raw control characters or an unbounded-length string.
        let raw = "rocksdb: io error\nINJ\x1b[31mred";
        let err = DedupLedgerError::backend_failure(raw);
        let display = format!("{err}");
        assert!(!display.contains('\n'), "newline must be sanitised");
        assert!(!display.contains('\x1b'), "ANSI escape must be sanitised");
        assert!(display.contains("INJ"), "letters preserved");
        assert!(display.contains("red"), "letters preserved");
        assert!(
            display.contains("backend failure"),
            "wrapper text preserved"
        );

        // Cap: 1 KiB of As must be truncated by sanitize_log_string's
        // 256-byte limit before reaching the Display surface.
        let huge = "A".repeat(1024);
        let err_big = DedupLedgerError::backend_failure(&huge);
        let display_big = format!("{err_big}");
        let a_count = display_big.chars().filter(|c| *c == 'A').count();
        assert!(
            a_count <= 256,
            "reason capped at 256 bytes (got {a_count} A's)"
        );
    }
}
