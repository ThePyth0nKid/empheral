//! Replay-protection ledger for anomaly-library signature verification
//! (§3.5.1 monotonic `library_version`).
//!
//! # What this ledger enforces
//!
//! The spec requires that for a given `library_id`, every subsequent
//! signed library MUST declare a `library_version` strictly greater than
//! the highest version previously accepted by the validator.  A signer
//! that re-publishes an older library (intentionally, to roll back a
//! tightened pattern set, or accidentally, by re-issuing a stale
//! envelope) MUST be rejected with the spec-named reject code
//! `pattern-library-version-too-old` — surfaced here as
//! [`crate::errors::AnomalyLibError::LibraryVersionTooOld`].
//!
//! This module owns the HWM state and the observation API; the
//! verifier in [`crate::signature`] calls into it as Stage 8 (after
//! Stage 7's pattern-body invariants succeed — see fail-order rationale
//! in [`verify_anomaly_library_signature_with_ledger`]).
//!
//! # Scope of V1 (Session 3)
//!
//! - **First-observation-wins bootstrap.**  A library_id that has
//!   never been observed by this ledger is accepted at whatever version
//!   the envelope declares.  Returned as
//!   [`LedgerObservation::FirstObservation`].  V2/V3 (seed-from-ceremony,
//!   bootstrap-attestation) can be layered on additively without breaking
//!   existing callers or stored state.
//! - **Strict-greater comparison (`>`).**  Analog to Tariff Step 10's
//!   rotation-ledger discipline.  Equality rejects — this closes the
//!   replay window on a previously-accepted envelope without requiring
//!   the caller to remember the last-seen bytes.
//! - **Raw `library_id` as key.**  [`crate::errors::sanitize_log_string`]
//!   is lossy on UTF-8 multi-byte chars (every non-ASCII byte maps to
//!   `'?'`), so using the sanitised form would collide two legitimate-
//!   but-visually-similar library_ids (e.g. `"lib::foö"` and
//!   `"lib::foÖ"` both sanitise to `"lib::fo?"`).  Collision would
//!   manifest as over-rejection (later signer sees mismatched HWM), an
//!   accessibility bug for operators using non-ASCII ids.  We keep the
//!   raw bytes here; sanitisation happens only at error-surface and
//!   Verified-struct construction boundaries.
//!
//! # Scope-out (deferred)
//!
//! - Persistence.  [`InMemoryAnomalyLedger`] is process-local.  A
//!   disk- or database-backed impl can implement the same trait
//!   without any signature-module change; consumers pick the backend.
//! - Bootstrap from a ceremony seed (threshold-HWM analog for
//!   `library_version`).  V1 accepts first-observation; a future V2
//!   can add `with_bootstrap_hwm(library_id, version)` or similar.
//! - Per-pattern high-water-marks and `PatternRelaxationException`
//!   flow (§3.5.1).  Those concern pattern *thresholds*, not the
//!   library envelope version, and are deferred to Session 5.

use std::collections::HashMap;

use thiserror::Error;

/// Outcome of a successful ledger observation.
///
/// Returned by [`AnomalyLedger::observe`] when the new
/// `library_version` is acceptable.  The two variants are
/// differentiable so a caller that wants to audit "this is a
/// first-ever load" separately from "this advanced the HWM from N to
/// M" can branch on the outcome without needing to read the ledger's
/// internal state.
///
/// `#[non_exhaustive]` so a future V2/V3 bootstrap mode (e.g.
/// `BootstrappedFromCeremony`) can appear without breaking downstream
/// exhaustive matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerObservation {
    /// No prior observation existed for this `library_id`; the ledger
    /// stored the declared version as the initial HWM.
    FirstObservation,
    /// The declared version advanced strictly past the previously-
    /// stored HWM, which is carried here for audit/log purposes.  The
    /// ledger has updated its internal state to the new version.
    AdvancedFrom(u64),
}

/// Failure surface for [`AnomalyLedger::observe`].
///
/// `#[non_exhaustive]` so future backends can add I/O / persistence
/// variants without breaking downstream exhaustive matches.
///
/// The `library_id` field carries the **raw** (un-sanitised) bytes
/// from the signed payload.  The caller site in
/// [`crate::signature::verify_anomaly_library_signature_with_ledger`]
/// maps this variant into
/// [`crate::errors::AnomalyLibError::LibraryVersionTooOld`] and applies
/// [`crate::errors::sanitize_log_string`] at that boundary, so log-
/// injection defense-in-depth is preserved without this module having
/// to depend on the log-sanitiser helper.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    /// The attempted `library_version` does not strictly exceed the
    /// currently-stored HWM for `library_id`.  Equality is rejected
    /// (replay of the exact same version) as well as any lower value
    /// (rollback).
    #[error(
        "library_version for `{library_id}` must be strictly greater than current HWM \
         {current_hwm}, got {attempted}"
    )]
    VersionNotStrictlyGreater {
        /// Raw (un-sanitised) library_id from the rejected envelope.
        /// Callers that render this variant to a log surface MUST
        /// sanitise first — [`crate::errors::sanitize_log_string`] is
        /// the canonical transform.
        library_id: String,
        /// HWM currently stored for `library_id`.
        current_hwm: u64,
        /// Version the rejected envelope declared.
        attempted: u64,
    },
}

/// Ledger trait consumed by
/// [`crate::signature::verify_anomaly_library_signature_with_ledger`].
///
/// # Object-safety
///
/// The sole method takes a `&str` and a `u64` and returns owned types,
/// so the trait is object-safe: callers can dispatch via
/// `&mut dyn AnomalyLedger` to swap backends (in-memory for tests,
/// persistent for production) without generic instantiation per
/// call-site.
///
/// # `Send` bound
///
/// Implementors MUST be `Send` so a `Box<dyn AnomalyLedger>` or an
/// `Arc<Mutex<dyn AnomalyLedger>>` can be moved across threads in
/// async / worker-pool contexts.  The bound is on the trait rather
/// than on individual call sites because the ledger is typically held
/// for the lifetime of a long-running verifier service.
///
/// `Sync` is intentionally NOT required: the ledger is mutated through
/// `&mut self`, and any cross-thread sharing goes through an external
/// mutex that supplies the synchronisation.  Requiring `Sync` would
/// block simple non-`Sync` backends (e.g. a ledger wrapping a
/// `RefCell`-based cache).
pub trait AnomalyLedger: Send {
    /// Observe that an anomaly library carrying `library_id` at
    /// `library_version` has just verified signature + pattern-body
    /// invariants.  Update the HWM if the version advances strictly.
    ///
    /// Returns:
    /// - [`LedgerObservation::FirstObservation`] if no HWM existed.
    /// - [`LedgerObservation::AdvancedFrom(prior_hwm)`] if the version
    ///   advanced strictly.
    ///
    /// # Errors
    ///
    /// - [`LedgerError::VersionNotStrictlyGreater`] if the declared
    ///   version is equal to or lower than the stored HWM.
    fn observe(
        &mut self,
        library_id: &str,
        library_version: u64,
    ) -> Result<LedgerObservation, LedgerError>;
}

/// Default in-memory implementation of [`AnomalyLedger`].
///
/// State is a `HashMap<String, u64>` from raw `library_id` to the
/// highest-observed `library_version`.  Process-local and intentionally
/// non-persistent: tests and short-lived consumers get a zero-friction
/// default; production deployments that need durable state can supply
/// their own impl.
///
/// `Default` returns an empty ledger; [`InMemoryAnomalyLedger::new`] is
/// the documented constructor.
#[derive(Debug, Default)]
pub struct InMemoryAnomalyLedger {
    /// Raw `library_id` → highest-observed `library_version`.
    state: HashMap<String, u64>,
}

impl InMemoryAnomalyLedger {
    /// Construct an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl AnomalyLedger for InMemoryAnomalyLedger {
    fn observe(
        &mut self,
        library_id: &str,
        library_version: u64,
    ) -> Result<LedgerObservation, LedgerError> {
        // Probe via `get_mut` so the strict-greater path mutates in
        // place without a second hash lookup and without allocating a
        // duplicate String for the key.  The first-observation path
        // still pays one allocation (to own the key); the reject path
        // pays one allocation (to carry the id into the error variant).
        if let Some(hwm_slot) = self.state.get_mut(library_id) {
            let hwm = *hwm_slot;
            if library_version > hwm {
                *hwm_slot = library_version;
                Ok(LedgerObservation::AdvancedFrom(hwm))
            } else {
                Err(LedgerError::VersionNotStrictlyGreater {
                    library_id: library_id.to_owned(),
                    current_hwm: hwm,
                    attempted: library_version,
                })
            }
        } else {
            self.state.insert(library_id.to_owned(), library_version);
            Ok(LedgerObservation::FirstObservation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_observation_on_empty_ledger_returns_first_observation() {
        let mut ledger = InMemoryAnomalyLedger::new();
        let obs = ledger
            .observe("lib::alpha", 1)
            .expect("first observation must succeed");
        assert_eq!(obs, LedgerObservation::FirstObservation);
    }

    #[test]
    fn strictly_greater_version_returns_advanced_from_prior_hwm() {
        let mut ledger = InMemoryAnomalyLedger::new();
        ledger.observe("lib::alpha", 1).unwrap();
        let obs = ledger
            .observe("lib::alpha", 2)
            .expect("strict-greater advance must succeed");
        assert_eq!(obs, LedgerObservation::AdvancedFrom(1));
    }

    #[test]
    fn equal_version_rejected_with_current_hwm_and_attempted() {
        let mut ledger = InMemoryAnomalyLedger::new();
        ledger.observe("lib::alpha", 5).unwrap();
        let err = ledger
            .observe("lib::alpha", 5)
            .expect_err("equal version must reject (no replay)");
        assert_eq!(
            err,
            LedgerError::VersionNotStrictlyGreater {
                library_id: "lib::alpha".to_string(),
                current_hwm: 5,
                attempted: 5,
            }
        );
    }

    #[test]
    fn lower_version_rejected_with_current_hwm_and_attempted() {
        let mut ledger = InMemoryAnomalyLedger::new();
        ledger.observe("lib::alpha", 5).unwrap();
        let err = ledger
            .observe("lib::alpha", 3)
            .expect_err("lower version must reject (rollback)");
        assert_eq!(
            err,
            LedgerError::VersionNotStrictlyGreater {
                library_id: "lib::alpha".to_string(),
                current_hwm: 5,
                attempted: 3,
            }
        );
    }

    #[test]
    fn rejected_observation_preserves_existing_hwm() {
        // After a rejected observation, the HWM for that library_id
        // must remain at its previous value — no partial update, no
        // leakage from the attempted version.  Verified behaviourally:
        // a subsequent version == prior HWM + 1 still advances.
        let mut ledger = InMemoryAnomalyLedger::new();
        ledger.observe("lib::alpha", 5).unwrap();
        let _ = ledger.observe("lib::alpha", 3); // reject, ignore
        let obs = ledger
            .observe("lib::alpha", 6)
            .expect("post-reject advance must succeed");
        assert_eq!(obs, LedgerObservation::AdvancedFrom(5));
    }

    #[test]
    fn two_distinct_library_ids_advance_independently() {
        // The HWM is scoped by library_id.  Storing version 10 for
        // lib::alpha must not bleed into lib::beta's namespace — a
        // fresh load of lib::beta@1 is a FirstObservation, not a
        // rollback.
        let mut ledger = InMemoryAnomalyLedger::new();
        ledger.observe("lib::alpha", 10).unwrap();
        let beta_first = ledger.observe("lib::beta", 1).unwrap();
        assert_eq!(beta_first, LedgerObservation::FirstObservation);
        let alpha_advance = ledger.observe("lib::alpha", 11).unwrap();
        assert_eq!(alpha_advance, LedgerObservation::AdvancedFrom(10));
    }

    #[test]
    fn multi_step_monotonic_advance_propagates_hwm() {
        // Sequentially advance through several versions and check each
        // AdvancedFrom carries the immediately prior HWM, not the
        // first-ever or max-ever.  Pins that the stored HWM is
        // overwritten on every successful advance.
        let mut ledger = InMemoryAnomalyLedger::new();
        assert_eq!(
            ledger.observe("lib::alpha", 1).unwrap(),
            LedgerObservation::FirstObservation
        );
        assert_eq!(
            ledger.observe("lib::alpha", 3).unwrap(),
            LedgerObservation::AdvancedFrom(1)
        );
        assert_eq!(
            ledger.observe("lib::alpha", 10).unwrap(),
            LedgerObservation::AdvancedFrom(3)
        );
        assert_eq!(
            ledger.observe("lib::alpha", 11).unwrap(),
            LedgerObservation::AdvancedFrom(10)
        );
    }

    #[test]
    fn ledger_error_display_contains_library_id_current_hwm_and_attempted() {
        let err = LedgerError::VersionNotStrictlyGreater {
            library_id: "lib::alpha".to_string(),
            current_hwm: 7,
            attempted: 5,
        };
        let display = format!("{err}");
        assert!(display.contains("lib::alpha"), "display = {display}");
        assert!(display.contains('7'), "display = {display}");
        assert!(display.contains('5'), "display = {display}");
    }

    #[test]
    fn in_memory_ledger_is_send_and_object_safe() {
        // Compile-time proofs: the trait must be object-safe (usable
        // behind `&mut dyn AnomalyLedger`), the default impl must be
        // Send (movable across threads), and a `Box<dyn>` must also be
        // Send so async/worker-pool callers can hand it off.
        fn assert_send<T: Send + ?Sized>() {}
        fn assert_object_safe(_: &mut dyn AnomalyLedger) {}

        assert_send::<InMemoryAnomalyLedger>();
        let mut ledger = InMemoryAnomalyLedger::new();
        assert_object_safe(&mut ledger);

        let boxed: Box<dyn AnomalyLedger> = Box::new(InMemoryAnomalyLedger::new());
        // Assert `Box<dyn AnomalyLedger>: Send` via turbofish — using a
        // `&Box<T>` helper would trigger `clippy::borrowed_box` with no
        // semantic gain over the direct type-parameter form.
        assert_send::<Box<dyn AnomalyLedger>>();
        let _ = &boxed; // tie the variable so Box survives to the dyn dispatch call below

        // Smoke-test the dyn dispatch path so a regression that
        // accidentally broke object-safety (e.g. adding a generic
        // method) is caught here as a compile error — not just in the
        // bound assertions.
        let mut also_dyn: Box<dyn AnomalyLedger> = boxed;
        let obs = also_dyn.observe("lib::dyn", 1).unwrap();
        assert_eq!(obs, LedgerObservation::FirstObservation);
    }
}
