//! EPHEMERAL Anomaly Pattern Library envelope verification.
//!
//! Phase C.4 (§3.5.1, R8.A1) defines an `AnomalyPatternLibrary` —
//! a signed CBOR artifact that carries operator-curated behavioural
//! anomaly patterns to the audit pipeline.  The artifact is wrapped in
//! a role-discriminated `COSE_Sign1` envelope signed by an
//! [`AnchorRole::AnomalyLibrarySigner`]-authorised key.  This crate
//! owns the envelope-verification primitives; pattern evaluation lives
//! in later phases and consumers.
//!
//! # Layering
//!
//! [`verify_anomaly_library_signature`] layers on top of
//! [`ephemeral_crypto::verify_cose_sign1_with_cap`] with a larger
//! per-envelope byte cap ([`signature::MAX_ANOMALY_LIBRARY_BYTES`] =
//! 128 KiB) than the default [`ephemeral_crypto::MAX_COSE_BYTES`] (64
//! KiB).  The classic Tariff / classifier / delegation envelopes
//! continue to enforce the tighter default; the raised cap is scoped
//! to this crate.
//!
//! # Role discrimination
//!
//! The verifier requires that the matched trust anchor is registered
//! under [`ephemeral_crypto::AnchorRole::AnomalyLibrarySigner`].  A
//! tariff-, classifier-, or delegation-signed envelope with a matching
//! `kid` fails the role check at the crypto layer and surfaces as
//! [`AnomalyLibError::CoseVerifyFailed`].  Role leakage is contained:
//! kid-unknown, role-mismatched, and signature-invalid all collapse
//! to the same outer failure so an attacker probing the anchor set
//! cannot enumerate role assignments.
//!
//! # Domain-separation AAD
//!
//! [`signature::ANOMALY_LIBRARY_AAD`] = `b"ephemeral/anomaly-library/v1"`.
//! The `/v1` suffix names the ABI-v1 envelope shape declared here; a
//! future v2 envelope with a structurally different payload MUST pick
//! a new AAD so v1 and v2 envelopes cannot be replayed interchangeably
//! even if both share the same signer key.
//!
//! # Scope of Session 2
//!
//! Extends the Session-1 envelope + 6-step verifier with Stage 7 —
//! pattern-body invariant validation.  After Session 2 a verified
//! library carries a decoded, structurally-validated
//! `Vec<PatternEntry>`; Session 3+ can rely on the pattern table
//! being unique, severity-action consistent, verb-family resolved,
//! and companion-pair sound per §3.5.3.
//!
//! Session-1-signed envelopes (no `patterns` field) continue to
//! verify successfully — they decode to `patterns = Vec::new()` via
//! the `#[serde(default)]` attribute on
//! [`schema::AnomalyLibraryPayload::patterns`], and all four Stage-7
//! invariant checks trivially pass on an empty slice.  This
//! forward-compat is pinned by the regression test
//! `session_one_envelope_decodes_with_empty_patterns`.
//!
//! # Scope of Session 3
//!
//! Adds Stage 8 — replay protection via an external
//! [`AnomalyLedger`].  The stateless
//! [`verify_anomaly_library_signature`] entry point is preserved
//! unchanged for bootstrap and fuzz flows; production verifiers
//! should switch to
//! [`verify_anomaly_library_signature_with_ledger`] so monotonic
//! `library_version` is enforced per `library_id` (§3.5.1 reject
//! code `pattern-library-version-too-old`).  V1 of the ledger is
//! first-observation-wins; seed-from-ceremony bootstrap (V2+) is
//! additive and can land without breaking existing callers.
//!
//! # Scope-out: remaining stateful checks (Session 5+)
//!
//! - Per-pattern high-water-mark tracking and the
//!   `PatternRelaxationException` flow (§3.5.1 threshold-HWM ratchet).
//!   Session 3 solves `library_version` monotonicity only; the
//!   per-threshold ratchet with `ceremony_quorum` is a separate
//!   protection surface that remains scoped to Session 5.
//! - Bootstrap-from-ceremony seeding of the replay ledger.  V1
//!   accepts a library_id's first observation at whatever version
//!   the envelope declares; V2 can add `with_bootstrap_hwm` without
//!   breaking the V1 API.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// Normative identifiers (COSE_Sign1, AnomalyPatternLibrary) appear
// verbatim in docs and would be verbose to backtick everywhere.
#![allow(clippy::doc_markdown)]

/// ABI revision implemented by this crate's envelope verifier.
///
/// A breaking change to the `AnomalyLibraryPayload` shape (field
/// rename, semantic repurpose, or removal) MUST bump this value.
/// Callers pass this constant as `expected_abi_version` to
/// [`verify_anomaly_library_signature`]; a signed payload declaring a
/// different version fails with
/// [`AnomalyLibError::AbiVersionMismatch`].
///
/// Forward-compatible additions (extra fields the verifier ignores on
/// decode) do NOT bump this constant — the envelope shape is stable
/// within a major version.
pub const ANOMALY_LIBRARY_ABI_VERSION: u32 = 1;

pub mod dedup_ledger;
pub mod errors;
// `evaluators` hosts the Session 5-B per-firing-rule evaluators
// (FirstMatch, SequenceMatch, CumulativeOverBaseline).  The public
// entry point is [`state::DetectorState::evaluate_all`]; evaluators
// themselves are internal detail — `pub(crate)` keeps the prod rlib
// symbol surface minimal (tracked by `prod-symbol-probe`).
pub(crate) mod evaluators;
pub mod event;
pub mod families;
pub mod fire;
pub mod invariants;
pub mod ledger;
pub mod orchestrator;
pub mod patterns;
pub mod schema;
pub mod scope;
// `scope_match` only adds `impl` blocks to types already re-exported via
// `pub use scope::{...}`; it contributes no items that a downstream
// consumer would import directly.  Keeping the module `pub(crate)` avoids
// widening the crate's public path surface with an impl-only path that
// Session 5-B callers could inadvertently bind to.
pub(crate) mod scope_match;
pub mod signature;
pub mod state;

#[cfg(feature = "test_fixtures")]
pub mod test_fixtures;

pub use dedup_ledger::{
    DedupLedger, DedupLedgerError, DedupLedgerStats, InMemoryDedupLedger,
    MAX_DEDUP_ENTRIES_PER_TENANT,
};
pub use errors::{AnomalyLibError, FiringCompanionFailure, StreamError};
pub use event::{
    AuditStreamInput, CanonicalizedEvent, Outcome, PatternDescription, TemplateEvent,
    MAX_EXPANDED_EVENTS,
};
pub use fire::{AnomalyDetectedRecord, AnomalyFire, MatchScope};
pub use ledger::{AnomalyLedger, InMemoryAnomalyLedger, LedgerError, LedgerObservation};
pub use orchestrator::AuditOrchestrator;
pub use patterns::{Action, FiringRule, PatternEntry, Severity, Threshold};
pub use schema::AnomalyLibraryPayload;
pub use scope::{MandateScope, ScopePredicate, VerbPredicate};
pub use signature::{
    verify_anomaly_library_signature, verify_anomaly_library_signature_with_ledger,
    VerifiedAnomalyLibrarySignature, ANOMALY_LIBRARY_AAD, MAX_ANOMALY_LIBRARY_BYTES,
};
pub use state::{
    DetectorState, PatternBuffer, ScopeBucketKey, SequenceTracker, MAX_CLOCK_SKEW_SECONDS,
    MAX_EVENTS_PER_BUFFER, MAX_EVENTS_PER_MANDATE,
};
