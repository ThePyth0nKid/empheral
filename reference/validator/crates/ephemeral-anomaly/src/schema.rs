//! CBOR schema for the `AnomalyPatternLibrary` envelope payload.
//!
//! # Session 1 subset
//!
//! This initial slice carries only the envelope header fields — enough
//! to authenticate the library and its validity window, not yet its
//! body of patterns.  The pattern list lands in Session 2+; forward
//! compatibility is preserved because ciborium's deserializer silently
//! ignores unknown fields on decode, so a Session-2-signed envelope
//! carrying a `patterns` array decodes cleanly in Session-1 code (the
//! `patterns` array is simply dropped).  The outer Ed25519 signature
//! commits to the full CBOR bytes, so forward-compat is structural:
//! extending the schema does not break signatures on already-signed
//! envelopes that only use the Session-1 subset.
//!
//! # Field validation
//!
//! Structural deserialization via serde/ciborium is necessary but not
//! sufficient.  [`crate::signature::verify_anomaly_library_signature`]
//! additionally enforces:
//!
//! - `signer_kid.len() ≤ MAX_INNER_KID_BYTES` (256 bytes)
//! - `library_id.len() ≤ MAX_LIBRARY_ID_BYTES` (256 bytes)
//! - `abi_version == caller.expected_abi_version`
//! - `signer_kid == outer COSE header kid`
//! - `issued_at ≤ now ≤ expires_at`
//!
//! # Signer-side invariant (NOT verifier-enforced)
//!
//! A well-formed signer MUST produce `issued_at ≤ expires_at`.  The
//! verifier does not check this — an inverted window (e.g. swapped
//! fields) will always fail the `now < issued_at` guard first and
//! surface as [`crate::errors::AnomalyLibError::NotYetValid`], which
//! is the safe fail-closed behaviour.  Operators seeing a persistent
//! `NotYetValid` for an otherwise-fresh library should suspect a
//! signer-side window inversion rather than clock skew.

use serde::Deserialize;

// `Serialize` is ONLY needed for test fixtures (inline tests build a
// payload, then CBOR-encode it via `ciborium::into_writer` to produce
// signed envelopes; Session 2+ `test_fixtures` signing helpers will do
// the same).  The production verifier deserialises only, so keeping
// `Serialize` out of the default build avoids dead weight in the prod
// rlib — the `prod-symbol-probe` feature-leak guard becomes slightly
// stricter as a result.
#[cfg(any(test, feature = "test_fixtures"))]
use serde::Serialize;

/// Payload structure for the `AnomalyPatternLibrary` envelope.
///
/// Deserialized from the `COSE_Sign1` inner payload after the outer
/// signature has been cryptographically verified.  Field names use
/// ciborium's default snake_case mapping so the wire format matches
/// the declared identifier verbatim — named-indexed rather than
/// position-indexed so backward-compatible extensions can be added
/// without breaking existing verifiers.
///
/// # Fields
///
/// - `abi_version` — the schema version this payload was authored
///   against.  Currently [`crate::ANOMALY_LIBRARY_ABI_VERSION`] = 1.
/// - `signer_kid` — human-readable signer identity, duplicated from
///   the outer COSE protected-header `kid`.  The verifier enforces
///   byte-exact equality between the two as a defense-in-depth check.
/// - `library_id` — stable identifier of *this* anomaly library (a
///   single operator may publish multiple libraries, e.g. one per
///   deployment environment).  Attacker-controlled in the sense that
///   a rogue signer picks the label; downstream log sinks see the
///   sanitised form via [`crate::errors::sanitize_log_string`].
/// - `library_version` — monotonic version counter for `library_id`.
///   A replay of an older envelope will decode cleanly; replay
///   protection belongs at the consumer side (e.g. the audit pipeline
///   MUST reject a library_version ≤ the last-seen one for that
///   library_id).  This crate does not maintain state, so it cannot
///   enforce monotonicity itself.
/// - `issued_at` — unix epoch seconds (signed i64) marking the start
///   of the validity window.  A library with a future `issued_at`
///   cannot be consumed yet — the verifier rejects with
///   [`crate::errors::AnomalyLibError::NotYetValid`].
/// - `expires_at` — unix epoch seconds (signed i64) marking the end
///   of the validity window.  A library whose `expires_at` has passed
///   MUST be rotated by the operator; the verifier rejects with
///   [`crate::errors::AnomalyLibError::Expired`].
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize)]
pub struct AnomalyLibraryPayload {
    /// ABI revision the payload was signed against.  Must equal the
    /// caller's `expected_abi_version` at verification time.
    pub abi_version: u32,
    /// Signer identity, duplicated from the outer COSE `kid`.
    pub signer_kid: String,
    /// Stable library identifier (curation namespace).
    pub library_id: String,
    /// Monotonic version counter within `library_id`.
    pub library_version: u64,
    /// Start of validity window (unix epoch seconds).
    pub issued_at: i64,
    /// End of validity window (unix epoch seconds).
    pub expires_at: i64,
}
