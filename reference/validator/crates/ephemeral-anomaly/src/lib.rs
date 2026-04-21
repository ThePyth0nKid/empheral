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
//! # Scope of Session 1
//!
//! This initial slice lands the envelope + 6-step verification
//! pipeline only: outer COSE verify, CBOR decode, shape check, ABI
//! pinning, signer-kid consistency, and time-bounds.  The pattern body
//! (Session 2+) is an opaque forward-compatibility zone: unknown
//! payload fields are silently ignored by serde/ciborium, so a
//! Session-2-signed envelope decodes cleanly in Session-1 code (with
//! patterns dropped).

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

pub mod errors;
pub mod schema;
pub mod signature;

pub use errors::AnomalyLibError;
pub use schema::AnomalyLibraryPayload;
pub use signature::{
    verify_anomaly_library_signature, VerifiedAnomalyLibrarySignature, ANOMALY_LIBRARY_AAD,
    MAX_ANOMALY_LIBRARY_BYTES,
};
