//! EPHEMERAL live crypto primitives: COSE_Sign1 verify + delegation-chain walk.
//!
//! All verification paths are panic-free on untrusted input (enforced via
//! property-tests). Size and depth caps (see [`MAX_COSE_BYTES`],
//! [`MAX_CBOR_DEPTH`]) gate adversarial CBOR before handing off to `coset`
//! or `ed25519-dalek`.
//!
//! # Layering
//!
//! This crate has **no dependency** on `ephemeral-core`. Mapping from
//! [`CoseError`] to suite-specific reject codes (e.g. `TariffRejectCode`)
//! lives in `ephemeral-core`. Keep the one-way dependency.
//!
//! # Phase C.1 scope
//!
//! Ed25519 (COSE `alg = -8`) only. ECDSA (P-256/P-384), ML-DSA, and PCR/TPM
//! quote verification land in C.2+. The algorithm enum is already
//! `#[non_exhaustive]` so extending it is a non-breaking change.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// Normative RFC/COSE identifiers (COSE_Sign1, Sig_structure_1, Ed25519)
// appear throughout the docs verbatim; backticking every occurrence hurts
// readability and traceability to RFC 9052 more than it helps.
#![allow(clippy::doc_markdown)]

mod alg;
mod anchors;
mod chain;
mod cose;
pub mod error;
mod size_guard;
mod verify;

pub use alg::{Alg, COSE_ALG_EDDSA};
pub use anchors::{AnchorRole, TrustAnchor, TrustAnchorSet};
pub use chain::{verify_chain_link, MAX_CHAIN_DEPTH};
pub use error::CoseError;
pub use size_guard::{size_depth_check, size_depth_check_with_cap, MAX_CBOR_DEPTH, MAX_COSE_BYTES};
pub use verify::{verify_cose_sign1, verify_cose_sign1_with_cap, VerifiedPayload};
