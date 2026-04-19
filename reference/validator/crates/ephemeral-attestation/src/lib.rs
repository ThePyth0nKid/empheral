//! EPHEMERAL AWS Nitro Enclave attestation verification primitives.
//!
//! This crate provides panic-free, adversarial-input-safe verification for
//! AWS Nitro Enclave attestation documents and (optionally) Rekor Merkle
//! inclusion proofs.
//!
//! # Entry points
//!
//! ```text
//! verify_nitro_attestation(doc_cose_bytes, roots, expected_nonce, current_time)
//!     → NitroClaims
//!
//! verify_pcr_set(claims, expected)
//!     → ()
//!
//! verify_rekor_inclusion(entry, payload_hash, tree_root)   [feature = "rekor"]
//!     → ()
//! ```
//!
//! `current_time` is caller-supplied Unix seconds used for cert validity
//! checks; policy-level freshness against the returned
//! `NitroClaims.timestamp` is the suite layer's concern.
//!
//! # Layering
//!
//! This crate has **no dependency** on `ephemeral-core` or `ephemeral-crypto`.
//! It is a standalone leaf crate; mapping attestation results to suite-specific
//! codes lives upstream. The COSE bridge is implemented locally (~60 LoC) to
//! avoid a circular-dependency risk as the workspace grows.
//!
//! # Size and depth caps
//!
//! Adversarial CBOR is gated before handing bytes to `coset` or `ciborium`:
//! - [`MAX_NITRO_DOC_BYTES`] = 128 KiB
//! - [`MAX_CBOR_DEPTH`] = 8
//! - [`MAX_CA_CHAIN_DEPTH`] = 4
//! - [`MAX_PCR_COUNT`] = 24

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// Normative identifiers (COSE_Sign1, Sig_structure_1, ES384) appear
// throughout docs verbatim; backticking every occurrence hurts traceability
// to RFC 9052 more than it helps.
#![allow(clippy::doc_markdown)]

mod anchors;
mod cert;
mod cose_bridge;
pub mod error;
mod nitro;
mod pcr;
mod size_guard;

#[cfg(feature = "rekor")]
pub mod rekor;

pub use anchors::NitroRootSet;
pub use error::AttestError;
pub use nitro::{verify_nitro_attestation, NitroClaims};
pub use pcr::verify_pcr_set;
pub use size_guard::{MAX_CA_CHAIN_DEPTH, MAX_CBOR_DEPTH, MAX_NITRO_DOC_BYTES, MAX_PCR_COUNT};

/// SHA-256 fingerprint of the AWS Nitro Enclave Root Certificate (G1).
///
/// Source: <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
/// Downloaded from:
/// <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
///
/// Verified independently via `openssl x509 -in root.pem -fingerprint -sha256`.
/// This fingerprint is stable for 30 years (root lifetime).
pub const AWS_NITRO_ROOT_FINGERPRINT: [u8; 32] = [
    0x64, 0x1A, 0x03, 0x21, 0xA3, 0xE2, 0x44, 0xEF,
    0xE4, 0x56, 0x46, 0x31, 0x95, 0xD6, 0x06, 0x31,
    0x7E, 0xD7, 0xCD, 0xCC, 0x3C, 0x17, 0x56, 0xE0,
    0x98, 0x93, 0xF3, 0xC6, 0x8F, 0x79, 0xBB, 0x5B,
];
