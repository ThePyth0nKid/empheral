//! Error surface for Nitro attestation verification.
//!
//! [`AttestError`] is `#[non_exhaustive]` so that future variants
//! (new certificate formats, new attestation doc fields) can be added
//! without breaking downstream `match` arms.
//!
//! External-library errors are wrapped in opaque source newtypes
//! ([`CoseAttSource`], [`X509Source`], [`EcdsaSource`], [`RekorSource`])
//! so that downstream consumers cannot match on library internals —
//! version bumps of `coset`, `x509-parser`, or `ecdsa` stay internal.

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Opaque source wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque wrapper for `coset::CoseError` sources.
///
/// Retained for `source()`-chain traversal only; Debug/Display render a
/// generic message so downstream code cannot depend on coset internals.
pub struct CoseAttSource(#[allow(dead_code)] pub(crate) coset::CoseError);

impl core::fmt::Debug for CoseAttSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CoseAttSource").finish_non_exhaustive()
    }
}

impl core::fmt::Display for CoseAttSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("cose decode failure")
    }
}

impl std::error::Error for CoseAttSource {}

/// Opaque wrapper for `x509_parser` errors.
///
/// Retained for error-chain traversal only.
pub struct X509Source(#[allow(dead_code)] pub(crate) x509_parser::error::X509Error);

impl core::fmt::Debug for X509Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X509Source").finish_non_exhaustive()
    }
}

impl core::fmt::Display for X509Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("x509 parse/verify failure")
    }
}

impl std::error::Error for X509Source {}

/// Opaque wrapper for `ecdsa::Error` sources.
pub struct EcdsaSource(#[allow(dead_code)] pub(crate) ecdsa::Error);

impl core::fmt::Debug for EcdsaSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcdsaSource").finish_non_exhaustive()
    }
}

impl core::fmt::Display for EcdsaSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ecdsa verify failure")
    }
}

impl std::error::Error for EcdsaSource {}

/// Opaque wrapper for Rekor proof failures.
///
/// Carries a static description string; no external library type exposed.
pub struct RekorSource(#[allow(dead_code)] pub(crate) &'static str);

impl core::fmt::Debug for RekorSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RekorSource").finish_non_exhaustive()
    }
}

impl core::fmt::Display for RekorSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("rekor proof failure")
    }
}

impl std::error::Error for RekorSource {}

// ─────────────────────────────────────────────────────────────────────────────
// Main error enum
// ─────────────────────────────────────────────────────────────────────────────

/// Unified error surface for Nitro attestation verification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestError {
    /// The COSE_Sign1 wrapper is malformed or could not be decoded.
    #[error("malformed attestation document")]
    MalformedDoc {
        #[source]
        source: Option<CoseAttSource>,
    },

    /// Input exceeds [`MAX_NITRO_DOC_BYTES`](crate::MAX_NITRO_DOC_BYTES).
    #[error("payload too large: {observed} > {cap}")]
    PayloadTooLarge { observed: usize, cap: usize },

    /// CBOR nesting depth exceeded [`MAX_CBOR_DEPTH`](crate::MAX_CBOR_DEPTH).
    #[error("CBOR nesting too deep (max {max})")]
    CborDepthExceeded { max: usize },

    /// The COSE alg label is not ES384 (`-35`).
    #[error("unsupported algorithm label: {alg}")]
    UnsupportedAlg { alg: i64 },

    /// A certificate in the chain failed to parse or verify.
    #[error("CA chain invalid at index {index}")]
    CaChainInvalid {
        index: usize,
        #[source]
        source: X509Source,
    },

    /// The chain depth exceeds [`MAX_CA_CHAIN_DEPTH`](crate::MAX_CA_CHAIN_DEPTH).
    #[error("CA chain depth {depth} exceeds max {max}")]
    CaChainTooLong { depth: usize, max: usize },

    /// The root certificate is not in the trusted [`NitroRootSet`](crate::NitroRootSet).
    #[error("untrusted root certificate")]
    UntrustedRoot { fingerprint: [u8; 32] },

    /// A certificate's `not_after` is in the past relative to the
    /// attestation timestamp.
    #[error("certificate expired: now={now}, not_after={not_after}")]
    CertExpired { now: i64, not_after: i64 },

    /// A certificate's `not_before` is in the future relative to the
    /// attestation timestamp.
    #[error("certificate not yet valid: now={now}, not_before={not_before}")]
    CertNotYetValid { now: i64, not_before: i64 },

    /// The ECDSA-P384 signature over the COSE Sig_structure is invalid.
    #[error("signature verification failed")]
    SignatureInvalid {
        #[source]
        source: EcdsaSource,
    },

    /// The nonce in the attestation document does not match `expected_nonce`.
    #[error("nonce mismatch")]
    NonceMismatch,

    /// A PCR index in `expected` is outside the valid range 0..=23.
    #[error("PCR index out of range: {id}")]
    PcrIndexOutOfRange { id: u8 },

    /// The claims contain two entries with the same PCR index.
    #[error("duplicate PCR id: {id}")]
    DuplicatePcrId { id: u8 },

    /// A PCR value does not match the expected hash.
    #[error("PCR {id} mismatch")]
    PcrMismatch {
        id: u8,
        expected_hash: [u8; 32],
        actual_hash: [u8; 32],
    },

    /// The certificate uses a hash algorithm weaker than SHA-256.
    #[error("weak hash algorithm in certificate: {alg}")]
    WeakHashAlg { alg: &'static str },

    /// A Rekor inclusion proof is structurally invalid.
    #[error("Rekor inclusion proof invalid")]
    RekorProofInvalid {
        #[source]
        source: RekorSource,
    },

    /// The Rekor signed tree head is too old.
    #[error("Rekor STH stale: age={age_seconds}s, max={max}s")]
    RekorSthStale { age_seconds: u64, max: u64 },

    /// The Rekor log ID is not in the trusted set.
    #[error("Rekor log untrusted")]
    RekorLogUntrusted { log_id: [u8; 32] },
}
