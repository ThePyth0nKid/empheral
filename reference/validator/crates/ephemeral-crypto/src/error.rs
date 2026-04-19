//! Error surface for live COSE_Sign1 / Ed25519 verification.
//!
//! [`CoseError`] is `#[non_exhaustive]` so that future alg families
//! (ECDSA P-256, ML-DSA) can add variants without breaking downstream
//! `match` arms. Downstream crates map variants to suite-specific reject
//! codes (see `ephemeral-core::suites::tariff::TariffRejectCode` etc.).
//!
//! The `coset::CoseError` and `ed25519_dalek::SignatureError` sources are
//! wrapped in opaque [`CosetSource`] / [`Ed25519Source`] newtypes so that
//! downstream consumers cannot match on library internals — version bumps
//! of `coset` or `ed25519-dalek` stay internal to this crate.

use thiserror::Error;

/// Opaque wrapper preventing downstream `match` on `coset` internals.
///
/// The inner error is retained for `source()`-chain traversal via
/// `std::error::Error` but never read directly — Debug/Display render
/// a generic message so downstream code cannot depend on library output.
pub struct CosetSource(#[allow(dead_code)] pub(crate) coset::CoseError);

impl core::fmt::Debug for CosetSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CosetSource").finish_non_exhaustive()
    }
}

impl core::fmt::Display for CosetSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("cose decode failure")
    }
}

impl std::error::Error for CosetSource {}

/// Opaque wrapper for `ed25519_dalek::SignatureError` sources.
///
/// Retained for error-chain traversal only; Debug/Display render a
/// generic message.
pub struct Ed25519Source(#[allow(dead_code)] pub(crate) ed25519_dalek::SignatureError);

impl core::fmt::Debug for Ed25519Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Source").finish_non_exhaustive()
    }
}

impl core::fmt::Display for Ed25519Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ed25519 verify failure")
    }
}

impl std::error::Error for Ed25519Source {}

/// Unified error surface for crypto verification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoseError {
    /// The COSE_Sign1 header is malformed: missing alg, missing kid, or
    /// coset could not decode the CBOR envelope.
    #[error("malformed COSE_Sign1 header")]
    MalformedHeader {
        #[source]
        source: Option<CosetSource>,
    },

    /// The alg label is known-but-unsupported in the current crypto build.
    #[error("unsupported alg label: {alg}")]
    UnsupportedAlg { alg: i64 },

    /// The alg label in the header does not match the key type pinned on
    /// the matched trust anchor (e.g. alg=-8/EdDSA but anchor is ECDSA).
    #[error("alg/key-type mismatch: alg={alg}, anchor_key_type={key_type}")]
    AlgMismatch { alg: i64, key_type: &'static str },

    /// The kid in the COSE header did not resolve to any trust anchor in
    /// the supplied [`TrustAnchorSet`](crate::TrustAnchorSet).
    #[error("unknown kid: {kid}")]
    UnknownKid { kid: String },

    /// Ed25519 signature verification failed for the reconstructed
    /// `Sig_structure_1` TBS bytes.
    #[error("signature verification failed")]
    SignatureInvalid {
        #[source]
        source: Ed25519Source,
    },

    /// The input byte slice exceeds [`MAX_COSE_BYTES`](crate::MAX_COSE_BYTES).
    #[error("payload exceeds size cap: {observed} > {cap}")]
    PayloadTooLarge { observed: usize, cap: usize },

    /// CBOR nesting exceeded [`MAX_CBOR_DEPTH`](crate::MAX_CBOR_DEPTH).
    #[error("CBOR nesting too deep (> {max})")]
    CborDepthExceeded { max: usize },

    /// Generic CBOR parse error (truncated, invalid tag, ...).
    #[error("CBOR parse failure")]
    CborParse,

    /// Delegation chain length exceeds [`MAX_CHAIN_DEPTH`](crate::MAX_CHAIN_DEPTH).
    #[error("delegation chain depth {depth} exceeds max {max}")]
    ChainDepthExceeded { depth: usize, max: usize },

    /// Structural chain linkage broken (e.g. child's `parent_key` does not
    /// match the previous link's `child_key`).
    #[error("chain linkage broken at link {index}: {reason}")]
    ChainLinkageBroken { index: usize, reason: &'static str },

    /// The supplied public key is a known-weak Ed25519 key (small-order /
    /// torsion). Rejected unconditionally per RFC 8032 strict-mode guidance.
    #[error("weak public key rejected")]
    WeakPublicKey,

    /// Invalid public-key encoding (wrong length, non-canonical point).
    #[error("public key encoding invalid (expected 32 bytes, canonical point)")]
    InvalidPublicKeyEncoding,

    /// Hex decode error for a public-key or signature field.
    #[error("hex decode error")]
    HexDecode,

    /// A [`TrustAnchorSet`](crate::TrustAnchorSet) received two anchors
    /// sharing the same `kid`. Rejected at insertion time so that kid
    /// resolution in [`TrustAnchorSet::lookup`](crate::TrustAnchorSet::lookup)
    /// is unambiguous — first-wins behaviour would let a prepended
    /// attacker-controlled anchor shadow a legitimate one.
    #[error("duplicate trust-anchor kid: {kid}")]
    DuplicateKid { kid: String },
}
