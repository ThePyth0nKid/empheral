//! Canon-specific constants mirrored from the `canon-signer` crate.
//!
//! Why duplicated instead of re-exported?  Importing `canon-signer` as a
//! runtime dep would pull the signer side of the code into the wasm32
//! build graph (SigningKey, OsRng via rand_core, zeroize).  Keeping
//! this crate `canon-signer`-free at runtime yields a WASM bundle that
//! *by construction* cannot produce a signature, only verify one — a
//! claim worth making at a security audit.
//!
//! Byte-parity with the source of truth is pinned by
//! `tests/aad_parity.rs` (dev-dep reaches into the real `canon-signer`
//! crate) — any divergence breaks the workspace build.

use sha2::{Digest, Sha256};

/// Fixed external AAD bound into every Canon COSE_Sign1 signature.
///
/// Mirror of `canon_signer::COSE_EXTERNAL_AAD`.  Changing this value
/// would invalidate every previously signed Canon fact — treat as
/// wire-format frozen.
pub const COSE_EXTERNAL_AAD: &[u8] = b"canon/fact/v1";

/// UTF-8 prefix emitted in every Canon kid.  Mirror of
/// `canon_signer::CANON_KID_PREFIX`.
pub const CANON_KID_PREFIX: &str = "canon/";

/// Derive the Canon-style UTF-8 kid for an Ed25519 public key.
///
/// Format: `canon/<first-16-hex-chars-of-raw-pubkey>`.  The 16 hex
/// chars encode 8 bytes of entropy, which is more than enough to
/// disambiguate signers in any realistic Canon deployment.
///
/// Byte-identical to `canon_signer::cose::derive_kid`; pinned by
/// `tests/kid_parity.rs`.
pub fn derive_kid(pubkey_bytes: &[u8; 32]) -> String {
    let hex_full = hex::encode(pubkey_bytes);
    format!("{CANON_KID_PREFIX}{}", &hex_full[..16])
}

/// SHA-256 over the canonical payload bytes, lowercase hex.  Exported
/// here (rather than re-using `canon_signer::event::event_hash`) for
/// the same reason as the AAD constant: keep this crate signer-free.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
