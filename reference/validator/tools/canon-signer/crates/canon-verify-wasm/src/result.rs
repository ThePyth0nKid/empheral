//! Wire-level shape of `verify_canon_envelope`'s return value.
//!
//! The struct is serialized via `serde-wasm-bindgen` so JavaScript
//! callers receive a plain `{ verified, event_hash, ... }` object
//! instead of an opaque wasm-bindgen handle.  Field names are
//! lower-snake-case — matches the canon-verify CLI JSON and plays
//! well with browser-side destructuring.

use serde::Serialize;

use crate::steps::Step;

#[derive(Debug, Serialize)]
pub struct VerifyResult {
    pub verified: bool,

    /// SHA-256 over the canonical payload bytes, lowercase hex.
    /// Empty string when verification did not reach step 9.
    pub event_hash: String,

    /// UTF-8 kid extracted from the protected header (or derived from
    /// pubkey when `kid_override` is used).  Empty string when the
    /// envelope could not be parsed far enough to extract one.
    pub kid: String,

    /// Always ten entries.  See `steps::STEP_NAMES` for the fixed
    /// order and `StepStatus` for the per-step outcome enum.
    pub steps: Vec<Step>,

    /// Populated only on `verified = true`.  The UI renders this as a
    /// seven-row human-readable table in the "Decoded payload" panel.
    pub decoded_payload: Option<DecodedPayload>,

    /// Hex-encoded copies of the CBOR pieces that went into the
    /// signature computation.  Power users read these in the
    /// "Raw bytes" drawer to convince themselves nothing is faked.
    pub raw: RawBytes,

    /// One-line reason on failure; `None` on success.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct RawBytes {
    /// Hex of the canonical CBOR payload (what SHA-256 is taken over).
    pub payload_cbor: String,

    /// Hex of the raw Ed25519 signature bytes (64 bytes = 128 chars).
    pub signature: String,

    /// Hex of the protected-header CBOR `bstr` contents.
    pub protected_header: String,

    /// Hex of the external AAD (`canon/fact/v1`).  Constant, but
    /// spelled out so the viewer can see the exact 13 bytes that were
    /// mixed into the signature input.
    pub aad: String,
}

#[derive(Debug, Serialize)]
pub struct DecodedPayload {
    /// Hex-encoded parent link.  Empty string for the genesis fact.
    pub parent_hash: String,
    pub fact_id: String,
    pub entity: String,
    pub claim: String,
    pub source_ref: String,
    pub source_excerpt: Option<String>,
    /// Positive Unix milliseconds.  i64 (not u64) because serde-json
    /// cannot losslessly round-trip u64 beyond 2^53 and the UI path
    /// goes through JSON for the share-URL feature.
    pub created_at_ms: i64,
}
