//! WebAssembly verifier for Canon fact COSE_Sign1 envelopes.
//!
//! Single public entry point: [`verify_canon_envelope`].  It consumes
//! the hex-encoded wire envelope plus an `ed25519:<base64>` public key
//! string and returns a fully populated [`VerifyResult`] — the same
//! shape whether verification succeeds or fails, so the UI can render
//! a uniform "transparency panel" in either case.
//!
//! # Why this crate exists
//!
//! The canon-verify CLI (`tools/canon-signer/src/bin/canon_verify.rs`)
//! is the authoritative verifier for audit / ops contexts.  This crate
//! targets a different audience: a Canon customer who scans a QR code
//! at the bottom of a signed PDF and wants a visual, tamper-evident
//! ✓ / ✗ in their browser.  The actual cryptography is identical —
//! both tools bottom-out on `ephemeral_crypto::verify_cose_sign1`.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::doc_markdown)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use ephemeral_crypto::{verify_cose_sign1, AnchorRole, TrustAnchor, TrustAnchorSet};
use wasm_bindgen::prelude::*;

pub mod canon;
pub mod payload;
pub mod result;
pub mod steps;

use canon::{derive_kid, sha256_hex, COSE_EXTERNAL_AAD};
use payload::decode_payload;
use result::{RawBytes, VerifyResult};
use steps::StepsBuilder;

/// Pure-Rust verify entry point.  Callable natively (parity tests) and
/// from the WASM wrapper below.  Never panics on untrusted input — all
/// failure modes map onto a populated [`VerifyResult`] with
/// `verified = false`.
#[must_use]
pub fn verify_canon_envelope_internal(
    envelope_hex: &str,
    pubkey_wire: &str,
    kid_override: Option<&str>,
) -> VerifyResult {
    let mut steps = StepsBuilder::new();
    let mut raw = RawBytes {
        aad: hex::encode(COSE_EXTERNAL_AAD),
        ..Default::default()
    };
    // --- Step 0: decode envelope hex ----------------------------------
    let envelope_bytes = match hex::decode(envelope_hex.trim()) {
        Ok(b) => {
            steps.ok(0, format!("{} bytes decoded", b.len()));
            b
        }
        Err(e) => {
            steps.fail(0, format!("hex decode failed: {e}"));
            steps.fill_skipped();
            return VerifyResult::failed(steps.into_vec(), raw, format!("hex: {e}"));
        }
    };

    // --- Step 1: parse CBOR as COSE_Sign1 -----------------------------
    // canon-signer emits untagged envelopes; try that first.  Accept
    // tagged input too (0xd2 ...) so a future signer variant or a
    // manually-hand-rolled envelope stays verifiable.
    let sign1 = match CoseSign1::from_slice(&envelope_bytes) {
        Ok(s) => s,
        Err(_untagged_err) => match CoseSign1::from_tagged_slice(&envelope_bytes) {
            Ok(s) => s,
            Err(tagged_err) => {
                let msg = format!("not a COSE_Sign1 structure: {tagged_err}");
                steps.fail(1, &msg);
                steps.fill_skipped();
                return VerifyResult::failed(steps.into_vec(), raw, msg);
            }
        },
    };
    steps.ok(1, "COSE_Sign1 parsed");

    // --- Step 2: extract protected header, payload, signature bytes ---
    // The "original_data" field is populated by coset when parsing
    // from a slice: it is the exact CBOR-bstr contents of the
    // protected header, which is what RFC 9052 §4.4 mixes into TBS.
    let protected_bytes = sign1
        .protected
        .original_data
        .clone()
        .unwrap_or_default();
    raw.protected_header = hex::encode(&protected_bytes);
    raw.signature = hex::encode(&sign1.signature);

    let Some(payload_bytes) = sign1.payload.clone() else {
        let msg = "COSE_Sign1 has no payload (detached payloads are not supported)".to_string();
        steps.fail(2, &msg);
        steps.fill_skipped();
        return VerifyResult::failed(steps.into_vec(), raw, msg);
    };
    raw.payload_cbor = hex::encode(&payload_bytes);
    steps.ok(
        2,
        format!(
            "protected={} B, payload={} B, signature={} B",
            protected_bytes.len(),
            payload_bytes.len(),
            sign1.signature.len()
        ),
    );

    // --- Step 3: extract kid from protected header --------------------
    let kid_bytes = &sign1.protected.header.key_id;
    if kid_bytes.is_empty() {
        let msg = "protected header has no kid".to_string();
        steps.fail(3, &msg);
        steps.fill_skipped();
        return VerifyResult::failed(steps.into_vec(), raw, msg);
    }
    let extracted = match std::str::from_utf8(kid_bytes) {
        Ok(s) => s.to_string(),
        Err(e) => {
            let msg = format!("kid is not UTF-8: {e}");
            steps.fail(3, &msg);
            steps.fill_skipped();
            return VerifyResult::failed(steps.into_vec(), raw, msg);
        }
    };
    steps.ok(3, format!("kid = {extracted}"));

    // --- Step 4: parse pubkey ed25519:<base64> → 32 bytes ------------
    let pubkey_bytes = match parse_pubkey(pubkey_wire.trim()) {
        Ok(b) => {
            steps.ok(4, "public key parsed (32 bytes)");
            b
        }
        Err(msg) => {
            steps.fail(4, &msg);
            steps.fill_skipped();
            return VerifyResult::with_kid(extracted, steps.into_vec(), raw, msg);
        }
    };

    // --- Step 5: derive expected kid, compare -------------------------
    let derived = derive_kid(&pubkey_bytes);
    let kid_to_trust = match kid_override {
        Some(override_str) => {
            steps.ok(
                5,
                format!("kid override applied: {override_str} (pubkey would derive {derived})"),
            );
            override_str.to_string()
        }
        None if derived == extracted => {
            steps.ok(5, format!("{derived} matches header kid"));
            derived
        }
        None => {
            let msg = format!(
                "kid mismatch: header claims {extracted}, but pubkey derives {derived}"
            );
            steps.fail(5, &msg);
            steps.fill_skipped();
            return VerifyResult::with_kid(extracted, steps.into_vec(), raw, msg);
        }
    };

    // --- Step 6: TBS construction (informational) ---------------------
    // The Sig_structure_1 layout per RFC 9052 §4.4 is:
    //   ["Signature1", protected_bstr, external_aad, payload]
    // ephemeral_crypto::verify_cose_sign1 assembles and hashes this
    // internally; we surface the ingredients here so the viewer sees
    // *what* goes into the signature, even though we do not
    // reconstruct the bytes ourselves.
    steps.ok(
        6,
        format!(
            "Sig_structure_1 = [\"Signature1\", protected ({} B), aad ({} B), payload ({} B)]",
            protected_bytes.len(),
            COSE_EXTERNAL_AAD.len(),
            payload_bytes.len()
        ),
    );

    // --- Step 7: Ed25519 verification via ephemeral-crypto ------------
    // Build a single-anchor trust set keyed by the kid we decided to
    // accept in step 5.  `verify_cose_sign1` rejects unknown kids
    // before even looking at the signature, so passing a non-matching
    // override here surfaces as "unknown kid" rather than a crypto
    // failure — the detail string reflects that.
    let anchor = match TrustAnchor::new_ed25519(
        kid_to_trust.clone(),
        &pubkey_bytes,
        AnchorRole::CanonSigner,
    ) {
        Ok(a) => a,
        Err(e) => {
            let msg = format!("trust anchor build failed: {e}");
            steps.fail(7, &msg);
            steps.fill_skipped();
            return VerifyResult::with_kid(extracted, steps.into_vec(), raw, msg);
        }
    };
    let mut anchors = TrustAnchorSet::new();
    if let Err(e) = anchors.insert(anchor) {
        let msg = format!("trust anchor insert failed: {e}");
        steps.fail(7, &msg);
        steps.fill_skipped();
        return VerifyResult::with_kid(extracted, steps.into_vec(), raw, msg);
    }

    let verified_payload = match verify_cose_sign1(
        &envelope_bytes,
        &anchors,
        COSE_EXTERNAL_AAD,
        AnchorRole::CanonSigner,
    ) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("signature verification failed: {e}");
            steps.fail(7, &msg);
            steps.fill_skipped();
            return VerifyResult::with_kid(extracted, steps.into_vec(), raw, msg);
        }
    };
    steps.ok(7, "Ed25519 signature valid over TBS");

    // --- Step 8: event_hash = sha256(payload) -------------------------
    let event_hash = sha256_hex(&verified_payload.payload);
    steps.ok(8, format!("event_hash = {event_hash}"));

    // --- Step 9: decode 7-field payload -------------------------------
    let decoded = match decode_payload(&verified_payload.payload) {
        Ok(d) => d,
        Err(e) => {
            // This is pathological: verification passed but the payload
            // shape is wrong.  Report as hard fail — a valid signature
            // over malformed content does not mean an authentic Canon
            // fact.
            let msg = format!("payload decode failed: {e}");
            steps.fail(9, &msg);
            return VerifyResult {
                verified: false,
                event_hash,
                kid: verified_payload.kid,
                steps: steps.into_vec(),
                decoded_payload: None,
                raw,
                error: Some(msg),
            };
        }
    };
    steps.ok(
        9,
        format!(
            "parent_hash={}, fact_id={}, entity={}, claim=…",
            if decoded.parent_hash.is_empty() { "(genesis)".to_string() } else { format!("{}…", &decoded.parent_hash[..12.min(decoded.parent_hash.len())]) },
            decoded.fact_id,
            decoded.entity,
        ),
    );

    VerifyResult {
        verified: true,
        event_hash,
        kid: verified_payload.kid,
        steps: steps.into_vec(),
        decoded_payload: Some(decoded),
        raw,
        error: None,
    }
}

/// Parse a Canon wire-format pubkey (`ed25519:<base64(32)>`) into raw
/// bytes.  Returns a human-readable error message on any failure.
fn parse_pubkey(wire: &str) -> Result<[u8; 32], String> {
    let b64 = wire
        .strip_prefix("ed25519:")
        .ok_or_else(|| "public key is missing 'ed25519:' prefix".to_string())?;
    let raw = B64
        .decode(b64)
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| format!("public key must be 32 bytes, got {}", raw.len()))
}

// ---------- VerifyResult constructors (failure paths) ---------------

impl VerifyResult {
    /// Constructor for failures before the kid was extracted.
    fn failed(steps: Vec<steps::Step>, raw: RawBytes, error: String) -> Self {
        Self {
            verified: false,
            event_hash: String::new(),
            kid: String::new(),
            steps,
            decoded_payload: None,
            raw,
            error: Some(error),
        }
    }

    /// Constructor for failures after the kid was extracted but before
    /// payload verification.  Preserves the extracted kid so the UI
    /// can still render "signer claimed X" context on the fail panel.
    fn with_kid(kid: String, steps: Vec<steps::Step>, raw: RawBytes, error: String) -> Self {
        Self {
            verified: false,
            event_hash: String::new(),
            kid,
            steps,
            decoded_payload: None,
            raw,
            error: Some(error),
        }
    }
}

// ---------- WASM boundary -------------------------------------------

/// JavaScript-facing entry point.  Serializes [`VerifyResult`] via
/// `serde-wasm-bindgen` so the caller receives a plain object.
///
/// The function is total: any input produces a value and never
/// throws.  Callers should `.verified` on the returned object to
/// branch; the `error` field carries a one-line reason when false.
#[wasm_bindgen]
pub fn verify_canon_envelope(
    envelope_hex: &str,
    pubkey_wire: &str,
    kid_override: Option<String>,
) -> JsValue {
    let result =
        verify_canon_envelope_internal(envelope_hex, pubkey_wire, kid_override.as_deref());
    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}
