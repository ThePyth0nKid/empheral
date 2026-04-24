//! Run the core verifier under wasm32-unknown-unknown via Node.js.
//!
//! `wasm-pack test --node -p canon-verify-wasm` builds the crate for
//! wasm32, links the wasm-bindgen-test shim, and executes each
//! `#[wasm_bindgen_test]` inside Node's V8.  A passing run here is the
//! load-bearing proof that every runtime dep (ed25519-dalek, coset,
//! ciborium, sha2, base64, hex) compiles and works correctly on the
//! wasm32 target — which is *not* trivially implied by a native-host
//! green.  curve25519-dalek, in particular, has historically shipped
//! SIMD backends that fail on wasm32 unless the right features are
//! off; this test would catch that regression.

#![cfg(target_arch = "wasm32")]

use canon_verify_wasm::{steps::StepStatus, verify_canon_envelope_internal};
use wasm_bindgen_test::wasm_bindgen_test;

mod fixtures;
use fixtures::{
    GOLDEN_ENVELOPE_HEX, GOLDEN_EVENT_HASH, GOLDEN_KID, GOLDEN_PUBKEY_WIRE, WRONG_PUBKEY_WIRE,
};

#[wasm_bindgen_test]
fn golden_envelope_verifies_under_wasm32() {
    let result =
        verify_canon_envelope_internal(GOLDEN_ENVELOPE_HEX, GOLDEN_PUBKEY_WIRE, None);
    assert!(result.verified, "wasm golden verification failed: {:?}", result.error);
    assert_eq!(result.event_hash, GOLDEN_EVENT_HASH);
    assert_eq!(result.kid, GOLDEN_KID);
    assert_eq!(result.steps.len(), 10);
    for (i, step) in result.steps.iter().enumerate() {
        assert_eq!(step.status, StepStatus::Ok, "step {i} failed under wasm32: {step:?}");
    }
}

#[wasm_bindgen_test]
fn wrong_pubkey_under_wasm32_fails_at_kid() {
    let result =
        verify_canon_envelope_internal(GOLDEN_ENVELOPE_HEX, WRONG_PUBKEY_WIRE, None);
    assert!(!result.verified);
    assert_eq!(result.steps[5].status, StepStatus::Fail);
}

#[wasm_bindgen_test]
fn malformed_hex_under_wasm32_fails_cleanly() {
    let result = verify_canon_envelope_internal("definitely not hex", GOLDEN_PUBKEY_WIRE, None);
    assert!(!result.verified);
    assert_eq!(result.steps[0].status, StepStatus::Fail);
}

#[wasm_bindgen_test]
fn tampered_envelope_under_wasm32_fails() {
    // Same tamper strategy as roundtrip_native.rs, expressed entirely
    // on strings so we don't drag `hex::decode` into the wasm path
    // here (even though the crate uses it at runtime).
    let mut s = String::from(GOLDEN_ENVELOPE_HEX);
    // Replace the 5th-to-last hex char with something different.
    let len = s.len();
    let idx = len - 5;
    let before = &s[..idx];
    let after = &s[idx + 1..];
    let original = s.as_bytes()[idx];
    let replacement: char = if original == b'0' { '1' } else { '0' };
    s = format!("{before}{replacement}{after}");

    let result = verify_canon_envelope_internal(&s, GOLDEN_PUBKEY_WIRE, None);
    assert!(!result.verified, "tampered envelope should fail");
}
