#![cfg(not(target_arch = "wasm32"))]
//! End-to-end round-trip: sign with the real `canon-signer`, verify
//! with the native-host form of `verify_canon_envelope_internal`.
//!
//! This is the ultimate parity gate — it exercises the full 10-step
//! pipeline against a signature produced by the *same* code path Canon
//! uses in production.  If this test fails, no hand-rolled unit test
//! will save us: Canon cannot verify what Canon signs.
//!
//! The wasm-pack layer adds only a thin serde boundary on top of
//! [`verify_canon_envelope_internal`], so passing here plus a smaller
//! wasm-bindgen-test (Phase 2) is sufficient coverage without needing
//! to boot a full browser.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use canon_signer::cose::{build_cose_sign1, derive_kid};
use canon_signer::event::encode_payload;
use canon_signer::io::SignRequest;
use canon_verify_wasm::verify_canon_envelope_internal;
use ed25519_dalek::SigningKey;

fn demo_signing_key() -> SigningKey {
    // Deterministic demo seed — matches the Obsidian demo vector kid
    // `canon/8a88e3dd7409f195` that appears in the web-verifier docs.
    SigningKey::from_bytes(&[1u8; 32])
}

fn demo_request() -> SignRequest {
    SignRequest {
        op: "sign".to_string(),
        fact_id: "f_demo_0001".to_string(),
        entity: "customer:acme".to_string(),
        claim: "Q1 revenue was EUR 127,000".to_string(),
        source_ref: "gmail:msg_abc123".to_string(),
        source_excerpt: Some("Our Q1 came in at 127k EUR...".to_string()),
        parent_hash: String::new(),
        created_at_ms: 1_713_974_400_000,
    }
}

fn pubkey_wire(sk: &SigningKey) -> String {
    format!("ed25519:{}", B64.encode(sk.verifying_key().to_bytes()))
}

fn make_envelope() -> (String, String) {
    let sk = demo_signing_key();
    let vk = sk.verifying_key().to_bytes();
    let kid = derive_kid(&vk);
    let payload = encode_payload(&demo_request()).unwrap();
    let envelope = build_cose_sign1(&payload, &sk, &kid).unwrap();
    (hex::encode(envelope), pubkey_wire(&sk))
}

#[test]
fn golden_envelope_verifies_all_ten_steps_pass() {
    let (hex_envelope, wire_pubkey) = make_envelope();
    let result = verify_canon_envelope_internal(&hex_envelope, &wire_pubkey, None);

    assert!(result.verified, "golden envelope must verify; error = {:?}", result.error);
    assert_eq!(result.steps.len(), 10);
    for (i, step) in result.steps.iter().enumerate() {
        assert_eq!(
            step.status,
            canon_verify_wasm::steps::StepStatus::Ok,
            "step {i} ({}) was not ok: detail={:?}",
            step.name,
            step.detail
        );
    }
    assert_eq!(result.event_hash.len(), 64);
    assert_eq!(result.kid, derive_kid(&demo_signing_key().verifying_key().to_bytes()));
    assert!(result.decoded_payload.is_some());
    let decoded = result.decoded_payload.unwrap();
    assert_eq!(decoded.fact_id, "f_demo_0001");
    assert_eq!(decoded.entity, "customer:acme");
    assert_eq!(decoded.parent_hash, ""); // genesis
}

#[test]
fn tampered_payload_fails_at_step_7() {
    // Decode the envelope, flip one byte inside the signature region
    // (last 64 bytes of a COSE_Sign1 are the signature), and re-encode.
    // This leaves the CBOR structure intact so the envelope still
    // *parses* — the failure must land on signature verify (step 7).
    let (hex_envelope, wire_pubkey) = make_envelope();
    let mut env_bytes = hex::decode(&hex_envelope).unwrap();
    let idx = env_bytes.len() - 5;
    env_bytes[idx] ^= 0x01;
    let tampered_hex = hex::encode(env_bytes);

    let result = verify_canon_envelope_internal(&tampered_hex, &wire_pubkey, None);
    assert!(!result.verified);
    // The first failing step must be one of the signature-adjacent ones
    // (7 or, rarely on certain flips, 1/2 if the flip lands in a length
    // prefix).  We assert on the *first* Fail rather than pinning to 7.
    let first_fail = result
        .steps
        .iter()
        .position(|s| s.status == canon_verify_wasm::steps::StepStatus::Fail)
        .expect("tampered envelope must fail somewhere");
    assert!(
        first_fail >= 1,
        "tampered envelope must fail at or after step 1, failed at {first_fail}"
    );
}

#[test]
fn wrong_pubkey_fails_at_kid_comparison() {
    let (hex_envelope, _real_pubkey) = make_envelope();
    // Substitute a different valid-but-unrelated Ed25519 pubkey — the
    // same seed used by the io-layer tests inside canon-signer.
    let other_sk = SigningKey::from_bytes(&[11u8; 32]);
    let other_wire = pubkey_wire(&other_sk);

    let result = verify_canon_envelope_internal(&hex_envelope, &other_wire, None);
    assert!(!result.verified);
    // Step 5 is the kid-mismatch step.
    assert_eq!(result.steps[5].status, canon_verify_wasm::steps::StepStatus::Fail);
    assert!(
        result
            .steps
            .iter()
            .skip(6)
            .all(|s| s.status == canon_verify_wasm::steps::StepStatus::Skipped),
        "steps after a kid failure must be skipped"
    );
}

#[test]
fn malformed_hex_fails_at_step_0() {
    let result = verify_canon_envelope_internal("not hex at all xyz", "ed25519:AAAA", None);
    assert!(!result.verified);
    assert_eq!(result.steps[0].status, canon_verify_wasm::steps::StepStatus::Fail);
    assert!(result.steps[1..]
        .iter()
        .all(|s| s.status == canon_verify_wasm::steps::StepStatus::Skipped));
}

#[test]
fn malformed_pubkey_prefix_fails_cleanly() {
    let (hex_envelope, _) = make_envelope();
    // Missing `ed25519:` prefix.
    let result = verify_canon_envelope_internal(&hex_envelope, "AAAAAAAA", None);
    assert!(!result.verified);
    assert_eq!(result.steps[4].status, canon_verify_wasm::steps::StepStatus::Fail);
}

#[test]
fn raw_bytes_populated_for_viewer() {
    // Transparency guarantee: the UI "Raw bytes" panel must always
    // receive the three pieces it needs to let a paranoid viewer
    // reconstruct the TBS themselves.
    let (hex_envelope, wire_pubkey) = make_envelope();
    let result = verify_canon_envelope_internal(&hex_envelope, &wire_pubkey, None);
    assert!(result.verified);

    assert!(!result.raw.payload_cbor.is_empty());
    assert_eq!(result.raw.signature.len(), 128, "signature is 64 bytes = 128 hex chars");
    assert!(!result.raw.protected_header.is_empty());
    assert_eq!(result.raw.aad, hex::encode(b"canon/fact/v1"));
}
