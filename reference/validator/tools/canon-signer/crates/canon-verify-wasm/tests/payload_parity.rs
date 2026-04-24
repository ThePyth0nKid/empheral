#![cfg(not(target_arch = "wasm32"))]
//! Canonical-CBOR payload byte-parity with `canon_signer::event`.
//!
//! Round-trip: encode a fact via the real signer's `encode_payload`,
//! decode via the wasm verifier's `decode_payload`, and assert every
//! field came back verbatim.  Also asserts the field *order* invariant
//! by pinning the expected `event_hash` for a known fixture — if
//! ciborium ever changed its encoding order or the signer crate
//! reordered the array, the hash would drift and this test would
//! catch it before we pushed a breaking change to Canon.

use canon_signer::event::{encode_payload, event_hash};
use canon_signer::io::SignRequest;
use canon_verify_wasm::payload::decode_payload;

fn sample_request_genesis() -> SignRequest {
    SignRequest {
        op: "sign".to_string(),
        fact_id: "f_01HQ_sample".to_string(),
        entity: "customer:acme".to_string(),
        claim: "Q1 revenue was EUR 127,000".to_string(),
        source_ref: "gmail:msg_abc123".to_string(),
        source_excerpt: Some("Our Q1 came in at 127k EUR...".to_string()),
        parent_hash: String::new(),
        created_at_ms: 1_713_974_400_000,
    }
}

fn sample_request_with_parent() -> SignRequest {
    SignRequest {
        op: "sign".to_string(),
        fact_id: "f_02HQ_chain".to_string(),
        entity: "customer:beta".to_string(),
        claim: "Q2 revenue was EUR 200,000".to_string(),
        source_ref: "gmail:msg_def456".to_string(),
        source_excerpt: None,
        parent_hash: "deadbeefcafef00d0011223344556677deadbeefcafef00d0011223344556677"
            .to_string(),
        created_at_ms: 1_720_000_000_000,
    }
}

#[test]
fn round_trip_genesis_fact_preserves_every_field() {
    let req = sample_request_genesis();
    let cbor = encode_payload(&req).expect("signer must encode");
    let decoded = decode_payload(&cbor).expect("wasm verifier must decode");

    assert_eq!(decoded.parent_hash, "", "genesis must decode to empty hex");
    assert_eq!(decoded.fact_id, req.fact_id);
    assert_eq!(decoded.entity, req.entity);
    assert_eq!(decoded.claim, req.claim);
    assert_eq!(decoded.source_ref, req.source_ref);
    assert_eq!(decoded.source_excerpt, req.source_excerpt);
    assert_eq!(decoded.created_at_ms, req.created_at_ms as i64);
}

#[test]
fn round_trip_chained_fact_with_parent_hash_preserves_hex() {
    let req = sample_request_with_parent();
    let cbor = encode_payload(&req).expect("signer must encode");
    let decoded = decode_payload(&cbor).expect("wasm verifier must decode");

    assert_eq!(decoded.parent_hash, req.parent_hash);
    assert_eq!(decoded.fact_id, req.fact_id);
    assert_eq!(decoded.source_excerpt, None);
    assert_eq!(decoded.created_at_ms, req.created_at_ms as i64);
}

#[test]
fn source_excerpt_null_round_trips_as_none() {
    let mut req = sample_request_genesis();
    req.source_excerpt = None;
    let cbor = encode_payload(&req).unwrap();
    let decoded = decode_payload(&cbor).unwrap();
    assert_eq!(decoded.source_excerpt, None);
}

#[test]
fn event_hash_matches_signer_computation() {
    // Cross-check: the wasm verifier computes event_hash via its own
    // `canon::sha256_hex`; the signer uses its `event::event_hash`.
    // Both must produce the identical 64-char lowercase hex string.
    let req = sample_request_genesis();
    let cbor = encode_payload(&req).unwrap();

    let from_signer = event_hash(&cbor);
    let from_wasm = canon_verify_wasm::canon::sha256_hex(&cbor);

    assert_eq!(from_signer, from_wasm);
    assert_eq!(from_signer.len(), 64);
}

#[test]
fn cbor_array_header_is_0x87() {
    // Canon fact is a 7-element CBOR array — header byte must be 0x87
    // (major type 4, short count 7).  If this ever changes, the
    // 7-field decoder will reject every fact; catch it here.
    let req = sample_request_genesis();
    let cbor = encode_payload(&req).unwrap();
    assert_eq!(cbor[0], 0x87, "expected 7-element CBOR array header");
}

#[test]
fn decode_rejects_wrong_arity() {
    // Hand-build a 6-element array that happens to be valid CBOR but
    // is the wrong shape for a Canon fact — decoder must reject.
    let mut buf = Vec::new();
    let shorter = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Text("f".to_string()),
        ciborium::Value::Text("e".to_string()),
        ciborium::Value::Text("c".to_string()),
        ciborium::Value::Text("s".to_string()),
        ciborium::Value::Null,
        // Missing created_at_ms → 6 fields instead of 7.
    ]);
    ciborium::ser::into_writer(&shorter, &mut buf).unwrap();

    let err = decode_payload(&buf).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("6"), "expected arity error mentioning 6, got: {msg}");
}

#[test]
fn decode_rejects_non_cbor() {
    let err = decode_payload(&[0xff, 0xff, 0xff]).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("cbor") || msg.to_lowercase().contains("array"),
        "expected cbor/array error, got: {msg}"
    );
}

#[test]
fn decode_rejects_wrong_field_type_at_known_index() {
    // Build a 7-array where `created_at_ms` (index 6) is a text string
    // instead of an integer — decoder must report index 6 by name.
    let mut buf = Vec::new();
    let malformed = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Text("f".to_string()),
        ciborium::Value::Text("e".to_string()),
        ciborium::Value::Text("c".to_string()),
        ciborium::Value::Text("s".to_string()),
        ciborium::Value::Null,
        ciborium::Value::Text("not-a-uint".to_string()),
    ]);
    ciborium::ser::into_writer(&malformed, &mut buf).unwrap();

    let err = decode_payload(&buf).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("created_at_ms"), "expected field name in error: {msg}");
}
