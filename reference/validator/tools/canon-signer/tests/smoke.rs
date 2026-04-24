//! Smoke test: spawn the real binary, send a single sign request,
//! assert the response has every required field and is syntactically
//! well-formed.

mod common;

use common::{close_and_wait, send_and_receive, sign_request_json, spawn_signer};

#[test]
fn single_sign_request_yields_well_formed_response() {
    let (child, mut stdin, mut stdout) = spawn_signer();

    let req = sign_request_json("f_smoke_1", "hello world", "");
    let response_line = send_and_receive(&mut stdin, &mut stdout, &req);

    let v: serde_json::Value =
        serde_json::from_str(&response_line).expect("response must be valid JSON");

    // All 5 response fields must be present and of the right type.
    assert_eq!(v["fact_id"], "f_smoke_1");
    assert!(
        v["event_hash"].as_str().is_some_and(|s| s.len() == 64),
        "event_hash must be 64 hex chars: got {:?}",
        v["event_hash"]
    );
    assert!(
        v["event_hash"]
            .as_str()
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "event_hash must be lowercase hex"
    );
    assert!(
        v["cose_sign1_hex"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() % 2 == 0),
        "cose_sign1_hex must be non-empty even-length hex"
    );
    let pk = v["signer_pubkey"].as_str().expect("signer_pubkey string");
    assert!(pk.starts_with("ed25519:"), "signer_pubkey must be prefixed");
    assert!(
        v["signed_at_ms"].is_u64(),
        "signed_at_ms must be a non-negative integer"
    );

    // The cose_sign1_hex should decode to valid CBOR.
    let bytes = hex::decode(v["cose_sign1_hex"].as_str().unwrap())
        .expect("cose_sign1_hex must be valid hex");
    let _: ciborium::Value = ciborium::de::from_reader(bytes.as_slice())
        .expect("cose_sign1_hex bytes must parse as CBOR");

    close_and_wait(child, stdin);
}
