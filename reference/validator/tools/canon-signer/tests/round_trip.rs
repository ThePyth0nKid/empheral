//! Round-trip test: spawn the binary, sign a fact, then verify the
//! resulting `COSE_Sign1` via `ephemeral_crypto::verify_cose_sign1`
//! (the production verifier library).  Recovered payload must match
//! an independently-built canonical CBOR, and `SHA256(payload)` must
//! match the returned `event_hash`.
//!
//! This is the load-bearing integration test.  If this passes, Canon
//! consumers can reproduce the signer's work end-to-end; if it fails,
//! every signed fact is un-verifiable and Canon's tamper-evidence
//! guarantee is broken.

mod common;

use canon_signer::event::{encode_payload, event_hash};
use canon_signer::io::SignRequest;
use canon_signer::COSE_EXTERNAL_AAD;
use common::{close_and_wait, send_and_receive, spawn_signer, TEST_SEED_HEX};
use ed25519_dalek::SigningKey;
use ephemeral_crypto::{verify_cose_sign1, AnchorRole, TrustAnchor, TrustAnchorSet};

#[test]
fn signed_envelope_verifies_via_ephemeral_crypto_and_payload_matches() {
    let (child, mut stdin, mut stdout) = spawn_signer();

    // Build the exact request the signer will process.
    let req = SignRequest {
        op: "sign".to_string(),
        fact_id: "f_roundtrip_1".to_string(),
        entity: "customer:acme".to_string(),
        claim: "Q1 revenue was EUR 127,000".to_string(),
        source_ref: "gmail:msg_abc".to_string(),
        source_excerpt: Some("Our Q1 came in at 127k EUR...".to_string()),
        parent_hash: String::new(),
        created_at_ms: 1_713_974_400_000,
    };
    let line = serde_json::to_string(&req).unwrap();
    let response_line = send_and_receive(&mut stdin, &mut stdout, &line);
    let resp: serde_json::Value = serde_json::from_str(&response_line).unwrap();

    // Reconstruct the canonical payload and the expected event_hash
    // independently — proves the binary and the library agree on the
    // wire-format contract.
    let expected_payload = encode_payload(&req).expect("encode_payload");
    let expected_hash = event_hash(&expected_payload);
    assert_eq!(
        resp["event_hash"].as_str().unwrap(),
        expected_hash,
        "event_hash must match independently-computed hash"
    );

    // Re-derive the public key from the deterministic test seed so we
    // can register a TrustAnchor with the right kid+role.
    let seed: [u8; 32] = hex::decode(TEST_SEED_HEX).unwrap().try_into().unwrap();
    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes = sk.verifying_key().to_bytes();

    // The kid the binary embeds in the protected header is
    // `canon/<first-16-hex-chars>` — reproduce it here.
    let expected_kid = format!("canon/{}", &hex::encode(pk_bytes)[..16]);
    let reported_kid_prefix = resp["signer_pubkey"].as_str().unwrap();
    assert!(reported_kid_prefix.starts_with("ed25519:"));

    let mut anchors = TrustAnchorSet::new();
    anchors
        .insert(
            TrustAnchor::new_ed25519(expected_kid.clone(), &pk_bytes, AnchorRole::CanonSigner)
                .unwrap(),
        )
        .unwrap();

    // Decode the COSE_Sign1 hex and hand it to the production
    // verifier.  Success means: valid Ed25519 signature over the
    // payload under AAD `b"canon/fact/v1"`, recovered payload bytes
    // returned.
    let cose_bytes = hex::decode(resp["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let verified = verify_cose_sign1(
        &cose_bytes,
        &anchors,
        COSE_EXTERNAL_AAD,
        AnchorRole::CanonSigner,
    )
    .expect("verify_cose_sign1 must succeed against canon-signer output");

    assert_eq!(verified.kid, expected_kid, "kid round-trips");
    assert_eq!(
        verified.payload, expected_payload,
        "recovered payload must match independently-built canonical CBOR"
    );

    close_and_wait(child, stdin);
}

#[test]
fn tampered_envelope_fails_verification() {
    // Negative control: flip a byte inside the COSE signature region
    // and assert verify_cose_sign1 rejects it.  Guarantees the
    // verification path is actually load-bearing (not just accepting
    // whatever bytes go through).
    let (child, mut stdin, mut stdout) = spawn_signer();
    let req_json = common::sign_request_json("f_tamper", "claim", "");
    let response_line = send_and_receive(&mut stdin, &mut stdout, &req_json);
    let resp: serde_json::Value = serde_json::from_str(&response_line).unwrap();

    let mut cose_bytes = hex::decode(resp["cose_sign1_hex"].as_str().unwrap()).unwrap();

    // Flip the final byte — which lives inside the signature field.
    // (Flipping a byte in the payload would also fail, but the
    // signature region is the most direct "tamper" semantics.)
    *cose_bytes.last_mut().unwrap() ^= 0x01;

    let seed: [u8; 32] = hex::decode(TEST_SEED_HEX).unwrap().try_into().unwrap();
    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes = sk.verifying_key().to_bytes();
    let kid = format!("canon/{}", &hex::encode(pk_bytes)[..16]);

    let mut anchors = TrustAnchorSet::new();
    anchors
        .insert(TrustAnchor::new_ed25519(kid, &pk_bytes, AnchorRole::CanonSigner).unwrap())
        .unwrap();

    let result = verify_cose_sign1(
        &cose_bytes,
        &anchors,
        COSE_EXTERNAL_AAD,
        AnchorRole::CanonSigner,
    );
    assert!(
        result.is_err(),
        "tampered COSE_Sign1 must fail verification"
    );

    close_and_wait(child, stdin);
}
