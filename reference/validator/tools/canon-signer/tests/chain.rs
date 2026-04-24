//! Chain-linking test: sign Fact A at genesis, then Fact B with
//! `parent_hash = Fact-A.event_hash`, then re-sign Fact A and verify
//! the `event_hash` is bit-identical (determinism invariant).
//!
//! Chain integrity depends on two properties:
//! 1. `event_hash` is a pure function of the request fields (same
//!    input → same output, always).
//! 2. Changing `parent_hash` produces a different `event_hash` (so a
//!    truncation or re-parenting attack is detectable).

mod common;

use common::{close_and_wait, send_and_receive, sign_request_json, spawn_signer};

#[test]
fn chain_of_two_facts_and_determinism_of_first() {
    let (child, mut stdin, mut stdout) = spawn_signer();

    // Fact A: genesis.
    let req_a = sign_request_json("f_A", "Q1 revenue 127k", "");
    let resp_a: serde_json::Value =
        serde_json::from_str(&send_and_receive(&mut stdin, &mut stdout, &req_a)).unwrap();
    let hash_a = resp_a["event_hash"].as_str().unwrap().to_string();
    assert_eq!(hash_a.len(), 64);

    // Fact B: parent = Fact A.
    let req_b = sign_request_json("f_B", "Q2 revenue 140k", &hash_a);
    let resp_b: serde_json::Value =
        serde_json::from_str(&send_and_receive(&mut stdin, &mut stdout, &req_b)).unwrap();
    let hash_b = resp_b["event_hash"].as_str().unwrap().to_string();
    assert_ne!(hash_a, hash_b, "distinct facts must have distinct hashes");

    // Fact A re-signed: bit-identical event_hash, proving the hash is
    // a pure function of the request fields (no wall-clock, no random
    // salt, no monotonic counter silently mixed in).
    let req_a2 = sign_request_json("f_A", "Q1 revenue 127k", "");
    let resp_a2: serde_json::Value =
        serde_json::from_str(&send_and_receive(&mut stdin, &mut stdout, &req_a2)).unwrap();
    let hash_a2 = resp_a2["event_hash"].as_str().unwrap();
    assert_eq!(hash_a, hash_a2, "event_hash must be deterministic");

    close_and_wait(child, stdin);
}

#[test]
fn flipping_parent_hash_changes_event_hash() {
    // Negative-control: identical facts except for parent must hash
    // differently.  Without this pin, a retro-parenting attack (swap
    // parent_hash on a stored fact) could go undetected.
    let (child, mut stdin, mut stdout) = spawn_signer();

    let req1 = sign_request_json("f_same", "same claim", "");
    let req2 = sign_request_json(
        "f_same",
        "same claim",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    let resp1: serde_json::Value =
        serde_json::from_str(&send_and_receive(&mut stdin, &mut stdout, &req1)).unwrap();
    let resp2: serde_json::Value =
        serde_json::from_str(&send_and_receive(&mut stdin, &mut stdout, &req2)).unwrap();

    assert_ne!(
        resp1["event_hash"].as_str().unwrap(),
        resp2["event_hash"].as_str().unwrap(),
        "parent_hash flip must propagate to event_hash"
    );

    close_and_wait(child, stdin);
}
