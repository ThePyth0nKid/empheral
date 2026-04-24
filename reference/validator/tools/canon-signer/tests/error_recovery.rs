//! Error-recovery test: the stdin loop must survive malformed lines.
//!
//! Canon will occasionally send a broken line (truncated write, a
//! misencoded character, a stale queue entry).  Per the wire spec,
//! the signer returns `{"error":..., "detail":...}` on that line and
//! continues reading the next line as if nothing happened.  If the
//! loop ever died on a bad line, Canon would need supervisor-level
//! restart logic for every malformed input, which defeats the
//! long-running-sidecar design.

mod common;

use common::{close_and_wait, send_and_receive, sign_request_json, spawn_signer};

#[test]
fn malformed_line_returns_error_and_loop_continues() {
    let (child, mut stdin, mut stdout) = spawn_signer();

    // 1) Garbage input — not JSON at all.
    let bad_response = send_and_receive(&mut stdin, &mut stdout, "{this is not json");
    let bad: serde_json::Value =
        serde_json::from_str(&bad_response).expect("error response must itself be JSON");
    assert!(
        bad.get("error").and_then(|v| v.as_str()).is_some(),
        "malformed input must yield an `error` field: got {bad_response}"
    );
    assert!(
        bad.get("event_hash").is_none(),
        "error response must not carry event_hash: got {bad_response}"
    );

    // 2) Valid request immediately after — loop must still be alive.
    let good_req = sign_request_json("f_recovered", "claim after error", "");
    let good_response = send_and_receive(&mut stdin, &mut stdout, &good_req);
    let good: serde_json::Value = serde_json::from_str(&good_response).unwrap();
    assert_eq!(good["fact_id"], "f_recovered");
    assert_eq!(good["event_hash"].as_str().unwrap().len(), 64);

    // 3) Semantically invalid parent_hash (not hex) — also recoverable.
    let bad_parent = sign_request_json("f_bad_parent", "claim", "not-hex-zzz");
    let bad_parent_response = send_and_receive(&mut stdin, &mut stdout, &bad_parent);
    let bad_parent_json: serde_json::Value =
        serde_json::from_str(&bad_parent_response).expect("error response must be JSON");
    assert!(
        bad_parent_json.get("error").is_some(),
        "invalid parent_hash must yield error: got {bad_parent_response}"
    );

    // 4) Final good request — loop still alive after the second error.
    let final_req = sign_request_json("f_final", "final claim", "");
    let final_response = send_and_receive(&mut stdin, &mut stdout, &final_req);
    let final_json: serde_json::Value = serde_json::from_str(&final_response).unwrap();
    assert_eq!(final_json["fact_id"], "f_final");

    close_and_wait(child, stdin);
}
