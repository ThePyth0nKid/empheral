//! Persistence test: one subprocess signs 100 facts in sequence.
//!
//! Validates the long-running-sidecar design: Canon will spawn the
//! signer once and reuse it across many requests.  If per-request
//! state leaks (handles, buffers, allocations scaling with requests),
//! this test catches it early.  We also pin latency so a future
//! refactor cannot silently regress into multi-ms-per-sign territory.
//!
//! Targets on Nelson's Windows dev box: median < 5 ms, p99 < 20 ms.
//! A generous safety margin is applied because CI spawn times vary;
//! the absolute ceiling is picked so an accidental O(n) regression
//! (e.g. re-reading the keyfile each request) would still trip.

mod common;

use std::time::Instant;

use common::{close_and_wait, send_and_receive, sign_request_json, spawn_signer};

const N: usize = 100;

#[test]
fn one_hundred_signs_in_one_subprocess_stay_fast_and_chain_correctly() {
    let (child, mut stdin, mut stdout) = spawn_signer();

    let mut prev_hash = String::new();
    let mut latencies_us: Vec<u128> = Vec::with_capacity(N);

    for i in 0..N {
        let fact_id = format!("f_persist_{i:03}");
        let claim = format!("fact number {i}");
        let req = sign_request_json(&fact_id, &claim, &prev_hash);

        let t0 = Instant::now();
        let response_line = send_and_receive(&mut stdin, &mut stdout, &req);
        let elapsed = t0.elapsed().as_micros();
        latencies_us.push(elapsed);

        let v: serde_json::Value = serde_json::from_str(&response_line).unwrap();
        let hash = v["event_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("iteration {i}: missing event_hash in {response_line}"))
            .to_string();
        assert_eq!(hash.len(), 64, "iteration {i}: bad event_hash length");
        assert_ne!(
            hash, prev_hash,
            "iteration {i}: consecutive facts must hash differently"
        );
        prev_hash = hash;
    }

    latencies_us.sort_unstable();
    let median = latencies_us[N / 2];
    let p99 = latencies_us[(N * 99) / 100];

    // Ceilings intentionally loose: the point is to catch an O(n)
    // regression, not to micro-benchmark.  Sub-ms local numbers are
    // expected; CI noise can push these up an order of magnitude.
    assert!(
        median < 50_000,
        "median sign latency too high: {median} us (>50ms)"
    );
    assert!(
        p99 < 200_000,
        "p99 sign latency too high: {p99} us (>200ms)"
    );

    close_and_wait(child, stdin);
}
