//! Phase C.3-C Session 2 Task #10 — deterministic builders for the two
//! fuzz-baseline vectors that exercise the live classifier dispatch path
//! in `ephemeral-core`'s fuzz suite executor.
//!
//! # Why two vectors, not eight
//!
//! Unlike `phase_c3_c` (eight classifier-signature vectors covering every
//! reject code) this module emits exactly two:
//!
//! - `fuzz-190` — the pre-existing cold-start reject whose mock field
//!   `classifier_would_return: u32` is replaced by a real signed
//!   classifier-WASM + context CBOR pair.  The live executor's tier
//!   (derived from `tier_1` fixture = `1`) falling below the Tariff floor
//!   (`2`) triggers `FuzzRejectCode::TierBelowMinimum`.
//! - `fuzz-200` — new.  Exercises the `classifier-execution-failed`
//!   reject path by pointing the runner at the `fuel_exhausted` fixture,
//!   whose ABI-v1 module parses and instantiates cleanly but traps
//!   inside `classify` (infinite `(loop (br))`).  Fuel exhaustion
//!   surfaces as `ClassifierExecError::ClassifyCallTrap`; the fuzz
//!   executor collapses every `ClassifierError` to
//!   `FuzzRejectCode::ClassifierExecutionFailed`.
//!
//! The remaining 204/205 accept vectors keep using the category-driven
//! mock tier derivation; migrating those is out of Phase C.3-C scope per
//! the V10 handoff and is deferred to Phase C.4.
//!
//! # Determinism guarantees
//!
//! - All WASM bytes flow through `ephemeral_classifier::test_fixtures::
//!   shared_wasm_artifacts` which is `OnceLock`-backed and `wat::parse_str`
//!   is a pure function of the input string, so the `Vec<u8>` hash of
//!   each fixture is byte-stable across runs.
//! - The context CBOR is `{} → 0xa0`, the shortest canonical empty-map
//!   encoding.  Fixture classifiers ignore their input, so the shape is
//!   irrelevant to behavior but pinned here so `--dry-run` stdout is
//!   reproducible.
//! - `serde_json::json!` preserves key-insertion order, and the
//!   consuming `gen-fuzz-c3-c` subcommand uses `serde_json::to_string_pretty`
//!   which is deterministic for the shapes emitted here.

use ephemeral_classifier::test_fixtures::shared_wasm_artifacts;
use serde_json::{json, Value};

/// ID of the cold-start `tier-below-minimum` reject vector.
pub const FUZZ_190_ID: &str = "fuzz-190";

/// ID of the fuel-exhaustion `classifier-execution-failed` reject vector.
pub const FUZZ_200_ID: &str = "fuzz-200";

/// Canonical CBOR encoding of an empty map `{}` as a single byte, hex.
/// Fixture classifiers ignore their input, so the shape is irrelevant
/// to behavior — pinning the shortest stable encoding keeps the
/// determinism-hash cleanest.
fn empty_ctx_cbor_hex() -> String {
    hex::encode([0xa0u8])
}

/// Build both live-classifier fuzz-baseline vectors.
///
/// Return order: `fuzz-190` then `fuzz-200`.  Used by:
///
/// - `gen-fuzz-c3-c --dry-run` — prints each vector as pretty JSON.
/// - `gen-fuzz-c3-c` — in-place patches `conformance/fuzz-baseline.json`,
///   replacing the pre-existing `fuzz-190` and inserting `fuzz-200`.
/// - `tests/determinism_fuzz.rs` — pins the SHA-256 of the dry-run
///   output so silent non-determinism regressions surface loud.
#[must_use]
pub fn build_all() -> Vec<(String, Value)> {
    vec![
        (FUZZ_190_ID.to_owned(), build_fuzz_190()),
        (FUZZ_200_ID.to_owned(), build_fuzz_200()),
    ]
}

/// `fuzz-190` — cold-start `tier-below-minimum`.
///
/// The tier-1 fixture classifier returns tier `1`; the Tariff floor for
/// `kubernetes:scale:deployment` is `2`; `1 < 2` triggers the reject.
/// The V10 handoff marks this as the demonstrator of
/// [§4.5 floor-vs-classifier] semantics, so the pre-C.3-C `rationale`
/// is preserved verbatim with an additive Phase-C.3-C annotation.
fn build_fuzz_190() -> Value {
    let pool = shared_wasm_artifacts();
    let wasm_hex = hex::encode(&pool.tier_1);
    json!({
        "id": FUZZ_190_ID,
        "category": "context-cold-start",
        "description": "Cold-start reject: live classifier-WASM returns tier 1 while the Tariff floor for kubernetes:scale:deployment is 2.",
        "input": {
            "integration": "kubernetes",
            "raw_intent": {
                "verb": "scale",
                "resource_kind": "deployment",
                "namespace": "prod",
                "name": "api",
                "replicas_from": 3,
                "replicas_to": 20
            },
            "tariff_minimum_tiers": {"kubernetes:scale:deployment": 2},
            "classifier_wasm_bytes_hex": wasm_hex,
            "classifier_context_cbor_hex": empty_ctx_cbor_hex()
        },
        "expected": {"outcome": "reject", "reject_code": "tier-below-minimum"},
        "rationale": "§4.4 tariff minimum_tiers floor: if classifier returns below floor, reject. Phase C.3-C replaces the mock `classifier_would_return: u32` context field with a real ABI-v1 classifier WASM (shared fixture `tier_1`) so the floor check runs through `ephemeral_classifier::execute_classifier`.",
        "redteam_refs": ["V3-8"],
        "severity_if_failed": "critical"
    })
}

/// `fuzz-200` — fuel-exhaustion `classifier-execution-failed`.
///
/// The `fuel_exhausted` fixture loads cleanly (canonical memory / alloc
/// / classify exports; no imports; no start) and only fails at `classify`
/// call time by burning through `ClassifierConfig::default().fuel_budget`
/// inside an infinite `(loop (br))`.  The fuzz executor collapses the
/// resulting `ClassifierExecError::ClassifyCallTrap` — and every other
/// `ClassifierError` variant — to `FuzzRejectCode::ClassifierExecutionFailed`
/// per the V10 session-2-scope decision.
fn build_fuzz_200() -> Value {
    let pool = shared_wasm_artifacts();
    let wasm_hex = hex::encode(&pool.fuel_exhausted);
    json!({
        "id": FUZZ_200_ID,
        "category": "context-exec-failure",
        "description": "Live classifier traps during `classify` invocation (infinite loop → fuel exhaustion). Runtime collapses Load + Exec error categories to the single `classifier-execution-failed` reject surface.",
        "input": {
            "integration": "kubernetes",
            "raw_intent": {
                "verb": "scale",
                "resource_kind": "deployment",
                "namespace": "prod",
                "name": "api",
                "replicas_from": 3,
                "replicas_to": 5
            },
            "tariff_minimum_tiers": {"kubernetes:scale:deployment": 2},
            "classifier_wasm_bytes_hex": wasm_hex,
            "classifier_context_cbor_hex": empty_ctx_cbor_hex()
        },
        "expected": {"outcome": "reject", "reject_code": "classifier-execution-failed"},
        "rationale": "§4.5 live classification failure: a classifier that never produces a tier cannot be trusted to authorize the intent. Phase C.3-C Session 2 introduces this surface explicitly so conformance consumers can distinguish it from tier-below-minimum — collapse posture splits further in a later session if a conformance vector ever demands it.",
        "redteam_refs": ["V3-8"],
        "severity_if_failed": "critical"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_all_returns_fuzz_190_then_fuzz_200() {
        let vs = build_all();
        assert_eq!(vs.len(), 2);
        assert_eq!(vs[0].0, FUZZ_190_ID);
        assert_eq!(vs[1].0, FUZZ_200_ID);
    }

    #[test]
    fn fuzz_190_carries_live_classifier_dispatch() {
        let v = build_fuzz_190();
        let input = v.get("input").expect("input field");
        let wasm_hex = input
            .get("classifier_wasm_bytes_hex")
            .and_then(Value::as_str)
            .expect("classifier_wasm_bytes_hex populated");
        let wasm = hex::decode(wasm_hex).expect("wasm-hex decodes");
        let pool = shared_wasm_artifacts();
        assert_eq!(
            wasm, pool.tier_1,
            "fuzz-190 must ship the tier_1 fixture so tier<floor is a verifiable property"
        );
        assert_eq!(
            v.get("expected")
                .and_then(|e| e.get("reject_code"))
                .and_then(Value::as_str),
            Some("tier-below-minimum")
        );
    }

    #[test]
    fn fuzz_200_ships_fuel_exhausted_fixture() {
        let v = build_fuzz_200();
        let input = v.get("input").expect("input field");
        let wasm_hex = input
            .get("classifier_wasm_bytes_hex")
            .and_then(Value::as_str)
            .expect("classifier_wasm_bytes_hex populated");
        let wasm = hex::decode(wasm_hex).expect("wasm-hex decodes");
        let pool = shared_wasm_artifacts();
        assert_eq!(
            wasm, pool.fuel_exhausted,
            "fuzz-200 must ship the fuel_exhausted fixture so the trap surface is real"
        );
        assert_eq!(
            v.get("expected")
                .and_then(|e| e.get("reject_code"))
                .and_then(Value::as_str),
            Some("classifier-execution-failed")
        );
    }

    #[test]
    fn build_all_is_deterministic_across_calls() {
        let a = build_all();
        let b = build_all();
        assert_eq!(a, b, "build_all must be pure — OnceLock pool + pinned hex");
    }

    #[test]
    fn empty_ctx_cbor_hex_is_canonical_empty_map() {
        // CBOR major type 5 (map), zero entries → 0xa0. Any drift here
        // silently changes the committed fuzz-baseline.json and breaks
        // the determinism tripwire.
        assert_eq!(empty_ctx_cbor_hex(), "a0");
    }
}
