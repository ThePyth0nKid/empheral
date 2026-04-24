//! Shared builders for the Phase C.4 Session 5-B Commit C audit-replay
//! generator.
//!
//! Split out of the top-level [`crate::phase_c4_audit`] module to keep
//! each sibling builder file (fires-single, fires-multi, rotation,
//! stream-errors, accepts) under the project's 800-line file ceiling.
//! Every helper is `pub(super)` so only the parent module tree can see
//! it — this is an internal implementation surface for the generator,
//! not a public API.
//!
//! The shapes below are load-bearing against the executor in
//! `crates/ephemeral-core/src/suites/audit.rs`:
//! - `canonical_event_*` produces the wire shape consumed by
//!   `observe_event` through the stream normalizer.
//! - `scope_*` produces the `MatchScope` projection the executor
//!   compares against via `ExpectedRecord::from_observed`.
//! - `build_fire_vector` / `build_accept_vector` / `build_reject_stream_vector`
//!   wrap the envelope, tenant streams, and expected block — the
//!   envelope hex comes from `aft::sign_minimum_library_with_version`
//!   (version 1) so every fire vector exercises the same MINIMUM
//!   library.  `attach_rotation` mutates the previously-built JSON to
//!   bolt on a version-2 envelope for the three rotation vectors
//!   (arep-108..110).

use ephemeral_anomaly::test_fixtures as aft;
use ephemeral_anomaly::ANOMALY_LIBRARY_ABI_VERSION;
use serde_json::{json, Value};

use super::{
    AGGREGATION_WIRE, AUDIT_INITIAL_TIME, AUDIT_INITIAL_TIME_UNIX, CURRENT_TIME,
    ROTATE_INITIAL_TIME, ROTATE_INITIAL_TIME_UNIX,
};

// ─── Canonical-event helpers (mirrors phase_c4_detect.rs) ─────────────────

pub(super) fn canonical_delete_event(
    event_id: &str,
    mandate_id: &str,
    offset_seconds: i64,
    tier: u8,
    resource_kind: &str,
    resource_ref: &str,
) -> Value {
    canonical_event_named(
        event_id,
        mandate_id,
        offset_seconds,
        tier,
        "k8s",
        "delete",
        resource_kind,
        resource_ref,
    )
}

pub(super) fn canonical_event_named(
    event_id: &str,
    mandate_id: &str,
    offset_seconds: i64,
    tier: u8,
    integration: &str,
    verb: &str,
    resource_kind: &str,
    resource_ref: &str,
) -> Value {
    json!({
        "event_id": event_id,
        "timestamp": AUDIT_INITIAL_TIME_UNIX + offset_seconds,
        "mandate_id": mandate_id,
        "tier": tier,
        "integration": integration,
        "verb": verb,
        "resource_kind": resource_kind,
        "resource_ref": resource_ref,
        "outcome": "executed",
    })
}

/// Post-rotation canonical event: timestamp keys to
/// [`ROTATE_INITIAL_TIME_UNIX`] rather than the pre-rotation clock.
pub(super) fn canonical_event_post_rotation(
    event_id: &str,
    mandate_id: &str,
    offset_seconds: i64,
    tier: u8,
    integration: &str,
    verb: &str,
    resource_kind: &str,
    resource_ref: &str,
) -> Value {
    json!({
        "event_id": event_id,
        "timestamp": ROTATE_INITIAL_TIME_UNIX + offset_seconds,
        "mandate_id": mandate_id,
        "tier": tier,
        "integration": integration,
        "verb": verb,
        "resource_kind": resource_kind,
        "resource_ref": resource_ref,
        "outcome": "executed",
    })
}

pub(super) fn literal_stream(events: Vec<Value>) -> Value {
    json!({ "literal": { "events": events } })
}

/// Identical to [`literal_stream`] — the distinction is purely
/// naming-level for clarity: post-rotation streams use
/// [`canonical_event_post_rotation`] for their events.
pub(super) fn literal_post_rotation_stream(events: Vec<Value>) -> Value {
    literal_stream(events)
}

pub(super) fn template_event(
    mandate_id: &str,
    tier: u8,
    resource_kind: &str,
    verb: &str,
) -> Value {
    json!({
        "mandate_id": mandate_id,
        "tier": tier,
        "integration": "k8s",
        "verb": verb,
        "resource_kind": resource_kind,
        "outcome": "executed",
    })
}

pub(super) fn tenant_stream(tenant_id: &str, stream: Value) -> Value {
    json!({ "tenant_id": tenant_id, "stream": stream })
}

// ─── Expected-record helpers ──────────────────────────────────────────────

/// MatchScope-shaped JSON with only `mandate_id` bound.
pub(super) fn scope_mandate(mandate_id: &str) -> Value {
    json!({ "mandate_id": mandate_id })
}

/// MatchScope-shaped JSON with `mandate_id` + `verb` bound — the
/// projection VerbFanout (with VerbPredicate::Exact) emits.
pub(super) fn scope_mandate_verb(mandate_id: &str, verb: &str) -> Value {
    json!({ "mandate_id": mandate_id, "verb": verb })
}

/// MatchScope-shaped JSON with `mandate_id` + `tier` bound — the
/// projection MandatePace emits.
pub(super) fn scope_mandate_tier(mandate_id: &str, tier: u8) -> Value {
    json!({ "mandate_id": mandate_id, "tier": tier })
}

/// MatchScope-shaped JSON with `mandate_id` + `verb` + `resource_kind`
/// bound — the projection VerbResourceMandate emits when the pattern
/// pins both a `VerbPredicate::Exact(_)` verb and a `Some(_)`
/// resource_kind (e.g. `vault-rotate-storm`, `vault-rotate-slow-burn`).
pub(super) fn scope_mandate_verb_kind(
    mandate_id: &str,
    verb: &str,
    resource_kind: &str,
) -> Value {
    json!({
        "mandate_id": mandate_id,
        "verb": verb,
        "resource_kind": resource_kind,
    })
}

/// Build an expected-record JSON at library_version = 1 (default).
pub(super) fn expected_record(
    tenant_id: &str,
    pattern_id: &str,
    severity: &str,
    firing_rule: &str,
    match_scope: Value,
) -> Value {
    expected_record_v(tenant_id, pattern_id, 1, severity, firing_rule, match_scope)
}

/// Build an expected-record JSON with an explicit library_version —
/// used by the rotation vectors to distinguish pre-rotation (v1) from
/// post-rotation (v2) fires.
pub(super) fn expected_record_v(
    tenant_id: &str,
    pattern_id: &str,
    library_version: u64,
    severity: &str,
    firing_rule: &str,
    match_scope: Value,
) -> Value {
    json!({
        "tenant_id": tenant_id,
        "pattern_id": pattern_id,
        "library_version": library_version,
        "severity": severity,
        "firing_rule": firing_rule,
        "match_scope": match_scope,
    })
}

// ─── Vector-shape builders ──────────────────────────────────────────────────

pub(super) fn build_fire_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    tenant_streams: Vec<Value>,
    records: Vec<Value>,
    severity: &str,
) -> Value {
    let env = aft::sign_minimum_library_with_version(1);

    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "cose_sign1_bytes_anomaly_library": hex::encode(&env),
            "trust_anchor_keys_anomaly_library": anchor_def(),
            "expected_abi_version": ANOMALY_LIBRARY_ABI_VERSION,
            "current_time": CURRENT_TIME,
            "initial_time": AUDIT_INITIAL_TIME,
            "tenant_streams": tenant_streams,
        },
        "expected": {
            "outcome": "reject",
            "reject_code": AGGREGATION_WIRE,
            "output": { "records": records },
        },
        "rationale": rationale,
        "redteam_refs": ["PHASE-C4-LIVE"],
        "severity_if_failed": severity,
    })
}

pub(super) fn build_accept_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    tenant_streams: Vec<Value>,
) -> Value {
    let env = aft::sign_minimum_library_with_version(1);

    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "cose_sign1_bytes_anomaly_library": hex::encode(&env),
            "trust_anchor_keys_anomaly_library": anchor_def(),
            "expected_abi_version": ANOMALY_LIBRARY_ABI_VERSION,
            "current_time": CURRENT_TIME,
            "initial_time": AUDIT_INITIAL_TIME,
            "tenant_streams": tenant_streams,
        },
        "expected": { "outcome": "accept" },
        "rationale": rationale,
        "redteam_refs": ["PHASE-C4-LIVE"],
        "severity_if_failed": "medium",
    })
}

pub(super) fn build_reject_stream_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    tenant_streams: Vec<Value>,
    reject_code: &str,
) -> Value {
    let env = aft::sign_minimum_library_with_version(1);

    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": {
            "cose_sign1_bytes_anomaly_library": hex::encode(&env),
            "trust_anchor_keys_anomaly_library": anchor_def(),
            "expected_abi_version": ANOMALY_LIBRARY_ABI_VERSION,
            "current_time": CURRENT_TIME,
            "initial_time": AUDIT_INITIAL_TIME,
            "tenant_streams": tenant_streams,
        },
        "expected": {
            "outcome": "reject",
            "reject_code": reject_code,
        },
        "rationale": rationale,
        "redteam_refs": ["PHASE-C4-LIVE"],
        "severity_if_failed": "high",
    })
}

/// Mutate a previously-built fire-vector JSON in place to attach the
/// `rotate_library` descriptor under `input`.  `after_stream_idx` is
/// the zero-based index of the last pre-rotation stream.
pub(super) fn attach_rotation(vector: &mut Value, after_stream_idx: usize) {
    let env = aft::sign_minimum_library_with_version(2);
    let rotation = json!({
        "after_tenant_stream_idx": after_stream_idx,
        "cose_sign1_bytes_anomaly_library": hex::encode(&env),
        "new_initial_time": ROTATE_INITIAL_TIME,
        "expected_abi_version": ANOMALY_LIBRARY_ABI_VERSION,
    });
    vector["input"]["rotate_library"] = rotation;
}

/// Trust-anchor array — fixture kid + fixture pubkey + Ed25519.  The
/// suite executor stamps the role as
/// `AnchorRole::AnomalyLibrarySigner` via `build_anchor_set`.  Both
/// the pre-rotation (v1) and post-rotation (v2) envelopes are signed
/// by the same fixture key, so a single anchor def covers both.
pub(super) fn anchor_def() -> Value {
    json!([{
        "kid": aft::FIXTURE_ANOMALY_KID,
        "alg": "ed25519",
        "pk_hex": hex::encode(aft::fixture_anomaly_verifying_key_bytes()),
    }])
}
