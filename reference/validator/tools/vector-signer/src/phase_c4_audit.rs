//! Phase C.4 Session 5-B Commit C — audit-replay multi-tenant vectors
//! (`arep-100`..`arep-116`).
//!
//! Dispatched through
//! `crates/ephemeral-core/src/suites/audit.rs`, which drives
//! [`ephemeral_anomaly::AuditOrchestrator::observe_event`] against
//! verified MINIMUM library envelopes and compares the observed
//! `AnomalyDetectedRecord` multiset against `expected.output.records`.
//! This generator replaces the legacy Session-3 category-based
//! `arep-0XX` corpus (32 vectors); the `arep-1XX` namespace signals the
//! Commit-C rewrite and reuses no IDs from the pre-rewrite set.
//!
//! | ID        | Scenario                                                                | Outcome / wire code                                     |
//! |-----------|-------------------------------------------------------------------------|---------------------------------------------------------|
//! | arep-100  | Single-tenant baseline: 5× delete / tier-2 / pod                        | reject `aggregation-pattern-detected` (2 records)       |
//! | arep-101  | Two tenants, only A fires (B = 2× read)                                 | reject — 2 records attribute to tenant-A                |
//! | arep-102  | Two tenants both fire delete-storm on distinct mandates                 | reject — 4 records (2 per tenant)                       |
//! | arep-103  | Two tenants sharing the mandate_id string yet isolated                  | reject — 4 records, tenant_id distinguishes             |
//! | arep-104  | Three tenants, three distinct patterns                                  | reject — 3 patterns × attribution                       |
//! | arep-105  | iam-attach-policy-storm on A, cross-tier on B                           | reject — mixed pattern fires per tenant                 |
//! | arep-106  | Tenant-A VerbFanout (verb projection), Tenant-B MandatePace (tier proj.)| reject — mixed scope-projection fires                   |
//! | arep-107  | Slow-burn cumulative: 20× delete on A, 2× read on B                     | reject — A fires slow-burn + co-fires, B silent         |
//! | arep-108  | Library rotation after stream 0 — tenant-A fires pre+post               | reject — records show both pre- and post-rotation fires |
//! | arep-109  | Library rotation after final stream (post-reset, no post-rotation fire) | reject — records are pre-rotation only                  |
//! | arep-110  | Two tenants, rotation mid-run, each fires on its own side               | reject — pre-A-fires + post-B-fires                     |
//! | arep-111  | ClockRegression inside tenant-A's stream                                | reject `audit-replay-stream-clock-regression`           |
//! | arep-112  | PatternDescription with `count = 0`                                     | reject `audit-replay-stream-pattern-description-…`      |
//! | arep-113  | PatternDescription with unparseable `start_time`                        | reject `audit-replay-stream-timestamp-parse-failed`     |
//! | arep-114  | Two tenants, empty streams                                              | accept                                                  |
//! | arep-115  | Two tenants, both below every firing threshold                          | accept                                                  |
//! | arep-116  | Single tenant, empty stream (negative control)                          | accept                                                  |
//!
//! # Design principles
//!
//! - **Multi-tenant isolation is the load-bearing invariant.**  Vectors
//!   101..107 drive the detector with tenant-keyed streams where the
//!   correct outcome is observable only if `AuditOrchestrator` keeps
//!   one `DetectorState` per tenant.  A regression that collapsed the
//!   tenant map would fire patterns on the wrong tenant_id and fail
//!   the reduced-projection multiset compare.
//! - **Library rotation models the §3.5.1 rotation event.**  Vectors
//!   108..110 exercise the `rotate_library` call; the executor's
//!   apply_rotation path verifies a fresh envelope and clears
//!   per-tenant state.  The post-rotation dedup window restarts
//!   structurally, which these vectors pin behaviourally.
//! - **Stream errors route through the `audit-replay-stream-` prefix.**
//!   Vectors 111..113 complete the wire-code surface for the top 3
//!   stream-normalize/ingest failures; the remaining 6 `StreamError`
//!   variants are covered by `audit-replay-stream-*` unit tests in
//!   `audit.rs`.
//! - **Accepts prove the executor distinguishes silence.**  114..116
//!   are the negative control; a validator that always rejected would
//!   pass every fire-expected vector but fail these.
//!
//! # Expected-record construction
//!
//! The `expected.output.records` shape is the `ExpectedRecord`
//! projection from `audit.rs`:
//! `{tenant_id, pattern_id, library_version, severity, firing_rule,
//! match_scope}`.  `record_timestamp` is NOT pinned — it tracks the
//! detector's current_time after the last `advance_clock`, which
//! would force the vector author into brittle arithmetic.  The
//! reduced projection still covers every load-bearing correctness
//! dimension: tenant attribution, pattern identity, severity/firing-
//! rule correctness, and scope-predicate projection fidelity.
//!
//! # MatchScope projections (mirror `phase_c4_detect.rs`)
//!
//! - `VerbResourceMandate` / `AnyDestructive` / `Family(_)` →
//!   `{mandate_id}` only.
//! - `IamAttachFamily` / `ProtectedBranches` / `CrossTierSequence` /
//!   `SilenceThenBurst` with default `mandate_scope` →
//!   `{mandate_id}` only.
//! - `MandatePace` → `{mandate_id, tier: sample_event.tier}`.
//! - `VerbFanout` with `VerbPredicate::Exact(_)` →
//!   `{mandate_id, verb}`.
//! - `VerbResourceMandate` with both `VerbPredicate::Exact(_)` AND
//!   `Some(resource_kind)` (e.g. vault-rotate-storm) →
//!   `{mandate_id, verb, resource_kind}`.
//!
//! # File layout
//!
//! The 17 builders are partitioned into topic-local sub-modules so no
//! single file exceeds the project's 800-line ceiling:
//!
//! - [`helpers`] — shared canonical-event / scope / vector-shape
//!   builders consumed by every group.
//! - [`fires_single_tenant`] — arep-100..arep-103 (single-tenant
//!   baseline + two-tenant isolation with shared mandate ids).
//! - [`fires_multi_tenant`] — arep-104..arep-107 (three-tenant
//!   attribution, mixed firing-rule families, scope projection
//!   fidelity, cumulative-over-baseline isolation).
//! - [`rotation`] — arep-108..arep-110 (library rotation between,
//!   after, and across tenants).
//! - [`stream_errors`] — arep-111..arep-113 (top-3 stream-error
//!   wire codes).
//! - [`accepts`] — arep-114..arep-116 (below-threshold and empty-
//!   stream negative controls).
//!
//! # Determinism
//!
//! Every constant is compile-time-fixed.  Library envelopes come from
//! [`ephemeral_anomaly::test_fixtures::sign_minimum_library_with_version`]
//! at versions 1 (initial) and 2 (rotation); Ed25519 is deterministic
//! (RFC 8032 §5.1.6) and `ciborium` is byte-stable for
//! `AnomalyLibraryPayload`, so every [`build_all`] call produces
//! byte-identical JSON.  Inline
//! `determinism_two_runs_produce_identical_bytes` pins it; the
//! external-process `tests/determinism_c4_audit.rs` tripwire pins the
//! SHA-256 of `gen-phase-c4-audit --dry-run` stdout against
//! regeneration drift.

use serde_json::Value;

mod accepts;
mod fires_multi_tenant;
mod fires_single_tenant;
mod helpers;
mod rotation;
mod stream_errors;

// ─── Deterministic fixture inputs ───────────────────────────────────────────

/// RFC-3339 "now" used to verify the library envelope.  Sits
/// comfortably inside `[FIXTURE_ANOMALY_ISSUED_AT,
/// FIXTURE_ANOMALY_EXPIRES_AT)` — Stage-6 time-bounds pass.
pub(crate) const CURRENT_TIME: &str = "2026-05-01T00:00:00Z";

/// RFC-3339 clock used as the orchestrator's initial clock
/// ([`AuditOrchestrator::initial_time`]).  Twelve hours after
/// `CURRENT_TIME` — the per-tenant detector's past-dated floor is
/// `initial_time - (max_library_window + PAST_DATED_GRACE_SECONDS)`,
/// so streams keyed to `AUDIT_INITIAL_TIME_UNIX + offset` are always
/// well inside the floor.
pub(crate) const AUDIT_INITIAL_TIME: &str = "2026-05-01T12:00:00Z";

/// Unix-seconds form of [`AUDIT_INITIAL_TIME`].  Cross-checked by
/// the inline `audit_initial_time_unix_matches_iso_literal` test.
pub(crate) const AUDIT_INITIAL_TIME_UNIX: i64 = 1_777_636_800;

/// RFC-3339 clock used as the post-rotation `new_initial_time`.
/// One hour after `AUDIT_INITIAL_TIME` — rotation happens mid-run
/// after pre-rotation streams drain.
pub(crate) const ROTATE_INITIAL_TIME: &str = "2026-05-01T13:00:00Z";

/// Unix-seconds form of [`ROTATE_INITIAL_TIME`].
pub(crate) const ROTATE_INITIAL_TIME_UNIX: i64 = AUDIT_INITIAL_TIME_UNIX + 3_600;

/// Spec-literal wire code for a non-empty firing set
/// (design-final.md §3.5 / R8.A1).
pub(crate) const AGGREGATION_WIRE: &str = "aggregation-pattern-detected";

// ─── Entry point ────────────────────────────────────────────────────────────

/// Emit all 17 Phase C.4 Session 5-B Commit C vectors in ascending
/// ID order.
pub fn build_all() -> Vec<Value> {
    vec![
        fires_single_tenant::build_arep_100_single_tenant_baseline(),
        fires_single_tenant::build_arep_101_two_tenants_only_a_fires(),
        fires_single_tenant::build_arep_102_two_tenants_both_fire(),
        fires_single_tenant::build_arep_103_shared_mandate_id_isolated(),
        fires_multi_tenant::build_arep_104_three_tenants_three_patterns(),
        fires_multi_tenant::build_arep_105_iam_on_a_cross_tier_on_b(),
        fires_multi_tenant::build_arep_106_fanout_a_pace_b(),
        fires_multi_tenant::build_arep_107_slow_burn_cumulative(),
        rotation::build_arep_108_rotation_after_stream_zero(),
        rotation::build_arep_109_rotation_after_final(),
        rotation::build_arep_110_rotation_mid_run(),
        stream_errors::build_arep_111_clock_regression(),
        stream_errors::build_arep_112_pattern_description_count_zero(),
        stream_errors::build_arep_113_timestamp_parse_failed(),
        accepts::build_arep_114_two_tenants_empty(),
        accepts::build_arep_115_two_tenants_below_threshold(),
        accepts::build_arep_116_single_tenant_empty(),
    ]
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_anomaly::ANOMALY_LIBRARY_ABI_VERSION;

    #[test]
    fn build_all_returns_seventeen_unique_ids() {
        let v = build_all();
        assert_eq!(v.len(), 17, "must emit exactly 17 vectors");

        let ids: Vec<_> = v.iter().map(|x| x["id"].as_str().unwrap()).collect();
        for id in &ids {
            assert!(
                id.starts_with("arep-1"),
                "id {id} does not use the arep-1XX namespace"
            );
        }
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 17, "ids must be unique across build_all");
    }

    #[test]
    fn audit_initial_time_unix_matches_iso_literal() {
        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;
        let parsed = OffsetDateTime::parse(AUDIT_INITIAL_TIME, &Rfc3339).unwrap();
        assert_eq!(parsed.unix_timestamp(), AUDIT_INITIAL_TIME_UNIX);
    }

    #[test]
    fn rotate_initial_time_unix_matches_iso_literal() {
        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;
        let parsed = OffsetDateTime::parse(ROTATE_INITIAL_TIME, &Rfc3339).unwrap();
        assert_eq!(parsed.unix_timestamp(), ROTATE_INITIAL_TIME_UNIX);
    }

    #[test]
    fn build_all_produces_expected_outcomes() {
        let v = build_all();
        let expected: [(&str, &str, Option<&str>); 17] = [
            ("arep-100", "reject", Some("aggregation-pattern-detected")),
            ("arep-101", "reject", Some("aggregation-pattern-detected")),
            ("arep-102", "reject", Some("aggregation-pattern-detected")),
            ("arep-103", "reject", Some("aggregation-pattern-detected")),
            ("arep-104", "reject", Some("aggregation-pattern-detected")),
            ("arep-105", "reject", Some("aggregation-pattern-detected")),
            ("arep-106", "reject", Some("aggregation-pattern-detected")),
            ("arep-107", "reject", Some("aggregation-pattern-detected")),
            ("arep-108", "reject", Some("aggregation-pattern-detected")),
            ("arep-109", "reject", Some("aggregation-pattern-detected")),
            ("arep-110", "reject", Some("aggregation-pattern-detected")),
            (
                "arep-111",
                "reject",
                Some("audit-replay-stream-clock-regression"),
            ),
            (
                "arep-112",
                "reject",
                Some("audit-replay-stream-pattern-description-count-zero"),
            ),
            (
                "arep-113",
                "reject",
                Some("audit-replay-stream-timestamp-parse-failed"),
            ),
            ("arep-114", "accept", None),
            ("arep-115", "accept", None),
            ("arep-116", "accept", None),
        ];
        for (i, (id, outcome, code)) in expected.iter().enumerate() {
            let got_id = v[i]["id"].as_str().unwrap();
            let got_outcome = v[i]["expected"]["outcome"].as_str().unwrap();
            assert_eq!(got_id, *id, "vector index {i} id mismatch");
            assert_eq!(got_outcome, *outcome, "vector {id} outcome mismatch");
            match code {
                Some(c) => {
                    let got_code = v[i]["expected"]["reject_code"].as_str().unwrap();
                    assert_eq!(got_code, *c, "vector {id} reject_code mismatch");
                }
                None => assert!(
                    v[i]["expected"].get("reject_code").is_none(),
                    "vector {id} must not carry reject_code for accept outcome"
                ),
            }
        }
    }

    #[test]
    fn rotation_vectors_carry_rotate_library_descriptor() {
        let v = build_all();
        // arep-108, arep-109, arep-110 → indices 8, 9, 10.
        for i in &[8_usize, 9, 10] {
            assert!(
                v[*i]["input"].get("rotate_library").is_some(),
                "vector {} at index {i} must carry rotate_library",
                v[*i]["id"].as_str().unwrap()
            );
            let ri = v[*i]["input"]["rotate_library"].clone();
            assert!(ri["after_tenant_stream_idx"].is_u64());
            assert!(ri["cose_sign1_bytes_anomaly_library"].is_string());
            assert!(ri["new_initial_time"].is_string());
            assert_eq!(
                ri["expected_abi_version"].as_u64().unwrap(),
                u64::from(ANOMALY_LIBRARY_ABI_VERSION)
            );
        }
        // All non-rotation indices MUST NOT carry rotate_library.
        for i in (0..17_usize).filter(|i| ![8, 9, 10].contains(i)) {
            assert!(
                v[i]["input"].get("rotate_library").is_none(),
                "vector {} at index {i} must NOT carry rotate_library",
                v[i]["id"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn determinism_two_runs_produce_identical_bytes() {
        let a = serde_json::to_string(&build_all()).unwrap();
        let b = serde_json::to_string(&build_all()).unwrap();
        assert_eq!(a, b, "build_all must be byte-deterministic");
    }

    #[test]
    fn record_counts_match_design() {
        let v = build_all();
        let expected: [(&str, usize); 17] = [
            ("arep-100", 2),
            ("arep-101", 2),
            ("arep-102", 4),
            ("arep-103", 4),
            ("arep-104", 6),
            ("arep-105", 4),
            ("arep-106", 8),
            ("arep-107", 4),
            ("arep-108", 4),
            ("arep-109", 2),
            ("arep-110", 4),
            ("arep-111", 0),
            ("arep-112", 0),
            ("arep-113", 0),
            ("arep-114", 0),
            ("arep-115", 0),
            ("arep-116", 0),
        ];
        for (i, (id, expected_count)) in expected.iter().enumerate() {
            let got = v[i]["expected"]
                .get("output")
                .and_then(|o| o.get("records").and_then(|f| f.as_array()).map(Vec::len));
            let got_count = got.unwrap_or(0);
            assert_eq!(
                got_count, *expected_count,
                "vector {id} record-count mismatch (got {got_count}, expected {expected_count})"
            );
        }
    }
}
