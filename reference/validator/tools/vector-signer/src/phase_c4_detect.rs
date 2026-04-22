//! Phase C.4 Session 5-B Commit B — anomaly-detect firing-rule vectors
//! (`adet-100`..`adet-114`).
//!
//! Dispatched through
//! `crates/ephemeral-core/src/suites/anomaly_detect.rs`, which drives
//! [`ephemeral_anomaly::DetectorState::evaluate_all`] against the
//! MINIMUM library envelope (same envelope the
//! `anomaly-library-reject` suite uses) and compares the observed
//! firing multiset against `expected.output.fires`.
//!
//! | ID        | Scenario                                                                 | Outcome / wire code                                      |
//! |-----------|--------------------------------------------------------------------------|----------------------------------------------------------|
//! | adet-100  | 5 × delete / tier-2 / same pod                                           | reject `anomaly-detected` — delete-storm + gfp-storm     |
//! | adet-101  | 5 × attachrolepolicy / tier-2 / role                                     | reject `anomaly-detected` — iam-attach-storm + gfp-storm |
//! | adet-102  | 3 × rotate / tier-2 / vault-secret                                       | reject `anomaly-detected` — vault-rotate-storm + gfp     |
//! | adet-103  | 3 × get / tier-0 / repo (non-destructive, below machine-pace floor)      | reject `anomaly-detected` — gfp-storm only               |
//! | adet-104  | 10 × delete / tier-0 / distinct pods                                     | reject `anomaly-detected` — storm + gfp×2 + fanout       |
//! | adet-105  | 3 × get / tiers 0→2→3 / config (cross-tier completion)                   | reject `anomaly-detected` — cross-tier + gfp-storm       |
//! | adet-106  | 20 × delete / 30s spacing / tier-0 / same pod (walk-under + slow-burn)   | reject `anomaly-detected` — slow-burn + gfp×2            |
//! | adet-107  | 20 × attachrolepolicy / 150s spacing / tier-0 / same role                | reject `anomaly-detected` — iam-slow-burn + gfp×2        |
//! | adet-108  | two streams same mandate (fire-once dedup within window)                 | reject `anomaly-detected` — storm + gfp, stream 2 dedupd |
//! | adet-109  | empty literal stream                                                     | accept                                                   |
//! | adet-110  | 2 × get / tier-0 (below every threshold)                                 | accept                                                   |
//! | adet-111  | 50 × patch / 1s spacing / tier-1 (machine-pace + silence-burst + gfp×2)  | reject `anomaly-detected` — four-way fire                |
//! | adet-112  | ClockRegression — stream-level monotonic-clock violation                 | reject `anomaly-detect-stream-clock-regression`          |
//! | adet-113  | PatternDescription with `count = 0`                                      | reject `anomaly-detect-stream-pattern-description-…`     |
//! | adet-114  | PatternDescription with unparseable `start_time`                         | reject `anomaly-detect-stream-timestamp-parse-failed`    |
//!
//! # Design principles
//!
//! Every fire-expected vector pins the MINIMUM library intentionally:
//! the library's 10 primaries + 5 companions drive a rich collision
//! surface (ProtectedBranches has wildcard mandate_scope → fires on
//! every mandate that crosses its 3-event threshold), so a single
//! stream often triggers multiple patterns at once.  That is precisely
//! the correctness burden the executor's multiset comparison must
//! shoulder; authoring it out of the vectors would leave the multiset
//! path untested.
//!
//! The accept vectors (adet-109, adet-110) are the negative control:
//! a validator that always rejected would pass every fire-expected
//! vector but fail the accepts, so the accepts carry the load of
//! proving the executor actually DISTINGUISHES firing from silence.
//!
//! # Expected-fire construction
//!
//! [`AnomalyFire`] is `#[non_exhaustive]`, so a downstream crate (this
//! one) cannot build instances via struct literal.  Instead each
//! builder emits the expected-fire object as `serde_json::json!({...})`
//! at the shape matched by the `Deserialize` impl.  Field names mirror
//! §11.2 literally — any drift between the wire shape and the DTO is
//! caught at executor time by `AnomalyFire::deserialize`.
//!
//! # MatchScope projections
//!
//! The executor projects observed-event values into `MatchScope` per
//! the firing pattern's scope-predicate shape
//! (`build_match_scope` in `evaluators.rs`).  The expected-fire
//! builders below mirror that projection exactly:
//!
//! - `VerbResourceMandate` with `VerbPredicate::AnyDestructive` or
//!   `Family(_)` → `{mandate_id}` only (family predicates do not pin
//!   a verb).
//! - `VerbResourceMandate` with `VerbPredicate::Exact(_)` → adds
//!   `verb`; `+ resource_kind` if the predicate bound that dimension.
//! - `IamAttachFamily` / `ProtectedBranches` / `CrossTierSequence` /
//!   `SilenceThenBurst` with default `mandate_scope` → `{mandate_id}`
//!   only (integration_ref stays unbound).
//! - `MandatePace` → `{mandate_id, tier: sample_event.tier}`.
//! - `VerbFanout` with `VerbPredicate::Exact(_)` → `{mandate_id,
//!   verb}`.
//!
//! # Determinism
//!
//! Every constant is compile-time-fixed.  The library envelope comes
//! from [`ephemeral_anomaly::test_fixtures::sign_minimum_library_with_version`]
//! at `version=1`; Ed25519 signing is deterministic (RFC 8032 §5.1.6)
//! and `ciborium` is byte-stable for `AnomalyLibraryPayload`, so every
//! `build_all()` call produces byte-identical JSON.  Inline regression
//! test `determinism_two_runs_produce_identical_bytes` pins it; the
//! external-process `tests/determinism_c4_detect.rs` tripwire mirrors
//! the C.4 Session-4 pattern and pins the SHA-256 of `gen-phase-c4-
//! detect --dry-run` stdout against regeneration drift.

use ephemeral_anomaly::test_fixtures as aft;
use ephemeral_anomaly::ANOMALY_LIBRARY_ABI_VERSION;
use serde_json::{json, Value};

// ─── Deterministic fixture inputs ───────────────────────────────────────────

/// RFC-3339 clock used to verify the library envelope.  Sits
/// comfortably inside `[FIXTURE_ANOMALY_ISSUED_AT,
/// FIXTURE_ANOMALY_EXPIRES_AT)` — Stage-6 time-bounds pass.
const CURRENT_TIME: &str = "2026-05-01T00:00:00Z";

/// RFC-3339 clock used as the detector's initial clock
/// ([`DetectorState::new`] `initial_time`).  Twelve hours AFTER
/// `CURRENT_TIME` — the detector's past-dated floor is
/// `initial_time - (max_library_window + PAST_DATED_GRACE_SECONDS)`
/// = `initial_time - 691 200s` (~8 d), so streams keyed to
/// `INITIAL_TIME_UNIX + offset` are always well inside the floor.
const DETECT_INITIAL_TIME: &str = "2026-05-01T12:00:00Z";

/// Unix-seconds form of [`DETECT_INITIAL_TIME`].  Duplicated as a
/// compile-time constant so per-event timestamps are bare integer
/// arithmetic — no runtime ISO parsing inside the builder.
/// `2026-05-01T12:00:00Z` = `1_777_593_600` (`2026-05-01T00:00:00Z`
/// unix base) `+ 43_200` (12 h) `= 1_777_636_800`.  Cross-checked at
/// compile time by the inline `detect_initial_time_unix_matches_iso_literal`
/// test near the bottom of this file.
const DETECT_INITIAL_TIME_UNIX: i64 = 1_777_636_800;

/// Spec-literal wire code for a non-empty firing set (§11.2).
/// Mirrored against `suites::anomaly_detect::ANOMALY_DETECTED_WIRE`
/// — any drift between the two is caught at the CLI-total-pin
/// tripwire.
const ANOMALY_DETECTED_WIRE: &str = "anomaly-detected";

// ─── Entry point ────────────────────────────────────────────────────────────

/// Emit all 15 Phase C.4 Session 5-B Commit B vectors in ascending
/// ID order.
pub fn build_all() -> Vec<Value> {
    vec![
        build_adet_100_delete_storm_basic(),
        build_adet_101_iam_attach_storm(),
        build_adet_102_vault_rotate_storm(),
        build_adet_103_gfp_only(),
        build_adet_104_fanout_and_slow_burn(),
        build_adet_105_cross_tier_escalation(),
        build_adet_106_delete_walk_under_slow_burn(),
        build_adet_107_iam_walk_under_slow_burn(),
        build_adet_108_fire_once_dedup_across_streams(),
        build_adet_109_empty_stream(),
        build_adet_110_below_threshold(),
        build_adet_111_machine_pace_and_silence_burst(),
        build_adet_112_clock_regression(),
        build_adet_113_pattern_description_count_zero(),
        build_adet_114_timestamp_parse_failed(),
    ]
}

// ─── Fire-expected vectors (adet-100..108, adet-111) ────────────────────────

/// adet-100 — five delete events at tier=2 on the same pod, within
/// 5 s.
///
/// Fires:
/// - `delete-storm` (FirstMatch, Count≥5 in 60 s).
/// - `git-force-push-storm` — fires because the pattern's
///   `MandateScope` is fully unbound (any mandate) AND the
///   `protected_patterns` resource-ref filter is not yet applied at
///   bucket-membership time at Session 5-B Commit A (deferred to a
///   later commit; see scope_match.rs §140-141 comment).  The two
///   conditions are independent — the mandate wildcard alone would
///   not fire on arbitrary resource_refs if `protected_patterns`
///   were already enforced; the current behaviour is load-bearing
///   for every adet-10x vector expecting a co-fire from this
///   pattern.  Count≥3 in 300 s.
fn build_adet_100_delete_storm_basic() -> Value {
    let stream = literal_stream(vec![
        canonical_delete_event("e-0", "m-a100", 0, 2, "pod", "pod/foo"),
        canonical_delete_event("e-1", "m-a100", 1, 2, "pod", "pod/foo"),
        canonical_delete_event("e-2", "m-a100", 2, 2, "pod", "pod/foo"),
        canonical_delete_event("e-3", "m-a100", 3, 2, "pod", "pod/foo"),
        canonical_delete_event("e-4", "m-a100", 4, 2, "pod", "pod/foo"),
    ]);

    build_vector(
        "adet-100",
        "anomaly-detect-delete-storm-basic",
        "Five destructive `delete` events on the same pod under one \
         mandate at tier 2 cross the FirstMatch Count(5) threshold in \
         60 s. `delete-storm` fires; the ProtectedBranches wildcard \
         co-fires `git-force-push-storm` because Session 5-B Commit A \
         does not yet narrow the predicate with `protected_patterns` \
         resource-ref globbing (scope_match.rs §140-141 comment).",
        "design-final.md §3.5.3 FirstMatch + §3.5.4 MINIMUM-library \
         `delete-storm` and `git-force-push-storm` rows. The multiset \
         expected-fire assertion pins that the evaluator emits BOTH \
         fires from a single evaluate_all call rather than \
         short-circuiting at the first match.",
        vec![stream],
        vec![
            expected_fire(
                "delete-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a100"),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a100"),
            ),
        ],
        "high",
    )
}

/// adet-101 — five `attachrolepolicy` events within 5 s drive the
/// `iam-attach` family primary plus the ProtectedBranches wildcard.
fn build_adet_101_iam_attach_storm() -> Value {
    let stream = literal_stream(vec![
        canonical_event_named("e-0", "m-a101", 0, 2, "aws-iam", "attachrolepolicy", "role", "role/admin"),
        canonical_event_named("e-1", "m-a101", 1, 2, "aws-iam", "attachrolepolicy", "role", "role/admin"),
        canonical_event_named("e-2", "m-a101", 2, 2, "aws-iam", "attachrolepolicy", "role", "role/admin"),
        canonical_event_named("e-3", "m-a101", 3, 2, "aws-iam", "attachrolepolicy", "role", "role/admin"),
        canonical_event_named("e-4", "m-a101", 4, 2, "aws-iam", "attachrolepolicy", "role", "role/admin"),
    ]);

    build_vector(
        "adet-101",
        "anomaly-detect-iam-attach-storm",
        "Five `attachrolepolicy` events (member of the `iam-attach` \
         verb family) on the same role within 5 s satisfy \
         `iam-attach-policy-storm` FirstMatch Count(5) in 300 s. \
         `git-force-push-storm` co-fires through its ProtectedBranches \
         wildcard at Count(3).",
        "design-final.md §3.5.3 IamAttachFamily + MINIMUM library. \
         IamAttachFamily does NOT pin a specific verb at projection \
         time (family predicates carry no verb attribution per \
         MatchScope::verb docstring), so the expected fire omits \
         `verb`.",
        vec![stream],
        vec![
            expected_fire(
                "iam-attach-policy-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a101"),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a101"),
            ),
        ],
        "high",
    )
}

/// adet-102 — three `rotate` events on `vault-secret` resources.
/// Tests the VerbResourceMandate `Exact(_)` + bound `resource_kind`
/// MatchScope projection (verb AND resource_kind appear in the fire).
fn build_adet_102_vault_rotate_storm() -> Value {
    let stream = literal_stream(vec![
        canonical_event_named("e-0", "m-a102", 0, 2, "vault", "rotate", "vault-secret", "secret/prod/db-key"),
        canonical_event_named("e-1", "m-a102", 1, 2, "vault", "rotate", "vault-secret", "secret/prod/db-key"),
        canonical_event_named("e-2", "m-a102", 2, 2, "vault", "rotate", "vault-secret", "secret/prod/db-key"),
    ]);

    build_vector(
        "adet-102",
        "anomaly-detect-vault-rotate-storm",
        "Three `rotate` events on `vault-secret` in 3 s satisfy \
         `vault-rotate-storm` FirstMatch Count(3) in 3 600 s. \
         The fire's MatchScope pins both `verb=rotate` and \
         `resource_kind=vault-secret` because the predicate \
         `VerbResourceMandate { verb: Exact(\"rotate\"), \
         resource_kind: Some(\"vault-secret\"), .. }` binds both. \
         `git-force-push-storm` co-fires at Count(3).",
        "design-final.md §3.5.3 MatchScope projection for VerbResource-\
         Mandate: `verb` is `Some(sample_event.verb.clone())` iff \
         `VerbPredicate::Exact(_)`; `resource_kind` is \
         `Some(sample_event.resource_kind.clone())` iff bound.",
        vec![stream],
        vec![
            expected_fire(
                "vault-rotate-storm",
                "high",
                "first-match",
                json!({
                    "mandate_id": "m-a102",
                    "verb": "rotate",
                    "resource_kind": "vault-secret",
                }),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a102"),
            ),
        ],
        "high",
    )
}

/// adet-103 — three read-only `get` events at tier 0.
///
/// Fires only `git-force-push-storm` (ProtectedBranches wildcard).
/// `machine-pace` is tier-floored at 1 and read-only-excluded, so
/// the `get`/tier-0 stream never enters its bucket.  `delete-storm`
/// requires AnyDestructive — `get` is read-only.
fn build_adet_103_gfp_only() -> Value {
    let stream = literal_stream(vec![
        canonical_event_named("e-0", "m-a103", 0, 0, "github", "get", "repo", "org/app"),
        canonical_event_named("e-1", "m-a103", 1, 0, "github", "get", "repo", "org/app"),
        canonical_event_named("e-2", "m-a103", 2, 0, "github", "get", "repo", "org/app"),
    ]);

    build_vector(
        "adet-103",
        "anomaly-detect-gfp-only-isolation",
        "Three `get` events at tier 0. `machine-pace` is tier-floored \
         (tier_floor=1) and excludes the `read-only` verb family, so \
         it does not even enter the bucket. `delete-storm` requires \
         AnyDestructive. Only `git-force-push-storm` fires, isolating \
         the ProtectedBranches wildcard path from the destructive-\
         verb path.",
        "design-final.md §3.5.3 MandatePace `tier_floor` + \
         `exclude_verb_category` semantics. This vector pins that \
         read-only events below the tier floor neither enter \
         machine-pace's bucket nor block other patterns' firing — \
         the gates are independent.",
        vec![stream],
        vec![expected_fire(
            "git-force-push-storm",
            "high",
            "first-match",
            match_scope_mandate("m-a103"),
        )],
        "high",
    )
}

/// adet-104 — ten `delete` events on TEN distinct pod resources
/// within 10 s.
///
/// Fires:
/// - `delete-storm` (Count 10 ≥ 5).
/// - `git-force-push-storm` (wildcard, 10 ≥ 3).
/// - `git-force-push-slow-burn` (wildcard cumulative, 10 ≥ 10).
/// - `fanout-distinct-resources` (VerbFanout + DistinctCount(10)).
///
/// `machine-pace` does NOT fire because tier_floor=1 rejects tier=0.
fn build_adet_104_fanout_and_slow_burn() -> Value {
    let mut events = Vec::with_capacity(10);
    for i in 0..10 {
        events.push(canonical_delete_event(
            &format!("e-{i}"),
            "m-a104",
            i,
            0,
            "pod",
            &format!("pod/n-{i}"),
        ));
    }
    let stream = literal_stream(events);

    build_vector(
        "adet-104",
        "anomaly-detect-fanout-distinct-and-slow-burn",
        "Ten `delete` events on ten distinct pods under one mandate. \
         Four patterns fire: delete-storm (Count), \
         git-force-push-storm (wildcard Count), git-force-push-slow-\
         burn (wildcard Cumulative 10 ≥ 10), and fanout-distinct-\
         resources (VerbFanout + DistinctCount 10 = 10). machine-pace \
         is NOT a bucket candidate because its `tier_floor=1` rejects \
         all tier=0 events at bucket-membership time (scope_match.rs \
         §193-194) — so the bucket is empty, not just below-threshold.",
        "design-final.md §3.5.3 DistinctCount threshold + §3.5.4 \
         `fanout-distinct-resources` row. Pins that the distinct-\
         resource counter and the plain Count counter fire \
         INDEPENDENTLY on the same stream — fanout is scope-\
         sensitive, not a mere variant of delete-storm.",
        vec![stream],
        vec![
            expected_fire(
                "delete-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a104"),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a104"),
            ),
            expected_fire(
                "git-force-push-slow-burn",
                "medium",
                "cumulative-over-baseline",
                match_scope_mandate("m-a104"),
            ),
            expected_fire(
                "fanout-distinct-resources",
                "high",
                "first-match",
                json!({
                    "mandate_id": "m-a104",
                    "verb": "delete",
                }),
            ),
        ],
        "high",
    )
}

/// adet-105 — three `get` events at tiers [0, 2, 3] drive a
/// CrossTierSequence completion.
///
/// `cross-tier-escalation` walks the `[0, 2, 3]` progression
/// exactly; 1 completion ≥ Sequence(1) → fires.
/// `git-force-push-storm` wildcard co-fires.
/// `machine-pace` rejects on read-only + tier-floor for events 0/1
/// and read-only for event 2 → 0 events in its bucket → silent.
fn build_adet_105_cross_tier_escalation() -> Value {
    let stream = literal_stream(vec![
        canonical_event_named("e-0", "m-a105", 0, 0, "config", "get", "config", "cfg/a"),
        canonical_event_named("e-1", "m-a105", 1, 2, "config", "get", "config", "cfg/b"),
        canonical_event_named("e-2", "m-a105", 2, 3, "config", "get", "config", "cfg/c"),
    ]);

    build_vector(
        "adet-105",
        "anomaly-detect-cross-tier-escalation",
        "Three events walk tiers 0 → 2 → 3 in order — satisfying the \
         `cross-tier-escalation` CrossTierSequence template `[0, 2, \
         3]` in 1 800 s. Severity=Critical, FiringRule=SequenceMatch. \
         `git-force-push-storm` wildcard co-fires at Count(3).",
        "design-final.md §3.5.3 CrossTierSequence walk semantics: \
         step k matches on `event.tier >= tier_progression[k]`, \
         advances to step k+1 on match, records a completion at \
         `step == len`. This vector pins 1 completion = 1 fire \
         under Threshold::Sequence(1).",
        vec![stream],
        vec![
            expected_fire(
                "cross-tier-escalation",
                "critical",
                "sequence-match",
                match_scope_mandate("m-a105"),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a105"),
            ),
        ],
        "critical",
    )
}

/// adet-106 — 20 destructive events spaced 30 s apart, same pod.
///
/// delete-storm's 60 s window holds at most 3 events at this pace,
/// so it NEVER fires — the walk-under succeeds against the short-
/// window primary. `delete-slow-burn` (the companion, window=600 s,
/// threshold=20) catches the whole 20-event window and fires. This
/// is the canonical anti-walk-under demonstration from §3.5.3.
///
/// `git-force-push-storm` (window=300, Count=3) and
/// `git-force-push-slow-burn` (window=3000, Count=10) both fire
/// from the ProtectedBranches wildcard.
fn build_adet_106_delete_walk_under_slow_burn() -> Value {
    let mut events = Vec::with_capacity(20);
    for i in 0..20 {
        events.push(canonical_delete_event(
            &format!("e-{i}"),
            "m-a106",
            i64::from(i) * 30,
            0,
            "pod",
            "pod/n-0",
        ));
    }
    let stream = literal_stream(events);

    build_vector(
        "adet-106",
        "anomaly-detect-delete-walk-under-slow-burn",
        "Twenty `delete` events spaced 30 s apart on the same pod. \
         The 60 s window of `delete-storm` holds at most 3 events at \
         this pace, so the short-window primary NEVER fires — the \
         textbook walk-under. The `delete-slow-burn` companion \
         (Cumulative Count=20 in 600 s) catches the cumulative stream \
         and fires. git-force-push-* co-fire via ProtectedBranches \
         wildcard at their own thresholds.",
        "design-final.md §3.5.3 anti-walk-under rationale. Without \
         the Cumulative companion, a patient attacker spaced just \
         below the FirstMatch threshold defeats the primary entirely \
         — this vector is the positive proof that the companion \
         mechanism WORKS on a textbook walk-under.",
        vec![stream],
        vec![
            expected_fire(
                "delete-slow-burn",
                "medium",
                "cumulative-over-baseline",
                match_scope_mandate("m-a106"),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a106"),
            ),
            expected_fire(
                "git-force-push-slow-burn",
                "medium",
                "cumulative-over-baseline",
                match_scope_mandate("m-a106"),
            ),
        ],
        "high",
    )
}

/// adet-107 — 20 `attachrolepolicy` events spaced 150 s apart.
///
/// iam-attach-policy-storm's 300 s window holds at most 3 events at
/// this pace → walk-under succeeds against the short-window
/// primary. The companion iam-attach-slow-burn (window=3000 s,
/// Count=20) catches all 20 events and fires. gfp-storm + gfp-slow-
/// burn co-fire.
fn build_adet_107_iam_walk_under_slow_burn() -> Value {
    let mut events = Vec::with_capacity(20);
    for i in 0..20 {
        events.push(canonical_event_named(
            &format!("e-{i}"),
            "m-a107",
            i64::from(i) * 150,
            0,
            "aws-iam",
            "attachrolepolicy",
            "role",
            "role/admin",
        ));
    }
    let stream = literal_stream(events);

    build_vector(
        "adet-107",
        "anomaly-detect-iam-walk-under-slow-burn",
        "Twenty `attachrolepolicy` events spaced 150 s apart. The \
         `iam-attach-policy-storm` 300 s window holds at most 3 \
         events at this pace → walk-under succeeds against the \
         short-window primary. `iam-attach-slow-burn` (Cumulative \
         Count=20 in 3 000 s) catches the cumulative stream. gfp-* \
         co-fire.",
        "design-final.md §3.5.3 anti-walk-under — mirrored across \
         two different verb-family patterns to pin that the companion \
         mechanism is scope-agnostic: IamAttachFamily walk-under \
         behaves identically to VerbResourceMandate walk-under.",
        vec![stream],
        vec![
            expected_fire(
                "iam-attach-slow-burn",
                "medium",
                "cumulative-over-baseline",
                match_scope_mandate("m-a107"),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a107"),
            ),
            expected_fire(
                "git-force-push-slow-burn",
                "medium",
                "cumulative-over-baseline",
                match_scope_mandate("m-a107"),
            ),
        ],
        "high",
    )
}

/// adet-108 — fire-once dedup across two streams on the same
/// (pattern_id, mandate_id).
///
/// Stream 1: 5 delete events → delete-storm + git-force-push-storm
/// fire, `last_fired_at[(delete-storm, m-a108)] = 4` (current_time
/// after ingest).  Stream 2: 3 delete events at t=5..7. Evaluate_all
/// runs; the bucket has 8 events in window so threshold crosses
/// again, but `current_time (7) - fired_at (4) = 3 < 60` → suppressed
/// → NO second fire.  Same for git-force-push-storm (3 < 300).
fn build_adet_108_fire_once_dedup_across_streams() -> Value {
    let stream_one = literal_stream(vec![
        canonical_delete_event("e1-0", "m-a108", 0, 2, "pod", "pod/foo"),
        canonical_delete_event("e1-1", "m-a108", 1, 2, "pod", "pod/foo"),
        canonical_delete_event("e1-2", "m-a108", 2, 2, "pod", "pod/foo"),
        canonical_delete_event("e1-3", "m-a108", 3, 2, "pod", "pod/foo"),
        canonical_delete_event("e1-4", "m-a108", 4, 2, "pod", "pod/foo"),
    ]);
    let stream_two = literal_stream(vec![
        canonical_delete_event("e2-0", "m-a108", 5, 2, "pod", "pod/foo"),
        canonical_delete_event("e2-1", "m-a108", 6, 2, "pod", "pod/foo"),
        canonical_delete_event("e2-2", "m-a108", 7, 2, "pod", "pod/foo"),
    ]);

    build_vector(
        "adet-108",
        "anomaly-detect-fire-once-dedup-across-streams",
        "Two streams on the same (delete-storm, m-a108) key. Stream 1 \
         fires delete-storm and gfp-storm; stream 2's additional 3 \
         events recross the threshold but land inside the 60 s (or \
         300 s) suppression window → no re-fire. Pins the fire-once \
         dedup key against a future refactor that reset \
         `last_fired_at` at stream boundaries.",
        "design-final.md §3.5.3 fire-once semantics + evaluators.rs \
         `is_fire_suppressed`: `current_time - fired_at < \
         window_seconds` is STRICT `<`, so equal-window re-fires are \
         allowed. This vector's second stream lands at distance 3, \
         firmly inside the window, so suppression is unambiguous.",
        vec![stream_one, stream_two],
        vec![
            expected_fire(
                "delete-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a108"),
            ),
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a108"),
            ),
        ],
        "high",
    )
}

// ─── Accept vectors (adet-109, adet-110) ────────────────────────────────────

/// adet-109 — empty literal stream. The executor ingests zero
/// events, `evaluate_all` returns empty, the expected.fires list is
/// also empty → accept.
fn build_adet_109_empty_stream() -> Value {
    let stream = literal_stream(vec![]);

    build_accept_vector(
        "adet-109",
        "anomaly-detect-empty-stream",
        "Empty literal stream. Zero events, zero fires, zero \
         suppression bookkeeping. Pins that the executor's \
         accept path produces ValidationOutcome::Pass rather than \
         Fail on the edge case of a stream with no events.",
        "design-final.md §3.5.3: an empty observation window is a \
         valid state (no activity observed). A validator that \
         treated it as an error would fail every post-restart \
         cold start — reject that shape at this vector.",
        vec![stream],
    )
}

/// adet-110 — two `get` events at tier 0 on the same repo.
///
/// Below the 3-event ProtectedBranches threshold; tier-floored out
/// of machine-pace; non-destructive so no storm primary matches.
/// Expected: accept, zero fires.
fn build_adet_110_below_threshold() -> Value {
    let stream = literal_stream(vec![
        canonical_event_named("e-0", "m-a110", 0, 0, "github", "get", "repo", "org/x"),
        canonical_event_named("e-1", "m-a110", 1, 0, "github", "get", "repo", "org/x"),
    ]);

    build_accept_vector(
        "adet-110",
        "anomaly-detect-below-all-thresholds",
        "Two read-only `get` events at tier 0 — below every \
         MINIMUM-library threshold. ProtectedBranches requires 3, \
         machine-pace requires tier ≥ 1, storm primaries require \
         destructive verbs. Pins the negative control: the executor \
         does NOT emit a spurious fire when a stream is strictly \
         under-threshold.",
        "design-final.md §3.5.3: the firing rule is `count ≥ \
         threshold`, NOT `count > 0`. A validator that fired on \
         any activity at all would catch this case as a false \
         positive — this vector surfaces that regression.",
        vec![stream],
    )
}

// ─── Four-way fire (adet-111) ────────────────────────────────────────────────

/// adet-111 — 50 `patch` events at tier 1, 1 s spacing, same
/// configmap.
///
/// Fires four ways:
/// - `git-force-push-storm` (wildcard, 50 ≥ 3).
/// - `git-force-push-slow-burn` (wildcard cumulative, 50 ≥ 10).
/// - `machine-pace` (tier 1 passes floor, `patch` not in read-only
///   family; Cumulative 50 ≥ 50 in 60 s).  MatchScope binds `tier`.
/// - `long-silence-before-burst` (first event carries implicit
///   infinite silence; 20 events fall within 300 s burst window →
///   1 completion ≥ Sequence(1)).  NOTE: `ScopePredicate::
///   SilenceThenBurst` has no mandate-scope filtering at bucket-
///   membership time (scope_match.rs §204 — matches every event
///   globally), so all 50 events land in the same bucket.  In a
///   future multi-mandate vector, events from an unrelated mandate
///   would contribute to this same bucket and could mask the
///   implicit-infinite-silence at `i=0`; this vector is single-
///   mandate so the buffer is clean.
fn build_adet_111_machine_pace_and_silence_burst() -> Value {
    let mut events = Vec::with_capacity(50);
    for i in 0..50 {
        events.push(canonical_event_named(
            &format!("e-{i}"),
            "m-a111",
            i64::from(i),
            1,
            "k8s",
            "patch",
            "configmap",
            "cm/foo",
        ));
    }
    let stream = literal_stream(events);

    build_vector(
        "adet-111",
        "anomaly-detect-machine-pace-and-silence-burst",
        "Fifty `patch` events at tier 1, 1 s apart on the same \
         configmap. Four patterns fire: git-force-push-storm and \
         -slow-burn (wildcard ProtectedBranches), machine-pace \
         (MandatePace Cumulative Count 50 ≥ 50, MatchScope binds \
         tier), and long-silence-before-burst (first event's \
         implicit infinite silence satisfies the silence gate; 20 \
         events within 1 s span fall well inside the 300 s burst \
         window).",
        "design-final.md §3.5.3 MandatePace tier projection + \
         SilenceThenBurst implicit-silence semantics \
         (evaluators.rs `count_silence_then_burst` i=0 branch). This \
         vector pins the widest-multiset fire in the suite, exercising \
         every projection path the evaluator supports except the \
         fanout distinct-count path.",
        vec![stream],
        vec![
            expected_fire(
                "git-force-push-storm",
                "high",
                "first-match",
                match_scope_mandate("m-a111"),
            ),
            expected_fire(
                "git-force-push-slow-burn",
                "medium",
                "cumulative-over-baseline",
                match_scope_mandate("m-a111"),
            ),
            expected_fire(
                "machine-pace",
                "low",
                "cumulative-over-baseline",
                json!({
                    "mandate_id": "m-a111",
                    "tier": 1,
                }),
            ),
            expected_fire(
                "long-silence-before-burst",
                "medium",
                "sequence-match",
                match_scope_mandate("m-a111"),
            ),
        ],
        "high",
    )
}

// ─── Stream-reject vectors (adet-112..114) ──────────────────────────────────

/// adet-112 — two literal events whose timestamps regress (second
/// < first). `state.advance_clock` rejects at the second event's
/// non-monotone step with `ClockRegression { from, to }`, wire
/// `anomaly-detect-stream-clock-regression`.
fn build_adet_112_clock_regression() -> Value {
    let stream = literal_stream(vec![
        canonical_delete_event("e-forward", "m-a112", 100, 2, "pod", "pod/foo"),
        // Regressing timestamp — 50 < 100.  Passes
        // CanonicalizedEvent/Deserialize shape validation, but fails
        // `state.advance_clock` with `ClockRegression { from: 100,
        // to: 50 }`.
        canonical_delete_event("e-regress", "m-a112", 50, 2, "pod", "pod/foo"),
    ]);

    build_reject_stream_vector(
        "adet-112",
        "anomaly-detect-clock-regression",
        "Two literal events where the second timestamp is lower than \
         the first. `DetectorState::advance_clock` enforces strict \
         monotonic progression and rejects the second event with \
         `ClockRegression { from, to }` before ingest. Wire \
         `anomaly-detect-stream-clock-regression`.",
        "design-final.md §3.5.3 — the detector clock is the operator's \
         best estimate of `now`, and out-of-order audit input MUST \
         reject rather than silently mask a replay. A backwards \
         step here could let an attacker re-window a stale event \
         into a fresh sliding-window bucket.",
        vec![stream],
        "anomaly-detect-stream-clock-regression",
    )
}

/// adet-113 — a `pattern_description` stream with `count = 0`.
/// Fails at `AuditStreamInput::normalize` with
/// `PatternDescriptionCountZero`.
fn build_adet_113_pattern_description_count_zero() -> Value {
    let stream = json!({
        "pattern_description": {
            "start_time": DETECT_INITIAL_TIME,
            "end_time": DETECT_INITIAL_TIME,
            "count": 0,
            "interval_seconds": 0,
            "template_event": template_event("m-a113", 2, "pod", "delete"),
            "resource_ref_pattern": "pod/n-{i}",
        }
    });

    build_reject_stream_vector(
        "adet-113",
        "anomaly-detect-pattern-description-count-zero",
        "Pattern-description stream with count=0. Expansion rejects \
         at normalize with `PatternDescriptionCountZero`, wire \
         `anomaly-detect-stream-pattern-description-count-zero`.",
        "design-final.md §3.5.3 — a zero-count expansion is a \
         degenerate signer-side mistake. Accepting it would silently \
         produce zero events (indistinguishable from a legitimate \
         empty stream) and mask the vector author's bug. Reject \
         eagerly.",
        vec![stream],
        "anomaly-detect-stream-pattern-description-count-zero",
    )
}

/// adet-114 — a `pattern_description` stream whose `start_time` is
/// not RFC-3339. Normalize parses the timestamp first and rejects
/// with `TimestampParseFailed`.
fn build_adet_114_timestamp_parse_failed() -> Value {
    let stream = json!({
        "pattern_description": {
            "start_time": "not-a-real-iso-timestamp",
            "end_time": DETECT_INITIAL_TIME,
            "count": 3,
            "interval_seconds": 1,
            "template_event": template_event("m-a114", 2, "pod", "delete"),
            "resource_ref_pattern": "pod/n-{i}",
        }
    });

    build_reject_stream_vector(
        "adet-114",
        "anomaly-detect-timestamp-parse-failed",
        "Pattern-description stream with `start_time` = \
         `not-a-real-iso-timestamp`. Normalize parses start_time \
         first; any parse failure surfaces as `TimestampParseFailed` \
         with wire `anomaly-detect-stream-timestamp-parse-failed`.",
        "design-final.md §3.5.3 — RFC-3339 is the normative \
         interchange format for audit event timestamps. Any lenient \
         fallback here (e.g. accepting Unix seconds inline) would \
         open a stream-authoring ambiguity that spec'd conformance \
         explicitly closes.",
        vec![stream],
        "anomaly-detect-stream-timestamp-parse-failed",
    )
}

// ─── Canonical-event helpers ────────────────────────────────────────────────

/// Build a `CanonicalizedEvent`-shaped JSON object for a
/// `delete`-verb event. Thin wrapper around
/// [`canonical_event_named`] — the default integration is `"pod"`
/// (matching the `kubernetes` namespace in the MINIMUM library's
/// hypothetical deployments), the resource_kind defaults to whatever
/// the caller names explicitly.
fn canonical_delete_event(
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

/// Build a `CanonicalizedEvent`-shaped JSON object with full
/// specification of every field. `offset_seconds` is added to
/// [`DETECT_INITIAL_TIME_UNIX`] so the event lands inside the
/// detector's past-dated floor.
fn canonical_event_named(
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
        "timestamp": DETECT_INITIAL_TIME_UNIX + offset_seconds,
        "mandate_id": mandate_id,
        "tier": tier,
        "integration": integration,
        "verb": verb,
        "resource_kind": resource_kind,
        "resource_ref": resource_ref,
        "outcome": "executed",
    })
}

/// Wrap a vector of canonical-event JSON objects in an
/// `AuditStreamInput::Literal` shape.
fn literal_stream(events: Vec<Value>) -> Value {
    json!({ "literal": { "events": events } })
}

/// Build a `TemplateEvent`-shaped JSON object for pattern-
/// description streams.
fn template_event(mandate_id: &str, tier: u8, resource_kind: &str, verb: &str) -> Value {
    json!({
        "mandate_id": mandate_id,
        "tier": tier,
        "integration": "k8s",
        "verb": verb,
        "resource_kind": resource_kind,
        "outcome": "executed",
    })
}

// ─── Expected-fire helpers ──────────────────────────────────────────────────

/// MatchScope-shaped JSON with only `mandate_id` bound — the
/// default projection for `VerbResourceMandate { verb:
/// AnyDestructive | Family(_), resource_kind: None, .. }`,
/// `IamAttachFamily` with unbound integration, `ProtectedBranches`
/// with unbound integration, `CrossTierSequence`, and
/// `SilenceThenBurst`.
fn match_scope_mandate(mandate_id: &str) -> Value {
    json!({ "mandate_id": mandate_id })
}

/// Build an `AnomalyFire`-shaped JSON object. `library_version` is
/// always 1 (the `sign_minimum_library_with_version(1)` envelope).
fn expected_fire(
    pattern_id: &str,
    severity: &str,
    firing_rule: &str,
    match_scope: Value,
) -> Value {
    json!({
        "pattern_id": pattern_id,
        "library_version": 1,
        "severity": severity,
        "firing_rule": firing_rule,
        "match_scope": match_scope,
    })
}

// ─── Vector-shape builders ──────────────────────────────────────────────────

/// Assemble a `vector_suite: "anomaly-detect"` vector whose
/// expected outcome is `reject` with `reject_code =
/// "anomaly-detected"` and a non-empty `expected.output.fires`
/// array. The library envelope is
/// [`sign_minimum_library_with_version`] at version 1 with a
/// fresh ledger.
fn build_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    streams: Vec<Value>,
    fires: Vec<Value>,
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
            "initial_time": DETECT_INITIAL_TIME,
            "streams": streams,
        },
        "expected": {
            "outcome": "reject",
            "reject_code": ANOMALY_DETECTED_WIRE,
            "output": { "fires": fires },
        },
        "rationale": rationale,
        "redteam_refs": ["PHASE-C4-LIVE"],
        "severity_if_failed": severity,
    })
}

/// Assemble an `accept`-shape vector. No reject_code, no output
/// block — the executor defaults `ExpectedOutput::fires` to empty.
fn build_accept_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    streams: Vec<Value>,
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
            "initial_time": DETECT_INITIAL_TIME,
            "streams": streams,
        },
        "expected": { "outcome": "accept" },
        "rationale": rationale,
        "redteam_refs": ["PHASE-C4-LIVE"],
        "severity_if_failed": "medium",
    })
}

/// Assemble a stream-level reject vector (adet-112..114). The
/// `reject_code` is one of the `anomaly-detect-stream-*` surfaces.
fn build_reject_stream_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    streams: Vec<Value>,
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
            "initial_time": DETECT_INITIAL_TIME,
            "streams": streams,
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

/// Trust-anchor array for every detect vector — fixture kid, fixture
/// pubkey, Ed25519. The suite executor stamps the role as
/// `AnchorRole::AnomalyLibrarySigner` via `build_anchor_set`.
fn anchor_def() -> Value {
    json!([{
        "kid": aft::FIXTURE_ANOMALY_KID,
        "alg": "ed25519",
        "pk_hex": hex::encode(aft::fixture_anomaly_verifying_key_bytes()),
    }])
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------- build_all shape + IDs ------------------------------------

    #[test]
    fn build_all_returns_fifteen_unique_ids() {
        let v = build_all();
        assert_eq!(v.len(), 15, "must emit exactly 15 vectors");

        let ids: Vec<_> = v.iter().map(|x| x["id"].as_str().unwrap()).collect();
        for id in &ids {
            assert!(
                id.starts_with("adet-1"),
                "id {id} does not use the adet-1XX namespace"
            );
        }
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 15, "ids must be unique across build_all");
    }

    #[test]
    fn build_all_produces_expected_outcomes() {
        let v = build_all();
        let expected: [(&str, &str, Option<&str>); 15] = [
            ("adet-100", "reject", Some("anomaly-detected")),
            ("adet-101", "reject", Some("anomaly-detected")),
            ("adet-102", "reject", Some("anomaly-detected")),
            ("adet-103", "reject", Some("anomaly-detected")),
            ("adet-104", "reject", Some("anomaly-detected")),
            ("adet-105", "reject", Some("anomaly-detected")),
            ("adet-106", "reject", Some("anomaly-detected")),
            ("adet-107", "reject", Some("anomaly-detected")),
            ("adet-108", "reject", Some("anomaly-detected")),
            ("adet-109", "accept", None),
            ("adet-110", "accept", None),
            ("adet-111", "reject", Some("anomaly-detected")),
            ("adet-112", "reject", Some("anomaly-detect-stream-clock-regression")),
            (
                "adet-113",
                "reject",
                Some("anomaly-detect-stream-pattern-description-count-zero"),
            ),
            (
                "adet-114",
                "reject",
                Some("anomaly-detect-stream-timestamp-parse-failed"),
            ),
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
    fn determinism_two_runs_produce_identical_bytes() {
        let a = serde_json::to_string(&build_all()).unwrap();
        let b = serde_json::to_string(&build_all()).unwrap();
        assert_eq!(a, b, "build_all must be byte-deterministic");
    }

    // ---------------- fire-count pins ------------------------------------------
    //
    // Each vector's `output.fires` is pinned by length here; the
    // per-fire MatchScope shape is pinned below.  A silent drop of
    // one fire from a builder would fail this test before any
    // downstream harness observes the regression.

    #[test]
    fn fire_counts_match_design() {
        let v = build_all();
        let expected: [(&str, usize); 15] = [
            ("adet-100", 2),
            ("adet-101", 2),
            ("adet-102", 2),
            ("adet-103", 1),
            ("adet-104", 4),
            ("adet-105", 2),
            ("adet-106", 3),
            ("adet-107", 3),
            ("adet-108", 2),
            ("adet-109", 0),
            ("adet-110", 0),
            ("adet-111", 4),
            ("adet-112", 0),
            ("adet-113", 0),
            ("adet-114", 0),
        ];
        for (i, (id, expected_count)) in expected.iter().enumerate() {
            let got = v[i]["expected"].get("output").and_then(|o| {
                o.get("fires").and_then(|f| f.as_array()).map(Vec::len)
            });
            let got_count = got.unwrap_or(0);
            assert_eq!(
                got_count, *expected_count,
                "vector {id} fire-count mismatch (got {got_count}, expected {expected_count})"
            );
        }
    }

    // ---------------- per-fire property pins -----------------------------------

    #[test]
    fn adet_102_binds_verb_and_resource_kind_in_match_scope() {
        let v = build_adet_102_vault_rotate_storm();
        let fires = v["expected"]["output"]["fires"].as_array().unwrap();
        let vault = fires
            .iter()
            .find(|f| f["pattern_id"] == "vault-rotate-storm")
            .expect("vault-rotate-storm fire present");
        let scope = &vault["match_scope"];
        assert_eq!(scope["mandate_id"].as_str().unwrap(), "m-a102");
        assert_eq!(scope["verb"].as_str().unwrap(), "rotate");
        assert_eq!(scope["resource_kind"].as_str().unwrap(), "vault-secret");
    }

    #[test]
    fn adet_104_binds_verb_on_fanout() {
        let v = build_adet_104_fanout_and_slow_burn();
        let fires = v["expected"]["output"]["fires"].as_array().unwrap();
        let fanout = fires
            .iter()
            .find(|f| f["pattern_id"] == "fanout-distinct-resources")
            .expect("fanout-distinct-resources fire present");
        let scope = &fanout["match_scope"];
        assert_eq!(scope["mandate_id"].as_str().unwrap(), "m-a104");
        assert_eq!(
            scope["verb"].as_str().unwrap(),
            "delete",
            "VerbFanout Exact(delete) MUST pin verb in MatchScope"
        );
        // resource_kind must NOT appear — VerbFanout does not bind
        // resource_kind in the projection.
        assert!(
            scope.get("resource_kind").is_none(),
            "VerbFanout projection does NOT bind resource_kind"
        );
    }

    #[test]
    fn adet_111_binds_tier_on_machine_pace() {
        let v = build_adet_111_machine_pace_and_silence_burst();
        let fires = v["expected"]["output"]["fires"].as_array().unwrap();
        let mp = fires
            .iter()
            .find(|f| f["pattern_id"] == "machine-pace")
            .expect("machine-pace fire present");
        let scope = &mp["match_scope"];
        assert_eq!(scope["mandate_id"].as_str().unwrap(), "m-a111");
        assert_eq!(
            scope["tier"].as_u64().unwrap(),
            1,
            "MandatePace projection MUST pin tier"
        );
    }

    #[test]
    fn non_tier_patterns_omit_tier_and_verb() {
        // Pin that patterns with family predicates (delete-storm
        // AnyDestructive, iam-attach-policy-storm IamAttachFamily,
        // git-force-push-storm ProtectedBranches) do NOT leak
        // tier/verb into their MatchScope — a refactor that
        // accidentally projected them would show up here.
        let v = build_adet_100_delete_storm_basic();
        let fires = v["expected"]["output"]["fires"].as_array().unwrap();
        for fire in fires {
            let scope = &fire["match_scope"];
            assert!(
                scope.get("tier").is_none(),
                "family/wildcard predicate fire MUST omit tier: {fire}"
            );
            assert!(
                scope.get("verb").is_none(),
                "family/wildcard predicate fire MUST omit verb: {fire}"
            );
        }
    }

    // ---------------- envelope / stream pins -----------------------------------

    #[test]
    fn every_fire_vector_uses_library_version_one() {
        // All expected fires carry library_version=1 because the
        // envelope is sign_minimum_library_with_version(1). A
        // mismatch between the envelope and the expected library_
        // version would make the executor's equality check fail
        // catastrophically — pin it here before any vector runs.
        let v = build_all();
        for vec_ in &v {
            if let Some(fires) = vec_["expected"].get("output").and_then(|o| o["fires"].as_array())
            {
                for fire in fires {
                    assert_eq!(
                        fire["library_version"].as_u64().unwrap(),
                        1,
                        "vector {} fire library_version must be 1: {fire}",
                        vec_["id"]
                    );
                }
            }
        }
    }

    #[test]
    fn adet_108_has_two_streams() {
        let v = build_adet_108_fire_once_dedup_across_streams();
        let streams = v["input"]["streams"].as_array().unwrap();
        assert_eq!(
            streams.len(),
            2,
            "adet-108 MUST carry two streams to exercise cross-stream dedup"
        );
    }

    #[test]
    fn adet_109_stream_has_zero_events() {
        let v = build_adet_109_empty_stream();
        let streams = v["input"]["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 1);
        let events = streams[0]["literal"]["events"].as_array().unwrap();
        assert!(
            events.is_empty(),
            "adet-109 empty-stream vector must have zero events"
        );
    }

    #[test]
    fn adet_112_second_timestamp_regresses() {
        let v = build_adet_112_clock_regression();
        let events = v["input"]["streams"][0]["literal"]["events"]
            .as_array()
            .unwrap();
        assert_eq!(events.len(), 2);
        let t0 = events[0]["timestamp"].as_i64().unwrap();
        let t1 = events[1]["timestamp"].as_i64().unwrap();
        assert!(
            t1 < t0,
            "adet-112 MUST carry a regressing timestamp: got t0={t0} t1={t1}"
        );
    }

    #[test]
    fn adet_113_pattern_description_carries_count_zero() {
        let v = build_adet_113_pattern_description_count_zero();
        let pd = &v["input"]["streams"][0]["pattern_description"];
        assert_eq!(
            pd["count"].as_u64().unwrap(),
            0,
            "adet-113 MUST carry count=0"
        );
    }

    #[test]
    fn adet_114_pattern_description_carries_bad_iso() {
        let v = build_adet_114_timestamp_parse_failed();
        let pd = &v["input"]["streams"][0]["pattern_description"];
        let st = pd["start_time"].as_str().unwrap();
        assert!(
            st.starts_with("not-"),
            "adet-114 start_time MUST be non-RFC-3339: got {st}"
        );
    }

    #[test]
    fn adet_106_events_are_30s_spaced() {
        let v = build_adet_106_delete_walk_under_slow_burn();
        let events = v["input"]["streams"][0]["literal"]["events"]
            .as_array()
            .unwrap();
        assert_eq!(events.len(), 20, "walk-under demo needs 20 events");
        // Pin the spacing — if a refactor silently dropped to 20s
        // spacing, the short-window primary WOULD start firing and
        // this vector's meaning would change.
        let t0 = events[0]["timestamp"].as_i64().unwrap();
        let t1 = events[1]["timestamp"].as_i64().unwrap();
        assert_eq!(t1 - t0, 30, "adet-106 spacing MUST remain 30 s");
    }

    // ---------------- envelope determinism -------------------------------------

    #[test]
    fn every_vector_uses_fixture_anomaly_kid() {
        let v = build_all();
        for vec_ in &v {
            let anchors = vec_["input"]["trust_anchor_keys_anomaly_library"]
                .as_array()
                .unwrap();
            assert_eq!(anchors.len(), 1);
            assert_eq!(
                anchors[0]["kid"].as_str().unwrap(),
                aft::FIXTURE_ANOMALY_KID,
                "vector {} must anchor on the fixture kid",
                vec_["id"]
            );
            assert_eq!(anchors[0]["alg"].as_str().unwrap(), "ed25519");
        }
    }

    #[test]
    fn cose_hex_identical_across_vectors() {
        // Every vector uses the SAME library envelope (sign_minimum_
        // library_with_version(1)). Pin byte-identity so a refactor
        // that accidentally re-signed per-vector (with a fresh random
        // nonce from some non-deterministic COSE codepath, say) shows
        // up as loud hex divergence rather than a silent N-fold
        // signing-cost regression.
        let v = build_all();
        let first = v[0]["input"]["cose_sign1_bytes_anomaly_library"]
            .as_str()
            .unwrap()
            .to_owned();
        for vec_ in &v[1..] {
            let got = vec_["input"]["cose_sign1_bytes_anomaly_library"]
                .as_str()
                .unwrap();
            assert_eq!(
                got, first,
                "vector {} MUST share envelope bytes with adet-100",
                vec_["id"]
            );
        }
    }

    #[test]
    fn detect_initial_time_unix_matches_iso_literal() {
        use time::{format_description::well_known::Rfc3339, OffsetDateTime};
        let parsed = OffsetDateTime::parse(DETECT_INITIAL_TIME, &Rfc3339)
            .unwrap()
            .unix_timestamp();
        assert_eq!(
            parsed, DETECT_INITIAL_TIME_UNIX,
            "DETECT_INITIAL_TIME_UNIX MUST match the ISO literal"
        );
    }
}
