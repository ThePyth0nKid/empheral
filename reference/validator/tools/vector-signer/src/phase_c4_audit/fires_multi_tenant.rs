//! Group 2 cont'd: multi-tenant scope-projection + cumulative fires
//! (arep-104..arep-107).
//!
//! These four vectors exercise the MatchScope projection contract
//! (`VerbResourceMandate`, `VerbFanout::Exact`, `MandatePace`) and the
//! CumulativeOverBaseline firing rule across 2-3 tenants.  Split from
//! the simpler `fires_single_tenant` group because these builders pull
//! in the full scope-projection helper set (verb / tier / verb_kind)
//! and dominate the line count of the former combined file.

use serde_json::Value;

use super::helpers::{
    build_fire_vector, canonical_delete_event, canonical_event_named, expected_record,
    literal_stream, scope_mandate, scope_mandate_tier, scope_mandate_verb, scope_mandate_verb_kind,
    tenant_stream,
};

#[allow(clippy::too_many_lines)]
pub(super) fn build_arep_104_three_tenants_three_patterns() -> Value {
    // Tenant A: delete-storm
    let a_stream = literal_stream(vec![
        canonical_delete_event("ea-0", "m-a104", 0, 2, "pod", "pod/x"),
        canonical_delete_event("ea-1", "m-a104", 1, 2, "pod", "pod/x"),
        canonical_delete_event("ea-2", "m-a104", 2, 2, "pod", "pod/x"),
        canonical_delete_event("ea-3", "m-a104", 3, 2, "pod", "pod/x"),
        canonical_delete_event("ea-4", "m-a104", 4, 2, "pod", "pod/x"),
    ]);
    // Tenant B: iam-attach-policy-storm
    let b_stream = literal_stream(vec![
        canonical_event_named(
            "eb-0",
            "m-b104",
            0,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "eb-1",
            "m-b104",
            1,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "eb-2",
            "m-b104",
            2,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "eb-3",
            "m-b104",
            3,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "eb-4",
            "m-b104",
            4,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
    ]);
    // Tenant C: vault-rotate-storm (count >= 3)
    let c_stream = literal_stream(vec![
        canonical_event_named(
            "ec-0",
            "m-c104",
            0,
            2,
            "vault",
            "rotate",
            "vault-secret",
            "secret/s0",
        ),
        canonical_event_named(
            "ec-1",
            "m-c104",
            1,
            2,
            "vault",
            "rotate",
            "vault-secret",
            "secret/s0",
        ),
        canonical_event_named(
            "ec-2",
            "m-c104",
            2,
            2,
            "vault",
            "rotate",
            "vault-secret",
            "secret/s0",
        ),
    ]);

    build_fire_vector(
        "arep-104",
        "audit-replay-three-tenants-three-patterns",
        "Three tenants firing three distinct primaries: t-a delete-storm, \
         t-b iam-attach-policy-storm, t-c vault-rotate-storm. Every fire \
         co-fires git-force-push-storm (ProtectedBranches wildcard). \
         Pins that the orchestrator routes events by tenant_id without \
         loss when the tenant map holds 3+ entries.",
        "design-final.md §11.2: AuditOrchestrator's BTreeMap-backed \
         tenant table must scale to N tenants without cross-contamination. \
         A bucketing bug that collapsed the map to O(1) shared state \
         would reorder fires across tenant_ids in non-deterministic ways.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
            tenant_stream("t-c", c_stream),
        ],
        vec![
            expected_record(
                "t-a",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-a104"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a104"),
            ),
            expected_record(
                "t-b",
                "iam-attach-policy-storm",
                "high",
                "first-match",
                scope_mandate("m-b104"),
            ),
            expected_record(
                "t-b",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-b104"),
            ),
            expected_record(
                "t-c",
                "vault-rotate-storm",
                "high",
                "first-match",
                scope_mandate_verb_kind("m-c104", "rotate", "vault-secret"),
            ),
            expected_record(
                "t-c",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-c104"),
            ),
        ],
        "critical",
    )
}

#[allow(clippy::too_many_lines)]
pub(super) fn build_arep_105_iam_on_a_cross_tier_on_b() -> Value {
    // Tenant A: iam-attach-policy-storm
    let a_stream = literal_stream(vec![
        canonical_event_named(
            "ea-0",
            "m-a105",
            0,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "ea-1",
            "m-a105",
            1,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "ea-2",
            "m-a105",
            2,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "ea-3",
            "m-a105",
            3,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
        canonical_event_named(
            "ea-4",
            "m-a105",
            4,
            2,
            "aws",
            "attachrolepolicy",
            "iam-role",
            "role/r0",
        ),
    ]);
    // Tenant B: cross-tier-escalation (tier 0 → 2 → 3)
    let b_stream = literal_stream(vec![
        canonical_event_named("eb-0", "m-b105", 0, 0, "k8s", "get", "configmap", "cm/c0"),
        canonical_event_named("eb-1", "m-b105", 1, 2, "k8s", "get", "configmap", "cm/c0"),
        canonical_event_named("eb-2", "m-b105", 2, 3, "k8s", "get", "configmap", "cm/c0"),
    ]);

    build_fire_vector(
        "arep-105",
        "audit-replay-iam-storm-and-cross-tier-escalation",
        "Tenant A fires iam-attach-policy-storm (FirstMatch/Count≥5 in 60s on \
         IamAttachFamily scope). Tenant B fires cross-tier-escalation \
         (SequenceMatch tier-ladder 0→2→3 within 300s). Both co-fire \
         git-force-push-storm. Pins that two different firing-rule \
         families (FirstMatch/Count vs SequenceMatch) coexist in the \
         same orchestrator without cross-pollination.",
        "design-final.md §3.5.3 FirstMatch/Count + SequenceMatch under \
         multi-tenant dispatch: the orchestrator must preserve per-\
         tenant bucket iteration state so SequenceMatch's ordered \
         match under t-b is not confused by t-a's flat counter.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
        ],
        vec![
            expected_record(
                "t-a",
                "iam-attach-policy-storm",
                "high",
                "first-match",
                scope_mandate("m-a105"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a105"),
            ),
            expected_record(
                "t-b",
                "cross-tier-escalation",
                "critical",
                "sequence-match",
                scope_mandate("m-b105"),
            ),
            expected_record(
                "t-b",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-b105"),
            ),
        ],
        "critical",
    )
}

#[allow(clippy::too_many_lines)]
pub(super) fn build_arep_106_fanout_a_pace_b() -> Value {
    // Tenant A: VerbFanout — 10× delete across distinct pods on one
    // mandate at tier 0 (fanout DistinctCount≥10).  No ProtectedBranches
    // co-fire because the stream is at tier 0.
    let mut a_events = Vec::new();
    for i in 0..10 {
        a_events.push(canonical_delete_event(
            &format!("ea-{i}"),
            "m-a106",
            i,
            0,
            "pod",
            &format!("pod/n-{i}"),
        ));
    }
    let a_stream = literal_stream(a_events);

    // Tenant B: MandatePace — 50 events at 1s spacing fires
    // machine-pace + silence-then-burst + gfp co-fires (same shape as
    // adet-111 but with tier=1 instead of mixed).
    let mut b_events = Vec::new();
    for i in 0..50 {
        b_events.push(canonical_event_named(
            &format!("eb-{i}"),
            "m-b106",
            i,
            1,
            "k8s",
            "patch",
            "deployment",
            &format!("dep/d-{i}"),
        ));
    }
    let b_stream = literal_stream(b_events);

    build_fire_vector(
        "arep-106",
        "audit-replay-fanout-a-mandatepace-b",
        "Tenant A: 10× delete on distinct pods at tier 0 fires \
         fanout-distinct-resources (DistinctCount≥10) with verb projection \
         `{mandate_id, verb: delete}` and co-fires delete-storm + \
         gfp-storm + gfp-slow-burn (CumulativeOverBaseline trips at the \
         10-event mark). Tenant B: 50× patch at 1s spacing at tier 1 \
         fires machine-pace (tier projection `{mandate_id, tier: 1}`), \
         long-silence-before-burst, gfp-storm and gfp-slow-burn. Pins \
         that tier and verb projections survive orchestrator dispatch \
         with per-tenant MatchScope fidelity.",
        "design-final.md §11.2 match_scope projection contract: scope \
         predicates that bind `verb` or `tier` must surface those \
         fields on the emitted AnomalyFire. Orchestrator wrapping does \
         not re-project — it forwards the inner fire verbatim.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
        ],
        vec![
            // Tenant A — fanout DistinctCount≥10, delete-storm at 10≥5,
            // gfp-storm, gfp-slow-burn (cumulative threshold met at 10).
            expected_record(
                "t-a",
                "fanout-distinct-resources",
                "high",
                "first-match",
                scope_mandate_verb("m-a106", "delete"),
            ),
            expected_record(
                "t-a",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-a106"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a106"),
            ),
            expected_record(
                "t-a",
                "git-force-push-slow-burn",
                "medium",
                "cumulative-over-baseline",
                scope_mandate("m-a106"),
            ),
            // Tenant B — machine-pace, long-silence-before-burst,
            // gfp-storm, gfp-slow-burn.
            expected_record(
                "t-b",
                "machine-pace",
                "low",
                "cumulative-over-baseline",
                scope_mandate_tier("m-b106", 1),
            ),
            expected_record(
                "t-b",
                "long-silence-before-burst",
                "medium",
                "sequence-match",
                scope_mandate("m-b106"),
            ),
            expected_record(
                "t-b",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-b106"),
            ),
            expected_record(
                "t-b",
                "git-force-push-slow-burn",
                "medium",
                "cumulative-over-baseline",
                scope_mandate("m-b106"),
            ),
        ],
        "high",
    )
}

pub(super) fn build_arep_107_slow_burn_cumulative() -> Value {
    // Tenant A: 20× delete at 30s spacing over 10 minutes — walks
    // under the storm's 60s window but crosses slow-burn's cumulative
    // threshold.  Mirrors adet-106 shape at tenant-A.
    let mut a_events = Vec::new();
    for i in 0..20 {
        a_events.push(canonical_delete_event(
            &format!("ea-{i}"),
            "m-a107",
            i * 30,
            0,
            "pod",
            "pod/x",
        ));
    }
    let a_stream = literal_stream(a_events);
    // Tenant B: 2× read — below every threshold.
    let b_stream = literal_stream(vec![
        canonical_event_named("eb-0", "m-b107", 0, 0, "k8s", "get", "pod", "pod/z"),
        canonical_event_named("eb-1", "m-b107", 1, 0, "k8s", "get", "pod", "pod/z"),
    ]);

    build_fire_vector(
        "arep-107",
        "audit-replay-slow-burn-tenant-a-silent-b",
        "Tenant A: 20× delete at 30s spacing (walks under delete-storm's \
         60s window). Fires delete-slow-burn (CumulativeOverBaseline) \
         and co-fires gfp-storm×2 (ProtectedBranches wildcard — the 300s \
         dedup window lets the storm re-fire across the 570s run) plus \
         gfp-slow-burn. Tenant B: 2× reads, well below every threshold \
         — zero records. Pins that cumulative-over-baseline evaluators \
         respect per-tenant counter isolation.",
        "design-final.md §3.5.3 CumulativeOverBaseline + §11.2 \
         multi-tenant: a slow-burn counter on tenant-A MUST NOT leak \
         into tenant-B's baseline; a leak would either inflate B's \
         counter toward threshold or suppress A's via a shared budget.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
        ],
        vec![
            expected_record(
                "t-a",
                "delete-slow-burn",
                "medium",
                "cumulative-over-baseline",
                scope_mandate("m-a107"),
            ),
            expected_record(
                "t-a",
                "git-force-push-slow-burn",
                "medium",
                "cumulative-over-baseline",
                scope_mandate("m-a107"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a107"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a107"),
            ),
        ],
        "high",
    )
}
