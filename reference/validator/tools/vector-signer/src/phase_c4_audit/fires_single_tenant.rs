//! Group 1-2: single-tenant baseline + shared-mandate isolation
//! (arep-100..arep-103).
//!
//! These four vectors hold the load-bearing per-tenant attribution
//! invariants at 1-, 2-, and mandate-colliding-2-tenant configurations.
//! They are grouped together because every builder here consumes only
//! the "literal delete stream" + `scope_mandate` helpers — no verb /
//! tier projections, no rotation, no stream errors.

use serde_json::Value;

use super::helpers::{
    build_fire_vector, canonical_delete_event, canonical_event_named, expected_record,
    literal_stream, scope_mandate, tenant_stream,
};

pub(super) fn build_arep_100_single_tenant_baseline() -> Value {
    let stream = literal_stream(vec![
        canonical_delete_event("e-0", "m-a100", 0, 2, "pod", "pod/foo"),
        canonical_delete_event("e-1", "m-a100", 1, 2, "pod", "pod/foo"),
        canonical_delete_event("e-2", "m-a100", 2, 2, "pod", "pod/foo"),
        canonical_delete_event("e-3", "m-a100", 3, 2, "pod", "pod/foo"),
        canonical_delete_event("e-4", "m-a100", 4, 2, "pod", "pod/foo"),
    ]);

    build_fire_vector(
        "arep-100",
        "audit-replay-single-tenant-baseline",
        "Single tenant `t-a` receives five delete events on pod/foo at \
         tier 2. Fires delete-storm (FirstMatch/Count≥5 in 60s) and \
         co-fires git-force-push-storm (ProtectedBranches wildcard). \
         Baseline proving the orchestrator emits identical fires to a \
         single-tenant DetectorState when only one tenant is registered.",
        "design-final.md §3.5.3 MINIMUM + orchestrator dispatch \
         transparency: registering one tenant through AuditOrchestrator \
         MUST produce the same firing multiset a bare DetectorState \
         produces on the same stream (per §11.2 attribution).",
        vec![tenant_stream("t-a", stream)],
        vec![
            expected_record(
                "t-a",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-a100"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a100"),
            ),
        ],
        "high",
    )
}

pub(super) fn build_arep_101_two_tenants_only_a_fires() -> Value {
    let a_stream = literal_stream(vec![
        canonical_delete_event("ea-0", "m-a101", 0, 2, "pod", "pod/x"),
        canonical_delete_event("ea-1", "m-a101", 1, 2, "pod", "pod/x"),
        canonical_delete_event("ea-2", "m-a101", 2, 2, "pod", "pod/x"),
        canonical_delete_event("ea-3", "m-a101", 3, 2, "pod", "pod/x"),
        canonical_delete_event("ea-4", "m-a101", 4, 2, "pod", "pod/x"),
    ]);
    let b_stream = literal_stream(vec![
        canonical_event_named("eb-0", "m-b101", 0, 0, "k8s", "get", "pod", "pod/z"),
        canonical_event_named("eb-1", "m-b101", 1, 0, "k8s", "get", "pod", "pod/z"),
    ]);

    build_fire_vector(
        "arep-101",
        "audit-replay-two-tenants-only-a-fires",
        "Tenant A streams five delete events (delete-storm + gfp \
         co-fire); tenant B streams two benign reads below every \
         threshold. Records MUST attribute both fires to tenant-A; \
         tenant-B emits zero records despite being registered.",
        "design-final.md §11.2 multi-tenant attribution + \
         AuditOrchestrator isolation invariant: a fire under tenant-A's \
         `DetectorState` never leaks into tenant-B's attribution. This \
         is the single most load-bearing property of the orchestrator.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
        ],
        vec![
            expected_record(
                "t-a",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-a101"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a101"),
            ),
        ],
        "high",
    )
}

pub(super) fn build_arep_102_two_tenants_both_fire() -> Value {
    let a_stream = literal_stream(vec![
        canonical_delete_event("ea-0", "m-a102", 0, 2, "pod", "pod/x"),
        canonical_delete_event("ea-1", "m-a102", 1, 2, "pod", "pod/x"),
        canonical_delete_event("ea-2", "m-a102", 2, 2, "pod", "pod/x"),
        canonical_delete_event("ea-3", "m-a102", 3, 2, "pod", "pod/x"),
        canonical_delete_event("ea-4", "m-a102", 4, 2, "pod", "pod/x"),
    ]);
    let b_stream = literal_stream(vec![
        canonical_delete_event("eb-0", "m-b102", 0, 2, "pod", "pod/y"),
        canonical_delete_event("eb-1", "m-b102", 1, 2, "pod", "pod/y"),
        canonical_delete_event("eb-2", "m-b102", 2, 2, "pod", "pod/y"),
        canonical_delete_event("eb-3", "m-b102", 3, 2, "pod", "pod/y"),
        canonical_delete_event("eb-4", "m-b102", 4, 2, "pod", "pod/y"),
    ]);

    build_fire_vector(
        "arep-102",
        "audit-replay-two-tenants-both-fire",
        "Tenants A and B both stream five destructive delete events \
         on distinct mandates. Each tenant fires delete-storm + gfp \
         independently. Observed record set = 4 (2 per tenant), \
         attribution MUST distinguish t-a from t-b.",
        "design-final.md §11.2: two concurrently-firing tenants produce \
         independent AnomalyDetectedRecord streams keyed by tenant_id. \
         A bug that merged tenant state would short-circuit the second \
         storm under the first's dedup window.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
        ],
        vec![
            expected_record(
                "t-a",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-a102"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-a102"),
            ),
            expected_record(
                "t-b",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-b102"),
            ),
            expected_record(
                "t-b",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-b102"),
            ),
        ],
        "high",
    )
}

pub(super) fn build_arep_103_shared_mandate_id_isolated() -> Value {
    // Both tenants intentionally use the same mandate_id string
    // "m-shared" — a classic attacker-probing case: does the
    // orchestrator conflate per-mandate buckets across tenants?
    let a_stream = literal_stream(vec![
        canonical_delete_event("ea-0", "m-shared", 0, 2, "pod", "pod/x"),
        canonical_delete_event("ea-1", "m-shared", 1, 2, "pod", "pod/x"),
        canonical_delete_event("ea-2", "m-shared", 2, 2, "pod", "pod/x"),
        canonical_delete_event("ea-3", "m-shared", 3, 2, "pod", "pod/x"),
        canonical_delete_event("ea-4", "m-shared", 4, 2, "pod", "pod/x"),
    ]);
    let b_stream = literal_stream(vec![
        canonical_delete_event("eb-0", "m-shared", 0, 2, "pod", "pod/y"),
        canonical_delete_event("eb-1", "m-shared", 1, 2, "pod", "pod/y"),
        canonical_delete_event("eb-2", "m-shared", 2, 2, "pod", "pod/y"),
        canonical_delete_event("eb-3", "m-shared", 3, 2, "pod", "pod/y"),
        canonical_delete_event("eb-4", "m-shared", 4, 2, "pod", "pod/y"),
    ]);

    build_fire_vector(
        "arep-103",
        "audit-replay-shared-mandate-id-isolated",
        "Two tenants whose mandate_ids happen to be identical \
         (`m-shared`). Each fires delete-storm + gfp independently. \
         Attribution MUST keep records separate: t-a's fires carry \
         tenant_id=t-a, t-b's fires carry tenant_id=t-b. This pins \
         that bucket keys are `(tenant_id, mandate_id, …)` tuples, \
         not raw mandate_id across the global map.",
        "design-final.md §11.2 + orchestrator docblock: tenant_id is \
         the FIRST component of every isolation boundary; a malicious \
         operator assigning a shared mandate_id across tenants cannot \
         influence another tenant's firing thresholds.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
        ],
        vec![
            expected_record(
                "t-a",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-shared"),
            ),
            expected_record(
                "t-a",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-shared"),
            ),
            expected_record(
                "t-b",
                "delete-storm",
                "high",
                "first-match",
                scope_mandate("m-shared"),
            ),
            expected_record(
                "t-b",
                "git-force-push-storm",
                "high",
                "first-match",
                scope_mandate("m-shared"),
            ),
        ],
        "critical",
    )
}
