//! Group 5: accept-path negative controls (arep-114..arep-116).
//!
//! These three vectors pin that the detector distinguishes silence.  A
//! validator that always rejected would pass every fire-expected
//! vector but fail this triplet; the below-threshold accept is the
//! load-bearing negative control the suite commits to.

use serde_json::Value;

use super::helpers::{build_accept_vector, canonical_event_named, literal_stream, tenant_stream};

pub(super) fn build_arep_114_two_tenants_empty() -> Value {
    build_accept_vector(
        "arep-114",
        "audit-replay-two-tenants-empty",
        "Two tenants both register with empty literal streams. Zero \
         events → zero records. Negative control proving the orchestrator \
         accepts registered-but-silent tenants without emitting \
         phantom fires.",
        "design-final.md §11.2: an orchestrator with registered-but-idle \
         tenants produces zero AnomalyDetected records until events \
         actually arrive.",
        vec![
            tenant_stream("t-a", literal_stream(vec![])),
            tenant_stream("t-b", literal_stream(vec![])),
        ],
    )
}

pub(super) fn build_arep_115_two_tenants_below_threshold() -> Value {
    let a_stream = literal_stream(vec![
        canonical_event_named("ea-0", "m-a115", 0, 0, "k8s", "get", "pod", "pod/z"),
        canonical_event_named("ea-1", "m-a115", 1, 0, "k8s", "get", "pod", "pod/z"),
    ]);
    let b_stream = literal_stream(vec![
        canonical_event_named("eb-0", "m-b115", 0, 0, "k8s", "get", "pod", "pod/z"),
        canonical_event_named("eb-1", "m-b115", 1, 0, "k8s", "get", "pod", "pod/z"),
    ]);

    build_accept_vector(
        "arep-115",
        "audit-replay-two-tenants-below-threshold",
        "Two tenants each streaming two benign read events — well below \
         every MINIMUM-library firing threshold. Zero records; negative \
         control proving the detector actually DISCRIMINATES below \
         threshold vs above.",
        "design-final.md §3.5.4 MINIMUM library thresholds: a validator \
         that always rejected would pass every fire-expected vector but \
         fail this; the below-threshold accept is the load-bearing \
         negative control.",
        vec![
            tenant_stream("t-a", a_stream),
            tenant_stream("t-b", b_stream),
        ],
    )
}

pub(super) fn build_arep_116_single_tenant_empty() -> Value {
    build_accept_vector(
        "arep-116",
        "audit-replay-single-tenant-empty",
        "Single tenant with one empty literal stream — the simplest \
         degenerate accept case. Zero events, zero records, zero tenants \
         lazily-registered until the first event arrives (none do).",
        "design-final.md §11.2: a tenant_streams list with empty streams \
         MUST NOT emit records. This vector anchors the lower bound of \
         the accept path.",
        vec![tenant_stream("t-a", literal_stream(vec![]))],
    )
}
