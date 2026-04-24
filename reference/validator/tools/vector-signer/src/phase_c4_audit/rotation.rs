//! Group 3: library rotation (arep-108..arep-110).
//!
//! These three vectors exercise `rotate_library`:
//! - arep-108: rotation between two streams, same tenant, verifies the
//!   state-clear invariant lets a pattern re-fire post-rotation.
//! - arep-109: rotation after the only stream, verifies rotation is a
//!   no-op on the observed fire multiset when no post-rotation events
//!   follow.
//! - arep-110: rotation mid-run with distinct tenants pre and post,
//!   verifies cross-rotation attribution stays loyal to `tenant_id`.
//!
//! All three use [`attach_rotation`] to bolt on the v2 envelope after
//! the initial `build_fire_vector` call.

use serde_json::Value;

use super::helpers::{
    attach_rotation, build_fire_vector, canonical_delete_event, canonical_event_post_rotation,
    expected_record_v, literal_post_rotation_stream, literal_stream, scope_mandate, tenant_stream,
};

pub(super) fn build_arep_108_rotation_after_stream_zero() -> Value {
    // Stream 0: tenant-A fires delete-storm at AUDIT_INITIAL_TIME.
    // Rotation swaps the library; tenant-A's `last_fired_at` resets.
    // Stream 1: tenant-A's SECOND storm (post-rotation) at
    // ROTATE_INITIAL_TIME + offset fires AGAIN because the dedup
    // table was cleared.  Pre- and post-rotation records BOTH appear
    // in the observed multiset.
    let a_stream_pre = literal_stream(vec![
        canonical_delete_event("ea-pre-0", "m-a108", 0, 2, "pod", "pod/x"),
        canonical_delete_event("ea-pre-1", "m-a108", 1, 2, "pod", "pod/x"),
        canonical_delete_event("ea-pre-2", "m-a108", 2, 2, "pod", "pod/x"),
        canonical_delete_event("ea-pre-3", "m-a108", 3, 2, "pod", "pod/x"),
        canonical_delete_event("ea-pre-4", "m-a108", 4, 2, "pod", "pod/x"),
    ]);
    let a_stream_post = literal_post_rotation_stream(vec![
        canonical_event_post_rotation("ea-post-0", "m-a108", 0, 2, "k8s", "delete", "pod", "pod/x"),
        canonical_event_post_rotation("ea-post-1", "m-a108", 1, 2, "k8s", "delete", "pod", "pod/x"),
        canonical_event_post_rotation("ea-post-2", "m-a108", 2, 2, "k8s", "delete", "pod", "pod/x"),
        canonical_event_post_rotation("ea-post-3", "m-a108", 3, 2, "k8s", "delete", "pod", "pod/x"),
        canonical_event_post_rotation("ea-post-4", "m-a108", 4, 2, "k8s", "delete", "pod", "pod/x"),
    ]);

    // Both fires carry library_version — 1 pre, 2 post.
    let mut v = build_fire_vector(
        "arep-108",
        "audit-replay-rotation-after-stream-zero",
        "Library rotation between streams: tenant-A fires delete-storm \
         under library v1 (stream 0), then rotates to library v2 which \
         clears all tenant state, then tenant-A streams an identical \
         storm under v2 (stream 1). Observed records contain four \
         fires — TWO per library version (delete-storm + gfp×2), the \
         second delete-storm emitted because `last_fired_at` was \
         cleared by rotate_library. Pins the state-reset invariant.",
        "design-final.md §3.5.1 library rotation + orchestrator \
         duplicate-tolerance contract: rotate_library MUST clear every \
         tenant's last_fired_at so a pattern can fire anew under the \
         new library. Downstream consumers are required to be \
         duplicate-tolerant across rotation boundaries per the \
         orchestrator module-level docblock.",
        vec![
            tenant_stream("t-a", a_stream_pre),
            tenant_stream("t-a", a_stream_post),
        ],
        vec![
            // Pre-rotation under library v1
            expected_record_v(
                "t-a",
                "delete-storm",
                1,
                "high",
                "first-match",
                scope_mandate("m-a108"),
            ),
            expected_record_v(
                "t-a",
                "git-force-push-storm",
                1,
                "high",
                "first-match",
                scope_mandate("m-a108"),
            ),
            // Post-rotation under library v2
            expected_record_v(
                "t-a",
                "delete-storm",
                2,
                "high",
                "first-match",
                scope_mandate("m-a108"),
            ),
            expected_record_v(
                "t-a",
                "git-force-push-storm",
                2,
                "high",
                "first-match",
                scope_mandate("m-a108"),
            ),
        ],
        "high",
    );
    // Attach rotation descriptor after stream 0.
    attach_rotation(&mut v, 0);
    v
}

pub(super) fn build_arep_109_rotation_after_final() -> Value {
    // Only one stream (stream 0). Rotation lands AFTER stream 0 drains,
    // so no post-rotation streams exist — observed records are purely
    // from the pre-rotation library.  This pins that rotate_library
    // runs as a no-op on fire accumulation when no post-rotation
    // streams follow.
    let a_stream = literal_stream(vec![
        canonical_delete_event("ea-0", "m-a109", 0, 2, "pod", "pod/x"),
        canonical_delete_event("ea-1", "m-a109", 1, 2, "pod", "pod/x"),
        canonical_delete_event("ea-2", "m-a109", 2, 2, "pod", "pod/x"),
        canonical_delete_event("ea-3", "m-a109", 3, 2, "pod", "pod/x"),
        canonical_delete_event("ea-4", "m-a109", 4, 2, "pod", "pod/x"),
    ]);

    let mut v = build_fire_vector(
        "arep-109",
        "audit-replay-rotation-after-final-stream",
        "Library rotates after the final (only) stream drains. Observed \
         records are from the pre-rotation library only; the rotation \
         itself happens but produces no additional fires because no \
         streams follow. Pins that rotate_library is idempotent w.r.t. \
         the observed record multiset when no post-rotation events \
         arrive.",
        "design-final.md §3.5.1: rotation is a control-plane event; the \
         audit record stream flows through it without interleaving \
         phantom fires at the rotation boundary.",
        vec![tenant_stream("t-a", a_stream)],
        vec![
            expected_record_v(
                "t-a",
                "delete-storm",
                1,
                "high",
                "first-match",
                scope_mandate("m-a109"),
            ),
            expected_record_v(
                "t-a",
                "git-force-push-storm",
                1,
                "high",
                "first-match",
                scope_mandate("m-a109"),
            ),
        ],
        "medium",
    );
    attach_rotation(&mut v, 0);
    v
}

pub(super) fn build_arep_110_rotation_mid_run() -> Value {
    // Stream 0 (pre-rotation): tenant-A fires delete-storm under v1.
    // Stream 1 (post-rotation): tenant-B fires delete-storm under v2.
    // Tenant-A does NOT reappear post-rotation (state cleared + no
    // further events for A).
    let a_stream = literal_stream(vec![
        canonical_delete_event("ea-0", "m-a110", 0, 2, "pod", "pod/x"),
        canonical_delete_event("ea-1", "m-a110", 1, 2, "pod", "pod/x"),
        canonical_delete_event("ea-2", "m-a110", 2, 2, "pod", "pod/x"),
        canonical_delete_event("ea-3", "m-a110", 3, 2, "pod", "pod/x"),
        canonical_delete_event("ea-4", "m-a110", 4, 2, "pod", "pod/x"),
    ]);
    let b_stream = literal_post_rotation_stream(vec![
        canonical_event_post_rotation("eb-0", "m-b110", 0, 2, "k8s", "delete", "pod", "pod/y"),
        canonical_event_post_rotation("eb-1", "m-b110", 1, 2, "k8s", "delete", "pod", "pod/y"),
        canonical_event_post_rotation("eb-2", "m-b110", 2, 2, "k8s", "delete", "pod", "pod/y"),
        canonical_event_post_rotation("eb-3", "m-b110", 3, 2, "k8s", "delete", "pod", "pod/y"),
        canonical_event_post_rotation("eb-4", "m-b110", 4, 2, "k8s", "delete", "pod", "pod/y"),
    ]);

    let mut v = build_fire_vector(
        "arep-110",
        "audit-replay-rotation-mid-run-different-tenants",
        "Tenant-A fires delete-storm under library v1 (stream 0). \
         Rotation clears ALL tenant state (including A's newly-minted \
         DetectorState). Tenant-B fires delete-storm under library v2 \
         (stream 1). Observed records attribute to different tenants \
         across the rotation; t-a produces 2 records under v1, t-b \
         produces 2 records under v2.",
        "design-final.md §11.2 attribution + rotate_library clear-all \
         semantics: a tenant registered pre-rotation does not carry \
         into post-rotation automatically — each tenant re-registers \
         lazily on first post-rotation event. Cross-rotation \
         attribution stays loyal to the tenant_id that dispatched the \
         event, not to a stale map entry.",
        vec![tenant_stream("t-a", a_stream), tenant_stream("t-b", b_stream)],
        vec![
            expected_record_v(
                "t-a",
                "delete-storm",
                1,
                "high",
                "first-match",
                scope_mandate("m-a110"),
            ),
            expected_record_v(
                "t-a",
                "git-force-push-storm",
                1,
                "high",
                "first-match",
                scope_mandate("m-a110"),
            ),
            expected_record_v(
                "t-b",
                "delete-storm",
                2,
                "high",
                "first-match",
                scope_mandate("m-b110"),
            ),
            expected_record_v(
                "t-b",
                "git-force-push-storm",
                2,
                "high",
                "first-match",
                scope_mandate("m-b110"),
            ),
        ],
        "high",
    );
    attach_rotation(&mut v, 0);
    v
}
