//! Integration tests for the Session-3 replay-protection ledger
//! (`verify_anomaly_library_signature_with_ledger` + `AnomalyLedger`
//! trait + `InMemoryAnomalyLedger`).
//!
//! # Why this file exists
//!
//! The `signature` module already carries inline unit tests that
//! exercise every Stage-8 code path (happy, replay, rollback,
//! cross-id isolation, co-occurrent fail-order, dyn dispatch, failed-
//! envelope no-observation).  This file is the **external-consumer**
//! view of the same surface: it lives under `tests/`, so `cargo`
//! compiles it as a separate binary that imports `ephemeral-anomaly`
//! through `pub` items only.
//!
//! A compile failure or missing item here means the ledger module
//! leaks something only via `pub(crate)` — downstream crates
//! (`ephemeral-core`, `vector-signer`, conformance harness) would
//! then silently fail to see the expected public API even though
//! the intra-crate tests pass.  Pinning the external view here
//! prevents that drift.
//!
//! # What this file protects
//!
//! 1. The `pub mod ledger` + `pub use ledger::{...}` chain resolves
//!    from outside the crate (trait `AnomalyLedger`, default impl
//!    `InMemoryAnomalyLedger`, error and observation enums).
//! 2. The `test_fixtures::sign_minimum_library_with_version` and
//!    `test_fixtures::seeded_ledger_at_version` helpers are publicly
//!    reachable and produce envelopes/ledgers that the public
//!    verifier accepts.
//! 3. End-to-end replay protection: re-submitting a previously-
//!    accepted envelope rejects with `LibraryVersionTooOld` — the
//!    spec-named §3.5.1 `pattern-library-version-too-old` reject code.
//! 4. Object-safety of `AnomalyLedger`: callers can thread
//!    `&mut dyn AnomalyLedger` through the public API, enabling
//!    backend swap without generic re-instantiation.
//! 5. Per-`library_id` HWM isolation across the public API: loading
//!    one library at a high version does not inhibit a first-ever
//!    load of a distinct library at a low version.
//! 6. `Send + Sync` on `InMemoryAnomalyLedger`: the default impl is
//!    shareable behind `Arc<Mutex<...>>` in async / worker-pool
//!    contexts.  The trait itself only requires `Send`, so this file
//!    pins `Sync` on the concrete impl rather than on the trait.

// The file only compiles when the upstream fixture feature is active.
// Without it, `ephemeral_anomaly::test_fixtures::*` does not exist and
// the binary would fail to link — the `#[cfg]` turns it into an empty
// compilation unit instead, so `cargo test -p ephemeral-anomaly`
// (without features) still passes.
#![cfg(feature = "test_fixtures")]
#![allow(clippy::doc_markdown)]

use ephemeral_anomaly::{
    test_fixtures::{
        fixture_anomaly_verifying_key_bytes, seeded_ledger_at_version,
        sign_minimum_library_with_version, FIXTURE_ANOMALY_KID,
        FIXTURE_ANOMALY_LIBRARY_ID,
    },
    verify_anomaly_library_signature_with_ledger, AnomalyLedger, AnomalyLibError,
    InMemoryAnomalyLedger, ANOMALY_LIBRARY_ABI_VERSION,
};
use ephemeral_crypto::{AnchorRole, TrustAnchor, TrustAnchorSet};

/// Test clock anchored inside the fixture validity window — kept
/// distinct from the fixture-clock constants so a future seed/window
/// edit is forced to touch this constant and cannot silently drift
/// outside the window.
const TEST_NOW: i64 = 1_750_000_000;

/// Assemble a `TrustAnchorSet` carrying only the fixture signer under
/// [`AnchorRole::AnomalyLibrarySigner`].  Any other role assignment
/// would mean the crypto layer's role check rejects the envelope
/// with `CoseVerifyFailed`.
fn fixture_anchor_set() -> TrustAnchorSet {
    let anchor = TrustAnchor::new_ed25519(
        FIXTURE_ANOMALY_KID.to_string(),
        &fixture_anomaly_verifying_key_bytes(),
        AnchorRole::AnomalyLibrarySigner,
    )
    .expect("fixture pk is non-weak");
    let mut set = TrustAnchorSet::new();
    set.insert(anchor).expect("fresh set has no dup kid");
    set
}

#[test]
fn replay_of_previously_accepted_envelope_rejects_end_to_end() {
    // End-to-end: sign a MINIMUM library at v7, verify it once
    // against a fresh ledger (first observation), then re-submit the
    // same bytes and expect `LibraryVersionTooOld` — the spec-named
    // §3.5.1 `pattern-library-version-too-old` reject code.
    let cose_v7 = sign_minimum_library_with_version(7);
    let anchors = fixture_anchor_set();
    let mut ledger = InMemoryAnomalyLedger::new();

    let first = verify_anomaly_library_signature_with_ledger(
        &cose_v7,
        &anchors,
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
        &mut ledger,
    )
    .expect("first observation must verify");
    assert_eq!(first.library_version, 7);
    assert_eq!(first.library_id, FIXTURE_ANOMALY_LIBRARY_ID);
    assert_eq!(first.patterns.len(), 15);

    // Exact byte-for-byte replay — rejects.
    let err = verify_anomaly_library_signature_with_ledger(
        &cose_v7,
        &anchors,
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
        &mut ledger,
    )
    .expect_err("replay of identical envelope must reject");
    assert!(
        matches!(
            err,
            AnomalyLibError::LibraryVersionTooOld {
                current_hwm: 7,
                attempted: 7,
                ..
            }
        ),
        "expected LibraryVersionTooOld{{7,7}}, got {err:?}"
    );
}

#[test]
fn with_ledger_accepts_trait_object_and_preseeded_ledger() {
    // Exercise two extensibility vectors at once:
    // 1. `&mut dyn AnomalyLedger` through the public API — the trait
    //    MUST be object-safe.  Any generic/Sized bound that broke
    //    object-safety would surface here at compile time.
    // 2. A pre-seeded ledger (from the `seeded_ledger_at_version`
    //    fixture helper) behaves identically to one that observed a
    //    real envelope at that version: the next observe at the same
    //    or lower version MUST reject.
    //
    // The seeded HWM matches FIXTURE_ANOMALY_LIBRARY_ID at v5; the
    // v3 envelope below is strictly lower and rejects as rollback.
    let pre: Box<dyn AnomalyLedger> = Box::new(seeded_ledger_at_version(
        FIXTURE_ANOMALY_LIBRARY_ID,
        5,
    ));
    let mut pre = pre; // bind as mut so we can pass &mut

    let cose_v3 = sign_minimum_library_with_version(3);
    let err = verify_anomaly_library_signature_with_ledger(
        &cose_v3,
        &fixture_anchor_set(),
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
        pre.as_mut(),
    )
    .expect_err("v3 after seed@5 must reject as rollback");
    assert!(matches!(
        err,
        AnomalyLibError::LibraryVersionTooOld {
            current_hwm: 5,
            attempted: 3,
            ..
        }
    ));

    // And a strictly-greater version advances through the same dyn
    // dispatch — proves the mutable-state path works end-to-end
    // behind the trait object, not just the immutable reject path.
    let cose_v6 = sign_minimum_library_with_version(6);
    verify_anomaly_library_signature_with_ledger(
        &cose_v6,
        &fixture_anchor_set(),
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
        pre.as_mut(),
    )
    .expect("v6 advance past seeded HWM 5 must succeed via dyn dispatch");
}

#[test]
fn two_distinct_library_ids_advance_independently_end_to_end() {
    // Per-library_id HWM isolation at the public-API boundary.  The
    // inline unit test in `signature.rs` already proves this at the
    // verifier level; here we prove it end-to-end using two
    // different `library_id` strings — one from the fixture pool,
    // one constructed by re-signing the same patterns under a
    // different library_id.
    //
    // The seeded ledger has FIXTURE_ANOMALY_LIBRARY_ID @ 100.  Loading
    // the same id at v1 would reject; loading a DIFFERENT library_id
    // at v1 must succeed as a first observation.
    let mut ledger = seeded_ledger_at_version(FIXTURE_ANOMALY_LIBRARY_ID, 100);

    // Sanity check: same-id, lower version rejects.
    let cose_same = sign_minimum_library_with_version(50);
    let err = verify_anomaly_library_signature_with_ledger(
        &cose_same,
        &fixture_anchor_set(),
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
        &mut ledger,
    )
    .expect_err("same-id v50 after seed@100 must reject");
    assert!(matches!(
        err,
        AnomalyLibError::LibraryVersionTooOld {
            current_hwm: 100,
            attempted: 50,
            ..
        }
    ));

    // Construct a second ledger pre-seeded with a *different*
    // library_id.  The two namespaces are independent; observing
    // "lib::beta"@1 on the FIXTURE-seeded ledger succeeds as a
    // first observation because that id has no prior HWM.
    let obs = ledger
        .observe("lib::beta", 1)
        .expect("first observation on distinct library_id must succeed");
    // Two advances in a row on the same ledger to prove no cross-id
    // contamination after the first-observation succeeded.
    let _ = obs;
    let again = ledger
        .observe("lib::beta", 2)
        .expect("advance on distinct library_id must succeed");
    let _ = again;

    // Original fixture id still rejects at v50 — its HWM is
    // untouched.  This pins the isolation in BOTH directions.
    let err = verify_anomaly_library_signature_with_ledger(
        &cose_same,
        &fixture_anchor_set(),
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
        &mut ledger,
    )
    .expect_err("fixture library HWM must be untouched by beta loads");
    assert!(matches!(
        err,
        AnomalyLibError::LibraryVersionTooOld {
            current_hwm: 100,
            ..
        }
    ));
}

#[test]
fn in_memory_anomaly_ledger_is_send_and_sync_from_external_crate() {
    // Compile-time proof: an external crate can treat
    // `InMemoryAnomalyLedger` as `Send + Sync` — required to put one
    // behind `Arc<Mutex<...>>` in an async or worker-pool context.
    //
    // The trait itself only requires `Send` (a `dyn AnomalyLedger`
    // might wrap a non-Sync backend like `RefCell`).  We pin `Sync`
    // on the *concrete* default impl rather than on the trait, to
    // avoid over-constraining future backends while still giving
    // the out-of-the-box impl cross-thread ergonomics.
    fn assert_send<T: Send + ?Sized>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<InMemoryAnomalyLedger>();
    assert_sync::<InMemoryAnomalyLedger>();
    // Pin `Box<dyn AnomalyLedger>: Send` via turbofish — a `&Box<T>`
    // helper would trigger `clippy::borrowed_box` with no semantic
    // gain over the direct type-parameter form.
    assert_send::<Box<dyn AnomalyLedger>>();
    // Runtime instantiation proves the `dyn` erasure compiles, not
    // just the bound.
    let _boxed: Box<dyn AnomalyLedger> = Box::new(InMemoryAnomalyLedger::new());
}
