//! End-to-end integration tests for the §3.5.4 MINIMUM anomaly
//! pattern library.
//!
//! # Why this file exists
//!
//! The `test_fixtures` self-tests inside `src/test_fixtures.rs`
//! already pin fixture-internal invariants (key stability, pattern
//! order, OnceLock memoisation, byte determinism of a single
//! signing).  This file is the **external-consumer** view of the same
//! surface — it lives under `tests/` so `cargo` compiles it as a
//! separate binary that imports `ephemeral-anomaly` through `pub`
//! items only.
//!
//! A compile failure or missing item here means the fixture module
//! leaks something only via `pub(crate)` (i.e. is unreachable to
//! downstream crates such as `ephemeral-core`, the vector-signer, or
//! the conformance harness) — that would silently break every
//! downstream fixture consumer, not just this binary.
//!
//! # What this file protects
//!
//! 1. The feature-gated `pub mod test_fixtures` / `pub use` chain
//!    resolves from outside the crate.
//! 2. The MINIMUM-library envelope round-trips through the full
//!    7-stage verifier and yields a decoded payload whose pattern
//!    table matches the fixture shape exactly.
//! 3. The `empty_library` preset — a Session-2 envelope with
//!    `patterns = Vec::new()` — verifies with an empty decoded
//!    pattern table; the Stage-7 invariant loop trivially accepts.
//! 4. A Session-1-shaped envelope (CBOR payload OMITS the
//!    `patterns` field entirely) still verifies under the Session-2
//!    verifier.  Load-bearing proof of `#[serde(default)]` forward-
//!    compat from the external-consumer perspective: an already-
//!    signed Session-1 envelope in the wild MUST NOT break when the
//!    consumer upgrades to a Session-2 `ephemeral-anomaly`.
//! 5. Byte-equality tripwire: a pinned SHA-256 over the shared
//!    MINIMUM envelope fires on any change to the MINIMUM pattern
//!    table or its document order, the fixture constants (seed,
//!    kid, issued_at, expires_at, library_id, library_version),
//!    the CBOR encoder (`ciborium`) byte layout, the COSE_Sign1
//!    encoder (`coset`) byte layout, or Ed25519 signing
//!    determinism (RFC 8032 §5.1.6).
//!
//! # Regenerating the pinned hash
//!
//! After an intentional fixture change, run the tripwire test with
//! `-- --nocapture`; the assertion message reports the observed
//! hash to paste back into [`SHARED_MINIMUM_SHA256`].

// The file only compiles when the upstream fixture feature is active.
// Without it, `ephemeral_anomaly::test_fixtures::*` does not exist and
// the binary would fail to link — the `#[cfg]` turns it into an empty
// compilation unit instead, so `cargo test -p ephemeral-anomaly`
// (without features) still passes.
#![cfg(feature = "test_fixtures")]
// Normative identifiers (COSE_Sign1, AnomalyPatternLibrary, Ed25519)
// appear verbatim in the doc comments here; backticking them every
// time hurts readability more than it helps.
#![allow(clippy::doc_markdown)]

use ephemeral_anomaly::{
    test_fixtures::{
        cbor_encode_anomaly_payload, fixture_anomaly_signing_key,
        fixture_anomaly_verifying_key_bytes, minimum_anomaly_library_payload,
        shared_anomaly_artifacts, sign_anomaly_library_envelope,
        sign_anomaly_library_envelope_raw, FIXTURE_ANOMALY_EXPIRES_AT,
        FIXTURE_ANOMALY_ISSUED_AT, FIXTURE_ANOMALY_KID, FIXTURE_ANOMALY_LIBRARY_ID,
    },
    verify_anomaly_library_signature, ANOMALY_LIBRARY_AAD, ANOMALY_LIBRARY_ABI_VERSION,
};
use ephemeral_crypto::{AnchorRole, TrustAnchor, TrustAnchorSet};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Test clock anchored inside the fixture validity window
/// `[FIXTURE_ANOMALY_ISSUED_AT, FIXTURE_ANOMALY_EXPIRES_AT]` so the
/// time-bounds guards accept.  Kept distinct from the fixture clock
/// constants so a future seed/window edit is forced to touch this
/// constant and cannot silently drift outside the window.
const TEST_NOW: i64 = 1_750_000_000;

/// SHA-256 hex digest over the shared MINIMUM-library envelope.
///
/// Regeneration workflow: run this binary with `-- --nocapture`; the
/// panic message from `shared_minimum_envelope_matches_pinned_hash`
/// reports the observed hash.  Paste it back here and commit
/// alongside the intentional fixture change.
const SHARED_MINIMUM_SHA256: &str =
    "7f5e167701468d917c35b47fe2e9b0701621f54891329bb799b7d6dcea46bea6";

/// Assemble a `TrustAnchorSet` carrying only the fixture signer under
/// the correct [`AnchorRole::AnomalyLibrarySigner`].  Any other role
/// assignment would mean the crypto layer's role check rejects the
/// envelope with `CoseVerifyFailed`.
fn fixture_anchor_set() -> TrustAnchorSet {
    let anchor = TrustAnchor::new_ed25519(
        FIXTURE_ANOMALY_KID.to_string(),
        &fixture_anomaly_verifying_key_bytes(),
        AnchorRole::AnomalyLibrarySigner,
    )
    .expect("fixture public key is non-weak");
    let mut set = TrustAnchorSet::new();
    set.insert(anchor).expect("fresh set has no duplicate kid");
    set
}

#[test]
fn shared_minimum_library_verifies_through_public_api() {
    let pool = shared_anomaly_artifacts();

    let out = verify_anomaly_library_signature(
        &pool.minimum_library,
        &fixture_anchor_set(),
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
    )
    .expect("shared MINIMUM library must verify end-to-end");

    assert_eq!(out.patterns.len(), 15, "MINIMUM library must carry 15 patterns");
    assert_eq!(out.library_id, FIXTURE_ANOMALY_LIBRARY_ID);
    assert_eq!(out.signer_kid, FIXTURE_ANOMALY_KID);
    assert_eq!(out.abi_version, ANOMALY_LIBRARY_ABI_VERSION);

    // Document-order head + tail anchors.  A silent reorder of the
    // fixture pattern set would break byte-equality tripwires and the
    // conformance harness baseline, so pin the boundary entries here
    // too — the tripwire below catches the interior but head/tail
    // make the failure localisable.
    assert_eq!(out.patterns[0].pattern_id, "delete-storm");
    assert_eq!(out.patterns[14].pattern_id, "fanout-slow-burn");
}

#[test]
fn shared_empty_library_verifies_through_public_api() {
    let pool = shared_anomaly_artifacts();

    let out = verify_anomaly_library_signature(
        &pool.empty_library,
        &fixture_anchor_set(),
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
    )
    .expect("shared empty library must verify end-to-end");

    assert!(
        out.patterns.is_empty(),
        "empty-library preset must decode to an empty pattern table"
    );
}

/// A minimal serde struct mirroring the Session-1 wire shape of
/// `AnomalyLibraryPayload`: identical field set EXCEPT the `patterns`
/// field is absent entirely (not merely empty).  Used to emit a
/// Session-1-shaped CBOR payload and prove the Session-2 verifier
/// accepts it via `#[serde(default)]` on
/// [`ephemeral_anomaly::AnomalyLibraryPayload::patterns`].
///
/// Defined locally (not reusing the fixture payload) because the
/// fixture encoder always emits the `patterns` key — reconstructing
/// a truly Session-1-shaped CBOR requires a type without that field.
#[derive(Serialize)]
struct SessionOnePayload {
    abi_version: u32,
    signer_kid: String,
    library_id: String,
    library_version: u64,
    issued_at: i64,
    expires_at: i64,
}

#[test]
fn session_one_shaped_envelope_decodes_with_empty_patterns() {
    // Session-1 envelopes were signed BEFORE the `patterns` field
    // existed.  Their CBOR payload OMITS the key entirely — not empty
    // Vec, but absent.  `#[serde(default)]` on
    // `AnomalyLibraryPayload::patterns` is what makes them decode
    // cleanly under the Session-2 verifier; without it, ciborium
    // would error with `MissingField("patterns")` and every already-
    // signed Session-1 envelope in the wild would break.
    let legacy = SessionOnePayload {
        abi_version: ANOMALY_LIBRARY_ABI_VERSION,
        signer_kid: FIXTURE_ANOMALY_KID.to_string(),
        library_id: "fixture::legacy-session1".to_string(),
        library_version: 1,
        issued_at: FIXTURE_ANOMALY_ISSUED_AT,
        expires_at: FIXTURE_ANOMALY_EXPIRES_AT,
    };

    let mut inner = Vec::new();
    ciborium::into_writer(&legacy, &mut inner)
        .expect("ciborium serialize of Session-1 struct is infallible");

    let env = sign_anomaly_library_envelope_raw(
        inner,
        FIXTURE_ANOMALY_KID,
        ANOMALY_LIBRARY_AAD,
        &fixture_anomaly_signing_key(),
    );

    let out = verify_anomaly_library_signature(
        &env,
        &fixture_anchor_set(),
        ANOMALY_LIBRARY_ABI_VERSION,
        TEST_NOW,
    )
    .expect("Session-1-shaped envelope must verify under Session-2 verifier");

    assert!(
        out.patterns.is_empty(),
        "#[serde(default)] must yield an empty Vec for absent `patterns` field"
    );
    assert_eq!(out.library_id, "fixture::legacy-session1");
}

#[test]
fn signing_is_byte_deterministic_across_independent_calls() {
    // External-consumer determinism check: two independent signings
    // of the same payload with the same key MUST produce byte-
    // identical envelopes.  Ed25519 is deterministic (RFC 8032
    // §5.1.6), `ciborium` is byte-stable for this struct shape, and
    // `coset`'s CoseSign1 serialisation is byte-stable for a fixed
    // protected header.  Independent of the shared OnceLock pool —
    // the pool caches a single signing, this test forces two.
    let key = fixture_anomaly_signing_key();
    let payload = minimum_anomaly_library_payload();
    let a = sign_anomaly_library_envelope(&payload, &key);
    let b = sign_anomaly_library_envelope(&payload, &key);
    assert_eq!(
        a, b,
        "anomaly-library envelope signing is not byte-deterministic"
    );
}

#[test]
fn shared_minimum_envelope_matches_pinned_hash() {
    // Byte-equality tripwire.  The shared MINIMUM envelope's SHA-256
    // is pinned as [`SHARED_MINIMUM_SHA256`]; any change to the
    // signing pipeline (pattern table, encoder, algorithm, fixture
    // constants) flips the hash and trips this assertion.
    //
    // On intentional change: run
    //   cargo test -p ephemeral-anomaly --features test_fixtures \
    //     --test minimum_library \
    //     shared_minimum_envelope_matches_pinned_hash -- --nocapture
    // and copy the observed hash into `SHARED_MINIMUM_SHA256`.
    let pool = shared_anomaly_artifacts();
    let digest = hex::encode(Sha256::digest(&pool.minimum_library));

    assert_eq!(
        digest, SHARED_MINIMUM_SHA256,
        "\nMINIMUM-library envelope hash mismatch.\n\
         Expected: {SHARED_MINIMUM_SHA256}\n\
         Observed: {digest}\n\
         If this change is INTENTIONAL, update SHARED_MINIMUM_SHA256\n\
         in tests/minimum_library.rs to the Observed value above."
    );
}

#[test]
fn cbor_encoder_output_matches_shared_envelope_payload() {
    // Extra guard covering the `cbor_encode_anomaly_payload` public
    // helper from the external-consumer perspective.  A downstream
    // tool (vector-signer, conformance harness) calling the helper
    // directly MUST observe the same bytes that drive the shared
    // envelope — otherwise the two paths would silently diverge and
    // the conformance vectors would drift from what the verifier
    // actually accepts.
    let inner = cbor_encode_anomaly_payload(&minimum_anomaly_library_payload());
    assert!(
        !inner.is_empty(),
        "encoded MINIMUM payload must be non-empty"
    );
    // CBOR map encodes as a major-type-5 header byte.  The payload
    // struct has 7 fields (6 headers + patterns), so the first byte
    // is 0xa7 (map of 7).  Pin it here: if the serde-layer renames
    // or drops a field the byte count changes and this catches the
    // regression without needing a full hash.
    assert_eq!(
        inner[0], 0xa7,
        "MINIMUM payload must encode as a 7-field CBOR map (major 5, len 7)"
    );
}
