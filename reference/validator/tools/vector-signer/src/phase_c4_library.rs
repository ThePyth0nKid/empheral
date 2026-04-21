//! Phase C.4 Session 4 — anomaly-library envelope verification reject +
//! accept vectors (`alrej-100`..`alrej-116`).
//!
//! The `anomaly-library-reject` suite executor
//! (`crates/ephemeral-core/src/suites/anomaly_library.rs`) dispatches every
//! vector of this file into
//! [`ephemeral_anomaly::verify_anomaly_library_signature_with_ledger`] with
//! a fresh [`InMemoryAnomalyLedger`] optionally pre-seeded from the
//! vector's `pre_ledger` field.  Each reject vector isolates one failure
//! mode so the expected `reject_code` pins a specific verifier branch:
//!
//! | ID         | Failure mode                                                         | Expected wire code                              |
//! |------------|----------------------------------------------------------------------|-------------------------------------------------|
//! | alrej-100  | COSE envelope byte flipped post-sign                                 | `anomaly-library-signature-invalid`             |
//! | alrej-101  | Inner payload is non-CBOR bytes                                      | `anomaly-library-signature-payload-malformed`   |
//! | alrej-102  | Signed `abi_version=2`, verifier expects 1                           | `anomaly-library-abi-version-mismatch`          |
//! | alrej-103  | Inner `signer_kid` ≠ outer COSE header `kid`                         | `anomaly-library-signer-kid-mismatch`           |
//! | alrej-104  | `issued_at` in the future relative to `current_time`                 | `anomaly-library-not-yet-valid`                 |
//! | alrej-105  | `expires_at` in the past relative to `current_time`                  | `anomaly-library-expired`                       |
//! | alrej-106  | MINIMUM library extended with duplicate pattern row                  | `anomaly-library-pattern-id-duplicate`          |
//! | alrej-107  | Pattern with (`severity=Critical`, `action=Alert`) pair              | `anomaly-library-severity-action-inconsistent`  |
//! | alrej-108  | `IamAttachFamily` pattern referencing unknown family                 | `anomaly-library-unknown-verb-family`           |
//! | alrej-109  | Short-window `FirstMatch` with empty `firing_rule_companions`        | `anomaly-library-firing-rule-companion-missing` |
//! | alrej-110  | Companion named in `firing_rule_companions` not present in library   | `anomaly-library-firing-rule-companion-missing` |
//! | alrej-111  | Companion present but `firing_rule != CumulativeOverBaseline`        | `anomaly-library-firing-rule-companion-missing` |
//! | alrej-112  | Companion cumulative but `window_seconds < 10× primary_window`       | `anomaly-library-firing-rule-companion-missing` |
//! | alrej-113  | Replay — same `library_version` already in ledger                    | `pattern-library-version-too-old`               |
//! | alrej-114  | Rollback — lower `library_version` than ledger HWM                   | `pattern-library-version-too-old`               |
//! | alrej-115  | Happy path — first observation of `library_version=1`                | `accept`                                        |
//! | alrej-116  | Happy path — strict advance from `library_version=5` to `7`          | `accept`                                        |
//!
//! # Why fifteen rejects + two accepts
//!
//! Eleven of the twelve [`AnomalyLibError`] variants map directly to a
//! single isolating vector (alrej-100..108, plus replay/rollback).
//! Stage 7d's [`FiringCompanionFailure`] sub-variants split into four
//! distinct signer-side failure modes — each gets its own vector
//! (alrej-109..112) because each has a different fix.  The twelfth top-
//! level variant [`AnomalyLibError::LedgerFailure`] is NOT covered: it
//! requires a custom [`AnomalyLedger`] implementation that deliberately
//! errors, which is beyond what a JSON-serialisable vector can express.
//!
//! Two accepts because the replay-ledger dial is operationally load-
//! bearing: a validator that always rejected Stage 8 would pass every
//! replay/rollback reject and never be caught.  alrej-115 pins the
//! first-observation happy path; alrej-116 pins the strict-advance
//! happy path with a non-trivial seeded ledger.
//!
//! # Pattern-library construction for Stage-7 vectors
//!
//! Stage 7 rejects (alrej-106..112) need a library that passes every
//! earlier stage but fails at exactly the target Stage-7 sub-check.
//! We use two approaches:
//!
//! - For alrej-106 (duplicate pattern_id) we keep the full MINIMUM
//!   library because the canonical 15-row fixture already exercises
//!   every `ScopePredicate` variant and every `firing_rule` shape —
//!   any Stage-7 regression would surface there first.  The duplicate
//!   row is appended to exercise 7a without touching the well-formed
//!   body.
//! - For alrej-107..112 we assemble a minimal custom library of 1–2
//!   patterns so the failure mode is visible at a glance in `git
//!   diff`.  Each pattern starts from a canonical fixture builder
//!   (`delete_storm_pattern`, `machine_pace_pattern`,
//!   `iam_attach_policy_storm_pattern`) and mutates only the fields
//!   needed to drive the target reject — `#[non_exhaustive]` on
//!   `PatternEntry` forbids struct-literal construction in this
//!   crate, and the fixture+mutate path is the only path that scales
//!   to future variant additions.
//!
//! # Determinism
//!
//! Every constant (signing seed, `issued_at`/`expires_at`, library id,
//! current_time) is compile-time-fixed.  The signing key is
//! [`ephemeral_anomaly::test_fixtures::fixture_anomaly_signing_key`] —
//! a pinned Ed25519 seed.  Ed25519 signing is deterministic (RFC 8032
//! §5.1.6), `ciborium` encoding is byte-stable for the
//! `AnomalyLibraryPayload` shape, and `coset::CoseSign1` serialisation
//! is byte-stable for a fixed protected header, so every `build_all()`
//! call produces byte-identical JSON.  The in-process regression test
//! `determinism_two_runs_produce_identical_bytes` pins this; the
//! external-process `tests/determinism_c4_library.rs` tripwire mirrors
//! the C.2.5 / C.3-C pattern and pins the SHA-256 of the `gen-phase-
//! c4-library --dry-run` stdout against regeneration drift.

use ephemeral_anomaly::patterns::{Action, FiringRule, Severity};
use ephemeral_anomaly::scope::{MandateScope, ScopePredicate};
use ephemeral_anomaly::schema::AnomalyLibraryPayload;
use ephemeral_anomaly::signature::ANOMALY_LIBRARY_AAD;
use ephemeral_anomaly::test_fixtures as aft;
use ephemeral_anomaly::ANOMALY_LIBRARY_ABI_VERSION;
use serde_json::{json, Value};

use crate::tamper_payload_byte;

// ─── Deterministic fixture inputs ───────────────────────────────────────────

/// Fixed RFC-3339 clock for every vector.  `2026-05-01T00:00:00Z`
/// parses to ~1_777_593_600 unix seconds, which sits comfortably
/// inside `[FIXTURE_ANOMALY_ISSUED_AT, FIXTURE_ANOMALY_EXPIRES_AT)` =
/// `[1_700_000_000, 1_800_000_000)`.  Every vector that expects
/// time-bounds to pass inherits this constant; alrej-104 and alrej-
/// 105 deliberately diverge by supplying out-of-band `issued_at` /
/// `expires_at` on the signed payload.
const CURRENT_TIME: &str = "2026-05-01T00:00:00Z";

/// Deliberately-future validity window for alrej-104 (NotYetValid).
/// `issued_at = 1_900_000_000` (~June 2030) sits well after
/// [`CURRENT_TIME`], so the Stage-6 check `now < issued_at` fires.
const FUTURE_ISSUED_AT: i64 = 1_900_000_000;
const FUTURE_EXPIRES_AT: i64 = 2_000_000_000;

/// Deliberately-past validity window for alrej-105 (Expired).
/// `expires_at = 1_600_000_000` (~September 2020) is well before
/// [`CURRENT_TIME`], so the Stage-6 check `expires_at ≤ now` fires.
const PAST_ISSUED_AT: i64 = 1_500_000_000;
const PAST_EXPIRES_AT: i64 = 1_600_000_000;

/// Outer COSE header `kid` used exclusively by alrej-103 to drive the
/// inner/outer `signer_kid` mismatch.  The anchor set in that vector
/// registers this impostor `kid` against the real fixture pubkey so
/// the outer COSE MAC verifies; the mismatch surfaces purely at
/// Stage 5's inner-vs-outer consistency check.
const IMPOSTOR_OUTER_KID: &str = "K_impostor_anomaly_pk";

// ─── Entry point ────────────────────────────────────────────────────────────

/// Emit all 17 Phase C.4 Session 4 vectors in ascending ID order.
pub fn build_all() -> Vec<Value> {
    vec![
        build_alrej_100_cose_verify_tampered(),
        build_alrej_101_payload_not_cbor(),
        build_alrej_102_abi_version_mismatch(),
        build_alrej_103_signer_kid_mismatch(),
        build_alrej_104_not_yet_valid(),
        build_alrej_105_expired(),
        build_alrej_106_pattern_id_duplicate(),
        build_alrej_107_severity_action_inconsistent(),
        build_alrej_108_unknown_verb_family(),
        build_alrej_109_no_companions_declared(),
        build_alrej_110_companion_not_found(),
        build_alrej_111_companion_not_cumulative(),
        build_alrej_112_companion_window_too_short(),
        build_alrej_113_library_version_replay(),
        build_alrej_114_library_version_rollback(),
        build_alrej_115_accept_first_observation(),
        build_alrej_116_accept_strict_advance(),
    ]
}

// ─── Stage 1: COSE verify ───────────────────────────────────────────────────

/// alrej-100 — happy envelope with one inner-payload byte flipped.
/// The outer Ed25519 MAC no longer validates → `CoseVerifyFailed` →
/// `anomaly-library-signature-invalid`.
fn build_alrej_100_cose_verify_tampered() -> Value {
    let env = aft::sign_minimum_library_with_version(1);
    let tampered_hex = tamper_payload_byte(&hex::encode(&env))
        .expect("tampering a freshly-built envelope must succeed");

    build_vector(
        "alrej-100",
        "anomaly-library-cose-verify-tampered",
        "Phase C.4 live-crypto vector: a valid MINIMUM anomaly-library \
         COSE_Sign1 envelope with the first inner-payload byte flipped \
         after signing. The outer Ed25519 MAC fails, anomaly-library \
         verification surfaces as anomaly-library-signature-invalid.",
        "design-final.md §3.5.1 + RFC 9052 §4.4: the anomaly-library \
         envelope is protected identically to tariff and classifier \
         envelopes. Any post-signing mutation of the signed bytes \
         breaks the MAC; the live path must detect what a stateless \
         bool never could.",
        tampered_hex,
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-signature-invalid"),
        "critical",
    )
}

// ─── Stage 3: payload decode ────────────────────────────────────────────────
// (Stage 2 — outer-signature verify — is covered by alrej-100 above; the
// verifier short-circuits on `CoseVerifyFailed` so a dedicated Stage 2
// vector and a dedicated Stage 1 (envelope parse) vector collapse into
// alrej-100.  Stage-audit tools should read alrej-100 as covering both
// Stage 1 and Stage 2.)

/// alrej-101 — COSE_Sign1 envelope signs arbitrary non-CBOR inner
/// bytes. The outer MAC verifies cleanly, but the ciborium decoder
/// rejects at parse time → `PayloadDecodeFailed` →
/// `anomaly-library-signature-payload-malformed`.
fn build_alrej_101_payload_not_cbor() -> Value {
    let env = aft::sign_anomaly_library_envelope_raw(
        b"this is not cbor".to_vec(),
        aft::FIXTURE_ANOMALY_KID,
        ANOMALY_LIBRARY_AAD,
        &aft::fixture_anomaly_signing_key(),
    );

    build_vector(
        "alrej-101",
        "anomaly-library-payload-not-cbor",
        "Phase C.4 live-crypto vector: the outer COSE_Sign1 signature \
         verifies (correct kid, correct AAD, correct key) but the \
         inner payload is arbitrary ASCII bytes rather than the \
         expected ciborium-encoded AnomalyLibraryPayload. Decode \
         rejects at parse time.",
        "design-final.md §3.5.1: the inner payload contract is \
         structural CBOR under a fixed schema. A malformed inner \
         payload that still verifies at the COSE layer MUST surface \
         as a payload decode failure, not be silently accepted — \
         silent acceptance would let a signer rotate to arbitrary \
         bytes and defeat the entire structural-validation stage.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-signature-payload-malformed"),
        "critical",
    )
}

// ─── Stage 4: ABI version ───────────────────────────────────────────────────

/// alrej-102 — signed `abi_version=2`, validator expects
/// `ANOMALY_LIBRARY_ABI_VERSION=1`. `AbiVersionMismatch` →
/// `anomaly-library-abi-version-mismatch`.
fn build_alrej_102_abi_version_mismatch() -> Value {
    let payload = AnomalyLibraryPayload {
        abi_version: 2,
        signer_kid: aft::FIXTURE_ANOMALY_KID.to_string(),
        library_id: aft::FIXTURE_ANOMALY_LIBRARY_ID.to_string(),
        library_version: 1,
        issued_at: aft::FIXTURE_ANOMALY_ISSUED_AT,
        expires_at: aft::FIXTURE_ANOMALY_EXPIRES_AT,
        patterns: aft::minimum_anomaly_library_patterns(),
    };
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-102",
        "anomaly-library-abi-version-mismatch",
        "Phase C.4 live-crypto vector: anomaly-library envelope signed \
         with abi_version=2 but the validator pins abi_version=1 \
         (ANOMALY_LIBRARY_ABI_VERSION). Mismatch rejects before any \
         Stage-5+ field is consulted.",
        "design-final.md §3.5.1: abi_version is how a signer declares \
         which library generation this envelope commits to. A stale or \
         forward-rolled version must be caught before trust is extended \
         to the pattern table — a higher abi could imply changed \
         scope-predicate or firing-rule semantics.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-abi-version-mismatch"),
        "critical",
    )
}

// ─── Stage 5: signer-kid consistency ────────────────────────────────────────

/// alrej-103 — inner payload `signer_kid` is `FIXTURE_ANOMALY_KID`,
/// but the outer COSE protected header `kid` is `IMPOSTOR_OUTER_KID`.
/// The anchor set registers `IMPOSTOR_OUTER_KID` → real fixture pubkey
/// so the outer MAC verifies; the mismatch surfaces exclusively at
/// Stage 5 → `SignerKidMismatch` → `anomaly-library-signer-kid-mismatch`.
fn build_alrej_103_signer_kid_mismatch() -> Value {
    let payload = aft::minimum_anomaly_library_payload();
    let inner_cbor = aft::cbor_encode_anomaly_payload(&payload);
    let env = aft::sign_anomaly_library_envelope_raw(
        inner_cbor,
        IMPOSTOR_OUTER_KID,
        ANOMALY_LIBRARY_AAD,
        &aft::fixture_anomaly_signing_key(),
    );

    build_vector(
        "alrej-103",
        "anomaly-library-signer-kid-mismatch",
        "Phase C.4 live-crypto vector: outer COSE_Sign1 header kid is \
         K_impostor_anomaly_pk (anchor registers this kid against the \
         real fixture pubkey so the outer MAC verifies); inner CBOR \
         payload's signer_kid is K_fixture_anomaly_pk. Inner/outer \
         mismatch MUST reject with anomaly-library-signer-kid-mismatch.",
        "design-final.md §3.5.1: duplicating signer identity inside the \
         signed payload is defense-in-depth against outer-header \
         substitution. An attacker who can rewrite the outer kid but \
         not the inner bytes must still be caught by the consistency \
         gate — this vector pins that gate.",
        hex::encode(&env),
        anchor_def(IMPOSTOR_OUTER_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-signer-kid-mismatch"),
        "critical",
    )
}

// ─── Stage 6: time bounds ───────────────────────────────────────────────────

/// alrej-104 — payload declares `issued_at = FUTURE_ISSUED_AT` (~year
/// 2030), while `current_time = CURRENT_TIME` (~year 2026). Stage 6's
/// `now < issued_at` check fires → `NotYetValid` →
/// `anomaly-library-not-yet-valid`.
fn build_alrej_104_not_yet_valid() -> Value {
    let payload = AnomalyLibraryPayload {
        abi_version: ANOMALY_LIBRARY_ABI_VERSION,
        signer_kid: aft::FIXTURE_ANOMALY_KID.to_string(),
        library_id: aft::FIXTURE_ANOMALY_LIBRARY_ID.to_string(),
        library_version: 1,
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        patterns: aft::minimum_anomaly_library_patterns(),
    };
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-104",
        "anomaly-library-not-yet-valid",
        "Phase C.4 live-crypto vector: validly-signed envelope with an \
         issued_at in the future (year 2030) relative to the verifier \
         clock (year 2026). Time-bounds check rejects with \
         anomaly-library-not-yet-valid before Stage-7 pattern-body \
         invariants run.",
        "design-final.md §3.5.1: the validity window is the operator's \
         declaration of WHEN this library is authoritative. A future- \
         dated library has not yet taken effect; consuming it now would \
         let a signer pre-roll a library and ship it silently ahead of \
         schedule. The verifier's clock is the source of truth, not the \
         envelope's.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-not-yet-valid"),
        "critical",
    )
}

/// alrej-105 — payload declares `expires_at = PAST_EXPIRES_AT` (~year
/// 2020), while `current_time = CURRENT_TIME` (~year 2026). Stage 6's
/// `expires_at ≤ now` check fires → `Expired` → `anomaly-library-expired`.
fn build_alrej_105_expired() -> Value {
    let payload = AnomalyLibraryPayload {
        abi_version: ANOMALY_LIBRARY_ABI_VERSION,
        signer_kid: aft::FIXTURE_ANOMALY_KID.to_string(),
        library_id: aft::FIXTURE_ANOMALY_LIBRARY_ID.to_string(),
        library_version: 1,
        issued_at: PAST_ISSUED_AT,
        expires_at: PAST_EXPIRES_AT,
        patterns: aft::minimum_anomaly_library_patterns(),
    };
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-105",
        "anomaly-library-expired",
        "Phase C.4 live-crypto vector: validly-signed envelope with an \
         expires_at in the past (year 2020) relative to the verifier \
         clock (year 2026). Time-bounds check rejects with \
         anomaly-library-expired before Stage-7 pattern-body invariants \
         run.",
        "design-final.md §3.5.1: an expired library is stale detection \
         surface. Continuing to evaluate its patterns after expiry \
         would let obsolete signer-approved behaviour outlive the \
         operator's intent. Reject at the envelope boundary, before \
         the pattern table is trusted.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-expired"),
        "critical",
    )
}

// ─── Stage 7a: pattern-ID uniqueness ────────────────────────────────────────

/// alrej-106 — MINIMUM library extended with a duplicate `delete-storm`
/// row. Stage 7a's pairwise uniqueness check fires at the first
/// collision → `PatternIdDuplicate` → `anomaly-library-pattern-id-
/// duplicate`.
fn build_alrej_106_pattern_id_duplicate() -> Value {
    let mut patterns = aft::minimum_anomaly_library_patterns();
    // Append a second `delete-storm` row — identical pattern_id as
    // `patterns[0]`. 7a surfaces the collision.
    patterns.push(aft::delete_storm_pattern());

    let payload = AnomalyLibraryPayload {
        abi_version: ANOMALY_LIBRARY_ABI_VERSION,
        signer_kid: aft::FIXTURE_ANOMALY_KID.to_string(),
        library_id: aft::FIXTURE_ANOMALY_LIBRARY_ID.to_string(),
        library_version: 1,
        issued_at: aft::FIXTURE_ANOMALY_ISSUED_AT,
        expires_at: aft::FIXTURE_ANOMALY_EXPIRES_AT,
        patterns,
    };
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-106",
        "anomaly-library-pattern-id-duplicate",
        "Phase C.4 live-crypto vector: MINIMUM library with a \
         duplicated `delete-storm` row appended at the end of the \
         patterns array. Stage 7a pairwise uniqueness check surfaces \
         the collision before Stage 7b/7c/7d run.",
        "design-final.md §4.2.1 R7.C6: patterns is a SET keyed by \
         pattern_id. A duplicate would create ambiguity at dispatch \
         time — the evaluator would not know which row's thresholds \
         and companions apply. Reject at library-load time.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-pattern-id-duplicate"),
        "high",
    )
}

// ─── Stage 7b: severity-action consistency ──────────────────────────────────

/// alrej-107 — single-pattern library where a `CumulativeOverBaseline`
/// row carries `(severity=Critical, action=Alert)`. 7b's severity-
/// action invariant fires → `SeverityActionInconsistent` →
/// `anomaly-library-severity-action-inconsistent`.
fn build_alrej_107_severity_action_inconsistent() -> Value {
    // Start from `machine-pace` (CumulativeOverBaseline, MandatePace
    // scope, Low + Alert). Bumping `severity` to Critical keeps Alert
    // as the action → (Critical, Alert) pair → 7b violation.
    //
    // Cumulative firing_rule + MandatePace scope means this pattern
    // is exempt from Stage 7c (MandatePace carries no verb-family
    // reference) and Stage 7d (not FirstMatch), so Stage 7b is the
    // only surface that fires.
    let mut p = aft::machine_pace_pattern();
    p.severity = Severity::Critical;
    // Keep p.action = Action::Alert from fixture → inconsistent.
    debug_assert!(matches!(p.action, Action::Alert), "fixture drift");

    let payload = build_custom_payload(vec![p]);
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-107",
        "anomaly-library-severity-action-inconsistent",
        "Phase C.4 live-crypto vector: single-pattern library where a \
         pattern declares severity=Critical but action=Alert. Per \
         §3.5.2 R8.A2, severity ∈ {High, Critical} MUST pair with \
         action=AutoRevoke. Stage 7b rejects this pattern before Stages \
         7c/7d run.",
        "design-final.md §3.5.2 R8.A2: Alert's 300s operator-ack SLA is \
         not fast enough for a Critical-severity compromise. The \
         invariant forbids the pair at library-load time so a signer \
         cannot author a Critical pattern that waits on human \
         attention.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-severity-action-inconsistent"),
        "high",
    )
}

// ─── Stage 7c: verb-family resolution ───────────────────────────────────────

/// alrej-108 — single-pattern library where an `IamAttachFamily` scope
/// references a verb family name that does not resolve. Stage 7c's
/// family lookup fires → `UnknownVerbFamily` →
/// `anomaly-library-unknown-verb-family`.
fn build_alrej_108_unknown_verb_family() -> Value {
    // Start from `iam-attach-policy-storm` (IamAttachFamily with the
    // known family "iam-attach"). Swap in an unknown family name so
    // the lookup fails. Keep the firing_rule/window/companions
    // intact — 7c fires before 7d, so the companion reference can
    // stay valid-shape without needing an actual companion pattern
    // in the library.
    //
    // Severity=High + action=AutoRevoke → 7b ok.
    // FirstMatch + window=300 + companion="iam-attach-slow-burn" — 7d
    // would run next, but 7c rejects first so we don't need the
    // companion row to actually exist.
    let mut p = aft::iam_attach_policy_storm_pattern();
    p.scope = ScopePredicate::IamAttachFamily {
        verb_family: "not-a-real-family".into(),
        mandate_scope: MandateScope::default(),
    };
    // Clear companions so if anyone (accidentally) reorders the
    // checks to put 7d before 7c, this still fires 7c cleanly rather
    // than surfacing as NoCompanionsDeclared.
    p.firing_rule_companions = vec![];

    let payload = build_custom_payload(vec![p]);
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-108",
        "anomaly-library-unknown-verb-family",
        "Phase C.4 live-crypto vector: single-pattern library where an \
         IamAttachFamily scope references the family name \
         `not-a-real-family`, which does not resolve against the \
         validator's family lookup. Stage 7c rejects before Stage 7d \
         runs.",
        "design-final.md §3.5.3: families are the validator's trust \
         surface. An operator cannot redefine `iam-attach` to \
         `[\"noop\"]` and defeat the iam-attach-policy-storm pattern. \
         Unknown family names at library-load time would let a signer \
         ship a pattern that never matches anything real.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-unknown-verb-family"),
        "critical",
    )
}

// ─── Stage 7d: anti-walk-under companion invariant ──────────────────────────

/// alrej-109 — single-pattern library where a short-window `FirstMatch`
/// has an empty `firing_rule_companions`. Stage 7d's
/// `NoCompanionsDeclared` sub-variant fires.
fn build_alrej_109_no_companions_declared() -> Value {
    // `delete-storm` is FirstMatch + window=60 (< ANTI_WALK_UNDER_
    // WINDOW_SECONDS=3600), so it is subject to anti-walk-under. An
    // empty companions list violates §3.5.3.
    let mut p = aft::delete_storm_pattern();
    p.firing_rule_companions = vec![];

    let payload = build_custom_payload(vec![p]);
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-109",
        "anomaly-library-companion-none-declared",
        "Phase C.4 live-crypto vector: single-pattern library where a \
         FirstMatch pattern with window_seconds=60 (subject to §3.5.3 \
         anti-walk-under) declares an empty firing_rule_companions \
         list. Stage 7d rejects with the NoCompanionsDeclared sub-\
         variant.",
        "design-final.md §3.5.3: short-window FirstMatch patterns can \
         be defeated by a walk-under attacker who spaces their events \
         just below the threshold. A cumulative-over-baseline companion \
         at ≥10× the primary window closes that gap. An empty companion \
         list is structurally invalid at library-load time.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-firing-rule-companion-missing"),
        "high",
    )
}

/// alrej-110 — single-pattern library where the companion name does
/// not resolve inside the library. Stage 7d's `CompanionNotFound`
/// sub-variant fires.
fn build_alrej_110_companion_not_found() -> Value {
    // `delete-storm` references an explicit companion name that
    // does not exist in the library — this is a signer-side typo
    // or rename mistake.
    let mut p = aft::delete_storm_pattern();
    p.firing_rule_companions = vec!["does-not-exist-companion".into()];

    let payload = build_custom_payload(vec![p]);
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-110",
        "anomaly-library-companion-not-found",
        "Phase C.4 live-crypto vector: single-pattern library where a \
         FirstMatch primary names a companion pattern_id that does not \
         exist in the library. Stage 7d rejects with the \
         CompanionNotFound sub-variant.",
        "design-final.md §3.5.3: a companion reference that does not \
         resolve is a signer-side typo or a rename that missed an \
         uplink. Either way, the evaluator would never find the \
         backstop — reject at library-load time with a name-level \
         error so the signer's fix is obvious.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-firing-rule-companion-missing"),
        "high",
    )
}

/// alrej-111 — two-pattern library where the named companion exists
/// but has `firing_rule = FirstMatch` instead of
/// `CumulativeOverBaseline`. Stage 7d's `CompanionNotCumulative`
/// sub-variant fires.
fn build_alrej_111_companion_not_cumulative() -> Value {
    // Primary: delete-storm (FirstMatch, window=60, companion
    //   "delete-slow-burn").
    let primary = aft::delete_storm_pattern();

    // Companion row with the matching id, but FirstMatch instead of
    // CumulativeOverBaseline. Crucially the companion's window must
    // be > ANTI_WALK_UNDER_WINDOW_SECONDS so it is itself exempt from
    // 7d as a primary — otherwise 7d would first reject IT for having
    // no companion (empty firing_rule_companions) and the test would
    // fire the wrong sub-variant.
    let mut companion = aft::delete_slow_burn_pattern();
    companion.firing_rule = FiringRule::FirstMatch;
    companion.window_seconds = Some(4000);
    companion.firing_rule_companions = vec![];

    let payload = build_custom_payload(vec![primary, companion]);
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-111",
        "anomaly-library-companion-not-cumulative",
        "Phase C.4 live-crypto vector: two-pattern library where a \
         FirstMatch primary names a companion that exists but carries \
         firing_rule=FirstMatch (not CumulativeOverBaseline). Stage 7d \
         rejects with the CompanionNotCumulative sub-variant.",
        "design-final.md §3.5.3: a short-window FirstMatch backstop \
         inherits the very walk-under weakness it is meant to close. \
         Only CumulativeOverBaseline — which integrates across the \
         whole long window — delivers the anti-walk-under guarantee. \
         A mistyped firing_rule in the signer tooling must be caught \
         at load time.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-firing-rule-companion-missing"),
        "high",
    )
}

/// alrej-112 — two-pattern library where the cumulative companion's
/// `window_seconds` is below `10× primary_window`. Stage 7d's
/// `CompanionWindowTooShort` sub-variant fires.
fn build_alrej_112_companion_window_too_short() -> Value {
    // Primary: delete-storm (window=60, needs companion ≥ 10×60=600).
    let primary = aft::delete_storm_pattern();

    // Companion keeps CumulativeOverBaseline but window=500 < 600.
    let mut companion = aft::delete_slow_burn_pattern();
    companion.window_seconds = Some(500);

    let payload = build_custom_payload(vec![primary, companion]);
    let env = aft::sign_anomaly_library_envelope(&payload, &aft::fixture_anomaly_signing_key());

    build_vector(
        "alrej-112",
        "anomaly-library-companion-window-too-short",
        "Phase C.4 live-crypto vector: two-pattern library where a \
         FirstMatch primary (window=60s) names a CumulativeOverBaseline \
         companion whose window is 500s — below the §3.5.3 required \
         10× multiple (600s). Stage 7d rejects with the \
         CompanionWindowTooShort sub-variant.",
        "design-final.md §3.5.3: the 10× multiplier is the normative \
         ratio that makes the companion's cumulative backstop reach \
         far enough in time to catch a paced walk-under. A shorter \
         window narrows the detection horizon and a patient attacker \
         evades both.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "reject",
        Some("anomaly-library-firing-rule-companion-missing"),
        "high",
    )
}

// ─── Stage 8: replay ledger ─────────────────────────────────────────────────

/// alrej-113 — envelope at `library_version=5`, ledger already at
/// HWM=5 for the same library_id. Replay (equal version) rejects →
/// `LibraryVersionTooOld` → `pattern-library-version-too-old`.
fn build_alrej_113_library_version_replay() -> Value {
    let env = aft::sign_minimum_library_with_version(5);

    build_vector(
        "alrej-113",
        "anomaly-library-version-replay",
        "Phase C.4 live-crypto vector: MINIMUM library envelope signed \
         at library_version=5, Stage-8 ledger pre-seeded with \
         library_id→5. Stage 8 rejects the second observation at the \
         same version as replay (VersionNotStrictlyGreater with \
         current_hwm=5, attempted=5).",
        "design-final.md §3.5.1 replay-protection: `library_version` is \
         a monotonic counter. Accepting a same-version envelope twice \
         would let a signer replay an old library through a clock-skew \
         window, bypassing a subsequent revocation. Strict-greater \
         advance is mandatory.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        Some(json!({ aft::FIXTURE_ANOMALY_LIBRARY_ID: 5 })),
        "reject",
        Some("pattern-library-version-too-old"),
        "critical",
    )
}

/// alrej-114 — envelope at `library_version=3`, ledger at HWM=5.
/// Rollback (lower version) rejects identically via
/// `LibraryVersionTooOld` → `pattern-library-version-too-old`.
fn build_alrej_114_library_version_rollback() -> Value {
    let env = aft::sign_minimum_library_with_version(3);

    build_vector(
        "alrej-114",
        "anomaly-library-version-rollback",
        "Phase C.4 live-crypto vector: MINIMUM library envelope signed \
         at library_version=3, Stage-8 ledger pre-seeded with \
         library_id→5. Stage 8 rejects the rollback attempt with \
         VersionNotStrictlyGreater (current_hwm=5, attempted=3).",
        "design-final.md §3.5.1 replay-protection: rollback to an older \
         signed library is functionally identical to replaying it — the \
         effect is that a retired pattern set runs in production after \
         the operator's updated library was already accepted. Strict-\
         greater advance catches both paths with one rule.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        Some(json!({ aft::FIXTURE_ANOMALY_LIBRARY_ID: 5 })),
        "reject",
        Some("pattern-library-version-too-old"),
        "critical",
    )
}

// ─── Accept vectors ─────────────────────────────────────────────────────────

/// alrej-115 — MINIMUM library at `library_version=1`, no pre-seeded
/// ledger. Stage 8 treats this as a first observation and accepts.
/// Positive control for the whole Stage-1..8 pipeline.
fn build_alrej_115_accept_first_observation() -> Value {
    let env = aft::sign_minimum_library_with_version(1);

    build_vector(
        "alrej-115",
        "anomaly-library-accept-first-observation",
        "Phase C.4 live-crypto accept: canonical MINIMUM library signed \
         at library_version=1, verifier clock inside the validity \
         window, anchor registered, ledger fresh. Every Stage-1..8 \
         check passes.",
        "design-final.md §3.5.1: the happy-path vector is the positive \
         control. A validator that always rejected at any stage would \
         pass every reject vector above and appear conformant — this \
         vector makes that failure mode observable.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        None,
        "accept",
        None,
        "high",
    )
}

/// alrej-116 — MINIMUM library at `library_version=7`, ledger pre-
/// seeded with HWM=5. Strict advance succeeds. Positive control
/// for the ledger-advance path that a validator hard-coding "always
/// reject at Stage 8 when pre-seeded" would fail.
fn build_alrej_116_accept_strict_advance() -> Value {
    let env = aft::sign_minimum_library_with_version(7);

    build_vector(
        "alrej-116",
        "anomaly-library-accept-strict-advance",
        "Phase C.4 live-crypto accept: MINIMUM library signed at \
         library_version=7, Stage-8 ledger pre-seeded with \
         library_id→5. Stage 8 accepts as strict advance \
         (AdvancedFrom(5)).",
        "design-final.md §3.5.1 replay-protection: the strict-greater \
         rule must actually accept strictly-greater advances. A \
         validator that silently rejected every post-seeded observation \
         would pass alrej-113 and alrej-114 while silently breaking \
         every legitimate library rotation — this vector pins the \
         positive path.",
        hex::encode(&env),
        anchor_def(aft::FIXTURE_ANOMALY_KID),
        ANOMALY_LIBRARY_ABI_VERSION,
        Some(json!({ aft::FIXTURE_ANOMALY_LIBRARY_ID: 5 })),
        "accept",
        None,
        "high",
    )
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Assemble a custom `AnomalyLibraryPayload` around a caller-supplied
/// pattern vector. Every envelope-layer field inherits from the
/// canonical fixture so only the pattern-body varies across Stage-7
/// vectors.
///
/// `patterns` is moved in and installed verbatim — callers have
/// already applied any field mutation needed to drive the target
/// Stage-7 reject.
fn build_custom_payload(patterns: Vec<ephemeral_anomaly::PatternEntry>) -> AnomalyLibraryPayload {
    AnomalyLibraryPayload {
        abi_version: ANOMALY_LIBRARY_ABI_VERSION,
        signer_kid: aft::FIXTURE_ANOMALY_KID.to_string(),
        library_id: aft::FIXTURE_ANOMALY_LIBRARY_ID.to_string(),
        library_version: 1,
        issued_at: aft::FIXTURE_ANOMALY_ISSUED_AT,
        expires_at: aft::FIXTURE_ANOMALY_EXPIRES_AT,
        patterns,
    }
}

/// Build the per-vector `trust_anchor_keys_anomaly_library` JSON
/// array. `kid` varies per vector (fixture `kid` for the common case,
/// `IMPOSTOR_OUTER_KID` for the alrej-103 signer-kid-mismatch case);
/// the pubkey is always the canonical fixture verifying key hex.
///
/// No explicit `role` override — the suite executor stamps every
/// anchor with `AnchorRole::AnomalyLibrarySigner` via
/// `build_anchor_set`.
fn anchor_def(kid: &str) -> Value {
    json!([
        {
            "kid": kid,
            "alg": "ed25519",
            "pk_hex": hex::encode(aft::fixture_anomaly_verifying_key_bytes()),
        }
    ])
}

/// Assemble the full `anomaly-library-reject`-shape vector JSON.
/// Shape matches the fields deserialised by
/// `crates/ephemeral-core/src/suites/anomaly_library.rs::AnomalyLibraryInput`.
#[allow(clippy::too_many_arguments)]
fn build_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    cose_hex: String,
    anchors: Value,
    expected_abi_version: u32,
    pre_ledger: Option<Value>,
    outcome: &str,
    reject_code: Option<&str>,
    severity: &str,
) -> Value {
    let mut input = serde_json::Map::new();
    input.insert("cose_sign1_bytes_anomaly_library".into(), json!(cose_hex));
    input.insert("trust_anchor_keys_anomaly_library".into(), anchors);
    input.insert("expected_abi_version".into(), json!(expected_abi_version));
    input.insert("current_time".into(), json!(CURRENT_TIME));
    if let Some(pl) = pre_ledger {
        input.insert("pre_ledger".into(), pl);
    }

    let expected = match (outcome, reject_code) {
        ("reject", Some(code)) => json!({ "outcome": "reject", "reject_code": code }),
        ("accept", None) => json!({ "outcome": "accept" }),
        (o, rc) => panic!(
            "build_vector: outcome={o:?} reject_code={rc:?} is not a supported combination",
        ),
    };

    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": Value::Object(input),
        "expected": expected,
        "rationale": rationale,
        "redteam_refs": ["PHASE-C4-LIVE"],
        "severity_if_failed": severity,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // `CoseSign1::from_slice` is provided by the CborSerializable trait.
    // The production builders above never reparse (they only produce
    // envelopes), so the trait is only needed inside the inline tests
    // where we decode the emitted envelope to pin a property of the
    // inner payload.
    use coset::CborSerializable;

    // ---------------- build_all shape + IDs ------------------------------------

    #[test]
    fn build_all_returns_seventeen_unique_ids() {
        let v = build_all();
        assert_eq!(v.len(), 17, "must emit exactly 17 vectors");

        let ids: Vec<_> = v.iter().map(|x| x["id"].as_str().unwrap()).collect();
        for id in &ids {
            assert!(
                id.starts_with("alrej-1"),
                "id {id} does not use the alrej-1XX namespace"
            );
        }
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 17, "ids must be unique across build_all");
    }

    #[test]
    fn build_all_produces_expected_outcomes() {
        let v = build_all();
        let expected: [(&str, &str, Option<&str>); 17] = [
            ("alrej-100", "reject", Some("anomaly-library-signature-invalid")),
            ("alrej-101", "reject", Some("anomaly-library-signature-payload-malformed")),
            ("alrej-102", "reject", Some("anomaly-library-abi-version-mismatch")),
            ("alrej-103", "reject", Some("anomaly-library-signer-kid-mismatch")),
            ("alrej-104", "reject", Some("anomaly-library-not-yet-valid")),
            ("alrej-105", "reject", Some("anomaly-library-expired")),
            ("alrej-106", "reject", Some("anomaly-library-pattern-id-duplicate")),
            ("alrej-107", "reject", Some("anomaly-library-severity-action-inconsistent")),
            ("alrej-108", "reject", Some("anomaly-library-unknown-verb-family")),
            ("alrej-109", "reject", Some("anomaly-library-firing-rule-companion-missing")),
            ("alrej-110", "reject", Some("anomaly-library-firing-rule-companion-missing")),
            ("alrej-111", "reject", Some("anomaly-library-firing-rule-companion-missing")),
            ("alrej-112", "reject", Some("anomaly-library-firing-rule-companion-missing")),
            ("alrej-113", "reject", Some("pattern-library-version-too-old")),
            ("alrej-114", "reject", Some("pattern-library-version-too-old")),
            ("alrej-115", "accept", None),
            ("alrej-116", "accept", None),
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

    // ---------------- vector-specific property pins ---------------------------
    //
    // Each property below catches a class of refactor that would
    // silently degrade the vector's meaning — for example, an
    // accidental swap of `tamper_payload_byte` for a no-op would make
    // alrej-100 still emit a "reject" expected verdict but carry an
    // un-tampered envelope that actually passes Stage 1. A conformance
    // harness running such a vector would report PASS falsely.

    #[test]
    fn alrej_100_envelope_differs_from_untampered() {
        let v = build_alrej_100_cose_verify_tampered();
        let cose_hex = v["input"]["cose_sign1_bytes_anomaly_library"]
            .as_str()
            .unwrap();
        let pristine_hex = hex::encode(aft::sign_minimum_library_with_version(1));
        assert_ne!(
            cose_hex, pristine_hex,
            "alrej-100 MUST carry a tampered envelope, not the pristine one"
        );
        // Byte length is preserved by `tamper_payload_byte` (XOR flip
        // in place) — pin that so a future rewrite that appends or
        // truncates is caught here.
        assert_eq!(
            cose_hex.len(),
            pristine_hex.len(),
            "tamper must preserve envelope byte length"
        );
    }

    #[test]
    fn alrej_101_inner_is_literal_ascii_not_cbor() {
        let v = build_alrej_101_payload_not_cbor();
        let cose_hex = v["input"]["cose_sign1_bytes_anomaly_library"]
            .as_str()
            .unwrap();
        let bytes = hex::decode(cose_hex).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&bytes)
            .expect("outer envelope must still parse as COSE_Sign1");
        let inner = sign1.payload.expect("envelope carries an inner payload");
        // The inner bytes are literal ASCII — not CBOR.
        assert_eq!(inner, b"this is not cbor");
    }

    #[test]
    fn alrej_102_signed_payload_carries_abi_two() {
        let v = build_alrej_102_abi_version_mismatch();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.abi_version, 2, "alrej-102 must sign abi_version=2");
    }

    #[test]
    fn alrej_103_inner_kid_fixture_outer_kid_impostor() {
        let v = build_alrej_103_signer_kid_mismatch();
        let cose_hex = v["input"]["cose_sign1_bytes_anomaly_library"]
            .as_str()
            .unwrap();
        let bytes = hex::decode(cose_hex).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&bytes).unwrap();
        let outer_kid =
            std::str::from_utf8(&sign1.protected.header.key_id).unwrap().to_owned();
        assert_eq!(outer_kid, IMPOSTOR_OUTER_KID, "outer kid must be impostor");

        let inner = decode_inner_payload(&v);
        assert_eq!(
            inner.signer_kid, aft::FIXTURE_ANOMALY_KID,
            "inner signer_kid must stay FIXTURE so the two diverge"
        );
        assert_ne!(outer_kid, inner.signer_kid);

        // Anchor set registers IMPOSTOR against the real fixture
        // pubkey so the outer MAC verifies — the mismatch fires
        // EXCLUSIVELY at the Stage-5 consistency check.
        let anchors = v["input"]["trust_anchor_keys_anomaly_library"]
            .as_array()
            .unwrap();
        assert_eq!(anchors[0]["kid"].as_str().unwrap(), IMPOSTOR_OUTER_KID);
    }

    #[test]
    fn alrej_104_future_issued_at() {
        let v = build_alrej_104_not_yet_valid();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.issued_at, FUTURE_ISSUED_AT);
        assert_eq!(inner.expires_at, FUTURE_EXPIRES_AT);
    }

    #[test]
    fn alrej_105_past_expires_at() {
        let v = build_alrej_105_expired();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.issued_at, PAST_ISSUED_AT);
        assert_eq!(inner.expires_at, PAST_EXPIRES_AT);
    }

    #[test]
    fn alrej_106_has_duplicate_delete_storm() {
        let v = build_alrej_106_pattern_id_duplicate();
        let inner = decode_inner_payload(&v);
        let delete_storm_count = inner
            .patterns
            .iter()
            .filter(|p| p.pattern_id == "delete-storm")
            .count();
        assert_eq!(
            delete_storm_count, 2,
            "alrej-106 MUST carry two `delete-storm` rows to drive 7a"
        );
    }

    #[test]
    fn alrej_107_has_critical_alert_pair() {
        let v = build_alrej_107_severity_action_inconsistent();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.patterns.len(), 1);
        assert!(
            matches!(inner.patterns[0].severity, Severity::Critical),
            "severity must be Critical"
        );
        assert!(
            matches!(inner.patterns[0].action, Action::Alert),
            "action must be Alert → pair violates 7b"
        );
    }

    #[test]
    fn alrej_108_uses_unknown_family_name() {
        let v = build_alrej_108_unknown_verb_family();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.patterns.len(), 1);
        match &inner.patterns[0].scope {
            ScopePredicate::IamAttachFamily { verb_family, .. } => {
                assert_eq!(verb_family, "not-a-real-family");
            }
            other => panic!("alrej-108 must use IamAttachFamily scope, got {other:?}"),
        }
    }

    #[test]
    fn alrej_109_has_empty_companions() {
        let v = build_alrej_109_no_companions_declared();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.patterns.len(), 1);
        assert!(inner.patterns[0].firing_rule_companions.is_empty());
        assert!(matches!(
            inner.patterns[0].firing_rule,
            FiringRule::FirstMatch
        ));
    }

    #[test]
    fn alrej_110_companion_name_not_in_library() {
        let v = build_alrej_110_companion_not_found();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.patterns.len(), 1);
        let companions = &inner.patterns[0].firing_rule_companions;
        assert_eq!(companions, &vec!["does-not-exist-companion".to_string()]);
        // And the companion id doesn't resolve to any pattern in the
        // library.
        assert!(!inner
            .patterns
            .iter()
            .any(|p| p.pattern_id == "does-not-exist-companion"));
    }

    #[test]
    fn alrej_111_companion_is_first_match() {
        let v = build_alrej_111_companion_not_cumulative();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.patterns.len(), 2);
        let companion = inner
            .patterns
            .iter()
            .find(|p| p.pattern_id == "delete-slow-burn")
            .expect("companion row present");
        assert!(
            matches!(companion.firing_rule, FiringRule::FirstMatch),
            "companion must be FirstMatch → fails CumulativeOverBaseline check"
        );
    }

    #[test]
    fn alrej_112_companion_window_below_multiplier() {
        let v = build_alrej_112_companion_window_too_short();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.patterns.len(), 2);
        let primary = inner
            .patterns
            .iter()
            .find(|p| p.pattern_id == "delete-storm")
            .unwrap();
        let companion = inner
            .patterns
            .iter()
            .find(|p| p.pattern_id == "delete-slow-burn")
            .unwrap();
        let primary_window = primary.window_seconds.unwrap();
        let companion_window = companion.window_seconds.unwrap();
        assert!(
            companion_window < primary_window * 10,
            "alrej-112: companion window {companion_window}s must be below 10× primary \
             window ({primary_window}s) to drive CompanionWindowTooShort"
        );
        assert!(matches!(
            companion.firing_rule,
            FiringRule::CumulativeOverBaseline
        ));
    }

    #[test]
    fn alrej_113_pre_ledger_seeds_same_version() {
        let v = build_alrej_113_library_version_replay();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.library_version, 5);
        let pre_ledger = v["input"]["pre_ledger"].as_object().unwrap();
        assert_eq!(
            pre_ledger.get(aft::FIXTURE_ANOMALY_LIBRARY_ID).unwrap(),
            5,
            "ledger must be pre-seeded at same version as envelope to drive replay"
        );
    }

    #[test]
    fn alrej_114_pre_ledger_higher_than_envelope() {
        let v = build_alrej_114_library_version_rollback();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.library_version, 3);
        let pre_ledger = v["input"]["pre_ledger"].as_object().unwrap();
        assert_eq!(
            pre_ledger.get(aft::FIXTURE_ANOMALY_LIBRARY_ID).unwrap(),
            5,
            "ledger must be pre-seeded above envelope version to drive rollback"
        );
    }

    #[test]
    fn alrej_115_has_no_pre_ledger() {
        let v = build_alrej_115_accept_first_observation();
        assert!(
            v["input"].get("pre_ledger").is_none(),
            "alrej-115 is first-observation; pre_ledger must be absent"
        );
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.library_version, 1);
    }

    #[test]
    fn alrej_116_ledger_below_envelope() {
        let v = build_alrej_116_accept_strict_advance();
        let inner = decode_inner_payload(&v);
        assert_eq!(inner.library_version, 7);
        let pre_ledger = v["input"]["pre_ledger"].as_object().unwrap();
        assert_eq!(
            pre_ledger.get(aft::FIXTURE_ANOMALY_LIBRARY_ID).unwrap(),
            5,
            "ledger HWM must be strictly less than envelope version"
        );
    }

    // ---------------- helpers --------------------------------------------------

    /// Decode the `cose_sign1_bytes_anomaly_library` hex field back
    /// into a parsed [`AnomalyLibraryPayload`]. Used by the per-vector
    /// property pins above to assert on envelope contents without
    /// re-implementing the decode path.
    fn decode_inner_payload(v: &Value) -> AnomalyLibraryPayload {
        let cose_hex = v["input"]["cose_sign1_bytes_anomaly_library"]
            .as_str()
            .expect("cose hex present");
        let bytes = hex::decode(cose_hex).expect("valid hex");
        let sign1 =
            coset::CoseSign1::from_slice(&bytes).expect("envelope parses as COSE_Sign1");
        let inner = sign1.payload.expect("inner payload present");
        ciborium::from_reader::<AnomalyLibraryPayload, _>(&inner[..])
            .expect("inner payload decodes as AnomalyLibraryPayload")
    }
}
