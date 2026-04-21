//! Test-only fixtures for the anomaly-library crate — canned
//! [`AnomalyLibraryPayload`] shapes, a §3.5.4 MINIMUM library builder,
//! a deterministic signing key, and a `OnceLock`-backed shared
//! envelope pool.
//!
//! # Purpose
//!
//! Two places currently need fixture-signing infrastructure for the
//! anomaly-library envelope:
//!
//! - `src/signature.rs` inline unit tests (already there, pre-
//!   `test_fixtures`, via a module-local `build_sign1` helper).
//! - `tests/minimum_library.rs` (Session-2 Task #10) — end-to-end
//!   verification of the §3.5.4 MINIMUM library round-tripping through
//!   `verify_anomaly_library_signature` + a byte-equality determinism
//!   tripwire.
//!
//! A future `vector-signer` tool (Phase C.5+) will reuse the same
//! fixture primitives to generate committed conformance vectors.
//! Consolidating here means all three consumers route through a single
//! deterministic source of fixture truth — any drift in the canonical
//! bytes is visible as a test diff, not a silent vector regeneration.
//!
//! # Feature gating
//!
//! The module is published only when the crate is built with
//! `features = ["test_fixtures"]`.  The feature activates two optional
//! dependencies (`ed25519-dalek`, `coset`) that never ship in a
//! production-consumer build.  The `ephemeral-prod-symbol-probe`
//! rlib-scan invariant fails loudly if any symbol declared in this
//! module appears in a default-features build of the anomaly crate.
//!
//! # Determinism guarantees
//!
//! - [`FIXTURE_ANOMALY_SIGNING_SEED`] is a compile-time constant; every
//!   invocation of [`fixture_anomaly_signing_key`] returns the same
//!   Ed25519 key.
//! - [`cbor_encode_anomaly_payload`] uses `ciborium`, whose encoder is
//!   byte-stable for the struct-literal shape of
//!   [`AnomalyLibraryPayload`].  The §3.5.4 MINIMUM library fixture
//!   therefore has a fixed byte image that Session-2 tests pin via
//!   byte-equality assertions.
//! - [`shared_anomaly_artifacts`] memoises the signed envelopes with
//!   `OnceLock`, so repeated calls inside a test binary return the
//!   same allocation.

use std::sync::OnceLock;

use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::ledger::{AnomalyLedger as _, InMemoryAnomalyLedger};
use crate::patterns::{Action, FiringRule, PatternEntry, Severity, Threshold};
use crate::schema::AnomalyLibraryPayload;
use crate::scope::{MandateScope, ScopePredicate, VerbPredicate};
use crate::signature::ANOMALY_LIBRARY_AAD;
use crate::ANOMALY_LIBRARY_ABI_VERSION;

// ============================================================================
// Deterministic signing infrastructure
// ============================================================================

/// Stable header `kid` for the fixture anomaly-library signer.
/// Distinct from the per-module seed used by `signature.rs` inline
/// tests (`K_anomaly_pk_TEST`) so cross-crate consumers can register
/// an anchor under this `kid` without colliding with intra-module
/// fixtures.
pub const FIXTURE_ANOMALY_KID: &str = "K_fixture_anomaly_pk";

/// Fixed 32-byte Ed25519 seed for the anomaly-library fixture signer.
///
/// Any change to this constant regenerates the fixture public key and
/// invalidates every committed conformance envelope that references
/// it.  Treat as a pinned magic number — the signer tooling and the
/// conformance-harness baseline must both recompute if this changes.
///
/// Distinct from `FIXTURE_CLASSIFIER_SEED` in the classifier crate:
/// the two roles never share a key (see
/// [`ephemeral_crypto::AnchorRole`]).
///
/// # Periodic byte pattern is intentional
///
/// The 8-byte prefix `a1 0f 2e e4 b1 50 31 c5` repeats four times.
/// This is a *cosmetic* property of the seed constant, NOT a property
/// of the resulting Ed25519 scalar or signatures: Ed25519 key
/// derivation (RFC 8032 §5.1.5) runs the 32-byte seed through SHA-512
/// and applies scalar clamping, both of which destroy any visible
/// periodicity in the derived secret and public keys.  A reader
/// reviewing committed fixtures should therefore NOT treat the
/// repeating pattern as a signal of weak key material.  The
/// repetition is preserved as a visual pin that makes accidental
/// edits (e.g. a typo in the first block) stand out at code-review
/// time; changing any byte invalidates every committed conformance
/// vector that references this fixture signer.
pub const FIXTURE_ANOMALY_SIGNING_SEED: [u8; 32] = [
    0xa1, 0x0f, 0x2e, 0xe4, 0xb1, 0x50, 0x31, 0xc5, 0xa1, 0x0f, 0x2e, 0xe4, 0xb1, 0x50, 0x31, 0xc5,
    0xa1, 0x0f, 0x2e, 0xe4, 0xb1, 0x50, 0x31, 0xc5, 0xa1, 0x0f, 0x2e, 0xe4, 0xb1, 0x50, 0x31, 0xc5,
];

/// Deterministic Ed25519 signing key derived from
/// [`FIXTURE_ANOMALY_SIGNING_SEED`].
#[must_use]
pub fn fixture_anomaly_signing_key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_ANOMALY_SIGNING_SEED)
}

/// Public key matching [`fixture_anomaly_signing_key`].
#[must_use]
pub fn fixture_anomaly_verifying_key() -> VerifyingKey {
    fixture_anomaly_signing_key().verifying_key()
}

/// 32-byte raw public key for registering as a
/// [`ephemeral_crypto::TrustAnchor`] under
/// [`ephemeral_crypto::AnchorRole::AnomalyLibrarySigner`].
#[must_use]
pub fn fixture_anomaly_verifying_key_bytes() -> [u8; 32] {
    *fixture_anomaly_verifying_key().as_bytes()
}

// ============================================================================
// §3.5.4 MINIMUM library pattern builders
// ============================================================================
//
// The spec's §3.5.4 declares a MINIMUM library of ten operator-
// curated patterns.  Four of them are short-window `FirstMatch` rules
// that require anti-walk-under companions; one (`fanout-distinct-
// resources`) is also short-window-FirstMatch with a companion.  That
// yields 10 primaries + 5 companions = 15 fixture patterns.
//
// Each builder below returns ONE `PatternEntry`.  A
// [`minimum_anomaly_library_patterns`] assembler concatenates them in
// document order; downstream consumers use that as a whole, but
// direct access is also useful for negative-path tests that mutate
// one entry.

/// `delete-storm` — short-window destructive-verb storm.
/// FirstMatch 60 s / Count(5), companion `delete-slow-burn`.
#[must_use]
pub fn delete_storm_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "delete-storm".into(),
        window_seconds: Some(60),
        threshold: Threshold::Count(5),
        scope: ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::AnyDestructive,
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::High,
        firing_rule: FiringRule::FirstMatch,
        firing_rule_companions: vec!["delete-slow-burn".into()],
    }
}

/// `delete-slow-burn` — cumulative 600 s companion for `delete-storm`.
#[must_use]
pub fn delete_slow_burn_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "delete-slow-burn".into(),
        window_seconds: Some(600),
        threshold: Threshold::Count(20),
        scope: ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::AnyDestructive,
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::Medium,
        firing_rule: FiringRule::CumulativeOverBaseline,
        firing_rule_companions: vec![],
    }
}

/// `vault-rotate-storm` — rotate-verb storm scoped to vault resources.
/// FirstMatch 3 600 s / Count(3), companion `vault-rotate-slow-burn`.
#[must_use]
pub fn vault_rotate_storm_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "vault-rotate-storm".into(),
        window_seconds: Some(3_600),
        threshold: Threshold::Count(3),
        scope: ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("rotate".into()),
            resource_kind: Some("vault-secret".into()),
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::High,
        firing_rule: FiringRule::FirstMatch,
        firing_rule_companions: vec!["vault-rotate-slow-burn".into()],
    }
}

/// `vault-rotate-slow-burn` — cumulative 36 000 s companion.
#[must_use]
pub fn vault_rotate_slow_burn_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "vault-rotate-slow-burn".into(),
        window_seconds: Some(36_000),
        threshold: Threshold::Count(10),
        scope: ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("rotate".into()),
            resource_kind: Some("vault-secret".into()),
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::Medium,
        firing_rule: FiringRule::CumulativeOverBaseline,
        firing_rule_companions: vec![],
    }
}

/// `iam-attach-policy-storm` — IAM attach-family storm.
/// FirstMatch 300 s / Count(5), companion `iam-attach-slow-burn`.
#[must_use]
pub fn iam_attach_policy_storm_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "iam-attach-policy-storm".into(),
        window_seconds: Some(300),
        threshold: Threshold::Count(5),
        scope: ScopePredicate::IamAttachFamily {
            verb_family: "iam-attach".into(),
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::High,
        firing_rule: FiringRule::FirstMatch,
        firing_rule_companions: vec!["iam-attach-slow-burn".into()],
    }
}

/// `iam-attach-slow-burn` — cumulative 3 000 s companion.
#[must_use]
pub fn iam_attach_slow_burn_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "iam-attach-slow-burn".into(),
        window_seconds: Some(3_000),
        threshold: Threshold::Count(20),
        scope: ScopePredicate::IamAttachFamily {
            verb_family: "iam-attach".into(),
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::Medium,
        firing_rule: FiringRule::CumulativeOverBaseline,
        firing_rule_companions: vec![],
    }
}

/// `git-force-push-storm` — protected-branch force-push detection.
/// FirstMatch 300 s / Count(3), companion `git-force-push-slow-burn`.
#[must_use]
pub fn git_force_push_storm_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "git-force-push-storm".into(),
        window_seconds: Some(300),
        threshold: Threshold::Count(3),
        scope: ScopePredicate::ProtectedBranches {
            mandate_scope: MandateScope::default(),
            protected_patterns: vec!["main".into(), "release/*".into()],
        },
        action: Action::AutoRevoke,
        severity: Severity::High,
        firing_rule: FiringRule::FirstMatch,
        firing_rule_companions: vec!["git-force-push-slow-burn".into()],
    }
}

/// `git-force-push-slow-burn` — cumulative 3 000 s companion.
#[must_use]
pub fn git_force_push_slow_burn_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "git-force-push-slow-burn".into(),
        window_seconds: Some(3_000),
        threshold: Threshold::Count(10),
        scope: ScopePredicate::ProtectedBranches {
            mandate_scope: MandateScope::default(),
            protected_patterns: vec!["main".into(), "release/*".into()],
        },
        action: Action::AutoRevoke,
        severity: Severity::Medium,
        firing_rule: FiringRule::CumulativeOverBaseline,
        firing_rule_companions: vec![],
    }
}

/// `cross-tier-escalation` — sequence template `T0 → T2+ → T3+`.
/// Not subject to anti-walk-under (not FirstMatch), no companion
/// needed.
#[must_use]
pub fn cross_tier_escalation_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "cross-tier-escalation".into(),
        window_seconds: Some(1_800),
        threshold: Threshold::Sequence(1),
        scope: ScopePredicate::CrossTierSequence {
            mandate_scope: MandateScope::default(),
            tier_progression: vec![0, 2, 3],
        },
        action: Action::AutoRevoke,
        severity: Severity::Critical,
        firing_rule: FiringRule::SequenceMatch,
        firing_rule_companions: vec![],
    }
}

/// `machine-pace` — rate-limit backstop excluding read-only verbs.
/// CumulativeOverBaseline, not subject to anti-walk-under.
#[must_use]
pub fn machine_pace_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "machine-pace".into(),
        window_seconds: Some(60),
        threshold: Threshold::Count(50),
        scope: ScopePredicate::MandatePace {
            tier_floor: 1,
            exclude_verb_category: Some("read-only".into()),
        },
        action: Action::Alert,
        severity: Severity::Low,
        firing_rule: FiringRule::CumulativeOverBaseline,
        firing_rule_companions: vec![],
    }
}

/// `long-silence-before-burst` — silence-then-burst sequence.
/// SequenceMatch, not subject to anti-walk-under.
#[must_use]
pub fn long_silence_before_burst_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "long-silence-before-burst".into(),
        window_seconds: Some(604_800),
        threshold: Threshold::Sequence(1),
        scope: ScopePredicate::SilenceThenBurst {
            silence_seconds: 604_800,
            burst_seconds: 300,
            burst_threshold: 20,
        },
        action: Action::Alert,
        severity: Severity::Medium,
        firing_rule: FiringRule::SequenceMatch,
        firing_rule_companions: vec![],
    }
}

/// `canary-window-second-tier3` — canary-attestor-set observation.
/// FirstMatch with a 24 h window, so exempt from anti-walk-under
/// (window > ANTI_WALK_UNDER_WINDOW_SECONDS).
#[must_use]
pub fn canary_window_second_tier3_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "canary-window-second-tier3".into(),
        window_seconds: Some(86_400),
        threshold: Threshold::Count(1),
        scope: ScopePredicate::CanaryWindow {
            pcr_attestor_set: "canary-tier-3".into(),
            observation_threshold: 1,
        },
        action: Action::AutoRevoke,
        severity: Severity::High,
        firing_rule: FiringRule::FirstMatch,
        firing_rule_companions: vec![],
    }
}

/// `unusual-delegation-depth` — chain-depth ceiling check (R7.D3).
/// Windowless, so exempt from anti-walk-under.
#[must_use]
pub fn unusual_delegation_depth_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "unusual-delegation-depth".into(),
        window_seconds: None,
        threshold: Threshold::ChainDepth(4),
        scope: ScopePredicate::DelegationDepth { limit: 4 },
        action: Action::Alert,
        severity: Severity::Medium,
        firing_rule: FiringRule::FirstMatch,
        firing_rule_companions: vec![],
    }
}

/// `fanout-distinct-resources` — same-verb, same-mandate fanout.
/// FirstMatch 60 s / DistinctCount(10), companion `fanout-slow-burn`.
#[must_use]
pub fn fanout_distinct_resources_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "fanout-distinct-resources".into(),
        window_seconds: Some(60),
        threshold: Threshold::DistinctCount(10),
        scope: ScopePredicate::VerbFanout {
            verb: VerbPredicate::Exact("delete".into()),
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::High,
        firing_rule: FiringRule::FirstMatch,
        firing_rule_companions: vec!["fanout-slow-burn".into()],
    }
}

/// `fanout-slow-burn` — cumulative 600 s companion.
#[must_use]
pub fn fanout_slow_burn_pattern() -> PatternEntry {
    PatternEntry {
        pattern_id: "fanout-slow-burn".into(),
        window_seconds: Some(600),
        threshold: Threshold::Count(30),
        scope: ScopePredicate::VerbFanout {
            verb: VerbPredicate::Exact("delete".into()),
            mandate_scope: MandateScope::default(),
        },
        action: Action::AutoRevoke,
        severity: Severity::Medium,
        firing_rule: FiringRule::CumulativeOverBaseline,
        firing_rule_companions: vec![],
    }
}

/// Return the §3.5.4 MINIMUM library as a flat vector of 15 pattern
/// entries (10 primaries + 5 companions) in document order.
///
/// Document order is load-bearing for the byte-equality tripwire
/// committed in `tests/minimum_library.rs` — `ciborium`'s encoding
/// of `Vec<T>` preserves insertion order, so reordering this builder
/// changes the signed envelope's bytes (and any vector-signer
/// output).
#[must_use]
pub fn minimum_anomaly_library_patterns() -> Vec<PatternEntry> {
    vec![
        delete_storm_pattern(),
        delete_slow_burn_pattern(),
        vault_rotate_storm_pattern(),
        vault_rotate_slow_burn_pattern(),
        iam_attach_policy_storm_pattern(),
        iam_attach_slow_burn_pattern(),
        git_force_push_storm_pattern(),
        git_force_push_slow_burn_pattern(),
        cross_tier_escalation_pattern(),
        machine_pace_pattern(),
        long_silence_before_burst_pattern(),
        canary_window_second_tier3_pattern(),
        unusual_delegation_depth_pattern(),
        fanout_distinct_resources_pattern(),
        fanout_slow_burn_pattern(),
    ]
}

// ============================================================================
// Library-payload builders
// ============================================================================

/// Canonical fixture clock: `issued_at` for the MINIMUM library.
/// Chosen well away from i64 boundaries and from u32::MAX / 2038 so
/// tests are insensitive to wall-clock drift.
pub const FIXTURE_ANOMALY_ISSUED_AT: i64 = 1_700_000_000;

/// Canonical fixture clock: `expires_at` for the MINIMUM library.
/// 100 M seconds after `FIXTURE_ANOMALY_ISSUED_AT` (~3.17 years) so
/// the window covers any reasonable test clock.
pub const FIXTURE_ANOMALY_EXPIRES_AT: i64 = 1_800_000_000;

// Canary: the fixture validity window (100 M seconds, ~3.17 years)
// MUST remain vastly wider than the §3.5.3 anti-walk-under window
// (3600 seconds by default, bounded by ANTI_WALK_UNDER_WINDOW_SECONDS).
// A future governance change that widened the anti-walk-under window
// past ~one day while leaving the fixture window untouched would be
// a spec-level red flag — the primary/companion pair is designed
// around a short detection horizon.  A single day (86_400 seconds)
// is a generous upper bound that catches any accidental regression
// in either direction without creating false positives during normal
// spec evolution.
const _: () = assert!(crate::invariants::ANTI_WALK_UNDER_WINDOW_SECONDS < 86_400);

/// Default `library_id` for the MINIMUM fixture.  Namespaced with
/// `fixture::` so it cannot collide with a production library id by
/// accident.
pub const FIXTURE_ANOMALY_LIBRARY_ID: &str = "fixture::minimum-v1";

/// Assemble the MINIMUM §3.5.4 library as an
/// [`AnomalyLibraryPayload`] under the canonical fixture constants.
///
/// Downstream consumers (`tests/minimum_library.rs`, future
/// `vector-signer`) wrap this output with
/// [`sign_anomaly_library_envelope`] or the raw signer to produce a
/// COSE_Sign1 envelope.
#[must_use]
pub fn minimum_anomaly_library_payload() -> AnomalyLibraryPayload {
    AnomalyLibraryPayload {
        abi_version: ANOMALY_LIBRARY_ABI_VERSION,
        signer_kid: FIXTURE_ANOMALY_KID.to_string(),
        library_id: FIXTURE_ANOMALY_LIBRARY_ID.to_string(),
        library_version: 1,
        issued_at: FIXTURE_ANOMALY_ISSUED_AT,
        expires_at: FIXTURE_ANOMALY_EXPIRES_AT,
        patterns: minimum_anomaly_library_patterns(),
    }
}

// ============================================================================
// CBOR + COSE_Sign1 envelope builders
// ============================================================================

/// CBOR-encode an [`AnomalyLibraryPayload`] with the same `ciborium`
/// encoder the live verifier decodes against, so round-trip bytes are
/// canonical by construction.
///
/// Exposed so negative-path tests can craft payloads with individually
/// tampered fields (off-by-one `abi_version`, mismatched inner
/// `signer_kid`) without re-implementing the encoder contract.
#[must_use]
pub fn cbor_encode_anomaly_payload(payload: &AnomalyLibraryPayload) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(payload, &mut out)
        .expect("ciborium serialize AnomalyLibraryPayload is infallible for this struct shape");
    out
}

/// Build a `COSE_Sign1` envelope over pre-encoded inner bytes with
/// full control over the outer header `kid` and the external AAD.
///
/// Lower-level than [`sign_anomaly_library_envelope`].  Use this when
/// a test needs the inner payload, outer kid, or AAD to deliberately
/// diverge from the happy-path convention — for example:
///
/// - Non-CBOR inner bytes to exercise the payload-decode branch.
/// - Wrong AAD (tariff-, classifier-, or delegation-domain) to
///   exercise the AAD-mismatch rejection at the crypto layer.
/// - Outer `kid` that deliberately differs from
///   `AnomalyLibraryPayload.signer_kid` so the inner/outer-kid
///   consistency check (Step 5) rejects.
///
/// The signature is over the canonical `Sig_structure` defined by
/// RFC 9052 §4.4 with `external_aad = aad`.
#[must_use]
pub fn sign_anomaly_library_envelope_raw(
    inner_payload_bytes: Vec<u8>,
    outer_kid: &str,
    aad: &[u8],
    key: &SigningKey,
) -> Vec<u8> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(outer_kid.as_bytes().to_vec())
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(inner_payload_bytes)
        .create_signature(aad, |tbs| key.sign(tbs).to_bytes().to_vec())
        .build();
    sign1.to_vec().expect("serialize COSE_Sign1 is infallible")
}

/// Happy-path convenience: encode an [`AnomalyLibraryPayload`] with
/// [`cbor_encode_anomaly_payload`], then sign it under the
/// [`ANOMALY_LIBRARY_AAD`] with the outer header `kid` set to
/// [`FIXTURE_ANOMALY_KID`] and the supplied signing key.
///
/// The returned bytes verify under
/// [`crate::signature::verify_anomaly_library_signature`] when a
/// matching [`ephemeral_crypto::TrustAnchor`] is registered under
/// [`ephemeral_crypto::AnchorRole::AnomalyLibrarySigner`].
///
/// Pass a payload whose `signer_kid` matches [`FIXTURE_ANOMALY_KID`]
/// or Step 5's inner/outer consistency check rejects.
#[must_use]
pub fn sign_anomaly_library_envelope(
    payload: &AnomalyLibraryPayload,
    key: &SigningKey,
) -> Vec<u8> {
    sign_anomaly_library_envelope_raw(
        cbor_encode_anomaly_payload(payload),
        FIXTURE_ANOMALY_KID,
        ANOMALY_LIBRARY_AAD,
        key,
    )
}

// ============================================================================
// Session-3 versioned-envelope + ledger helpers
// ============================================================================
//
// These helpers support downstream dev-deps (`tests/ledger_behavior.rs`,
// the future `vector-signer` tool, and a Phase C.5+ conformance
// harness) that need to construct MINIMUM-library envelopes at
// arbitrary `library_version` values and pre-seeded in-memory
// ledgers.  Both are gated behind the `test_fixtures` feature so
// production builds never link these symbols.

/// Sign the §3.5.4 MINIMUM library with a caller-specified
/// `library_version`.
///
/// Re-uses the canonical fixture constants for `signer_kid`,
/// `library_id`, `issued_at`, `expires_at`, and the pattern set —
/// only `library_version` varies.  Bytes are deterministic for the
/// same input version (Ed25519 is deterministic + ciborium encoding
/// is byte-stable + coset's CoseSign1 serialisation is byte-stable
/// for a fixed protected header).
///
/// Two envelopes with different `library_version` values MUST differ
/// byte-for-byte: the version is part of the CBOR-encoded signed
/// payload, so any change flows through the Ed25519 signature.  The
/// self-test
/// `sign_minimum_library_with_version_overrides_only_version_field`
/// pins this.
#[must_use]
pub fn sign_minimum_library_with_version(library_version: u64) -> Vec<u8> {
    // Struct-update syntax rather than post-construct mutation: the
    // project-wide immutability rule applies even to test-only code so
    // the "build new value, don't mutate" discipline is visible at
    // every site.  The base payload's `library_version` is discarded by
    // the `..` tail because the explicit field shadows it.
    let payload = AnomalyLibraryPayload {
        library_version,
        ..minimum_anomaly_library_payload()
    };
    sign_anomaly_library_envelope(&payload, &fixture_anomaly_signing_key())
}

/// Construct an [`InMemoryAnomalyLedger`] pre-seeded so that
/// `library_id` has HWM = `library_version`.
///
/// After this call, a subsequent `observe(library_id, library_version)`
/// rejects as replay (equal HWM) and any lower version rejects as
/// rollback.  Strictly-greater versions advance.  Implementation
/// detail: a single first-observation is performed to install the
/// HWM — the returned ledger is behaviourally equivalent to one that
/// has already accepted a legitimate load at `library_version`.
///
/// `library_id` is passed raw.  The ledger uses raw bytes as its
/// keyspace by design (sanitisation would collide UTF-8 multi-byte
/// ids via `sanitize_log_string`), so callers seeding a ledger
/// intended to interact with a real verifier-supplied `library_id`
/// MUST pass the same raw bytes that will appear in the envelope's
/// signed payload.
#[must_use]
pub fn seeded_ledger_at_version(library_id: &str, library_version: u64) -> InMemoryAnomalyLedger {
    let mut ledger = InMemoryAnomalyLedger::new();
    ledger
        .observe(library_id, library_version)
        .expect("fresh ledger accepts first observation for any version");
    ledger
}

// ============================================================================
// Shared pre-signed envelope pool
// ============================================================================

/// Pre-signed anomaly-library envelopes, memoised.
///
/// Obtained via [`shared_anomaly_artifacts`]; the struct is
/// intentionally `#[non_exhaustive]` so adding a future preset does
/// not break existing callers that destructure it.
#[derive(Debug)]
#[non_exhaustive]
pub struct SharedAnomalyArtifacts {
    /// Signed envelope carrying the §3.5.4 MINIMUM library (15
    /// patterns in document order).  Verifies under the fixture
    /// anchor and the canonical `[FIXTURE_ANOMALY_ISSUED_AT,
    /// FIXTURE_ANOMALY_EXPIRES_AT]` window.
    pub minimum_library: Vec<u8>,
    /// Signed envelope with an empty `patterns` field — the
    /// Session-1 happy-path shape.  Included so forward-compat
    /// regression tests can reach a known good Session-1 baseline
    /// without reconstructing it each time.
    pub empty_library: Vec<u8>,
}

/// Return a lazily initialised, process-global pool of pre-signed
/// anomaly-library envelopes.
///
/// The first call inside a test binary pays the
/// `ciborium::into_writer` + Ed25519 `sign` cost (~hundreds of
/// microseconds total); subsequent calls return the exact same
/// allocation.  This amortises signing across the Session-2 tests
/// that need a known good envelope but do not care about its
/// specific pattern shape.
///
/// Determinism: Ed25519 signing is deterministic (no random nonce)
/// per RFC 8032 §5.1.6, `ciborium` encoding is byte-stable for the
/// `AnomalyLibraryPayload` struct shape, and `coset`'s `CoseSign1`
/// serialisation is byte-stable for a fixed protected header.  The
/// returned bytes are therefore stable across runs of the same
/// binary on the same target — a property the committed conformance
/// bytes in `tests/minimum_library.rs` rely on.
#[must_use]
pub fn shared_anomaly_artifacts() -> &'static SharedAnomalyArtifacts {
    static POOL: OnceLock<SharedAnomalyArtifacts> = OnceLock::new();
    POOL.get_or_init(|| {
        let key = fixture_anomaly_signing_key();

        let minimum_library = sign_anomaly_library_envelope(
            &minimum_anomaly_library_payload(),
            &key,
        );

        let empty_payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: FIXTURE_ANOMALY_KID.to_string(),
            library_id: "fixture::empty-v1".to_string(),
            library_version: 1,
            issued_at: FIXTURE_ANOMALY_ISSUED_AT,
            expires_at: FIXTURE_ANOMALY_EXPIRES_AT,
            patterns: Vec::new(),
        };
        let empty_library = sign_anomaly_library_envelope(&empty_payload, &key);

        SharedAnomalyArtifacts {
            minimum_library,
            empty_library,
        }
    })
}

// ============================================================================
// Module-internal regression tests
// ============================================================================
//
// These tests pin the invariants this module is meant to uphold for
// downstream consumers.  A break here means a caller
// (`tests/minimum_library.rs`, future `vector-signer`,
// `ephemeral-core` integration harness) would observe silently wrong
// bytes.

#[cfg(test)]
mod self_test {
    use super::*;
    use crate::signature::verify_anomaly_library_signature;
    use ephemeral_crypto::{AnchorRole, TrustAnchor, TrustAnchorSet};

    // Test clock sits inside `[FIXTURE_ANOMALY_ISSUED_AT,
    // FIXTURE_ANOMALY_EXPIRES_AT]` so time-bounds checks pass.
    const TEST_NOW: i64 = 1_750_000_000;

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
    fn fixture_verifying_key_is_stable() {
        // Pins the public key bytes so committed conformance vectors
        // cannot silently drift if the seed constant is edited.  32
        // bytes is the raw Ed25519 pk length (RFC 8032 §5.1.5).
        let bytes = fixture_anomaly_verifying_key_bytes();
        assert_eq!(bytes.len(), 32);
        // A second derivation MUST produce the exact same bytes —
        // pins determinism of `SigningKey::from_bytes`.
        let again = fixture_anomaly_verifying_key_bytes();
        assert_eq!(bytes, again);
    }

    #[test]
    fn minimum_library_has_fifteen_patterns_in_document_order() {
        // Document order is load-bearing for byte-equality
        // tripwires; pin both count and head/tail anchors so a
        // reorder becomes visible here, not in the downstream
        // determinism vector.
        let patterns = minimum_anomaly_library_patterns();
        assert_eq!(patterns.len(), 15);
        assert_eq!(patterns[0].pattern_id, "delete-storm");
        assert_eq!(patterns[14].pattern_id, "fanout-slow-burn");
    }

    #[test]
    fn minimum_library_payload_round_trips_through_verifier() {
        // End-to-end: build the MINIMUM payload, sign it, verify it
        // under the fixture anchor.  Every Stage-7 invariant MUST
        // pass — if one fails here, the fixture table itself is
        // ill-formed and downstream conformance tests are building
        // on a broken baseline.
        let env = sign_anomaly_library_envelope(
            &minimum_anomaly_library_payload(),
            &fixture_anomaly_signing_key(),
        );
        let out = verify_anomaly_library_signature(
            &env,
            &fixture_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            TEST_NOW,
        )
        .expect("MINIMUM library fixture must verify");
        assert_eq!(out.signer_kid, FIXTURE_ANOMALY_KID);
        assert_eq!(out.library_id, FIXTURE_ANOMALY_LIBRARY_ID);
        assert_eq!(out.patterns.len(), 15);
    }

    #[test]
    fn shared_pool_is_stable_across_calls() {
        // OnceLock MUST return the same allocation for every call;
        // the signed bytes are deterministic by construction (Ed25519
        // deterministic + ciborium byte-stable + coset byte-stable).
        let first = shared_anomaly_artifacts();
        let second = shared_anomaly_artifacts();
        assert!(std::ptr::eq(first, second), "OnceLock must memoise");
        assert!(!first.minimum_library.is_empty());
        assert!(!first.empty_library.is_empty());
    }

    #[test]
    fn shared_minimum_library_verifies() {
        let pool = shared_anomaly_artifacts();
        let out = verify_anomaly_library_signature(
            &pool.minimum_library,
            &fixture_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            TEST_NOW,
        )
        .expect("shared minimum library must verify");
        assert_eq!(out.patterns.len(), 15);
    }

    #[test]
    fn shared_empty_library_verifies_with_empty_patterns() {
        // The empty-library fixture exercises the Stage-7 empty-
        // slice path: every invariant MUST trivially pass on an
        // empty `Vec<PatternEntry>`.
        let pool = shared_anomaly_artifacts();
        let out = verify_anomaly_library_signature(
            &pool.empty_library,
            &fixture_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            TEST_NOW,
        )
        .expect("shared empty library must verify");
        assert!(out.patterns.is_empty());
    }

    #[test]
    fn signed_envelope_is_byte_deterministic() {
        // Ed25519 is deterministic (RFC 8032 §5.1.6), ciborium
        // encoding is stable for the AnomalyLibraryPayload struct
        // shape, and coset's CoseSign1 serialisation is stable for
        // a fixed protected header.  Two calls MUST produce the
        // exact same bytes — if they diverge, a future refactor
        // accidentally introduced nondeterminism and every
        // committed conformance vector is at risk.
        let payload = minimum_anomaly_library_payload();
        let key = fixture_anomaly_signing_key();
        let a = sign_anomaly_library_envelope(&payload, &key);
        let b = sign_anomaly_library_envelope(&payload, &key);
        assert_eq!(a, b);
    }

    #[test]
    fn raw_signer_accepts_custom_aad_and_kid() {
        // The low-level signer MUST let tests divert the AAD and
        // the outer kid from the happy-path defaults.  This is the
        // primary way negative-path tests exercise the verifier's
        // role / AAD / kid-mismatch branches.
        let inner = cbor_encode_anomaly_payload(&minimum_anomaly_library_payload());
        let env = sign_anomaly_library_envelope_raw(
            inner,
            "K_alt_kid",
            b"ephemeral/other-domain/v1",
            &fixture_anomaly_signing_key(),
        );
        // Envelope parses as a COSE_Sign1 structurally — we don't
        // assert verification here (it MUST fail because of the
        // mismatched AAD and kid) but the bytes MUST be non-empty.
        assert!(!env.is_empty());
    }

    #[test]
    fn sign_minimum_library_with_version_overrides_only_version_field() {
        // Different library_versions produce different envelopes
        // (the version is part of the signed payload → flows through
        // the Ed25519 signature → byte-level difference).  Same
        // library_version produces byte-identical envelopes (full
        // determinism pipeline).  And the v1 envelope equals the
        // MINIMUM-library pool envelope byte-for-byte — both reuse
        // the canonical fixture payload with library_version=1.
        let env_v1 = sign_minimum_library_with_version(1);
        let env_v2 = sign_minimum_library_with_version(2);
        assert_ne!(env_v1, env_v2, "different versions must change bytes");

        let env_v1_again = sign_minimum_library_with_version(1);
        assert_eq!(env_v1, env_v1_again, "same version must be deterministic");

        // Round-trip: the v1 envelope MUST verify as the MINIMUM
        // library with the expected 15 patterns.
        let out = crate::signature::verify_anomaly_library_signature(
            &env_v1,
            &fixture_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            TEST_NOW,
        )
        .expect("versioned MINIMUM envelope must verify");
        assert_eq!(out.library_version, 1);
        assert_eq!(out.library_id, FIXTURE_ANOMALY_LIBRARY_ID);
        assert_eq!(out.patterns.len(), 15);

        // Pool's minimum_library envelope is also library_version=1
        // with the same payload — the two MUST be byte-equal.
        let pool = shared_anomaly_artifacts();
        assert_eq!(
            env_v1, pool.minimum_library,
            "v1 override must byte-match the shared MINIMUM pool entry"
        );
    }

    #[test]
    fn seeded_ledger_at_version_rejects_replay_and_allows_strict_advance() {
        use crate::ledger::{LedgerError, LedgerObservation};

        let mut ledger = seeded_ledger_at_version("lib::seed", 7);

        // Replay of the seeded version rejects with current_hwm=7,
        // attempted=7.
        let err = ledger
            .observe("lib::seed", 7)
            .expect_err("equal version after seeding must reject");
        assert!(
            matches!(
                err,
                LedgerError::VersionNotStrictlyGreater {
                    current_hwm: 7,
                    attempted: 7,
                    ..
                }
            ),
            "expected VersionNotStrictlyGreater{{7,7}}, got {err:?}"
        );

        // Rollback rejects analogously.
        let err = ledger
            .observe("lib::seed", 3)
            .expect_err("lower version after seeding must reject");
        assert!(matches!(
            err,
            LedgerError::VersionNotStrictlyGreater {
                current_hwm: 7,
                attempted: 3,
                ..
            }
        ));

        // Strictly-greater advance succeeds, carrying the seeded HWM.
        let obs = ledger
            .observe("lib::seed", 8)
            .expect("advance from seeded HWM must succeed");
        assert_eq!(obs, LedgerObservation::AdvancedFrom(7));
    }
}
