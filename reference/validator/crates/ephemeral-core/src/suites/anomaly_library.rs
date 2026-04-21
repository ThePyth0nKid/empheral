//! Anomaly-library signature-verification suite — §3.5 (Phase C.4).
//!
//! Dispatches conformance vectors of `vector_suite:
//! "anomaly-library-reject"` into
//! [`ephemeral_anomaly::verify_anomaly_library_signature_with_ledger`].
//! Always uses the `_with_ledger` entry point — a fresh
//! [`InMemoryAnomalyLedger`] is constructed when the vector omits
//! `pre_ledger`, so Stages 1–7 behave exactly as under the stateless
//! entry point while Session-3 (Stage 8) replay-monotonicity vectors
//! get the same code path without a separate dispatch branch.
//!
//! ## Wire-code mapping
//!
//! [`wire_code`] is the externally visible contract between this
//! suite and downstream conformance harnesses.  Changes here break
//! third-party implementations and MUST be co-versioned with a bump
//! to the `schema_version` field of
//! `conformance/anomaly-library-reject.json`.
//!
//! ### §3.5.1 spec-literal exception
//!
//! Eleven of the twelve [`AnomalyLibError`] variants map into a
//! kebab-case wire string prefixed `anomaly-library-*`, matching the
//! envelope-domain convention used by `tariff-*`, `classifier-*`, and
//! `delegation-*` suites.
//!
//! The twelfth, [`AnomalyLibError::LibraryVersionTooOld`], maps to the
//! spec-literal string `pattern-library-version-too-old` per §3.5.1.
//! The spec names this reject code explicitly and the crate-internal
//! `Display` already embeds it verbatim in error text; aligning the
//! wire string preserves a single ground-truth identifier for the
//! replay-rejection path.  Convention yields to spec where the spec
//! is explicit.
//!
//! ### `#[non_exhaustive]` wildcard
//!
//! [`AnomalyLibError`] is `#[non_exhaustive]`, so a future verifier
//! variant introduced upstream MUST not cause a compile failure in
//! this crate.  The wildcard arm keeps the match exhaustive and
//! buckets unknown variants into the sentinel
//! `anomaly-library-reject-unknown-variant` — a stable wire code
//! signalling "downstream harness upgrade required before trusting
//! this reject's semantics" rather than a silent fall-through that
//! could let an added variant leak into a pre-existing wire bucket.
//! `#[allow(unreachable_patterns)]` suppresses the within-crate
//! Clippy warning without masking the forward-compat guarantee.

use std::collections::BTreeMap;

use ephemeral_anomaly::{
    verify_anomaly_library_signature_with_ledger, AnomalyLedger as _, AnomalyLibError,
    InMemoryAnomalyLedger, VerifiedAnomalyLibrarySignature,
};
use ephemeral_crypto::AnchorRole;
use serde::Deserialize;
use time::OffsetDateTime;

use super::crypto_support::{build_anchor_set, TrustAnchorKeyDef};
use crate::types::{Outcome, ValidationOutcome, Vector};

/// Deserialized shape of a `vector.input` block for this suite.
///
/// The envelope-type suffix (`_anomaly_library`) on each hex-carrying
/// field mirrors the Phase C.3-C convention (`*_classifier`), leaving
/// room for a future multi-envelope vector that composes anomaly-
/// library verification with another domain (e.g. a delegation chain
/// rooted in the same ceremony) without a field-name collision.
#[derive(Debug, Deserialize)]
struct AnomalyLibraryInput {
    /// Hex-encoded COSE_Sign1 envelope bytes.  Decoded at execute-time;
    /// a decode failure short-circuits to a harness `Fail` rather than
    /// a wire-coded reject, because hex-corrupt input is always a
    /// vector-authoring bug — a real envelope from a signer tool is
    /// hex-clean by construction.
    cose_sign1_bytes_anomaly_library: String,

    /// Vector-supplied trust anchors.  Each def carries `kid`, `alg`,
    /// `pk_hex`, and an optional `role` override; anchors that omit
    /// `role` inherit [`AnchorRole::AnomalyLibrarySigner`] from this
    /// suite's default.  Shared helper builds the
    /// [`ephemeral_crypto::TrustAnchorSet`].
    trust_anchor_keys_anomaly_library: Vec<TrustAnchorKeyDef>,

    /// Validator-side ABI-version expectation, passed through to the
    /// verifier's `expected_abi_version` argument.  Almost always
    /// `1` for Phase C.4; a value of `2`+ exercises the
    /// [`AnomalyLibError::AbiVersionMismatch`] branch.
    expected_abi_version: u32,

    /// RFC-3339 timestamp used by the verifier as "now" for the
    /// not-yet-valid / expired time-bound checks.  Encoded as a string
    /// (rather than Unix seconds) to match the rest of the conformance
    /// suite's time conventions.
    current_time: String,

    /// Optional pre-seeded replay-ledger state: `library_id → HWM`.
    /// Raw `library_id` bytes as keys — matches the
    /// [`InMemoryAnomalyLedger`] keyspace contract (§3.5.1 raw bytes,
    /// not `sanitize_log_string`-lossy).  Empty map (or absent) means
    /// the vector runs against a fresh ledger, so the verifier's
    /// Stage 8 always sees a [`ephemeral_anomaly::LedgerObservation::FirstObservation`]
    /// and S1/S2 reject-codes surface unshadowed by replay gating.
    #[serde(default)]
    pre_ledger: BTreeMap<String, u64>,
}

/// Entry point called by [`crate::runner::run_file`] for every vector
/// in a `vector_suite: "anomaly-library-reject"` file.
///
/// See the module docblock for the design of the dispatch and the
/// wire-code mapping contract.
pub fn execute(vector: &Vector) -> ValidationOutcome {
    let input: AnomalyLibraryInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-library vector {} input deserialize: {e}",
                    vector.id
                ),
            };
        }
    };

    let anchors = match build_anchor_set(
        &input.trust_anchor_keys_anomaly_library,
        AnchorRole::AnomalyLibrarySigner,
    ) {
        Ok(a) => a,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-library vector {} anchor build: {e}",
                    vector.id
                ),
            };
        }
    };

    let cose_bytes = match hex::decode(&input.cose_sign1_bytes_anomaly_library) {
        Ok(b) => b,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-library vector {} cose_sign1_bytes_anomaly_library hex decode: {e}",
                    vector.id
                ),
            };
        }
    };

    let now_unix = match parse_iso_seconds(&input.current_time) {
        Ok(n) => n,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-library vector {} current_time not RFC-3339 ({}): {e}",
                    vector.id, input.current_time
                ),
            };
        }
    };

    // Seed the in-memory ledger via the public `observe` API rather
    // than by reaching into its internal HashMap.  BTreeMap iteration
    // is insertion-order-stable for the JSON-deserialised map (serde
    // preserves the source object's key order under the default
    // `preserve_order` setting), and the `InMemoryAnomalyLedger`'s
    // first-observation-always-accepts semantic makes each loop
    // iteration a deterministic no-conflict advance for the
    // `BTreeMap::insert`-deduplicated keyset.  The `observe` call is
    // still surfaced as a `Fail` (not `.expect`) so that a future
    // ledger backend injected into this executor — or a vector that
    // accidentally seeds a library twice through some path we have
    // not anticipated — records a harness failure instead of aborting
    // the whole runner process.  The raw `library_id` is NOT echoed
    // into the reason string because `LedgerError::Display` may
    // itself embed attacker-controlled bytes (see §3.5 — raw
    // `library_id` is opaque to the executor); `vector.id` is the
    // safe stable identifier.
    let mut ledger = InMemoryAnomalyLedger::new();
    for (library_id, hwm) in &input.pre_ledger {
        if let Err(e) = ledger.observe(library_id, *hwm) {
            return ValidationOutcome::Fail {
                reason: format!(
                    "anomaly-library vector {} pre_ledger seed failed: {e}",
                    vector.id
                ),
            };
        }
    }

    let result = verify_anomaly_library_signature_with_ledger(
        &cose_bytes,
        &anchors,
        input.expected_abi_version,
        now_unix,
        &mut ledger,
    );

    render_outcome(vector, result)
}

/// Map an [`AnomalyLibError`] onto its kebab-case wire string.
///
/// The mapping is the suite's external contract; see the module
/// docblock (wire-code section) for the §3.5.1 spec-literal exception
/// on [`AnomalyLibError::LibraryVersionTooOld`] and the
/// `#[non_exhaustive]` wildcard policy.
#[must_use]
pub(crate) fn wire_code(err: &AnomalyLibError) -> &'static str {
    // All twelve currently-declared variants are enumerated; the
    // wildcard arm exists for forward-compat against a future
    // `#[non_exhaustive]` variant addition.  Clippy sees the wildcard
    // as unreachable today and the `allow` suppresses that — without
    // the wildcard, an upstream variant addition would fail this
    // crate's build, defeating the point of the `#[non_exhaustive]`
    // attribute.
    #[allow(unreachable_patterns)]
    match err {
        AnomalyLibError::CoseVerifyFailed => "anomaly-library-signature-invalid",
        AnomalyLibError::PayloadDecodeFailed => "anomaly-library-signature-payload-malformed",
        AnomalyLibError::AbiVersionMismatch { .. } => "anomaly-library-abi-version-mismatch",
        AnomalyLibError::SignerKidMismatch { .. } => "anomaly-library-signer-kid-mismatch",
        AnomalyLibError::NotYetValid { .. } => "anomaly-library-not-yet-valid",
        AnomalyLibError::Expired { .. } => "anomaly-library-expired",
        AnomalyLibError::PatternIdDuplicate { .. } => "anomaly-library-pattern-id-duplicate",
        AnomalyLibError::SeverityActionInconsistent { .. } => {
            "anomaly-library-severity-action-inconsistent"
        }
        AnomalyLibError::UnknownVerbFamily { .. } => "anomaly-library-unknown-verb-family",
        AnomalyLibError::FiringRuleCompanionMissing { .. } => {
            "anomaly-library-firing-rule-companion-missing"
        }
        // §3.5.1 spec-literal wire string — see module docblock.
        AnomalyLibError::LibraryVersionTooOld { .. } => "pattern-library-version-too-old",
        AnomalyLibError::LedgerFailure { .. } => "anomaly-library-ledger-failure",
        _ => "anomaly-library-reject-unknown-variant",
    }
}

fn parse_iso_seconds(s: &str) -> Result<i64, time::error::Parse> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|dt| dt.unix_timestamp())
}

fn render_outcome(
    vector: &Vector,
    result: Result<VerifiedAnomalyLibrarySignature, AnomalyLibError>,
) -> ValidationOutcome {
    let expected_code = vector.expected.reject_code.as_deref().unwrap_or("");
    match (vector.expected.outcome, result) {
        (Outcome::Accept, Ok(_)) => ValidationOutcome::Pass,
        (Outcome::Accept, Err(e)) => ValidationOutcome::Fail {
            reason: format!("expected accept, got reject={}", wire_code(&e)),
        },
        (Outcome::Reject, Ok(_)) => ValidationOutcome::Fail {
            reason: format!("expected reject={expected_code}, got accept"),
        },
        (Outcome::Reject, Err(e)) => {
            let got = wire_code(&e);
            if got == expected_code {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!("reject-code mismatch: expected={expected_code} got={got}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_anomaly::FiringCompanionFailure;

    // ---------------- wire_code mapping (12 variants + wildcard) ------------

    #[test]
    fn wire_code_maps_cose_verify_failed_to_signature_invalid() {
        assert_eq!(
            wire_code(&AnomalyLibError::CoseVerifyFailed),
            "anomaly-library-signature-invalid"
        );
    }

    #[test]
    fn wire_code_maps_payload_decode_failed_to_signature_payload_malformed() {
        assert_eq!(
            wire_code(&AnomalyLibError::PayloadDecodeFailed),
            "anomaly-library-signature-payload-malformed"
        );
    }

    #[test]
    fn wire_code_maps_abi_mismatch_to_abi_version_mismatch() {
        assert_eq!(
            wire_code(&AnomalyLibError::AbiVersionMismatch {
                expected: 1,
                signed: 2,
            }),
            "anomaly-library-abi-version-mismatch"
        );
    }

    #[test]
    fn wire_code_maps_signer_kid_mismatch_to_signer_kid_mismatch() {
        assert_eq!(
            wire_code(&AnomalyLibError::SignerKidMismatch {
                outer: "K_outer".into(),
                signed: "K_inner".into(),
            }),
            "anomaly-library-signer-kid-mismatch"
        );
    }

    #[test]
    fn wire_code_maps_not_yet_valid() {
        assert_eq!(
            wire_code(&AnomalyLibError::NotYetValid {
                issued_at: 100,
                now: 50,
            }),
            "anomaly-library-not-yet-valid"
        );
    }

    #[test]
    fn wire_code_maps_expired() {
        assert_eq!(
            wire_code(&AnomalyLibError::Expired {
                expires_at: 50,
                now: 100,
            }),
            "anomaly-library-expired"
        );
    }

    #[test]
    fn wire_code_maps_pattern_id_duplicate() {
        assert_eq!(
            wire_code(&AnomalyLibError::PatternIdDuplicate {
                pattern_id: "pat::dup".into(),
            }),
            "anomaly-library-pattern-id-duplicate"
        );
    }

    #[test]
    fn wire_code_maps_severity_action_inconsistent() {
        assert_eq!(
            wire_code(&AnomalyLibError::SeverityActionInconsistent {
                pattern_id: "pat::x".into(),
                severity: "critical",
                action: "observe",
            }),
            "anomaly-library-severity-action-inconsistent"
        );
    }

    #[test]
    fn wire_code_maps_unknown_verb_family() {
        assert_eq!(
            wire_code(&AnomalyLibError::UnknownVerbFamily {
                pattern_id: "pat::x".into(),
                family: "not-real".into(),
            }),
            "anomaly-library-unknown-verb-family"
        );
    }

    #[test]
    fn wire_code_maps_firing_rule_companion_missing() {
        assert_eq!(
            wire_code(&AnomalyLibError::FiringRuleCompanionMissing {
                pattern_id: "pat::x".into(),
                window: 300,
                missing_reason: FiringCompanionFailure::NoCompanionsDeclared,
            }),
            "anomaly-library-firing-rule-companion-missing"
        );
    }

    /// §3.5.1 spec-literal exception — explicitly pinned so a future
    /// rename of this wire string cannot land without a conformance
    /// bump.
    #[test]
    fn wire_code_maps_library_version_too_old_to_spec_literal_pattern_library_version_too_old() {
        assert_eq!(
            wire_code(&AnomalyLibError::LibraryVersionTooOld {
                library_id: "lib::x".into(),
                current_hwm: 42,
                attempted: 42,
            }),
            "pattern-library-version-too-old"
        );
    }

    #[test]
    fn wire_code_maps_ledger_failure() {
        assert_eq!(
            wire_code(&AnomalyLibError::LedgerFailure {
                reason: "io error".into(),
            }),
            "anomaly-library-ledger-failure"
        );
    }

    // ---------------- parse_iso_seconds -------------------------------------

    #[test]
    fn parse_iso_seconds_accepts_rfc3339_utc() {
        let n = parse_iso_seconds("2026-05-01T00:00:00Z").unwrap();
        // OffsetDateTime::unix_timestamp returns seconds since epoch.
        // Sanity check that the result is non-zero and matches the
        // expected range for 2026 (> year 2020 → > 1.577e9).
        assert!(n > 1_577_836_800);
        assert!(n < 2_000_000_000);
    }

    #[test]
    fn parse_iso_seconds_rejects_non_rfc3339() {
        assert!(parse_iso_seconds("not a date").is_err());
        assert!(parse_iso_seconds("2026-05-01").is_err()); // missing time part
    }
}
