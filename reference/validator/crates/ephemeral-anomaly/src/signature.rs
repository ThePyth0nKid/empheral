//! Anomaly-library envelope signature verification (Phase C.4 / §3.5.1).
//!
//! This module binds an operator-published `AnomalyPatternLibrary` to
//! an [`AnchorRole::AnomalyLibrarySigner`]-signed metadata envelope
//! via a cryptographic pipeline that layers over
//! [`ephemeral_crypto::verify_cose_sign1_with_cap`]:
//!
//! ```text
//! cose_bytes ───► verify_cose_sign1_with_cap            (step 1)
//!      AAD       = b"ephemeral/anomaly-library/v1"
//!      role      = AnchorRole::AnomalyLibrarySigner
//!      max_bytes = MAX_ANOMALY_LIBRARY_BYTES (128 KiB)
//!                                   │
//!                                   ▼
//!                     inner payload bytes
//!                                   │
//!                ciborium::from_reader ──────────────► (step 2)
//!                                   │
//!                                   ▼
//!                     AnomalyLibraryPayload
//!                                   │
//!                 shape check on String length ──────► (step 3)
//!                 abi_version == expected              (step 4)
//!                 signer_kid  == outer COSE kid        (step 5)
//!                 issued_at ≤ now ≤ expires_at         (step 6)
//!                                   │
//!                                   ▼
//!                     pattern-body invariants
//!                 pattern_id uniqueness (§4.2.1)       (step 7a)
//!                 severity-action consistency (§3.5.2) (step 7b)
//!                 verb-family known (§3.5.3)           (step 7c)
//!                 anti-walk-under companion (§3.5.3)   (step 7d)
//!                                   │
//!                                   ▼
//!                     replay-ledger observation
//!                 library_version strictly greater    (step 8,
//!                   than per-library_id HWM (§3.5.1)    _with_ledger only)
//! ```
//!
//! Stage 7 is integrated here rather than exposed as a separate
//! `validate_invariants()` fn because the caller MUST NOT be able to
//! consume a signature-verified but structurally-broken library.
//! The fail-close posture is symmetric with the signer side:
//! `test_fixtures::sign_anomaly_library_envelope` performs the
//! inverse validation before signing, so a well-formed signer can
//! never produce bytes this verifier rejects at Stage 7.
//!
//! # Two public entry points
//!
//! - [`verify_anomaly_library_signature`] runs Stages 1-7 and is
//!   stateless.  Suitable for bootstrap flows, fuzz harnesses, and
//!   vector-generation where replay is not a concern.
//! - [`verify_anomaly_library_signature_with_ledger`] additionally
//!   threads a mutable [`AnomalyLedger`] through Stage 8 to enforce
//!   monotonic `library_version` per `library_id` (§3.5.1 reject
//!   code `pattern-library-version-too-old`).  Production callers
//!   should prefer this entry.  The two entry points share an
//!   internal helper (`verify_anomaly_library_signature_internal`)
//!   so Stages 1-7 behaviour and failure precedence are identical
//!   between them.
//!
//! # Why the cap differs from the generic one
//!
//! Tariff / classifier / delegation envelopes carry a handful of
//! small fields and fit well under the default
//! [`ephemeral_crypto::MAX_COSE_BYTES`] (64 KiB).  The anomaly library
//! is the first envelope domain where the *payload itself* is the
//! signed artifact — a mature library may carry hundreds of operator
//! patterns.  [`MAX_ANOMALY_LIBRARY_BYTES`] raises the cap to 128 KiB
//! for this domain only; the classic suites continue to enforce the
//! tighter default.
//!
//! # No inner-payload pre-cap
//!
//! Unlike [`ephemeral_classifier::signature`], which caps the inner
//! payload at 4 KiB because a legitimate classifier metadata payload
//! is a few hundred bytes, the anomaly library has no such headroom:
//! the legitimate inner payload approaches the outer envelope cap.
//! Adding an inner pre-cap would either be redundant (if set near the
//! outer cap) or false-positive (if set lower).  The outer cap is the
//! binding constraint; ciborium's internal recursion bound (and the
//! depth guard in `size_depth_check_with_cap`) bound memory pressure
//! during decode.
//!
//! # Role discrimination
//!
//! The verifier requires that the matched trust anchor is registered
//! under [`AnchorRole::AnomalyLibrarySigner`].  A tariff-,
//! classifier-, or delegation-signed envelope with a matching `kid`
//! fails the role check at the crypto layer and surfaces as
//! [`AnomalyLibError::CoseVerifyFailed`] — kid-unknown,
//! role-mismatched, and signature-invalid are indistinguishable from
//! the caller's perspective.

use ephemeral_crypto::{verify_cose_sign1_with_cap, AnchorRole, TrustAnchorSet};

use crate::errors::{sanitize_log_string, AnomalyLibError};
use crate::invariants::{
    check_firing_rule_companions, check_pattern_id_uniqueness, check_severity_action_consistency,
    check_verb_families_known,
};
use crate::ledger::{AnomalyLedger, LedgerError};
use crate::patterns::PatternEntry;
use crate::schema::AnomalyLibraryPayload;

/// Domain-separation tag for anomaly-library envelopes.
///
/// Included verbatim in the `COSE_Sign1` external AAD so that a
/// tariff-, classifier-, or delegation-signed envelope cannot be
/// replayed as an anomaly-library signature — the signed TBS
/// (`Sig_structure_1`) differs between domains, so the Ed25519
/// verification fails even if the signer key and `kid` happen to
/// collide across roles.
///
/// The `/v1` suffix names the ABI-v1 envelope shape; a future v2
/// shape (with, e.g., a new top-level field or a different payload
/// map) MUST pick a new AAD so v1 and v2 signatures cannot be
/// confused even when the `AnomalyLibrarySigner` role's key rotates
/// identically under both.
pub const ANOMALY_LIBRARY_AAD: &[u8] = b"ephemeral/anomaly-library/v1";

/// Maximum byte length accepted for an `AnomalyPatternLibrary`
/// COSE_Sign1 envelope (inclusive of COSE framing).
///
/// 128 KiB is sized to hold a mature operator pattern set: roughly
/// 200 patterns × ~500 bytes each fits under this cap with envelope
/// overhead.  Sitting above the generic
/// [`ephemeral_crypto::MAX_COSE_BYTES`] (64 KiB) is intentional —
/// callers reach the larger cap via
/// [`ephemeral_crypto::verify_cose_sign1_with_cap`], which this module
/// uses in place of the default
/// [`ephemeral_crypto::verify_cose_sign1`].
///
/// Raising this cap further is a governance-level decision (§3.5.1
/// budget) and MUST coincide with a re-run of the determinism and
/// fuzz vectors; do NOT relax in isolation.
pub const MAX_ANOMALY_LIBRARY_BYTES: usize = 131_072;

// Compile-time floor: the anomaly cap MUST stay above the generic
// `MAX_COSE_BYTES` default, otherwise the whole reason for adopting
// the `_with_cap` dispatch path collapses — any legitimate anomaly
// envelope sized between `MAX_COSE_BYTES` and `MAX_ANOMALY_LIBRARY_BYTES`
// would get rejected by the outer size guard before the role-specific
// code path sees it.  A future change that narrows the anomaly cap
// below the generic cap is a design regression that must not compile.
const _: () = assert!(MAX_ANOMALY_LIBRARY_BYTES > ephemeral_crypto::MAX_COSE_BYTES);

/// Maximum byte length accepted for the inner `signer_kid` field.
///
/// Acts as a belt-and-braces guard: the outer
/// [`MAX_ANOMALY_LIBRARY_BYTES`] cap already bounds the whole
/// envelope, but a pathological payload could dedicate all of that
/// budget to a single string.  Clamped at 256 bytes to match the
/// classifier-crate precedent — `kid` is a short human-readable label
/// in practice.
const MAX_INNER_KID_BYTES: usize = 256;

/// Maximum byte length accepted for the `library_id` field.
///
/// Same rationale as [`MAX_INNER_KID_BYTES`]: a pathological signer
/// could author a multi-KiB `library_id` to bloat validator logs on
/// any future logged form.  256 bytes is comfortable headroom for any
/// legitimate namespacing scheme.
const MAX_LIBRARY_ID_BYTES: usize = 256;

// Cap coherence: both `signer_kid` and `library_id` are stored in
// `VerifiedAnomalyLibrarySignature` AFTER passing through
// `sanitize_log_string`, which truncates at
// `crate::errors::MAX_LOG_STRING_BYTES`.  If either inner cap ever
// rose above that log-cap, the stored value would be silently
// truncated and no longer byte-equal to what the crypto layer
// authenticated — a latent data-corruption path where the caller
// receives a `VerifiedAnomalyLibrarySignature` whose `signer_kid` /
// `library_id` does NOT match the bytes the signature bound.  The
// boundary tests `signer_kid_at_max_length_accepts` and
// `library_id_at_max_length_accepts` would still pass at runtime (the
// stored value's length equals the cap) while silently dropping the
// tail.  Failing at compile time closes that divergence for good.
const _: () = assert!(MAX_INNER_KID_BYTES <= crate::errors::MAX_LOG_STRING_BYTES);
const _: () = assert!(MAX_LIBRARY_ID_BYTES <= crate::errors::MAX_LOG_STRING_BYTES);

/// Successful outcome of an anomaly-library signature verification.
///
/// The authoritative signer kid (from the outer COSE header) and the
/// decoded envelope header fields are returned together so callers
/// can route the verified library to downstream consumers (e.g. the
/// audit pipeline) and log the full provenance in one pass.
///
/// Both string fields (`signer_kid`, `library_id`) have already been
/// passed through [`sanitize_log_string`] — they are safe to embed in
/// log output or error messages without further escaping, but MUST
/// NOT be used as lookup keys back into the [`TrustAnchorSet`] (the
/// sanitising transform is lossy).  The raw values have already
/// served their purpose during Step 5's equality check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAnomalyLibrarySignature {
    /// Sanitised signer kid, taken from the cryptographically
    /// authoritative outer `COSE_Sign1` protected header.
    pub signer_kid: String,
    /// ABI version the library was signed against.
    pub abi_version: u32,
    /// Sanitised library identifier.
    pub library_id: String,
    /// Monotonic version counter within `library_id`.
    pub library_version: u64,
    /// Start of validity window (unix epoch seconds).
    pub issued_at: i64,
    /// End of validity window (unix epoch seconds).
    pub expires_at: i64,
    /// Structurally-validated pattern table.  Guaranteed at this
    /// point to be:
    ///
    /// - pattern-id unique (§4.2.1 R7.C6 SET semantics),
    /// - severity-action consistent (§3.5.2 R8.A2),
    /// - all verb-family references resolvable (§3.5.3 trust-surface),
    /// - anti-walk-under companion-pair sound (§3.5.3).
    ///
    /// Empty for Session-1-signed envelopes (see crate-level
    /// forward-compat note).  The raw contents — in particular the
    /// `pattern_id` and scope strings — are NOT sanitised here
    /// because they are *not* attacker-surfaced to logs at this
    /// layer; the invariant-check error variants sanitise them on
    /// their way into `AnomalyLibError`.  Session-3+ consumers that
    /// log pattern ids in success paths MUST apply
    /// [`sanitize_log_string`] themselves at that log site.
    pub patterns: Vec<PatternEntry>,
}

/// Internal helper: run Stages 1-7 and return the decoded CBOR
/// payload plus the cryptographically authoritative outer kid from
/// the `COSE_Sign1` protected header.  Sanitisation is deferred to
/// the caller.
///
/// Both public entry points ([`verify_anomaly_library_signature`] and
/// [`verify_anomaly_library_signature_with_ledger`]) route through
/// this so their Stage 1-7 semantics and failure precedence are
/// byte-for-byte identical.
///
/// Surfacing the raw `library_id` here (rather than the sanitised
/// form) is load-bearing for the with-ledger entry point:
/// [`sanitize_log_string`] is non-injective on UTF-8 multi-byte bytes
/// (every byte outside `0x20..=0x7E` maps to `'?'`), so using the
/// sanitised form as the ledger key would collide two legitimate but
/// non-ASCII library_ids — e.g. `"lib::foö"` (`0xC3 0xB6`) and
/// `"lib::foÖ"` (`0xC3 0x96`) both reduce to `"lib::fo??"` — and the
/// second library's first load would mis-reject as a stale replay.
/// Keeping the raw bytes out of the `VerifiedAnomalyLibrarySignature`
/// surface but available to the ledger caller closes that divergence.
fn verify_anomaly_library_signature_internal(
    cose_sign1_bytes: &[u8],
    anchors: &TrustAnchorSet,
    expected_abi_version: u32,
    now_unix_seconds: i64,
) -> Result<(AnomalyLibraryPayload, String), AnomalyLibError> {
    // Step 1: outer COSE_Sign1 verify with AAD + role + raised byte
    // cap.  The crypto layer enforces size/depth caps, parse, alg
    // allowlist, role-aware kid resolution, alg/anchor consistency,
    // payload presence, and Ed25519 strict-mode signature check — all
    // failures collapse into CoseVerifyFailed for anti-enumeration.
    let verified = verify_cose_sign1_with_cap(
        cose_sign1_bytes,
        anchors,
        ANOMALY_LIBRARY_AAD,
        AnchorRole::AnomalyLibrarySigner,
        MAX_ANOMALY_LIBRARY_BYTES,
    )
    .map_err(|_| AnomalyLibError::CoseVerifyFailed)?;

    // Step 2: decode the inner CBOR payload. `from_reader` expects a
    // `Read` impl, which `&[u8]` provides.  Any deserialization
    // failure — wrong type, missing field, truncated input — collapses
    // to PayloadDecodeFailed.
    //
    // No inner pre-cap here: legitimate anomaly payloads approach the
    // outer envelope size (see module-level "No inner-payload pre-cap"
    // rationale).  Adding one would be redundant (at ~MAX_ANOMALY)
    // or false-positive (below it).
    let payload: AnomalyLibraryPayload = ciborium::from_reader(verified.payload.as_slice())
        .map_err(|_| AnomalyLibError::PayloadDecodeFailed)?;

    // Step 3: structural validation beyond what serde guaranteed.
    // String fields passed through serde as UTF-8-valid but of
    // arbitrary length; enforce field-specific caps before any path
    // that would log or compare them.
    if payload.signer_kid.len() > MAX_INNER_KID_BYTES {
        return Err(AnomalyLibError::PayloadDecodeFailed);
    }
    if payload.library_id.len() > MAX_LIBRARY_ID_BYTES {
        return Err(AnomalyLibError::PayloadDecodeFailed);
    }

    // Step 4: ABI version pinning.
    if payload.abi_version != expected_abi_version {
        return Err(AnomalyLibError::AbiVersionMismatch {
            expected: expected_abi_version,
            signed: payload.abi_version,
        });
    }

    // Step 5: signer-kid consistency (inner vs. outer).  The outer
    // kid is cryptographically authoritative; this catches signer-
    // side authoring bugs where the inner metadata was stale.
    // Sanitise both sides for the error variant so adversarial CBOR
    // cannot inject newlines or control chars into validator logs.
    if payload.signer_kid != verified.kid {
        return Err(AnomalyLibError::SignerKidMismatch {
            outer: sanitize_log_string(&verified.kid),
            signed: sanitize_log_string(&payload.signer_kid),
        });
    }

    // Step 6: time-bounds enforcement.  Validity window is inclusive
    // at both ends: `now == issued_at` is accepted as "just activated"
    // and `now == expires_at` is accepted as "final valid second".
    // The caller-supplied clock means this check is deterministic for
    // vector generation.
    if now_unix_seconds < payload.issued_at {
        return Err(AnomalyLibError::NotYetValid {
            issued_at: payload.issued_at,
            now: now_unix_seconds,
        });
    }
    if now_unix_seconds > payload.expires_at {
        return Err(AnomalyLibError::Expired {
            expires_at: payload.expires_at,
            now: now_unix_seconds,
        });
    }

    // Step 7: pattern-body invariant validation.  Ordering is
    // documented in `invariants` module — cheapest/library-level
    // first, cross-pattern last.  Any failure here aborts before we
    // construct the verified struct: a signature-verified but
    // structurally-broken library MUST be indistinguishable from an
    // unsigned one at the caller's boundary.
    //
    // 7a: pattern_id SET-semantics (§4.2.1 R7.C6).
    check_pattern_id_uniqueness(&payload.patterns)?;
    // 7b: severity-action consistency (§3.5.2 R8.A2).
    check_severity_action_consistency(&payload.patterns)?;
    // 7c: verb-family references known (§3.5.3 trust-surface).
    check_verb_families_known(&payload.patterns)?;
    // 7d: anti-walk-under companion pair (§3.5.3).
    check_firing_rule_companions(&payload.patterns)?;

    // Return raw outer kid + raw payload.  `VerifiedAnomalyLibrarySignature`
    // construction (with sanitisation) happens in `build_verified`.
    Ok((payload, verified.kid))
}

/// Build the public [`VerifiedAnomalyLibrarySignature`] from a
/// validated payload + the cryptographically authoritative outer kid.
///
/// Kept as a named helper so both public entry points share exactly
/// one sanitisation + field-mapping site.  Any future field addition
/// to `VerifiedAnomalyLibrarySignature` touches only this function,
/// not every caller.
fn build_verified(
    payload: AnomalyLibraryPayload,
    raw_outer_kid: &str,
) -> VerifiedAnomalyLibrarySignature {
    // Both outward-facing string fields pass through `sanitize_log_string`
    // so a rogue signer cannot smuggle control chars or ANSI escapes
    // into validator logs via the `VerifiedAnomalyLibrarySignature`
    // surface.  Raw values have already served their equality-check
    // and ledger-key purposes upstream.
    //
    // `patterns` is moved (not cloned) into the verified struct —
    // this crate produces exactly one verified result per call, and
    // downstream consumers take ownership.
    VerifiedAnomalyLibrarySignature {
        signer_kid: sanitize_log_string(raw_outer_kid),
        abi_version: payload.abi_version,
        library_id: sanitize_log_string(&payload.library_id),
        library_version: payload.library_version,
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        patterns: payload.patterns,
    }
}

/// Verify an anomaly-library envelope against a set of trust anchors
/// (stateless — no replay protection).
///
/// Prefer [`verify_anomaly_library_signature_with_ledger`] for
/// production verifiers: the stateless form accepts replayed or
/// rolled-back libraries and is kept only for bootstrap, fuzz, and
/// vector-generation flows that have no ledger to thread through.
///
/// # Arguments
///
/// * `cose_sign1_bytes` — a `COSE_Sign1` envelope (RFC 9052 §4.2)
///   carrying a CBOR-encoded [`AnomalyLibraryPayload`] as its payload,
///   with Ed25519 signature (`alg = -8`).
/// * `anchors` — trust-anchor set.  The anchor matching the envelope's
///   `kid` must be registered under
///   [`AnchorRole::AnomalyLibrarySigner`]; any other role fails the
///   verification at the crypto layer.
/// * `expected_abi_version` — the ABI version this validator was
///   built against.  Production callers pass
///   [`crate::ANOMALY_LIBRARY_ABI_VERSION`].
/// * `now_unix_seconds` — caller-supplied clock for the time-bounds
///   check in Step 6.  Production callers pass
///   `SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64`;
///   tests inject a fixed value.  Passing the clock rather than
///   reading it internally keeps this crate pure (no `std::time`
///   side-effects) and makes the verdict deterministic for vector
///   generation.
///
/// # Returns
///
/// On success, a [`VerifiedAnomalyLibrarySignature`] with the
/// authoritative signer kid, ABI version, library identity, version
/// counter, and validity window.
///
/// # Errors
///
/// See [`AnomalyLibError`] for the full taxonomy.  In short:
///
/// - [`AnomalyLibError::CoseVerifyFailed`] — outer envelope fails any
///   check (size, parse, role, kid, alg, signature).  Role leakage is
///   contained in this single variant.
/// - [`AnomalyLibError::PayloadDecodeFailed`] — inner CBOR is
///   malformed or a structural string-length cap was exceeded.
/// - [`AnomalyLibError::AbiVersionMismatch`] — payload version ≠
///   `expected_abi_version`.
/// - [`AnomalyLibError::SignerKidMismatch`] — inner `signer_kid` ≠
///   outer COSE header `kid`.
/// - [`AnomalyLibError::NotYetValid`] — `now_unix_seconds <
///   issued_at`.
/// - [`AnomalyLibError::Expired`] — `now_unix_seconds > expires_at`.
#[must_use = "an unchecked anomaly-library signature is indistinguishable from an unsigned one"]
pub fn verify_anomaly_library_signature(
    cose_sign1_bytes: &[u8],
    anchors: &TrustAnchorSet,
    expected_abi_version: u32,
    now_unix_seconds: i64,
) -> Result<VerifiedAnomalyLibrarySignature, AnomalyLibError> {
    let (payload, raw_outer_kid) = verify_anomaly_library_signature_internal(
        cose_sign1_bytes,
        anchors,
        expected_abi_version,
        now_unix_seconds,
    )?;
    Ok(build_verified(payload, &raw_outer_kid))
}

/// Verify an anomaly-library envelope AND observe its
/// `library_version` against a replay-protection ledger (Stage 8 per
/// §3.5.1).  Prefer this entry point for production verifiers — the
/// stateless [`verify_anomaly_library_signature`] accepts replayed or
/// rolled-back libraries.
///
/// # Failure precedence (Stages 1-8)
///
/// 1. Outer COSE envelope failures → [`AnomalyLibError::CoseVerifyFailed`]
/// 2. Inner CBOR decode / field caps → [`AnomalyLibError::PayloadDecodeFailed`]
/// 3. ABI version mismatch → [`AnomalyLibError::AbiVersionMismatch`]
/// 4. Signer kid inner/outer mismatch → [`AnomalyLibError::SignerKidMismatch`]
/// 5. Time bounds (not-yet-valid / expired) → [`AnomalyLibError::NotYetValid`] /
///    [`AnomalyLibError::Expired`]
/// 6. Pattern-body invariants (§§3.5.2, 3.5.3, 4.2.1) → the respective
///    `Pattern*` / `FiringRule*` / `SeverityAction*` / `UnknownVerbFamily`
///    variants.
/// 7. **Stage 8 (this entry only):** ledger monotonicity → [`AnomalyLibError::LibraryVersionTooOld`]
///    on replay or rollback; [`AnomalyLibError::LedgerFailure`] on
///    future-backend infrastructure failure.
///
/// **Stage 7 fails before Stage 8.**  A signed envelope that declares
/// a stale `library_version` for a structurally-broken library
/// surfaces the pattern-body error (§3.5.3 anti-walk-under, etc.)
/// rather than the stale-version error — the signer's actionable fix
/// is to repair the body, not bump the version.  Co-occurrent-fault
/// test `tests::stage7_body_failure_short_circuits_before_stage8_ledger`
/// locks this ordering globally.
///
/// # Arguments
///
/// Arguments 1-4 match [`verify_anomaly_library_signature`].  The
/// additional `ledger` argument carries the per-library_id
/// high-water-mark state.
///
/// * `ledger` — mutable reference to an [`AnomalyLedger`].  The
///   [`crate::ledger::InMemoryAnomalyLedger`] default is process-local;
///   production callers supply a persistent backend.  The trait is
///   object-safe, so `&mut dyn AnomalyLedger` works transparently.
///
/// # State mutation discipline
///
/// The ledger is advanced only if every prior stage succeeds.  A
/// failed envelope (wrong role, stale time, broken patterns) leaves
/// the ledger untouched — the HWM for the envelope's `library_id`
/// stays at whatever a prior successful load placed there.  This
/// matches the Tariff-Step-10 precedent and ensures a failed re-load
/// attempt cannot bump the HWM past a legitimate upcoming envelope.
#[must_use = "an unchecked anomaly-library signature is indistinguishable from an unsigned one"]
pub fn verify_anomaly_library_signature_with_ledger<L: AnomalyLedger + ?Sized>(
    cose_sign1_bytes: &[u8],
    anchors: &TrustAnchorSet,
    expected_abi_version: u32,
    now_unix_seconds: i64,
    ledger: &mut L,
) -> Result<VerifiedAnomalyLibrarySignature, AnomalyLibError> {
    let (payload, raw_outer_kid) = verify_anomaly_library_signature_internal(
        cose_sign1_bytes,
        anchors,
        expected_abi_version,
        now_unix_seconds,
    )?;

    // Stage 8: replay-ledger observation.  Runs AFTER internal Stages
    // 1-7 so body failures win over ledger failures on co-occurrent
    // faults — the signer's actionable fix is "repair the body", not
    // "bump the version".
    //
    // Raw `library_id` (not the sanitised form) goes to `observe`:
    // `sanitize_log_string` is lossy on non-ASCII bytes and would
    // collide legitimate distinct ids.  Sanitisation applies only
    // when mapping `LedgerError` into the outward `AnomalyLibError`
    // below, so the log-surface stays safe.
    ledger
        .observe(&payload.library_id, payload.library_version)
        .map_err(|e| {
            // `LedgerError` is `#[non_exhaustive]` for external-crate
            // forward-compat.  Within this crate the compiler sees
            // only one variant today, so the wildcard arm looks
            // unreachable — but removing it would defeat the purpose
            // of `#[non_exhaustive]` the moment a future backend adds
            // an I/O-failure variant (disk, DB).  The arm MUST stay
            // so a new LedgerError variant lands safely in
            // `LedgerFailure` instead of silently folding into
            // `CoseVerifyFailed` (wrong semantic: that variant exists
            // for anti-enumeration of anchor roles).
            #[allow(unreachable_patterns)]
            match e {
                LedgerError::VersionNotStrictlyGreater {
                    library_id,
                    current_hwm,
                    attempted,
                } => AnomalyLibError::LibraryVersionTooOld {
                    library_id: sanitize_log_string(&library_id),
                    current_hwm,
                    attempted,
                },
                other => AnomalyLibError::LedgerFailure {
                    reason: sanitize_log_string(&other.to_string()),
                },
            }
        })?;

    Ok(build_verified(payload, &raw_outer_kid))
}

#[cfg(test)]
mod tests {
    use super::*;

    use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
    use ed25519_dalek::{Signer, SigningKey};
    use ephemeral_crypto::TrustAnchor;

    use crate::errors::FiringCompanionFailure;
    use crate::patterns::{Action, FiringRule, Severity, Threshold};
    use crate::scope::{MandateScope, ScopePredicate, VerbPredicate};
    use crate::ANOMALY_LIBRARY_ABI_VERSION;

    const TEST_KID: &str = "K_anomaly_pk_TEST";
    const ALT_KID: &str = "K_other_anomaly_pk_TEST";

    // Fixed seed so test keys are deterministic across runs — failures
    // reproduce, and future vector-signer tooling can reuse the same
    // seed when generating committed conformance vectors.
    const SEED: [u8; 32] = [
        0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f, 0x20,
    ];
    const ALT_SEED: [u8; 32] = [
        0x7f, 0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0x19, 0x08, 0xf7, 0xe6, 0xd5, 0xc4, 0xb3, 0xa2, 0x91,
        0x80, 0x7f, 0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0x19, 0x08, 0xf7, 0xe6, 0xd5, 0xc4, 0xb3, 0xa2,
        0x91, 0x80,
    ];

    // Fixed time values so tests are independent of the wall clock.
    // Chosen well away from i64 boundaries and from u32::MAX to avoid
    // accidental year-2038 confusion.
    const T_ISSUED: i64 = 1_700_000_000;
    const T_EXPIRES: i64 = 1_800_000_000;
    const T_NOW: i64 = 1_750_000_000;

    fn signing_key(seed: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&seed)
    }

    fn anomaly_anchor_set() -> TrustAnchorSet {
        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            TEST_KID.to_string(),
            pk.as_bytes(),
            AnchorRole::AnomalyLibrarySigner,
        )
        .expect("fixed seed yields non-weak pk");
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).expect("fresh set has no dup kid");
        set
    }

    fn encode_payload(payload: &AnomalyLibraryPayload) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(payload, &mut out).expect("ciborium serialize");
        out
    }

    fn build_sign1(inner_payload_bytes: Vec<u8>, kid: &str, aad: &[u8], seed: [u8; 32]) -> Vec<u8> {
        let sk = signing_key(seed);
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(kid.as_bytes().to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(inner_payload_bytes)
            .create_signature(aad, |tbs| sk.sign(tbs).to_bytes().to_vec())
            .build();
        sign1.to_vec().expect("serialize")
    }

    /// Happy-path fixture: the signer commits to the current ABI,
    /// a fresh library id + version, a reasonable validity window
    /// straddling T_NOW, and the correct kid; signs under
    /// AnomalyLibrarySigner role.
    fn happy_envelope() -> Vec<u8> {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        build_sign1(
            encode_payload(&payload),
            TEST_KID,
            ANOMALY_LIBRARY_AAD,
            SEED,
        )
    }

    #[test]
    fn happy_path_verifies() {
        let cose = happy_envelope();
        let out = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("happy path verifies");
        assert_eq!(out.signer_kid, TEST_KID);
        assert_eq!(out.abi_version, ANOMALY_LIBRARY_ABI_VERSION);
        assert_eq!(out.library_id, "lib::default");
        assert_eq!(out.library_version, 1);
        assert_eq!(out.issued_at, T_ISSUED);
        assert_eq!(out.expires_at, T_EXPIRES);
        // Session-1-shape happy envelope carries no patterns — Stage
        // 7 trivially passes on the empty slice, and `patterns` is
        // surfaced empty rather than absent.
        assert!(out.patterns.is_empty());
    }

    #[test]
    fn wrong_role_fails_as_cose_verify() {
        // Anchor registered as TariffSigner — anomaly verification
        // must fail at the crypto-layer role check.
        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            TEST_KID.to_string(),
            pk.as_bytes(),
            AnchorRole::TariffSigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).unwrap();

        let cose = happy_envelope();
        let err = verify_anomaly_library_signature(&cose, &set, ANOMALY_LIBRARY_ABI_VERSION, T_NOW)
            .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn classifier_role_also_fails_as_cose_verify() {
        // Guard against future role drift: an anchor under
        // ClassifierSigner must also be rejected (not just Tariff).
        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            TEST_KID.to_string(),
            pk.as_bytes(),
            AnchorRole::ClassifierSigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).unwrap();

        let err = verify_anomaly_library_signature(
            &happy_envelope(),
            &set,
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn unknown_kid_fails_as_cose_verify() {
        // Signer uses ALT_SEED (and ALT_KID in the header), but the
        // anchor set only holds TEST_KID.  Resolution fails and the
        // crypto layer returns UnknownKid, which folds to
        // CoseVerifyFailed.
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: ALT_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, ALT_KID, ANOMALY_LIBRARY_AAD, ALT_SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn wrong_aad_fails_as_cose_verify() {
        // Envelope signed with the tariff AAD — the
        // AnomalyLibrarySigner verifier picks the anomaly AAD so TBS
        // differs and the signature check fails.
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, b"tariff", SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn classifier_aad_fails_as_cose_verify() {
        // Belt-and-braces: signing under the classifier AAD must also
        // be rejected by the anomaly verifier.  Locks against AAD
        // drift or copy-paste confusion in future refactors.
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, b"ephemeral/classifier/v1", SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn tampered_payload_fails_as_cose_verify() {
        // Flip one byte inside the signed inner payload after signing.
        let mut cose = happy_envelope();
        let mut parsed = coset::CoseSign1::from_slice(&cose).expect("parse");
        let payload = parsed.payload.as_mut().expect("payload");
        payload[0] ^= 0xFF;
        cose = parsed.to_vec().expect("reserialize");

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn oversize_envelope_fails_as_cose_verify() {
        // A raw buffer that exceeds MAX_ANOMALY_LIBRARY_BYTES must be
        // rejected by the outer size-cap check regardless of
        // structure.  Using a plain zero buffer (not CBOR) is fine
        // because the size check runs before parse.
        let huge = vec![0u8; MAX_ANOMALY_LIBRARY_BYTES + 1];
        let err = verify_anomaly_library_signature(
            &huge,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn above_default_cap_but_within_anomaly_cap_only_rejects_on_signature() {
        // Positive control for the raised _with_cap path: a buffer
        // sized between the default MAX_COSE_BYTES (64 KiB) and
        // MAX_ANOMALY_LIBRARY_BYTES (128 KiB) must NOT be rejected for
        // size.  It will still fail later (not valid CBOR), and the
        // collapse-posture surfaces that as CoseVerifyFailed — the
        // point of this test is proving that the *size* gate does not
        // fire, which would happen under the legacy verify_cose_sign1.
        let size = ephemeral_crypto::MAX_COSE_BYTES + 1024;
        // Lock the test's intent at both ends of the size window so the
        // collapse-posture assertion below unambiguously reflects a
        // "passed size gate, failed at CBOR parse" outcome (not a
        // "failed at size gate" false positive).
        assert!(
            size > ephemeral_crypto::MAX_COSE_BYTES,
            "test size must exceed the generic cap so the raised path is exercised",
        );
        assert!(
            size < MAX_ANOMALY_LIBRARY_BYTES,
            "test size must stay under the anomaly cap to isolate CBOR-parse from size-gate failure",
        );
        let buf = vec![0u8; size];

        // Under the default (non-raised) path, this would fail with
        // PayloadTooLarge.  Under the raised anomaly path, it fails
        // at CBOR parse (which is also CoseVerifyFailed via collapse
        // posture) — *not* at the size gate.  We assert collapse here;
        // the direct proof that the size gate did not fire lives in
        // `ephemeral_crypto::size_guard::tests::with_cap_*`.
        let err = verify_anomaly_library_signature(
            &buf,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn abi_version_mismatch_surfaces_explicitly() {
        let payload = AnomalyLibraryPayload {
            abi_version: 99,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AnomalyLibError::AbiVersionMismatch {
                expected: ANOMALY_LIBRARY_ABI_VERSION,
                signed: 99,
            }
        );
    }

    #[test]
    fn abi_version_edge_values_reject() {
        // Both ends of the u32 range must surface as AbiVersionMismatch
        // when the verifier expects ANOMALY_LIBRARY_ABI_VERSION.
        for signed in [0u32, u32::MAX] {
            let payload = AnomalyLibraryPayload {
                abi_version: signed,
                signer_kid: TEST_KID.to_string(),
                library_id: "lib::default".to_string(),
                library_version: 1,
                issued_at: T_ISSUED,
                expires_at: T_EXPIRES,
                patterns: Vec::new(),
            };
            let inner = encode_payload(&payload);
            let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);
            let err = verify_anomaly_library_signature(
                &cose,
                &anomaly_anchor_set(),
                ANOMALY_LIBRARY_ABI_VERSION,
                T_NOW,
            )
            .unwrap_err();
            assert_eq!(
                err,
                AnomalyLibError::AbiVersionMismatch {
                    expected: ANOMALY_LIBRARY_ABI_VERSION,
                    signed,
                },
                "abi_version={signed} must reject as AbiVersionMismatch"
            );
        }
    }

    #[test]
    fn signer_kid_mismatch_surfaces_explicitly() {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: "K_wrong_inner_kid".to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        match err {
            AnomalyLibError::SignerKidMismatch { outer, signed } => {
                assert_eq!(outer, TEST_KID);
                assert_eq!(signed, "K_wrong_inner_kid");
            }
            other => panic!("expected SignerKidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn signer_kid_mismatch_display_is_sanitized() {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: "K_\nINJECTED".to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        let display = format!("{err}");
        assert!(!display.contains('\n'));
        assert!(display.contains("K_?INJECTED"));
    }

    #[test]
    fn payload_decode_failure_on_non_cbor() {
        let bogus_inner = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD];
        let cose = build_sign1(bogus_inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::PayloadDecodeFailed);
    }

    #[test]
    fn payload_decode_failure_on_oversize_inner_kid() {
        let big_kid: String = "x".repeat(MAX_INNER_KID_BYTES + 1);
        // The outer kid must match the inner to reach the Step-3 cap
        // rather than the Step-5 mismatch; we install a fresh anchor
        // under the big kid so Step 1-2 succeed.
        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            big_kid.clone(),
            pk.as_bytes(),
            AnchorRole::AnomalyLibrarySigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).unwrap();

        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: big_kid.clone(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, &big_kid, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(&cose, &set, ANOMALY_LIBRARY_ABI_VERSION, T_NOW)
            .unwrap_err();
        assert_eq!(err, AnomalyLibError::PayloadDecodeFailed);
    }

    #[test]
    fn payload_decode_failure_on_oversize_library_id() {
        let big_lib: String = "y".repeat(MAX_LIBRARY_ID_BYTES + 1);
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: big_lib,
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::PayloadDecodeFailed);
    }

    #[test]
    fn signer_kid_at_max_length_accepts() {
        let max_kid: String = "x".repeat(MAX_INNER_KID_BYTES);
        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            max_kid.clone(),
            pk.as_bytes(),
            AnchorRole::AnomalyLibrarySigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).unwrap();

        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: max_kid.clone(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, &max_kid, ANOMALY_LIBRARY_AAD, SEED);

        let out = verify_anomaly_library_signature(&cose, &set, ANOMALY_LIBRARY_ABI_VERSION, T_NOW)
            .expect("max-length kid must accept at boundary");
        assert_eq!(out.signer_kid.len(), MAX_INNER_KID_BYTES);
        // Byte-identical to the input — guards against a future cap
        // divergence between MAX_INNER_KID_BYTES and
        // MAX_LOG_STRING_BYTES silently truncating the stored value
        // while still matching the length expectation.
        assert_eq!(out.signer_kid, max_kid);
    }

    #[test]
    fn library_id_at_max_length_accepts() {
        let max_lib: String = "z".repeat(MAX_LIBRARY_ID_BYTES);
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: max_lib.clone(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let out = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("max-length library_id must accept at boundary");
        assert_eq!(out.library_id.len(), MAX_LIBRARY_ID_BYTES);
        // Byte-identical to the input — same divergence guard as the
        // sibling `signer_kid_at_max_length_accepts` test above.
        assert_eq!(out.library_id, max_lib);
    }

    #[test]
    fn not_yet_valid_surfaces_explicitly() {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_NOW + 1,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AnomalyLibError::NotYetValid {
                issued_at: T_NOW + 1,
                now: T_NOW,
            }
        );
    }

    #[test]
    fn expired_surfaces_explicitly() {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_NOW - 1,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            AnomalyLibError::Expired {
                expires_at: T_NOW - 1,
                now: T_NOW,
            }
        );
    }

    #[test]
    fn exactly_at_issued_at_accepts() {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_NOW,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("now == issued_at must accept (inclusive lower bound)");
    }

    #[test]
    fn exactly_at_expires_at_accepts() {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_NOW,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("now == expires_at must accept (inclusive upper bound)");
    }

    #[test]
    fn inverted_window_rejects_as_not_yet_valid() {
        // Pathological envelope: issued_at > expires_at.  With T_NOW
        // between the two, the code ordering puts the expiry check
        // after the not-yet-valid check, so:
        //   now (T_NOW) < issued_at (T_NOW + 100) -> NotYetValid
        // We assert NotYetValid to lock the step ordering; a future
        // refactor that flips the order would surface Expired instead.
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_NOW + 100,
            expires_at: T_NOW - 100,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnomalyLibError::NotYetValid { .. }),
            "inverted window must surface NotYetValid first (step ordering lock), got {err:?}"
        );
    }

    #[test]
    fn check_order_cose_before_payload_decode() {
        // Crafted envelope: inner payload is garbage, outer is signed
        // under ALT_SEED (no anchor).  Both would fail — the crypto
        // failure must be reported first.
        let bogus_inner = vec![0x00, 0x01, 0x02];
        let cose = build_sign1(bogus_inner, ALT_KID, ANOMALY_LIBRARY_AAD, ALT_SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert_eq!(err, AnomalyLibError::CoseVerifyFailed);
    }

    #[test]
    fn check_order_abi_before_kid() {
        // Compound-failure envelope: wrong abi (step 4), wrong inner
        // kid (step 5), and `now > expires_at` (step 6b).  Step 4
        // must win.  Split from the sibling kid-before-time test so
        // a regression in the kid/time ordering surfaces independently
        // of a regression in the abi/kid ordering.
        let payload = AnomalyLibraryPayload {
            abi_version: 99,
            signer_kid: "K_wrong_inner".to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_NOW - 1,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnomalyLibError::AbiVersionMismatch { .. }),
            "step 4 (abi) must win over 5 (kid) and 6 (time), got {err:?}"
        );
    }

    #[test]
    fn check_order_kid_before_time() {
        // ABI is correct, inner kid diverges from outer, and the
        // validity window is already past.  Step 5 (kid) must win
        // over step 6 (time).  Split from the sibling abi-before-kid
        // test so a regression in the abi/kid ordering does not mask
        // a regression in the kid/time ordering.
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: "K_wrong_inner".to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_NOW - 1,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnomalyLibError::SignerKidMismatch { .. }),
            "step 5 (kid) must win over 6 (time), got {err:?}"
        );
    }

    #[test]
    fn anomaly_library_aad_is_versioned() {
        // Guard against accidental constant drift — the AAD ships in
        // conformance vectors and the /v1 suffix is reserved.
        assert_eq!(ANOMALY_LIBRARY_AAD, b"ephemeral/anomaly-library/v1");
    }

    #[test]
    fn max_anomaly_library_bytes_is_128_kib() {
        // Lock the approved 128 KiB cap against accidental drift.
        // Governance-level change (§3.5.1 budget) — a future bump
        // MUST re-run the determinism + fuzz vectors, so failing this
        // assertion forces intentionality.
        //
        // The cap's ordering relative to `ephemeral_crypto::MAX_COSE_BYTES`
        // is enforced at compile time by the `const _: ()` assertion near
        // the `MAX_ANOMALY_LIBRARY_BYTES` definition above; no runtime
        // re-check is needed here.
        assert_eq!(MAX_ANOMALY_LIBRARY_BYTES, 131_072);
    }

    #[test]
    fn sanitized_library_id_present_in_success_case() {
        // A library_id carrying control characters must decode and
        // verify successfully, but the *stored* identifier must be
        // sanitised — attackers must not be able to inject log chars
        // via a happy-path envelope.
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib\n\r::evil".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let out = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("control chars in library_id must not block happy path");
        assert!(!out.library_id.contains('\n'));
        assert!(!out.library_id.contains('\r'));
        assert_eq!(out.library_id, "lib??::evil");
    }

    #[test]
    fn library_version_value_round_trips_through_verifier() {
        // Large library_version (≥ 2^40) must survive encode/decode
        // without loss.  Guards against a future schema change that
        // accidentally narrowed the type.
        let big_version = 1_u64 << 50;
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: big_version,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let out = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("large library_version must round-trip");
        assert_eq!(out.library_version, big_version);
    }

    #[test]
    fn duplicate_signed_envelope_verifies_twice_identically() {
        // The verifier is stateless — replaying the same envelope with
        // the same clock MUST produce identical output.  This is the
        // scaffolding for downstream replay protection: since the
        // crate itself has no state, the consumer layer is the
        // enforcement point.  We lock statelessness here.
        let cose = happy_envelope();
        let a = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap();
        let b = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    // ──────────────────────────────────────────────────────────
    // Stage-7 integration — pattern-body invariants surface
    // through the full verifier path, not only from invariants.rs
    // unit tests.  These tests lock the wiring: every Stage-7
    // failure MUST reach the caller as its intended variant, with
    // ordering determined by the call sequence in
    // `verify_anomaly_library_signature` Step 7.  If a refactor
    // silently reshuffles the four `check_*` calls, the adjacent-
    // pair ordering tests below fail.
    // ──────────────────────────────────────────────────────────

    /// Build a well-formed 2-row pattern table: a 300 s `FirstMatch`
    /// primary plus a 3 000 s (= 10× primary window)
    /// `CumulativeOverBaseline` companion.  Used by Stage-7 happy-
    /// path and negative tests alike — each negative test mutates
    /// one row to inject the target fault.
    fn well_formed_patterns() -> Vec<PatternEntry> {
        let primary = PatternEntry {
            pattern_id: "delete-storm".into(),
            window_seconds: Some(300),
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
        };
        let companion = PatternEntry {
            pattern_id: "delete-slow-burn".into(),
            window_seconds: Some(3_000),
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
        };
        vec![primary, companion]
    }

    /// Encode an envelope carrying an explicit `Vec<PatternEntry>`
    /// under the happy-path kid + clock fixture.  Reuses the module-
    /// level fixture constants so each Stage-7 test differs only in
    /// the pattern payload.
    fn envelope_with_patterns(patterns: Vec<PatternEntry>) -> Vec<u8> {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::default".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns,
        };
        build_sign1(
            encode_payload(&payload),
            TEST_KID,
            ANOMALY_LIBRARY_AAD,
            SEED,
        )
    }

    #[test]
    fn happy_path_with_patterns_verifies_and_returns_populated_vec() {
        // A well-formed library passes all four Stage-7 checks and
        // the verified struct carries the decoded pattern table
        // through to the caller.  The table ownership is moved (not
        // cloned) into the verified struct — see
        // `verify_anomaly_library_signature` Step 7 docblock.
        let cose = envelope_with_patterns(well_formed_patterns());
        let out = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("well-formed pattern table must verify");
        assert_eq!(out.patterns.len(), 2);
        assert_eq!(out.patterns[0].pattern_id, "delete-storm");
        assert_eq!(out.patterns[1].pattern_id, "delete-slow-burn");
    }

    #[test]
    fn session_one_envelope_decodes_with_empty_patterns() {
        // Forward-compat lock: a Session-1-signed envelope — one
        // that does NOT include a `patterns` field in the CBOR map
        // at all — must still decode under the Session-2 schema via
        // the `#[serde(default)]` attribute on
        // `AnomalyLibraryPayload.patterns`.  Distinct from the plain
        // `happy_envelope` test: that one carries `patterns: Vec::
        // new()` (empty but present); this one MUST omit the field
        // from the encoded map entirely.
        //
        // Regression target: if a future refactor removes
        // `serde(default)`, this test fails with PayloadDecodeFailed.
        #[derive(serde::Serialize)]
        struct SessionOnePayload {
            abi_version: u32,
            signer_kid: String,
            library_id: String,
            library_version: u64,
            issued_at: i64,
            expires_at: i64,
        }
        let s1 = SessionOnePayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::session1".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
        };
        let mut inner = Vec::new();
        ciborium::into_writer(&s1, &mut inner).expect("serialize session-1 payload");
        let cose = build_sign1(inner, TEST_KID, ANOMALY_LIBRARY_AAD, SEED);

        let out = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .expect("Session-1 envelope (no patterns field) must verify under Session-2");
        assert!(out.patterns.is_empty());
        assert_eq!(out.library_id, "lib::session1");
    }

    #[test]
    fn stage7a_duplicate_pattern_id_rejects_through_full_verifier() {
        let mut patterns = well_formed_patterns();
        // Clone the primary to create a pattern_id collision.
        let dup = patterns[0].clone();
        patterns.push(dup);
        let cose = envelope_with_patterns(patterns);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        match err {
            AnomalyLibError::PatternIdDuplicate { pattern_id } => {
                assert_eq!(pattern_id, "delete-storm");
            }
            other => panic!("expected PatternIdDuplicate, got {other:?}"),
        }
    }

    #[test]
    fn stage7b_severity_action_mismatch_rejects_through_full_verifier() {
        let mut patterns = well_formed_patterns();
        // Primary keeps `severity = High` but switches to `Alert` —
        // §3.5.2 forbids this pair.  Also drop the companion list
        // to isolate the 7b fault from any accidental 7d surface.
        patterns[0].action = Action::Alert;
        patterns[0].firing_rule = FiringRule::CumulativeOverBaseline;
        patterns[0].firing_rule_companions = vec![];
        let cose = envelope_with_patterns(patterns);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        match err {
            AnomalyLibError::SeverityActionInconsistent {
                pattern_id,
                severity,
                action,
            } => {
                assert_eq!(pattern_id, "delete-storm");
                assert_eq!(severity, "high");
                assert_eq!(action, "alert");
            }
            other => panic!("expected SeverityActionInconsistent, got {other:?}"),
        }
    }

    #[test]
    fn stage7c_unknown_verb_family_rejects_through_full_verifier() {
        let mut patterns = well_formed_patterns();
        // Inject an unknown family reference into the primary.
        patterns[0].scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("not-a-real-family".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        let cose = envelope_with_patterns(patterns);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        match err {
            AnomalyLibError::UnknownVerbFamily { pattern_id, family } => {
                assert_eq!(pattern_id, "delete-storm");
                assert_eq!(family, "not-a-real-family");
            }
            other => panic!("expected UnknownVerbFamily, got {other:?}"),
        }
    }

    #[test]
    fn stage7d_missing_companion_rejects_through_full_verifier() {
        let mut patterns = well_formed_patterns();
        // Drop the companions list — the short-window FirstMatch
        // primary now has no anti-walk-under backstop.
        patterns[0].firing_rule_companions = vec![];
        // Drop the companion row entirely — it's orphaned now and
        // would pass on its own anyway (cumulative, any window).
        patterns.truncate(1);
        let cose = envelope_with_patterns(patterns);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        match err {
            AnomalyLibError::FiringRuleCompanionMissing {
                pattern_id,
                window,
                missing_reason,
            } => {
                assert_eq!(pattern_id, "delete-storm");
                assert_eq!(window, 300);
                assert!(matches!(
                    missing_reason,
                    FiringCompanionFailure::NoCompanionsDeclared
                ));
            }
            other => panic!("expected FiringRuleCompanionMissing, got {other:?}"),
        }
    }

    #[test]
    fn check_order_7a_uniqueness_wins_over_7b_severity() {
        // Compound violation: duplicate pattern_id AND a (High,
        // Alert) severity-action mismatch on the same rows.  7a
        // MUST surface first per the call order in
        // `verify_anomaly_library_signature` Step 7.
        let mut bad = well_formed_patterns()[0].clone();
        bad.severity = Severity::High;
        bad.action = Action::Alert;
        bad.firing_rule = FiringRule::CumulativeOverBaseline; // neutralise 7d
        bad.firing_rule_companions = vec![];
        let dup = bad.clone();
        let cose = envelope_with_patterns(vec![bad, dup]);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnomalyLibError::PatternIdDuplicate { .. }),
            "7a (uniqueness) MUST run before 7b (severity) — got {err:?}"
        );
    }

    #[test]
    fn check_order_7b_severity_wins_over_7c_family() {
        // Compound violation: (Critical, Alert) mismatch AND an
        // unknown family reference on the same row.  7b MUST
        // surface before 7c.
        let mut bad = well_formed_patterns()[0].clone();
        bad.severity = Severity::Critical;
        bad.action = Action::Alert;
        bad.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("unknown-x".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        bad.firing_rule = FiringRule::CumulativeOverBaseline; // neutralise 7d
        bad.firing_rule_companions = vec![];
        let cose = envelope_with_patterns(vec![bad]);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnomalyLibError::SeverityActionInconsistent { .. }),
            "7b (severity) MUST run before 7c (family) — got {err:?}"
        );
    }

    #[test]
    fn check_order_7c_family_wins_over_7d_companion() {
        // Compound violation: unknown family reference AND missing
        // anti-walk-under companion on the same row.  Severity is
        // (Low, Alert) so 7b does not trigger.  7c MUST surface
        // before 7d.
        let mut bad = well_formed_patterns()[0].clone();
        bad.severity = Severity::Low;
        bad.action = Action::Alert;
        bad.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("unknown-y".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        bad.firing_rule = FiringRule::FirstMatch;
        bad.firing_rule_companions = vec![]; // 7d fault
        let cose = envelope_with_patterns(vec![bad]);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnomalyLibError::UnknownVerbFamily { .. }),
            "7c (family) MUST run before 7d (companion) — got {err:?}"
        );
    }

    #[test]
    fn check_order_full_chain_7a_wins_over_all_downstream_stages() {
        // Compound 4-fault library: duplicate `pattern_id` (7a),
        // (High, Alert) severity-action mismatch (7b), unknown verb
        // family (7c), AND FirstMatch + short window + no companions
        // (7d) all triggered simultaneously on the same rows.
        //
        // The adjacent pairwise tests above
        // (check_order_7a_wins_over_7b, …_7b_wins_over_7c,
        // …_7c_wins_over_7d) only lock each neighbouring transition.
        // A regression that re-ordered 7a and 7c (but left 7a>7b and
        // 7c>7d intact) would still pass the three pairwise tests
        // while silently inverting the full chain.  Locking the
        // 4-fault compound forces the `Step 7` call order in
        // `verify_anomaly_library_signature` to remain 7a → 7b → 7c
        // → 7d, not just adjacent-consistent.
        //
        // 7a MUST surface because the uniqueness check runs first.
        let mut bad = well_formed_patterns()[0].clone();
        bad.severity = Severity::High; // 7b upper half
        bad.action = Action::Alert; // 7b lower half
        bad.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("chain-proof-unknown".into()), // 7c
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        bad.firing_rule = FiringRule::FirstMatch; // 7d upper half
        bad.window_seconds = Some(300); // short window → needs companion
        bad.firing_rule_companions = vec![]; // 7d lower half
                                             // Duplicate the row to synthesise 7a on top of the other
                                             // three faults.  Both rows carry identical `pattern_id`
                                             // "delete-storm", so uniqueness fails on the second insert.
        let dup = bad.clone();
        let cose = envelope_with_patterns(vec![bad, dup]);
        let err = verify_anomaly_library_signature(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
        )
        .unwrap_err();
        assert!(
            matches!(err, AnomalyLibError::PatternIdDuplicate { .. }),
            "full chain 7a→7b→7c→7d: 7a MUST surface when all four \
             faults are present — got {err:?}"
        );
    }

    // ==============================================================
    // Stage 8 — replay-ledger tests (Session 3+).
    //
    // Exercise `verify_anomaly_library_signature_with_ledger` against
    // the in-memory ledger.  Covers the happy path, the three
    // monotonicity reject cases, cross-library isolation, failure
    // precedence (Stages 1/6/7 short-circuit before Stage 8), dyn-
    // trait dispatch, and the "failed envelope leaves ledger
    // unchanged" discipline.
    // ==============================================================

    use crate::ledger::{AnomalyLedger, InMemoryAnomalyLedger};

    /// Sign an empty-patterns envelope under the happy-path kid +
    /// clock fixture with caller-specified `library_id` and
    /// `library_version`.  Used by Stage-8 tests that need to vary
    /// only these two fields; pattern-body is empty so Stages 7a-7d
    /// trivially pass.
    fn envelope_with_id_and_version(library_id: &str, library_version: u64) -> Vec<u8> {
        let payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: library_id.to_string(),
            library_version,
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        build_sign1(
            encode_payload(&payload),
            TEST_KID,
            ANOMALY_LIBRARY_AAD,
            SEED,
        )
    }

    #[test]
    fn with_ledger_happy_path_first_observation_verifies() {
        // Empty ledger + fresh envelope → verifies.  The first load
        // is FirstObservation (consumed internally), returning the
        // same VerifiedAnomalyLibrarySignature shape as the stateless
        // entry point.
        let cose = envelope_with_id_and_version("lib::alpha", 1);
        let mut ledger = InMemoryAnomalyLedger::new();
        let out = verify_anomaly_library_signature_with_ledger(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("first observation must verify");
        assert_eq!(out.library_id, "lib::alpha");
        assert_eq!(out.library_version, 1);
    }

    #[test]
    fn with_ledger_advancing_version_verifies_and_updates_hwm() {
        // Pre-seed the ledger at lib::alpha=1 then verify the same
        // library at version 2.  Must succeed (AdvancedFrom(1)) and
        // the internal HWM must advance so a subsequent v2 re-load
        // rejects.
        let mut ledger = InMemoryAnomalyLedger::new();
        let cose_v1 = envelope_with_id_and_version("lib::alpha", 1);
        verify_anomaly_library_signature_with_ledger(
            &cose_v1,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("seed v1 must verify");

        let cose_v2 = envelope_with_id_and_version("lib::alpha", 2);
        verify_anomaly_library_signature_with_ledger(
            &cose_v2,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("advance v1→v2 must verify");

        // Re-loading v2 now rejects as replay — proves the HWM moved.
        let err = verify_anomaly_library_signature_with_ledger(
            &cose_v2,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect_err("replay of v2 must reject");
        assert!(matches!(
            err,
            AnomalyLibError::LibraryVersionTooOld {
                ref library_id,
                current_hwm: 2,
                attempted: 2,
            } if library_id == "lib::alpha"
        ));
    }

    #[test]
    fn with_ledger_equal_version_rejects_with_library_version_too_old() {
        let mut ledger = InMemoryAnomalyLedger::new();
        let cose_v5 = envelope_with_id_and_version("lib::alpha", 5);
        verify_anomaly_library_signature_with_ledger(
            &cose_v5,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("seed v5 must verify");

        // Replay the same envelope — equal version rejects.
        let err = verify_anomaly_library_signature_with_ledger(
            &cose_v5,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect_err("equal version must reject as replay");
        assert!(
            matches!(
                err,
                AnomalyLibError::LibraryVersionTooOld {
                    current_hwm: 5,
                    attempted: 5,
                    ..
                }
            ),
            "expected LibraryVersionTooOld{{5, 5}}, got {err:?}"
        );
    }

    #[test]
    fn with_ledger_lower_version_rejects_with_library_version_too_old() {
        let mut ledger = InMemoryAnomalyLedger::new();
        let cose_v5 = envelope_with_id_and_version("lib::alpha", 5);
        verify_anomaly_library_signature_with_ledger(
            &cose_v5,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("seed v5 must verify");

        let cose_v3 = envelope_with_id_and_version("lib::alpha", 3);
        let err = verify_anomaly_library_signature_with_ledger(
            &cose_v3,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect_err("lower version must reject as rollback");
        assert!(
            matches!(
                err,
                AnomalyLibError::LibraryVersionTooOld {
                    current_hwm: 5,
                    attempted: 3,
                    ..
                }
            ),
            "expected LibraryVersionTooOld{{5, 3}}, got {err:?}"
        );
    }

    #[test]
    fn with_ledger_error_carries_sanitised_library_id() {
        // The signature module sanitises the library_id before
        // constructing the outward error.  Pin that the stored id is
        // the sanitised ASCII-only form, not the raw bytes — the log
        // surface MUST be injection-safe even though the ledger key
        // uses the raw form internally.  This happy-path library_id
        // is ASCII, so sanitised == raw; the separate injection-path
        // test in `errors.rs` covers the control-char branch.
        let mut ledger = InMemoryAnomalyLedger::new();
        let cose = envelope_with_id_and_version("lib::prod-v1", 5);
        verify_anomaly_library_signature_with_ledger(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .unwrap();
        let err = verify_anomaly_library_signature_with_ledger(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .unwrap_err();
        match err {
            AnomalyLibError::LibraryVersionTooOld {
                library_id,
                current_hwm,
                attempted,
            } => {
                assert_eq!(library_id, "lib::prod-v1");
                assert_eq!(current_hwm, 5);
                assert_eq!(attempted, 5);
            }
            other => panic!("expected LibraryVersionTooOld, got {other:?}"),
        }
    }

    #[test]
    fn with_ledger_two_distinct_library_ids_do_not_cross_contaminate() {
        // Loading lib::alpha at a high version MUST NOT inhibit a
        // first-ever load of lib::beta at a low version — the HWM is
        // per-library_id.  Proves the ledger key space is correctly
        // scoped at the signature-module boundary.
        let mut ledger = InMemoryAnomalyLedger::new();
        let cose_alpha = envelope_with_id_and_version("lib::alpha", 100);
        verify_anomaly_library_signature_with_ledger(
            &cose_alpha,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("alpha@100 first-observation must verify");

        let cose_beta = envelope_with_id_and_version("lib::beta", 1);
        verify_anomaly_library_signature_with_ledger(
            &cose_beta,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("beta@1 first-observation must verify despite alpha at 100");
    }

    #[test]
    fn stage7_body_failure_short_circuits_before_stage8_ledger() {
        // T20 fail-order test.  Co-occurrent fault: a library with
        // duplicate pattern_ids (Stage 7a) AND a stale
        // library_version that would separately fail Stage 8.
        //
        // Expected: Stage 7a wins because pattern-body invariants run
        // before the ledger observation.  The signer's actionable fix
        // is "repair the body"; bumping the version on a broken body
        // would leak a broken library into the ledger HWM.
        let mut ledger = InMemoryAnomalyLedger::new();

        // Seed the ledger at version 5 so v1 envelope would be stale.
        let cose_seed = envelope_with_id_and_version("lib::default", 5);
        verify_anomaly_library_signature_with_ledger(
            &cose_seed,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("seed must verify");

        // Build a broken-body envelope at version 1 (stale).  The
        // envelope_with_patterns helper hardcodes library_version=1,
        // which is now stale w.r.t. HWM=5.
        let mut bad_primary = well_formed_patterns()[0].clone();
        let bad_dup = bad_primary.clone(); // duplicate pattern_id
        bad_primary.pattern_id = "delete-storm".into();
        let cose_broken_stale = envelope_with_patterns(vec![bad_primary, bad_dup]);

        let err = verify_anomaly_library_signature_with_ledger(
            &cose_broken_stale,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect_err("broken-body + stale-version must reject");

        // Stage 7 MUST win over Stage 8.
        assert!(
            matches!(err, AnomalyLibError::PatternIdDuplicate { .. }),
            "Stage 7 (pattern-body) MUST short-circuit before Stage 8 \
             (ledger) — got {err:?}"
        );
    }

    #[test]
    fn stage6_time_failure_short_circuits_before_stage8_ledger() {
        // An expired envelope that also declares a stale version must
        // surface the Expired error, not LibraryVersionTooOld.  Stage 6
        // runs before Stage 8 for the same fail-order reason: the
        // signer's fix is "re-sign with a fresh window", not "bump".
        let mut ledger = InMemoryAnomalyLedger::new();
        let cose_seed = envelope_with_id_and_version("lib::alpha", 5);
        verify_anomaly_library_signature_with_ledger(
            &cose_seed,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("seed must verify");

        // Construct a v1 envelope with a past-expiry window.  Signed
        // at T_ISSUED, expires well before T_NOW → Expired.
        let past_expiry = T_ISSUED + 1;
        let expired_payload = AnomalyLibraryPayload {
            abi_version: ANOMALY_LIBRARY_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::alpha".to_string(),
            library_version: 1,
            issued_at: T_ISSUED,
            expires_at: past_expiry,
            patterns: Vec::new(),
        };
        let cose_expired = build_sign1(
            encode_payload(&expired_payload),
            TEST_KID,
            ANOMALY_LIBRARY_AAD,
            SEED,
        );

        let err = verify_anomaly_library_signature_with_ledger(
            &cose_expired,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect_err("expired + stale-version must reject");
        assert!(
            matches!(err, AnomalyLibError::Expired { .. }),
            "Stage 6 (time-bounds) MUST short-circuit before Stage 8 \
             (ledger) — got {err:?}"
        );
    }

    #[test]
    fn stage1_cose_failure_short_circuits_before_stage8_ledger() {
        // A wrong-role anchor produces CoseVerifyFailed at Stage 1 —
        // Stage 8 must not run.  If the ledger observed a
        // CoseVerifyFailed envelope, an attacker could DoS the HWM
        // by submitting rogue envelopes with high declared versions.
        // Proving no-observation-on-Stage-1-failure is the anti-DoS
        // guarantee.
        let pk = signing_key(SEED).verifying_key();
        let wrong_role_anchor = TrustAnchor::new_ed25519(
            TEST_KID.to_string(),
            pk.as_bytes(),
            AnchorRole::TariffSigner,
        )
        .expect("fixed seed yields non-weak pk");
        let mut anchors = TrustAnchorSet::new();
        anchors
            .insert(wrong_role_anchor)
            .expect("fresh set has no dup kid");

        let mut ledger = InMemoryAnomalyLedger::new();
        // Envelope declares a high version — if Stage 8 ran, it would
        // pollute the HWM.
        let cose = envelope_with_id_and_version("lib::alpha", 999);
        let err = verify_anomaly_library_signature_with_ledger(
            &cose,
            &anchors,
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect_err("wrong-role anchor must reject at Stage 1");
        assert!(
            matches!(err, AnomalyLibError::CoseVerifyFailed),
            "Stage 1 (COSE) MUST short-circuit before Stage 8 (ledger) — \
             got {err:?}"
        );

        // Post-hoc proof: a legitimate v1 envelope under the correct
        // anchor MUST still be acceptable as a first observation —
        // i.e., Stage 1's failure did not leak into the ledger state.
        verify_anomaly_library_signature_with_ledger(
            &envelope_with_id_and_version("lib::alpha", 1),
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("post-failure first-observation must still succeed");
    }

    #[test]
    fn with_ledger_dispatches_through_dyn_trait_object() {
        // Compile- and runtime-check that the trait is object-safe
        // and the `?Sized` bound on L lets callers thread
        // `&mut dyn AnomalyLedger` through the public API.  Exercises
        // the intended extensibility vector: a caller holding a
        // boxed or trait-object ledger swaps backends without
        // re-generating the verifier.
        let cose = envelope_with_id_and_version("lib::dyn", 1);
        let mut ledger: Box<dyn AnomalyLedger> = Box::new(InMemoryAnomalyLedger::new());
        verify_anomaly_library_signature_with_ledger(
            &cose,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            ledger.as_mut(),
        )
        .expect("dyn-dispatch first observation must verify");
    }

    #[test]
    fn with_ledger_failed_envelope_leaves_ledger_untouched() {
        // A failed verification (here: wrong ABI version) MUST leave
        // the ledger state untouched.  Proof: after a failed attempt
        // at a high version under the wrong ABI, a legitimate v1
        // load of the same library_id still succeeds as a
        // FirstObservation (the HWM was never seeded).
        let mut ledger = InMemoryAnomalyLedger::new();

        // First attempt: envelope with wrong ABI (validator expects
        // version 1, envelope claims version 42).  Pre-Stage-8 fail.
        let wrong_abi_payload = AnomalyLibraryPayload {
            abi_version: 42,
            signer_kid: TEST_KID.to_string(),
            library_id: "lib::alpha".to_string(),
            library_version: 999, // would bump HWM if Stage 8 ran
            issued_at: T_ISSUED,
            expires_at: T_EXPIRES,
            patterns: Vec::new(),
        };
        let cose_wrong_abi = build_sign1(
            encode_payload(&wrong_abi_payload),
            TEST_KID,
            ANOMALY_LIBRARY_AAD,
            SEED,
        );
        let err = verify_anomaly_library_signature_with_ledger(
            &cose_wrong_abi,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect_err("wrong ABI must reject");
        assert!(matches!(err, AnomalyLibError::AbiVersionMismatch { .. }));

        // Second attempt: legitimate v1 envelope.  If Stage 8 had
        // observed the earlier v999 attempt, this would mis-reject as
        // stale.  FirstObservation success proves no observation
        // leaked.
        let cose_v1 = envelope_with_id_and_version("lib::alpha", 1);
        verify_anomaly_library_signature_with_ledger(
            &cose_v1,
            &anomaly_anchor_set(),
            ANOMALY_LIBRARY_ABI_VERSION,
            T_NOW,
            &mut ledger,
        )
        .expect("legitimate v1 must still be FirstObservation");
    }
}
