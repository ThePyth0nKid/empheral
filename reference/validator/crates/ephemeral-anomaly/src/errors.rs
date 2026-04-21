//! Error surface for anomaly-library envelope verification.
//!
//! The enum is `#[non_exhaustive]` so future verification steps
//! (pattern-body validation in Session 2+, rotation-ledger checks
//! later) can introduce variants without breaking downstream exhaustive
//! matches.
//!
//! Variant boundaries follow the classifier-crate convention: every
//! outer-envelope failure folds into [`AnomalyLibError::CoseVerifyFailed`]
//! so an attacker cannot enumerate the anchor set's role assignments by
//! probing `kid`s.  Specific semantic failures (ABI, kid consistency,
//! time bounds) surface their own variants only when the crypto layer
//! has already succeeded — at that point role leakage is no longer a
//! concern because the signature has bound the caller to a known
//! signer.

use thiserror::Error;

/// Maximum length (in bytes) of an attacker-controlled string carried
/// into an error variant for `Display`/log output.  See
/// [`sanitize_log_string`].
pub(crate) const MAX_LOG_STRING_BYTES: usize = 256;

/// Sanitize an attacker-controlled string for safe inclusion in
/// [`Display`](core::fmt::Display) output and logs.
///
/// - Truncated to at most [`MAX_LOG_STRING_BYTES`] bytes.
/// - Every byte outside printable ASCII (`0x20..=0x7E`) is replaced
///   with `'?'` — strips newlines, control characters, ANSI escape
///   sequences, and high-bit bytes that could otherwise confuse log
///   parsers or terminal renderers.
///
/// The cap is applied in bytes, not chars, because the input comes
/// from attacker-controlled fields of a signed CBOR payload (signer
/// kid, library id) which are not guaranteed UTF-8 well-formed nor
/// bounded in length.  Byte-level processing avoids an additional
/// validation step and is safe because every non-ASCII byte is
/// normalised to `'?'`.
///
/// TODO(extract-at-3rd-caller): this helper is duplicated from
/// `ephemeral-classifier::errors::sanitize_log_string`.  Two callers
/// sharing an identical helper is tolerable; a third caller
/// (Phase C.5+ or a new envelope domain) MUST trigger an extract into
/// a shared utility crate — `ephemeral-crypto` or a new
/// `ephemeral-logsafe` — so the three copies cannot drift independently.
pub(crate) fn sanitize_log_string(input: &str) -> String {
    let bytes = input.as_bytes();
    let truncated = if bytes.len() > MAX_LOG_STRING_BYTES {
        &bytes[..MAX_LOG_STRING_BYTES]
    } else {
        bytes
    };
    truncated
        .iter()
        .map(|&b| {
            if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

/// Failure surface for `AnomalyPatternLibrary` envelope verification.
///
/// Returned by [`crate::signature::verify_anomaly_library_signature`].
/// Variant boundaries are drawn to avoid leaking anchor-set structure
/// to an attacker: every outer-envelope failure collapses into
/// [`AnomalyLibError::CoseVerifyFailed`] so unknown-kid, role-mismatch,
/// AAD-mismatch, and signature-invalid are indistinguishable from the
/// caller's perspective.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyLibError {
    /// Outer `COSE_Sign1` verification failed.  All underlying causes
    /// (envelope-size exceeded, CBOR parse error, depth cap, unknown
    /// kid, role mismatch, alg mismatch, AAD mismatch, signature
    /// invalid) fold into this single variant so the caller cannot
    /// distinguish e.g. a missing kid from a role mismatch — otherwise
    /// a probing adversary could enumerate the anchor set's role
    /// assignments by rotating kids.
    #[error("anomaly-library COSE envelope verification failed")]
    CoseVerifyFailed,

    /// The inner payload bytes could not be decoded as a
    /// [`crate::schema::AnomalyLibraryPayload`] CBOR structure, or a
    /// structural field-level cap was exceeded (oversize `signer_kid`,
    /// oversize `library_id`).
    ///
    /// Folding shape failures in with raw CBOR parse failures matches
    /// the classifier-crate convention: either way the signed bytes
    /// violate the v1 envelope contract and the caller's response is
    /// the same (reject).  The crypto signature has already succeeded
    /// at this point so role leakage is no longer a concern.
    #[error("anomaly-library signature payload is not a valid CBOR-encoded AnomalyLibraryPayload")]
    PayloadDecodeFailed,

    /// The `abi_version` declared in the signed payload does not match
    /// the version this validator was built against (passed by the
    /// caller, typically [`crate::ANOMALY_LIBRARY_ABI_VERSION`]).  A
    /// mismatch means the library was signed for a different envelope
    /// era; the validator refuses to trust it.
    #[error(
        "anomaly-library ABI version mismatch: validator expects {expected}, \
         signed payload declares {signed}"
    )]
    AbiVersionMismatch { expected: u32, signed: u32 },

    /// The `signer_kid` field embedded in the signed CBOR payload does
    /// not match the `kid` from the outer `COSE_Sign1` protected
    /// header.  The outer value is cryptographically authoritative;
    /// this check is a defense-in-depth consistency gate that catches
    /// signer-side authoring bugs (duplicated envelopes with stale
    /// inner metadata).
    ///
    /// Both fields are truncated to [`MAX_LOG_STRING_BYTES`] bytes and
    /// sanitised of control characters before storage via
    /// [`sanitize_log_string`], so adversarial CBOR cannot inject
    /// newlines or ANSI sequences into validator logs via this path.
    #[error(
        "anomaly-library signer kid mismatch: outer COSE kid `{outer}`, \
         signed payload claims `{signed}`"
    )]
    SignerKidMismatch { outer: String, signed: String },

    /// Current verification time is before the library's `issued_at`
    /// field — the envelope is signed but not yet active.  Both
    /// values are unix epoch seconds; mismatched clocks between the
    /// signer and verifier are the usual cause.
    #[error(
        "anomaly-library is not yet valid: issued_at={issued_at}, now={now} (unix seconds)"
    )]
    NotYetValid { issued_at: i64, now: i64 },

    /// Current verification time is past the library's `expires_at`
    /// field — the envelope has lapsed and MUST be rotated by the
    /// operator before further use.  Both values are unix epoch
    /// seconds.
    #[error(
        "anomaly-library has expired: expires_at={expires_at}, now={now} (unix seconds)"
    )]
    Expired { expires_at: i64, now: i64 },

    // ──────────────────────────────────────────────────────────────
    // Stage 7 — pattern-body invariant failures (Session 2+).
    //
    // At this point the crypto signature has already succeeded and
    // the library-level metadata has passed Stages 1-6, so role
    // leakage is no longer a concern.  These variants surface
    // structural contradictions inside the pattern table that the
    // signer MUST fix before a retry.
    // ──────────────────────────────────────────────────────────────

    /// Two or more pattern entries share the same `pattern_id`.  Per
    /// §4.2.1 R7.C6 the pattern table has SET semantics — dispatch
    /// keyed by `pattern_id` must be unambiguous, so duplicates
    /// reject at verification time rather than at first match.  The
    /// duplicate id is sanitised via [`sanitize_log_string`] before
    /// storage, so adversarial CBOR cannot inject control characters
    /// through this path.
    #[error("anomaly library contains duplicate pattern_id `{pattern_id}`")]
    PatternIdDuplicate { pattern_id: String },

    /// A pattern's `severity` implies auto-revoke per §3.5.2 but its
    /// declared `action` does not.  Specifically: `severity` ∈
    /// {`high`, `critical`} MUST map to `action = auto-revoke`;
    /// `severity` = `low` or `medium` MAY map to any action.  Both
    /// fields are enum discriminants, so they are rendered as
    /// `&'static str` — no sanitisation required.
    #[error(
        "pattern `{pattern_id}` declares severity `{severity}` but action `{action}` \
         (severity high/critical MUST imply action auto-revoke per §3.5.2)"
    )]
    SeverityActionInconsistent {
        pattern_id: String,
        severity: &'static str,
        action: &'static str,
    },

    /// A pattern's scope predicate references a verb-family name that
    /// is not in the hardcoded family table (see
    /// `crate::families`).  Per §3.5.3 verb families are part of the
    /// validator's trust surface and cannot be operator-defined:
    /// allowing an envelope to rename `iam-attach` to `[noop]` would
    /// defeat the anti-walk-under invariant.  Both `pattern_id` and
    /// `family` are sanitised via [`sanitize_log_string`].
    #[error("pattern `{pattern_id}` references unknown verb family `{family}`")]
    UnknownVerbFamily { pattern_id: String, family: String },

    /// A pattern with `firing_rule = FirstMatch` and a window short
    /// enough to qualify as "ephemeral" (≤
    /// `crate::invariants::ANTI_WALK_UNDER_WINDOW_SECONDS`) must
    /// declare one or more companion patterns with firing rule
    /// `CumulativeOverBaseline` and a window at least
    /// `ANTI_WALK_UNDER_COMPANION_MULTIPLIER × window_seconds`.  This
    /// is the §3.5.3 anti-walk-under invariant: a narrow first-match
    /// window alone lets a patient adversary pace their actions to
    /// stay under it indefinitely.  `missing_reason` pinpoints which
    /// sub-check failed so the signer can fix the table without
    /// trial and error.
    #[error(
        "pattern `{pattern_id}` has firing_rule=first-match with window {window}s \
         (≤ anti-walk-under threshold) but {missing_reason}"
    )]
    FiringRuleCompanionMissing {
        pattern_id: String,
        window: u32,
        missing_reason: FiringCompanionFailure,
    },

    // ──────────────────────────────────────────────────────────────
    // Stage 8 — replay-ledger monotonicity (Session 3+).
    //
    // Surfaces the spec-named reject code `pattern-library-version-
    // too-old` (§3.5.1).  The ledger lives in
    // [`crate::ledger`]; the signature-verification entry point
    // `verify_anomaly_library_signature_with_ledger` threads a mutable
    // ledger through Stage 8 after Stage 7's pattern-body invariants
    // succeed.  The stateless `verify_anomaly_library_signature` never
    // raises this variant (no ledger → no HWM check).
    //
    // The ledger module carries raw `library_id` bytes; this variant
    // sanitises them via [`sanitize_log_string`] at the call site to
    // keep error display log-safe.
    // ──────────────────────────────────────────────────────────────

    /// The declared `library_version` did not strictly exceed the
    /// ledger's stored high-water-mark for this `library_id`.  Covers
    /// both replay (equal version) and rollback (lower version).  The
    /// operator fix is to sign a new library with a strictly higher
    /// version; the validator does NOT accept the envelope even if it
    /// is otherwise signature- and body-valid.
    ///
    /// `library_id` has been passed through [`sanitize_log_string`] at
    /// the call site — the raw form stays inside
    /// [`crate::ledger::LedgerError`].
    #[error(
        "anomaly library `{library_id}` declares library_version {attempted} \
         but ledger HWM is {current_hwm} (pattern-library-version-too-old per §3.5.1)"
    )]
    LibraryVersionTooOld {
        library_id: String,
        current_hwm: u64,
        attempted: u64,
    },

    /// The replay ledger raised a non-monotonicity failure the
    /// signature verifier cannot interpret semantically (e.g. a disk-
    /// or database-backed ledger reporting an I/O error).  V1's
    /// [`crate::ledger::InMemoryAnomalyLedger`] never triggers this
    /// path — it is reserved for future backends whose additional
    /// [`crate::ledger::LedgerError`] variants MUST NOT be silently
    /// bucketed into [`AnomalyLibError::CoseVerifyFailed`] (wrong
    /// semantic: that variant exists for anti-enumeration of role
    /// assignments, not for backend infrastructure failure).
    ///
    /// `reason` carries the backend's own `Display` message and is
    /// sanitised at the call site via [`sanitize_log_string`].  No
    /// role-leakage concern applies here because the crypto signature
    /// already succeeded before Stage 8 ran.
    #[error("anomaly library replay ledger failed: {reason}")]
    LedgerFailure { reason: String },
}

/// Sub-enum surfacing the specific anti-walk-under companion check
/// that rejected a pattern.  Carried inside
/// [`AnomalyLibError::FiringRuleCompanionMissing`] so the failure
/// message points the signer at the exact fix — "declare at least
/// one companion", "rename the referenced companion", "widen the
/// companion window" — without requiring the signer to re-derive
/// the §3.5.3 rules from scratch.
///
/// All string fields are sanitised at construction time so Display
/// cannot re-leak control characters.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FiringCompanionFailure {
    /// `firing_rule_companions` is empty — the pattern declares no
    /// long-window backstop at all.
    #[error("no firing_rule_companions are declared")]
    NoCompanionsDeclared,

    /// A named companion references a `pattern_id` that does not
    /// exist in this library.  Name is sanitised via
    /// [`sanitize_log_string`].
    #[error("companion `{name}` is not a known pattern_id in this library")]
    CompanionNotFound { name: String },

    /// The referenced companion exists but its `firing_rule` is not
    /// `CumulativeOverBaseline`.  Per §3.5.3 only a cumulative-over-
    /// baseline companion closes the walk-under gap — a companion
    /// that is itself a FirstMatch provides no long-window backstop.
    #[error(
        "companion `{name}` exists but its firing_rule is not CumulativeOverBaseline"
    )]
    CompanionNotCumulative { name: String },

    /// The companion is cumulative but its `window_seconds` is
    /// shorter than the required multiplier of the first-match
    /// window.  Carries both values so the signer knows exactly how
    /// much to widen.
    #[error(
        "companion `{name}` window {companion_window}s is shorter than required \
         minimum {required_minimum}s ({multiplier}× the first-match window)",
        multiplier = crate::invariants::ANTI_WALK_UNDER_COMPANION_MULTIPLIER
    )]
    CompanionWindowTooShort {
        name: String,
        companion_window: u32,
        required_minimum: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_passes_printable_ascii_unchanged() {
        assert_eq!(sanitize_log_string("lib::sample-v1"), "lib::sample-v1");
        assert_eq!(sanitize_log_string(""), "");
    }

    #[test]
    fn sanitize_replaces_control_chars() {
        assert_eq!(sanitize_log_string("a\nb"), "a?b");
        assert_eq!(sanitize_log_string("a\tb\rc"), "a?b?c");
        assert_eq!(sanitize_log_string("\x1b[31mred"), "?[31mred");
    }

    #[test]
    fn sanitize_replaces_non_ascii_bytes() {
        // Each multi-byte UTF-8 encoded codepoint maps 1 byte -> '?'.
        assert_eq!(sanitize_log_string("café"), "caf??");
        assert_eq!(sanitize_log_string("\u{FFFF}"), "???");
    }

    #[test]
    fn sanitize_truncates_past_max_length() {
        let input: String = "a".repeat(MAX_LOG_STRING_BYTES + 50);
        let out = sanitize_log_string(&input);
        assert_eq!(out.len(), MAX_LOG_STRING_BYTES);
        assert!(out.chars().all(|c| c == 'a'));
    }

    #[test]
    fn sanitize_truncates_at_byte_boundary_safely() {
        // Cap is bytes; if truncation falls mid-UTF-8-codepoint, the
        // following map replaces the orphan high-bit bytes with '?',
        // so the result is always a valid String.
        let prefix = "a".repeat(MAX_LOG_STRING_BYTES - 1);
        let input = format!("{prefix}ä"); // 'ä' = 2 bytes (0xC3 0xA4)
        let out = sanitize_log_string(&input);
        assert_eq!(out.len(), MAX_LOG_STRING_BYTES);
        assert!(out.ends_with("a?"));
    }

    #[test]
    fn sanitize_truncates_mid_three_byte_codepoint_safely() {
        // Push a 3-byte codepoint across the cap so that one leading
        // byte and one continuation byte land inside the cap, and the
        // second continuation byte is dropped.  Both retained bytes
        // are `>= 0x80` and map to `'?'`, producing a safe String.
        let prefix = "a".repeat(MAX_LOG_STRING_BYTES - 2);
        let input = format!("{prefix}\u{2603}"); // ☃ = 3 bytes (E2 98 83)
        let out = sanitize_log_string(&input);
        assert_eq!(out.len(), MAX_LOG_STRING_BYTES);
        // Last character before cap is the 'a' pad; the two retained
        // bytes of ☃ both sanitise to '?'.
        assert!(out.ends_with("a??"));
    }

    #[test]
    fn sanitize_truncates_mid_four_byte_codepoint_safely() {
        // Push a 4-byte codepoint across the cap so that one leading
        // byte and two continuation bytes land inside the cap, and
        // the third continuation byte is dropped.  All three retained
        // bytes are `>= 0x80` and map to `'?'`.
        let prefix = "a".repeat(MAX_LOG_STRING_BYTES - 3);
        let input = format!("{prefix}\u{1F600}"); // 😀 = 4 bytes (F0 9F 98 80)
        let out = sanitize_log_string(&input);
        assert_eq!(out.len(), MAX_LOG_STRING_BYTES);
        assert!(out.ends_with("a???"));
    }

    #[test]
    fn signer_kid_mismatch_display_does_not_embed_raw_newlines() {
        // The verifier sanitises both kids before building the variant;
        // this test locks that Display output stays single-line even if
        // a raw control character slipped into the struct by direct
        // construction (defense-in-depth: error display is the last
        // rendering step and must not re-leak).
        let err = AnomalyLibError::SignerKidMismatch {
            outer: sanitize_log_string("K_out\nINJ"),
            signed: sanitize_log_string("K_in\rINJ"),
        };
        let display = format!("{err}");
        assert!(!display.contains('\n'));
        assert!(!display.contains('\r'));
        assert!(display.contains("K_out?INJ"));
        assert!(display.contains("K_in?INJ"));
    }

    #[test]
    fn pattern_id_duplicate_display_stays_single_line() {
        let err = AnomalyLibError::PatternIdDuplicate {
            pattern_id: sanitize_log_string("pat::dup\nINJ"),
        };
        let display = format!("{err}");
        assert!(!display.contains('\n'));
        assert!(display.contains("pat::dup?INJ"));
    }

    #[test]
    fn severity_action_inconsistent_display_uses_static_discriminants() {
        let err = AnomalyLibError::SeverityActionInconsistent {
            pattern_id: sanitize_log_string("pat::ok"),
            severity: "critical",
            action: "require-human-approval",
        };
        let display = format!("{err}");
        assert!(display.contains("severity `critical`"));
        assert!(display.contains("action `require-human-approval`"));
        assert!(display.contains("§3.5.2"));
    }

    #[test]
    fn unknown_verb_family_display_sanitises_both_fields() {
        let err = AnomalyLibError::UnknownVerbFamily {
            pattern_id: sanitize_log_string("pat::x\tINJ"),
            family: sanitize_log_string("not-a-family\x00INJ"),
        };
        let display = format!("{err}");
        assert!(!display.contains('\n'));
        assert!(!display.contains('\t'));
        assert!(!display.contains('\0'));
        assert!(display.contains("pat::x?INJ"));
        assert!(display.contains("not-a-family?INJ"));
    }

    #[test]
    fn firing_companion_failure_variants_render_distinctly() {
        let none = FiringCompanionFailure::NoCompanionsDeclared;
        assert!(format!("{none}").contains("no firing_rule_companions"));

        let missing = FiringCompanionFailure::CompanionNotFound {
            name: sanitize_log_string("pat::missing\nINJ"),
        };
        let missing_d = format!("{missing}");
        assert!(!missing_d.contains('\n'));
        assert!(missing_d.contains("pat::missing?INJ"));

        let not_cum = FiringCompanionFailure::CompanionNotCumulative {
            name: sanitize_log_string("pat::wrong-rule"),
        };
        assert!(format!("{not_cum}").contains("CumulativeOverBaseline"));

        let too_short = FiringCompanionFailure::CompanionWindowTooShort {
            name: sanitize_log_string("pat::short"),
            companion_window: 1800,
            required_minimum: 18_000,
        };
        let too_short_d = format!("{too_short}");
        assert!(too_short_d.contains("1800s"));
        assert!(too_short_d.contains("18000s"));
        // The multiplier is injected from the invariants module const
        // so the message stays in sync if the constant moves.
        assert!(too_short_d.contains(&format!(
            "{}×",
            crate::invariants::ANTI_WALK_UNDER_COMPANION_MULTIPLIER
        )));
    }

    #[test]
    fn firing_rule_companion_missing_nests_sub_variant_cleanly() {
        let err = AnomalyLibError::FiringRuleCompanionMissing {
            pattern_id: sanitize_log_string("pat::ephemeral"),
            window: 300,
            missing_reason: FiringCompanionFailure::NoCompanionsDeclared,
        };
        let display = format!("{err}");
        assert!(display.contains("pat::ephemeral"));
        assert!(display.contains("300s"));
        assert!(display.contains("no firing_rule_companions"));
    }

    #[test]
    fn library_version_too_old_display_contains_all_fields_and_spec_ref() {
        // The variant surfaces the §3.5.1 reject code
        // `pattern-library-version-too-old` plus the three values an
        // operator needs to produce a valid re-signed envelope:
        // which library, what HWM, what they attempted.  Pin every
        // field in the rendered Display so a future format change
        // cannot silently drop one.
        let err = AnomalyLibError::LibraryVersionTooOld {
            library_id: sanitize_log_string("lib::prod-v1"),
            current_hwm: 42,
            attempted: 41,
        };
        let display = format!("{err}");
        assert!(display.contains("lib::prod-v1"));
        assert!(display.contains("42"));
        assert!(display.contains("41"));
        assert!(display.contains("pattern-library-version-too-old"));
        assert!(display.contains("§3.5.1"));
    }

    #[test]
    fn library_version_too_old_display_stays_single_line_with_sanitised_id() {
        // The variant stores a String `library_id` that the signature
        // module sanitises before construction, but Display is the
        // last rendering step — defense-in-depth: even a direct
        // construction with control chars pre-baked into the field
        // MUST NOT re-leak newlines or ANSI escapes.  Sanitised
        // injection attempts collapse control bytes to '?'.
        let err = AnomalyLibError::LibraryVersionTooOld {
            library_id: sanitize_log_string("lib::inj\nINJ"),
            current_hwm: 1,
            attempted: 0,
        };
        let display = format!("{err}");
        assert!(!display.contains('\n'));
        assert!(!display.contains('\r'));
        assert!(display.contains("lib::inj?INJ"));
    }
}
