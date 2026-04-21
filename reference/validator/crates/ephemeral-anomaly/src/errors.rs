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
}
