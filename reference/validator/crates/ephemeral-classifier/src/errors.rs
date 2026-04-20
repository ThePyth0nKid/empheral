//! Error surface for classifier loading and execution.
//!
//! Both enums are `#[non_exhaustive]`.  Phase C.3-A defined the minimal
//! variant set required for hash verification and basic execute; Phase
//! C.3-B extends the load-time surface with pre-instantiation-walk
//! diagnostics ([`ClassifierLoadError::ForbiddenImport`],
//! [`ClassifierLoadError::ForbiddenStartFunction`],
//! [`ClassifierLoadError::InvalidExportSignature`]) and adds
//! [`ClassifierExecError::MemoryGrowthDenied`] for linear-memory cap
//! enforcement via a `ResourceLimiter`.
//!
//! `MissingExport` was moved from [`ClassifierExecError`] to
//! [`ClassifierLoadError`] in C.3-B — the check now runs before
//! instantiation, not after.

use thiserror::Error;

/// Maximum length (in bytes) of an attacker-controlled string carried
/// into an error variant for `Display`/log output.  See
/// [`sanitize_log_string`].
pub(crate) const MAX_LOG_STRING_BYTES: usize = 256;

/// Sanitize an attacker-controlled string for safe inclusion in
/// [`Display`](core::fmt::Display) output and logs:
///
/// - truncated to at most [`MAX_LOG_STRING_BYTES`] bytes;
/// - every byte outside printable ASCII (0x20..=0x7E) is replaced with
///   `'?'` — this strips newlines, control characters, ANSI escape
///   sequences, and high-bit bytes that could otherwise confuse log
///   parsers or terminal renderers.
///
/// The cap is applied in bytes, not chars, because the input comes from
/// attacker-controlled sections of a WASM binary (import names, export
/// names) which are neither guaranteed UTF-8 well-formed nor bounded in
/// length.  Byte-level processing avoids an additional validation step
/// and is safe because every non-ASCII byte is normalised to `'?'`.
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

/// Failure surface for classifier *loading* — hash pinning, pre-instantiation
/// module walks, and ABI-signature validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassifierLoadError {
    /// The expected-hash string is not a 64-character lowercase-hex digest.
    #[error("expected hash is not a 64-character lowercase-hex digest")]
    InvalidHashHex,

    /// `SHA-256(wasm_bytes)` does not match the expected digest.
    #[error("classifier WASM hash mismatch")]
    HashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// The module declares an import (function, memory, table, or global).
    /// Spec §4.3 hermeticity forbids any import in a conformant classifier;
    /// the pre-instantiation walk names the offending entry.
    #[error("classifier WASM imports `{module}::{name}` ({kind}); spec §4.3 forbids all imports")]
    ForbiddenImport {
        module: String,
        name: String,
        /// One of `"function"`, `"memory"`, `"table"`, `"global"`.
        kind: &'static str,
    },

    /// The module declares a `(start …)` function.  ABI v1 requires that
    /// every meaningful execution happen through the explicit `alloc`/
    /// `classify` entry points; implicit start-time execution is forbidden.
    #[error("classifier WASM declares a start function; ABI v1 forbids implicit entry points")]
    ForbiddenStartFunction,

    /// A required export (`memory`, `alloc`, or `classify`) is absent.
    #[error("required export `{name}` is missing")]
    MissingExport { name: &'static str },

    /// A required export is present but its type signature does not match
    /// the ABI v1 contract.
    #[error("export `{name}` has wrong signature: expected {expected}, got {actual}")]
    InvalidExportSignature {
        name: &'static str,
        expected: &'static str,
        actual: String,
    },
}

/// Failure surface for classifier *execution*.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassifierExecError {
    /// `wasmi::Module::new` could not parse the supplied WASM bytes.
    /// This also covers rejection by the `Config`-level feature disables
    /// (SIMD, bulk-memory, reference-types, etc.) — those surface as
    /// parse failures rather than as a dedicated variant, because
    /// disentangling wasmi's internal parse-error taxonomy would couple
    /// this crate to wasmi's unstable internals.
    #[error("WASM module failed to parse or uses a disabled feature")]
    WasmParseError,

    /// `wasmi::Linker::instantiate` failed for a reason other than an
    /// explicitly-walked ForbiddenImport/ForbiddenStartFunction — e.g.
    /// data-segment out-of-bounds at instantiation.
    #[error("WASM instance could not be created")]
    InstantiationFailed,

    /// The `alloc` export trapped (e.g. memory.grow failure that the
    /// guest translated to `unreachable`).
    #[error("`alloc` trapped")]
    AllocCallTrap,

    /// The `classify` export trapped — fuel exhaustion, `unreachable`,
    /// div-by-zero, or a memory-access trap inside the guest.
    #[error("`classify` trapped")]
    ClassifyCallTrap,

    /// A host-mediated input or output memory access was out of bounds
    /// of the classifier's linear memory.
    #[error("WASM linear-memory access out of bounds")]
    MemoryAccessError,

    /// The classifier's packed output locator claimed a length above the
    /// host-side allocation ceiling [`crate::ClassifierConfig::max_output_bytes`].
    /// Reported before any `vec![0u8; claimed]` is allocated, so an
    /// attacker-controlled length field cannot OOM-kill the validator.
    #[error(
        "classifier claimed output of {claimed} bytes; \
         host ceiling is {cap} bytes (max_output_bytes)"
    )]
    OutputTooLarge { claimed: usize, cap: usize },

    /// The caller-supplied context exceeds the `i32::MAX` byte envelope
    /// that the v1 ABI can address.
    #[error("input CBOR context is {len} bytes; ceiling is i32::MAX")]
    InputTooLarge { len: usize },

    /// The classifier attempted to grow linear memory past the
    /// configured cap (`ClassifierConfig::max_memory_pages`).  Reported
    /// in pages (64 KiB per page), not bytes, to match the ABI's
    /// native unit.
    #[error(
        "memory.grow denied: current={current_pages} pages, requested={requested_pages} pages, \
         cap={cap_pages} pages"
    )]
    MemoryGrowthDenied {
        current_pages: u32,
        requested_pages: u32,
        cap_pages: u32,
    },

    /// CBOR deserialization of the classifier's output bytes failed
    /// (malformed CBOR, missing required field, wrong type, etc.).
    #[error("classifier output is not a valid CBOR-encoded ClassifierOutput")]
    OutputDecodeFailed,
}

/// Combined load + execute failure surface.
///
/// [`crate::execute_classifier`] returns this so callers can distinguish
/// deterministic load-time rejections (import forbidden, ABI mismatch,
/// start-function present) from per-invocation execution failures
/// (fuel exhaustion, trap, memory cap, decode error) without a second
/// enum layer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassifierError {
    #[error(transparent)]
    Load(#[from] ClassifierLoadError),
    #[error(transparent)]
    Exec(#[from] ClassifierExecError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_passes_printable_ascii_unchanged() {
        assert_eq!(sanitize_log_string("env::host_log"), "env::host_log");
        assert_eq!(
            sanitize_log_string("(i32, i32) -> i64"),
            "(i32, i32) -> i64"
        );
        assert_eq!(sanitize_log_string(""), "");
    }

    #[test]
    fn sanitize_replaces_control_chars() {
        assert_eq!(sanitize_log_string("a\nb"), "a?b");
        assert_eq!(sanitize_log_string("a\tb\rc"), "a?b?c");
        // ANSI CSI sequence → '?' for ESC (0x1B), rest passes.
        assert_eq!(sanitize_log_string("\x1b[31mred"), "?[31mred");
    }

    #[test]
    fn sanitize_replaces_non_ascii_bytes() {
        // Multi-byte UTF-8 encoded name: each high-bit byte becomes '?'.
        assert_eq!(sanitize_log_string("café"), "caf??");
        // Raw non-UTF-8 bytes can't be constructed here without unsafe,
        // but the byte-level sanitiser replaces every byte >= 0x80
        // regardless of UTF-8 structure — any multi-byte codepoint
        // produces one '?' per encoded byte.
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
    fn forbidden_import_display_is_sanitized_at_construction() {
        // Caller builds the variant directly with an attacker-style name.
        // Display output must not embed a newline even if the inner
        // String field (post-sanitize) was set manually to printable ASCII.
        let err = ClassifierLoadError::ForbiddenImport {
            module: sanitize_log_string("env\nINJECTED"),
            name: sanitize_log_string("x"),
            kind: "function",
        };
        let display = format!("{err}");
        assert!(!display.contains('\n'));
        assert!(display.contains("env?INJECTED"));
    }
}
