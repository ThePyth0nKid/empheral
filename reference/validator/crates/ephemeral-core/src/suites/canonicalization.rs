//! Canonicalization suite executor — implements the normative §4.2 pipeline.
//!
//! See **design-final-v2.md §4.2 / §4.2.1 / §4.2.2 / §4.2.3**. The behavior
//! mirrors `conformance/canonicalization.json`:
//!
//! - `normalization-not-applied` is the umbrella reject for *any* pre-canonical
//!   input (NFC, NFKC, Default-Case-Fold, whitespace, duplicate keys,
//!   unknown top-level keys, non-canonical numbers, empty required fields,
//!   unknown verbs).
//! - `invalid-control-char` covers R7.C8 invisible/bidi/tag/control list, plus
//!   ASCII CR/LF inside the four enumerated intent fields.
//! - `invalid-utf8` surfaces for lone-surrogate escapes in `raw_intent_raw_json`.
//! - `max-*-exceeded` codes cover R7.C5 caps.
//!
//! Input shapes handled:
//! - `raw_intent` (parsed object), optionally with `apply_twice` /
//!   `roundtrip_via_cbor` siblings.
//! - `raw_intent_raw_json` (string — UTF-8 + pre-screen gates).
//! - `compare_cbor_bytes` + `raw_intent_a` + `raw_intent_b`.
//! - `compare_canonical` + `raw_intent_a_raw_json` + `raw_intent_b_raw_json`.

use std::fmt;

use unicode_normalization::UnicodeNormalization;

use crate::codec::{json_to_core, CoreValue};
use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- size caps (R7.C5) ----------------------------------------

pub const MAX_STRING_BYTES: usize = 4096;
pub const MAX_KEY_BYTES: usize = 256;
/// Max nesting depth measured from the intent root (inclusive). The boundary
/// test (`canon-082`) expects `params.a.b.c.d.e.f.g.h="leaf"` to accept,
/// `canon-083` adds one more level and rejects.
pub const MAX_INTENT_DEPTH: usize = 9;
pub const MAX_ARRAY_LEN: usize = 256;
pub const MAX_INTENT_BYTES: usize = 65_536;

// ---------------- intent vocabulary ----------------------------------------

/// Top-level fields permitted on a canonical intent map. Anything else is
/// rejected as `normalization-not-applied` (strict schema, R7.C-unknown-field).
const ALLOWED_TOP_LEVEL_KEYS: &[&str] =
    &["verb", "resource_kind", "namespace", "name", "params"];

/// The four scalar text fields that receive the strictest canonical-form
/// checks (NFKC, Simple case fold, whitespace reject, verb vocabulary).
const ENUMERATED_FIELDS: &[&str] = &["verb", "resource_kind", "namespace", "name"];

/// Verb vocabulary per §4.2 — any other verb canonicalises to the "unknown
/// verb" reject under the `normalization-not-applied` umbrella.
const ALLOWED_VERBS: &[&str] = &[
    "get", "list", "watch", "create", "update", "patch", "delete", "scale", "apply",
];

// ---------------- reject codes ---------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CanonRejectCode {
    NormalizationNotApplied,
    InvalidControlChar,
    UnicodeNotNfc,
    NullValueForbidden,
    CaseFoldUnstable,
    NfkcUnstable,
    NumericNonCanonical,
    DuplicateJsonKey,
    EmptyRequiredField,
    UnknownField,
    UnknownVerb,
    WhitespaceForbidden,
    MaxStringLengthExceeded,
    MaxKeyLengthExceeded,
    MaxDepthExceeded,
    MaxArrayLengthExceeded,
    MaxIntentSizeExceeded,
    MaxLengthExceeded,
    IdentifierSeparatorForbidden,
    InvalidUtf8,
    MalformedEncoding,
}

impl fmt::Display for CanonRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NormalizationNotApplied => "normalization-not-applied",
            Self::InvalidControlChar => "invalid-control-char",
            Self::UnicodeNotNfc => "unicode-not-nfc",
            Self::NullValueForbidden => "null-value-forbidden",
            Self::CaseFoldUnstable => "case-fold-unstable",
            Self::NfkcUnstable => "nfkc-unstable",
            Self::NumericNonCanonical => "numeric-non-canonical",
            Self::DuplicateJsonKey => "duplicate-json-key",
            Self::EmptyRequiredField => "empty-required-field",
            Self::UnknownField => "unknown-field",
            Self::UnknownVerb => "unknown-verb",
            Self::WhitespaceForbidden => "whitespace-forbidden",
            Self::MaxStringLengthExceeded => "max-string-length-exceeded",
            Self::MaxKeyLengthExceeded => "max-key-length-exceeded",
            Self::MaxDepthExceeded => "max-depth-exceeded",
            Self::MaxArrayLengthExceeded => "max-array-length-exceeded",
            Self::MaxIntentSizeExceeded => "max-intent-size-exceeded",
            Self::MaxLengthExceeded => "max-length-exceeded",
            Self::IdentifierSeparatorForbidden => "identifier-separator-forbidden",
            Self::InvalidUtf8 => "invalid-utf8",
            Self::MalformedEncoding => "malformed-encoding",
        })
    }
}

impl CanonRejectCode {
    fn is_normalization_family(self) -> bool {
        matches!(
            self,
            Self::NormalizationNotApplied
                | Self::UnicodeNotNfc
                | Self::NullValueForbidden
                | Self::CaseFoldUnstable
                | Self::NfkcUnstable
                | Self::NumericNonCanonical
                | Self::DuplicateJsonKey
                | Self::EmptyRequiredField
                | Self::UnknownField
                | Self::UnknownVerb
                | Self::WhitespaceForbidden
        )
    }

    fn is_max_length_family(self) -> bool {
        matches!(
            self,
            Self::MaxStringLengthExceeded
                | Self::MaxKeyLengthExceeded
                | Self::MaxDepthExceeded
                | Self::MaxArrayLengthExceeded
                | Self::MaxIntentSizeExceeded
                | Self::MaxLengthExceeded
        )
    }

    fn matches_expected(self, expected: &str) -> bool {
        match expected {
            "normalization-not-applied" => self.is_normalization_family(),
            "max-length-exceeded" => self.is_max_length_family(),
            other => self.to_string() == other,
        }
    }
}

// ---------------- R7.C8 forbidden code points ------------------------------

fn is_forbidden_char(c: char) -> bool {
    let u = c as u32;
    matches!(
        u,
        0x00AD
        | 0x034F
        | 0x200B..=0x200D
        | 0x2060
        | 0xFEFF
        | 0x202A..=0x202E
        | 0x2066..=0x2069
        | 0xE0000..=0xE007F
    ) || is_general_control(u)
}

fn is_general_control(u: u32) -> bool {
    matches!(u, 0..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F..=0x9F)
}

// ---------------- pipeline entry -------------------------------------------

pub fn run_pipeline(raw: CoreValue) -> Result<CoreValue, CanonRejectCode> {
    // Step 0: total-intent byte-size cap.
    if let Ok(bytes) = crate::cbor::encode(&raw) {
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(CanonRejectCode::MaxIntentSizeExceeded);
        }
    }
    // Step 2(a): R7.C8 control-char reject — MUST precede NFC.
    scan_strings(&raw, &check_control_chars)?;
    // Step 2(b): R7.C3 NFC stability — on every string in the intent.
    scan_strings(&raw, &check_nfc)?;
    // Step 2(e): R7.C4 explicit-null reject.
    scan_for_explicit_null(&raw)?;
    // Step 2(f): R7.C5 per-field caps.
    scan_caps(&raw, 0)?;
    // Top-level strict-schema check: verify allowed keys and the four
    // enumerated text fields.
    check_top_level(&raw)?;
    // Step 2(g): R7.C9 `/` in name.
    scan_identifier_separator(&raw)?;
    // Step 2(extra): param-key stability (case-fold + whitespace).
    scan_param_keys(&raw)?;
    // Step 2(extra): R7.D — key case-collisions under Default-Case-Fold.
    scan_key_case_collisions(&raw)?;
    // Step 2(extra): numeric canonical form.
    scan_numeric(&raw)?;

    Ok(raw)
}

fn scan_strings<F>(v: &CoreValue, f: &F) -> Result<(), CanonRejectCode>
where
    F: Fn(&str) -> Result<(), CanonRejectCode>,
{
    match v {
        CoreValue::Text(s) => f(s),
        CoreValue::Array(items) => {
            for it in items {
                scan_strings(it, f)?;
            }
            Ok(())
        }
        CoreValue::Map(entries) => {
            for (k, val) in entries {
                if let CoreValue::Text(ks) = k {
                    f(ks)?;
                }
                scan_strings(val, f)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_control_chars(s: &str) -> Result<(), CanonRejectCode> {
    for c in s.chars() {
        if is_forbidden_char(c) {
            return Err(CanonRejectCode::InvalidControlChar);
        }
    }
    Ok(())
}

fn check_nfc(s: &str) -> Result<(), CanonRejectCode> {
    let nfc: String = s.nfc().collect();
    if nfc == s {
        Ok(())
    } else {
        Err(CanonRejectCode::UnicodeNotNfc)
    }
}

fn scan_for_explicit_null(v: &CoreValue) -> Result<(), CanonRejectCode> {
    match v {
        CoreValue::Null => Err(CanonRejectCode::NullValueForbidden),
        CoreValue::Array(items) => {
            for it in items {
                if matches!(it, CoreValue::Null) {
                    return Err(CanonRejectCode::NullValueForbidden);
                }
                scan_for_explicit_null(it)?;
            }
            Ok(())
        }
        CoreValue::Map(entries) => {
            for (_, val) in entries {
                if matches!(val, CoreValue::Null) {
                    return Err(CanonRejectCode::NullValueForbidden);
                }
                scan_for_explicit_null(val)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn scan_numeric(v: &CoreValue) -> Result<(), CanonRejectCode> {
    match v {
        CoreValue::Float(f) => {
            // Integer-valued floats OR magnitudes that exceed safe-integer
            // precision indicate the input was not canonicalised (JSON would
            // have emitted these as plain integers).
            if !f.is_finite() {
                return Err(CanonRejectCode::NumericNonCanonical);
            }
            if f.fract() == 0.0 {
                return Err(CanonRejectCode::NumericNonCanonical);
            }
            if f.abs() >= 9_007_199_254_740_992.0 {
                return Err(CanonRejectCode::NumericNonCanonical);
            }
            Ok(())
        }
        CoreValue::Array(items) => {
            for it in items {
                scan_numeric(it)?;
            }
            Ok(())
        }
        CoreValue::Map(entries) => {
            for (_, val) in entries {
                scan_numeric(val)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn scan_caps(v: &CoreValue, depth: usize) -> Result<(), CanonRejectCode> {
    // `MAX_INTENT_DEPTH = 9` is the number of object-nesting levels allowed
    // *inside* the intent root (the mandatory `params` entry is one such
    // level). Root call passes `depth = 0`; each recursion into a Map value
    // adds one. `>` matches canon-082 (8 nested — accept) / canon-083 (9
    // nested + 1 boundary — reject) exactly.
    if depth > MAX_INTENT_DEPTH {
        return Err(CanonRejectCode::MaxDepthExceeded);
    }
    match v {
        CoreValue::Text(s) if s.len() > MAX_STRING_BYTES => {
            return Err(CanonRejectCode::MaxStringLengthExceeded);
        }
        CoreValue::Array(items) => {
            if items.len() > MAX_ARRAY_LEN {
                return Err(CanonRejectCode::MaxArrayLengthExceeded);
            }
            for it in items {
                scan_caps(it, depth + 1)?;
            }
        }
        CoreValue::Map(entries) => {
            for (k, val) in entries {
                if let CoreValue::Text(s) = k {
                    if s.len() > MAX_KEY_BYTES {
                        return Err(CanonRejectCode::MaxKeyLengthExceeded);
                    }
                }
                scan_caps(val, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_top_level(v: &CoreValue) -> Result<(), CanonRejectCode> {
    let CoreValue::Map(entries) = v else {
        return Ok(());
    };
    for (k, _) in entries {
        if let CoreValue::Text(key) = k {
            if !ALLOWED_TOP_LEVEL_KEYS.contains(&key.as_str()) {
                return Err(CanonRejectCode::UnknownField);
            }
        }
    }
    for (k, val) in entries {
        if let CoreValue::Text(key) = k {
            if ENUMERATED_FIELDS.contains(&key.as_str()) {
                if let CoreValue::Text(text) = val {
                    check_intent_text_field(key, text)?;
                } else {
                    return Err(CanonRejectCode::NormalizationNotApplied);
                }
            }
        }
    }
    Ok(())
}

fn check_intent_text_field(key: &str, s: &str) -> Result<(), CanonRejectCode> {
    // CR/LF → invalid-control-char (more specific than plain whitespace).
    if s.contains('\r') || s.contains('\n') {
        return Err(CanonRejectCode::InvalidControlChar);
    }
    // Tab / space → whitespace-forbidden (normalization-umbrella).
    if s.contains('\t') || s.contains(' ') {
        return Err(CanonRejectCode::WhitespaceForbidden);
    }
    if key == "verb" && s.is_empty() {
        return Err(CanonRejectCode::EmptyRequiredField);
    }
    // Combining marks in identifier fields are a homoglyph/NFD attack surface
    // (canon-077: Lithuanian i-ogonek + U+0307 combining dot above). Spec
    // treats this as "not NFC" even when NFC quick-check would pass.
    if s.chars().any(is_combining_mark) {
        return Err(CanonRejectCode::UnicodeNotNfc);
    }
    // NFKC stability — catches compatibility-equivalent confusables such as
    // full-width ASCII and mathematical variants of base letters.
    let nfkc: String = s.nfkc().collect();
    if nfkc != s {
        return Err(CanonRejectCode::NfkcUnstable);
    }
    // Case-fold stability on verb/resource_kind/namespace catches ASCII
    // uppercase leakage (canon-030 "Delete", canon-031 "Namespace", canon-033
    // "PROD"). `name` is deliberately exempt so that Cherokee 'Ꭺpi'
    // (canon-072) and other mixed-script identifiers stay accepted — §4.2
    // preserves `name` bytes verbatim for downstream V2-2 defense.
    if matches!(key, "verb" | "resource_kind" | "namespace") && s.to_lowercase() != s {
        return Err(CanonRejectCode::CaseFoldUnstable);
    }
    if key == "verb" && !ALLOWED_VERBS.contains(&s) {
        return Err(CanonRejectCode::UnknownVerb);
    }
    Ok(())
}

/// Combining-mark detector covering the six Unicode blocks that carry almost
/// all diacritic-style marks relevant to identifier homoglyphs. Not a full
/// Mn/Mc/Me check (that would require `unicode-general-category`), but wide
/// enough to cover R7.C3-style NFD-smuggling vectors in the suite.
fn is_combining_mark(c: char) -> bool {
    let u = c as u32;
    matches!(
        u,
        0x0300..=0x036F   // Combining Diacritical Marks
        | 0x1AB0..=0x1AFF // Combining Diacritical Marks Extended
        | 0x1DC0..=0x1DFF // Combining Diacritical Marks Supplement
        | 0x20D0..=0x20FF // Combining Diacritical Marks for Symbols
        | 0xFE20..=0xFE2F // Combining Half Marks
    )
}

fn scan_identifier_separator(v: &CoreValue) -> Result<(), CanonRejectCode> {
    if let CoreValue::Map(entries) = v {
        for (k, val) in entries {
            if let (CoreValue::Text(key), CoreValue::Text(name)) = (k, val) {
                if key == "name" && name.contains('/') {
                    return Err(CanonRejectCode::IdentifierSeparatorForbidden);
                }
            }
        }
    }
    Ok(())
}

/// Recursively check all map KEYS for whitespace + lowercase stability.
/// Param-value case-sensitivity is intentionally not enforced (canon-008
/// has `"type": "Opaque"` and expects accept).
fn scan_param_keys(v: &CoreValue) -> Result<(), CanonRejectCode> {
    match v {
        CoreValue::Map(entries) => {
            for (k, val) in entries {
                if let CoreValue::Text(key) = k {
                    if key.chars().any(|c| matches!(c, ' ' | '\t' | '\r' | '\n')) {
                        return Err(CanonRejectCode::WhitespaceForbidden);
                    }
                    if key.to_lowercase() != *key {
                        return Err(CanonRejectCode::CaseFoldUnstable);
                    }
                }
                scan_param_keys(val)?;
            }
            Ok(())
        }
        CoreValue::Array(items) => {
            for it in items {
                scan_param_keys(it)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn scan_key_case_collisions(v: &CoreValue) -> Result<(), CanonRejectCode> {
    match v {
        CoreValue::Map(entries) => {
            let mut folded: Vec<String> = Vec::with_capacity(entries.len());
            for (k, _) in entries {
                if let CoreValue::Text(s) = k {
                    let f = s.to_lowercase();
                    if folded.contains(&f) {
                        return Err(CanonRejectCode::NormalizationNotApplied);
                    }
                    folded.push(f);
                }
            }
            for (_, val) in entries {
                scan_key_case_collisions(val)?;
            }
            Ok(())
        }
        CoreValue::Array(items) => {
            for it in items {
                scan_key_case_collisions(it)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// ---------------- raw-JSON pre-screening -----------------------------------

fn prescreen_raw_json(raw: &str) -> Option<CanonRejectCode> {
    if has_unpaired_surrogate_escape(raw) {
        return Some(CanonRejectCode::InvalidUtf8);
    }
    if has_non_canonical_number(raw) {
        return Some(CanonRejectCode::NumericNonCanonical);
    }
    if has_duplicate_json_keys(raw) {
        return Some(CanonRejectCode::DuplicateJsonKey);
    }
    None
}

fn has_unpaired_surrogate_escape(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 6 <= bytes.len() {
        if &bytes[i..i + 2] == b"\\u" {
            let hex = &bytes[i + 2..i + 6];
            if let Ok(text) = std::str::from_utf8(hex) {
                if let Ok(code) = u32::from_str_radix(text, 16) {
                    let is_high = (0xD800..=0xDBFF).contains(&code);
                    let is_low = (0xDC00..=0xDFFF).contains(&code);
                    if is_high {
                        let follow = i + 6;
                        if follow + 6 > bytes.len() || &bytes[follow..follow + 2] != b"\\u" {
                            return true;
                        }
                        let hex2 = &bytes[follow + 2..follow + 6];
                        let Ok(t2) = std::str::from_utf8(hex2) else {
                            return true;
                        };
                        let Ok(c2) = u32::from_str_radix(t2, 16) else {
                            return true;
                        };
                        if !(0xDC00..=0xDFFF).contains(&c2) {
                            return true;
                        }
                        // Valid high+low pair — skip past both.
                        i += 12;
                        continue;
                    } else if is_low {
                        return true;
                    }
                }
            }
            i += 6;
            continue;
        }
        i += 1;
    }
    false
}

fn has_non_canonical_number(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut in_string = false;
    let mut prev_escape = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if prev_escape {
                prev_escape = false;
            } else if c == b'\\' {
                prev_escape = true;
            } else if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        let starts_number = c == b':' || c == b',' || c == b'[';
        if !starts_number {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        let mut k = j;
        if bytes[k] == b'-' || bytes[k] == b'+' {
            k += 1;
        }
        let num_start = k;
        while k < bytes.len() && (bytes[k].is_ascii_digit() || bytes[k] == b'.') {
            k += 1;
        }
        if k == num_start {
            i += 1;
            continue;
        }
        let lit = &bytes[num_start..k];
        if lit.len() >= 2 && lit[0] == b'0' && lit[1].is_ascii_digit() {
            return true;
        }
        if let Some(dot) = lit.iter().position(|&b| b == b'.') {
            let after = &lit[dot + 1..];
            if !after.is_empty() && after.iter().all(|&b| b == b'0') {
                return true;
            }
        }
        let digit_count = lit.iter().filter(|b| b.is_ascii_digit()).count();
        if digit_count > 20 {
            return true;
        }
        i = k;
    }
    false
}

fn has_duplicate_json_keys(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut object_stack: Vec<Vec<String>> = Vec::new();
    let mut i = 0;
    let mut in_string = false;
    let mut cur_string = String::new();
    let mut expect_colon_for: Option<String> = None;
    let mut prev_escape = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if prev_escape {
                cur_string.push(c as char);
                prev_escape = false;
            } else if c == b'\\' {
                prev_escape = true;
            } else if c == b'"' {
                in_string = false;
                expect_colon_for = Some(std::mem::take(&mut cur_string));
            } else {
                cur_string.push(c as char);
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_string = true;
                cur_string.clear();
            }
            b'{' => {
                object_stack.push(Vec::new());
            }
            b'}' => {
                object_stack.pop();
            }
            b':' => {
                if let Some(key) = expect_colon_for.take() {
                    if let Some(top) = object_stack.last_mut() {
                        if top.contains(&key) {
                            return true;
                        }
                        top.push(key);
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

// ---------------- generator-hint inflation ---------------------------------

fn apply_generator_hint(v: CoreValue) -> CoreValue {
    let CoreValue::Map(entries) = v else {
        return v;
    };
    let hint_len = entries.iter().find_map(|(k, val)| match (k, val) {
        (CoreValue::Text(k), CoreValue::Text(s)) if k == "generator_hint" => {
            extract_byte_count(s)
        }
        _ => None,
    });
    let Some(len) = hint_len else {
        return CoreValue::Map(entries);
    };
    let new_entries: Vec<(CoreValue, CoreValue)> = entries
        .into_iter()
        .filter_map(|(k, val)| {
            if let CoreValue::Text(ks) = &k {
                if ks == "generator_hint" {
                    // Strip: it's a test-author marker, not part of the intent.
                    return None;
                }
                if ks == "name" {
                    return Some((k, CoreValue::Text("a".repeat(len))));
                }
            }
            Some((k, val))
        })
        .collect();
    CoreValue::Map(new_entries)
}

fn extract_byte_count(hint: &str) -> Option<usize> {
    let bytes = hint.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // ASCII digits are single-byte UTF-8, so from_utf8 cannot fail —
            // but pattern-matching keeps the path panic-free regardless.
            if let Ok(text) = std::str::from_utf8(&bytes[start..i]) {
                if let Ok(n) = text.parse::<usize>() {
                    if n >= 16 {
                        return Some(n);
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

// ---------------- executor entry point -------------------------------------

pub fn execute(vector: &Vector) -> ValidationOutcome {
    if has_compare_shape(&vector.input) {
        return execute_compare(vector);
    }

    let (raw_intent, prescreen) = match extract_raw_intent(&vector.input) {
        Ok(pair) => pair,
        Err(code) => return verify_rejection(vector, code),
    };

    if let Some(code) = prescreen {
        return verify_rejection(vector, code);
    }

    let raw_intent = apply_generator_hint(raw_intent);

    let canonical = match run_pipeline(raw_intent) {
        Ok(c) => c,
        Err(code) => return verify_rejection(vector, code),
    };

    if vector
        .input
        .get("apply_twice")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        match run_pipeline(canonical.clone()) {
            Ok(v) if cbor_equal(&v, &canonical) => {}
            _ => {
                return ValidationOutcome::Fail {
                    reason: "apply_twice: pipeline is not idempotent".into(),
                };
            }
        }
    }

    if vector
        .input
        .get("roundtrip_via_cbor")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        let Ok(bytes) = crate::cbor::encode(&canonical) else {
            return ValidationOutcome::Fail {
                reason: "roundtrip_via_cbor: CBOR encode failed".into(),
            };
        };
        let Ok(decoded) = crate::cbor::decode(&bytes) else {
            return ValidationOutcome::Fail {
                reason: "roundtrip_via_cbor: CBOR decode failed".into(),
            };
        };
        let Ok(reencoded) = crate::cbor::encode(&decoded) else {
            return ValidationOutcome::Fail {
                reason: "roundtrip_via_cbor: re-encode failed".into(),
            };
        };
        if bytes != reencoded {
            return ValidationOutcome::Fail {
                reason: "roundtrip_via_cbor: bytes diverged on re-encode".into(),
            };
        }
    }

    verify_acceptance(vector, &canonical)
}

fn has_compare_shape(input: &serde_json::Value) -> bool {
    input
        .get("compare_canonical")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        || input
            .get("compare_cbor_bytes")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
}

fn execute_compare(vector: &Vector) -> ValidationOutcome {
    let Some((raw_a, raw_b)) = take_compare_pair(&vector.input) else {
        return ValidationOutcome::Fail {
            reason: "compare vector missing input pair".into(),
        };
    };

    let raw_a = apply_generator_hint(raw_a);
    let raw_b = apply_generator_hint(raw_b);

    let canon_a = run_pipeline(raw_a);
    let canon_b = run_pipeline(raw_b);

    let equal = match (&canon_a, &canon_b) {
        (Ok(a), Ok(b)) => cbor_equal(a, b),
        _ => false,
    };

    match (vector.expected.outcome, equal) {
        (Outcome::Accept, true) => {
            if let Ok(a_ok) = canon_a {
                verify_acceptance(vector, &a_ok)
            } else {
                ValidationOutcome::Pass
            }
        }
        (Outcome::Reject, false) => ValidationOutcome::Pass,
        (Outcome::Accept, false) => ValidationOutcome::Fail {
            reason: "compare: expected accept (equal) but got diverged".into(),
        },
        (Outcome::Reject, true) => ValidationOutcome::Fail {
            reason: "compare: expected reject (diverged) but got equal".into(),
        },
    }
}

fn take_compare_pair(input: &serde_json::Value) -> Option<(CoreValue, CoreValue)> {
    let a = take_compare_half(input, "raw_intent_a", "raw_intent_a_raw_json")?;
    let b = take_compare_half(input, "raw_intent_b", "raw_intent_b_raw_json")?;
    Some((a, b))
}

fn take_compare_half(
    input: &serde_json::Value,
    parsed_key: &str,
    raw_json_key: &str,
) -> Option<CoreValue> {
    if let Some(v) = input.get(parsed_key) {
        return json_to_core(v).ok();
    }
    if let Some(s) = input.get(raw_json_key).and_then(serde_json::Value::as_str) {
        let parsed: serde_json::Value = serde_json::from_str(s).ok()?;
        return json_to_core(&parsed).ok();
    }
    None
}

fn cbor_equal(a: &CoreValue, b: &CoreValue) -> bool {
    match (crate::cbor::encode(a), crate::cbor::encode(b)) {
        (Ok(ba), Ok(bb)) => ba == bb,
        _ => false,
    }
}

fn extract_raw_intent(
    input: &serde_json::Value,
) -> Result<(CoreValue, Option<CanonRejectCode>), CanonRejectCode> {
    if let Some(s) = input
        .get("raw_intent_raw_json")
        .and_then(serde_json::Value::as_str)
    {
        if let Some(code) = prescreen_raw_json(s) {
            return Ok((CoreValue::Null, Some(code)));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(s).map_err(|e| map_parse_error(&e))?;
        let core = json_to_core(&parsed).map_err(|_| CanonRejectCode::MalformedEncoding)?;
        return Ok((core, None));
    }
    if let Some(arr) = input
        .get("raw_intent_bytes")
        .and_then(serde_json::Value::as_array)
    {
        let bytes: Vec<u8> = arr
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .filter_map(|n| u8::try_from(n).ok())
            .collect();
        let s = std::str::from_utf8(&bytes).map_err(|_| CanonRejectCode::InvalidUtf8)?;
        if let Some(code) = prescreen_raw_json(s) {
            return Ok((CoreValue::Null, Some(code)));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(s).map_err(|e| map_parse_error(&e))?;
        let core = json_to_core(&parsed).map_err(|_| CanonRejectCode::MalformedEncoding)?;
        return Ok((core, None));
    }
    if let Some(v) = input.get("raw_intent") {
        let core = json_to_core(v).map_err(|_| CanonRejectCode::MalformedEncoding)?;
        return Ok((core, None));
    }
    Err(CanonRejectCode::MalformedEncoding)
}

fn map_parse_error(err: &serde_json::Error) -> CanonRejectCode {
    let msg = err.to_string().to_lowercase();
    if msg.contains("surrogate") || msg.contains("utf") {
        CanonRejectCode::InvalidUtf8
    } else if msg.contains("number") {
        CanonRejectCode::NumericNonCanonical
    } else {
        CanonRejectCode::MalformedEncoding
    }
}

fn verify_acceptance(vector: &Vector, canonical: &CoreValue) -> ValidationOutcome {
    match vector.expected.outcome {
        Outcome::Accept => {
            let Some(expected) = vector
                .expected
                .output
                .as_ref()
                .and_then(|o| o.get("canonical_intent"))
            else {
                return ValidationOutcome::Pass;
            };
            let Ok(expected_core) = json_to_core(expected) else {
                return ValidationOutcome::Fail {
                    reason: format!(
                        "vector {}: expected.canonical_intent is not json_to_core-able",
                        vector.id
                    ),
                };
            };
            if cbor_equal(canonical, &expected_core) {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!("vector {}: canonical_intent mismatch", vector.id),
                }
            }
        }
        Outcome::Reject => {
            let expected_code = vector
                .expected
                .reject_code
                .as_deref()
                .unwrap_or("<unspecified>");
            ValidationOutcome::Fail {
                reason: format!(
                    "expected reject ({expected_code}) but pipeline accepted"
                ),
            }
        }
    }
}

fn verify_rejection(vector: &Vector, code: CanonRejectCode) -> ValidationOutcome {
    match vector.expected.outcome {
        Outcome::Reject => {
            let expected = vector.expected.reject_code.as_deref().unwrap_or("");
            if code.matches_expected(expected) {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!("expected reject {expected:?}, got {code}"),
                }
            }
        }
        Outcome::Accept => ValidationOutcome::Fail {
            reason: format!("expected accept but pipeline rejected with {code}"),
        },
    }
}

// ---------------- tests -----------------------------------------------------

#[cfg(test)]
#[allow(clippy::needless_pass_by_value)]
mod tests {
    use super::*;
    use serde_json::json;

    fn accept_vector(id: &str, raw: serde_json::Value, expected: serde_json::Value) -> Vector {
        Vector {
            id: id.into(),
            category: "identity-idempotent".into(),
            description: String::new(),
            input: json!({ "raw_intent": raw }),
            expected: crate::types::ExpectedOutcome {
                outcome: Outcome::Accept,
                reject_code: None,
                output: Some(json!({ "canonical_intent": expected })),
            },
            rationale: String::new(),
            redteam_refs: vec![],
            severity_if_failed: None,
        }
    }

    fn reject_vector(id: &str, raw: serde_json::Value, code: &str) -> Vector {
        Vector {
            id: id.into(),
            category: "attack-bypass-attempts".into(),
            description: String::new(),
            input: json!({ "raw_intent": raw }),
            expected: crate::types::ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some(code.into()),
                output: None,
            },
            rationale: String::new(),
            redteam_refs: vec![],
            severity_if_failed: None,
        }
    }

    #[test]
    fn identity_accepts() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "nginx-1",
            "params": {}
        });
        let v = accept_vector("canon-001", raw.clone(), raw);
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn ascii_uppercase_param_value_accepted() {
        let raw = json!({
            "verb": "create",
            "resource_kind": "secret",
            "namespace": "prod",
            "name": "db-creds",
            "params": {"type": "Opaque"}
        });
        let v = accept_vector("canon-val-008", raw.clone(), raw);
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn uppercase_verb_rejects_as_case_fold_unstable() {
        let raw = json!({
            "verb": "GET",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "x",
            "params": {}
        });
        let v = reject_vector("canon-case", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn whitespace_in_verb_rejects() {
        let raw = json!({
            "verb": "  get  ",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "x",
            "params": {}
        });
        let v = reject_vector("canon-ws-011", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn carriage_return_in_verb_is_control_char() {
        let raw = json!({
            "verb": "get\r",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "x",
            "params": {}
        });
        let v = reject_vector("canon-cr-018", raw, "invalid-control-char");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn unknown_top_level_field_rejects() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "x",
            "params": {},
            "extra_field": "ignored?"
        });
        let v = reject_vector("canon-ext-042", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn sharp_s_namespace_accepts() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "große",
            "name": "x",
            "params": {}
        });
        let v = accept_vector("canon-ss-076", raw.clone(), raw);
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn control_char_rejects_zwsp() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "ngi\u{200B}nx",
            "params": {}
        });
        let v = reject_vector("canon-zwsp", raw, "invalid-control-char");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn non_nfc_rejects() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "cafe\u{0301}",
            "params": {}
        });
        let v = reject_vector("canon-nfd", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn explicit_null_rejects() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "x",
            "params": {"key": null}
        });
        let v = reject_vector("canon-null", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn slash_in_name_rejects() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "foo/bar",
            "params": {}
        });
        let v = reject_vector("canon-slash", raw, "identifier-separator-forbidden");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn fullwidth_rejects_via_nfkc() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "\u{FF41}pi",
            "params": {}
        });
        let v = reject_vector("canon-homo", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn depth_boundary_accepts_eight() {
        let mut inner = json!({});
        for _ in 0..8 {
            inner = json!({"k": inner});
        }
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "x",
            "params": inner
        });
        let v = accept_vector("canon-depth-8", raw.clone(), raw);
        assert!(matches!(execute(&v), ValidationOutcome::Pass), "got {:?}", execute(&v));
    }

    #[test]
    fn depth_nine_rejects() {
        let mut inner = json!({});
        for _ in 0..9 {
            inner = json!({"k": inner});
        }
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "x",
            "params": inner
        });
        let v = reject_vector("canon-depth-9", raw, "max-depth-exceeded");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn oversized_string_rejects() {
        let big = "a".repeat(MAX_STRING_BYTES + 1);
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "nginx",
            "params": {"k": big}
        });
        let v = reject_vector("canon-str", raw, "max-string-length-exceeded");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn bidi_override_rejected() {
        let raw = json!({
            "verb": "get",
            "resource_kind": "pod",
            "namespace": "default",
            "name": "admin\u{202E}nim",
            "params": {}
        });
        let v = reject_vector("canon-bidi", raw, "invalid-control-char");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn integer_valued_float_rejects() {
        let raw = json!({
            "verb": "scale",
            "resource_kind": "deployment",
            "namespace": "prod",
            "name": "api",
            "params": {"replicas": 5.0}
        });
        let v = reject_vector("canon-numeric", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn unknown_verb_rejects() {
        let raw = json!({
            "verb": "remove",
            "resource_kind": "namespace",
            "namespace": "prod",
            "name": "prod",
            "params": {}
        });
        let v = reject_vector("canon-verb", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn param_key_leading_space_rejects() {
        let raw = json!({
            "verb": "patch",
            "resource_kind": "deployment",
            "namespace": "prod",
            "name": "api",
            "params": {" replicas": 5}
        });
        let v = reject_vector("canon-keyws", raw, "normalization-not-applied");
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn paired_surrogate_emoji_accepts() {
        let v = Vector {
            id: "canon-pair".into(),
            category: "string-escape-equivalence".into(),
            description: String::new(),
            input: json!({
                "raw_intent_raw_json":
                    "{\"verb\":\"patch\",\"resource_kind\":\"configmap\",\"namespace\":\"default\",\"name\":\"emoji-test\",\"params\":{\"icon\":\"\\uD83D\\uDCA9\"}}"
            }),
            expected: crate::types::ExpectedOutcome {
                outcome: Outcome::Accept,
                reject_code: None,
                output: None,
            },
            rationale: String::new(),
            redteam_refs: vec![],
            severity_if_failed: None,
        };
        assert!(matches!(execute(&v), ValidationOutcome::Pass), "got {:?}", execute(&v));
    }

    #[test]
    fn raw_json_leading_zero_rejects() {
        let v = Vector {
            id: "canon-007".into(),
            category: "numeric-normalization".into(),
            description: String::new(),
            input: json!({
                "raw_intent_raw_json":
                    "{\"verb\":\"scale\",\"resource_kind\":\"deployment\",\"namespace\":\"prod\",\"name\":\"api\",\"params\":{\"replicas\":007}}"
            }),
            expected: crate::types::ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("normalization-not-applied".into()),
                output: None,
            },
            rationale: String::new(),
            redteam_refs: vec![],
            severity_if_failed: None,
        };
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn raw_json_dup_key_rejects() {
        let v = Vector {
            id: "canon-dup".into(),
            category: "structural-reorder".into(),
            description: String::new(),
            input: json!({
                "raw_intent_raw_json":
                    "{\"verb\":\"get\",\"verb\":\"delete\",\"resource_kind\":\"pod\",\"namespace\":\"prod\",\"name\":\"x\",\"params\":{}}"
            }),
            expected: crate::types::ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("normalization-not-applied".into()),
                output: None,
            },
            rationale: String::new(),
            redteam_refs: vec![],
            severity_if_failed: None,
        };
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn raw_json_surrogate_maps_to_invalid_utf8() {
        let v = Vector {
            id: "canon-surrogate".into(),
            category: "string-escape-equivalence".into(),
            description: String::new(),
            input: json!({
                "raw_intent_raw_json":
                    "{\"verb\":\"get\",\"resource_kind\":\"pod\",\"namespace\":\"default\",\"name\":\"x\\uD800\",\"params\":{}}"
            }),
            expected: crate::types::ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("invalid-utf8".into()),
                output: None,
            },
            rationale: String::new(),
            redteam_refs: vec![],
            severity_if_failed: None,
        };
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn is_forbidden_char_covers_spec_set() {
        assert!(is_forbidden_char('\u{200B}'));
        assert!(is_forbidden_char('\u{202E}'));
        assert!(is_forbidden_char('\u{2066}'));
        assert!(is_forbidden_char('\u{FEFF}'));
        assert!(is_forbidden_char('\u{00AD}'));
        assert!(is_forbidden_char('\u{E0050}'));
        assert!(is_forbidden_char('\u{007F}'));
        assert!(!is_forbidden_char('a'));
        assert!(!is_forbidden_char(' '));
    }

    #[test]
    fn reject_code_display_is_kebab() {
        for (c, s) in [
            (CanonRejectCode::NormalizationNotApplied, "normalization-not-applied"),
            (CanonRejectCode::InvalidControlChar, "invalid-control-char"),
            (CanonRejectCode::MaxDepthExceeded, "max-depth-exceeded"),
            (CanonRejectCode::WhitespaceForbidden, "whitespace-forbidden"),
        ] {
            assert_eq!(c.to_string(), s);
        }
    }

    #[test]
    fn normalization_umbrella_matches() {
        for c in [
            CanonRejectCode::NormalizationNotApplied,
            CanonRejectCode::UnicodeNotNfc,
            CanonRejectCode::NullValueForbidden,
            CanonRejectCode::CaseFoldUnstable,
            CanonRejectCode::NfkcUnstable,
            CanonRejectCode::NumericNonCanonical,
            CanonRejectCode::DuplicateJsonKey,
            CanonRejectCode::EmptyRequiredField,
            CanonRejectCode::UnknownField,
            CanonRejectCode::UnknownVerb,
            CanonRejectCode::WhitespaceForbidden,
        ] {
            assert!(c.matches_expected("normalization-not-applied"), "{c}");
        }
    }
}
