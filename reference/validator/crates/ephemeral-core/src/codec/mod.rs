//! JSON ↔ `CoreValue` conversion with roundtrip check.
//!
//! [`CoreValue`] is the validator's internal, canonicalization-ready value
//! representation. It is a thin supertype of JSON plus byte-string and CBOR
//! integer width (we use `i128` so the full CBOR integer range survives
//! decode). It is **not** the same as `serde_json::Value`:
//!
//! - JSON numbers route to `Int(i128)` when representable losslessly, else
//!   `Float(f64)`.
//! - JSON strings route to `Text(String)` (post-validation NFC will land in
//!   the canonicalization module in Session 2).
//! - JSON objects route to `Map(Vec<(CoreValue, CoreValue)>)` — keys remain
//!   strings here but the representation can carry any-key maps when CBOR
//!   determinism arrives.
//!
//! Session 1 scope: establish the lossless JSON-only roundtrip. Deterministic
//! CBOR encoding (R7.C6 SET ordering + RFC 8949 §4.2) lands in Session 2.
//!
//! # Known limitation — IEEE 754 negative zero
//!
//! JSON has no distinct representation for `-0.0`; `serde_json` normalizes
//! negative zero to positive zero during `Number::from_f64`. The roundtrip
//! check therefore treats `-0.0` and `0.0` as equal. This is a JSON-not-CBOR
//! limitation; the Session-2 canonical-CBOR encoder will preserve the sign
//! bit per RFC 8949 §4.2.1.

use std::fmt;

/// Maximum JSON/CoreValue nesting depth accepted by `json_to_core` /
/// `core_to_json`. Hand-crafted deeply nested inputs would otherwise
/// stack-overflow the recursive walkers. 64 is ~4× `serde_json`'s own parse
/// recursion limit — the validator will never see a document deeper than
/// `serde_json` would refuse to parse in the first place.
pub const MAX_JSON_DEPTH: usize = 64;

/// Internal canonical value representation.
#[derive(Debug, Clone, PartialEq)]
pub enum CoreValue {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<CoreValue>),
    /// Map entries, deliberately a `Vec` (not a `BTreeMap`) so callers can
    /// observe and control ordering when the canonical-CBOR encoder lands.
    Map(Vec<(CoreValue, CoreValue)>),
}

impl CoreValue {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// A value from JSON never carries byte strings — this helper lets callers
    /// pin that invariant in assertions.
    pub fn contains_bytes(&self) -> bool {
        match self {
            Self::Bytes(_) => true,
            Self::Array(items) => items.iter().any(Self::contains_bytes),
            Self::Map(entries) => entries
                .iter()
                .any(|(k, v)| k.contains_bytes() || v.contains_bytes()),
            _ => false,
        }
    }
}

/// Convert a parsed JSON value into a [`CoreValue`].
///
/// Numbers that are representable as `i128` route to `Int`; all others route
/// to `Float(f64)` (JSON's number grammar has no integer/float distinction).
/// Returns `Err(CoreToJsonError::DepthExceeded)` if the input exceeds
/// [`MAX_JSON_DEPTH`] levels of nesting.
pub fn json_to_core(v: &serde_json::Value) -> Result<CoreValue, CoreToJsonError> {
    json_to_core_impl(v, 0)
}

fn json_to_core_impl(v: &serde_json::Value, depth: usize) -> Result<CoreValue, CoreToJsonError> {
    if depth > MAX_JSON_DEPTH {
        return Err(CoreToJsonError::DepthExceeded);
    }
    Ok(match v {
        serde_json::Value::Null => CoreValue::Null,
        serde_json::Value::Bool(b) => CoreValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CoreValue::Int(i128::from(i))
            } else if let Some(u) = n.as_u64() {
                CoreValue::Int(i128::from(u))
            } else if let Some(f) = n.as_f64() {
                CoreValue::Float(f)
            } else {
                // Spec-wise this branch is unreachable for serde_json::Number.
                CoreValue::Null
            }
        }
        serde_json::Value::String(s) => CoreValue::Text(s.clone()),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(json_to_core_impl(it, depth + 1)?);
            }
            CoreValue::Array(out)
        }
        serde_json::Value::Object(obj) => {
            let mut out = Vec::with_capacity(obj.len());
            for (k, v) in obj {
                out.push((
                    CoreValue::Text(k.clone()),
                    json_to_core_impl(v, depth + 1)?,
                ));
            }
            CoreValue::Map(out)
        }
    })
}

/// Error converting a [`CoreValue`] back to `serde_json::Value`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CoreToJsonError {
    /// JSON cannot carry raw byte strings.
    BytesNotExpressible,
    /// JSON object keys must be strings; a non-`Text` key was encountered.
    NonStringMapKey,
    /// JSON cannot carry NaN or ±infinity.
    NonFiniteFloat,
    /// Integer larger than `i64::MAX` / smaller than `i64::MIN`.
    ///
    /// `serde_json::Number` does accept `u64` but the combined `[i64::MIN,
    /// u64::MAX]` window is still a strict subset of `i128`.
    IntOutOfJsonRange,
    /// Duplicate keys in a map — JSON objects disallow this semantically.
    DuplicateMapKey(String),
    /// JSON → `CoreValue` → JSON did not round-trip to an equal value. This is
    /// a harness bug if it fires, not a property of the input document.
    RoundtripMismatch,
    /// Value exceeds `MAX_JSON_DEPTH`. Defends against stack overflow from
    /// adversarial inputs whose nesting depth survives `serde_json`'s own
    /// parse-time depth limit (128) but still triggers our recursive walker.
    DepthExceeded,
}

impl fmt::Display for CoreToJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BytesNotExpressible => f.write_str("byte-string is not expressible as JSON"),
            Self::NonStringMapKey => f.write_str("map key is not a text string"),
            Self::NonFiniteFloat => f.write_str("float is NaN or infinite"),
            Self::IntOutOfJsonRange => f.write_str("integer is outside the JSON number range"),
            Self::DuplicateMapKey(k) => write!(f, "duplicate map key: {k}"),
            Self::RoundtripMismatch => {
                f.write_str("json→core→json round-trip did not preserve value equality")
            }
            Self::DepthExceeded => {
                write!(f, "value nesting exceeds MAX_JSON_DEPTH ({MAX_JSON_DEPTH})")
            }
        }
    }
}

impl std::error::Error for CoreToJsonError {}

/// Convert a [`CoreValue`] back to a parsed JSON value.
///
/// Returns `Err(CoreToJsonError::DepthExceeded)` if the value exceeds
/// [`MAX_JSON_DEPTH`] levels of nesting.
pub fn core_to_json(v: &CoreValue) -> Result<serde_json::Value, CoreToJsonError> {
    core_to_json_impl(v, 0)
}

fn core_to_json_impl(v: &CoreValue, depth: usize) -> Result<serde_json::Value, CoreToJsonError> {
    if depth > MAX_JSON_DEPTH {
        return Err(CoreToJsonError::DepthExceeded);
    }
    Ok(match v {
        CoreValue::Null => serde_json::Value::Null,
        CoreValue::Bool(b) => serde_json::Value::Bool(*b),
        CoreValue::Int(i) => {
            if let Ok(as_i64) = i64::try_from(*i) {
                serde_json::Value::Number(serde_json::Number::from(as_i64))
            } else if let Ok(as_u64) = u64::try_from(*i) {
                serde_json::Value::Number(serde_json::Number::from(as_u64))
            } else {
                return Err(CoreToJsonError::IntOutOfJsonRange);
            }
        }
        CoreValue::Float(f) => {
            let n = serde_json::Number::from_f64(*f).ok_or(CoreToJsonError::NonFiniteFloat)?;
            serde_json::Value::Number(n)
        }
        CoreValue::Text(s) => serde_json::Value::String(s.clone()),
        CoreValue::Bytes(_) => return Err(CoreToJsonError::BytesNotExpressible),
        CoreValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(core_to_json_impl(it, depth + 1)?);
            }
            serde_json::Value::Array(out)
        }
        CoreValue::Map(entries) => {
            let mut obj = serde_json::Map::with_capacity(entries.len());
            for (k, val) in entries {
                let key = match k {
                    CoreValue::Text(s) => s.clone(),
                    _ => return Err(CoreToJsonError::NonStringMapKey),
                };
                if obj.contains_key(&key) {
                    return Err(CoreToJsonError::DuplicateMapKey(key));
                }
                obj.insert(key, core_to_json_impl(val, depth + 1)?);
            }
            serde_json::Value::Object(obj)
        }
    })
}

/// Assert that a JSON value survives the `json → CoreValue → json` round-trip
/// exactly (structural equality via `serde_json::Value`'s `PartialEq`).
///
/// Returns [`CoreToJsonError::RoundtripMismatch`] on equality failure; surfaces
/// the underlying error directly for depth / numeric / bytes violations.
/// IEEE 754 `-0.0` is normalized to `0.0` by `serde_json` — see the module
/// doc for details.
///
/// This is the Session 1 minimum evidence that [`CoreValue`] is a faithful
/// intermediate. In Session 2 we extend to `json → CoreValue →
/// canonical-CBOR → CoreValue → json`.
pub fn assert_json_roundtrip(v: &serde_json::Value) -> Result<(), CoreToJsonError> {
    let core = json_to_core(v)?;
    let back = core_to_json(&core)?;
    if v == &back {
        Ok(())
    } else {
        Err(CoreToJsonError::RoundtripMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        let cases: &[serde_json::Value] = &[
            serde_json::Value::Null,
            serde_json::Value::Bool(true),
            serde_json::Value::Bool(false),
            serde_json::json!(0),
            serde_json::json!(1),
            serde_json::json!(-1),
            serde_json::json!(i64::MAX),
            serde_json::json!(i64::MIN),
            serde_json::json!(""),
            serde_json::json!("hello"),
            serde_json::json!(1.5),
        ];
        for c in cases {
            assert_json_roundtrip(c).unwrap_or_else(|e| panic!("failed {c}: {e}"));
        }
    }

    #[test]
    fn roundtrip_nested() {
        let v = serde_json::json!({
            "id": "canon-001",
            "tags": ["a", "b", "c"],
            "nested": {
                "int": 42,
                "null": null,
                "arr": [1, 2, {"inner": true}]
            }
        });
        assert_json_roundtrip(&v).unwrap();
    }

    #[test]
    fn roundtrip_empty_containers() {
        assert_json_roundtrip(&serde_json::json!({})).unwrap();
        assert_json_roundtrip(&serde_json::json!([])).unwrap();
        assert_json_roundtrip(&serde_json::json!({"empty_arr": [], "empty_obj": {}})).unwrap();
    }

    #[test]
    fn bytes_cannot_roundtrip_to_json() {
        let c = CoreValue::Bytes(vec![1, 2, 3]);
        let err = core_to_json(&c).unwrap_err();
        assert_eq!(err, CoreToJsonError::BytesNotExpressible);
    }

    #[test]
    fn non_finite_float_rejected() {
        let c = CoreValue::Float(f64::NAN);
        assert_eq!(
            core_to_json(&c).unwrap_err(),
            CoreToJsonError::NonFiniteFloat
        );
        let c = CoreValue::Float(f64::INFINITY);
        assert_eq!(
            core_to_json(&c).unwrap_err(),
            CoreToJsonError::NonFiniteFloat
        );
    }

    #[test]
    fn non_string_key_rejected() {
        let c = CoreValue::Map(vec![(CoreValue::Int(1), CoreValue::Bool(true))]);
        assert_eq!(
            core_to_json(&c).unwrap_err(),
            CoreToJsonError::NonStringMapKey
        );
    }

    #[test]
    fn duplicate_key_rejected() {
        let c = CoreValue::Map(vec![
            (CoreValue::Text("k".into()), CoreValue::Int(1)),
            (CoreValue::Text("k".into()), CoreValue::Int(2)),
        ]);
        assert!(matches!(
            core_to_json(&c).unwrap_err(),
            CoreToJsonError::DuplicateMapKey(_)
        ));
    }

    #[test]
    fn contains_bytes_scan() {
        assert!(!CoreValue::Text("x".into()).contains_bytes());
        assert!(CoreValue::Bytes(vec![0]).contains_bytes());
        assert!(CoreValue::Array(vec![CoreValue::Bytes(vec![0])]).contains_bytes());
        assert!(CoreValue::Map(vec![(
            CoreValue::Text("k".into()),
            CoreValue::Bytes(vec![0])
        )])
        .contains_bytes());
    }

    /// Documents the known `-0.0 == 0.0` JSON normalization limitation. If
    /// this test ever starts failing, `serde_json` changed its semantics and
    /// the module-level doc needs revisiting.
    #[test]
    fn negative_zero_is_treated_as_zero() {
        let neg_zero = serde_json::json!(-0.0);
        let core = json_to_core(&neg_zero).unwrap();
        let back = core_to_json(&core).unwrap();
        assert_eq!(neg_zero, back);
    }

    #[test]
    fn depth_limit_enforced_on_arrays() {
        let mut v = serde_json::Value::Null;
        for _ in 0..(MAX_JSON_DEPTH + 2) {
            v = serde_json::Value::Array(vec![v]);
        }
        let err = json_to_core(&v).unwrap_err();
        assert_eq!(err, CoreToJsonError::DepthExceeded);
    }

    #[test]
    fn depth_limit_enforced_on_objects() {
        let mut v = serde_json::Value::Null;
        for i in 0..(MAX_JSON_DEPTH + 2) {
            let mut m = serde_json::Map::new();
            m.insert(format!("k{i}"), v);
            v = serde_json::Value::Object(m);
        }
        let err = json_to_core(&v).unwrap_err();
        assert_eq!(err, CoreToJsonError::DepthExceeded);
    }
}
