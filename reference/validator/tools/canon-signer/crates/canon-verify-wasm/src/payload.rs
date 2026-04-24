//! Decode the 7-field Canon fact CBOR array into a typed payload.
//!
//! Mirrors the encoding contract documented in
//! `canon_signer::event` — any drift here breaks round-trip parity
//! and is caught by `tests/payload_parity.rs`.
//!
//! Index → field:
//!
//! | idx | field            | CBOR type     | Rust type        |
//! |-----|------------------|---------------|------------------|
//! | 0   | `parent_hash`    | `bstr`        | `Vec<u8>`        |
//! | 1   | `fact_id`        | `tstr`        | `String`         |
//! | 2   | `entity`         | `tstr`        | `String`         |
//! | 3   | `claim`          | `tstr`        | `String`         |
//! | 4   | `source_ref`     | `tstr`        | `String`         |
//! | 5   | `source_excerpt` | `tstr`/`null` | `Option<String>` |
//! | 6   | `created_at_ms`  | `uint`        | `i64`            |

use ciborium::Value;

use crate::result::DecodedPayload;

#[derive(Debug, thiserror::Error)]
pub enum PayloadDecodeError {
    #[error("payload is not valid CBOR: {0}")]
    NotCbor(String),
    #[error("payload is not a CBOR array (got a {0})")]
    NotArray(&'static str),
    #[error("payload array has {0} fields, expected exactly 7")]
    WrongArity(usize),
    #[error("field {index} ({name}) has wrong CBOR type ({detail})")]
    WrongFieldType {
        index: usize,
        name: &'static str,
        detail: String,
    },
    #[error("created_at_ms does not fit in i64: {0}")]
    TimestampOverflow(String),
}

/// Decode the canonical CBOR payload produced by `canon-signer` back
/// into a typed struct.  Does *not* re-validate any signatures — the
/// caller is expected to only invoke this on payloads whose signature
/// has already verified.
pub fn decode_payload(bytes: &[u8]) -> Result<DecodedPayload, PayloadDecodeError> {
    let value: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| PayloadDecodeError::NotCbor(e.to_string()))?;

    let Value::Array(items) = value else {
        return Err(PayloadDecodeError::NotArray(cbor_kind(&value)));
    };
    if items.len() != 7 {
        return Err(PayloadDecodeError::WrongArity(items.len()));
    }

    let parent_hash_bytes = match &items[0] {
        Value::Bytes(b) => b.clone(),
        other => {
            return Err(PayloadDecodeError::WrongFieldType {
                index: 0,
                name: "parent_hash",
                detail: format!("expected bstr, got {}", cbor_kind(other)),
            });
        }
    };

    let fact_id = expect_text(&items[1], 1, "fact_id")?;
    let entity = expect_text(&items[2], 2, "entity")?;
    let claim = expect_text(&items[3], 3, "claim")?;
    let source_ref = expect_text(&items[4], 4, "source_ref")?;

    let source_excerpt = match &items[5] {
        Value::Text(s) => Some(s.clone()),
        Value::Null => None,
        other => {
            return Err(PayloadDecodeError::WrongFieldType {
                index: 5,
                name: "source_excerpt",
                detail: format!("expected tstr or null, got {}", cbor_kind(other)),
            });
        }
    };

    let created_at_ms = match &items[6] {
        Value::Integer(int) => i128::from(*int)
            .try_into()
            .map_err(|_| PayloadDecodeError::TimestampOverflow(
                "value exceeds i64::MAX".to_string(),
            ))?,
        other => {
            return Err(PayloadDecodeError::WrongFieldType {
                index: 6,
                name: "created_at_ms",
                detail: format!("expected uint, got {}", cbor_kind(other)),
            });
        }
    };

    Ok(DecodedPayload {
        parent_hash: hex::encode(parent_hash_bytes),
        fact_id,
        entity,
        claim,
        source_ref,
        source_excerpt,
        created_at_ms,
    })
}

fn expect_text(v: &Value, index: usize, name: &'static str) -> Result<String, PayloadDecodeError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        other => Err(PayloadDecodeError::WrongFieldType {
            index,
            name,
            detail: format!("expected tstr, got {}", cbor_kind(other)),
        }),
    }
}

fn cbor_kind(v: &Value) -> &'static str {
    match v {
        Value::Integer(_) => "integer",
        Value::Bytes(_) => "bstr",
        Value::Text(_) => "tstr",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tagged",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        Value::Float(_) => "float",
        _ => "unknown",
    }
}
