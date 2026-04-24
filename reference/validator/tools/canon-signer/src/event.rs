//! Canonical CBOR encoding of a Canon fact + SHA-256 derivation of its
//! `event_hash`.
//!
//! # Encoding contract (normative, versioned by [`crate::COSE_EXTERNAL_AAD`])
//!
//! A Canon fact serialises to a CBOR **array of 7 elements** in the
//! following fixed order:
//!
//! | idx | field            | CBOR type | notes                                                |
//! |-----|------------------|-----------|------------------------------------------------------|
//! | 0   | `parent_hash`    | `bstr`    | hex-decoded to raw bytes; `bstr<0>` for genesis      |
//! | 1   | `fact_id`        | `tstr`    |                                                      |
//! | 2   | `entity`         | `tstr`    |                                                      |
//! | 3   | `claim`          | `tstr`    |                                                      |
//! | 4   | `source_ref`     | `tstr`    |                                                      |
//! | 5   | `source_excerpt` | `tstr`/`null` | `null` (0xf6) when the request field was `null`  |
//! | 6   | `created_at_ms`  | `uint`    | positive Unix milliseconds                           |
//!
//! Array ordering is positional, so there is no key-ordering ambiguity.
//! ciborium's default encoder emits shortest-length integers and
//! length-prefixed bstr/tstr — canonical per RFC 8949 §4.2 "core
//! deterministic encoding" for the subset we use (no maps, no floats,
//! no indefinite-length items).
//!
//! `event_hash` is then `hex_lowercase(SHA-256(payload_bytes))`.
//!
//! # Why a `bstr` for `parent_hash` (not `tstr`)
//!
//! Genesis is encoded as a zero-length byte string (0x40), which is
//! byte-distinct from an empty text string (0x60).  Canon consumers
//! compare hashes as bytes; encoding the parent as bytes keeps the
//! comparison type-consistent through the whole pipeline.

use ciborium::Value;
use sha2::{Digest, Sha256};

use crate::io::SignRequest;

/// Error produced by the encoder.  Only one failure mode exists: the
/// caller supplied a non-hex or odd-length `parent_hash`.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("parent_hash is not valid hex: {0}")]
    InvalidParentHashHex(String),
}

/// Decode the `parent_hash` hex string to raw bytes.
///
/// Empty string → empty `Vec` (genesis).  Any other length is accepted
/// verbatim (we do not force 32 bytes here — Canon may choose a
/// different hash width in future; the signature binds whatever bytes
/// the caller supplies).
pub fn decode_parent_hash(hex_str: &str) -> Result<Vec<u8>, EncodeError> {
    if hex_str.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(hex_str).map_err(|e| EncodeError::InvalidParentHashHex(e.to_string()))
}

/// Canonically encode a fact to the CBOR payload bytes that go into the
/// COSE_Sign1 envelope (and whose SHA-256 is the `event_hash`).
pub fn encode_payload(req: &SignRequest) -> Result<Vec<u8>, EncodeError> {
    let parent_bytes = decode_parent_hash(&req.parent_hash)?;

    let value = Value::Array(vec![
        Value::Bytes(parent_bytes),
        Value::Text(req.fact_id.clone()),
        Value::Text(req.entity.clone()),
        Value::Text(req.claim.clone()),
        Value::Text(req.source_ref.clone()),
        match &req.source_excerpt {
            Some(s) => Value::Text(s.clone()),
            None => Value::Null,
        },
        Value::Integer(ciborium::value::Integer::from(req.created_at_ms)),
    ]);

    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(&value, &mut buf)
        .expect("encoding into Vec<u8> is infallible for well-formed Value");
    Ok(buf)
}

/// SHA-256 of `encode_payload` output, hex-encoded lowercase.
pub fn event_hash(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> SignRequest {
        SignRequest {
            op: "sign".to_string(),
            fact_id: "f_01HQ_sample".to_string(),
            entity: "customer:acme".to_string(),
            claim: "Q1 revenue was EUR 127,000".to_string(),
            source_ref: "gmail:msg_abc123".to_string(),
            source_excerpt: Some("Our Q1 came in at 127k EUR...".to_string()),
            parent_hash: String::new(),
            created_at_ms: 1_713_974_400_000,
        }
    }

    #[test]
    fn genesis_parent_hash_decodes_to_empty_bytes() {
        let bytes = decode_parent_hash("").unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn parent_hash_round_trips_lowercase_hex() {
        let bytes = decode_parent_hash("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn invalid_parent_hash_returns_error() {
        let err = decode_parent_hash("not-hex").unwrap_err();
        assert!(matches!(err, EncodeError::InvalidParentHashHex(_)));
    }

    #[test]
    fn encoding_is_deterministic_for_same_input() {
        let req = sample_request();
        let a = encode_payload(&req).unwrap();
        let b = encode_payload(&req).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn encoding_starts_with_array_header_0x87() {
        // CBOR array of 7 elements = 0x87 (major type 4, short count 7).
        let req = sample_request();
        let bytes = encode_payload(&req).unwrap();
        assert_eq!(bytes[0], 0x87, "expected CBOR array(7) header");
    }

    #[test]
    fn genesis_payload_second_byte_is_empty_bstr_0x40() {
        // After the 0x87 array header, the first element is the parent
        // hash bstr.  For genesis (empty parent) this is 0x40 =
        // major type 2, length 0.
        let req = sample_request();
        let bytes = encode_payload(&req).unwrap();
        assert_eq!(bytes[1], 0x40, "expected empty bstr for genesis parent");
    }

    #[test]
    fn source_excerpt_null_encodes_to_0xf6() {
        let mut req = sample_request();
        req.source_excerpt = None;
        let bytes = encode_payload(&req).unwrap();
        // The payload contains the null byte 0xf6 at some position; it
        // is easier to assert presence than compute the exact offset
        // (which depends on string lengths).  No other CBOR major
        // type uses 0xf6.
        assert!(
            bytes.contains(&0xf6),
            "expected CBOR null (0xf6) somewhere in encoded payload"
        );
    }

    #[test]
    fn event_hash_is_64_hex_chars_lowercase() {
        let req = sample_request();
        let payload = encode_payload(&req).unwrap();
        let hash = event_hash(&payload);
        assert_eq!(hash.len(), 64);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn different_claim_produces_different_hash() {
        let req_a = sample_request();
        let mut req_b = sample_request();
        req_b.claim = "Q1 revenue was EUR 500,000".to_string();

        let hash_a = event_hash(&encode_payload(&req_a).unwrap());
        let hash_b = event_hash(&encode_payload(&req_b).unwrap());
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn different_parent_hash_produces_different_event_hash() {
        // Chain invariant: flipping parent_hash must change event_hash.
        let req_a = sample_request();
        let mut req_b = sample_request();
        req_b.parent_hash =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let hash_a = event_hash(&encode_payload(&req_a).unwrap());
        let hash_b = event_hash(&encode_payload(&req_b).unwrap());
        assert_ne!(hash_a, hash_b);
    }
}
