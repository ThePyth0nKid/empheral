//! Adversarial-input guardrails applied before handing CBOR bytes to `coset`.
//!
//! The byte cap here (64 KiB) sits **inside** the outer Tariff envelope cap
//! (256 KiB, `ephemeral-core::suites::tariff::MAX_TARIFF_BYTES`). A
//! well-formed Tariff signing blob is expected to fit well under 64 KiB;
//! values above that are an adversarial signal.
//!
//! CBOR depth is bounded at 16: a COSE_Sign1 is structurally a 4-tuple with
//! a handful of nested header maps. Legitimate payloads rarely exceed a
//! handful of nesting levels; 16 is comfortable headroom without enabling
//! stack-exhaustion attacks via deep-nested arrays/maps.
//!
//! Note on walker safety: `ciborium::de::from_reader` already applies an
//! internal recursion limit during parsing (default 100 for 0.2.x). That
//! bounds the depth of the resulting [`ciborium::value::Value`] tree; our
//! [`cbor_depth`] walker is therefore safe to recurse on the decoded
//! value — the recursion is bounded by ciborium's parser before we ever
//! inspect the tree.

use ciborium::value::Value as CborValue;

use crate::error::CoseError;

/// Hard byte cap for a single COSE_Sign1 blob.
pub const MAX_COSE_BYTES: usize = 65_536;

/// Max legitimate CBOR nesting depth for COSE_Sign1.
pub const MAX_CBOR_DEPTH: usize = 16;

/// Run both guardrails. Returns `Ok(())` if the input is within caps;
/// otherwise the first-failing cap's [`CoseError`].
pub fn size_depth_check(bytes: &[u8]) -> Result<(), CoseError> {
    if bytes.len() > MAX_COSE_BYTES {
        return Err(CoseError::PayloadTooLarge {
            observed: bytes.len(),
            cap: MAX_COSE_BYTES,
        });
    }

    let value: CborValue = ciborium::de::from_reader(bytes).map_err(|_| CoseError::CborParse)?;
    let depth = cbor_depth(&value, 1);
    if depth > MAX_CBOR_DEPTH {
        return Err(CoseError::CborDepthExceeded {
            max: MAX_CBOR_DEPTH,
        });
    }
    Ok(())
}

/// Walk the decoded CBOR tree and report maximum nesting depth observed.
///
/// Safe to recurse: `ciborium` already bounded the tree during parsing
/// (see module docs). The `current` parameter is the depth of the node
/// passed in (root = 1).
fn cbor_depth(v: &CborValue, current: usize) -> usize {
    match v {
        CborValue::Array(items) => items
            .iter()
            .map(|i| cbor_depth(i, current + 1))
            .max()
            .unwrap_or(current),
        CborValue::Map(pairs) => pairs
            .iter()
            .flat_map(|(k, v)| [cbor_depth(k, current + 1), cbor_depth(v, current + 1)])
            .max()
            .unwrap_or(current),
        CborValue::Tag(_, inner) => cbor_depth(inner, current + 1),
        _ => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_cbor_accepted() {
        // Encode a simple integer via ciborium.
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&42u32, &mut buf).unwrap();
        size_depth_check(&buf).unwrap();
    }

    #[test]
    fn oversize_rejected() {
        let huge = vec![0u8; MAX_COSE_BYTES + 1];
        let err = size_depth_check(&huge).unwrap_err();
        match err {
            CoseError::PayloadTooLarge { observed, cap } => {
                assert_eq!(observed, MAX_COSE_BYTES + 1);
                assert_eq!(cap, MAX_COSE_BYTES);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn malformed_cbor_rejected() {
        // 0xff is a "break" marker — invalid as a top-level item.
        let bad = vec![0xffu8];
        let err = size_depth_check(&bad).unwrap_err();
        assert!(matches!(err, CoseError::CborParse));
    }

    #[test]
    fn empty_slice_rejected() {
        let err = size_depth_check(&[]).unwrap_err();
        assert!(matches!(err, CoseError::CborParse));
    }
}
