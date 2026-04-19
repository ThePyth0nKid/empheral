//! Adversarial-input guardrails applied before handing CBOR bytes to `coset`.
//!
//! The byte cap (128 KiB) is larger than the ephemeral-crypto cap (64 KiB)
//! because Nitro attestation documents include full certificate chains.
//! CBOR depth is bounded at 8: a Nitro doc is a flat map of scalar/bytes
//! fields; 8 levels is comfortable headroom without enabling stack-exhaustion
//! attacks via deep-nested maps.

use ciborium::value::Value as CborValue;

use crate::error::AttestError;

/// Hard byte cap for a Nitro attestation document.
pub const MAX_NITRO_DOC_BYTES: usize = 131_072; // 128 KiB

/// Max CBOR nesting depth for a Nitro attestation document.
pub const MAX_CBOR_DEPTH: usize = 8;

/// Maximum length of the CA chain (leaf + intermediates, excluding root).
pub const MAX_CA_CHAIN_DEPTH: usize = 4;

/// Maximum number of PCR entries (TPM 2.0 range 0..23).
pub const MAX_PCR_COUNT: usize = 24;

/// Run size and depth guardrails.
///
/// Returns `Ok(())` when both caps are satisfied; the first failing cap
/// produces the matching [`AttestError`] variant.
pub fn size_depth_check(bytes: &[u8]) -> Result<(), AttestError> {
    if bytes.len() > MAX_NITRO_DOC_BYTES {
        return Err(AttestError::PayloadTooLarge {
            observed: bytes.len(),
            cap: MAX_NITRO_DOC_BYTES,
        });
    }

    let value: CborValue =
        ciborium::de::from_reader(bytes).map_err(|_| AttestError::MalformedDoc { source: None })?;

    let depth = cbor_depth(&value, 1);
    if depth > MAX_CBOR_DEPTH {
        return Err(AttestError::CborDepthExceeded { max: MAX_CBOR_DEPTH });
    }

    Ok(())
}

/// Walk a decoded CBOR tree and return the maximum nesting depth observed.
///
/// Safe to recurse: `ciborium` already bounded the tree during parsing
/// (internal recursion limit ≈ 100 for ciborium 0.2.x). The `current`
/// parameter is the depth of the node passed in (root = 1).
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
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&42u32, &mut buf).unwrap();
        size_depth_check(&buf).unwrap();
    }

    #[test]
    fn oversize_rejected() {
        let huge = vec![0u8; MAX_NITRO_DOC_BYTES + 1];
        let err = size_depth_check(&huge).unwrap_err();
        assert!(matches!(
            err,
            AttestError::PayloadTooLarge {
                observed,
                cap
            } if observed == MAX_NITRO_DOC_BYTES + 1 && cap == MAX_NITRO_DOC_BYTES
        ));
    }

    #[test]
    fn malformed_cbor_rejected() {
        let bad = vec![0xffu8]; // break marker — invalid top-level
        let err = size_depth_check(&bad).unwrap_err();
        assert!(matches!(err, AttestError::MalformedDoc { .. }));
    }

    #[test]
    fn empty_slice_rejected() {
        let err = size_depth_check(&[]).unwrap_err();
        assert!(matches!(err, AttestError::MalformedDoc { .. }));
    }
}
