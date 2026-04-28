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

/// Default hard byte cap for a single COSE_Sign1 blob (Tariff,
/// classifier, delegation envelopes).
///
/// Per-domain callers whose legitimate envelope exceeds this cap (e.g.
/// Phase C.4 anomaly-library envelopes carry a full pattern set) MUST
/// use [`size_depth_check_with_cap`] / [`crate::verify_cose_sign1_with_cap`]
/// with their own explicit cap rather than relaxing this constant —
/// keeping the default tight protects the existing classic suites.
pub const MAX_COSE_BYTES: usize = 65_536;

/// Max legitimate CBOR nesting depth for COSE_Sign1.
pub const MAX_CBOR_DEPTH: usize = 16;

/// Run both guardrails against the default [`MAX_COSE_BYTES`] cap.
/// Returns `Ok(())` if the input is within caps; otherwise the first-
/// failing cap's [`CoseError`].
///
/// Thin wrapper over [`size_depth_check_with_cap`] preserved to avoid
/// churning every existing caller; per-domain callers wanting a larger
/// byte cap must call [`size_depth_check_with_cap`] directly.
pub fn size_depth_check(bytes: &[u8]) -> Result<(), CoseError> {
    size_depth_check_with_cap(bytes, MAX_COSE_BYTES)
}

/// Size-and-depth guard with an explicit byte cap.
///
/// The byte cap comes from the caller so per-domain envelopes (Phase
/// C.4 `AnomalyPatternLibrary` at 128 KiB, for example) can enforce a
/// strictly-larger limit without relaxing the default [`MAX_COSE_BYTES`]
/// that the classic suites rely on.  Depth cap is always
/// [`MAX_CBOR_DEPTH`]: nesting depth is a structural property of the
/// CBOR tree that does not change with payload size.
///
/// Panics-free on every input path (property-tested).  The depth
/// walker runs only after `ciborium` itself bounded recursion during
/// parsing (default 100 levels), so the walker's own recursion is
/// bounded before it starts.
pub fn size_depth_check_with_cap(bytes: &[u8], max_bytes: usize) -> Result<(), CoseError> {
    if bytes.len() > max_bytes {
        return Err(CoseError::PayloadTooLarge {
            observed: bytes.len(),
            cap: max_bytes,
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

    #[test]
    fn with_cap_accepts_bytes_above_default_under_explicit_cap() {
        // A well-formed CBOR blob larger than MAX_COSE_BYTES must pass
        // when the caller raises the cap (Phase C.4 anomaly envelope
        // path), and must fail under the default cap.
        let large = 80_000usize;
        assert!(large > MAX_COSE_BYTES);
        // Build a valid CBOR byte string of `large` payload bytes so the
        // parser accepts it; 0x5a = bstr with 4-byte length prefix.
        let mut buf: Vec<u8> = vec![0x5a];
        buf.extend_from_slice(
            &u32::try_from(large)
                .expect("test fixture size fits u32")
                .to_be_bytes(),
        );
        buf.extend(std::iter::repeat(0u8).take(large));

        // Default cap rejects.
        let err = size_depth_check(&buf).unwrap_err();
        assert!(matches!(err, CoseError::PayloadTooLarge { .. }));

        // Explicit larger cap accepts.
        size_depth_check_with_cap(&buf, 131_072).unwrap();
    }

    #[test]
    fn with_cap_reports_caller_supplied_cap_on_reject() {
        let cap = 1024;
        let payload = vec![0u8; cap + 1];
        let err = size_depth_check_with_cap(&payload, cap).unwrap_err();
        match err {
            CoseError::PayloadTooLarge {
                observed,
                cap: reported,
            } => {
                assert_eq!(observed, cap + 1);
                assert_eq!(
                    reported, cap,
                    "reject error must echo caller's cap, not MAX_COSE_BYTES"
                );
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn default_wrapper_matches_explicit_max() {
        // Invariant: size_depth_check(bytes) ≡
        // size_depth_check_with_cap(bytes, MAX_COSE_BYTES).  Locks the
        // wrapper so a future regression that forgets to forward the
        // default cap is caught here.
        let at_cap = vec![0u8; MAX_COSE_BYTES + 1];
        let a = size_depth_check(&at_cap).unwrap_err();
        let b = size_depth_check_with_cap(&at_cap, MAX_COSE_BYTES).unwrap_err();
        match (a, b) {
            (
                CoseError::PayloadTooLarge {
                    observed: oa,
                    cap: ca,
                },
                CoseError::PayloadTooLarge {
                    observed: ob,
                    cap: cb,
                },
            ) => {
                assert_eq!(oa, ob);
                assert_eq!(ca, cb);
            }
            (a, b) => panic!("wrapper diverged from explicit: {a:?} vs {b:?}"),
        }
    }
}
