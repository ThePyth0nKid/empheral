//! Thin wrapper around `coset::CoseSign1` for parse + header extraction.
//!
//! Kept separate from `verify.rs` so unit tests can exercise parsing
//! behaviour (alg label extraction, kid decoding) without running the
//! full Ed25519 verification pipeline. All functions here return typed
//! [`CoseError`] — they never propagate raw `coset::CoseError`.

use coset::{CborSerializable, CoseSign1, RegisteredLabelWithPrivate};

use crate::error::{CoseError, CosetSource};

/// Parse bytes into a [`CoseSign1`] structure.
///
/// Byte-length and CBOR-depth caps are enforced separately via
/// [`crate::size_guard::size_depth_check`]; callers must run that check
/// first when dealing with untrusted input.
pub(crate) fn parse_cose_sign1(bytes: &[u8]) -> Result<CoseSign1, CoseError> {
    CoseSign1::from_slice(bytes).map_err(|e| CoseError::MalformedHeader {
        source: Some(CosetSource(e)),
    })
}

/// Extract the COSE `alg` integer label from the protected header.
///
/// Text-based algorithm labels (`RegisteredLabelWithPrivate::Text`) are
/// rejected: the conformance vectors and the `ephemeral-core` tariff
/// executor both pin integer labels (§2.2, `COSE_ALG_EDDSA = -8`).
pub(crate) fn extract_alg_label(sign1: &CoseSign1) -> Result<i64, CoseError> {
    match &sign1.protected.header.alg {
        Some(RegisteredLabelWithPrivate::PrivateUse(n)) => Ok(*n),
        Some(RegisteredLabelWithPrivate::Assigned(a)) => Ok(i64::from(*a as i32)),
        Some(RegisteredLabelWithPrivate::Text(_)) | None => {
            Err(CoseError::MalformedHeader { source: None })
        }
    }
}

/// Extract the `kid` from the protected header as a UTF-8 string.
///
/// Empty kid is rejected. Non-UTF-8 kid bytes (legal per COSE but not used
/// by EPHEMERAL vectors — kids are ASCII identifiers like
/// `K_cust_root_pk_TEST`) are rejected as malformed header.
pub(crate) fn extract_kid(sign1: &CoseSign1) -> Result<String, CoseError> {
    let kid_bytes = &sign1.protected.header.key_id;
    if kid_bytes.is_empty() {
        return Err(CoseError::MalformedHeader { source: None });
    }
    String::from_utf8(kid_bytes.clone()).map_err(|_| CoseError::MalformedHeader { source: None })
}
