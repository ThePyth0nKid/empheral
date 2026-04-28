//! Minimal COSE_Sign1 parse + ES384 signature verification.
//!
//! This module deliberately does NOT depend on `ephemeral-crypto` to maintain
//! strict one-way layering (attestation is a sibling crate, not a consumer).
//! The ~80 LoC duplicated from ephemeral-crypto's cose.rs is cheaper than
//! introducing a shared-crate dependency that would complicate workspace
//! versioning.
//!
//! Only the ES384 (alg = -35) path is implemented — the only algorithm used
//! in AWS Nitro attestation documents.

use ciborium::value::Value as CborValue;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::error::{AttestError, EcdsaSource};

/// COSE alg label for ECDSA-P384 with SHA-384 (RFC 9053 §2.1 table).
pub(crate) const COSE_ALG_ES384: i64 = -35;

/// Parse a COSE_Sign1 tagged/untagged array, check alg = -35, and verify
/// the ES384 signature against `verifying_key` using `expected_aad`.
///
/// Returns the payload bytes on success.
///
/// # Structure assumed
///
/// ```text
/// COSE_Sign1 = [
///   protected:   bstr .cbor header_map,
///   unprotected: header_map,
///   payload:     bstr / nil,
///   signature:   bstr,
/// ]
/// ```
/// Optionally wrapped in CBOR tag 18.
pub(crate) fn verify_cose_sign1_es384(
    cose_bytes: &[u8],
    verifying_key: &VerifyingKey,
    expected_aad: &[u8],
) -> Result<Vec<u8>, AttestError> {
    // ── 1. Decode outer CBOR (may or may not carry tag 18) ───────────────────
    let top: CborValue = ciborium::de::from_reader(cose_bytes).map_err(malformed_cbor)?;

    // Unwrap tag 18 if present
    let array = match top {
        CborValue::Tag(18, inner) => match *inner {
            CborValue::Array(a) => a,
            _ => return Err(malformed_none()),
        },
        CborValue::Array(a) => a,
        _ => return Err(malformed_none()),
    };

    if array.len() != 4 {
        return Err(malformed_none());
    }

    // ── 2. Extract fields ────────────────────────────────────────────────────
    let protected_bstr = match &array[0] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(malformed_none()),
    };
    // unprotected header at index 1 — not inspected
    let payload_bytes = match &array[2] {
        CborValue::Bytes(b) => b.clone(),
        CborValue::Null => vec![],
        _ => return Err(malformed_none()),
    };
    let sig_bytes = match &array[3] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(malformed_none()),
    };

    // ── 3. Check alg in protected header ─────────────────────────────────────
    let alg = extract_alg(&protected_bstr)?;
    if alg != COSE_ALG_ES384 {
        return Err(AttestError::UnsupportedAlg { alg });
    }

    // ── 4. Rebuild Sig_structure_1 TBS bytes ─────────────────────────────────
    // Sig_structure_1 = ["Signature1", protected_bstr, aad, payload]
    let tbs = build_sig_structure(&protected_bstr, expected_aad, &payload_bytes)?;

    // ── 5. Verify ES384 signature ─────────────────────────────────────────────
    // P-384 raw signature is 96 bytes (r || s, 48 each)
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| AttestError::SignatureInvalid {
        source: EcdsaSource(e),
    })?;
    verifying_key
        .verify(&tbs, &sig)
        .map_err(|e| AttestError::SignatureInvalid {
            source: EcdsaSource(e),
        })?;

    Ok(payload_bytes)
}

/// Extract the integer `alg` label (map key 1) from a protected header bstr.
fn extract_alg(protected_bstr: &[u8]) -> Result<i64, AttestError> {
    if protected_bstr.is_empty() {
        return Err(malformed_none());
    }
    let header: CborValue = ciborium::de::from_reader(protected_bstr).map_err(malformed_cbor)?;
    let CborValue::Map(pairs) = header else {
        return Err(malformed_none());
    };
    for (k, v) in &pairs {
        if let CborValue::Integer(ki) = k {
            let ki_i64 = i64::try_from(*ki).unwrap_or(i64::MAX);
            if ki_i64 == 1 {
                // alg key
                match v {
                    CborValue::Integer(alg_val) => {
                        return i64::try_from(*alg_val)
                            .map_err(|_| AttestError::UnsupportedAlg { alg: i64::MIN });
                    }
                    _ => return Err(malformed_none()),
                }
            }
        }
    }
    Err(malformed_none())
}

/// Encode the COSE Sig_structure_1 for verification.
fn build_sig_structure(
    protected_bstr: &[u8],
    aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, AttestError> {
    let sig_structure = CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(protected_bstr.to_vec()),
        CborValue::Bytes(aad.to_vec()),
        CborValue::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut buf)
        .map_err(|_| AttestError::MalformedDoc { source: None })?;
    Ok(buf)
}

fn malformed_none() -> AttestError {
    AttestError::MalformedDoc { source: None }
}

fn malformed_cbor(_e: ciborium::de::Error<std::io::Error>) -> AttestError {
    AttestError::MalformedDoc { source: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::{signature::Signer, SigningKey};

    fn test_key() -> SigningKey {
        SigningKey::from_slice(&[0x42u8; 48]).expect("test key")
    }

    fn build_sign1(payload: &[u8], alg: i64, signing_key: &SigningKey) -> Vec<u8> {
        use ciborium::value::Value;

        let protected_map: Vec<(Value, Value)> =
            vec![(Value::Integer(1i64.into()), Value::Integer(alg.into()))];
        let mut protected_bytes = Vec::new();
        ciborium::ser::into_writer(&Value::Map(protected_map), &mut protected_bytes).unwrap();

        let sig_structure = Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected_bytes.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(payload.to_vec()),
        ]);
        let mut tbs = Vec::new();
        ciborium::ser::into_writer(&sig_structure, &mut tbs).unwrap();

        let sig: p384::ecdsa::Signature = signing_key.sign(&tbs);
        let sig_bytes = sig.to_bytes().to_vec();

        let sign1 = Value::Array(vec![
            Value::Bytes(protected_bytes),
            Value::Map(vec![]),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(sig_bytes),
        ]);
        let mut buf = vec![0xd2u8]; // tag 18
        ciborium::ser::into_writer(&sign1, &mut buf).unwrap();
        buf
    }

    #[test]
    fn roundtrip_es384() {
        let sk = test_key();
        let vk = *sk.verifying_key();
        let payload = b"test-payload";
        let bytes = build_sign1(payload, COSE_ALG_ES384, &sk);
        let out = verify_cose_sign1_es384(&bytes, &vk, &[]).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn wrong_alg_rejected() {
        let sk = test_key();
        let vk = *sk.verifying_key();
        let bytes = build_sign1(b"p", -7, &sk); // ES256
        let err = verify_cose_sign1_es384(&bytes, &vk, &[]).unwrap_err();
        assert!(matches!(err, AttestError::UnsupportedAlg { alg: -7 }));
    }

    #[test]
    fn tampered_payload_rejected() {
        let sk = test_key();
        let mut buf = build_sign1(b"original", COSE_ALG_ES384, &sk);
        // Flip a byte in the last quarter (signature bytes)
        let last = buf.len() - 10;
        buf[last] ^= 0x01;
        let vk = *sk.verifying_key();
        let err = verify_cose_sign1_es384(&buf, &vk, &[]).unwrap_err();
        assert!(matches!(err, AttestError::SignatureInvalid { .. }));
    }

    #[test]
    fn empty_input_rejected() {
        let vk = *test_key().verifying_key();
        let err = verify_cose_sign1_es384(&[], &vk, &[]).unwrap_err();
        assert!(matches!(err, AttestError::MalformedDoc { .. }));
    }
}
