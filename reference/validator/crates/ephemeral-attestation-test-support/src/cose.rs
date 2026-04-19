//! COSE_Sign1 ES384 signer for test fixtures.
//!
//! Produces a tag-18 COSE_Sign1 structure with deterministic RFC-6979
//! signatures.

use p384::ecdsa::{signature::Signer, SigningKey};

/// Build a COSE_Sign1 byte string.
///
/// `use_wrong_alg` causes the protected header to advertise ES256 (-7)
/// instead of the correct ES384 (-35).  The actual signing key is still
/// P-384, so the verifier will reject the alg mismatch before checking
/// the signature.
pub(crate) fn build_cose_sign1(
    payload: &[u8],
    signing_key: &SigningKey,
    use_wrong_alg: bool,
) -> Vec<u8> {
    use ciborium::value::Value;

    // alg: -35 = ES384, -7 = ES256 (wrong)
    let alg_id: i64 = if use_wrong_alg { -7 } else { -35 };

    // Protected header: {1: alg_id}
    let protected_map: Vec<(Value, Value)> = vec![(
        Value::Integer(1i64.into()),
        Value::Integer(alg_id.into()),
    )];
    let mut protected_bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(protected_map), &mut protected_bytes)
        .expect("protected header encode");

    // Build Sig_Structure: ["Signature1", protected_bstr, aad_bstr, payload_bstr]
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_bytes.clone()),
        Value::Bytes(vec![]),   // empty AAD for Nitro
        Value::Bytes(payload.to_vec()),
    ]);
    let mut tbs_bytes = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut tbs_bytes)
        .expect("sig structure encode");

    // Sign — RFC-6979 deterministic nonce
    let signature: p384::ecdsa::Signature = signing_key.sign(&tbs_bytes);
    let sig_bytes = signature.to_bytes().to_vec(); // raw r||s (96 bytes for P-384)

    // COSE_Sign1 = [protected_bstr, {}, payload_bstr, signature_bstr]
    let sign1_array = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(vec![]),     // unprotected header (empty)
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig_bytes),
    ]);

    let mut buf = Vec::new();
    // Tag 18 manually: 0xd2 = tag(18)
    buf.push(0xd2u8);
    ciborium::ser::into_writer(&sign1_array, &mut buf).expect("cose encode");
    buf
}
