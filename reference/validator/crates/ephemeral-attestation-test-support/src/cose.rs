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
///
/// `tamper_after_sign` flips the low bit of the last byte of the payload
/// **after** signing.  The signature is computed over the untampered payload,
/// so once the tampered payload is embedded in the outer COSE_Sign1 array the
/// verifier will reconstruct Sig_structure_1 with bytes that do not match
/// the signed TBS, and ECDSA verify fails.  Flipping the last byte lands
/// inside the `public_key` SPKI DER (or the `nonce` bstr when a nonce is
/// present); both fields are byte-arrays that stay CBOR-parseable after a
/// single-bit flip, so the failure is specifically a signature-invalid one
/// and not a malformed-doc one.
pub(crate) fn build_cose_sign1(
    payload: &[u8],
    signing_key: &SigningKey,
    use_wrong_alg: bool,
    tamper_after_sign: bool,
) -> Vec<u8> {
    use ciborium::value::Value;

    // alg: -35 = ES384, -7 = ES256 (wrong)
    let alg_id: i64 = if use_wrong_alg { -7 } else { -35 };

    // Protected header: {1: alg_id}
    let protected_map: Vec<(Value, Value)> =
        vec![(Value::Integer(1i64.into()), Value::Integer(alg_id.into()))];
    let mut protected_bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(protected_map), &mut protected_bytes)
        .expect("protected header encode");

    // Build Sig_Structure over the UNTAMPERED payload.
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_bytes.clone()),
        Value::Bytes(vec![]), // empty AAD for Nitro
        Value::Bytes(payload.to_vec()),
    ]);
    let mut tbs_bytes = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut tbs_bytes).expect("sig structure encode");

    // Sign — RFC-6979 deterministic nonce
    let signature: p384::ecdsa::Signature = signing_key.sign(&tbs_bytes);
    let sig_bytes = signature.to_bytes().to_vec(); // raw r||s (96 bytes for P-384)

    // Embedded payload: optionally tamper the last byte AFTER signing.
    let mut embedded_payload = payload.to_vec();
    if tamper_after_sign {
        if let Some(b) = embedded_payload.last_mut() {
            *b ^= 0x01;
        }
    }

    // COSE_Sign1 = [protected_bstr, {}, payload_bstr, signature_bstr]
    let sign1_array = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(vec![]), // unprotected header (empty)
        Value::Bytes(embedded_payload),
        Value::Bytes(sig_bytes),
    ]);

    let mut buf = Vec::new();
    // Tag 18 manually: 0xd2 = tag(18)
    buf.push(0xd2u8);
    ciborium::ser::into_writer(&sign1_array, &mut buf).expect("cose encode");
    buf
}
