//! Nitro `AttestationDoc` CBOR builder.

use p384::ecdsa::VerifyingKey;
use p384::pkcs8::EncodePublicKey;

/// A single PCR slot to embed in the attestation document.
#[derive(Clone, Debug)]
pub struct PcrEntry {
    pub id: u8,
    pub hash: Vec<u8>,
}

/// Build the CBOR-encoded Nitro attestation payload.
///
/// Includes `leaf_der` as the `certificate` field, `ca_ders` as the
/// `cabundle`, and the leaf's SPKI as `public_key`.
pub(crate) fn build_payload_cbor(
    leaf_der: &[u8],
    ca_ders: &[Vec<u8>],
    leaf_vk: &VerifyingKey,
    pcrs: &[PcrEntry],
    nonce: Option<Vec<u8>>,
    now: i64,
    duplicate_pcr: bool,
) -> Vec<u8> {
    use ciborium::value::Value;

    let spki_bytes = leaf_vk.to_public_key_der().expect("spki").into_vec();

    let mut pcr_pairs: Vec<(Value, Value)> = pcrs
        .iter()
        .map(|e| {
            (
                Value::Integer(i64::from(e.id).into()),
                Value::Bytes(e.hash.clone()),
            )
        })
        .collect();

    if duplicate_pcr {
        // Inject a duplicate PCR-0 with a different hash value.
        pcr_pairs.push((Value::Integer(0i64.into()), Value::Bytes(vec![0xBBu8; 48])));
    }

    let ca_array: Vec<Value> = ca_ders.iter().map(|d| Value::Bytes(d.clone())).collect();

    let mut map: Vec<(Value, Value)> = vec![
        (
            Value::Text("module_id".into()),
            Value::Text("i-test-module-00".into()),
        ),
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (Value::Text("timestamp".into()), Value::Integer(now.into())),
        (Value::Text("pcrs".into()), Value::Map(pcr_pairs)),
        (
            Value::Text("certificate".into()),
            Value::Bytes(leaf_der.to_vec()),
        ),
        (Value::Text("cabundle".into()), Value::Array(ca_array)),
        (Value::Text("public_key".into()), Value::Bytes(spki_bytes)),
    ];

    if let Some(n) = nonce {
        map.push((Value::Text("nonce".into()), Value::Bytes(n)));
    }

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut buf).expect("cbor encode");
    buf
}
