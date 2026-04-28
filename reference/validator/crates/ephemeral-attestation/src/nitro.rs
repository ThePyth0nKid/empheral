//! Core Nitro attestation document verification pipeline.
//!
//! Pipeline (in order):
//! 1. Size/depth guard.
//! 2. COSE_Sign1 decode — extract leaf cert from payload.
//! 3. Certificate chain verification (cert.rs) → leaf SPKI.
//! 4. COSE_Sign1 signature verify with leaf SPKI (cose_bridge).
//! 5. Parse payload CBOR into [`NitroClaims`].
//! 6. Optional nonce check.

use ciborium::value::Value as CborValue;

use crate::anchors::NitroRootSet;
use crate::cert::verify_chain;
use crate::cose_bridge::verify_cose_sign1_es384;
use crate::error::AttestError;
use crate::size_guard::size_depth_check;

/// Claims extracted from a verified Nitro attestation document.
///
/// The Debug impl redacts `certificate`, `cabundle`, and `public_key` to
/// keep test output clean — these can be hundreds of bytes each.
#[derive(Clone)]
pub struct NitroClaims {
    /// The Nitro enclave module identifier (e.g., `"i-0abc123def456789"`).
    pub module_id: String,
    /// Hash algorithm used for PCR measurements (`"SHA256"`, `"SHA384"`, ...).
    pub digest: String,
    /// Creation timestamp (milliseconds since Unix epoch in AWS format,
    /// treated as seconds for validity window checks).
    pub timestamp: i64,
    /// PCR measurements as `(index, hash_bytes)` pairs.
    pub pcrs: Vec<(u8, Vec<u8>)>,
    /// DER-encoded enclave leaf certificate.
    pub certificate: Vec<u8>,
    /// DER-encoded intermediate CA certificates.
    pub cabundle: Vec<Vec<u8>>,
    /// Optional enclave public key (SPKI-encoded).
    pub public_key: Option<Vec<u8>>,
    /// Optional user data embedded by the caller.
    pub user_data: Option<Vec<u8>>,
    /// Optional nonce set by the caller.
    pub nonce: Option<Vec<u8>>,
}

impl core::fmt::Debug for NitroClaims {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NitroClaims")
            .field("module_id", &self.module_id)
            .field("digest", &self.digest)
            .field("timestamp", &self.timestamp)
            .field("pcrs", &self.pcrs.len())
            .field(
                "certificate",
                &format!("<{} bytes>", self.certificate.len()),
            )
            .field("cabundle", &format!("<{} certs>", self.cabundle.len()))
            .field(
                "public_key",
                &self
                    .public_key
                    .as_ref()
                    .map(|b| format!("<{} bytes>", b.len())),
            )
            .field(
                "user_data",
                &self
                    .user_data
                    .as_ref()
                    .map(|b| format!("<{} bytes>", b.len())),
            )
            .field(
                "nonce",
                &self.nonce.as_ref().map(|b| format!("<{} bytes>", b.len())),
            )
            .finish()
    }
}

/// Verify a DER-encoded COSE_Sign1 Nitro attestation document.
///
/// Returns parsed [`NitroClaims`] on success.
///
/// # Arguments
///
/// - `doc_cose_bytes`: raw bytes of the COSE_Sign1 document.
/// - `roots`: trusted root CA set for chain verification.
/// - `expected_nonce`: if `Some`, the document's `nonce` field must match.
/// - `current_time`: caller-supplied wall-clock (Unix seconds). Used for
///   certificate validity-window checks. MUST come from the caller's
///   trusted clock — the document's own `timestamp` is adversary-controlled
///   and must not govern expiry decisions.
///
/// # Freshness
///
/// This primitive does **not** compare `current_time` against the doc's
/// `timestamp` field. Policy-level freshness (max-age, clock-skew
/// tolerance) is the suite layer's concern — `NitroClaims.timestamp` is
/// returned for that purpose.
pub fn verify_nitro_attestation(
    doc_cose_bytes: &[u8],
    roots: &NitroRootSet,
    expected_nonce: Option<&[u8]>,
    current_time: i64,
) -> Result<NitroClaims, AttestError> {
    // ── 1. Size / depth guard ─────────────────────────────────────────────────
    size_depth_check(doc_cose_bytes)?;

    // ── 2. Peek into COSE_Sign1 to extract the pre-signature payload ──────────
    //    We need the leaf cert from the payload to build the verifying key
    //    BEFORE we can call verify_cose_sign1_es384.  So we do a two-pass:
    //    first parse cert chain, then verify signature.
    let payload_bytes = extract_cose_payload(doc_cose_bytes)?;

    // ── 3. Parse payload CBOR (partial) to get cert chain ────────────────────
    let proto = parse_claims_cbor(&payload_bytes)?;

    // Build full chain: [leaf, cabundle*]
    let mut chain_der: Vec<Vec<u8>> = vec![proto.certificate.clone()];
    chain_der.extend(proto.cabundle.clone());

    // ── 4. Certificate chain verify → leaf verifying key ─────────────────────
    //    Use the CALLER's wall-clock, not `proto.timestamp`. The doc's
    //    timestamp is attacker-controlled — deferring cert-expiry to it
    //    would let a forged doc pass an expired leaf by simply claiming to
    //    have been produced inside the validity window.
    let leaf_vk = verify_chain(&chain_der, roots, current_time)?;

    // ── 5. COSE signature verify with leaf key ────────────────────────────────
    //    Nitro uses empty AAD (no application-specific binding).
    verify_cose_sign1_es384(doc_cose_bytes, &leaf_vk, &[])?;

    // ── 6. Nonce check ────────────────────────────────────────────────────────
    if let Some(expected) = expected_nonce {
        match &proto.nonce {
            None => return Err(AttestError::NonceMismatch),
            Some(actual) => {
                if actual != expected {
                    return Err(AttestError::NonceMismatch);
                }
            }
        }
    }

    Ok(proto)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the payload bytes from a COSE_Sign1 without verifying the signature.
///
/// Used in pass-1 to get the cert chain before we have a verifying key.
fn extract_cose_payload(cose_bytes: &[u8]) -> Result<Vec<u8>, AttestError> {
    let top: CborValue = ciborium::de::from_reader(cose_bytes)
        .map_err(|_| AttestError::MalformedDoc { source: None })?;

    let array = match top {
        CborValue::Tag(18, inner) => match *inner {
            CborValue::Array(a) => a,
            _ => return Err(AttestError::MalformedDoc { source: None }),
        },
        CborValue::Array(a) => a,
        _ => return Err(AttestError::MalformedDoc { source: None }),
    };

    if array.len() != 4 {
        return Err(AttestError::MalformedDoc { source: None });
    }

    match &array[2] {
        CborValue::Bytes(b) => Ok(b.clone()),
        CborValue::Null => Ok(vec![]),
        _ => Err(AttestError::MalformedDoc { source: None }),
    }
}

/// Parse the CBOR payload of a Nitro attestation document into [`NitroClaims`].
fn parse_claims_cbor(payload: &[u8]) -> Result<NitroClaims, AttestError> {
    let value: CborValue = ciborium::de::from_reader(payload)
        .map_err(|_| AttestError::MalformedDoc { source: None })?;

    let CborValue::Map(pairs) = value else {
        return Err(AttestError::MalformedDoc { source: None });
    };

    let mut module_id = String::new();
    let mut digest = String::new();
    let mut timestamp = 0i64;
    let mut pcrs: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut certificate = Vec::new();
    let mut cabundle: Vec<Vec<u8>> = Vec::new();
    let mut public_key = None;
    let mut user_data = None;
    let mut nonce = None;

    for (k, v) in &pairs {
        let key = match k {
            CborValue::Text(s) => s.as_str(),
            _ => continue,
        };
        match key {
            "module_id" => {
                if let CborValue::Text(s) = v {
                    module_id.clone_from(s);
                }
            }
            "digest" => {
                if let CborValue::Text(s) = v {
                    digest.clone_from(s);
                }
            }
            "timestamp" => {
                if let CborValue::Integer(i) = v {
                    // Reject implausible values fail-closed. The Nitro wire
                    // format permits any integer, so we bound it here to
                    // [0, 2100-01-01 UTC). A negative or far-future timestamp
                    // is structurally invalid — not merely a cert-expiry miss.
                    let t = i64::try_from(*i)
                        .map_err(|_| AttestError::MalformedDoc { source: None })?;
                    if !(0..4_102_444_800).contains(&t) {
                        return Err(AttestError::MalformedDoc { source: None });
                    }
                    timestamp = t;
                }
            }
            "pcrs" => {
                if let CborValue::Map(pcr_pairs) = v {
                    for (pk, pv) in pcr_pairs {
                        if let (CborValue::Integer(id_int), CborValue::Bytes(hash)) = (pk, pv) {
                            if let Ok(id) = u8::try_from(u64::try_from(*id_int).unwrap_or(255)) {
                                pcrs.push((id, hash.clone()));
                            }
                        }
                    }
                }
            }
            "certificate" => {
                if let CborValue::Bytes(b) = v {
                    certificate.clone_from(b);
                }
            }
            "cabundle" => {
                if let CborValue::Array(arr) = v {
                    for item in arr {
                        if let CborValue::Bytes(b) = item {
                            cabundle.push(b.clone());
                        }
                    }
                }
            }
            "public_key" => {
                if let CborValue::Bytes(b) = v {
                    public_key = Some(b.clone());
                }
            }
            "user_data" => {
                if let CborValue::Bytes(b) = v {
                    user_data = Some(b.clone());
                }
            }
            "nonce" => {
                if let CborValue::Bytes(b) = v {
                    nonce = Some(b.clone());
                }
            }
            _ => {} // unknown fields are ignored
        }
    }

    Ok(NitroClaims {
        module_id,
        digest,
        timestamp,
        pcrs,
        certificate,
        cabundle,
        public_key,
        user_data,
        nonce,
    })
}
