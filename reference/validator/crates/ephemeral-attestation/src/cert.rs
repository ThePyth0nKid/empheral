//! X.509 certificate parsing and chain verification for Nitro attestation.
//!
//! AWS Nitro attestation documents contain a DER-encoded leaf certificate
//! plus a `cabundle` of intermediate certificates.  This module:
//!
//! 1. Parses each cert with `x509-parser`.
//! 2. Checks `not_before` / `not_after` against the attestation timestamp.
//! 3. Verifies each link's ECDSA-P384 signature against the parent's SPKI.
//! 4. Checks the root's fingerprint against the [`NitroRootSet`].
//! 5. Rejects SHA-1 or MD5 signature algorithms (`WeakHashAlg`).
//! 6. Caps chain length at [`MAX_CA_CHAIN_DEPTH`].

use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p384::elliptic_curve::sec1::FromEncodedPoint;
use p384::pkcs8::DecodePublicKey;
use p384::{AffinePoint, EncodedPoint};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::anchors::{sha256_fingerprint, NitroRootSet};
use crate::error::{AttestError, X509Source};
use crate::size_guard::MAX_CA_CHAIN_DEPTH;

/// Weak signature algorithm OIDs that we refuse.
/// - sha1WithRSAEncryption: 1.2.840.113549.1.1.5
/// - md5WithRSAEncryption:  1.2.840.113549.1.1.4
/// - ecdsa-with-SHA1:       1.2.840.10045.4.1
const WEAK_SIG_ALGS: &[&str] = &[
    "1.2.840.113549.1.1.5",
    "1.2.840.113549.1.1.4",
    "1.2.840.10045.4.1",
];

/// Parse `der` as a DER-encoded X.509 certificate.
///
/// Returns an error if parsing fails (does not validate the signature).
/// `index` is the position of this cert in the chain — it is embedded in
/// any resulting `CaChainInvalid` error so the caller can report which
/// link failed without re-deriving the index later.
pub(crate) fn decode_cert(der: &[u8], index: usize) -> Result<X509CertOwned, AttestError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| AttestError::CaChainInvalid {
        index,
        source: X509Source(e.into()),
    })?;
    Ok(X509CertOwned {
        der: der.to_vec(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        sig_alg_oid: cert.signature_algorithm.algorithm.to_string(),
        spki_der: cert.public_key().raw.to_vec(),
        tbs_der: cert.tbs_certificate.as_ref().to_vec(),
        sig_bytes: cert.signature_value.data.to_vec(),
    })
}

/// Owned view of parsed cert data needed for chain verification.
#[derive(Clone)]
pub(crate) struct X509CertOwned {
    pub der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub sig_alg_oid: String,
    pub spki_der: Vec<u8>,
    pub tbs_der: Vec<u8>,
    pub sig_bytes: Vec<u8>,
}

impl core::fmt::Debug for X509CertOwned {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("X509CertOwned")
            .field("der", &"<redacted>")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("sig_alg_oid", &self.sig_alg_oid)
            .field("spki_der", &"<redacted>")
            .field("tbs_der", &"<redacted>")
            .field("sig_bytes", &"<redacted>")
            .finish()
    }
}

/// Verify a certificate chain in order `[leaf, intermediate*, root_candidate]`.
///
/// - `chain_der`: leaf cert first, then intermediates (no explicit root — the
///   root must be in `roots`).
/// - `now`: Unix seconds to check validity windows.
///
/// On success returns the P-384 verifying key extracted from the leaf SPKI.
pub(crate) fn verify_chain(
    chain_der: &[Vec<u8>],
    roots: &NitroRootSet,
    now: i64,
) -> Result<VerifyingKey, AttestError> {
    if chain_der.is_empty() {
        return Err(AttestError::MalformedDoc { source: None });
    }

    // Total depth = chain_der length + implicit root (1 more)
    if chain_der.len() > MAX_CA_CHAIN_DEPTH {
        return Err(AttestError::CaChainTooLong {
            depth: chain_der.len(),
            max: MAX_CA_CHAIN_DEPTH,
        });
    }

    // Parse all certs. `decode_cert` embeds the correct index AND preserves
    // the real x509-parser error so diagnostics survive the chain walk.
    let certs: Vec<X509CertOwned> = chain_der
        .iter()
        .enumerate()
        .map(|(i, der)| decode_cert(der, i))
        .collect::<Result<_, _>>()?;

    // Validate leaf cert (index 0)
    let leaf = &certs[0];
    check_validity(leaf, now, 0)?;
    check_sig_alg(leaf, 0)?;

    // The issuer of the leaf must be verified by something in the chain or roots.
    // Walk: each cert in chain is signed by the next one; the last cert must
    // be in the root set (self-signed CA).

    // If chain has only leaf, the leaf's issuer must be a trusted root
    if certs.len() == 1 {
        // Find parent in roots by fingerprint of the chain
        // Try to find a root that can verify the leaf signature
        verify_leaf_against_roots(leaf, roots, now)?;
        return extract_leaf_key(leaf);
    }

    // Verify each link: certs[i] is signed by certs[i+1]
    for i in 0..certs.len() - 1 {
        let child = &certs[i];
        let parent = &certs[i + 1];
        check_validity(parent, now, i + 1)?;
        check_sig_alg(parent, i + 1)?;
        verify_cert_signature(child, parent, i)?;
    }

    // Last cert in chain must be in roots or be verifiable by a root
    let last = &certs[certs.len() - 1];
    verify_leaf_against_roots(last, roots, now)?;

    extract_leaf_key(leaf)
}

/// Check a cert's validity window against `now`.
fn check_validity(cert: &X509CertOwned, now: i64, index: usize) -> Result<(), AttestError> {
    let _ = index; // used for future error context
    if now < cert.not_before {
        return Err(AttestError::CertNotYetValid {
            now,
            not_before: cert.not_before,
        });
    }
    if now > cert.not_after {
        return Err(AttestError::CertExpired {
            now,
            not_after: cert.not_after,
        });
    }
    Ok(())
}

/// Reject known-weak signature algorithm OIDs.
///
/// Matches the OID string by strict equality only. Substring matching would
/// mis-classify any future OID that happens to overlap lexically with a
/// retired algorithm — X.509 OIDs are fixed dot-notation identifiers and
/// are never substrings of one another in practice.
fn check_sig_alg(cert: &X509CertOwned, _index: usize) -> Result<(), AttestError> {
    for weak in WEAK_SIG_ALGS {
        if cert.sig_alg_oid == *weak {
            return Err(AttestError::WeakHashAlg {
                alg: weak_alg_name(&cert.sig_alg_oid),
            });
        }
    }
    Ok(())
}

fn weak_alg_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        _ => "weak-hash-alg",
    }
}

/// Verify `child`'s TBS signature using `parent`'s SPKI.
///
/// A failed link signature is a chain-structure defect, not a COSE envelope
/// defect, so we return `CaChainInvalid` rather than `SignatureInvalid`.
/// `SignatureInvalid` is reserved exclusively for the COSE_Sign1 payload
/// signature, which is checked by `cose_bridge::verify_cose_sign1_es384`.
fn verify_cert_signature(
    child: &X509CertOwned,
    parent: &X509CertOwned,
    index: usize,
) -> Result<(), AttestError> {
    let chain_err = || AttestError::CaChainInvalid {
        index,
        source: X509Source(x509_parser::error::X509Error::Generic),
    };
    let parent_vk = spki_to_p384_key(&parent.spki_der, index)?;
    let sig = Signature::from_der(&child.sig_bytes).map_err(|_| chain_err())?;
    parent_vk
        .verify(&child.tbs_der, &sig)
        .map_err(|_| chain_err())
}

/// Check whether `cert` is a trusted root by fingerprint.
///
/// For the Nitro chain the last cert is always a self-signed CA root whose
/// fingerprint must be in [`NitroRootSet`]. We don't attempt to find a
/// "signer" in the root set — a root cert signs itself, and the signing
/// relationship is encoded in its presence in the pinned set.
///
/// Computes the SHA-256 fingerprint exactly once and reuses it for both the
/// lookup and the error payload.
fn verify_leaf_against_roots(
    cert: &X509CertOwned,
    roots: &NitroRootSet,
    _now: i64,
) -> Result<(), AttestError> {
    let fp = sha256_fingerprint(&cert.der);
    if roots.find_by_fingerprint(&fp).is_some() {
        return Ok(());
    }
    Err(AttestError::UntrustedRoot { fingerprint: fp })
}

/// Extract a P-384 `VerifyingKey` from a SubjectPublicKeyInfo DER blob.
fn spki_to_p384_key(spki_der: &[u8], index: usize) -> Result<VerifyingKey, AttestError> {
    // x509-parser gives us the raw SPKI bytes (from SubjectPublicKeyInfo.raw)
    // which may be the BIT STRING content or the whole SPKI struct.
    // p384 can parse SEC1 uncompressed point (0x04 || x || y, 97 bytes) directly.
    // Attempt two parsings: pkcs8 SPKI first, then raw point.

    // Try as full SPKI (DER SubjectPublicKeyInfo)
    if let Ok(vk) = VerifyingKey::from_public_key_der(spki_der) {
        return Ok(vk);
    }

    // Try as raw SEC1 uncompressed point
    if let Ok(ep) = EncodedPoint::from_bytes(spki_der) {
        if let Some(ap) = AffinePoint::from_encoded_point(&ep).into() {
            let vk = VerifyingKey::from_affine(ap).map_err(|_| AttestError::CaChainInvalid {
                index,
                source: X509Source(x509_parser::error::X509Error::Generic),
            })?;
            return Ok(vk);
        }
    }

    Err(AttestError::CaChainInvalid {
        index,
        source: X509Source(x509_parser::error::X509Error::Generic),
    })
}

/// Extract the P-384 verifying key from the leaf cert's SPKI.
fn extract_leaf_key(leaf: &X509CertOwned) -> Result<VerifyingKey, AttestError> {
    spki_to_p384_key(&leaf.spki_der, 0)
}
