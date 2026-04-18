//! Live COSE_Sign1 verification pipeline (Phase C.1).
//!
//! Pipeline ordering (fail-fast, first-failing wins):
//!
//! 1. **Size & depth guard** — adversarial CBOR rejected before handing to
//!    `coset`. See [`crate::size_guard`].
//! 2. **Structural parse** — `coset::CoseSign1::from_slice`.
//! 3. **Alg extraction & allowlist** — integer alg label from the
//!    protected header, matched against [`crate::Alg`].
//! 4. **Kid resolution** — protected-header `kid` looked up in the
//!    [`TrustAnchorSet`].
//! 5. **Alg/anchor consistency** — alg declared in header must match the
//!    alg bound to the trust anchor.
//! 6. **Payload presence** — a COSE_Sign1 without a `payload` field is
//!    malformed for our use-case (we never use detached payloads).
//! 7. **Signature verification** — `coset::CoseSign1::verify_signature`
//!    assembles `Sig_structure_1` per RFC 9052 §4.4 and hands
//!    `(sig, tbs)` to our closure, which runs Ed25519
//!    [`VerifyingKey::verify_strict`]. Strict-mode rejects non-canonical
//!    `R` and enforces the cofactor-less equation — matching Sigstore /
//!    transparency-log verifiers.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::alg::Alg;
use crate::anchors::TrustAnchorSet;
use crate::cose::{extract_alg_label, extract_kid, parse_cose_sign1};
use crate::error::{CoseError, Ed25519Source};
use crate::size_guard::size_depth_check;

/// The verified outcome of a COSE_Sign1 envelope: kid, declared alg,
/// and the inner `payload` bytes (opaque to this crate — downstream
/// decoders interpret them per domain CDDL).
#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    pub kid: String,
    pub alg: Alg,
    pub payload: Vec<u8>,
}

/// Verify a COSE_Sign1 blob against a set of trust anchors and an
/// external AAD, returning the inner payload on success.
///
/// `aad` is the external additional authenticated data per RFC 9052
/// §4.4. Callers supply a fixed domain-separation tag (e.g. `b"tariff"`,
/// `b"delegation-link"`) to prevent cross-document signature confusion.
pub fn verify_cose_sign1(
    cose_bytes: &[u8],
    anchors: &TrustAnchorSet,
    aad: &[u8],
) -> Result<VerifiedPayload, CoseError> {
    size_depth_check(cose_bytes)?;
    let sign1 = parse_cose_sign1(cose_bytes)?;

    let alg_label = extract_alg_label(&sign1)?;
    let alg = Alg::from_cose_label(alg_label)?;

    let kid = extract_kid(&sign1)?;
    let anchor = anchors
        .lookup(&kid)
        .ok_or_else(|| CoseError::UnknownKid { kid: kid.clone() })?;

    if anchor.alg != alg {
        return Err(CoseError::AlgMismatch {
            alg: alg.as_cose_label(),
            key_type: anchor.alg.as_wire_str(),
        });
    }

    let payload = sign1
        .payload
        .as_ref()
        .ok_or(CoseError::MalformedHeader { source: None })?
        .clone();

    let pk: &VerifyingKey = &anchor.pk;
    sign1.verify_signature(aad, |sig_bytes, tbs| {
        let sig = Signature::from_slice(sig_bytes).map_err(|e| CoseError::SignatureInvalid {
            source: Ed25519Source(e),
        })?;
        pk.verify_strict(tbs, &sig)
            .map_err(|e| CoseError::SignatureInvalid {
                source: Ed25519Source(e),
            })
    })?;

    Ok(VerifiedPayload { kid, alg, payload })
}
