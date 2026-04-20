//! Live COSE_Sign1 verification pipeline (Phase C.1, role-aware as of C.3-C).
//!
//! Pipeline ordering (fail-fast, first-failing wins):
//!
//! 1. **Size & depth guard** — adversarial CBOR rejected before handing to
//!    `coset`. See [`crate::size_guard`].
//! 2. **Structural parse** — `coset::CoseSign1::from_slice`.
//! 3. **Alg extraction & allowlist** — integer alg label from the
//!    protected header, matched against [`crate::Alg`].
//! 4. **Role-aware kid resolution** — the protected-header `kid` is
//!    resolved against [`TrustAnchorSet::lookup_with_role`] with the
//!    caller-supplied [`AnchorRole`]. A kid that is present in the set
//!    but under a different role surfaces as
//!    [`CoseError::UnknownKid`] so role assignments are not leaked.
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
use crate::anchors::{AnchorRole, TrustAnchorSet};
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

/// Verify a COSE_Sign1 blob against a set of trust anchors, an external
/// AAD, and an expected signer role — returning the inner payload on
/// success.
///
/// `aad` is the external additional authenticated data per RFC 9052
/// §4.4. Callers supply a fixed domain-separation tag (e.g. `b"tariff"`,
/// `b"delegation-link"`, `b"ephemeral/classifier/v1"`) to prevent
/// cross-document signature confusion.
///
/// `expected_role` narrows kid resolution to anchors authorised for the
/// caller's domain. A kid present in the set but registered under a
/// different role is indistinguishable from an absent kid from the
/// caller's perspective — both surface as [`CoseError::UnknownKid`] so
/// an attacker probing the anchor set cannot enumerate role assignments.
pub fn verify_cose_sign1(
    cose_bytes: &[u8],
    anchors: &TrustAnchorSet,
    aad: &[u8],
    expected_role: AnchorRole,
) -> Result<VerifiedPayload, CoseError> {
    size_depth_check(cose_bytes)?;
    let sign1 = parse_cose_sign1(cose_bytes)?;

    let alg_label = extract_alg_label(&sign1)?;
    let alg = Alg::from_cose_label(alg_label)?;

    let kid = extract_kid(&sign1)?;
    let anchor = anchors
        .lookup_with_role(&kid, expected_role)
        .ok_or_else(|| CoseError::UnknownKid { kid: kid.clone() })?;

    if anchor.alg != alg {
        return Err(CoseError::AlgMismatch {
            alg: alg.as_cose_label(),
            key_type: anchor.alg.as_wire_str(),
        });
    }

    // Existence check first — malformed envelopes without a payload
    // MUST still fail before we hand TBS bytes to the verifier (step 6
    // of the module-level pipeline). We deliberately do NOT clone here:
    // on the reject path the allocation is pure waste, and on the success
    // path we move the payload out of `sign1` below without a copy.
    if sign1.payload.is_none() {
        return Err(CoseError::MalformedHeader { source: None });
    }

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

    // Move payload out of sign1 (checked non-None above, sign1 not
    // touched by the closure). No clone, no re-check — the signature
    // is now known-valid and the allocation is the only one on the path.
    let payload = sign1
        .payload
        .expect("payload existence checked before verify_signature");

    Ok(VerifiedPayload { kid, alg, payload })
}
