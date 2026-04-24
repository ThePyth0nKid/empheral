//! COSE_Sign1 envelope construction (RFC 9052 §4.2).
//!
//! The envelope binds three things:
//! 1. The fact payload bytes (`crate::event::encode_payload`).
//! 2. The domain-separation AAD [`crate::COSE_EXTERNAL_AAD`].
//! 3. The Ed25519 signing key's public identity via its `kid`.
//!
//! Verifiers (including the round-trip integration test) recover (1)
//! directly as `VerifiedPayload::payload` from
//! `ephemeral_crypto::verify_cose_sign1`, so the fact is self-contained
//! in the envelope and no out-of-band payload shipping is required.

use coset::iana;
use coset::CborSerializable;
use coset::CoseSign1Builder;
use coset::HeaderBuilder;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;

use crate::COSE_EXTERNAL_AAD;

/// Error produced when building a COSE_Sign1 envelope.
#[derive(Debug, thiserror::Error)]
pub enum CoseBuildError {
    #[error("coset serialisation failed: {0}")]
    Serialize(String),
}

/// Build a COSE_Sign1 envelope over `payload` using `signing_key` under
/// the supplied UTF-8 `kid`.
///
/// The envelope is emitted in **untagged** form so it is directly
/// consumable by `ephemeral_crypto::verify_cose_sign1` (which calls
/// `CoseSign1::from_slice`, not `from_tagged_slice`).
///
/// Returned bytes are the CBOR-encoded `COSE_Sign1` structure per
/// RFC 9052.  Hex-encoded by the caller before going on the wire.
pub fn build_cose_sign1(
    payload: &[u8],
    signing_key: &SigningKey,
    kid: &str,
) -> Result<Vec<u8>, CoseBuildError> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(kid.as_bytes().to_vec())
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(COSE_EXTERNAL_AAD, |tbs| {
            signing_key.sign(tbs).to_bytes().to_vec()
        })
        .build();

    sign1
        .to_vec()
        .map_err(|e| CoseBuildError::Serialize(format!("{e:?}")))
}

/// Derive the Canon-style UTF-8 kid for an Ed25519 public key.
///
/// Format: `canon/<first-16-hex-chars-of-raw-pubkey>`.  16 hex chars
/// encode 8 bytes of entropy — more than enough to disambiguate
/// signers in any realistic Canon deployment (collision probability
/// 2^-32 per 65k keys).  Choosing a UTF-8 string (not raw bytes) lets
/// `ephemeral_crypto::verify_cose_sign1` consume the kid via its
/// `extract_kid` helper, which rejects non-UTF-8 kids.
pub fn derive_kid(pubkey_bytes: &[u8; 32]) -> String {
    let hex_full = hex::encode(pubkey_bytes);
    format!("{}{}", crate::CANON_KID_PREFIX, &hex_full[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ephemeral_crypto::{verify_cose_sign1, AnchorRole, TrustAnchor, TrustAnchorSet};

    fn fixed_signing_key() -> SigningKey {
        // Deterministic 32-byte seed for test reproducibility.  Not a
        // production key; never reuse outside tests.
        let seed = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn kid_derivation_is_deterministic_and_well_formed() {
        let sk = fixed_signing_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let kid = derive_kid(&vk_bytes);
        assert!(kid.starts_with("canon/"));
        assert_eq!(kid.len(), "canon/".len() + 16);
        assert!(kid[6..].chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic: derive again, must match.
        assert_eq!(kid, derive_kid(&vk_bytes));
    }

    #[test]
    fn built_envelope_verifies_via_ephemeral_crypto() {
        // End-to-end round-trip within the unit layer: sign a payload,
        // hand it to ephemeral-crypto's production verifier, recover
        // the same payload bytes.  This is the load-bearing invariant
        // of the whole binary — if this fails, Canon cannot verify
        // anything we sign.
        let sk = fixed_signing_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let kid = derive_kid(&vk_bytes);
        let payload = b"canonical-cbor-bytes-would-go-here".to_vec();

        let envelope = build_cose_sign1(&payload, &sk, &kid).unwrap();

        let mut anchors = TrustAnchorSet::new();
        anchors
            .insert(
                TrustAnchor::new_ed25519(kid.clone(), &vk_bytes, AnchorRole::CanonSigner).unwrap(),
            )
            .unwrap();

        let verified = verify_cose_sign1(
            &envelope,
            &anchors,
            COSE_EXTERNAL_AAD,
            AnchorRole::CanonSigner,
        )
        .expect("verification must succeed");

        assert_eq!(verified.kid, kid);
        assert_eq!(verified.payload, payload);
    }

    #[test]
    fn wrong_aad_rejects_signature() {
        let sk = fixed_signing_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let kid = derive_kid(&vk_bytes);
        let payload = b"payload".to_vec();
        let envelope = build_cose_sign1(&payload, &sk, &kid).unwrap();

        let mut anchors = TrustAnchorSet::new();
        anchors
            .insert(
                TrustAnchor::new_ed25519(kid.clone(), &vk_bytes, AnchorRole::CanonSigner).unwrap(),
            )
            .unwrap();

        // Wrong AAD = cross-protocol reuse attempt. Must fail.
        let result = verify_cose_sign1(
            &envelope,
            &anchors,
            b"wrong/aad/v1",
            AnchorRole::CanonSigner,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_role_rejects_signature() {
        let sk = fixed_signing_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let kid = derive_kid(&vk_bytes);
        let payload = b"payload".to_vec();
        let envelope = build_cose_sign1(&payload, &sk, &kid).unwrap();

        // Anchor registered under the WRONG role — role-confusion must
        // collapse to UnknownKid rather than verifying.
        let mut anchors = TrustAnchorSet::new();
        anchors
            .insert(
                TrustAnchor::new_ed25519(kid.clone(), &vk_bytes, AnchorRole::TariffSigner).unwrap(),
            )
            .unwrap();

        let result = verify_cose_sign1(
            &envelope,
            &anchors,
            COSE_EXTERNAL_AAD,
            AnchorRole::CanonSigner,
        );
        assert!(result.is_err());
    }
}
