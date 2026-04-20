//! End-to-end tests for [`verify_cose_sign1`].
//!
//! These tests drive the verifier through its public API only. They
//! construct real COSE_Sign1 envelopes with `coset` + `ed25519-dalek` so
//! the pipeline is exercised exactly as downstream suites (tariff,
//! delegation) will call it.
//!
//! Matrix:
//! - happy_path_roundtrips
//! - wrong_kid_rejected            → UnknownKid
//! - tampered_payload_rejected     → SignatureInvalid
//! - wrong_aad_rejected            → SignatureInvalid
//! - unsupported_alg_rejected      → UnsupportedAlg
//! - oversize_rejected             → PayloadTooLarge
//! - empty_kid_rejected            → MalformedHeader
//! - bogus_bytes_rejected          → MalformedHeader / CborParse
//! - proptest_no_panics            → verifier is total on random bytes
//!
//! Key material is deterministic (fixed seeds) so failures are
//! reproducible and the vector-signer tool can reuse the same seeds
//! when generating committed conformance vectors.

// Normative COSE identifiers (COSE_Sign1, Sig_structure_1) appear
// throughout the doc comments verbatim; backticking them every time
// hurts readability more than it helps.
#![allow(clippy::doc_markdown)]

use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};

use ephemeral_crypto::{
    verify_cose_sign1, Alg, AnchorRole, CoseError, TrustAnchor, TrustAnchorSet,
};

const KID: &str = "K_test_ed25519";
const AAD: &[u8] = b"tariff";
/// These tests drive the tariff-signing path (AAD = `b"tariff"`), so
/// the anchor is registered as a [`AnchorRole::TariffSigner`] and the
/// verifier is invoked with the same role. Negative tests that want to
/// exercise *signature* failure keep this role so the failure point is
/// the TBS mismatch rather than a silent kid-miss under the wrong role.
const ROLE: AnchorRole = AnchorRole::TariffSigner;
const SEED: [u8; 32] = [
    0x42, 0xe1, 0x7a, 0x3f, 0x5b, 0x9c, 0x12, 0x88, 0x44, 0x77, 0xaa, 0x0b, 0xcd, 0xef, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn anchor_set() -> TrustAnchorSet {
    let pk = signing_key().verifying_key();
    let anchor = TrustAnchor::new_ed25519(KID.to_string(), pk.as_bytes(), ROLE)
        .expect("fixed seed yields non-weak pk");
    let mut set = TrustAnchorSet::new();
    set.insert(anchor).expect("fresh set has no dup kid");
    set
}

/// Build a valid COSE_Sign1 blob with the supplied payload, kid, and AAD.
fn build_sign1(payload: Vec<u8>, kid: &str, aad: &[u8]) -> Vec<u8> {
    let sk = signing_key();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(kid.as_bytes().to_vec())
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(aad, |tbs| sk.sign(tbs).to_bytes().to_vec())
        .build();

    sign1.to_vec().expect("serialize")
}

#[test]
fn happy_path_roundtrips() {
    let payload = b"{\"price\":\"100\"}".to_vec();
    let bytes = build_sign1(payload.clone(), KID, AAD);
    let verified = verify_cose_sign1(&bytes, &anchor_set(), AAD, ROLE).expect("verify");

    assert_eq!(verified.kid, KID);
    assert_eq!(verified.alg, Alg::Ed25519);
    assert_eq!(verified.payload, payload);
}

#[test]
fn wrong_kid_rejected() {
    let bytes = build_sign1(b"payload".to_vec(), "K_unknown_kid", AAD);
    let err = verify_cose_sign1(&bytes, &anchor_set(), AAD, ROLE).unwrap_err();
    assert!(matches!(err, CoseError::UnknownKid { kid } if kid == "K_unknown_kid"));
}

#[test]
fn tampered_payload_rejected() {
    // Flip a byte inside the signed payload after signing. Parse,
    // mutate, re-serialize — signature verification must fail.
    let bytes = build_sign1(b"payload-original".to_vec(), KID, AAD);
    let mut sign1 = coset::CoseSign1::from_slice(&bytes).expect("parse");
    let payload = sign1.payload.as_mut().expect("has payload");
    payload[0] ^= 0x01; // flip one bit
    let tampered = sign1.to_vec().expect("reserialize");

    let err = verify_cose_sign1(&tampered, &anchor_set(), AAD, ROLE).unwrap_err();
    assert!(matches!(err, CoseError::SignatureInvalid { .. }));
}

#[test]
fn wrong_aad_rejected() {
    let bytes = build_sign1(b"payload".to_vec(), KID, AAD);
    let err = verify_cose_sign1(&bytes, &anchor_set(), b"delegation-link", ROLE).unwrap_err();
    assert!(matches!(err, CoseError::SignatureInvalid { .. }));
}

#[test]
fn unsupported_alg_rejected() {
    // Build a COSE_Sign1 with alg=ES256 (-7). Signature bytes are
    // arbitrary — the verifier must reject on alg gate before ever
    // touching them.
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(KID.as_bytes().to_vec())
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(b"payload".to_vec())
        .create_signature(AAD, |_tbs| vec![0u8; 64])
        .build();
    let bytes = sign1.to_vec().expect("serialize");

    let err = verify_cose_sign1(&bytes, &anchor_set(), AAD, ROLE).unwrap_err();
    assert!(matches!(err, CoseError::UnsupportedAlg { alg: -7 }));
}

#[test]
fn oversize_rejected() {
    // Build a payload that pushes the serialized blob past 64 KiB.
    let big = vec![0xAA; 70_000];
    let bytes = build_sign1(big, KID, AAD);
    assert!(bytes.len() > 65_536);

    let err = verify_cose_sign1(&bytes, &anchor_set(), AAD, ROLE).unwrap_err();
    assert!(matches!(
        err,
        CoseError::PayloadTooLarge { observed, cap } if observed == bytes.len() && cap == 65_536
    ));
}

#[test]
fn empty_kid_rejected() {
    let bytes = build_sign1(b"payload".to_vec(), "", AAD);
    let err = verify_cose_sign1(&bytes, &anchor_set(), AAD, ROLE).unwrap_err();
    assert!(matches!(err, CoseError::MalformedHeader { .. }));
}

#[test]
fn bogus_bytes_rejected() {
    // Random-looking but non-CBOR input — must not panic, must return Err.
    let junk: Vec<u8> = (0..128u8).collect();
    let err = verify_cose_sign1(&junk, &anchor_set(), AAD, ROLE).unwrap_err();
    assert!(matches!(
        err,
        CoseError::MalformedHeader { .. } | CoseError::CborParse
    ));
}

#[test]
fn empty_input_rejected() {
    let err = verify_cose_sign1(&[], &anchor_set(), AAD, ROLE).unwrap_err();
    assert!(matches!(
        err,
        CoseError::MalformedHeader { .. } | CoseError::CborParse
    ));
}

mod proptest_fuzz {
    use super::{anchor_set, verify_cose_sign1, AAD, ROLE};
    use proptest::prelude::*;

    // The verifier must be total on random bytes — no panics, no
    // recursion blow-ups from unbounded CBOR nesting. Defaults give
    // 256 cases which is plenty for this surface.
    proptest! {
        #[test]
        fn verifier_is_total_on_random_input(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = verify_cose_sign1(&bytes, &anchor_set(), AAD, ROLE);
        }
    }
}
