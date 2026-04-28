//! Integration tests for [`verify_nitro_attestation`] and [`verify_pcr_set`].
//!
//! All tests drive the public API only. Synthetic Nitro attestation documents
//! are constructed at test-time using a local P-384 CA + leaf keypair — no
//! AWS infrastructure required.
//!
//! Test matrix:
//! 1. happy_path_verifies_cleanly
//! 2. ca_chain_expired
//! 3. ca_chain_not_yet_valid
//! 4. nonce_mismatch
//! 5. pcr_mismatch
//! 6. malformed_doc_truncated
//! 7. unknown_alg_rejected
//! 8. duplicate_pcr_id_rejected
//! 9. weak_hash_alg_rejected (SHA-1 in cert)

#![allow(clippy::doc_markdown)]

use ephemeral_attestation::{verify_nitro_attestation, verify_pcr_set, AttestError, NitroRootSet};

mod helpers;
use helpers::{build_attestation_doc, BuildParams};

// ── 1. happy path ────────────────────────────────────────────────────────────

/// Default-fixture Unix seconds — matches `BuildParams::default().now`.
const DEFAULT_NOW: i64 = 1_700_000_000;

#[test]
fn happy_path_verifies_cleanly() {
    let (doc_bytes, roots) = build_attestation_doc(BuildParams::default());
    let claims =
        verify_nitro_attestation(&doc_bytes, &roots, None, DEFAULT_NOW).expect("should verify");
    assert_eq!(claims.module_id, "i-test-module-00");
    assert_eq!(claims.digest, "SHA384");
    assert!(!claims.pcrs.is_empty());

    // PCR verify round-trip
    let expected: Vec<(u8, Vec<u8>)> = claims.pcrs.clone();
    let expected_refs: Vec<(u8, &[u8])> =
        expected.iter().map(|(i, h)| (*i, h.as_slice())).collect();
    verify_pcr_set(&claims, &expected_refs).expect("exact match should pass");
}

// ── 2. expired leaf cert ─────────────────────────────────────────────────────

#[test]
fn ca_chain_expired() {
    // now = 2_000_000; leaf validity window is entirely in the past.
    let now = 2_000_000i64;
    let params = BuildParams {
        now,
        leaf_not_before: now - 100_000, // valid window was 900_000..1_000_000
        leaf_not_after: 1_000_000,      // expired before now
        ..BuildParams::default()
    };
    let (doc_bytes, roots) = build_attestation_doc(params);
    let err = verify_nitro_attestation(&doc_bytes, &roots, None, now).unwrap_err();
    assert!(
        matches!(err, AttestError::CertExpired { .. }),
        "expected CertExpired, got {err:?}"
    );
}

// ── 3. not-yet-valid leaf cert ───────────────────────────────────────────────

#[test]
fn ca_chain_not_yet_valid() {
    let now = 1_000_000i64;
    let params = BuildParams {
        leaf_not_before: now + 9999,
        now,
        ..BuildParams::default()
    };
    let (doc_bytes, roots) = build_attestation_doc(params);
    let err = verify_nitro_attestation(&doc_bytes, &roots, None, now).unwrap_err();
    assert!(
        matches!(err, AttestError::CertNotYetValid { .. }),
        "expected CertNotYetValid, got {err:?}"
    );
}

// ── 4. nonce mismatch ────────────────────────────────────────────────────────

#[test]
fn nonce_mismatch() {
    let expected_nonce = b"expected_nonce_value";
    let params = BuildParams {
        nonce: Some(b"different_nonce".to_vec()),
        ..BuildParams::default()
    };
    let (doc_bytes, roots) = build_attestation_doc(params);
    let err = verify_nitro_attestation(&doc_bytes, &roots, Some(expected_nonce), DEFAULT_NOW)
        .unwrap_err();
    assert!(
        matches!(err, AttestError::NonceMismatch),
        "expected NonceMismatch, got {err:?}"
    );
}

// ── 5. PCR mismatch ──────────────────────────────────────────────────────────

#[test]
fn pcr_mismatch() {
    let (doc_bytes, roots) = build_attestation_doc(BuildParams::default());
    let claims =
        verify_nitro_attestation(&doc_bytes, &roots, None, DEFAULT_NOW).expect("verify ok");

    // Expect PCR0 to be all-zeros but claims has real data
    let wrong_hash = [0xFFu8; 48];
    let expected = &[(0u8, wrong_hash.as_slice())];
    let err = verify_pcr_set(&claims, expected).unwrap_err();
    assert!(
        matches!(err, AttestError::PcrMismatch { id: 0, .. }),
        "expected PcrMismatch for id=0, got {err:?}"
    );
}

// ── 6. malformed / truncated doc ─────────────────────────────────────────────

#[test]
fn malformed_doc_truncated() {
    let roots = NitroRootSet::new();
    let truncated = vec![0x82, 0x43, 0xa1, 0x01]; // partial COSE array
    let err = verify_nitro_attestation(&truncated, &roots, None, DEFAULT_NOW).unwrap_err();
    assert!(
        matches!(err, AttestError::MalformedDoc { .. }),
        "expected MalformedDoc, got {err:?}"
    );
}

// ── 7. unsupported alg (not ES384 / -35) ─────────────────────────────────────

#[test]
fn unknown_alg_rejected() {
    let params = BuildParams {
        use_wrong_alg: true,
        ..BuildParams::default()
    };
    let (doc_bytes, roots) = build_attestation_doc(params);
    let err = verify_nitro_attestation(&doc_bytes, &roots, None, DEFAULT_NOW).unwrap_err();
    assert!(
        matches!(err, AttestError::UnsupportedAlg { .. }),
        "expected UnsupportedAlg, got {err:?}"
    );
}

// ── 8. duplicate PCR id in claims ────────────────────────────────────────────

#[test]
fn duplicate_pcr_id_rejected() {
    let params = BuildParams {
        duplicate_pcr: true,
        ..BuildParams::default()
    };
    let (doc_bytes, roots) = build_attestation_doc(params);
    let claims =
        verify_nitro_attestation(&doc_bytes, &roots, None, DEFAULT_NOW).expect("doc parse ok");
    // verify_pcr_set must detect the duplicate
    let err = verify_pcr_set(&claims, &[]).unwrap_err();
    assert!(
        matches!(err, AttestError::DuplicatePcrId { .. }),
        "expected DuplicatePcrId, got {err:?}"
    );
}

// ── 9. weak hash algorithm in cert (SHA-1) ───────────────────────────────────

#[test]
fn weak_hash_alg_rejected() {
    let params = BuildParams {
        use_sha1_cert: true,
        ..BuildParams::default()
    };
    let (doc_bytes, roots) = build_attestation_doc(params);
    let err = verify_nitro_attestation(&doc_bytes, &roots, None, DEFAULT_NOW).unwrap_err();
    assert!(
        matches!(err, AttestError::WeakHashAlg { .. }),
        "expected WeakHashAlg, got {err:?}"
    );
}
