#![cfg(not(target_arch = "wasm32"))]
//! AAD byte-parity with the real `canon-signer` crate.
//!
//! The external AAD is a wire-format commitment: every COSE_Sign1
//! signature Canon has ever produced binds these exact bytes.  The
//! wasm verifier stores its own copy (see `src/canon.rs` for the
//! rationale) so a single fat-finger rename in either crate would
//! silently break verification for every historical fact.  This test
//! is the tripwire.

#[test]
fn external_aad_is_byte_identical_to_canon_signer() {
    assert_eq!(
        canon_verify_wasm::canon::COSE_EXTERNAL_AAD,
        canon_signer::COSE_EXTERNAL_AAD,
        "AAD drift: the wasm verifier and canon-signer must bind the \
         exact same external AAD bytes.  Changing either side breaks \
         verification of every previously signed Canon fact."
    );
}

#[test]
fn kid_prefix_is_byte_identical_to_canon_signer() {
    assert_eq!(
        canon_verify_wasm::canon::CANON_KID_PREFIX,
        canon_signer::CANON_KID_PREFIX,
        "CANON_KID_PREFIX drift between verifier and signer"
    );
}

#[test]
fn external_aad_matches_documented_value() {
    // Defence-in-depth: catches the case where someone flips both
    // constants to the same *wrong* value in a single refactor.
    assert_eq!(canon_verify_wasm::canon::COSE_EXTERNAL_AAD, b"canon/fact/v1");
    assert_eq!(canon_verify_wasm::canon::CANON_KID_PREFIX, "canon/");
}
