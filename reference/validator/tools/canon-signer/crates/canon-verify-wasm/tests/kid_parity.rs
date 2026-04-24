#![cfg(not(target_arch = "wasm32"))]
//! kid-derivation byte-parity with `canon_signer::cose::derive_kid`.
//!
//! The wasm verifier re-implements `derive_kid` locally to avoid
//! pulling signer-side dependencies into the wasm32 build graph.  If
//! the two implementations ever diverge (a different hex case, a
//! different prefix, a different slice length), verification of
//! existing facts would silently start returning "kid mismatch" in
//! step 5 of the transparency panel.  These tests pin byte equality.

use ed25519_dalek::SigningKey;

/// Cover pubkeys that exercise every hex nibble + several edge
/// patterns so the test would fail on any case/length drift.
fn pubkey_vectors() -> Vec<[u8; 32]> {
    vec![
        // All zeros — the identity-point seed Canon never uses, but
        // which would still produce a well-formed kid.
        [0u8; 32],
        // All 0xff — the opposite extreme.
        [0xffu8; 32],
        // Deterministic demo seed used in canon-signer fixtures.
        SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes(),
        // Seed [7..7] — reused inside canon-signer's own tests.
        SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes(),
        // Seed [11..11] — used by the io-layer tests.
        SigningKey::from_bytes(&[11u8; 32]).verifying_key().to_bytes(),
        // Mixed nibble pattern so a case-changing bug in hex encoding
        // would be caught.
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ],
    ]
}

#[test]
fn derive_kid_byte_identical_to_canon_signer() {
    for vk_bytes in pubkey_vectors() {
        let from_wasm_crate = canon_verify_wasm::canon::derive_kid(&vk_bytes);
        let from_signer_crate = canon_signer::cose::derive_kid(&vk_bytes);
        assert_eq!(
            from_wasm_crate, from_signer_crate,
            "kid drift for pubkey {}",
            hex::encode(vk_bytes)
        );
    }
}

#[test]
fn derive_kid_emits_documented_shape() {
    // Not parity, but a shape invariant: `canon/` + 16 lowercase hex
    // chars.  If this ever fails, the UI that slices the first 6
    // chars for the signer avatar would break.
    let kid = canon_verify_wasm::canon::derive_kid(&[0u8; 32]);
    assert!(kid.starts_with("canon/"));
    assert_eq!(kid.len(), "canon/".len() + 16);
    assert!(kid[6..].chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!kid[6..].chars().any(|c| c.is_ascii_uppercase()));
}
