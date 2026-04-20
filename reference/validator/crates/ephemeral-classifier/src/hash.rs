//! SHA-256 verification of WASM binaries against a Tariff-pinned digest
//! (spec §4.1: *"Tariff pins its hash; only this exact WASM runs"*).
//!
//! Pinned hashes in EPHEMERAL conformance artifacts are canonical
//! lowercase-hex — uppercase input is rejected to prevent accidental
//! case-inconsistent encoding from drifting into signed Tariffs.

use sha2::{Digest, Sha256};

use crate::errors::ClassifierLoadError;

/// Verify that `SHA-256(wasm_bytes)` equals the digest encoded by
/// `expected_hash_hex` (64 lowercase-hex characters).
///
/// # Errors
/// - [`ClassifierLoadError::InvalidHashHex`] when the expected-hash string
///   is not exactly 64 characters or contains any character outside
///   `[0-9a-f]`.
/// - [`ClassifierLoadError::HashMismatch`] when the computed SHA-256
///   digest differs from the expected value.
pub fn verify_classifier_hash(
    wasm_bytes: &[u8],
    expected_hash_hex: &str,
) -> Result<(), ClassifierLoadError> {
    // Manual lowercase-hex validation.  `hex::decode_to_slice` alone
    // would accept mixed-case input (the `hex` crate treats `A`–`F` as
    // valid hex by default); spec §4.1 canonicality demands lowercase
    // only to prevent case-inconsistent digests from drifting into
    // signed Tariffs.  The length check is technically subsumed by
    // `decode_to_slice`'s 32-byte buffer constraint, but keeping it
    // explicit yields a sharp "not 64 chars" diagnostic independent
    // of the hex crate's internal error taxonomy.
    if expected_hash_hex.len() != 64
        || !expected_hash_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ClassifierLoadError::InvalidHashHex);
    }

    let mut expected = [0u8; 32];
    hex::decode_to_slice(expected_hash_hex, &mut expected)
        .map_err(|_| ClassifierLoadError::InvalidHashHex)?;

    // Non-constant-time equality is deliberate.  Attacker model here:
    // a static Tariff signer, not a remote timing-oracle adversary.
    // The comparison runs once per classifier load, over 32 bytes of
    // publicly-derived data (both digests are non-secret), with no
    // observable per-byte timing feedback channel in any deployment
    // path.  Swapping this for `subtle::ConstantTimeEq` would add a
    // dependency and obscure the fast path without defending against
    // any real threat.
    let actual: [u8; 32] = Sha256::digest(wasm_bytes).into();

    if actual == expected {
        Ok(())
    } else {
        Err(ClassifierLoadError::HashMismatch { expected, actual })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn accepts_matching_hash() {
        let wasm = b"pretend-wasm-bytes";
        let digest = sha256_hex(wasm);
        assert!(verify_classifier_hash(wasm, &digest).is_ok());
    }

    #[test]
    fn rejects_mismatched_hash() {
        let wasm = b"pretend-wasm-bytes";
        let wrong = sha256_hex(b"other-bytes-entirely");
        let err = verify_classifier_hash(wasm, &wrong).unwrap_err();
        let ClassifierLoadError::HashMismatch { expected, actual } = err else {
            panic!("expected HashMismatch, got {err:?}");
        };
        assert_ne!(expected, actual);
    }

    #[test]
    fn rejects_short_hex() {
        assert!(matches!(
            verify_classifier_hash(b"bytes", "deadbeef"),
            Err(ClassifierLoadError::InvalidHashHex)
        ));
    }

    #[test]
    fn rejects_long_hex() {
        let long = "0".repeat(65);
        assert!(matches!(
            verify_classifier_hash(b"bytes", &long),
            Err(ClassifierLoadError::InvalidHashHex)
        ));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let wasm = b"bytes";
        let digest = sha256_hex(wasm).to_uppercase();
        assert!(matches!(
            verify_classifier_hash(wasm, &digest),
            Err(ClassifierLoadError::InvalidHashHex)
        ));
    }

    #[test]
    fn rejects_mixed_case_hex() {
        let wasm = b"bytes";
        let digest = sha256_hex(wasm);
        // Uppercase the first alphabetic hex character (a-f).  Picking the
        // first character unconditionally is unsound because digest positions
        // holding 0-9 have no uppercase form.
        let letter_pos = digest
            .char_indices()
            .find_map(|(i, c)| c.is_ascii_alphabetic().then_some(i))
            .expect("sha256 hex of `bytes` contains at least one a-f");
        let mut mixed = digest.clone();
        mixed.replace_range(
            letter_pos..=letter_pos,
            &digest[letter_pos..=letter_pos].to_uppercase(),
        );
        assert_ne!(digest, mixed);
        assert!(matches!(
            verify_classifier_hash(wasm, &mixed),
            Err(ClassifierLoadError::InvalidHashHex)
        ));
    }

    #[test]
    fn rejects_non_hex_characters() {
        let not_hex = "g".repeat(64);
        assert!(matches!(
            verify_classifier_hash(b"bytes", &not_hex),
            Err(ClassifierLoadError::InvalidHashHex)
        ));
    }

    #[test]
    fn rejects_empty_hex() {
        assert!(matches!(
            verify_classifier_hash(b"bytes", ""),
            Err(ClassifierLoadError::InvalidHashHex)
        ));
    }

    #[test]
    fn accepts_known_test_vector() {
        // RFC 6234 / NIST empty-string test vector:
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(verify_classifier_hash(b"", digest).is_ok());
    }

    proptest! {
        #[test]
        fn prop_accepts_any_sha256_roundtrip(bytes: Vec<u8>) {
            let digest = sha256_hex(&bytes);
            prop_assert!(verify_classifier_hash(&bytes, &digest).is_ok());
        }

        #[test]
        fn prop_rejects_when_bytes_differ(
            bytes_a: Vec<u8>,
            bytes_b: Vec<u8>,
        ) {
            prop_assume!(bytes_a != bytes_b);
            let digest_b = sha256_hex(&bytes_b);
            let err = verify_classifier_hash(&bytes_a, &digest_b)
                .expect_err("mismatched inputs must fail");
            // `prop_assert!` treats its expression as a format string,
            // so the `{ .. }` pattern inside `matches!` would be parsed
            // as a format placeholder.  Bind the match to a bool first.
            let is_mismatch = matches!(err, ClassifierLoadError::HashMismatch { .. });
            prop_assert!(is_mismatch);
        }
    }
}
