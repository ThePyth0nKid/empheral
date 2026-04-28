//! PCR set verification for Nitro attestation claims.
//!
//! [`verify_pcr_set`] is the public entry point. It compares a caller-supplied
//! expected set against the PCRs in [`NitroClaims`] using constant-time
//! comparison (`subtle::ConstantTimeEq`) to avoid timing side-channels on the
//! measured hash values.

use subtle::ConstantTimeEq;

use crate::error::AttestError;
use crate::nitro::NitroClaims;
use crate::size_guard::MAX_PCR_COUNT;

/// Verify that all PCR entries in `expected` match the corresponding entries
/// in `claims.pcrs`.
///
/// # Checks performed
///
/// 1. No duplicate PCR indices in `claims.pcrs` → [`AttestError::DuplicatePcrId`].
/// 2. All expected indices are in range 0..=23 → [`AttestError::PcrIndexOutOfRange`].
/// 3. Each expected `(id, hash)` is present in claims and matches via
///    constant-time compare → [`AttestError::PcrMismatch`].
///
/// Passing an empty `expected` slice succeeds if `claims.pcrs` has no
/// duplicates and all indices are in range.
pub fn verify_pcr_set(claims: &NitroClaims, expected: &[(u8, &[u8])]) -> Result<(), AttestError> {
    // ── 1. Reject duplicate PCR ids in claims ─────────────────────────────────
    check_no_duplicates(&claims.pcrs)?;

    // ── 2. Validate expected indices ──────────────────────────────────────────
    for (id, _) in expected {
        if *id as usize >= MAX_PCR_COUNT {
            return Err(AttestError::PcrIndexOutOfRange { id: *id });
        }
    }

    // ── 3. Constant-time compare for each expected entry ──────────────────────
    for (id, expected_hash) in expected {
        let actual = find_pcr(&claims.pcrs, *id);
        match actual {
            None => {
                // PCR id not present in claims — treat as mismatch
                let expected_arr = hash_to_32(expected_hash);
                return Err(AttestError::PcrMismatch {
                    id: *id,
                    expected_hash: expected_arr,
                    actual_hash: [0u8; 32],
                });
            }
            Some(actual_hash) => {
                if expected_hash.ct_eq(actual_hash).unwrap_u8() == 0 {
                    let expected_arr = hash_to_32(expected_hash);
                    let actual_arr = hash_to_32(actual_hash);
                    return Err(AttestError::PcrMismatch {
                        id: *id,
                        expected_hash: expected_arr,
                        actual_hash: actual_arr,
                    });
                }
            }
        }
    }

    Ok(())
}

/// Check that no two entries in `pcrs` share the same index.
fn check_no_duplicates(pcrs: &[(u8, Vec<u8>)]) -> Result<(), AttestError> {
    for i in 0..pcrs.len() {
        for j in (i + 1)..pcrs.len() {
            if pcrs[i].0 == pcrs[j].0 {
                return Err(AttestError::DuplicatePcrId { id: pcrs[i].0 });
            }
        }
    }
    Ok(())
}

/// Find the hash for `id` in the PCR list (linear scan — list is small).
fn find_pcr(pcrs: &[(u8, Vec<u8>)], id: u8) -> Option<&[u8]> {
    pcrs.iter()
        .find(|(pcr_id, _)| *pcr_id == id)
        .map(|(_, hash)| hash.as_slice())
}

/// Trim or zero-pad a hash slice to exactly 32 bytes for the error struct.
fn hash_to_32(bytes: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = bytes.len().min(32);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nitro::NitroClaims;

    fn make_claims(pcrs: Vec<(u8, Vec<u8>)>) -> NitroClaims {
        NitroClaims {
            module_id: "test".into(),
            digest: "SHA384".into(),
            timestamp: 0,
            pcrs,
            certificate: vec![],
            cabundle: vec![],
            public_key: None,
            user_data: None,
            nonce: None,
        }
    }

    #[test]
    fn exact_match_passes() {
        let hash = vec![0xAAu8; 48];
        let claims = make_claims(vec![(0, hash.clone()), (1, hash.clone())]);
        verify_pcr_set(&claims, &[(0, &hash), (1, &hash)]).unwrap();
    }

    #[test]
    fn empty_expected_passes() {
        let claims = make_claims(vec![(0, vec![0u8; 48])]);
        verify_pcr_set(&claims, &[]).unwrap();
    }

    #[test]
    fn mismatch_detected() {
        let real_hash = vec![0xAAu8; 48];
        let wrong_hash = vec![0xBBu8; 48];
        let claims = make_claims(vec![(0, real_hash)]);
        let err = verify_pcr_set(&claims, &[(0, &wrong_hash)]).unwrap_err();
        assert!(matches!(err, AttestError::PcrMismatch { id: 0, .. }));
    }

    #[test]
    fn duplicate_pcr_detected() {
        let hash = vec![0u8; 48];
        let claims = make_claims(vec![(0, hash.clone()), (0, hash)]);
        let err = verify_pcr_set(&claims, &[]).unwrap_err();
        assert!(matches!(err, AttestError::DuplicatePcrId { id: 0 }));
    }

    #[test]
    fn out_of_range_id_rejected() {
        let claims = make_claims(vec![]);
        let hash = [0u8; 32];
        let err = verify_pcr_set(&claims, &[(24, hash.as_slice())]).unwrap_err();
        assert!(matches!(err, AttestError::PcrIndexOutOfRange { id: 24 }));
    }
}
