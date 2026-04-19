//! Trusted-root registry for Nitro attestation CA validation.
//!
//! [`NitroRootSet`] holds DER-encoded root certificates indexed by their
//! SHA-256 fingerprint. The `insert_trusted_der` method rejects unknown
//! fingerprints (not in [`ALLOWED_FINGERPRINTS`]) and duplicate entries.
//!
//! The Debug impl redacts the raw DER bytes to keep test output readable;
//! the fingerprint (32 bytes hex) is shown instead.
//!
//! # Design note
//!
//! `FromIterator` is intentionally absent — collecting would bypass the
//! duplicate-fingerprint check, re-opening the shadow-root bypass that the
//! check exists to close. Callers must build via `insert_trusted_der()?`.
//!
//! # Feature: `test-fixtures`
//!
//! When compiled with `--features test-fixtures`, the additional method
//! [`NitroRootSet::insert_trusted_der_for_test`] is available.  It bypasses
//! the fingerprint allowlist so test fixtures can register a locally-generated
//! CA root.  This code path is **completely absent** from default (production)
//! builds — the compiler never emits it.

use sha2::{Digest, Sha256};

use crate::error::AttestError;
use crate::AWS_NITRO_ROOT_FINGERPRINT;

/// Fingerprints (SHA-256 of DER) of certificates allowed into [`NitroRootSet`]
/// via the production [`NitroRootSet::insert_trusted_der`] path.
///
/// Only the real AWS Nitro Enclave G1 root is allowed in production.
const ALLOWED_FINGERPRINTS: &[[u8; 32]] = &[AWS_NITRO_ROOT_FINGERPRINT];

/// A DER root certificate together with its SHA-256 fingerprint.
#[derive(Clone)]
struct RootEntry {
    fingerprint: [u8; 32],
    der: Vec<u8>,
}

impl core::fmt::Debug for RootEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RootEntry")
            .field("fingerprint", &hex::encode(self.fingerprint))
            .field("der", &"<redacted>")
            .finish()
    }
}

/// Registry of trusted Nitro root certificates.
///
/// Build via [`NitroRootSet::new`] + [`NitroRootSet::insert_trusted_der`].
/// No `FromIterator` impl — see module-level docs.
#[derive(Debug, Clone, Default)]
pub struct NitroRootSet {
    roots: Vec<RootEntry>,
}

impl NitroRootSet {
    /// Create an empty root set.
    #[must_use]
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Insert a DER-encoded root certificate.
    ///
    /// Rejects if:
    /// - the fingerprint is not in the crate-private `ALLOWED_FINGERPRINTS`
    ///   slice (production allowlist — only the real AWS G1 root passes), OR
    /// - a certificate with the same fingerprint is already registered.
    pub fn insert_trusted_der(&mut self, root_der: &[u8]) -> Result<(), AttestError> {
        let fingerprint = sha256_fingerprint(root_der);

        if !ALLOWED_FINGERPRINTS.contains(&fingerprint) {
            return Err(AttestError::UntrustedRoot { fingerprint });
        }

        if self.roots.iter().any(|r| r.fingerprint == fingerprint) {
            // Duplicate fingerprint — silently succeed (idempotent insert).
            return Ok(());
        }

        self.roots.push(RootEntry {
            fingerprint,
            der: root_der.to_vec(),
        });
        Ok(())
    }

    /// Register a root without fingerprint pinning.
    ///
    /// **ONLY compiled when the `test-fixtures` feature is active.**  Production
    /// builds literally do not contain this code path, closing the shadow-root
    /// bypass at compile time.
    ///
    /// Use this in test fixtures that generate a local CA root whose fingerprint
    /// is not in the production `ALLOWED_FINGERPRINTS` allowlist.
    #[cfg(feature = "test-fixtures")]
    pub fn insert_trusted_der_for_test(&mut self, root_der: &[u8]) -> Result<(), AttestError> {
        let fingerprint = sha256_fingerprint(root_der);
        if self.roots.iter().any(|r| r.fingerprint == fingerprint) {
            return Ok(());
        }
        self.roots.push(RootEntry {
            fingerprint,
            der: root_der.to_vec(),
        });
        Ok(())
    }

    /// Look up a root by its SHA-256 fingerprint.
    ///
    /// Returns the DER bytes if found.
    pub(crate) fn find_by_fingerprint(&self, fp: &[u8; 32]) -> Option<&[u8]> {
        self.roots
            .iter()
            .find(|r| &r.fingerprint == fp)
            .map(|r| r.der.as_slice())
    }

    /// Number of roots registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Returns `true` when no roots have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// SHA-256 fingerprint of raw bytes.
pub(crate) fn sha256_fingerprint(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY_DER: &[u8] = b"fake-der-bytes-for-unit-test";

    // ── structural tests (no fingerprint requirement) ─────────────────────────

    #[test]
    fn new_root_set_is_empty() {
        let s = NitroRootSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn find_by_fingerprint_none_for_absent_cert() {
        let s = NitroRootSet::new();
        let fp = sha256_fingerprint(DUMMY_DER);
        assert!(s.find_by_fingerprint(&fp).is_none());
    }

    // ── production path: untrusted root is rejected ───────────────────────────

    #[test]
    fn insert_trusted_der_rejects_untrusted_root() {
        let mut s = NitroRootSet::new();
        let err = s
            .insert_trusted_der(DUMMY_DER)
            .expect_err("unknown fingerprint must be rejected");
        assert!(
            matches!(err, AttestError::UntrustedRoot { .. }),
            "expected UntrustedRoot, got {err:?}"
        );
    }

    #[test]
    fn insert_trusted_der_rejects_second_unknown_root() {
        let mut s = NitroRootSet::new();
        let other_der: &[u8] = b"another-random-cert-bytes";
        assert!(matches!(
            s.insert_trusted_der(other_der),
            Err(AttestError::UntrustedRoot { .. })
        ));
        // Set must still be empty after failed inserts.
        assert!(s.is_empty());
    }

    // ── test-fixtures escape hatch ────────────────────────────────────────────

    #[cfg(feature = "test-fixtures")]
    #[test]
    fn insert_trusted_der_for_test_accepts_any_der() {
        let mut s = NitroRootSet::new();
        s.insert_trusted_der_for_test(DUMMY_DER)
            .expect("test-fixtures insert must succeed");
        assert_eq!(s.len(), 1);
        let fp = sha256_fingerprint(DUMMY_DER);
        assert!(s.find_by_fingerprint(&fp).is_some());
    }

    #[cfg(feature = "test-fixtures")]
    #[test]
    fn test_duplicate_insert_is_idempotent() {
        let mut s = NitroRootSet::new();
        s.insert_trusted_der_for_test(DUMMY_DER)
            .expect("first insert");
        s.insert_trusted_der_for_test(DUMMY_DER)
            .expect("second insert is ok");
        assert_eq!(s.len(), 1);
    }

    #[cfg(feature = "test-fixtures")]
    #[test]
    fn debug_redacts_der() {
        let mut s = NitroRootSet::new();
        s.insert_trusted_der_for_test(DUMMY_DER).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("<redacted>"));
    }
}
