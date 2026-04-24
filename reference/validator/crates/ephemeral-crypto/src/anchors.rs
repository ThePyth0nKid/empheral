//! Trust-anchor registry (indexed by COSE `kid` and role).
//!
//! A [`TrustAnchor`] binds a `kid` to a verified public key (Ed25519 here,
//! extensible to ECDSA in C.2+) and to an [`AnchorRole`] that declares
//! which signing context the anchor is authorised for. [`TrustAnchorSet`]
//! is a flat `Vec` — the expected cardinality is small (< 32 anchors per
//! verification context), so linear scan beats `HashMap` on both
//! throughput and constant-time characteristics.
//!
//! ## Role discrimination
//!
//! Verification routines MUST use [`TrustAnchorSet::lookup_with_role`].
//! An anchor authorised as an [`AnchorRole::TariffSigner`] will not
//! resolve when the verifier is checking a classifier-signer envelope,
//! even if the `kid` happens to collide — role confusion is closed at
//! lookup time rather than relying on per-suite anchor-set curation to
//! keep roles apart. A role mismatch surfaces as [`CoseError::UnknownKid`]
//! so role assignments are not leaked to an attacker probing the set.
//!
//! ## Debug redaction
//!
//! The `Debug` impl for [`TrustAnchor`] redacts the public-key bytes to
//! keep test logs free of 32-byte hex dumps; public keys are not secret
//! but clutter audit output.

use ed25519_dalek::VerifyingKey;

use crate::alg::Alg;
use crate::error::CoseError;

/// Role discrimination on trust anchors.
///
/// Prevents role confusion: a tariff-signer key MUST NOT be accepted
/// when verifying a classifier-signature envelope even if the `kid`
/// matches.  The verification pipeline (via
/// [`TrustAnchorSet::lookup_with_role`]) enforces role equality in
/// addition to kid lookup; a mismatch surfaces as
/// [`CoseError::UnknownKid`] so that role assignments are not leaked
/// to an attacker probing the anchor set.
///
/// Marked `#[non_exhaustive]` so future roles (audit-pattern signers in
/// C.4, for instance) can be added without breaking exhaustive matches
/// in downstream crates.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AnchorRole {
    /// Authorised to sign Tariff envelopes (AAD = `b"tariff"`).
    TariffSigner,
    /// Authorised to sign delegation-link and mandate envelopes
    /// (AAD ∈ { `b"delegation-link"`, `b"mandate"` }).
    DelegationSigner,
    /// Authorised to sign classifier-WASM metadata envelopes
    /// (AAD = `b"ephemeral/classifier/v1"`, Phase C.3-C).
    ClassifierSigner,
    /// Authorised to sign `AnomalyPatternLibrary` envelopes
    /// (AAD = `b"ephemeral/anomaly-library/v1"`, Phase C.4).
    /// Distinct terminal role under `K_cust_ops` (§3.5.1 / §7.2 /
    /// §7.3.0): a `TariffSigner`- or `ClassifierSigner`-authorised key
    /// MUST NOT validate an anomaly library even when the `kid`
    /// collides.  Resolves B-2.
    AnomalyLibrarySigner,
    /// Authorised to sign Canon fact envelopes
    /// (AAD = `b"canon/fact/v1"`).  Canon is an external project that
    /// re-uses EPHEMERAL's COSE_Sign1 + Ed25519 primitives via the
    /// `tools/canon-signer` CLI sidecar; the dedicated role keeps a
    /// Canon-signing key from being accepted for any EPHEMERAL
    /// verification path even under kid collision.
    CanonSigner,
}

impl AnchorRole {
    /// Wire-format string used in vector JSON / conformance output.
    /// Stable across phases — adding a variant here MUST pick a name
    /// that is never reused for another role in a later phase.
    #[must_use]
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::TariffSigner => "tariff-signer",
            Self::DelegationSigner => "delegation-signer",
            Self::ClassifierSigner => "classifier-signer",
            Self::AnomalyLibrarySigner => "anomaly-library-signer",
            Self::CanonSigner => "canon-signer",
        }
    }

    /// Parse the wire-format role string (case-insensitive).
    ///
    /// Returns [`CoseError::InvalidAnchorRole`] on any unknown token.
    /// The variant carries the rejected input truncated to at most
    /// 64 bytes (char-boundary safe) so log output stays bounded even
    /// for adversarial input from vector JSON.
    ///
    /// `#[must_use]` — accidentally dropping the `Result` silently
    /// accepts every role, re-opening role confusion at the vector
    /// parse seam.
    #[must_use = "dropping the Result silently accepts every role label"]
    pub fn from_wire_str(s: &str) -> Result<Self, CoseError> {
        if s.eq_ignore_ascii_case("tariff-signer") {
            Ok(Self::TariffSigner)
        } else if s.eq_ignore_ascii_case("delegation-signer") {
            Ok(Self::DelegationSigner)
        } else if s.eq_ignore_ascii_case("classifier-signer") {
            Ok(Self::ClassifierSigner)
        } else if s.eq_ignore_ascii_case("anomaly-library-signer") {
            Ok(Self::AnomalyLibrarySigner)
        } else if s.eq_ignore_ascii_case("canon-signer") {
            Ok(Self::CanonSigner)
        } else {
            // Char-boundary-safe truncation to ≤ 64 bytes so an
            // adversarial vector supplying a megabyte role string
            // cannot bloat the error surface.
            let mut trimmed = String::new();
            for c in s.chars() {
                if trimmed.len() + c.len_utf8() > 64 {
                    break;
                }
                trimmed.push(c);
            }
            Err(CoseError::InvalidAnchorRole { role: trimmed })
        }
    }
}

#[derive(Clone)]
pub struct TrustAnchor {
    pub kid: String,
    pub alg: Alg,
    pub pk: VerifyingKey,
    pub role: AnchorRole,
}

impl core::fmt::Debug for TrustAnchor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrustAnchor")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("role", &self.role)
            .field("pk", &"<redacted>")
            .finish()
    }
}

impl TrustAnchor {
    /// Build an Ed25519 trust anchor from a raw 32-byte public key.
    ///
    /// Enforces RFC 8032 strict-mode acceptance:
    /// 1. Byte length must be exactly 32.
    /// 2. The compressed Edwards point must decompress to a valid curve
    ///    point (`VerifyingKey::from_bytes`).
    /// 3. The point must not be in the set of small-order / torsion keys
    ///    flagged by [`VerifyingKey::is_weak`].
    pub fn new_ed25519(
        kid: impl Into<String>,
        pk_bytes: &[u8],
        role: AnchorRole,
    ) -> Result<Self, CoseError> {
        let arr: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| CoseError::InvalidPublicKeyEncoding)?;
        let pk = VerifyingKey::from_bytes(&arr)
            .map_err(|_| CoseError::InvalidPublicKeyEncoding)?;
        if pk.is_weak() {
            return Err(CoseError::WeakPublicKey);
        }
        Ok(Self {
            kid: kid.into(),
            alg: Alg::Ed25519,
            pk,
            role,
        })
    }

    /// Build from a hex-encoded public key (64 hex chars = 32 bytes).
    pub fn from_hex(
        kid: impl Into<String>,
        alg: Alg,
        pk_hex: &str,
        role: AnchorRole,
    ) -> Result<Self, CoseError> {
        let bytes = hex::decode(pk_hex).map_err(|_| CoseError::HexDecode)?;
        match alg {
            Alg::Ed25519 => Self::new_ed25519(kid, &bytes, role),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrustAnchorSet {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// Register a trust anchor. Rejects duplicate `kid` at insertion time
    /// so that [`TrustAnchorSet::lookup_with_role`] has exactly one
    /// answer per kid.
    ///
    /// Duplicate detection is kid-only, not `(kid, role)`-pair: two
    /// anchors sharing a kid are always ambiguous regardless of role.
    /// Allowing the same kid under two different roles would let an
    /// attacker redirect a verification path by flipping the role marker.
    ///
    /// Rationale: without this check a vector author (or an attacker who
    /// controls anchor-list assembly upstream) could prepend a fraudulent
    /// anchor under an authorized kid and have the `iter().find()` lookup
    /// return the attacker's public key before the legitimate one.
    pub fn insert(&mut self, anchor: TrustAnchor) -> Result<(), CoseError> {
        if self.anchors.iter().any(|a| a.kid == anchor.kid) {
            return Err(CoseError::DuplicateKid { kid: anchor.kid });
        }
        self.anchors.push(anchor);
        Ok(())
    }

    /// Role-aware lookup: returns an anchor only when both `kid` and
    /// `role` match.  A kid-matching but role-mismatched anchor causes
    /// this method to return `None`, so the caller's error path surfaces
    /// [`CoseError::UnknownKid`] and does not reveal role assignment
    /// information to an attacker probing the anchor set.
    ///
    /// This is the only supported lookup variant: a kid-only lookup
    /// would bypass the role check at the exact seam where role
    /// confusion attacks enter, so the API deliberately does not offer
    /// one.
    #[must_use]
    pub fn lookup_with_role(&self, kid: &str, role: AnchorRole) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|a| a.kid == kid && a.role == role)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

// Note: no `FromIterator` impl — collecting bypasses the duplicate-kid
// check in `insert`, re-opening the shadow-key bypass that the check
// exists to close. Callers must build via `insert()?` so the error is
// propagated rather than silently swallowed.

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed but arbitrary public key derived from a known seed.
    /// `ed25519-dalek` test vector round-trip basepoint.
    const TEST_PK_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    /// A different but well-formed Ed25519 public key — derived from a
    /// second canonical test vector so the duplicate-kid test compares
    /// against non-trivial bytes (not just the same key twice).
    const OTHER_PK_HEX: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    #[test]
    fn from_hex_accepts_well_formed_key() {
        let a = TrustAnchor::from_hex(
            "K_test",
            Alg::Ed25519,
            TEST_PK_HEX,
            AnchorRole::TariffSigner,
        )
        .unwrap();
        assert_eq!(a.kid, "K_test");
        assert_eq!(a.alg, Alg::Ed25519);
        assert_eq!(a.role, AnchorRole::TariffSigner);
    }

    #[test]
    fn from_hex_rejects_short_input() {
        let err = TrustAnchor::from_hex(
            "K_test",
            Alg::Ed25519,
            "deadbeef",
            AnchorRole::TariffSigner,
        )
        .unwrap_err();
        assert!(matches!(err, CoseError::InvalidPublicKeyEncoding));
    }

    #[test]
    fn from_hex_rejects_invalid_hex() {
        let err = TrustAnchor::from_hex(
            "K_test",
            Alg::Ed25519,
            "zz",
            AnchorRole::TariffSigner,
        )
        .unwrap_err();
        assert!(matches!(err, CoseError::HexDecode));
    }

    #[test]
    fn anchor_set_lookup_with_matching_role() {
        let a = TrustAnchor::from_hex(
            "K_test",
            Alg::Ed25519,
            TEST_PK_HEX,
            AnchorRole::TariffSigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(a).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set
            .lookup_with_role("K_test", AnchorRole::TariffSigner)
            .is_some());
        assert!(set
            .lookup_with_role("K_absent", AnchorRole::TariffSigner)
            .is_none());
    }

    #[test]
    fn lookup_with_role_rejects_role_mismatch() {
        // An anchor registered as a TariffSigner must NOT resolve when
        // the caller requests a DelegationSigner — otherwise a
        // role-confused verification would succeed with the wrong
        // authority.
        let a = TrustAnchor::from_hex(
            "K_shared_kid",
            Alg::Ed25519,
            TEST_PK_HEX,
            AnchorRole::TariffSigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(a).unwrap();
        assert!(set
            .lookup_with_role("K_shared_kid", AnchorRole::TariffSigner)
            .is_some());
        assert!(set
            .lookup_with_role("K_shared_kid", AnchorRole::DelegationSigner)
            .is_none());
        assert!(set
            .lookup_with_role("K_shared_kid", AnchorRole::ClassifierSigner)
            .is_none());
        assert!(set
            .lookup_with_role("K_shared_kid", AnchorRole::AnomalyLibrarySigner)
            .is_none());
    }

    #[test]
    fn insert_rejects_duplicate_kid_across_roles() {
        // Duplicate detection is kid-scoped, not `(kid, role)`-scoped —
        // re-registering the same kid under a different role would
        // otherwise let an attacker shadow the legitimate anchor.
        let first = TrustAnchor::from_hex(
            "K_dup",
            Alg::Ed25519,
            TEST_PK_HEX,
            AnchorRole::TariffSigner,
        )
        .unwrap();
        let second = TrustAnchor::from_hex(
            "K_dup",
            Alg::Ed25519,
            OTHER_PK_HEX,
            AnchorRole::DelegationSigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(first).unwrap();
        let err = set.insert(second).unwrap_err();
        assert!(matches!(err, CoseError::DuplicateKid { kid } if kid == "K_dup"));
        // Original anchor is still the only one — shadowing prevented.
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn debug_redacts_pk_and_shows_role() {
        let a = TrustAnchor::from_hex(
            "K_test",
            Alg::Ed25519,
            TEST_PK_HEX,
            AnchorRole::ClassifierSigner,
        )
        .unwrap();
        let s = format!("{a:?}");
        assert!(s.contains("<redacted>"));
        assert!(s.contains("ClassifierSigner"));
        assert!(!s.contains(TEST_PK_HEX));
    }

    #[test]
    fn role_wire_str_roundtrip() {
        for role in [
            AnchorRole::TariffSigner,
            AnchorRole::DelegationSigner,
            AnchorRole::ClassifierSigner,
            AnchorRole::AnomalyLibrarySigner,
            AnchorRole::CanonSigner,
        ] {
            let s = role.as_wire_str();
            let parsed = AnchorRole::from_wire_str(s).unwrap();
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn role_wire_str_accepts_case_variants() {
        assert_eq!(
            AnchorRole::from_wire_str("TARIFF-SIGNER").unwrap(),
            AnchorRole::TariffSigner,
        );
        assert_eq!(
            AnchorRole::from_wire_str("Delegation-Signer").unwrap(),
            AnchorRole::DelegationSigner,
        );
        assert_eq!(
            AnchorRole::from_wire_str("classifier-SIGNER").unwrap(),
            AnchorRole::ClassifierSigner,
        );
        assert_eq!(
            AnchorRole::from_wire_str("Anomaly-Library-Signer").unwrap(),
            AnchorRole::AnomalyLibrarySigner,
        );
    }

    #[test]
    fn role_wire_str_rejects_unknown() {
        let err = AnchorRole::from_wire_str("not-a-role").unwrap_err();
        assert!(matches!(err, CoseError::InvalidAnchorRole { role } if role == "not-a-role"));
    }

    #[test]
    fn role_wire_str_truncates_oversize_input() {
        // Adversarial role string of 10_000 bytes — the error must
        // carry at most 64 bytes so log surfaces do not bloat.
        let huge = "x".repeat(10_000);
        let err = AnchorRole::from_wire_str(&huge).unwrap_err();
        match err {
            CoseError::InvalidAnchorRole { role } => {
                assert!(role.len() <= 64);
                assert!(role.chars().all(|c| c == 'x'));
            }
            other => panic!("expected InvalidAnchorRole, got {other:?}"),
        }
    }

    #[test]
    fn role_wire_str_truncation_is_char_boundary_safe() {
        // Every codepoint is 2 bytes; the 32nd char lands exactly at
        // 64 bytes, the 33rd would overflow — the loop must stop at 32.
        let input: String = "ä".repeat(40);
        let err = AnchorRole::from_wire_str(&input).unwrap_err();
        match err {
            CoseError::InvalidAnchorRole { role } => {
                assert!(role.len() <= 64);
                // Result is still valid UTF-8 (implied by String type).
                assert!(role.chars().all(|c| c == 'ä'));
            }
            other => panic!("expected InvalidAnchorRole, got {other:?}"),
        }
    }
}
