//! Trust-anchor registry (indexed by COSE `kid`).
//!
//! A [`TrustAnchor`] binds a `kid` to a verified public key (Ed25519 here,
//! extensible to ECDSA in C.2+). [`TrustAnchorSet`] is a flat `Vec` — the
//! expected cardinality is small (< 32 anchors per verification context),
//! so linear scan beats `HashMap` on both throughput and constant-time
//! characteristics.
//!
//! The `Debug` impl for [`TrustAnchor`] redacts the public-key bytes to
//! keep test logs free of 32-byte hex dumps; public keys are not secret
//! but clutter audit output.

use ed25519_dalek::VerifyingKey;

use crate::alg::Alg;
use crate::error::CoseError;

#[derive(Clone)]
pub struct TrustAnchor {
    pub kid: String,
    pub alg: Alg,
    pub pk: VerifyingKey,
}

impl core::fmt::Debug for TrustAnchor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrustAnchor")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
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
    pub fn new_ed25519(kid: impl Into<String>, pk_bytes: &[u8]) -> Result<Self, CoseError> {
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
        })
    }

    /// Build from a hex-encoded public key (64 hex chars = 32 bytes).
    pub fn from_hex(kid: impl Into<String>, alg: Alg, pk_hex: &str) -> Result<Self, CoseError> {
        let bytes = hex::decode(pk_hex).map_err(|_| CoseError::HexDecode)?;
        match alg {
            Alg::Ed25519 => Self::new_ed25519(kid, &bytes),
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

    pub fn insert(&mut self, anchor: TrustAnchor) {
        self.anchors.push(anchor);
    }

    #[must_use]
    pub fn lookup(&self, kid: &str) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|a| a.kid == kid)
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

impl FromIterator<TrustAnchor> for TrustAnchorSet {
    fn from_iter<I: IntoIterator<Item = TrustAnchor>>(iter: I) -> Self {
        Self {
            anchors: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed but arbitrary public key derived from a known seed.
    /// `ed25519-dalek` test vector round-trip basepoint.
    const TEST_PK_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    #[test]
    fn from_hex_accepts_well_formed_key() {
        let a = TrustAnchor::from_hex("K_test", Alg::Ed25519, TEST_PK_HEX).unwrap();
        assert_eq!(a.kid, "K_test");
        assert_eq!(a.alg, Alg::Ed25519);
    }

    #[test]
    fn from_hex_rejects_short_input() {
        let err = TrustAnchor::from_hex("K_test", Alg::Ed25519, "deadbeef").unwrap_err();
        assert!(matches!(err, CoseError::InvalidPublicKeyEncoding));
    }

    #[test]
    fn from_hex_rejects_invalid_hex() {
        let err = TrustAnchor::from_hex("K_test", Alg::Ed25519, "zz").unwrap_err();
        assert!(matches!(err, CoseError::HexDecode));
    }

    #[test]
    fn anchor_set_lookup() {
        let a = TrustAnchor::from_hex("K_test", Alg::Ed25519, TEST_PK_HEX).unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(a);
        assert_eq!(set.len(), 1);
        assert!(set.lookup("K_test").is_some());
        assert!(set.lookup("K_absent").is_none());
    }

    #[test]
    fn debug_redacts_pk() {
        let a = TrustAnchor::from_hex("K_test", Alg::Ed25519, TEST_PK_HEX).unwrap();
        let s = format!("{a:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains(TEST_PK_HEX));
    }
}
