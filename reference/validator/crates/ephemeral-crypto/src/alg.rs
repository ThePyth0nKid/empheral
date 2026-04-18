//! Algorithm enum mapping COSE `alg` labels to typed variants.
//!
//! Currently supports Ed25519 (COSE `alg = -8`) only. The enum is
//! `#[non_exhaustive]` to keep C.2 ECDSA additions non-breaking.

use crate::error::CoseError;

/// COSE algorithm label for Ed25519, per RFC 9053 §2.2 (IANA registry
/// entry `EdDSA = -8`). RFC 9053bis additionally defines `Ed25519 = -19`,
/// but the existing conformance vectors and
/// `ephemeral-core::suites::tariff::COSE_ALG_EDDSA` pin `-8`; we match
/// that for consistency. A future extension can widen acceptance to both.
pub const COSE_ALG_EDDSA: i64 = -8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Alg {
    Ed25519,
}

impl Alg {
    /// Map a COSE `alg` label (i64 from protected header) to a typed [`Alg`].
    ///
    /// Returns [`CoseError::UnsupportedAlg`] for any label this build does
    /// not accept. Labels not yet in the IANA registry (e.g. PrivateUse)
    /// are always rejected — the validator operates against a strict
    /// allowlist.
    pub fn from_cose_label(label: i64) -> Result<Self, CoseError> {
        match label {
            COSE_ALG_EDDSA => Ok(Self::Ed25519),
            other => Err(CoseError::UnsupportedAlg { alg: other }),
        }
    }

    /// Inverse of [`Self::from_cose_label`].
    pub fn as_cose_label(self) -> i64 {
        match self {
            Self::Ed25519 => COSE_ALG_EDDSA,
        }
    }

    /// Kebab-case wire name, used in vector JSON (`"alg": "ed25519"`).
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }

    /// Parse wire name from vector JSON.
    pub fn from_wire_str(s: &str) -> Result<Self, CoseError> {
        match s {
            "ed25519" | "Ed25519" => Ok(Self::Ed25519),
            _ => Err(CoseError::UnsupportedAlg { alg: 0 }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_roundtrips_via_cose_label() {
        let alg = Alg::from_cose_label(COSE_ALG_EDDSA).unwrap();
        assert_eq!(alg.as_cose_label(), COSE_ALG_EDDSA);
    }

    #[test]
    fn unsupported_alg_rejected() {
        match Alg::from_cose_label(-257) {
            Err(CoseError::UnsupportedAlg { alg }) => assert_eq!(alg, -257),
            other => panic!("expected UnsupportedAlg, got {other:?}"),
        }
    }

    #[test]
    fn wire_string_roundtrip() {
        assert_eq!(Alg::Ed25519.as_wire_str(), "ed25519");
        assert_eq!(Alg::from_wire_str("ed25519").unwrap(), Alg::Ed25519);
        assert_eq!(Alg::from_wire_str("Ed25519").unwrap(), Alg::Ed25519);
        assert!(Alg::from_wire_str("rsa").is_err());
    }
}
