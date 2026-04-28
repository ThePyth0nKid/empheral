//! Local CA chain generation for test fixtures.
//!
//! Builds a 3-cert chain: root (self-signed) → intermediate (signed by root)
//! → leaf (signed by intermediate).  This mirrors real AWS Nitro chains and
//! exercises the chain-walk more realistically than a 2-cert chain.
//!
//! All keys are derived deterministically from fixed 48-byte seeds so output
//! is byte-for-byte identical across machines.

use p384::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
use p384::pkcs8::EncodePublicKey;

use crate::der::{
    der_bit_string, der_boolean, der_explicit, der_generalized_time, der_integer,
    der_name_from_spki, der_octet_string, der_oid, der_sequence,
};

/// 48-byte seeds for deterministic key derivation.
#[derive(Clone, Debug)]
pub struct CaSeeds {
    pub root: [u8; 48],
    pub intermediate: [u8; 48],
    pub leaf: [u8; 48],
    /// Used for `break_ca_chain` and `untrusted_root` scenarios.
    pub impostor: [u8; 48],
}

impl Default for CaSeeds {
    fn default() -> Self {
        Self {
            root: [0x01; 48],
            intermediate: [0x02; 48],
            leaf: [0x03; 48],
            impostor: [0x04; 48],
        }
    }
}

/// DER-encoded CA chain material produced for one fixture build.
pub struct CaMaterial {
    /// DER of the root cert (self-signed by root key).
    pub root_der: Vec<u8>,
    /// DER of the intermediate cert (signed by root key).
    pub intermediate_der: Vec<u8>,
    /// DER of the leaf cert (signed by intermediate key).
    pub leaf_der: Vec<u8>,
    /// Signing key for the leaf — used to sign the COSE payload.
    pub leaf_sk: SigningKey,
    /// Verifying key for the leaf — embedded in the attestation doc.
    pub leaf_vk: VerifyingKey,
}

impl core::fmt::Debug for CaMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CaMaterial")
            .field("root_der_len", &self.root_der.len())
            .field("intermediate_der_len", &self.intermediate_der.len())
            .field("leaf_der_len", &self.leaf_der.len())
            .field("leaf_sk", &"<redacted>")
            .field("leaf_vk", &self.leaf_vk)
            .finish()
    }
}

/// Build the full 3-cert chain from seeds.
///
/// When `use_sha1_cert` is true, the leaf cert's signature algorithm OID is
/// replaced with sha1WithRSAEncryption (should be rejected by the verifier).
///
/// When `break_ca_chain` is true, the intermediate is signed by the impostor
/// key instead of the root key, breaking the trust chain.
pub fn build_chain(
    seeds: &CaSeeds,
    now: i64,
    leaf_not_before: i64,
    leaf_not_after: i64,
    use_sha1_cert: bool,
    break_ca_chain: bool,
) -> CaMaterial {
    let root_sk = SigningKey::from_slice(&seeds.root).expect("root sk");
    let inter_sk = SigningKey::from_slice(&seeds.intermediate).expect("inter sk");
    let leaf_sk = SigningKey::from_slice(&seeds.leaf).expect("leaf sk");
    let impostor_sk = SigningKey::from_slice(&seeds.impostor).expect("impostor sk");

    let root_vk = root_sk.verifying_key();
    let inter_vk = inter_sk.verifying_key();
    let leaf_vk = *leaf_sk.verifying_key();

    // Root — self-signed CA
    let root_der = build_cert_der(
        root_vk,
        root_vk,
        &root_sk,
        now - 86400,
        now + 86400 * 3650,
        true,
        false,
    );

    // Intermediate — signed by root (or impostor when break_ca_chain)
    let inter_signer: &SigningKey = if break_ca_chain {
        &impostor_sk
    } else {
        &root_sk
    };
    let inter_issuer_vk: &VerifyingKey = if break_ca_chain {
        impostor_sk.verifying_key()
    } else {
        root_vk
    };
    let intermediate_der = build_cert_der(
        inter_vk,
        inter_issuer_vk,
        inter_signer,
        now - 86400,
        now + 86400 * 3650,
        true,
        false,
    );

    // Leaf — signed by intermediate
    let leaf_der = build_cert_der(
        &leaf_vk,
        inter_vk,
        &inter_sk,
        leaf_not_before,
        leaf_not_after,
        false,
        use_sha1_cert,
    );

    CaMaterial {
        root_der,
        intermediate_der,
        leaf_der,
        leaf_sk,
        leaf_vk,
    }
}

fn build_cert_der(
    subject_vk: &VerifyingKey,
    issuer_vk: &VerifyingKey,
    signer: &SigningKey,
    not_before: i64,
    not_after: i64,
    is_ca: bool,
    use_sha1: bool,
) -> Vec<u8> {
    let subject_spki = subject_vk
        .to_public_key_der()
        .expect("spki encode")
        .into_vec();
    let issuer_spki = issuer_vk
        .to_public_key_der()
        .expect("spki encode")
        .into_vec();

    let subject_dn = der_name_from_spki(&subject_spki);
    let issuer_dn = der_name_from_spki(&issuer_spki);

    let sig_alg_seq = if use_sha1 {
        // sha1WithRSAEncryption OID — deliberately weak, should be rejected
        der_sequence(&[
            &der_oid(&[1, 2, 840, 113549, 1, 1, 5]),
            &[0x05, 0x00], // NULL
        ])
    } else {
        // ecdsa-with-SHA384
        der_sequence(&[&der_oid(&[1, 2, 840, 10045, 4, 3, 3])])
    };

    let serial = der_integer(&[0x01]);
    let version = der_explicit(0, &der_integer(&[0x02])); // v3

    let validity = der_sequence(&[
        &der_generalized_time(not_before),
        &der_generalized_time(not_after),
    ]);

    let mut extensions_content = Vec::new();
    let bc_value = if is_ca {
        der_sequence(&[&[0x01, 0x01, 0xff]]) // BOOLEAN TRUE
    } else {
        der_sequence(&[])
    };
    let bc_ext = der_sequence(&[
        &der_oid(&[2, 5, 29, 19]),
        &der_boolean(true),
        &der_octet_string(&bc_value),
    ]);
    extensions_content.extend_from_slice(&bc_ext);
    let extensions = der_explicit(3, &der_sequence(&[&extensions_content]));

    let tbs = der_sequence(&[
        &version,
        &serial,
        &sig_alg_seq,
        &issuer_dn,
        &validity,
        &subject_dn,
        &subject_spki,
        &extensions,
    ]);

    let sig: p384::ecdsa::Signature = signer.sign(&tbs);
    let sig_bytes = sig.to_der().as_bytes().to_vec();
    let sig_bitstring = der_bit_string(&sig_bytes);

    der_sequence(&[&tbs, &sig_alg_seq, &sig_bitstring])
}
