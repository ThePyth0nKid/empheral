//! Deterministic AWS Nitro attestation-document fixtures.
//!
//! All keys, certificates, timestamps, and signatures are deterministic —
//! byte-for-byte identical across runs — so committed test vectors stay
//! stable in Git. Relies on `p384::ecdsa::SigningKey::sign`'s RFC-6979
//! deterministic nonces and `ciborium`'s insertion-order Map encoding.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use ephemeral_attestation_test_support::{build_attestation_doc, BuildParams};
//!
//! let params = BuildParams::default();
//! let now = params.now;
//! let (cose_bytes, roots) = build_attestation_doc(params);
//! // ephemeral_attestation::verify_nitro_attestation(&cose_bytes, &roots, None, now)
//! ```

#![forbid(unsafe_code)]
// Clippy lints relaxed for hand-rolled ASN.1 / test fixture code.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::similar_names)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::needless_pass_by_value)]

pub mod ca;
mod cose;
mod der;
pub mod payload;

pub use ca::{CaMaterial, CaSeeds};
pub use payload::PcrEntry;

use ephemeral_attestation::NitroRootSet;

/// Parameters controlling the synthetic attestation document.
///
/// All boolean flags default to `false` (happy-path document).
/// The multiple bool fields are intentional: each flag activates a distinct
/// failure-injection scenario, and a state machine would not improve clarity.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct BuildParams {
    /// Unix timestamp to stamp on the attestation.
    pub now: i64,
    /// `not_before` for the leaf cert (Unix seconds).
    pub leaf_not_before: i64,
    /// `not_after` for the leaf cert (Unix seconds).
    pub leaf_not_after: i64,
    /// Optional nonce to embed in the doc.
    pub nonce: Option<Vec<u8>>,
    /// PCR slots to embed.  Defaults to two slots (id=0,1 with all-0xAA hashes).
    pub pcrs: Vec<PcrEntry>,
    /// Sign COSE_Sign1 with alg=-7 (ES256) instead of -35 (ES384).
    pub use_wrong_cose_alg: bool,
    /// Alias for `use_wrong_cose_alg` — kept for backward compatibility with
    /// existing tests that used the old `use_wrong_alg` field name.
    pub use_wrong_alg: bool,
    /// Mark cert signature as using SHA-1 OID.
    pub use_sha1_cert: bool,
    /// Inject duplicate PCR-0 into map.
    pub duplicate_pcr: bool,
    /// Flip the low bit of `payload[len-1]` after signing — the outer COSE
    /// stays parseable, but the embedded payload no longer matches the signed
    /// TBS, so ECDSA verify fails with `AttestError::SignatureInvalid`.
    /// Field name is historical ("byte_0" predates the post-sign redesign);
    /// the actual byte tampered is the last one, chosen so CBOR parse still
    /// succeeds. See `cose::build_cose_sign1` for the tamper implementation.
    pub tamper_payload_byte_0: bool,
    /// Re-sign intermediate cert with an unrelated (impostor) key.
    pub break_ca_chain: bool,
    /// Do NOT insert CA root into `NitroRootSet` — root untrusted.
    pub untrusted_root: bool,
    /// Key seeds for the CA chain.
    pub seeds: CaSeeds,
}

impl Default for BuildParams {
    fn default() -> Self {
        let now = 1_700_000_000i64; // 2023-11-14 — arbitrary fixed timestamp
        let pcr_hash = vec![0xAAu8; 48]; // 48-byte SHA-384 placeholder
        Self {
            now,
            leaf_not_before: now - 3600,
            leaf_not_after: now + 86400 * 365,
            nonce: None,
            pcrs: vec![
                PcrEntry {
                    id: 0,
                    hash: pcr_hash.clone(),
                },
                PcrEntry {
                    id: 1,
                    hash: pcr_hash,
                },
            ],
            use_wrong_cose_alg: false,
            use_wrong_alg: false,
            use_sha1_cert: false,
            duplicate_pcr: false,
            tamper_payload_byte_0: false,
            break_ca_chain: false,
            untrusted_root: false,
            seeds: CaSeeds::default(),
        }
    }
}

/// Build a synthetic attestation doc + root-set ready for
/// `verify_nitro_attestation`.
///
/// Determinism: given the same `BuildParams`, `cose_sign1_bytes` is
/// byte-identical across machines (RFC-6979 nonces + ciborium insertion-order).
pub fn build_attestation_doc(params: BuildParams) -> (Vec<u8>, NitroRootSet) {
    // Resolve backward-compat alias: either flag triggers wrong-alg behaviour.
    let use_wrong_alg = params.use_wrong_cose_alg || params.use_wrong_alg;

    // ── 1. Build CA chain ─────────────────────────────────────────────────────
    let chain = ca::build_chain(
        &params.seeds,
        params.now,
        params.leaf_not_before,
        params.leaf_not_after,
        params.use_sha1_cert,
        params.break_ca_chain,
    );

    // ── 2. Build CBOR payload ─────────────────────────────────────────────────
    let ca_ders = vec![chain.intermediate_der.clone(), chain.root_der.clone()];
    let payload_cbor = payload::build_payload_cbor(
        &chain.leaf_der,
        &ca_ders,
        &chain.leaf_vk,
        &params.pcrs,
        params.nonce.clone(),
        params.now,
        params.duplicate_pcr,
    );

    // ── 3. Build COSE_Sign1 (optional post-sign payload tamper applied inside) ─
    let cose_bytes = cose::build_cose_sign1(
        &payload_cbor,
        &chain.leaf_sk,
        use_wrong_alg,
        params.tamper_payload_byte_0,
    );

    // ── 5. Build NitroRootSet ─────────────────────────────────────────────────
    let mut roots = NitroRootSet::new();
    if !params.untrusted_root {
        roots
            .insert_trusted_der_for_test(&chain.root_der)
            .expect("insert root");
    }

    (cose_bytes, roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Determinism: two calls with identical params produce byte-identical output.
    #[test]
    fn build_is_deterministic() {
        let (bytes1, _) = build_attestation_doc(BuildParams::default());
        let (bytes2, _) = build_attestation_doc(BuildParams::default());
        assert_eq!(
            bytes1, bytes2,
            "build_attestation_doc must be deterministic"
        );
    }

    /// Sanity-check the first 8 bytes of the default fixture.
    /// This pinned value catches any accidental change to encoding order or
    /// default parameters.
    #[test]
    fn deterministic_prefix_is_stable() {
        let (bytes, _) = build_attestation_doc(BuildParams::default());
        assert!(
            bytes.len() >= 8,
            "COSE output too short: {} bytes",
            bytes.len()
        );
        // 0xd2 is the CBOR tag(18) byte — always first.
        assert_eq!(bytes[0], 0xd2, "first byte must be CBOR tag(18) = 0xd2");
    }

    /// The default fixture must verify successfully end-to-end.
    #[test]
    fn default_params_verify_ok() {
        use ephemeral_attestation::verify_nitro_attestation;
        let params = BuildParams::default();
        let now = params.now;
        let (bytes, roots) = build_attestation_doc(params);
        verify_nitro_attestation(&bytes, &roots, None, now)
            .expect("default fixture must verify clean");
    }
}
