//! Classifier WASM signature verification (Phase C.3-C).
//!
//! This module binds a classifier WASM binary to a [`ClassifierSigner`]
//! -signed metadata envelope via a cryptographic pipeline that layers
//! over [`ephemeral_crypto::verify_cose_sign1`]:
//!
//! ```text
//!                     ┌────────────────────────────────┐
//! wasm_bytes  ───────►│ sha256(wasm_bytes)             │
//!                     │      must match                 │
//!                     │ ClassifierSigPayload.sha256     │
//!                     └─────────────┬──────────────────┘
//!                                   │
//! cose_bytes ───► verify_cose_sign1 │                    (outer)
//!      AAD = b"ephemeral/classifier/v1"
//!      role = AnchorRole::ClassifierSigner
//!                                   │
//!                                   ▼
//!                     inner payload = CBOR(ClassifierSigPayload)
//!                                   │
//!                    abi_version == expected
//!                    signer_kid   == outer COSE kid
//! ```
//!
//! ## Role discrimination
//!
//! The verifier requires that the matched trust anchor is registered
//! under [`AnchorRole::ClassifierSigner`]. A tariff- or delegation-
//! signed envelope with a matching `kid` will fail the role check at
//! the crypto layer and surface as
//! [`ClassifierSigError::CoseVerifyFailed`]. Role-leakage is avoided:
//! kid-unknown, role-mismatched, and signature-invalid all collapse
//! to the same outer failure.
//!
//! ## Domain-separation AAD
//!
//! [`CLASSIFIER_AAD`] = `b"ephemeral/classifier/v1"`. The `/v1` suffix
//! is reserved for the ABI-v1 envelope shape declared here; a v2
//! envelope with a structurally different payload would use a new AAD
//! so v1 and v2 envelopes cannot be replayed interchangeably even if
//! both share the same signer key.
//!
//! ## Wire format
//!
//! The `COSE_Sign1` payload is a CBOR map:
//!
//! ```cbor
//! {
//!   "sha256":      bstr .size 32,
//!   "abi_version": uint,
//!   "signer_kid":  tstr
//! }
//! ```
//!
//! Fields are named-indexed (not position-indexed) so
//! backward-compatible extensions can be added without breaking
//! existing verifiers. Unknown fields on decode are silently ignored
//! by serde/ciborium — the non-exhaustive posture is consistent with
//! the rest of the crate.
//!
//! # Example
//!
//! ```no_run
//! use ephemeral_classifier::{
//!     verify_classifier_signature, CLASSIFIER_ABI_VERSION,
//! };
//! use ephemeral_crypto::TrustAnchorSet;
//!
//! let wasm_bytes: &[u8] = &[];
//! let cose_sign1_bytes: &[u8] = &[];
//! let anchors = TrustAnchorSet::new();
//!
//! let verified = verify_classifier_signature(
//!     wasm_bytes,
//!     cose_sign1_bytes,
//!     &anchors,
//!     CLASSIFIER_ABI_VERSION,
//! )?;
//! println!("signed by {}", verified.signer_kid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ephemeral_crypto::{verify_cose_sign1, AnchorRole, TrustAnchorSet};

use crate::errors::{sanitize_log_string, ClassifierSigError, MAX_LOG_STRING_BYTES};

/// Domain-separation tag for classifier-signature envelopes.
///
/// Included verbatim in the `COSE_Sign1` external AAD so that a
/// tariff-signed or delegation-signed envelope cannot be replayed as a
/// classifier signature — the signed TBS (`Sig_structure_1`) differs
/// between domains, so the Ed25519 verification fails even if the
/// signer key and `kid` happen to collide across roles.
///
/// The `/v1` suffix names the ABI-v1 envelope shape; a future v2
/// shape (with, e.g., an `issuer` field or a different payload map)
/// MUST pick a new AAD so v1 and v2 signatures cannot be confused.
pub const CLASSIFIER_AAD: &[u8] = b"ephemeral/classifier/v1";

/// Maximum byte length accepted for the inner `signer_kid` field on
/// decode. Acts as a belt-and-braces guard: the outer
/// [`ephemeral_crypto::MAX_COSE_BYTES`] cap already bounds the whole
/// envelope, but a pathological payload could spend all of that budget
/// on the kid string.  We clamp to 256 bytes here — `kid` is a short
/// human-readable label in practice (`"K_cust_classifier_pk_TEST"` and
/// friends, all well under 64 bytes).
const MAX_INNER_KID_BYTES: usize = 256;

/// Expected on-wire byte length of the `sha256` field.
const SHA256_BYTES: usize = 32;

/// Hard cap on the inner CBOR payload size handed to `ciborium::from_reader`.
/// The outer [`ephemeral_crypto::MAX_COSE_BYTES`] already bounds the full
/// envelope, but an attacker controls what fraction of that budget lands
/// in the *inner* payload versus COSE framing overhead. We cap at 4 KiB
/// here — a well-formed v1 payload is ~300 bytes (32 sha256 + 4 abi +
/// up to 256 kid + CBOR overhead), so 4 KiB is > 10× the real envelope
/// size yet small enough that adversarial allocation is bounded well
/// below the outer cap.
///
/// If a future v2 payload adds structural fields that push the legitimate
/// size above this limit, bump this constant (and re-run the conformance
/// vectors); do NOT relax the bound by removing the check.
const MAX_INNER_PAYLOAD_BYTES: usize = 4096;

/// Payload structure for the classifier-signature envelope.
///
/// Deserialized from the `COSE_Sign1` inner payload after the outer
/// signature has been cryptographically verified. The `sha256` field
/// is decoded as a CBOR byte string via `serde_bytes` (ciborium's
/// default for `Vec<u8>` is a CBOR array-of-integers which would
/// change the on-wire shape and break deterministic vectors).
///
/// # Field validation
///
/// Structural deserialization is not enough: [`verify_classifier_signature`]
/// additionally enforces `sha256.len() == 32` and
/// `signer_kid.len() ≤ MAX_INNER_KID_BYTES` before trusting any field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierSigPayload {
    /// SHA-256 of the classifier WASM bytes the signer committed to.
    /// Decoders MUST reject any length other than 32 at parse time.
    #[serde(with = "serde_bytes")]
    pub sha256: Vec<u8>,
    /// ABI version the classifier was signed against (currently
    /// [`crate::CLASSIFIER_ABI_VERSION`] = 1).
    pub abi_version: u32,
    /// Human-readable signer identity, duplicated from the outer
    /// `COSE_Sign1` protected-header `kid`. The validator enforces
    /// equality with the outer kid as a defense-in-depth check.
    pub signer_kid: String,
}

/// Successful outcome of a classifier-signature verification.
///
/// Carries the authoritative signer kid (from the COSE outer header),
/// the signed ABI version, and the verified WASM digest. Callers
/// typically log `signer_kid` and the hex of `wasm_sha256` for audit
/// purposes before proceeding to runtime execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClassifierSignature {
    /// The kid of the signer, taken from the cryptographically
    /// authoritative outer `COSE_Sign1` protected header and passed
    /// through [`sanitize_log_string`] (non-printable ASCII replaced
    /// with `'?'`, truncated to [`MAX_LOG_STRING_BYTES`]) so this field
    /// is always safe to embed in log output or error messages.
    ///
    /// Do NOT use this value as a lookup key back into a
    /// [`TrustAnchorSet`] — the sanitising transform is lossy. The raw
    /// outer kid has already been consumed by the verifier for the
    /// Step 5 byte-exact equality check against the inner
    /// `signer_kid`, and is not retained.
    pub signer_kid: String,
    /// The ABI version the classifier was signed against.
    pub abi_version: u32,
    /// SHA-256 of the WASM bytes — both the signed payload and the
    /// runtime computation agreed on this value.
    pub wasm_sha256: [u8; 32],
}

/// Verify a classifier WASM against its signed metadata envelope.
///
/// # Arguments
///
/// * `wasm_bytes` — the classifier WASM binary to execute. The
///   validator hashes these bytes with SHA-256 and requires the
///   signed payload to commit to the same digest.
/// * `cose_sign1_bytes` — a `COSE_Sign1` envelope (RFC 9052 §4.2)
///   carrying a CBOR-encoded [`ClassifierSigPayload`] as its payload,
///   with Ed25519 signature (`alg = -8`).
/// * `anchors` — trust-anchor set. The anchor matching the envelope's
///   `kid` must be registered under
///   [`AnchorRole::ClassifierSigner`]; any other role fails the
///   verification at the crypto layer.
/// * `expected_abi_version` — the ABI version this validator was
///   built against. Production callers pass
///   [`crate::CLASSIFIER_ABI_VERSION`].
///
/// # Returns
///
/// On success, returns a [`VerifiedClassifierSignature`] with the
/// authoritative signer kid, ABI version, and WASM digest.
///
/// # Errors
///
/// See [`ClassifierSigError`] for the full taxonomy. In short:
///
/// - [`ClassifierSigError::CoseVerifyFailed`] — outer envelope fails
///   any check (parse, role, kid, alg, signature). Role-leakage is
///   contained in this single variant.
/// - [`ClassifierSigError::PayloadDecodeFailed`] — inner CBOR is
///   malformed or the `sha256` field is not exactly 32 bytes.
/// - [`ClassifierSigError::AbiVersionMismatch`] — payload version
///   ≠ `expected_abi_version`.
/// - [`ClassifierSigError::WasmHashMismatch`] — runtime SHA-256 of
///   `wasm_bytes` ≠ payload `sha256`.
/// - [`ClassifierSigError::SignerKidMismatch`] — inner `signer_kid`
///   ≠ outer COSE header `kid`.
#[must_use = "an unchecked classifier signature is indistinguishable from an unsigned one"]
pub fn verify_classifier_signature(
    wasm_bytes: &[u8],
    cose_sign1_bytes: &[u8],
    anchors: &TrustAnchorSet,
    expected_abi_version: u32,
) -> Result<VerifiedClassifierSignature, ClassifierSigError> {
    // Step 1: outer COSE_Sign1 verify with AAD + role pinning.
    // The crypto layer enforces size/depth caps, parse, alg allowlist,
    // role-aware kid resolution, alg/anchor consistency, payload
    // presence, and Ed25519 strict-mode signature verification.
    let verified = verify_cose_sign1(
        cose_sign1_bytes,
        anchors,
        CLASSIFIER_AAD,
        AnchorRole::ClassifierSigner,
    )
    .map_err(|_| ClassifierSigError::CoseVerifyFailed)?;

    // Step 2a: inner-payload size cap before handing bytes to ciborium.
    // The outer size_depth_check already bounded cose_sign1_bytes, but a
    // pathological signer could dedicate almost all of that budget to
    // the inner payload. Cap here so ciborium allocation stays small.
    if verified.payload.len() > MAX_INNER_PAYLOAD_BYTES {
        return Err(ClassifierSigError::PayloadDecodeFailed);
    }

    // Step 2b: decode the inner CBOR payload. `from_reader` expects a
    // `Read` impl, which `&[u8]` provides. Any deserialization failure
    // — wrong type, missing field, truncated input — collapses to
    // PayloadDecodeFailed.
    let payload: ClassifierSigPayload = ciborium::from_reader(verified.payload.as_slice())
        .map_err(|_| ClassifierSigError::PayloadDecodeFailed)?;

    // Step 3: structural validation beyond what serde guaranteed.
    // The sha256 field came through as a CBOR byte string but with an
    // arbitrary length; enforce the exact length here. Same reasoning
    // as [`crate::runtime`] bounding the packed output locator — every
    // field that will be indexed or compared bitwise MUST have its
    // bounds confirmed before use.
    if payload.sha256.len() != SHA256_BYTES {
        return Err(ClassifierSigError::PayloadDecodeFailed);
    }
    if payload.signer_kid.len() > MAX_INNER_KID_BYTES {
        return Err(ClassifierSigError::PayloadDecodeFailed);
    }

    // Step 4: ABI version pinning.
    if payload.abi_version != expected_abi_version {
        return Err(ClassifierSigError::AbiVersionMismatch {
            expected: expected_abi_version,
            signed: payload.abi_version,
        });
    }

    // Step 5: signer kid consistency (inner vs. outer). The outer kid
    // is cryptographically authoritative; this catches signer-side
    // authoring bugs where the inner metadata was stale.  Sanitise
    // both sides for log output so an adversarial CBOR can't inject
    // newlines or control chars into the error display.
    if payload.signer_kid != verified.kid {
        return Err(ClassifierSigError::SignerKidMismatch {
            outer: sanitize_log_string(&verified.kid),
            signed: sanitize_log_string(&payload.signer_kid),
        });
    }

    // Step 6: WASM hash pinning — compute runtime digest, compare to
    // the signed commitment. Both are 32-byte values after Step 3, so
    // `try_into` cannot fail.
    let mut hasher = Sha256::new();
    hasher.update(wasm_bytes);
    let actual: [u8; 32] = hasher.finalize().into();
    let expected: [u8; 32] = payload
        .sha256
        .as_slice()
        .try_into()
        .expect("length checked in Step 3");
    if actual != expected {
        return Err(ClassifierSigError::WasmHashMismatch { expected, actual });
    }

    // The outer kid has been cryptographically authenticated but its
    // byte content is attacker-controlled (the signer picks their own
    // kid label). Downstream consumers typically log this field —
    // sanitise before storing so a rogue signer cannot smuggle control
    // chars or ANSI escapes into validator logs via this surface. The
    // raw outer kid has already served its purpose in Step 5's byte-
    // exact equality check against `payload.signer_kid`; there is no
    // downstream use that requires the un-sanitised form.
    Ok(VerifiedClassifierSignature {
        signer_kid: sanitize_log_string(&verified.kid),
        abi_version: payload.abi_version,
        wasm_sha256: actual,
    })
}

/// Silence the unused-import linter on `MAX_LOG_STRING_BYTES`: the
/// constant is referenced in doc comments on [`ClassifierSigError::SignerKidMismatch`]
/// and in the `sanitize_log_string` helper contract, but is not used
/// by name in the module body.
#[allow(dead_code)]
const _: usize = MAX_LOG_STRING_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
    use ed25519_dalek::{Signer, SigningKey};
    use ephemeral_crypto::TrustAnchor;

    use crate::CLASSIFIER_ABI_VERSION;

    const TEST_KID: &str = "K_classifier_pk_TEST";
    const ALT_KID: &str = "K_other_classifier_pk_TEST";
    // Fixed seed so test keys are deterministic across runs — failures
    // reproduce, and the vector-signer tool can reuse the same seed
    // when generating committed conformance vectors.
    const SEED: [u8; 32] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
        0x8f, 0x90,
    ];
    // A second, non-overlapping seed for negative tests needing a
    // distinct key (e.g. wrong-kid under a well-formed anchor set).
    const ALT_SEED: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0, 0x01,
    ];

    fn signing_key(seed: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&seed)
    }

    /// Build an anchor set holding a single `ClassifierSigner` anchor
    /// under `TEST_KID` backed by `SEED`.
    fn classifier_anchor_set() -> TrustAnchorSet {
        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            TEST_KID.to_string(),
            pk.as_bytes(),
            AnchorRole::ClassifierSigner,
        )
        .expect("fixed seed yields non-weak pk");
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).expect("fresh set has no dup kid");
        set
    }

    /// Encode a payload as canonical CBOR.
    fn encode_payload(payload: &ClassifierSigPayload) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(payload, &mut out).expect("ciborium serialize");
        out
    }

    /// Build a `COSE_Sign1` blob over the supplied inner payload bytes,
    /// signed with `seed` under header kid `kid`, using `aad` as the
    /// external AAD.
    fn build_sign1(
        inner_payload_bytes: Vec<u8>,
        kid: &str,
        aad: &[u8],
        seed: [u8; 32],
    ) -> Vec<u8> {
        let sk = signing_key(seed);
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(kid.as_bytes().to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(inner_payload_bytes)
            .create_signature(aad, |tbs| sk.sign(tbs).to_bytes().to_vec())
            .build();
        sign1.to_vec().expect("serialize")
    }

    fn compute_sha256(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }

    /// Happy-path fixture: the signer commits to the runtime WASM's
    /// actual sha256 under the expected ABI version and the correct
    /// kid, and signs under `ClassifierSigner` role.
    fn happy_envelope(wasm_bytes: &[u8]) -> Vec<u8> {
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm_bytes).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
        };
        let inner = encode_payload(&payload);
        build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED)
    }

    #[test]
    fn happy_path_verifies() {
        let wasm = b"not-real-wasm-but-hashes-fine";
        let cose = happy_envelope(wasm);
        let out = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .expect("happy path verifies");
        assert_eq!(out.signer_kid, TEST_KID);
        assert_eq!(out.abi_version, CLASSIFIER_ABI_VERSION);
        assert_eq!(out.wasm_sha256, compute_sha256(wasm));
    }

    #[test]
    fn wrong_role_fails_as_cose_verify() {
        // Anchor registered as TariffSigner — classifier verification
        // must fail at the crypto-layer role check. Indistinguishable
        // from UnknownKid from the caller's perspective.
        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            TEST_KID.to_string(),
            pk.as_bytes(),
            AnchorRole::TariffSigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).unwrap();

        let wasm = b"wasm";
        let cose = happy_envelope(wasm);
        let err = verify_classifier_signature(wasm, &cose, &set, CLASSIFIER_ABI_VERSION)
            .unwrap_err();
        assert_eq!(err, ClassifierSigError::CoseVerifyFailed);
    }

    #[test]
    fn unknown_kid_fails_as_cose_verify() {
        // Signer uses ALT_SEED (and ALT_KID in the header), but the
        // anchor set only holds TEST_KID. Resolution fails and the
        // crypto layer returns UnknownKid, which folds to CoseVerifyFailed.
        let wasm = b"wasm";
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: ALT_KID.to_string(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, ALT_KID, CLASSIFIER_AAD, ALT_SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(err, ClassifierSigError::CoseVerifyFailed);
    }

    #[test]
    fn wrong_aad_fails_as_cose_verify() {
        // Envelope signed with the tariff AAD — the ClassifierSigner
        // verifier picks `b"ephemeral/classifier/v1"` so TBS differs
        // and the signature check fails.
        let wasm = b"wasm";
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, b"tariff", SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(err, ClassifierSigError::CoseVerifyFailed);
    }

    #[test]
    fn tampered_payload_fails_as_cose_verify() {
        // Flip one byte inside the signed inner payload after signing.
        let wasm = b"wasm";
        let mut cose = happy_envelope(wasm);
        // Find the payload section (bstr) by parsing and re-serializing.
        let mut parsed = coset::CoseSign1::from_slice(&cose).expect("parse");
        let payload = parsed.payload.as_mut().expect("payload");
        payload[0] ^= 0xFF;
        cose = parsed.to_vec().expect("reserialize");

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        // Tamper can land as either CoseVerifyFailed (if the post-flip
        // bytes still decode as a ClassifierSigPayload — ciborium is
        // lenient about unknown fields) or PayloadDecodeFailed (if the
        // flipped byte broke the CBOR header).  We assert the outer
        // family because the crypto signature check runs first.
        assert_eq!(err, ClassifierSigError::CoseVerifyFailed);
    }

    #[test]
    fn abi_version_mismatch_surfaces_explicitly() {
        let wasm = b"wasm";
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: 99,
            signer_kid: TEST_KID.to_string(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ClassifierSigError::AbiVersionMismatch {
                expected: CLASSIFIER_ABI_VERSION,
                signed: 99,
            }
        );
    }

    #[test]
    fn wasm_hash_mismatch_surfaces_explicitly() {
        // Payload commits to a different WASM's hash.
        let signed_wasm = b"signed-wasm";
        let runtime_wasm = b"tampered-wasm";
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(signed_wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);

        let err = verify_classifier_signature(
            runtime_wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        match err {
            ClassifierSigError::WasmHashMismatch { expected, actual } => {
                assert_eq!(expected, compute_sha256(signed_wasm));
                assert_eq!(actual, compute_sha256(runtime_wasm));
            }
            other => panic!("expected WasmHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn signer_kid_mismatch_surfaces_explicitly() {
        // Inner signer_kid differs from the outer COSE header kid.
        // Signature still validates because the inner bytes are part
        // of the TBS; the mismatch is a semantic consistency failure.
        let wasm = b"wasm";
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: "K_wrong_inner_kid".to_string(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        match err {
            ClassifierSigError::SignerKidMismatch { outer, signed } => {
                assert_eq!(outer, TEST_KID);
                assert_eq!(signed, "K_wrong_inner_kid");
            }
            other => panic!("expected SignerKidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn signer_kid_mismatch_display_is_sanitized() {
        // Inner kid contains newlines / control chars. The verifier
        // sanitises both kids before putting them into the error
        // variant; Display output must not embed raw control chars.
        let wasm = b"wasm";
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: "K_\nINJECTED".to_string(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        let display = format!("{err}");
        assert!(!display.contains('\n'));
        assert!(display.contains("K_?INJECTED"));
    }

    #[test]
    fn payload_decode_failure_on_non_cbor() {
        // Inner payload is garbage bytes — ciborium rejects the CBOR
        // parse even though the outer envelope signature verifies.
        let wasm = b"wasm";
        let bogus_inner = vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD];
        let cose = build_sign1(bogus_inner, TEST_KID, CLASSIFIER_AAD, SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(err, ClassifierSigError::PayloadDecodeFailed);
    }

    #[test]
    fn payload_decode_failure_on_wrong_sha256_length() {
        // Payload is well-formed CBOR but sha256 is 16 bytes, not 32.
        // Structural decode succeeds; the length validation in Step 3
        // rejects.
        let wasm = b"wasm";
        let payload = ClassifierSigPayload {
            sha256: vec![0xAA; 16],
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: TEST_KID.to_string(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(err, ClassifierSigError::PayloadDecodeFailed);
    }

    #[test]
    fn payload_decode_failure_on_oversize_inner_kid() {
        // Inner signer_kid is 300 bytes — exceeds MAX_INNER_KID_BYTES.
        let wasm = b"wasm";
        let big_kid: String = "x".repeat(300);
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: big_kid,
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(err, ClassifierSigError::PayloadDecodeFailed);
    }

    #[test]
    fn check_order_cose_before_payload_decode() {
        // Crafted envelope: inner payload is garbage, outer signature
        // is garbage (not signed by SEED). Both would fail — we assert
        // the crypto failure is reported *first* so that a bad-kid
        // vector does not shadow a subtle payload shape bug.
        let wasm = b"wasm";
        let bogus_inner = vec![0x00, 0x01, 0x02];
        // Sign with ALT_SEED — no anchor for that key.
        let cose = build_sign1(bogus_inner, ALT_KID, CLASSIFIER_AAD, ALT_SEED);

        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(err, ClassifierSigError::CoseVerifyFailed);
    }

    #[test]
    fn classifier_aad_is_versioned() {
        // Guard against accidental constant drift — the AAD ships in
        // conformance vectors and the /v1 suffix is reserved.
        assert_eq!(CLASSIFIER_AAD, b"ephemeral/classifier/v1");
    }

    #[test]
    fn payload_decode_failure_on_sha256_length_boundary() {
        // The existing 16-byte test guards the mid-range; these lock the
        // exact ±1 boundary around the SHA256_BYTES constant so that a
        // future refactor replacing `len() != 32` with `len() < 32` or
        // `len() <= 32` is caught immediately.
        let wasm = b"wasm";
        for len in [SHA256_BYTES - 1, SHA256_BYTES + 1] {
            let payload = ClassifierSigPayload {
                sha256: vec![0xAA; len],
                abi_version: CLASSIFIER_ABI_VERSION,
                signer_kid: TEST_KID.to_string(),
            };
            let inner = encode_payload(&payload);
            let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);
            let err = verify_classifier_signature(
                wasm,
                &cose,
                &classifier_anchor_set(),
                CLASSIFIER_ABI_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ClassifierSigError::PayloadDecodeFailed,
                "sha256 len={len} must reject as PayloadDecodeFailed"
            );
        }
    }

    #[test]
    fn signer_kid_at_max_length_accepts() {
        // Inner signer_kid = exactly MAX_INNER_KID_BYTES. The boundary
        // check is `> MAX` (strict), so `== MAX` must pass. The outer
        // header kid and the anchor kid must match byte-for-byte so
        // Step 5's equality check passes.
        let wasm = b"wasm";
        let max_kid: String = "x".repeat(MAX_INNER_KID_BYTES);

        let pk = signing_key(SEED).verifying_key();
        let anchor = TrustAnchor::new_ed25519(
            max_kid.clone(),
            pk.as_bytes(),
            AnchorRole::ClassifierSigner,
        )
        .unwrap();
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).unwrap();

        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: max_kid.clone(),
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, &max_kid, CLASSIFIER_AAD, SEED);

        let out = verify_classifier_signature(wasm, &cose, &set, CLASSIFIER_ABI_VERSION)
            .expect("max-length kid must accept at boundary");
        // `x` is printable ASCII so sanitize_log_string is identity here;
        // the stored kid retains its full 256 bytes.
        assert_eq!(out.signer_kid.len(), MAX_INNER_KID_BYTES);
        assert!(out.signer_kid.chars().all(|c| c == 'x'));
    }

    #[test]
    fn payload_decode_failure_on_signer_kid_length_one_past_max() {
        // Exactly MAX_INNER_KID_BYTES + 1 bytes must reject. Complements
        // the existing 300-byte test — locking the ±1 boundary catches
        // a future off-by-one in the length comparison.
        let wasm = b"wasm";
        let over: String = "x".repeat(MAX_INNER_KID_BYTES + 1);
        let payload = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: over,
        };
        let inner = encode_payload(&payload);
        let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);
        let err = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .unwrap_err();
        assert_eq!(err, ClassifierSigError::PayloadDecodeFailed);
    }

    #[test]
    fn abi_version_edge_values_reject() {
        // Both ends of the u32 range must surface as AbiVersionMismatch
        // when the verifier expects CLASSIFIER_ABI_VERSION. Locks the
        // mismatch-detection against a future `== 0 { accept-as-unset }`
        // or saturating-arithmetic regression.
        let wasm = b"wasm";
        for signed in [0u32, u32::MAX] {
            let payload = ClassifierSigPayload {
                sha256: compute_sha256(wasm).to_vec(),
                abi_version: signed,
                signer_kid: TEST_KID.to_string(),
            };
            let inner = encode_payload(&payload);
            let cose = build_sign1(inner, TEST_KID, CLASSIFIER_AAD, SEED);
            let err = verify_classifier_signature(
                wasm,
                &cose,
                &classifier_anchor_set(),
                CLASSIFIER_ABI_VERSION,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ClassifierSigError::AbiVersionMismatch {
                    expected: CLASSIFIER_ABI_VERSION,
                    signed,
                },
                "abi_version={signed} must reject as AbiVersionMismatch"
            );
        }
    }

    #[test]
    fn empty_wasm_happy_path_verifies() {
        // Degenerate-but-valid case: 0-byte WASM. The SHA-256 of the
        // empty string is a well-known constant (e3b0c44298fc1c149afb...);
        // a signer who commits to that hash with a 0-byte runtime binary
        // must verify successfully — the 6-step pipeline has no implicit
        // non-empty assumption.
        let wasm: &[u8] = &[];
        let cose = happy_envelope(wasm);
        let out = verify_classifier_signature(
            wasm,
            &cose,
            &classifier_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .expect("zero-byte wasm happy path must verify");
        assert_eq!(out.wasm_sha256, compute_sha256(&[]));
    }

    #[test]
    fn check_order_internal_steps_compounded() {
        // Compound-failure envelopes prove the internal check ordering
        // inside verify_classifier_signature: once a step surfaces, the
        // later steps do NOT override it. Extends `check_order_cose_
        // before_payload_decode` (which guards step 1 vs 2-6) by covering
        // the step 3 → 4 → 5 → 6 sequence.
        let wasm = b"wasm";

        // Case A: wrong sha256 length (step 3) + wrong abi (step 4).
        //   Step 3 wins as PayloadDecodeFailed.
        let payload_a = ClassifierSigPayload {
            sha256: vec![0xAA; SHA256_BYTES - 1],
            abi_version: 99,
            signer_kid: TEST_KID.to_string(),
        };
        let cose_a =
            build_sign1(encode_payload(&payload_a), TEST_KID, CLASSIFIER_AAD, SEED);
        assert_eq!(
            verify_classifier_signature(
                wasm,
                &cose_a,
                &classifier_anchor_set(),
                CLASSIFIER_ABI_VERSION,
            )
            .unwrap_err(),
            ClassifierSigError::PayloadDecodeFailed,
            "length (step 3) must win over abi (step 4)"
        );

        // Case B: wrong abi (step 4) + wrong inner kid (step 5).
        //   Step 4 wins as AbiVersionMismatch.
        let payload_b = ClassifierSigPayload {
            sha256: compute_sha256(wasm).to_vec(),
            abi_version: 99,
            signer_kid: "K_wrong_inner".to_string(),
        };
        let cose_b =
            build_sign1(encode_payload(&payload_b), TEST_KID, CLASSIFIER_AAD, SEED);
        assert!(
            matches!(
                verify_classifier_signature(
                    wasm,
                    &cose_b,
                    &classifier_anchor_set(),
                    CLASSIFIER_ABI_VERSION,
                )
                .unwrap_err(),
                ClassifierSigError::AbiVersionMismatch { .. }
            ),
            "abi (step 4) must win over inner-kid (step 5)"
        );

        // Case C: wrong inner kid (step 5) + wrong sha256 hash (step 6).
        //   Step 5 wins as SignerKidMismatch.
        let payload_c = ClassifierSigPayload {
            sha256: [0u8; SHA256_BYTES].to_vec(),
            abi_version: CLASSIFIER_ABI_VERSION,
            signer_kid: "K_wrong_inner".to_string(),
        };
        let cose_c =
            build_sign1(encode_payload(&payload_c), TEST_KID, CLASSIFIER_AAD, SEED);
        assert!(
            matches!(
                verify_classifier_signature(
                    wasm,
                    &cose_c,
                    &classifier_anchor_set(),
                    CLASSIFIER_ABI_VERSION,
                )
                .unwrap_err(),
                ClassifierSigError::SignerKidMismatch { .. }
            ),
            "inner-kid (step 5) must win over hash (step 6)"
        );
    }
}
