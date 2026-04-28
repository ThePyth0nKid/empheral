//! Phase C.3-C — classifier-signature verification reject + accept
//! vectors (`trej-120`..`trej-127`).
//!
//! Tariff step 9.5 (`crates/ephemeral-core/src/suites/tariff.rs`, the
//! `match` on the `(cose_sign1_bytes_classifier, wasm_bytes_classifier,
//! trust_anchor_keys_classifier)` triple) invokes
//! `ephemeral_classifier::verify_classifier_signature` whenever all three
//! fields are supplied. Each vector isolates one failure mode so the
//! expected `reject_code` pins a specific validator branch:
//!
//! | ID        | Failure mode                                       | Expected tariff code                           |
//! |-----------|----------------------------------------------------|------------------------------------------------|
//! | trej-120  | COSE envelope byte flipped post-sign               | `classifier-signature-invalid`                 |
//! | trej-121  | Inner payload `sha256` is 31 bytes (not 32)        | `classifier-signature-payload-malformed`       |
//! | trej-122  | Signed `abi_version=2`, Tariff expects 1           | `classifier-abi-version-mismatch`              |
//! | trej-123  | Signed `sha256(WASM_A)`, vector supplies WASM_B    | `classifier-wasm-hash-mismatch`                |
//! | trej-124  | Inner `signer_kid` ≠ outer envelope `kid`          | `classifier-signer-kid-mismatch`               |
//! | trej-125  | Partial triple — `cose`+`wasm` present, no anchors | `classifier-signature-invalid` (authoring)     |
//! | trej-126  | Happy path — ABI default (1)                       | `accept`                                       |
//! | trej-127  | Happy path — ABI override to 2 (signed abi=2)      | `accept`                                       |
//!
//! # Why six rejects + two accepts
//!
//! Five reject codes × one isolating vector each, plus one authoring-
//! error vector (trej-125). Two accepts because `policy_classifier_abi_version`
//! is a security-sensitive override dial: a single accept-vector cannot
//! differentiate between "validator always accepts" and "validator
//! correctly honours the override". trej-126 pins the default-ABI happy
//! path; trej-127 pins the override path.
//!
//! # Partial-triple security rationale
//!
//! Six partial-triple permutations all collapse to the same
//! `ClassifierSignatureInvalid` arm in `tariff.rs`. We encode the single
//! most-security-relevant permutation — `cose`+`wasm` present but
//! `trust_anchor_keys_classifier` missing — because it models the
//! plausible misconfiguration where an attacker-controlled envelope
//! rides through a Tariff file that simply forgot to declare classifier
//! anchors. If that ever silently accepts, the whole classifier-trust
//! layer is bypassed.
//!
//! # Determinism
//!
//! Every seed, hash, ABI version, kid, and WASM blob below is a
//! compile-time constant. The signing key is
//! `ephemeral_classifier::test_fixtures::fixture_signing_key()` — a
//! fixed Ed25519 secret. Ed25519 signing is deterministic (RFC 8032
//! §5.1.6), so every `build_all()` call produces byte-identical JSON.
//! The inline `determinism_two_runs_produce_identical_bytes` test at
//! the bottom of this file guards in-process determinism; a companion
//! `tests/determinism_c3_c.rs` mirrors the C.2.5 external-process
//! tripwire (pinned SHA-256 of the `gen-phase-c3-c --dry-run` stdout)
//! and is added alongside the generated conformance JSON (Session 2
//! Task #13).

use ephemeral_classifier::test_fixtures as cft;
use ephemeral_classifier::{ClassifierSigPayload, CLASSIFIER_AAD, CLASSIFIER_ABI_VERSION};
use serde_json::{json, Value};

use crate::tamper_payload_byte;

// ─── Deterministic fixture inputs ───────────────────────────────────────────

/// Canonical classifier WASM bytes referenced by every vector unless
/// noted. Tariff step 9.5 does **not** execute this blob — it only
/// checks that the signed inner `sha256` matches
/// `sha256(wasm_bytes_classifier)`. Using a non-parseable blob keeps
/// the conformance JSON small while still exercising the hash path.
const CLASSIFIER_WASM: &[u8] = b"phase-c3-c-classifier-wasm-blob-v1";

/// Alternate classifier WASM bytes used by `trej-123` to drive the
/// `wasm-hash-mismatch` reject: the signed payload commits to
/// `sha256(ALT_CLASSIFIER_WASM)` while the vector's
/// `wasm_bytes_classifier` decodes to `CLASSIFIER_WASM`.
const ALT_CLASSIFIER_WASM: &[u8] = b"phase-c3-c-alternate-wasm-blob-for-hash-mismatch";

/// Non-default ABI version used by trej-122 (reject, signed=2 vs
/// expected=1) and trej-127 (accept, signed=2 with explicit override).
const ABI_V2: u32 = 2;

/// Outer envelope `kid` deliberately distinct from
/// `cft::FIXTURE_CLASSIFIER_KID` so trej-124 drives the inner/outer-kid
/// consistency check. The fixture signing key itself is registered
/// against this kid in the vector's anchor set, so the outer COSE
/// signature verifies; the mismatch surfaces exclusively through the
/// inner `signer_kid` field check.
const IMPOSTOR_OUTER_KID: &str = "K_impostor_classifier_pk";

/// Fixed clock used by every vector — matches the default in
/// `ephemeral-core`'s step-9.5 integration tests.
const CURRENT_TIME: &str = "2026-05-01T00:00:00Z";
/// Previously-seen tariff version used so step-10 version monotonicity
/// does not fire (vectors omit `tariff_version_in_payload`).
const PREV_VERSION: i64 = 1;

// ─── Entry point ────────────────────────────────────────────────────────────

/// Emit all eight Phase C.3-C vectors in ascending ID order.
pub fn build_all() -> Vec<Value> {
    vec![
        build_trej_120_cose_verify_tampered(),
        build_trej_121_payload_sha256_wrong_length(),
        build_trej_122_abi_version_mismatch(),
        build_trej_123_wasm_hash_mismatch(),
        build_trej_124_inner_kid_mismatch(),
        build_trej_125_partial_triple_missing_anchors(),
        build_trej_126_accept_default_abi(),
        build_trej_127_accept_abi_override(),
    ]
}

// ─── Reject builders ────────────────────────────────────────────────────────

/// trej-120 — happy envelope with one payload byte flipped. The outer
/// COSE_Sign1 MAC no longer validates → `CoseVerifyFailed` →
/// `classifier-signature-invalid`.
fn build_trej_120_cose_verify_tampered() -> Value {
    let envelope = cft::happy_envelope(CLASSIFIER_WASM);
    let tampered_hex = tamper_payload_byte(&hex::encode(&envelope))
        .expect("tampering a freshly-built envelope must succeed");

    build_vector(
        "trej-120",
        "live-classifier-sig-cose-verify-tampered",
        "Phase C.3-C live-crypto vector: a valid classifier COSE_Sign1 \
         envelope with the first inner-payload byte flipped after \
         signing. Outer Ed25519 MAC fails, classifier-sig verification \
         surfaces as classifier-signature-invalid.",
        "design-final.md §4.3 + RFC 9052 §4.4: the classifier envelope \
         is protected exactly the way the tariff envelope is. Any \
         post-signing mutation of the signed bytes breaks the MAC; the \
         live path must detect what no mock bool could have.",
        Some(tampered_hex),
        Some(hex::encode(CLASSIFIER_WASM)),
        Some(classifier_anchor_def(cft::FIXTURE_CLASSIFIER_KID)),
        None,
        "reject",
        Some("classifier-signature-invalid"),
        "critical",
    )
}

/// trej-121 — inner CBOR payload carries `sha256` as a 31-byte string
/// (one byte short of SHA-256's required 32). Decoder rejects at parse
/// time → `PayloadDecodeFailed` → `classifier-signature-payload-malformed`.
fn build_trej_121_payload_sha256_wrong_length() -> Value {
    // Construct a ClassifierSigPayload directly so we can set a
    // deliberately wrong-length sha256. The struct's field is
    // `Vec<u8>` at the Rust level (see crates/ephemeral-classifier/
    // src/signature.rs), so ciborium will happily serialise a 31-byte
    // string; the verifier's explicit length check at parse time is
    // what catches this.
    let malformed_payload = ClassifierSigPayload {
        sha256: vec![0xAAu8; 31],
        abi_version: CLASSIFIER_ABI_VERSION,
        signer_kid: cft::FIXTURE_CLASSIFIER_KID.to_string(),
    };
    let inner_cbor = cft::cbor_encode_payload(&malformed_payload);
    let envelope = cft::sign_envelope_raw(
        inner_cbor,
        cft::FIXTURE_CLASSIFIER_KID,
        CLASSIFIER_AAD,
        &cft::fixture_signing_key(),
    );

    build_vector(
        "trej-121",
        "live-classifier-sig-payload-sha256-wrong-length",
        "Phase C.3-C live-crypto vector: valid outer COSE_Sign1 over an \
         inner CBOR payload whose `sha256` byte string is 31 bytes \
         (one short of SHA-256's 32-byte fixed width). Length gate \
         rejects at decode time → classifier-signature-payload-malformed.",
        "design-final.md §4.3: the classifier payload's hash field is \
         normatively 32 bytes. A decoder that silently zero-pads or \
         truncates would open a collision avenue; length enforcement is \
         mandatory, pre-crypto.",
        Some(hex::encode(&envelope)),
        Some(hex::encode(CLASSIFIER_WASM)),
        Some(classifier_anchor_def(cft::FIXTURE_CLASSIFIER_KID)),
        None,
        "reject",
        Some("classifier-signature-payload-malformed"),
        "critical",
    )
}

/// trej-122 — signed `abi_version=2`, Tariff's `policy_classifier_abi_version`
/// is absent so the expected value falls back to `CLASSIFIER_ABI_VERSION=1`.
/// `AbiVersionMismatch` → `classifier-abi-version-mismatch`.
fn build_trej_122_abi_version_mismatch() -> Value {
    let envelope = cft::sign_classifier_envelope(
        CLASSIFIER_WASM,
        ABI_V2,
        cft::FIXTURE_CLASSIFIER_KID,
        &cft::fixture_signing_key(),
    );

    build_vector(
        "trej-122",
        "live-classifier-sig-abi-version-mismatch",
        "Phase C.3-C live-crypto vector: classifier envelope signed with \
         abi_version=2 but Tariff policy pins abi_version=1 (default, \
         no policy override supplied). Mismatch MUST reject with \
         classifier-abi-version-mismatch before the hash path runs.",
        "design-final.md §4.3: the ABI version field is how the Tariff \
         signals which classifier generation it is willing to run. A \
         stale or forward-rolled version must be caught before \
         verify_classifier_hash executes — a higher abi could imply \
         changed guest↔host contracts.",
        Some(hex::encode(&envelope)),
        Some(hex::encode(CLASSIFIER_WASM)),
        Some(classifier_anchor_def(cft::FIXTURE_CLASSIFIER_KID)),
        None,
        "reject",
        Some("classifier-abi-version-mismatch"),
        "critical",
    )
}

/// trej-123 — signed `sha256(ALT_CLASSIFIER_WASM)` but the vector
/// supplies `wasm_bytes_classifier = hex(CLASSIFIER_WASM)`. Runtime
/// hash no longer matches committed hash → `WasmHashMismatch` →
/// `classifier-wasm-hash-mismatch`.
fn build_trej_123_wasm_hash_mismatch() -> Value {
    // Sign commits to the ALTERNATE blob's hash.
    let payload = ClassifierSigPayload {
        sha256: cft::sha256_of(ALT_CLASSIFIER_WASM).to_vec(),
        abi_version: CLASSIFIER_ABI_VERSION,
        signer_kid: cft::FIXTURE_CLASSIFIER_KID.to_string(),
    };
    let inner_cbor = cft::cbor_encode_payload(&payload);
    let envelope = cft::sign_envelope_raw(
        inner_cbor,
        cft::FIXTURE_CLASSIFIER_KID,
        CLASSIFIER_AAD,
        &cft::fixture_signing_key(),
    );

    build_vector(
        "trej-123",
        "live-classifier-sig-wasm-hash-mismatch",
        "Phase C.3-C live-crypto vector: envelope commits to \
         sha256(ALT_CLASSIFIER_WASM) but the vector supplies the \
         non-alternate CLASSIFIER_WASM blob for hashing. Mismatch MUST \
         reject with classifier-wasm-hash-mismatch.",
        "design-final.md §4.3: the sha256 field is the payload's \
         commitment to the exact WASM bytes the signer audited. A \
         swapped binary at deploy time must fail this comparison — \
         otherwise the signer's approval no longer applies to what \
         runs.",
        Some(hex::encode(&envelope)),
        // Vector carries the *non-alternate* blob so hash mismatches.
        Some(hex::encode(CLASSIFIER_WASM)),
        Some(classifier_anchor_def(cft::FIXTURE_CLASSIFIER_KID)),
        None,
        "reject",
        Some("classifier-wasm-hash-mismatch"),
        "critical",
    )
}

/// trej-124 — inner payload's `signer_kid` field carries
/// `FIXTURE_CLASSIFIER_KID`, but the outer COSE_Sign1 protected header's
/// `kid` is `IMPOSTOR_OUTER_KID`. The outer signature verifies (anchor
/// set maps `IMPOSTOR_OUTER_KID` → the real fixture pubkey), but the
/// inner/outer-kid consistency check fires → `SignerKidMismatch` →
/// `classifier-signer-kid-mismatch`.
fn build_trej_124_inner_kid_mismatch() -> Value {
    let payload = ClassifierSigPayload {
        sha256: cft::sha256_of(CLASSIFIER_WASM).to_vec(),
        abi_version: CLASSIFIER_ABI_VERSION,
        // Inner claims the real fixture kid…
        signer_kid: cft::FIXTURE_CLASSIFIER_KID.to_string(),
    };
    let inner_cbor = cft::cbor_encode_payload(&payload);
    // …while the outer envelope header advertises a different kid.
    let envelope = cft::sign_envelope_raw(
        inner_cbor,
        IMPOSTOR_OUTER_KID,
        CLASSIFIER_AAD,
        &cft::fixture_signing_key(),
    );

    // The anchor set registers IMPOSTOR_OUTER_KID → real fixture pk so
    // the outer MAC verifies. The mismatch surfaces EXCLUSIVELY at the
    // inner/outer-kid check — not before.
    let anchors = classifier_anchor_def(IMPOSTOR_OUTER_KID);

    build_vector(
        "trej-124",
        "live-classifier-sig-inner-kid-mismatch",
        "Phase C.3-C live-crypto vector: outer COSE_Sign1 header `kid` \
         is K_impostor_classifier_pk (anchor registers this kid against \
         the real fixture pubkey so the outer MAC verifies); inner \
         CBOR payload's signer_kid is K_fixture_classifier_pk. \
         Inner/outer mismatch MUST reject with \
         classifier-signer-kid-mismatch.",
        "design-final.md §4.3: duplicating the signer identity inside \
         the signed payload is defense-in-depth against header \
         substitution. An attacker who gains the ability to rewrite the \
         outer kid (but not the inner bytes) must still be caught by \
         the consistency gate — this vector pins that gate.",
        Some(hex::encode(&envelope)),
        Some(hex::encode(CLASSIFIER_WASM)),
        Some(anchors),
        None,
        "reject",
        Some("classifier-signer-kid-mismatch"),
        "critical",
    )
}

/// trej-125 — `cose_sign1_bytes_classifier` and `wasm_bytes_classifier`
/// are both populated, but `trust_anchor_keys_classifier` is absent.
/// The partial-triple arm in `tariff.rs` step 9.5 surfaces this as
/// `ClassifierSignatureInvalid` rather than silently skipping.
///
/// Security rationale: this models the plausible misconfiguration
/// where a Tariff ships a classifier envelope but forgets to declare
/// the anchor set. Silent acceptance would bypass the whole classifier
/// trust layer; the validator must reject the missing-anchors case
/// even when the bytes themselves would otherwise verify.
fn build_trej_125_partial_triple_missing_anchors() -> Value {
    let envelope = cft::happy_envelope(CLASSIFIER_WASM);

    build_vector(
        "trej-125",
        "live-classifier-sig-partial-triple-missing-anchors",
        "Phase C.3-C live-crypto vector: a perfectly-signed envelope + \
         valid wasm bytes are supplied but the Tariff input omits \
         trust_anchor_keys_classifier. tariff.rs step 9.5 treats any \
         partial triple as an authoring error and rejects with \
         classifier-signature-invalid — silent acceptance would bypass \
         classifier trust entirely.",
        "design-final.md §4.3: presence of the classifier envelope \
         fields is an all-or-nothing contract. A Tariff that declares \
         a classifier signature without anchors is not exempt — it is \
         malformed, and the validator must refuse to classify it.",
        Some(hex::encode(&envelope)),
        Some(hex::encode(CLASSIFIER_WASM)),
        // Anchors deliberately absent.
        None,
        None,
        "reject",
        Some("classifier-signature-invalid"),
        "critical",
    )
}

// ─── Accept builders ────────────────────────────────────────────────────────

/// trej-126 — happy path under the default ABI version (= 1). The
/// envelope is a canonical `cft::happy_envelope` signed by the fixture
/// key, the anchor set registers `FIXTURE_CLASSIFIER_KID` against the
/// fixture pubkey, and `policy_classifier_abi_version` is absent so
/// the expected ABI falls back to `CLASSIFIER_ABI_VERSION`.
fn build_trej_126_accept_default_abi() -> Value {
    let envelope = cft::happy_envelope(CLASSIFIER_WASM);

    build_vector(
        "trej-126",
        "live-classifier-sig-happy-default-abi",
        "Phase C.3-C live-crypto accept: canonical classifier envelope \
         signed under abi_version=CLASSIFIER_ABI_VERSION, matching hash, \
         matching kid, registered anchor. Validator reaches the end of \
         step 9.5 without rejecting and continues to steps 10-13 which \
         also pass (empty category, no version skew, no validity \
         window). Outcome: accept.",
        "design-final.md §4.3: the happy-path vector is the positive \
         control. Without it, a validator that always rejects at step \
         9.5 would pass every reject vector and appear conformant — \
         this vector makes that failure mode observable.",
        Some(hex::encode(&envelope)),
        Some(hex::encode(CLASSIFIER_WASM)),
        Some(classifier_anchor_def(cft::FIXTURE_CLASSIFIER_KID)),
        None,
        "accept",
        None,
        "high",
    )
}

/// trej-127 — happy path with `policy_classifier_abi_version = 2` and a
/// signed payload whose `abi_version` field is also 2. Confirms the
/// override is actually honoured — a validator that ignored the policy
/// override and always compared against `CLASSIFIER_ABI_VERSION` (=1)
/// would reject this vector with abi-version-mismatch.
fn build_trej_127_accept_abi_override() -> Value {
    let envelope = cft::sign_classifier_envelope(
        CLASSIFIER_WASM,
        ABI_V2,
        cft::FIXTURE_CLASSIFIER_KID,
        &cft::fixture_signing_key(),
    );

    build_vector(
        "trej-127",
        "live-classifier-sig-happy-abi-override",
        "Phase C.3-C live-crypto accept: envelope signed with \
         abi_version=2, Tariff sets policy_classifier_abi_version=2, \
         other fields match the happy path. Validator MUST accept — \
         pins that the override actually takes effect.",
        "design-final.md §4.3: the policy_classifier_abi_version \
         override is how a Tariff opts into a future classifier \
         generation. A validator that silently ignored the override \
         (and kept comparing against the hard-coded 1) would pass \
         trej-122 and fail trej-127 — that asymmetry is exactly what \
         this vector detects.",
        Some(hex::encode(&envelope)),
        Some(hex::encode(CLASSIFIER_WASM)),
        Some(classifier_anchor_def(cft::FIXTURE_CLASSIFIER_KID)),
        Some(ABI_V2),
        "accept",
        None,
        "high",
    )
}

// ─── JSON helpers ───────────────────────────────────────────────────────────

/// Build the per-vector `trust_anchor_keys_classifier` array. The
/// anchor definition carries no explicit `role` override, so
/// `tariff.rs` step 9.5 stamps each entry as
/// `AnchorRole::ClassifierSigner` via `build_anchor_set`.
fn classifier_anchor_def(kid: &str) -> Value {
    json!([
        {
            "kid": kid,
            "alg": "ed25519",
            "pk_hex": cft::fixture_verifying_key_hex(),
        }
    ])
}

/// Build the `signature_verification_context` for a Tariff step-6 pass.
/// Every C.3-C vector uses the same context because the outer tariff
/// signature is not the thing under test — only step 9.5 is.
fn base_signature_verification_context() -> Value {
    json!({
        "signer_key_id": "K_tariff_signer_pk_TEST",
        "trust_anchors": ["K_cust_root_pk_TEST"],
        "signature_valid_under_current_bytes": true
    })
}

/// Assemble the full tariff-reject-shape vector JSON around the
/// supplied classifier-sig inputs. Shape matches the fields deserialised
/// by `crates/ephemeral-core/src/suites/tariff.rs::TariffInput`.
///
/// Each of `cose_hex` / `wasm_hex` / `anchors` is optional so partial-
/// triple vectors (trej-125) can omit individual fields without
/// emitting `null` keys — the deserialiser treats absent and null keys
/// equivalently via `#[serde(default)]`, but omission is cleaner in
/// git diff.
#[allow(clippy::too_many_arguments)]
fn build_vector(
    id: &str,
    category: &str,
    description: &str,
    rationale: &str,
    cose_hex: Option<String>,
    wasm_hex: Option<String>,
    anchors: Option<Value>,
    abi_override: Option<u32>,
    outcome: &str,
    reject_code: Option<&str>,
    severity: &str,
) -> Value {
    let mut input = serde_json::Map::new();
    input.insert(
        "tariff_cbor_hex".into(),
        json!(
            "<placeholder: live-crypto vector drives verification via cose_sign1_bytes_classifier>"
        ),
    );
    input.insert(
        "signature_verification_context".into(),
        base_signature_verification_context(),
    );
    input.insert("current_time".into(), json!(CURRENT_TIME));
    input.insert("previously_seen_version".into(), json!(PREV_VERSION));
    if let Some(c) = cose_hex {
        input.insert("cose_sign1_bytes_classifier".into(), json!(c));
    }
    if let Some(w) = wasm_hex {
        input.insert("wasm_bytes_classifier".into(), json!(w));
    }
    if let Some(a) = anchors {
        input.insert("trust_anchor_keys_classifier".into(), a);
    }
    if let Some(v) = abi_override {
        input.insert("policy_classifier_abi_version".into(), json!(v));
    }

    let expected = match (outcome, reject_code) {
        ("reject", Some(code)) => json!({ "outcome": "reject", "reject_code": code }),
        ("accept", None) => json!({ "outcome": "accept" }),
        (o, rc) => {
            panic!("build_vector: outcome={o:?} reject_code={rc:?} is not a supported combination")
        }
    };

    json!({
        "id": id,
        "category": category,
        "description": description,
        "input": Value::Object(input),
        "expected": expected,
        "rationale": rationale,
        "redteam_refs": ["PHASE-C3-C-LIVE"],
        "severity_if_failed": severity,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // `CoseSign1::from_slice` is an inherent-style method provided by the
    // `CborSerializable` trait; it cannot be called without the trait in
    // scope.  We only need it inside tests that round-trip COSE_Sign1
    // bytes back to a parsed header + payload.
    use coset::CborSerializable;
    use ephemeral_core::TariffRejectCode;

    #[test]
    fn build_all_returns_eight_unique_ids() {
        let v = build_all();
        assert_eq!(v.len(), 8);
        let ids: Vec<_> = v.iter().map(|x| x["id"].as_str().unwrap()).collect();
        for id in &ids {
            assert!(id.starts_with("trej-12"));
        }
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 8, "ids must be unique");
    }

    #[test]
    fn build_all_produces_expected_outcomes() {
        // Reject codes taken from `TariffRejectCode`'s Display impl —
        // if a variant is renamed this refreshes automatically and any
        // mismatched vector surfaces here.
        let sig_invalid = TariffRejectCode::ClassifierSignatureInvalid.to_string();
        let payload_malformed = TariffRejectCode::ClassifierSignaturePayloadMalformed.to_string();
        let abi_mismatch = TariffRejectCode::ClassifierAbiVersionMismatch.to_string();
        let hash_mismatch = TariffRejectCode::ClassifierWasmHashMismatch.to_string();
        let kid_mismatch = TariffRejectCode::ClassifierSignerKidMismatch.to_string();

        let v = build_all();
        let expected: [(&str, &str, Option<&str>); 8] = [
            ("trej-120", "reject", Some(sig_invalid.as_str())),
            ("trej-121", "reject", Some(payload_malformed.as_str())),
            ("trej-122", "reject", Some(abi_mismatch.as_str())),
            ("trej-123", "reject", Some(hash_mismatch.as_str())),
            ("trej-124", "reject", Some(kid_mismatch.as_str())),
            ("trej-125", "reject", Some(sig_invalid.as_str())),
            ("trej-126", "accept", None),
            ("trej-127", "accept", None),
        ];
        for (i, (id, outcome, code)) in expected.iter().enumerate() {
            let got_id = v[i]["id"].as_str().unwrap();
            let got_outcome = v[i]["expected"]["outcome"].as_str().unwrap();
            assert_eq!(got_id, *id, "vector index {i} id mismatch");
            assert_eq!(got_outcome, *outcome, "vector {id} outcome mismatch");
            match code {
                Some(c) => {
                    let got_code = v[i]["expected"]["reject_code"].as_str().unwrap();
                    assert_eq!(got_code, *c, "vector {id} reject_code mismatch");
                }
                None => assert!(
                    v[i]["expected"].get("reject_code").is_none(),
                    "vector {id} must not carry reject_code for accept outcome"
                ),
            }
        }
    }

    #[test]
    fn determinism_two_runs_produce_identical_bytes() {
        let a = serde_json::to_string(&build_all()).unwrap();
        let b = serde_json::to_string(&build_all()).unwrap();
        assert_eq!(a, b, "build_all must be byte-deterministic");
    }

    #[test]
    fn trej_121_payload_sha256_is_31_bytes() {
        // Pin the wrong-length property so a refactor that accidentally
        // pads to 32 bytes is caught at test time, not at conformance
        // time.
        let v = build_trej_121_payload_sha256_wrong_length();
        let cose_hex = v["input"]["cose_sign1_bytes_classifier"]
            .as_str()
            .expect("cose hex present");
        let cose_bytes = hex::decode(cose_hex).expect("valid hex");
        let sign1 = coset::CoseSign1::from_slice(&cose_bytes).expect("parse COSE_Sign1");
        let inner = sign1.payload.expect("inner payload present");
        // Decode ciborium → Value and walk to the sha256 byte string.
        let val: ciborium::Value =
            ciborium::from_reader(&inner[..]).expect("inner is canonical cbor");
        let map = val.as_map().expect("inner is a map");
        let sha = map
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(t) if t == "sha256" => v.as_bytes(),
                _ => None,
            })
            .expect("sha256 field present");
        assert_eq!(
            sha.len(),
            31,
            "trej-121 must carry a 31-byte sha256 to exercise the length gate"
        );
    }

    #[test]
    fn trej_124_inner_and_outer_kid_diverge() {
        let v = build_trej_124_inner_kid_mismatch();
        let cose_hex = v["input"]["cose_sign1_bytes_classifier"].as_str().unwrap();
        let cose_bytes = hex::decode(cose_hex).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&cose_bytes).unwrap();
        let outer_kid = std::str::from_utf8(&sign1.protected.header.key_id)
            .expect("kid is utf-8")
            .to_owned();
        assert_eq!(outer_kid, IMPOSTOR_OUTER_KID);

        // Directly decode the inner CBOR payload and assert that
        // `signer_kid` is FIXTURE_CLASSIFIER_KID (NOT the impostor).
        // A refactor that accidentally signed the inner payload with
        // `signer_kid = IMPOSTOR_OUTER_KID` would collapse the
        // inner/outer divergence and silently degrade trej-124 into
        // a happy-path vector — this assertion catches that.
        let inner = sign1.payload.expect("inner payload present");
        let val: ciborium::Value =
            ciborium::from_reader(&inner[..]).expect("inner is canonical cbor");
        let inner_kid = val
            .as_map()
            .expect("inner is a map")
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(t) if t == "signer_kid" => v.as_text(),
                _ => None,
            })
            .expect("signer_kid field present");
        assert_eq!(
            inner_kid,
            cft::FIXTURE_CLASSIFIER_KID,
            "trej-124's inner signer_kid must stay FIXTURE to exercise the \
             inner/outer divergence",
        );
        assert_ne!(
            inner_kid, IMPOSTOR_OUTER_KID,
            "inner and outer kid must differ",
        );

        // Anchor wiring registers the IMPOSTOR outer kid against the
        // real fixture pk so the outer COSE layer verifies cleanly —
        // the mismatch must surface purely at the inner/outer check.
        let anchors = v["input"]["trust_anchor_keys_classifier"]
            .as_array()
            .unwrap();
        assert_eq!(anchors[0]["kid"].as_str().unwrap(), IMPOSTOR_OUTER_KID);
    }

    #[test]
    fn trej_125_has_no_trust_anchor_keys_classifier() {
        let v = build_trej_125_partial_triple_missing_anchors();
        assert!(
            v["input"].get("trust_anchor_keys_classifier").is_none(),
            "trej-125 must omit trust_anchor_keys_classifier to exercise the partial-triple arm"
        );
        assert!(
            v["input"].get("cose_sign1_bytes_classifier").is_some(),
            "trej-125 must still carry cose_sign1_bytes_classifier"
        );
        assert!(
            v["input"].get("wasm_bytes_classifier").is_some(),
            "trej-125 must still carry wasm_bytes_classifier"
        );
    }

    #[test]
    fn trej_123_signed_hash_differs_from_supplied_wasm() {
        let v = build_trej_123_wasm_hash_mismatch();
        let cose_hex = v["input"]["cose_sign1_bytes_classifier"].as_str().unwrap();
        let wasm_hex = v["input"]["wasm_bytes_classifier"].as_str().unwrap();
        let wasm_bytes = hex::decode(wasm_hex).unwrap();
        let supplied_hash = cft::sha256_of(&wasm_bytes);

        let cose_bytes = hex::decode(cose_hex).unwrap();
        let sign1 = coset::CoseSign1::from_slice(&cose_bytes).unwrap();
        let inner = sign1.payload.unwrap();
        let val: ciborium::Value = ciborium::from_reader(&inner[..]).unwrap();
        let signed_hash = val
            .as_map()
            .unwrap()
            .iter()
            .find_map(|(k, v)| match k {
                ciborium::Value::Text(t) if t == "sha256" => v.as_bytes(),
                _ => None,
            })
            .unwrap();

        assert_ne!(
            signed_hash,
            &supplied_hash[..],
            "signed hash must differ from hash of supplied wasm for trej-123 to be meaningful"
        );
    }
}
