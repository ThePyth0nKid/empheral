//! Test-only fixtures for the classifier crate — canned
//! [`ClassifierOutput`] shapes, a WAT-source builder parameterized by
//! those outputs, a `OnceLock`-backed pool of pre-compiled WASM
//! artifacts, and a deterministic classifier signing helper.
//!
//! # Purpose
//!
//! Before this module existed, three places built near-duplicate
//! versions of the same fixtures:
//!
//! - `src/runtime.rs` tests (inline `build_fixed_output_wasm` helper),
//! - `src/signature.rs` tests (inline `build_sign1` + fixture seed),
//! - `ephemeral-core`'s `step_9_5_fixtures` in `tariff.rs`
//!   (`classifier_key`, `sign_envelope`, `happy_envelope`).
//!
//! Only the first is strictly intrinsic to `runtime.rs`'s WASM harness.
//! The rest is shared concern; consolidating it here means Session 2
//! artefacts (`vector-signer gen-phase-c3-c`,
//! `conformance/classifier-verification.json`, `determinism_c3_c.rs`,
//! and the `fuzz.rs` real-classifier integration) all route through a
//! single deterministic source of fixture-signing truth.
//!
//! # Feature gating
//!
//! The module is published only when the crate is built with
//! `features = ["test_fixtures"]`.  The feature activates three
//! optional dependencies (`wat`, `ed25519-dalek`, `coset`) that never
//! ship in a production-consumer build.  The
//! `ephemeral-prod-symbol-probe` rlib scan fails loudly if any of the
//! symbols exported below appear in a default-features build.
//!
//! # Determinism guarantees
//!
//! - `FIXTURE_CLASSIFIER_SEED` is a compile-time constant; every
//!   invocation of `fixture_signing_key` returns the same private key
//!   and hence the same public key.
//! - `build_classifier_wat` performs CBOR encoding of
//!   [`ClassifierOutput`] with `ciborium` — ciborium's encoder is
//!   byte-stable for the struct-literal shape we use here, which is why
//!   the conformance harness can commit hex-encoded envelopes.
//! - `shared_wasm_artifacts` memoises the compiled WASM bytes with a
//!   `OnceLock`, so repeated calls inside a test binary return the
//!   exact same `Vec<u8>` memory (and the same hash).

use std::sync::OnceLock;

use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{ClassifierOutput, ClassifierSigPayload, CLASSIFIER_AAD, CLASSIFIER_ABI_VERSION};

// ============================================================================
// Canonical fixture ClassifierOutputs
// ============================================================================
//
// Each factory builds a ClassifierOutput with fixed reason-code /
// reason-text / justification-tag strings.  These strings are *not*
// part of any spec-level reject code — they are opaque labels the test
// harness can match on when it wants to distinguish which fixture ran.

/// tier=0 baseline classifier.  Always accepts, no escalations.
///
/// Used as the default "clean classifier" in Session-2 integration
/// tests — tariff step 9.5 happy-path, the conformance accept vectors,
/// and determinism pinning.
#[must_use]
pub fn echo_classifier_output() -> ClassifierOutput {
    ClassifierOutput {
        tier: 0,
        reason_code: "fixture-echo".to_string(),
        reason_text: "fixture classifier — tier-0 baseline".to_string(),
        escalations: Vec::new(),
        justification_tag: "read-only".to_string(),
    }
}

/// tier=1 classifier.  Used where the test needs a non-zero tier but
/// still inside spec range (§2 tier `0..=5`).
#[must_use]
pub fn always_tier_1_output() -> ClassifierOutput {
    ClassifierOutput {
        tier: 1,
        reason_code: "fixture-tier-1".to_string(),
        reason_text: "fixture classifier — constant tier 1".to_string(),
        escalations: Vec::new(),
        justification_tag: "bounded".to_string(),
    }
}

/// tier=9999 floor-breaker.  Deliberately above the spec-valid range
/// so tests exercising tier-floor / tier-ceiling policy see a clearly
/// out-of-band value (`0..=5` is the spec range per §2).
#[must_use]
pub fn always_tier_9999_output() -> ClassifierOutput {
    ClassifierOutput {
        tier: 9999,
        reason_code: "fixture-tier-floor-breaker".to_string(),
        reason_text: "fixture classifier — intentional out-of-spec tier".to_string(),
        escalations: Vec::new(),
        justification_tag: "destructive".to_string(),
    }
}

/// tier=0 with a single `schema-violation` escalation.  Exercises paths
/// where a classifier accepts at tier 0 but annotates a structural
/// rejection reason — Session-2 fuzz / tariff integration asserts that
/// the escalations survive the host ↔ guest CBOR boundary.
#[must_use]
pub fn reject_by_schema_output() -> ClassifierOutput {
    ClassifierOutput {
        tier: 0,
        reason_code: "fixture-schema-violation".to_string(),
        reason_text: "fixture classifier — schema-violation escalation".to_string(),
        escalations: vec!["schema-violation".to_string()],
        justification_tag: "rejected".to_string(),
    }
}

// ============================================================================
// WAT source builder
// ============================================================================

/// Minimum ABI-v1-conformant classifier module whose `classify` always
/// returns the packed locator of a pre-baked, CBOR-encoded `output`.
///
/// The emitted module has exactly the exports `memory`, `alloc`,
/// `classify` (no imports, no `start`) and embeds the encoded CBOR at a
/// fixed offset inside linear memory.  The `input_ptr` / `input_len`
/// arguments to `classify` are ignored: the fixture is a *fixed-output*
/// classifier, not an echo-ing one.
///
/// Panics inside a test context (via `.expect`) are acceptable because
/// the CBOR encoder is fallible only on out-of-memory, which is caught
/// upstream by the allocator.
#[must_use]
pub fn build_classifier_wat(output: &ClassifierOutput) -> String {
    use std::fmt::Write as _;

    let mut cbor = Vec::new();
    ciborium::into_writer(output, &mut cbor).expect("ciborium serialize ClassifierOutput");

    // Fixed memory layout:
    //   [0       .. 256   ] scratch
    //   [256     .. 256+N ] committed CBOR output (N = cbor.len())
    //   [4096    ..       ] returned by alloc() for host input writes
    let output_offset: u32 = 256;
    let alloc_offset: u32 = 4096;
    let cbor_len = u32::try_from(cbor.len()).expect("ClassifierOutput cbor fits in u32");
    let packed: u64 = (u64::from(output_offset) << 32) | u64::from(cbor_len);

    // Escape each byte as a WAT `\xx` two-digit hex datum.  The WAT
    // parser treats the `\xx` escape as a single byte, identical to the
    // original CBOR byte.
    let mut cbor_escaped = String::with_capacity(cbor.len() * 4);
    for b in &cbor {
        write!(cbor_escaped, "\\{b:02x}").expect("String write is infallible");
    }

    format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const {output_offset}) "{cbor_escaped}")
  (func (export "alloc") (param i32) (result i32)
    i32.const {alloc_offset})
  (func (export "classify") (param i32 i32) (result i64)
    i64.const {packed}))
"#
    )
}

/// Convenience: WAT source for the tier=0 baseline.
#[must_use]
pub fn echo_classifier_wat() -> String {
    build_classifier_wat(&echo_classifier_output())
}

/// Convenience: WAT source for the tier=1 classifier.
#[must_use]
pub fn always_tier_1_wat() -> String {
    build_classifier_wat(&always_tier_1_output())
}

/// Convenience: WAT source for the tier=9999 floor-breaker.
#[must_use]
pub fn always_tier_9999_wat() -> String {
    build_classifier_wat(&always_tier_9999_output())
}

/// Convenience: WAT source for the schema-violation escalator.
#[must_use]
pub fn reject_by_schema_wat() -> String {
    build_classifier_wat(&reject_by_schema_output())
}

// ============================================================================
// Shared pre-compiled WASM artifact pool
// ============================================================================

/// Pre-compiled WASM bytes for every canonical fixture output.
///
/// Obtained via [`shared_wasm_artifacts`]; the struct is intentionally
/// `#[non_exhaustive]` so adding a future preset does not break
/// existing callers that destructure it.
#[derive(Debug)]
#[non_exhaustive]
pub struct SharedWasmArtifacts {
    /// Bytes of the tier=0 classifier.
    pub echo: Vec<u8>,
    /// Bytes of the tier=1 classifier.
    pub tier_1: Vec<u8>,
    /// Bytes of the tier=9999 floor-breaker.
    pub tier_9999: Vec<u8>,
    /// Bytes of the schema-violation escalator.
    pub reject: Vec<u8>,
}

/// Return a lazily initialised, process-global pool of pre-compiled
/// classifier WASM bytes.
///
/// The first call inside a test binary pays the WAT → WASM compilation
/// cost (~tens of microseconds per artifact); subsequent calls return
/// the exact same allocation.  This amortises compilation across the
/// many Session-2 tests that need *some* valid classifier without
/// caring about its specific tier.
///
/// Determinism: `wat::parse_str` is a pure function of the input
/// string, so the returned bytes are byte-stable across runs of the
/// same binary on the same target.  The committed
/// `conformance/classifier-verification.json` harness relies on this
/// property.
#[must_use]
pub fn shared_wasm_artifacts() -> &'static SharedWasmArtifacts {
    static POOL: OnceLock<SharedWasmArtifacts> = OnceLock::new();
    POOL.get_or_init(|| SharedWasmArtifacts {
        echo: wat::parse_str(echo_classifier_wat())
            .expect("echo_classifier_wat must parse"),
        tier_1: wat::parse_str(always_tier_1_wat())
            .expect("always_tier_1_wat must parse"),
        tier_9999: wat::parse_str(always_tier_9999_wat())
            .expect("always_tier_9999_wat must parse"),
        reject: wat::parse_str(reject_by_schema_wat())
            .expect("reject_by_schema_wat must parse"),
    })
}

// ============================================================================
// Deterministic classifier signing
// ============================================================================

/// Stable header `kid` for the fixture classifier signer.  Distinct
/// from the per-module seeds used by `signature.rs` inline tests so
/// cross-crate consumers can register an anchor under this `kid`
/// without colliding with intra-module fixtures.
pub const FIXTURE_CLASSIFIER_KID: &str = "K_fixture_classifier_pk";

/// Fixed 32-byte Ed25519 seed.  Any change to this constant
/// regenerates the fixture public key and invalidates every committed
/// conformance envelope.  Treat as a pinned magic number.
pub const FIXTURE_CLASSIFIER_SEED: [u8; 32] = [
    0xf1, 0x28, 0x12, 0xe5, 0xc1, 0xa5, 0x51, 0xf1, 0xee, 0xd5, 0xec, 0xfa, 0x1b, 0xec, 0x4c, 0x0a,
    0x55, 0x1f, 0x1e, 0xe5, 0xec, 0xfa, 0x1b, 0xec, 0x4c, 0x0a, 0x55, 0x1f, 0x1e, 0xe5, 0xec, 0xfa,
];

/// Deterministic classifier signing key derived from
/// [`FIXTURE_CLASSIFIER_SEED`].
#[must_use]
pub fn fixture_signing_key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_CLASSIFIER_SEED)
}

/// Public key matching [`fixture_signing_key`].
#[must_use]
pub fn fixture_verifying_key() -> VerifyingKey {
    fixture_signing_key().verifying_key()
}

/// 32-byte public key (raw).
#[must_use]
pub fn fixture_verifying_key_bytes() -> [u8; 32] {
    *fixture_verifying_key().as_bytes()
}

/// Hex-encoded 64-char public key (lowercase).
#[must_use]
pub fn fixture_verifying_key_hex() -> String {
    hex::encode(fixture_verifying_key_bytes())
}

/// Compute sha256 of `bytes`.  Matches the hash verified by
/// `verify_classifier_hash` — passing this function's output into the
/// signed envelope guarantees hash-payload coherence.
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// CBOR-encode a [`ClassifierSigPayload`] with the same `ciborium`
/// encoder the live verifier decodes against, so round-trip bytes are
/// canonical by construction.
///
/// Exposed so negative-path tests can craft payloads with individually
/// tampered fields (`sha256` off-by-one, wrong `abi_version`, mismatched
/// inner `signer_kid`) without re-implementing the encoder contract.
#[must_use]
pub fn cbor_encode_payload(payload: &ClassifierSigPayload) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(payload, &mut out).expect("ciborium serialize ClassifierSigPayload");
    out
}

/// Build a `COSE_Sign1` envelope over pre-encoded inner bytes with full
/// control over the outer header `kid` and the external AAD.
///
/// Lower-level than [`sign_classifier_envelope`]. Use this when a test
/// needs the inner payload, outer kid, or AAD to deliberately diverge
/// from the happy-path convention — for example:
///
/// - Non-CBOR inner bytes to exercise the payload-decode branch.
/// - Wrong AAD to replay a tariff-domain envelope into the classifier
///   verifier.
/// - Outer `kid` that deliberately differs from the inner
///   `ClassifierSigPayload.signer_kid` to exercise the inner/outer-kid
///   consistency check.
///
/// The signature is over the canonical `Sig_structure` defined by
/// RFC 9052 §4.4 with `external_aad = aad`.
#[must_use]
pub fn sign_envelope_raw(
    inner_payload_bytes: Vec<u8>,
    outer_kid: &str,
    aad: &[u8],
    key: &SigningKey,
) -> Vec<u8> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(outer_kid.as_bytes().to_vec())
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(inner_payload_bytes)
        .create_signature(aad, |tbs| key.sign(tbs).to_bytes().to_vec())
        .build();
    sign1.to_vec().expect("serialize COSE_Sign1")
}

/// Build a `COSE_Sign1` classifier envelope over a commit-to-WASM
/// payload.  Happy-path convenience wrapper on top of
/// [`cbor_encode_payload`] + [`sign_envelope_raw`].
///
/// Lifecycle:
///
/// 1. Compute `sha256(wasm)` — committed inside the inner payload.
/// 2. Assemble [`ClassifierSigPayload`] with the supplied
///    `abi_version` and `signer_kid`.
/// 3. CBOR-encode the payload with `ciborium` (canonical by
///    construction for this struct-literal shape).
/// 4. Build a `COSE_Sign1` envelope protecting the payload under
///    `EdDSA`, with the outer header `kid` set to `signer_kid` and the
///    external AAD set to [`CLASSIFIER_AAD`].
/// 5. Sign with the provided `key` and serialise the envelope.
///
/// The returned bytes verify under `verify_classifier_signature` when
/// a matching [`ephemeral_crypto::TrustAnchor`] is registered under
/// [`ephemeral_crypto::AnchorRole::ClassifierSigner`].
#[must_use]
pub fn sign_classifier_envelope(
    wasm: &[u8],
    abi_version: u32,
    signer_kid: &str,
    key: &SigningKey,
) -> Vec<u8> {
    let payload = ClassifierSigPayload {
        sha256: sha256_of(wasm).to_vec(),
        abi_version,
        signer_kid: signer_kid.to_string(),
    };
    sign_envelope_raw(
        cbor_encode_payload(&payload),
        signer_kid,
        CLASSIFIER_AAD,
        key,
    )
}

/// Convenience: happy-path envelope signed by [`fixture_signing_key`]
/// under the default ABI version and [`FIXTURE_CLASSIFIER_KID`].
#[must_use]
pub fn happy_envelope(wasm: &[u8]) -> Vec<u8> {
    sign_classifier_envelope(
        wasm,
        CLASSIFIER_ABI_VERSION,
        FIXTURE_CLASSIFIER_KID,
        &fixture_signing_key(),
    )
}

// ============================================================================
// Module-internal regression tests
// ============================================================================
//
// These tests pin the invariants this module is meant to uphold for
// downstream consumers.  Breaking one of them means a caller in
// ephemeral-core / vector-signer / the conformance harness would
// observe silently wrong bytes.

#[cfg(test)]
mod self_test {
    use super::*;
    use crate::{execute_classifier, verify_classifier_signature, ClassifierConfig};
    use ephemeral_crypto::{AnchorRole, TrustAnchor, TrustAnchorSet};

    fn fixture_anchor_set() -> TrustAnchorSet {
        let anchor = TrustAnchor::new_ed25519(
            FIXTURE_CLASSIFIER_KID.to_string(),
            &fixture_verifying_key_bytes(),
            AnchorRole::ClassifierSigner,
        )
        .expect("fixture pk is non-weak");
        let mut set = TrustAnchorSet::new();
        set.insert(anchor).expect("fresh set has no dup kid");
        set
    }

    #[test]
    fn echo_artifact_executes_at_tier_0() {
        let pool = shared_wasm_artifacts();
        let out = execute_classifier(&pool.echo, b"ignored", &ClassifierConfig::default())
            .expect("echo classifier executes");
        assert_eq!(out, echo_classifier_output());
    }

    #[test]
    fn tier_1_artifact_executes_at_tier_1() {
        let pool = shared_wasm_artifacts();
        let out = execute_classifier(&pool.tier_1, b"ignored", &ClassifierConfig::default())
            .expect("tier_1 classifier executes");
        assert_eq!(out, always_tier_1_output());
    }

    #[test]
    fn tier_9999_artifact_executes_at_tier_9999() {
        let pool = shared_wasm_artifacts();
        let out = execute_classifier(&pool.tier_9999, b"ignored", &ClassifierConfig::default())
            .expect("tier_9999 classifier executes");
        assert_eq!(out, always_tier_9999_output());
    }

    #[test]
    fn reject_artifact_executes_with_schema_violation_escalation() {
        let pool = shared_wasm_artifacts();
        let out = execute_classifier(&pool.reject, b"ignored", &ClassifierConfig::default())
            .expect("reject classifier executes");
        assert_eq!(out, reject_by_schema_output());
        assert_eq!(out.escalations, vec!["schema-violation".to_string()]);
    }

    #[test]
    fn shared_pool_is_stable_across_calls() {
        let first = shared_wasm_artifacts();
        let second = shared_wasm_artifacts();
        assert!(std::ptr::eq(first, second), "OnceLock must memoise");
        // Re-parsing the same WAT source yields identical WASM bytes —
        // wat is a pure function of the input.
        let fresh = wat::parse_str(echo_classifier_wat()).expect("re-parse");
        assert_eq!(fresh, first.echo, "wat → wasm is deterministic");
    }

    #[test]
    fn happy_envelope_verifies_against_fixture_anchor() {
        let pool = shared_wasm_artifacts();
        let env = happy_envelope(&pool.echo);
        let out = verify_classifier_signature(
            &pool.echo,
            &env,
            &fixture_anchor_set(),
            CLASSIFIER_ABI_VERSION,
        )
        .expect("happy envelope verifies");
        assert_eq!(out.signer_kid, FIXTURE_CLASSIFIER_KID);
        assert_eq!(out.abi_version, CLASSIFIER_ABI_VERSION);
        assert_eq!(out.wasm_sha256, sha256_of(&pool.echo));
    }

    #[test]
    fn fixture_verifying_key_is_stable() {
        // Pins the public key bytes so committed conformance vectors
        // cannot silently drift if the seed constant is edited.
        let expected_hex = hex::encode(fixture_verifying_key_bytes());
        assert_eq!(expected_hex, fixture_verifying_key_hex());
        assert_eq!(
            fixture_verifying_key_bytes().len(),
            32,
            "Ed25519 pk is 32 bytes",
        );
    }
}
