//! Feature-leak guard probe — **NOT a production tool.**
//!
//! This binary is built by CI (`feature-leak-guard` job) and by the
//! local integration test `tests/no_leak.rs`. Its sole job is to link
//! against `ephemeral-core`, `ephemeral-classifier`, AND
//! `ephemeral-anomaly` with `default-features = false` and to
//! reference enough of each crate's public API that the linker keeps
//! real code in the final binary (otherwise dead-code elimination
//! would produce an empty binary and the no-leak assertion would be
//! trivially true).
//!
//! What the downstream check asserts:
//! - The symbols `insert_trusted_der_for_test`, `classify_live_nitro`,
//!   `insert_trusted_key_for_test`, `classify_live_rekor` (all gated
//!   behind `ephemeral-core` / `ephemeral-attestation`'s `test-fixtures`
//!   feature) are ABSENT.
//! - The symbols `shared_wasm_artifacts`, `sign_classifier_envelope`,
//!   `fixture_signing_key`, `build_classifier_wat`,
//!   `cbor_encode_payload`, `sign_envelope_raw` (all gated behind
//!   `ephemeral-classifier`'s `test_fixtures` feature) are ABSENT.
//! - The controls `total_failing` (ephemeral-core),
//!   `sha256_fingerprint` (ephemeral-attestation),
//!   `verify_classifier_hash` (ephemeral-classifier), and
//!   `verify_anomaly_library_signature` (ephemeral-anomaly) are
//!   PRESENT — proving the check is not trivially empty.
//!
//! If you add new feature-gated items to any of the four crates,
//! extend the assertions in `tests/no_leak.rs` to include them.
//!
//! Phase C.4 Session 2 populated the anomaly forbidden list with
//! `fixture_anomaly_signing_key`, `fixture_anomaly_verifying_key`,
//! `sign_anomaly_library_envelope`, `shared_anomaly_artifacts`,
//! `cbor_encode_anomaly_payload`, and `minimum_anomaly_library`.
//! Any later addition to `ephemeral-anomaly::test_fixtures` that
//! is not strictly a trivial `PatternEntry` constructor should
//! extend that list to preserve the coverage floor.

use std::hint::black_box;

use ephemeral_anomaly::{verify_anomaly_library_signature, MAX_ANOMALY_LIBRARY_BYTES};
use ephemeral_classifier::{execute_classifier, verify_classifier_hash, ClassifierConfig};
use ephemeral_core::{run_many, schema::CompiledSchema, RunConfig, VectorSuite};

fn main() {
    // Force the linker to retain the symbols we want to positively detect.
    // `black_box` defeats const-folding / dead-code elimination on the
    // function pointers. We never actually invoke these — we only need
    // their addresses to stay in the binary.
    let load_ptr: fn(&std::path::Path) -> _ = CompiledSchema::load;
    let run_ptr: fn(&[std::path::PathBuf], &RunConfig<'_>) -> _ = run_many;
    let _ = black_box(load_ptr);
    let _ = black_box(run_ptr);
    // Reference an enum variant so name mangling keeps the enum alive.
    let _ = black_box(VectorSuite::PcrAttestationReject);

    // Classifier-crate positive controls.  These are unconditionally
    // public (no feature gate); if they vanish from the rlib the
    // classifier-side negative checks become meaningless.
    let verify_ptr: fn(&[u8], &str) -> _ = verify_classifier_hash;
    let exec_ptr: fn(&[u8], &[u8], &ClassifierConfig) -> _ = execute_classifier;
    let _ = black_box(verify_ptr);
    let _ = black_box(exec_ptr);

    // Anomaly-crate positive control: `verify_anomaly_library_signature`
    // is unconditionally public (no feature gate); black-boxing its
    // address guarantees the function survives DCE under the
    // `symbol-probe` profile so the negative checks against future
    // Session-2 test_fixtures symbols have meaning.  The const
    // reference prevents the whole crate from being treated as unused.
    let anomaly_ptr: fn(&[u8], &ephemeral_crypto::TrustAnchorSet, u32, i64) -> _ =
        verify_anomaly_library_signature;
    let _ = black_box(anomaly_ptr);
    let _ = black_box(MAX_ANOMALY_LIBRARY_BYTES);

    eprintln!(
        "ephemeral-prod-symbol-probe: built with ephemeral-core, \
         ephemeral-classifier, and ephemeral-anomaly under \
         default-features = false; this binary exists only to be \
         inspected by the feature-leak-guard check."
    );
}
