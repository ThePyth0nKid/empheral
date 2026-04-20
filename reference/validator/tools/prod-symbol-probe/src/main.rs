//! Feature-leak guard probe — **NOT a production tool.**
//!
//! This binary is built by CI (`feature-leak-guard` job) and by the
//! local integration test `tests/no_leak.rs`. Its sole job is to link
//! against `ephemeral-core` AND `ephemeral-classifier` with
//! `default-features = false` and to reference enough of each crate's
//! public API that the linker keeps real code in the final binary
//! (otherwise dead-code elimination would produce an empty binary and
//! the no-leak assertion would be trivially true).
//!
//! What the downstream check asserts:
//! - The symbols `insert_trusted_der_for_test`, `classify_live_nitro`,
//!   `insert_trusted_key_for_test`, `classify_live_rekor` (all gated
//!   behind `ephemeral-core` / `ephemeral-attestation`'s `test-fixtures`
//!   feature) are ABSENT.
//! - The symbols `shared_wasm_artifacts`, `sign_classifier_envelope`,
//!   `fixture_signing_key`, `build_classifier_wat` (all gated behind
//!   `ephemeral-classifier`'s `test_fixtures` feature) are ABSENT.
//! - The controls `run_many` (ephemeral-core), `sha256_fingerprint`
//!   (ephemeral-attestation), and `verify_classifier_hash`
//!   (ephemeral-classifier) are PRESENT — proving the check is not
//!   trivially empty.
//!
//! If you add new feature-gated items to any of the three crates,
//! extend the assertions in `tests/no_leak.rs` to include them.

use std::hint::black_box;

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

    eprintln!(
        "ephemeral-prod-symbol-probe: built with ephemeral-core \
         and ephemeral-classifier default-features = false; this \
         binary exists only to be inspected by the feature-leak-guard \
         check."
    );
}
