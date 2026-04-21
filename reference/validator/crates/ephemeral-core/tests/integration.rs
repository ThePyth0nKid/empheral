//! Integration tests across both structural and semantic layers.
//!
//! Points at the repo's real `conformance/` directory (four levels up from
//! this file: `reference/validator/crates/ephemeral-core/tests`). Every
//! check therefore runs against the canonical 515-vector suite — any drift
//! surfaces here, not in a toy fixture.
//!
//! Phase C.4 Session 4 adds the seventh suite `anomaly-library-reject`
//! (`conformance/anomaly-library-reject.json`, 17 vectors).

use std::path::{Path, PathBuf};

use ephemeral_core::{run_file, schema::CompiledSchema, RunConfig, VectorSuite};

/// Path to the repo root's `conformance/` directory, derived from
/// `CARGO_MANIFEST_DIR` so tests are location-independent.
fn conformance_dir() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // .../reference/validator/crates/ephemeral-core -> up 4 -> repo root.
    manifest
        .parent() // crates/
        .and_then(Path::parent) // validator/
        .and_then(Path::parent) // reference/
        .and_then(Path::parent) // repo root
        .map(|p| p.join("conformance"))
        .expect("unexpected manifest layout")
}

fn schema() -> CompiledSchema {
    CompiledSchema::load(&conformance_dir().join("schema.json"))
        .expect("schema.json failed to load — the conformance suite is broken")
}

fn suite_file_path(name: &str) -> PathBuf {
    conformance_dir().join(name)
}

#[test]
fn schema_compiles() {
    let _ = schema();
}

/// Shared structural checks: schema validates, no harness errors, at least
/// one vector accounted for. The per-suite tests layer semantic expectations
/// on top of this.
fn run_suite_file(name: &str, expected: VectorSuite) -> ephemeral_core::SuiteReport {
    let s = schema();
    let cfg = RunConfig {
        schema: &s,
        suite_filter: &[],
        verbose: true,
    };
    let result = run_file(&suite_file_path(name), &cfg);
    assert_eq!(
        result.suite,
        Some(expected),
        "{name} declared the wrong vector_suite; expected {expected:?}"
    );
    assert_eq!(
        result.report.schema_ok,
        Some(true),
        "{name} failed schema validation. Failures: {:?}",
        result.report.failures
    );
    assert_eq!(
        result.report.error, 0,
        "{name} harness errors: {:?}",
        result.report.failures
    );
    let total =
        result.report.pass + result.report.fail + result.report.error + result.report.skipped;
    assert!(total > 0, "{name} reported zero vectors — suspicious");
    result.report
}

fn assert_file_all_executed(name: &str, expected: VectorSuite) {
    let report = run_suite_file(name, expected);
    assert_eq!(
        report.fail, 0,
        "{name} vector failures: {:?}",
        report.failures
    );
    assert!(
        report.pass > 0,
        "{name} had no passing vectors — executor should pass conformance vectors",
    );
    assert_eq!(
        report.skipped, 0,
        "{name} still skipped vectors — executor should cover every vector",
    );
}

#[test]
fn canonicalization_structural() {
    assert_file_all_executed("canonicalization.json", VectorSuite::Canonicalization);
}

#[test]
fn delegation_scope_structural() {
    assert_file_all_executed("delegation-scope.json", VectorSuite::DelegationScope);
}

#[test]
fn fuzz_baseline_structural() {
    assert_file_all_executed("fuzz-baseline.json", VectorSuite::FuzzBaseline);
}

#[test]
fn tariff_reject_structural() {
    assert_file_all_executed("tariff-reject.json", VectorSuite::TariffReject);
}

#[test]
fn pcr_attestation_reject_structural() {
    assert_file_all_executed(
        "pcr-attestation-reject.json",
        VectorSuite::PcrAttestationReject,
    );
}

/// Phase C.2 live-crypto vectors (pcrrej-090..097). Same `vector_suite`
/// declaration as the mock file; dispatch to the live path happens inside
/// the pcr executor based on the presence of `cose_sign1_bytes`. Requires
/// the `test-fixtures` feature so the live-Nitro code path is compiled in.
#[cfg(feature = "test-fixtures")]
#[test]
fn pcr_attestation_reject_c2_live_structural() {
    assert_file_all_executed(
        "pcr-attestation-reject-c2-live.json",
        VectorSuite::PcrAttestationReject,
    );
}

#[test]
fn audit_replay_structural() {
    assert_file_all_executed("audit-replay.json", VectorSuite::AuditReplay);
}

/// Phase C.4 Session 4 — cross-org `AnomalyPatternLibrary` envelope
/// verification vectors (alrej-100..alrej-116). 15 rejects exercise the 8
/// pipeline stages; 2 accepts pin the replay-ledger dial (first observation +
/// strict advance).  The suite executor consumes
/// `ephemeral_anomaly::verify_anomaly_library_signature_with_ledger` — the
/// same live-crypto path a production verifier would hit.
#[test]
fn anomaly_library_reject_structural() {
    assert_file_all_executed(
        "anomaly-library-reject.json",
        VectorSuite::AnomalyLibraryReject,
    );
}

#[test]
fn run_many_aggregates_all_seven() {
    let s = schema();
    let cfg = RunConfig {
        schema: &s,
        suite_filter: &[],
        verbose: false,
    };
    // The c2-live file only makes sense when the live-Nitro dispatch path
    // is compiled in; without `test-fixtures` the dispatch short-circuits
    // to Fail and the 8 vectors would be reported as failures. Build the
    // input list conditionally so both feature states compile warning-free.
    #[allow(unused_mut)]
    let mut input_names: Vec<&str> = vec![
        "canonicalization.json",
        "delegation-scope.json",
        "fuzz-baseline.json",
        "tariff-reject.json",
        "pcr-attestation-reject.json",
        "audit-replay.json",
        "anomaly-library-reject.json",
    ];
    #[cfg(feature = "test-fixtures")]
    input_names.push("pcr-attestation-reject-c2-live.json");

    let inputs: Vec<PathBuf> = input_names.iter().map(|n| suite_file_path(n)).collect();

    let report = ephemeral_core::run_many(&inputs, &cfg);
    assert_eq!(
        report.per_suite.len(),
        7,
        "expected 7 suites in the aggregate report, got {:?}",
        report.per_suite.keys().collect::<Vec<_>>()
    );
    for (suite, sr) in &report.per_suite {
        assert_eq!(
            sr.schema_ok,
            Some(true),
            "suite {suite:?} did not schema-validate"
        );
    }
    assert!(
        report.total_failing() == 0,
        "aggregate report has failures: {:#?}",
        report.per_suite
    );
    assert!(report.is_clean());
    // Phase C.4 Session 4: all seven suites execute. With `test-fixtures`
    // enabled the corpus is 545 vectors (93 canon + 70 deleg + 205 fuzz +
    // 71 tariff + 49 pcr mock + 8 pcr c2-live + 32 audit + 17 anomaly-
    // library); without the feature the c2-live file is excluded, leaving
    // 537.
    //
    // Intentionally NOT aggregated here: the Phase C.2.5 Rekor vectors
    // (`pcr-attestation-reject-c2-5-rekor.json`, 16 vectors) and the
    // Phase C.3-C classifier-signature vectors
    // (`tariff-reject-c3-c-classifier.json`, 8 vectors).  Each has a
    // dedicated `assert_file_all_executed` test covering its file end-
    // to-end; folding them into this aggregate would require another
    // feature-gated branch and an updated pin for every new session.
    // The total ephemeral-cli run covers them via `default_inputs` —
    // see the 553-vector number reported by `cargo run -p ephemeral-cli`.
    #[cfg(feature = "test-fixtures")]
    let expected_pass = 545;
    #[cfg(not(feature = "test-fixtures"))]
    let expected_pass = 537;
    assert_eq!(
        report.total_pass(),
        expected_pass,
        "expected {expected_pass} vectors passing, got {}",
        report.total_pass()
    );
    assert_eq!(
        report.total_skipped(),
        0,
        "expected 0 skipped vectors, got {}",
        report.total_skipped()
    );
}

#[test]
fn suite_filter_marks_unchecked() {
    // When `--suite canonicalization` is active, the other five files are
    // skipped without being schema-checked. `schema_ok` must be `None` for
    // them rather than `Some(false)`.
    let s = schema();
    let cfg = RunConfig {
        schema: &s,
        suite_filter: &[VectorSuite::Canonicalization],
        verbose: false,
    };
    let result = run_file(&suite_file_path("audit-replay.json"), &cfg);
    assert_eq!(result.suite, Some(VectorSuite::AuditReplay));
    assert_eq!(result.report.schema_ok, None);
    assert_eq!(result.report.pass, 0);
    assert_eq!(result.report.fail, 0);
    assert_eq!(result.report.error, 0);
    assert!(result.report.skipped > 0);
}
