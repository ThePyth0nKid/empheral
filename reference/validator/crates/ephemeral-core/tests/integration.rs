//! Integration tests for the Session-1 structural layer.
//!
//! Points at the repo's real `conformance/` directory (four levels up from
//! this file: `reference/validator/crates/ephemeral-core/tests`). Every
//! check therefore runs against the canonical 515-vector suite — any drift
//! surfaces here, not in a toy fixture.

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

fn assert_file_structural_ok(name: &str, expected: VectorSuite) {
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
    assert_eq!(
        result.report.fail, 0,
        "{name} vector failures: {:?}",
        result.report.failures
    );
    // Session 1: every vector is skipped.
    assert!(
        result.report.skipped > 0,
        "{name} reported zero vectors — suspicious",
    );
}

#[test]
fn canonicalization_structural() {
    assert_file_structural_ok("canonicalization.json", VectorSuite::Canonicalization);
}

#[test]
fn delegation_scope_structural() {
    assert_file_structural_ok("delegation-scope.json", VectorSuite::DelegationScope);
}

#[test]
fn fuzz_baseline_structural() {
    assert_file_structural_ok("fuzz-baseline.json", VectorSuite::FuzzBaseline);
}

#[test]
fn tariff_reject_structural() {
    assert_file_structural_ok("tariff-reject.json", VectorSuite::TariffReject);
}

#[test]
fn pcr_attestation_reject_structural() {
    assert_file_structural_ok(
        "pcr-attestation-reject.json",
        VectorSuite::PcrAttestationReject,
    );
}

#[test]
fn audit_replay_structural() {
    assert_file_structural_ok("audit-replay.json", VectorSuite::AuditReplay);
}

#[test]
fn run_many_aggregates_all_six() {
    let s = schema();
    let cfg = RunConfig {
        schema: &s,
        suite_filter: &[],
        verbose: false,
    };
    let inputs: Vec<PathBuf> = [
        "canonicalization.json",
        "delegation-scope.json",
        "fuzz-baseline.json",
        "tariff-reject.json",
        "pcr-attestation-reject.json",
        "audit-replay.json",
    ]
    .iter()
    .map(|n| suite_file_path(n))
    .collect();

    let report = ephemeral_core::run_many(&inputs, &cfg);
    assert_eq!(
        report.per_suite.len(),
        6,
        "expected 6 suites in the aggregate report, got {:?}",
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
    assert!(
        report.total_skipped() > 500,
        "expected ≥ 500 vectors skipped, got {}",
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
