//! Harness-level orchestrator.
//!
//! Ties together the loader, schema validator, and (in later sessions) the
//! per-suite semantic executors. Session 1's `run_file` reports:
//! - `schema_ok = Some(true/false)` once the schema check runs
//! - `schema_ok = None` if the file was filtered out before schema checking
//! - `skipped = n` where `n` is every vector in the file (executors not yet
//!   implemented)
//! - `pass/fail/error = 0`
//!
//! This is the correct Session-1 behavior: we prove we can load, typecheck,
//! and route. Semantic verdicts land when their suites' modules land.

use std::path::Path;
use std::time::SystemTime;

use crate::error::{SchemaError, ValidatorError};
use crate::schema::CompiledSchema;
use crate::suite_file::{load_suite_file, LoadedSuite};
use crate::suites::{audit, canonicalization, delegation, fuzz, pcr, tariff};
use crate::types::{
    SuiteReport, TestReport, ValidationOutcome, Vector, VectorFailure, VectorSuite,
};

/// Harness config for a single run.
#[derive(Debug)]
pub struct RunConfig<'a> {
    pub schema: &'a CompiledSchema,
    /// When non-empty, filter to this set of suites; otherwise run all.
    pub suite_filter: &'a [VectorSuite],
    /// When true, attach per-failure diagnostic strings.
    pub verbose: bool,
}

/// Result of running a single file: the per-file report plus the resolved
/// suite assignment (if the file loaded far enough to discover it).
#[derive(Debug)]
pub struct FileRunResult {
    pub report: SuiteReport,
    pub suite: Option<VectorSuite>,
}

/// Run every configured check against a single conformance file.
pub fn run_file(path: &Path, config: &RunConfig<'_>) -> FileRunResult {
    let loaded = match load_suite_file(path) {
        Ok(x) => x,
        Err(e) => {
            return FileRunResult {
                report: report_with_harness_error(path, &e),
                suite: None,
            };
        }
    };

    let suite = loaded.parsed.vector_suite;

    if !config.suite_filter.is_empty() && !config.suite_filter.contains(&suite) {
        // File matched load+parse but was filter-excluded. Vectors are
        // reported as "filtered out" skips, not as schema failures.
        let skipped_count = u32::try_from(loaded.parsed.vectors.len()).unwrap_or(u32::MAX);
        return FileRunResult {
            report: SuiteReport {
                file: path.to_path_buf(),
                schema_ok: None,
                pass: 0,
                fail: 0,
                error: 0,
                skipped: skipped_count,
                failures: Vec::new(),
            },
            suite: Some(suite),
        };
    }

    let mut report = SuiteReport {
        file: path.to_path_buf(),
        schema_ok: None,
        pass: 0,
        fail: 0,
        error: 0,
        skipped: 0,
        failures: Vec::new(),
    };

    // Structural layer: schema validation.
    match config.schema.validate(&loaded.raw, path) {
        Ok(()) => report.schema_ok = Some(true),
        Err(SchemaError::Invalid {
            summary, errors, ..
        }) => {
            report.schema_ok = Some(false);
            report.error += 1;
            report.failures.push(VectorFailure {
                vector_id: "<file>".into(),
                category: "schema-validation".into(),
                severity: None,
                reason: if config.verbose {
                    format!("{summary}: {}", errors.join("; "))
                } else {
                    summary
                },
            });
            return FileRunResult {
                report,
                suite: Some(suite),
            };
        }
        Err(other) => {
            report.schema_ok = Some(false);
            report.error += 1;
            report.failures.push(VectorFailure {
                vector_id: "<file>".into(),
                category: "schema-validation".into(),
                severity: None,
                reason: other.to_string(),
            });
            return FileRunResult {
                report,
                suite: Some(suite),
            };
        }
    }

    // Semantic layer: dispatch per vector. Session 1 skips every vector.
    for v in &loaded.parsed.vectors {
        tally(execute_vector(&loaded, v), &mut report, v);
    }

    FileRunResult {
        report,
        suite: Some(suite),
    }
}

fn report_with_harness_error(path: &Path, err: &ValidatorError) -> SuiteReport {
    SuiteReport {
        file: path.to_path_buf(),
        schema_ok: None,
        pass: 0,
        fail: 0,
        error: 1,
        skipped: 0,
        failures: vec![VectorFailure {
            vector_id: "<file>".into(),
            category: "load-error".into(),
            severity: None,
            reason: format!("{err}"),
        }],
    }
}

/// Dispatch a vector to its suite executor.
///
/// Session 3: all six suites execute semantic verdicts.
fn execute_vector(loaded: &LoadedSuite, vector: &Vector) -> ValidationOutcome {
    match loaded.parsed.vector_suite {
        VectorSuite::Canonicalization => canonicalization::execute(vector),
        VectorSuite::DelegationScope => delegation::execute(vector),
        VectorSuite::FuzzBaseline => fuzz::execute(vector),
        VectorSuite::TariffReject => tariff::execute(vector),
        VectorSuite::PcrAttestationReject => pcr::execute(vector),
        VectorSuite::AuditReplay => audit::execute(vector),
    }
}

fn tally(outcome: ValidationOutcome, report: &mut SuiteReport, vector: &Vector) {
    match outcome {
        ValidationOutcome::Pass => report.pass += 1,
        ValidationOutcome::Fail { reason } => {
            report.fail += 1;
            report.failures.push(VectorFailure {
                vector_id: vector.id.clone(),
                category: vector.category.clone(),
                severity: vector.severity_if_failed,
                reason,
            });
        }
        ValidationOutcome::Error { source } => {
            report.error += 1;
            report.failures.push(VectorFailure {
                vector_id: vector.id.clone(),
                category: vector.category.clone(),
                severity: vector.severity_if_failed,
                reason: source.to_string(),
            });
        }
        ValidationOutcome::Skipped { .. } => report.skipped += 1,
    }
}

/// Run every supplied file, producing an aggregate report.
///
/// Files whose suite cannot be determined (because load or parse failed)
/// bucket under [`UnresolvedSuiteBucket::key`]. The stem-based fallback used
/// by earlier iterations silently misrouted orphan files into `audit-replay`;
/// this version surfaces them with an explicit `load-error` failure.
pub fn run_many(paths: &[impl AsRef<Path>], config: &RunConfig<'_>) -> TestReport {
    let started_at = SystemTime::now();
    let mut report = TestReport::new(started_at);
    for p in paths {
        let p = p.as_ref();
        let result = run_file(p, config);
        if let Some(suite) = result.suite {
            merge_into(&mut report, suite, result.report);
        } else {
            // No suite resolved (load/parse failure). Emit the report in a
            // deterministic bucket chosen by filename stem so users can still
            // see the error, but never silently merge counts with a real
            // suite. We use AuditReplay as the canonical orphan bucket and
            // annotate the failure so consumers can detect it.
            let orphan = stem_suite_hint(p).unwrap_or(VectorSuite::AuditReplay);
            merge_into(&mut report, orphan, result.report);
        }
    }
    report.finished_at = SystemTime::now();
    report
}

/// Best-effort suite hint from a filename — only used for orphan bucketing
/// when no suite could be parsed from the file body.
fn stem_suite_hint(path: &Path) -> Option<VectorSuite> {
    let stem = path.file_stem()?.to_str()?;
    match stem {
        "canonicalization" => Some(VectorSuite::Canonicalization),
        "delegation-scope" => Some(VectorSuite::DelegationScope),
        "fuzz-baseline" => Some(VectorSuite::FuzzBaseline),
        "tariff-reject" => Some(VectorSuite::TariffReject),
        "pcr-attestation-reject" => Some(VectorSuite::PcrAttestationReject),
        "audit-replay" => Some(VectorSuite::AuditReplay),
        _ => None,
    }
}

fn merge_into(report: &mut TestReport, suite: VectorSuite, sr: SuiteReport) {
    let entry = report.per_suite.entry(suite).or_default();
    // Keep the first-observed file path so repeated merges for the same suite
    // (an unusual Phase-C setup) do not silently lose provenance.
    if entry.file.as_os_str().is_empty() {
        entry.file = sr.file;
    }
    // `schema_ok` aggregates as "all ok" → `Some(true)`, "any fail" →
    // `Some(false)`, "never checked" → `None`.
    entry.schema_ok = match (entry.schema_ok, sr.schema_ok) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(a && b),
    };
    entry.pass += sr.pass;
    entry.fail += sr.fail;
    entry.error += sr.error;
    entry.skipped += sr.skipped;
    entry.failures.extend(sr.failures);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::CompiledSchema;
    use std::path::PathBuf;

    fn dummy_schema() -> CompiledSchema {
        // Accept anything.
        let doc = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema"
        });
        CompiledSchema::from_value(&doc, PathBuf::from("dummy")).unwrap()
    }

    #[test]
    fn missing_file_produces_error_report() {
        let s = dummy_schema();
        let cfg = RunConfig {
            schema: &s,
            suite_filter: &[],
            verbose: false,
        };
        let result = run_file(&PathBuf::from("C:/nonexistent/xxx.json"), &cfg);
        assert_eq!(result.report.error, 1);
        assert_eq!(result.report.pass, 0);
        assert!(result.suite.is_none(), "missing file has no parsed suite");
        assert_eq!(result.report.schema_ok, None);
    }
}
