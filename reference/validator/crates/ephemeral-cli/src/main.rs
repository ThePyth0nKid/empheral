//! `ephemeral-validator` CLI.
//!
//! Loads a list of conformance vector files (or the default six),
//! validates each against the schema, runs every implemented executor, and
//! prints a per-suite summary. Exits `0` only when every loaded file is
//! structurally valid and every executed vector passes; any failure or
//! harness error exits `1`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use ephemeral_core::{is_live_rekor_proof, run_many, RunConfig, TestReport, VectorSuite};
use serde::Serialize;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "ephemeral-validator",
    version,
    about = "EPHEMERAL Agent-Authority Protocol reference validator"
)]
struct Cli {
    /// Conformance vector files to validate. If empty, every file in
    /// `--conformance-dir` matching the suite names is loaded.
    #[arg(value_name = "FILE")]
    inputs: Vec<PathBuf>,

    /// Path to the JSON Schema describing the suite-file shape.
    #[arg(long, default_value = "conformance/schema.json")]
    schema: PathBuf,

    /// Directory of conformance vector files. Default fills in every suite.
    #[arg(long, default_value = "conformance")]
    conformance_dir: PathBuf,

    /// Run only the named suite(s). Repeatable.
    #[arg(long, value_enum)]
    suite: Vec<SuiteArg>,

    /// Directory of fuzz corpus files. Session-3 feature; currently accepted
    /// and echoed but does not change behavior.
    #[arg(long, value_name = "DIR")]
    fuzz_corpus: Option<PathBuf>,

    /// Print per-failure diagnostic detail.
    #[arg(short, long)]
    verbose: bool,

    /// Write a structured JSON report to this path.
    #[arg(long, value_name = "FILE")]
    json_report: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
#[allow(clippy::enum_variant_names)]
enum SuiteArg {
    DelegationScope,
    Canonicalization,
    FuzzBaseline,
    TariffReject,
    PcrAttestationReject,
    AuditReplay,
}

impl From<SuiteArg> for VectorSuite {
    fn from(s: SuiteArg) -> Self {
        match s {
            SuiteArg::DelegationScope => Self::DelegationScope,
            SuiteArg::Canonicalization => Self::Canonicalization,
            SuiteArg::FuzzBaseline => Self::FuzzBaseline,
            SuiteArg::TariffReject => Self::TariffReject,
            SuiteArg::PcrAttestationReject => Self::PcrAttestationReject,
            SuiteArg::AuditReplay => Self::AuditReplay,
        }
    }
}

/// Tag embedded in JSON reports so downstream tooling can distinguish
/// Session-1 structural-only runs from later sessions that also execute
/// semantic vectors.
const RUN_SESSION_TAG: &str = "session-2-canonicalization-delegation";

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("ephemeral-validator: fatal: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool> {
    let cli = Cli::parse();

    let schema = ephemeral_core::schema::CompiledSchema::load(&cli.schema)
        .with_context(|| format!("loading schema from {}", cli.schema.display()))?;

    let inputs = if cli.inputs.is_empty() {
        default_inputs(&cli.conformance_dir)
    } else {
        cli.inputs.clone()
    };

    if inputs.is_empty() {
        anyhow::bail!(
            "no input files; pass explicit paths or ensure {} contains the six suite files",
            cli.conformance_dir.display()
        );
    }

    if let Some(dir) = &cli.fuzz_corpus {
        eprintln!(
            "note: --fuzz-corpus {} accepted but fuzz_runner is a Session-3 deliverable",
            dir.display()
        );
    }

    let filter: Vec<VectorSuite> = cli.suite.iter().copied().map(Into::into).collect();
    let config = RunConfig {
        schema: &schema,
        suite_filter: &filter,
        verbose: cli.verbose,
    };

    let report = run_many(&inputs, &config);
    let crypto = summarize_crypto(&inputs);
    let attestation = summarize_attestation(&inputs);
    let transparency = summarize_transparency(&inputs);
    print_report(&report, &crypto, &attestation, &transparency, cli.verbose);

    if let Some(out) = &cli.json_report {
        write_json_report(out, &report, &crypto, &attestation, &transparency, &inputs)
            .with_context(|| format!("writing JSON report to {}", out.display()))?;
    }

    Ok(report.is_clean())
}

/// Counts vectors whose `input` carries a cryptographic signature — live
/// (`cose_sign1_bytes`) or mocked (`signature_valid` / `signed_by` / a
/// `signature_verification_context`). Canonicalization and fuzz vectors
/// have no crypto dimension and are excluded so the `mocked` count
/// reflects actual mock-era signature vectors, not "every non-signed
/// vector in the corpus."
///
/// The aggregate `mode` is `"live"` when every crypto-bearing vector uses
/// live bytes, `"mocked"` when every one uses the mock bool, `"mixed"`
/// when both are present, and `"none"` when no crypto-bearing vectors
/// loaded.
#[derive(Debug, Clone)]
struct CryptoSummary {
    mode: &'static str,
    live: u32,
    mocked: u32,
}

fn summarize_crypto(inputs: &[PathBuf]) -> CryptoSummary {
    let mut live: u32 = 0;
    let mut mocked: u32 = 0;
    for path in inputs {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let Some(vectors) = v.get("vectors").and_then(Value::as_array) else {
            continue;
        };
        for vec in vectors {
            let Some(input) = vec.get("input") else {
                continue;
            };
            let has_live = contains_cose_sign1(input);
            let has_mock = contains_mock_signature(input);
            if has_live {
                live += 1;
            } else if has_mock {
                mocked += 1;
            }
        }
    }
    let mode = match (live, mocked) {
        (0, 0) => "none",
        (_, 0) => "live",
        (0, _) => "mocked",
        _ => "mixed",
    };
    CryptoSummary { mode, live, mocked }
}

/// Phase-C.2 attestation-mode breakdown scoped to the
/// `pcr-attestation-reject` suite alone. Unlike [`CryptoSummary`] (which
/// mixes delegation, tariff and PCR signature dimensions into a single
/// aggregate), this summary answers: which attestation paths were
/// exercised by the loaded PCR-suite files — the bool-based mock path,
/// the live Nitro verify path, or both?
#[derive(Debug, Clone)]
struct AttestationSummary {
    mode: &'static str,
    live: u32,
    mock: u32,
}

/// Walks every input file, keeps only those whose top-level
/// `vector_suite` is `pcr-attestation-reject`, and classifies each of
/// its vectors by presence of `cose_sign1_bytes` anywhere under
/// `input`. Non-PCR files are skipped, so callers can pass the full
/// default input set without polluting the count.
fn summarize_attestation(inputs: &[PathBuf]) -> AttestationSummary {
    let mut live: u32 = 0;
    let mut mock: u32 = 0;
    for path in inputs {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if v.get("vector_suite").and_then(Value::as_str) != Some("pcr-attestation-reject") {
            continue;
        }
        let Some(vectors) = v.get("vectors").and_then(Value::as_array) else {
            continue;
        };
        for vec in vectors {
            let Some(input) = vec.get("input") else {
                continue;
            };
            if contains_cose_sign1(input) {
                live += 1;
            } else {
                mock += 1;
            }
        }
    }
    let mode = match (live, mock) {
        (0, 0) => "none",
        (_, 0) => "live",
        (0, _) => "mock",
        _ => "mixed",
    };
    AttestationSummary { mode, live, mock }
}

/// Phase-C.2.5 transparency-log breakdown scoped to the
/// `pcr-attestation-reject` suite. Answers a dimension
/// [`AttestationSummary`] does not: which vectors exercise the live-Rekor
/// verifier (all seven proof fields present, routed through
/// `classify_live_rekor`) versus the mock-bool fallback
/// (`inclusion_proof_valid` booleans).
///
/// Orthogonal to attestation mode: a vector can be `cose_sign1_bytes`-live
/// and mock-bool transparency at the same time (Phase C.2 live-Nitro
/// vectors), or no-COSE and live-Rekor (Phase C.2.5 vectors).
#[derive(Debug, Clone)]
struct TransparencySummary {
    mode: &'static str,
    live: u32,
    mock: u32,
}

/// Walks every input file, keeps only those whose top-level `vector_suite`
/// is `pcr-attestation-reject`, and classifies each vector by applying
/// [`is_live_rekor_proof`] to its
/// `input.attestation_bundle.transparency_log_proof` JSON node. Vectors
/// without such a node (no transparency dimension at all) are skipped so
/// `mock` does not inflate with unrelated entries. Non-PCR files are
/// skipped for the same reason as [`summarize_attestation`].
fn summarize_transparency(inputs: &[PathBuf]) -> TransparencySummary {
    let mut live: u32 = 0;
    let mut mock: u32 = 0;
    for path in inputs {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if v.get("vector_suite").and_then(Value::as_str) != Some("pcr-attestation-reject") {
            continue;
        }
        let Some(vectors) = v.get("vectors").and_then(Value::as_array) else {
            continue;
        };
        for vec in vectors {
            let Some(proof) = vec
                .pointer("/input/attestation_bundle/transparency_log_proof")
            else {
                continue;
            };
            if is_live_rekor_proof(proof) {
                live += 1;
            } else {
                mock += 1;
            }
        }
    }
    let mode = match (live, mock) {
        (0, 0) => "none",
        (_, 0) => "live",
        (0, _) => "mock",
        _ => "mixed",
    };
    TransparencySummary { mode, live, mock }
}

/// Recursively scans a JSON value for a `cose_sign1_bytes` string field.
/// Used to detect live-crypto vectors without coupling the CLI to every
/// suite's concrete input schema.
fn contains_cose_sign1(v: &Value) -> bool {
    match v {
        Value::Object(map) => {
            if map.get("cose_sign1_bytes").and_then(Value::as_str).is_some() {
                return true;
            }
            map.values().any(contains_cose_sign1)
        }
        Value::Array(items) => items.iter().any(contains_cose_sign1),
        _ => false,
    }
}

/// Recursively scans for any mock-signature marker:
/// `signature_valid`, `signed_by`, or `signature_verification_context`.
/// A vector with any of these participates in the crypto dimension via
/// the mock path (515-vector pre-Phase-C regime).
fn contains_mock_signature(v: &Value) -> bool {
    match v {
        Value::Object(map) => {
            if map.contains_key("signature_valid")
                || map.contains_key("signed_by")
                || map.contains_key("signature_verification_context")
            {
                return true;
            }
            map.values().any(contains_mock_signature)
        }
        Value::Array(items) => items.iter().any(contains_mock_signature),
        _ => false,
    }
}

fn default_inputs(dir: &Path) -> Vec<PathBuf> {
    const NAMES: &[&str] = &[
        "canonicalization.json",
        "delegation-scope.json",
        "fuzz-baseline.json",
        "tariff-reject.json",
        "pcr-attestation-reject.json",
        "pcr-attestation-reject-c2-live.json",
        "pcr-attestation-reject-c2-5-rekor.json",
        "audit-replay.json",
        // Phase C.4 Session 4 — cross-org `AnomalyPatternLibrary` envelope
        // verification (§3.5).  Adds 17 vectors under the new
        // `anomaly-library-reject` suite key; CLI totals climb 536→553.
        "anomaly-library-reject.json",
        // Phase C.4 Session 5-B — firing-rule evaluation against a
        // verified library (§3.5.3 primary/companion patterns, §11.2
        // `AnomalyDetected` emission).  Adds 15 vectors under the new
        // `anomaly-detect` suite key; CLI totals climb 553→568.
        "anomaly-detect.json",
    ];
    NAMES
        .iter()
        .map(|n| dir.join(n))
        .filter(|p| p.exists())
        .collect()
}

fn print_report(
    report: &TestReport,
    crypto: &CryptoSummary,
    attestation: &AttestationSummary,
    transparency: &TransparencySummary,
    verbose: bool,
) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "EPHEMERAL reference validator — conformance report");
    let _ = writeln!(stdout, "{:=<56}", "");
    for (suite, sr) in &report.per_suite {
        let schema_label = match sr.schema_ok {
            Some(true) => "ok    ",
            Some(false) => "FAIL  ",
            None => "nocheck",
        };
        let _ = writeln!(
            stdout,
            "  {:<22} schema={} pass={} fail={} error={} skipped={} file={}",
            suite.as_str(),
            schema_label,
            sr.pass,
            sr.fail,
            sr.error,
            sr.skipped,
            sr.file.display()
        );
        if verbose {
            for f in &sr.failures {
                let _ = writeln!(
                    stdout,
                    "    - [{}] {}: {}",
                    f.category, f.vector_id, f.reason
                );
            }
        }
    }
    let _ = writeln!(stdout, "{:-<56}", "");
    let _ = writeln!(
        stdout,
        "  totals: pass={} fail={} skipped={} clean={}",
        report.total_pass(),
        report.total_failing(),
        report.total_skipped(),
        report.is_clean()
    );
    let _ = writeln!(
        stdout,
        "  crypto: mode={} live={} mocked={}",
        crypto.mode, crypto.live, crypto.mocked
    );
    let _ = writeln!(
        stdout,
        "  attestation: mode={} live={} mock={}",
        attestation.mode, attestation.live, attestation.mock
    );
    let _ = writeln!(
        stdout,
        "  transparency: mode={} live={} mock={}",
        transparency.mode, transparency.live, transparency.mock
    );
}

fn write_json_report(
    out: &Path,
    report: &TestReport,
    crypto: &CryptoSummary,
    attestation: &AttestationSummary,
    transparency: &TransparencySummary,
    inputs: &[PathBuf],
) -> Result<()> {
    let report_json = JsonReport {
        session: RUN_SESSION_TAG,
        clean: report.is_clean(),
        totals: JsonTotals {
            pass: report.total_pass(),
            failing: report.total_failing(),
            skipped: report.total_skipped(),
        },
        crypto: JsonCrypto {
            mode: crypto.mode,
            live: crypto.live,
            mocked: crypto.mocked,
        },
        attestation: JsonAttestation {
            mode: attestation.mode,
            live: attestation.live,
            mock: attestation.mock,
        },
        transparency: JsonTransparency {
            mode: transparency.mode,
            live: transparency.live,
            mock: transparency.mock,
        },
        inputs: inputs.iter().map(|p| p.display().to_string()).collect(),
        suites: report
            .per_suite
            .iter()
            .map(|(s, sr)| JsonSuiteEntry {
                suite: s.as_str(),
                file: sr.file.display().to_string(),
                schema_ok: sr.schema_ok,
                pass: sr.pass,
                fail: sr.fail,
                error: sr.error,
                skipped: sr.skipped,
                failures: sr
                    .failures
                    .iter()
                    .map(|f| JsonFailureEntry {
                        vector_id: f.vector_id.clone(),
                        category: f.category.clone(),
                        severity: f.severity.map(|s| format!("{s:?}").to_lowercase()),
                        reason: f.reason.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec_pretty(&report_json)?;
    std::fs::write(out, bytes)?;
    Ok(())
}

#[derive(Serialize)]
struct JsonReport {
    session: &'static str,
    clean: bool,
    totals: JsonTotals,
    crypto: JsonCrypto,
    attestation: JsonAttestation,
    transparency: JsonTransparency,
    inputs: Vec<String>,
    suites: Vec<JsonSuiteEntry>,
}

#[derive(Serialize)]
struct JsonTotals {
    pass: u32,
    failing: u32,
    skipped: u32,
}

#[derive(Serialize)]
struct JsonCrypto {
    mode: &'static str,
    live: u32,
    mocked: u32,
}

#[derive(Serialize)]
struct JsonAttestation {
    mode: &'static str,
    live: u32,
    mock: u32,
}

#[derive(Serialize)]
struct JsonTransparency {
    mode: &'static str,
    live: u32,
    mock: u32,
}

#[derive(Serialize)]
struct JsonSuiteEntry {
    suite: &'static str,
    file: String,
    schema_ok: Option<bool>,
    pass: u32,
    fail: u32,
    error: u32,
    skipped: u32,
    failures: Vec<JsonFailureEntry>,
}

#[derive(Serialize)]
struct JsonFailureEntry {
    vector_id: String,
    category: String,
    severity: Option<String>,
    reason: String,
}
