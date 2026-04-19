//! Task #8 — CLI must report an attestation-mode summary that classifies
//! `pcr-attestation-reject` runs independently from the suite-wide
//! `crypto:` line.
//!
//! The summary is computed from the input set alone (no dispatch logic
//! in ephemeral-core): each input file whose header declares
//! `vector_suite = "pcr-attestation-reject"` contributes its vectors to
//! the count, where a vector carrying `cose_sign1_bytes` is `live` and
//! any other vector in that suite is `mock`. Files belonging to other
//! suites are ignored entirely.

use std::path::{Path, PathBuf};
use std::process::Command;

fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../conformance")
        .canonicalize()
        .expect("conformance dir resolves")
}

fn run_cli(args: &[&str]) -> (String, std::process::ExitStatus) {
    let bin = env!("CARGO_BIN_EXE_ephemeral-validator");
    let out = Command::new(bin).args(args).output().expect("run cli");
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    (stdout, out.status)
}

fn schema_arg() -> String {
    conformance_dir().join("schema.json").to_string_lossy().into_owned()
}

fn vector_arg(name: &str) -> String {
    conformance_dir().join(name).to_string_lossy().into_owned()
}

#[test]
fn attestation_mode_live_only() {
    let schema = schema_arg();
    let live = vector_arg("pcr-attestation-reject-c2-live.json");
    let (out, status) = run_cli(&["--schema", &schema, &live]);
    assert!(status.success(), "cli exit: {status:?}\nstdout:\n{out}");
    assert!(
        out.contains("attestation: mode=live live=8 mock=0"),
        "expected live-only attestation summary; stdout was:\n{out}",
    );
}

#[test]
fn attestation_mode_mock_only() {
    let schema = schema_arg();
    let mock = vector_arg("pcr-attestation-reject.json");
    let (out, status) = run_cli(&["--schema", &schema, &mock]);
    assert!(status.success(), "cli exit: {status:?}\nstdout:\n{out}");
    assert!(
        out.contains("attestation: mode=mock live=0 mock=49"),
        "expected mock-only attestation summary; stdout was:\n{out}",
    );
}

#[test]
fn attestation_mode_mixed() {
    let schema = schema_arg();
    let mock = vector_arg("pcr-attestation-reject.json");
    let live = vector_arg("pcr-attestation-reject-c2-live.json");
    let (out, status) = run_cli(&["--schema", &schema, &mock, &live]);
    assert!(status.success(), "cli exit: {status:?}\nstdout:\n{out}");
    assert!(
        out.contains("attestation: mode=mixed live=8 mock=49"),
        "expected mixed attestation summary; stdout was:\n{out}",
    );
}

#[test]
fn attestation_mode_none_when_no_pcr_files_loaded() {
    let schema = schema_arg();
    let delegation = vector_arg("delegation-scope.json");
    let (out, status) = run_cli(&["--schema", &schema, &delegation]);
    assert!(status.success(), "cli exit: {status:?}\nstdout:\n{out}");
    assert!(
        out.contains("attestation: mode=none live=0 mock=0"),
        "expected none attestation summary when no PCR files loaded; stdout was:\n{out}",
    );
}

#[test]
fn attestation_mode_in_json_report() {
    let schema = schema_arg();
    let mock = vector_arg("pcr-attestation-reject.json");
    let live = vector_arg("pcr-attestation-reject-c2-live.json");
    let tmp = std::env::temp_dir().join(format!(
        "ephemeral-cli-attestation-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    let tmp_str = tmp.to_string_lossy().into_owned();
    let (_, status) = run_cli(&[
        "--schema", &schema,
        "--json-report", &tmp_str,
        &mock, &live,
    ]);
    assert!(status.success(), "cli exit: {status:?}");
    let bytes = std::fs::read(&tmp).expect("read json report");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
    let att = v.get("attestation").expect("attestation field present");
    assert_eq!(att.get("mode").and_then(serde_json::Value::as_str), Some("mixed"));
    assert_eq!(att.get("live").and_then(serde_json::Value::as_u64), Some(8));
    assert_eq!(att.get("mock").and_then(serde_json::Value::as_u64), Some(49));
    let _ = std::fs::remove_file(&tmp);
}
