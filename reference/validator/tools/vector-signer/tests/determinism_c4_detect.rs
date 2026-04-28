//! Golden-file guard: two consecutive `gen-phase-c4-detect --dry-run`
//! invocations must produce byte-identical stdout.
//!
//! Also pins the SHA-256 of the dry-run output so any accidental source of
//! non-determinism in the anomaly-detect vector generator (Ed25519 nonce
//! derivation, ciborium map ordering in the library envelope, `BTreeMap`
//! iteration drift, `COSE_Sign1` header serialisation,
//! `sign_minimum_library_with_version(1)` mutation sequencing,
//! `serde_json::json!` field-insertion order, …) is caught immediately.
//!
//! Mirrors `determinism_c4_library.rs` — same three invariants applied to
//! the Phase C.4 Session 5-B Commit B generator
//! (`phase_c4_detect::build_all` → adet-100..adet-114).
//!
//! Update `DRY_RUN_SHA256` when intentionally regenerating vectors — it is a
//! tripwire for silent non-determinism regressions.

use sha2::{Digest, Sha256};
use std::process::Command;

/// Pinned SHA-256 (hex) of the full `--dry-run` stdout for Phase C.4
/// Session 5-B Commit B.
///
/// Captured by running
/// `cargo run -p vector-signer -- gen-phase-c4-detect --dry-run` and piping
/// to `sha256sum`.  This is distinct from the SHA-256 of the committed
/// `conformance/anomaly-detect.json` file, which additionally wraps the 15
/// vectors in an envelope (`schema_version`, `vector_suite`,
/// `coverage_summary`, …) — `--dry-run` emits only the bare vector objects
/// pretty-printed and separated by newlines (the C.2 / C.2.5 / C.3-C / C.4
/// library convention, NOT the single-array C.3-C-fuzz convention).
///
/// The hash is captured from a DEBUG-mode build (the `cargo build`
/// fallback in `vector_signer_bin()` produces `target/debug/vector-signer`).
/// Debug vs. release does not change the JSON output — the generator is
/// pure data assembly with no conditional-on-debug-assert branches — but
/// a `serde_json` minor-version bump that tweaks float formatting or
/// `preserve_order` behaviour WILL change the hash without any source
/// change.  Recapture after any such toolchain or crate upgrade; a
/// regression here is the entire point of the tripwire.
///
/// Update this constant when intentionally regenerating vectors — it is a
/// tripwire for silent non-determinism regressions.
const DRY_RUN_SHA256: &str = "03b405cafabc2410aa36b6918aed05be84078258b99519e3ed2b5eb9ec6be35a";

fn vector_signer_bin() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_vector-signer") {
        return std::path::PathBuf::from(p);
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    let status = Command::new("cargo")
        .args(["build", "-p", "vector-signer"])
        .current_dir(workspace_root)
        .status()
        .expect("cargo build");
    assert!(status.success(), "cargo build -p vector-signer failed");

    workspace_root
        .join("target")
        .join("debug")
        .join("vector-signer")
}

fn run_dry_run() -> Vec<u8> {
    let bin = vector_signer_bin();
    let output = Command::new(&bin)
        .args(["gen-phase-c4-detect", "--dry-run"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", bin.display()));
    assert!(
        output.status.success(),
        "gen-phase-c4-detect --dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Two consecutive dry-run invocations must produce byte-identical stdout.
#[test]
fn dry_run_is_deterministic() {
    let out1 = run_dry_run();
    let out2 = run_dry_run();
    assert_eq!(
        out1, out2,
        "gen-phase-c4-detect --dry-run produced different output on two consecutive runs"
    );
}

/// Stdout must contain all fifteen vector IDs.
#[test]
fn dry_run_contains_all_vector_ids() {
    let stdout = run_dry_run();
    let text = std::str::from_utf8(&stdout).expect("stdout is UTF-8");
    for id in [
        "adet-100", "adet-101", "adet-102", "adet-103", "adet-104", "adet-105", "adet-106",
        "adet-107", "adet-108", "adet-109", "adet-110", "adet-111", "adet-112", "adet-113",
        "adet-114",
    ] {
        assert!(
            text.contains(id),
            "dry-run stdout missing expected vector id: {id}"
        );
    }
}

/// SHA-256 of the full dry-run stdout must match the pinned constant.
///
/// If this test fails after an intentional change to the vector generator,
/// update `DRY_RUN_SHA256` above with the new hash.
#[test]
fn dry_run_sha256_matches_pinned() {
    let stdout = run_dry_run();
    let hash = Sha256::digest(&stdout);
    let hex = hex::encode(hash.as_slice());
    assert_eq!(
        hex, DRY_RUN_SHA256,
        "dry-run SHA-256 changed — update DRY_RUN_SHA256 if this is intentional"
    );
}
