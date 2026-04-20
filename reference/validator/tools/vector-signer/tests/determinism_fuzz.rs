//! Golden-file guard: two consecutive `gen-fuzz-c3-c --dry-run` invocations
//! must produce byte-identical stdout.
//!
//! Also pins the SHA-256 of the dry-run output so any accidental source of
//! non-determinism in the fuzz-baseline live-classifier vector generator
//! (shared WASM-fixture hashing drift, ciborium map ordering, `serde_json`
//! insertion-order regressions, …) is caught immediately.
//!
//! Mirrors `determinism_c3_c.rs` — same three invariants applied to the
//! Phase C.3-C Session 2 generator (`phase_c3_c_fuzz::build_all` →
//! fuzz-190 + fuzz-200).
//!
//! Update `DRY_RUN_SHA256` when intentionally regenerating vectors — it is
//! a tripwire for silent non-determinism regressions.

use sha2::{Digest, Sha256};
use std::process::Command;

/// Pinned SHA-256 (hex) of the full `--dry-run` stdout for Phase C.3-C
/// Session 2 (fuzz-baseline live-classifier migration).
///
/// Captured by running
/// `cargo run -p vector-signer -- gen-fuzz-c3-c --dry-run` and piping to
/// `sha256sum`.  This is distinct from the SHA-256 of the committed
/// `conformance/fuzz-baseline.json` file, which additionally contains the
/// other 203 fuzz vectors — `--dry-run` emits only the two live-classifier
/// vectors as a bare JSON array.
///
/// Update this constant when intentionally regenerating vectors — it is a
/// tripwire for silent non-determinism regressions.
const DRY_RUN_SHA256: &str =
    "54ddf75e835ea07d0469bb92dd53493dc0e7c04485773296209c936ae0dbe869";

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

    workspace_root.join("target").join("debug").join("vector-signer")
}

fn run_dry_run() -> Vec<u8> {
    let bin = vector_signer_bin();
    let output = Command::new(&bin)
        .args(["gen-fuzz-c3-c", "--dry-run"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", bin.display()));
    assert!(
        output.status.success(),
        "gen-fuzz-c3-c --dry-run failed: {}",
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
        "gen-fuzz-c3-c --dry-run produced different output on two consecutive runs"
    );
}

/// Stdout must contain both vector IDs.
#[test]
fn dry_run_contains_both_vector_ids() {
    let stdout = run_dry_run();
    let text = std::str::from_utf8(&stdout).expect("stdout is UTF-8");
    for id in ["fuzz-190", "fuzz-200"] {
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
