//! Golden-file guard: two consecutive `gen-phase-c2 --dry-run` invocations
//! must produce byte-identical stdout.
//!
//! Also pins the SHA-256 of the dry-run output so any accidental non-determinism
//! in `build_attestation_doc` is caught immediately.
//!
//! Update `DRY_RUN_SHA256` when intentionally regenerating vectors — it is a
//! tripwire for silent non-determinism regressions.

use sha2::{Digest, Sha256};
use std::process::Command;

/// Pinned SHA-256 (hex) of the full `--dry-run` stdout.
///
/// Captured by running `cargo run -p vector-signer -- gen-phase-c2 --dry-run`
/// and piping to `sha256sum`.
///
/// Update this constant when intentionally regenerating vectors — it is a
/// tripwire for silent non-determinism regressions.
const DRY_RUN_SHA256: &str =
    "87f985aa9046b008851a30f6244fa168eeb65853442ed00179d33fb43ce46869";

fn vector_signer_bin() -> std::path::PathBuf {
    // `cargo test` runs from the workspace root or crate root.  The binary is
    // placed in the workspace target directory. Use CARGO_BIN_EXE_vector-signer
    // env var that `cargo test` sets automatically when the [[bin]] is in the
    // same crate, or fall back to building it ourselves.
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_vector-signer") {
        return std::path::PathBuf::from(p);
    }
    // Fall back: cargo build and find the binary in target/debug.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent() // tools/
        .and_then(|p| p.parent()) // reference/validator/
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
        .args(["gen-phase-c2", "--dry-run"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", bin.display()));
    assert!(
        output.status.success(),
        "gen-phase-c2 --dry-run failed: {}",
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
        "gen-phase-c2 --dry-run produced different output on two consecutive runs"
    );
}

/// Stdout must contain all eight vector IDs.
#[test]
fn dry_run_contains_all_vector_ids() {
    let stdout = run_dry_run();
    let text = std::str::from_utf8(&stdout).expect("stdout is UTF-8");
    for id in ["pcrrej-090", "pcrrej-091", "pcrrej-092", "pcrrej-093",
               "pcrrej-094", "pcrrej-095", "pcrrej-096", "pcrrej-097"] {
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
