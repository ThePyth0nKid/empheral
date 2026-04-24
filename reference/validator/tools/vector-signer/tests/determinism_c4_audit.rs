//! Golden-file guard: two consecutive `gen-phase-c4-audit --dry-run`
//! invocations must produce byte-identical stdout.
//!
//! Also pins the SHA-256 of the dry-run output so any accidental source of
//! non-determinism in the audit-replay vector generator (Ed25519 nonce
//! derivation, ciborium map ordering in the library envelope — including
//! the rotation envelope at `library_version = 2`, `BTreeMap` iteration
//! drift, `COSE_Sign1` header serialisation,
//! `sign_minimum_library_with_version(1|2)` mutation sequencing,
//! `serde_json::json!` field-insertion order, …) is caught immediately.
//!
//! Mirrors `determinism_c4_library.rs` / `determinism_c4_detect.rs` —
//! same three invariants applied to the Phase C.4 Session 5-B Commit C
//! generator (`phase_c4_audit::build_all` → arep-100..arep-116).
//!
//! Update `DRY_RUN_SHA256` when intentionally regenerating vectors — it is a
//! tripwire for silent non-determinism regressions.

use sha2::{Digest, Sha256};
use std::process::Command;

/// Pinned SHA-256 (hex) of the full `--dry-run` stdout for Phase C.4
/// Session 5-B Commit C.
///
/// Captured by running
/// `cargo run -p vector-signer -- gen-phase-c4-audit --dry-run` and piping
/// to `sha256sum`.  This is distinct from the SHA-256 of the committed
/// `conformance/audit-replay.json` file, which additionally wraps the 17
/// vectors in an envelope (`schema_version`, `vector_suite`,
/// `coverage_summary`, …) — `--dry-run` emits only the bare vector objects
/// pretty-printed and separated by newlines (the C.2 / C.2.5 / C.3-C / C.4
/// library / C.4 detect convention, NOT the single-array C.3-C-fuzz
/// convention).
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
const DRY_RUN_SHA256: &str =
    "4e6055df026c29efd31b00087aa4512937b3289a64720e5003ce013850e787aa";

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
        .args(["gen-phase-c4-audit", "--dry-run"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", bin.display()));
    assert!(
        output.status.success(),
        "gen-phase-c4-audit --dry-run failed: {}",
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
        "gen-phase-c4-audit --dry-run produced different output on two consecutive runs"
    );
}

/// Stdout must contain all seventeen vector IDs.
#[test]
fn dry_run_contains_all_vector_ids() {
    let stdout = run_dry_run();
    let text = std::str::from_utf8(&stdout).expect("stdout is UTF-8");
    for id in [
        "arep-100", "arep-101", "arep-102", "arep-103",
        "arep-104", "arep-105", "arep-106", "arep-107",
        "arep-108", "arep-109", "arep-110", "arep-111",
        "arep-112", "arep-113", "arep-114", "arep-115",
        "arep-116",
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
