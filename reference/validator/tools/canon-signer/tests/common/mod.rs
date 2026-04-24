//! Shared helpers for integration tests.
//!
//! `tests/common/mod.rs` is treated by Cargo as a module, not as a
//! standalone test binary — the empty `mod.rs` pattern lets each
//! integration-test file `mod common;` to pull these utilities in.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A fixed 32-byte Ed25519 seed used across integration tests so
/// produced signatures are deterministic and reviewable in diffs.
/// Not a production key.
pub const TEST_SEED_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

/// Spawn the `canon-signer` binary with a deterministic seed injected
/// via the `CANON_SIGNER_KEY_HEX` environment variable.
pub fn spawn_signer() -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let path = env!("CARGO_BIN_EXE_canon-signer");
    let mut child = Command::new(path)
        .env("CANON_SIGNER_KEY_HEX", TEST_SEED_HEX)
        // Windows keeps a default TMPDIR; forcing it here keeps the
        // auto-gen fallback out of the test identity path even though
        // the env var above already short-circuits that branch.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn canon-signer binary");

    let stdin = child.stdin.take().expect("spawned stdin");
    let stdout = BufReader::new(child.stdout.take().expect("spawned stdout"));
    (child, stdin, stdout)
}

/// Send one request line and read one response line.  Panics on EOF or
/// I/O error — integration tests treat those as bugs, not expected
/// outcomes.
pub fn send_and_receive(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    request_json: &str,
) -> String {
    writeln!(stdin, "{request_json}").expect("write request");
    stdin.flush().expect("flush stdin");
    let mut line = String::new();
    let n = stdout.read_line(&mut line).expect("read response");
    assert!(n > 0, "signer closed stdout before writing a response");
    line.trim_end_matches(['\n', '\r']).to_string()
}

/// Gracefully close stdin and wait for the subprocess to exit.  Used
/// at the end of every test so leaked child processes do not
/// accumulate in the test harness.
pub fn close_and_wait(mut child: Child, stdin: ChildStdin) {
    drop(stdin); // EOF on stdin → clean exit path in the binary
    let status = child.wait().expect("subprocess wait");
    // `status.code().is_none()` covers signal termination (e.g. SIGPIPE
    // on unix when the parent drops stdout before the child's final
    // writeln flushes).  That is not a failure of the sidecar — the
    // test got what it needed before tearing the pipe down.
    assert!(
        status.success() || status.code().is_none(),
        "canon-signer exited with unexpected status: {status:?}"
    );
}

/// Convenience: build a minimal valid sign-request JSON with a custom
/// `parent_hash` and `claim` — the two fields integration tests
/// typically vary.
pub fn sign_request_json(fact_id: &str, claim: &str, parent_hash: &str) -> String {
    serde_json::json!({
        "op": "sign",
        "fact_id": fact_id,
        "entity": "customer:acme",
        "claim": claim,
        "source_ref": "test:integration",
        "source_excerpt": null,
        "parent_hash": parent_hash,
        "created_at_ms": 1_713_974_400_000u64,
    })
    .to_string()
}
