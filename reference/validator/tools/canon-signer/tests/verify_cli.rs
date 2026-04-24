//! Integration tests for the `canon-verify` companion CLI.
//!
//! These tests exercise the full demo flow: spawn `canon-signer`, sign
//! a fact, then invoke the standalone `canon-verify` binary to
//! independently verify the envelope.  They are the executable form of
//! the demo playbook — if these pass, the hackathon "paste envelope,
//! see verified=true" story works as advertised.

mod common;

use std::process::{Command, Output};

use common::{close_and_wait, send_and_receive, spawn_signer, TEST_SEED_HEX};

/// Absolute path to the `canon-verify` binary built by Cargo for this
/// integration-test target.  `CARGO_BIN_EXE_<name>` is set by Cargo for
/// every `[[bin]]` declared in the same package as the test.
fn verify_bin() -> &'static str {
    env!("CARGO_BIN_EXE_canon-verify")
}

fn run_verify(envelope_hex: &str, pubkey: &str, kid: Option<&str>) -> Output {
    let mut cmd = Command::new(verify_bin());
    cmd.arg("--envelope-hex")
        .arg(envelope_hex)
        .arg("--pubkey")
        .arg(pubkey);
    if let Some(k) = kid {
        cmd.arg("--kid").arg(k);
    }
    cmd.output().expect("failed to run canon-verify")
}

fn sign_one() -> (String, String) {
    // Produce one envelope + pubkey pair via a live signer subprocess.
    let (child, mut stdin, mut stdout) = spawn_signer();
    let req = common::sign_request_json("f_verify_cli", "the demo claim", "");
    let resp_line = send_and_receive(&mut stdin, &mut stdout, &req);
    close_and_wait(child, stdin);

    let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap();
    let cose = resp["cose_sign1_hex"].as_str().unwrap().to_string();
    let pubkey = resp["signer_pubkey"].as_str().unwrap().to_string();
    (cose, pubkey)
}

#[test]
fn verify_cli_accepts_valid_envelope() {
    let (cose, pubkey) = sign_one();

    let out = run_verify(&cose, &pubkey, None);
    assert!(
        out.status.success(),
        "canon-verify must exit 0 on a valid envelope; got {:?}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["verified"], serde_json::Value::Bool(true));
    assert_eq!(
        parsed["event_hash"].as_str().map_or(0, str::len),
        64,
        "event_hash must be SHA-256 hex (64 chars)"
    );
    let kid = parsed["kid"].as_str().unwrap();
    assert!(kid.starts_with("canon/"));
    assert_eq!(kid.len(), "canon/".len() + 16);
}

#[test]
fn verify_cli_rejects_tampered_envelope() {
    let (cose, pubkey) = sign_one();

    // Flip the final nibble — that byte sits inside the Ed25519
    // signature region, so verification must fail.
    let mut chars: Vec<char> = cose.chars().collect();
    let last = chars.last_mut().unwrap();
    let flipped = match *last {
        '0' => '1',
        '1' => '0',
        c if c.is_ascii_hexdigit() => {
            // Toggle bit 0 within the same nibble space.
            let v = u8::from_str_radix(&c.to_string(), 16).unwrap() ^ 1;
            std::char::from_digit(u32::from(v), 16).unwrap()
        }
        _ => panic!("envelope must be hex-encoded"),
    };
    *last = flipped;
    let tampered: String = chars.into_iter().collect();
    assert_ne!(tampered, cose, "tampered envelope must differ");

    let out = run_verify(&tampered, &pubkey, None);
    assert!(
        !out.status.success(),
        "canon-verify must exit nonzero on a tampered envelope"
    );
    assert_eq!(out.status.code(), Some(1), "tamper exit code should be 1");

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["verified"], serde_json::Value::Bool(false));
    assert!(
        parsed["error"].as_str().unwrap_or("").contains("signature")
            || parsed["error"].as_str().unwrap_or("").contains("verif"),
        "error message should mention signature/verification; got {parsed:?}"
    );
}

#[test]
fn verify_cli_rejects_wrong_pubkey() {
    let (cose, _real_pubkey) = sign_one();

    // A different Ed25519 public key (all-zero scalar is still a valid
    // Ed25519 point on the signature-verification side, so the anchor
    // builds fine but the signature check fails).  We use a derived
    // wrong key from a different seed.
    //
    // base64-encoded 32 zero bytes:
    let wrong_pubkey = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    let out = run_verify(&cose, wrong_pubkey, None);
    assert!(
        !out.status.success(),
        "canon-verify must reject a mismatched pubkey"
    );
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["verified"], serde_json::Value::Bool(false));
}

#[test]
fn verify_cli_rejects_bad_envelope_hex() {
    let (_cose, pubkey) = sign_one();
    let out = run_verify("not-hex-at-all", &pubkey, None);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["verified"], serde_json::Value::Bool(false));
    assert!(parsed["error"]
        .as_str()
        .unwrap_or("")
        .contains("hex decode"));
}

#[test]
fn verify_cli_usage_on_missing_args() {
    // No args at all — must exit 2 (arg-error) with usage to stderr.
    let out = Command::new(verify_bin())
        .output()
        .expect("failed to run canon-verify");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("USAGE:"), "stderr should contain USAGE");
}

#[test]
fn verify_cli_respects_explicit_kid_override() {
    let (cose, pubkey) = sign_one();

    // Derive the kid the same way the library does, then pass it
    // explicitly — must behave identically to the auto-derived path.
    let b64 = pubkey.strip_prefix("ed25519:").unwrap();
    let pk_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        b64,
    )
    .unwrap();
    let kid = format!("canon/{}", &hex::encode(&pk_bytes)[..16]);

    let out = run_verify(&cose, &pubkey, Some(&kid));
    assert!(out.status.success());

    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["verified"], serde_json::Value::Bool(true));
    assert_eq!(parsed["kid"].as_str().unwrap(), kid);
    // Unused constant: reminder that the test uses the real seed.
    let _ = TEST_SEED_HEX;
}
