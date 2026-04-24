//! `canon-verify` — standalone verifier CLI for Canon fact envelopes.
//!
//! Takes a `cose_sign1_hex` envelope plus the signer's `ed25519:<base64>`
//! public key, verifies the signature via
//! `ephemeral_crypto::verify_cose_sign1` under
//! [`canon_signer::COSE_EXTERNAL_AAD`] and
//! `AnchorRole::CanonSigner`, and emits a single JSON line on stdout.
//!
//! On success (exit 0):
//! ```json
//! {"verified":true,"event_hash":"<sha256-hex>","kid":"canon/..."}
//! ```
//! On failure (exit 1):
//! ```json
//! {"verified":false,"error":"<reason>"}
//! ```
//!
//! This binary is intentionally tiny — it wraps the production
//! `ephemeral_crypto::verify_cose_sign1` library without introducing any
//! new crypto.  It exists so that Canon operators, auditors, and
//! hackathon judges can independently verify a signed fact from the
//! command line without pulling in the Rust toolchain: an Alpine static
//! build is a single ~3 MiB binary.

use std::fmt::Write as _;
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use canon_signer::cose::derive_kid;
use canon_signer::COSE_EXTERNAL_AAD;
use ephemeral_crypto::{verify_cose_sign1, AnchorRole, TrustAnchor, TrustAnchorSet};
use sha2::{Digest, Sha256};

const USAGE: &str = "\
canon-verify — verify a Canon fact COSE_Sign1 envelope

USAGE:
    canon-verify --envelope-hex <HEX> --pubkey <ed25519:BASE64> [--kid <canon/...>]

OPTIONS:
    --envelope-hex <HEX>         The `cose_sign1_hex` field from a signer response.
    --pubkey <ed25519:BASE64>    The `signer_pubkey` field from a signer response.
    --kid <canon/...>            Optional. Defaults to derive_kid(pubkey).
    --version                    Print version and exit.
    --help                       Print this help and exit.

EXIT CODES:
    0   envelope verified (payload is authentic and unmodified)
    1   verification failed (bad signature, wrong key, tampered envelope)
    2   argument error

OUTPUT:
    One JSON line on stdout:
      success → {\"verified\":true,\"event_hash\":\"...\",\"kid\":\"...\"}
      failure → {\"verified\":false,\"error\":\"...\"}
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut envelope_hex: Option<String> = None;
    let mut pubkey_wire: Option<String> = None;
    let mut kid_override: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("canon-verify {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--envelope-hex" => {
                i += 1;
                if i >= args.len() {
                    return arg_error("--envelope-hex requires a value");
                }
                envelope_hex = Some(args[i].clone());
            }
            "--pubkey" => {
                i += 1;
                if i >= args.len() {
                    return arg_error("--pubkey requires a value");
                }
                pubkey_wire = Some(args[i].clone());
            }
            "--kid" => {
                i += 1;
                if i >= args.len() {
                    return arg_error("--kid requires a value");
                }
                kid_override = Some(args[i].clone());
            }
            other => {
                return arg_error(&format!("unknown argument: {other}"));
            }
        }
        i += 1;
    }

    let Some(envelope_hex) = envelope_hex else {
        return arg_error("missing --envelope-hex");
    };
    let Some(pubkey_wire) = pubkey_wire else {
        return arg_error("missing --pubkey");
    };

    match run(&envelope_hex, &pubkey_wire, kid_override.as_deref()) {
        Ok(summary) => {
            println!(
                "{{\"verified\":true,\"event_hash\":\"{}\",\"kid\":\"{}\"}}",
                summary.event_hash, summary.kid
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            // JSON-escape the error so a quote in the message can't break parsers.
            println!(
                "{{\"verified\":false,\"error\":{}}}",
                json_string(&e.to_string())
            );
            ExitCode::from(1)
        }
    }
}

struct VerifySummary {
    event_hash: String,
    kid: String,
}

fn run(
    envelope_hex: &str,
    pubkey_wire: &str,
    kid_override: Option<&str>,
) -> Result<VerifySummary, VerifyError> {
    let envelope_bytes =
        hex::decode(envelope_hex).map_err(|e| VerifyError::BadEnvelopeHex(e.to_string()))?;

    let pubkey_bytes = parse_pubkey(pubkey_wire)?;
    let kid = match kid_override {
        Some(k) => k.to_string(),
        None => derive_kid(&pubkey_bytes),
    };

    let anchor = TrustAnchor::new_ed25519(kid.clone(), &pubkey_bytes, AnchorRole::CanonSigner)
        .map_err(|e| VerifyError::AnchorBuild(e.to_string()))?;
    let mut anchors = TrustAnchorSet::new();
    anchors
        .insert(anchor)
        .map_err(|e| VerifyError::AnchorBuild(e.to_string()))?;

    let verified = verify_cose_sign1(
        &envelope_bytes,
        &anchors,
        COSE_EXTERNAL_AAD,
        AnchorRole::CanonSigner,
    )
    .map_err(|e| VerifyError::Signature(e.to_string()))?;

    let event_hash = hex::encode(Sha256::digest(&verified.payload));
    Ok(VerifySummary {
        event_hash,
        kid: verified.kid,
    })
}

fn parse_pubkey(wire: &str) -> Result<[u8; 32], VerifyError> {
    let b64 = wire
        .strip_prefix("ed25519:")
        .ok_or_else(|| VerifyError::BadPubkey("expected ed25519:<base64> prefix".into()))?;
    let raw = B64
        .decode(b64)
        .map_err(|e| VerifyError::BadPubkey(format!("base64 decode failed: {e}")))?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| VerifyError::BadPubkey(format!("expected 32 bytes, got {}", raw.len())))
}

fn arg_error(msg: &str) -> ExitCode {
    eprintln!("ERROR: {msg}");
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn json_string(s: &str) -> String {
    // Minimal JSON string escape — sufficient for error strings we emit.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Can't fail: writing into a String.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, thiserror::Error)]
enum VerifyError {
    #[error("envelope hex decode failed: {0}")]
    BadEnvelopeHex(String),
    #[error("pubkey parse failed: {0}")]
    BadPubkey(String),
    #[error("trust anchor build failed: {0}")]
    AnchorBuild(String),
    #[error("signature verification failed: {0}")]
    Signature(String),
}
