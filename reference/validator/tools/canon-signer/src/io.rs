//! NDJSON wire types and the stdin-loop driver.
//!
//! One request per line on stdin; one response (success or error) per
//! line on stdout.  `writeln!` + `flush` after every line so a
//! consumer (Canon) reading line-by-line never deadlocks on a
//! buffered-stdout race.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::cose::{build_cose_sign1, derive_kid};
use crate::event::{encode_payload, event_hash};
use crate::key::SignerIdentity;

/// A `sign` request from Canon.
///
/// `op` is accepted permissively: only `"sign"` is valid today; any
/// other value yields an error response.  Future ops (e.g. `"verify"`)
/// can be added without a schema break.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignRequest {
    pub op: String,
    pub fact_id: String,
    pub entity: String,
    pub claim: String,
    pub source_ref: String,
    #[serde(default)]
    pub source_excerpt: Option<String>,
    pub parent_hash: String,
    pub created_at_ms: u64,
}

/// A successful sign response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub fact_id: String,
    pub event_hash: String,
    pub cose_sign1_hex: String,
    pub signer_pubkey: String,
    pub signed_at_ms: u64,
}

/// A human-readable error response.  `error` is a short slug for
/// machine dispatch; `detail` is free-form text for human logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub detail: String,
}

/// Either a successful sign response or an error, serialised as a
/// single JSON object.  Uses `serde(untagged)` so the output shape is
/// exactly the spec (no `"type"` discriminator field).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Response {
    Ok(SignResponse),
    Err(ErrorResponse),
}

/// Handle one request line: parse, sign, return a serialisable response.
///
/// `now_ms` is injected (rather than read from the clock) so tests can
/// pin reproducible timestamps; the production binary passes
/// `SystemTime::now()`-derived ms.
pub fn handle_line(line: &str, identity: &SignerIdentity, now_ms: u64) -> Response {
    let req: SignRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Response::Err(ErrorResponse {
                error: "parse_error".to_string(),
                detail: format!("invalid JSON: {e}"),
            });
        }
    };

    if req.op != "sign" {
        return Response::Err(ErrorResponse {
            error: "parse_error".to_string(),
            detail: format!("unsupported op: {}", req.op),
        });
    }

    let payload = match encode_payload(&req) {
        Ok(p) => p,
        Err(e) => {
            return Response::Err(ErrorResponse {
                error: "parse_error".to_string(),
                detail: format!("payload encode failed: {e}"),
            });
        }
    };

    let hash = event_hash(&payload);

    let envelope = match build_cose_sign1(&payload, identity.signing_key(), identity.kid()) {
        Ok(e) => e,
        Err(e) => {
            return Response::Err(ErrorResponse {
                error: "internal_error".to_string(),
                detail: format!("COSE_Sign1 build failed: {e}"),
            });
        }
    };

    Response::Ok(SignResponse {
        fact_id: req.fact_id,
        event_hash: hash,
        cose_sign1_hex: hex::encode(envelope),
        signer_pubkey: identity.pubkey_wire_string(),
        signed_at_ms: now_ms,
    })
}

/// Run the stdin-loop against the supplied reader/writer pair.
///
/// Exposed as a library function (rather than inlined in `main`) so
/// integration tests can drive the loop with synthetic pipes without
/// spawning a subprocess when they do not need process-boundary
/// coverage.
pub fn run_stdin_loop<R: BufRead, W: Write, F: FnMut() -> u64>(
    mut input: R,
    mut output: W,
    identity: &SignerIdentity,
    mut now_ms_fn: F,
) -> std::io::Result<()> {
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = input.read_line(&mut buf)?;
        if n == 0 {
            return Ok(()); // clean EOF
        }
        let line = buf.trim_end_matches(['\n', '\r']);
        if line.is_empty() {
            continue;
        }
        let response = handle_line(line, identity, now_ms_fn());
        let json =
            serde_json::to_string(&response).expect("Response always serialises to valid JSON");
        writeln!(output, "{json}")?;
        output.flush()?;
    }
}

/// Derive the wire-format pubkey string `ed25519:<base64(32 raw bytes)>`.
pub fn encode_pubkey_wire_string(pubkey_bytes: &[u8; 32]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    format!("ed25519:{}", STANDARD.encode(pubkey_bytes))
}

/// Derive `kid` + `pubkey_wire_string` together from a verifying key's
/// raw bytes — used by `SignerIdentity` at load time.
pub fn derive_public_identity(pubkey_bytes: &[u8; 32]) -> (String, String) {
    (
        derive_kid(pubkey_bytes),
        encode_pubkey_wire_string(pubkey_bytes),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::SignerIdentity;
    use ed25519_dalek::SigningKey;

    fn fixed_identity() -> SignerIdentity {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        SignerIdentity::from_signing_key(sk)
    }

    fn request_line() -> String {
        r#"{"op":"sign","fact_id":"f1","entity":"e","claim":"c","source_ref":"s","source_excerpt":null,"parent_hash":"","created_at_ms":0}"#.to_string()
    }

    #[test]
    fn valid_request_yields_ok_response() {
        let id = fixed_identity();
        let response = handle_line(&request_line(), &id, 1_000);
        match response {
            Response::Ok(r) => {
                assert_eq!(r.fact_id, "f1");
                assert_eq!(r.event_hash.len(), 64);
                assert!(!r.cose_sign1_hex.is_empty());
                assert!(r.signer_pubkey.starts_with("ed25519:"));
                assert_eq!(r.signed_at_ms, 1_000);
            }
            Response::Err(e) => panic!("expected Ok, got error: {e:?}"),
        }
    }

    #[test]
    fn malformed_json_yields_parse_error() {
        let id = fixed_identity();
        let response = handle_line("not json", &id, 0);
        match response {
            Response::Err(e) => assert_eq!(e.error, "parse_error"),
            Response::Ok(_) => panic!("expected error on malformed JSON"),
        }
    }

    #[test]
    fn unsupported_op_yields_parse_error() {
        let id = fixed_identity();
        let line = r#"{"op":"verify","fact_id":"f1","entity":"e","claim":"c","source_ref":"s","source_excerpt":null,"parent_hash":"","created_at_ms":0}"#;
        let response = handle_line(line, &id, 0);
        match response {
            Response::Err(e) => {
                assert_eq!(e.error, "parse_error");
                assert!(e.detail.contains("unsupported op"));
            }
            Response::Ok(_) => panic!("expected error on unsupported op"),
        }
    }

    #[test]
    fn invalid_parent_hash_yields_parse_error() {
        let id = fixed_identity();
        let line = r#"{"op":"sign","fact_id":"f1","entity":"e","claim":"c","source_ref":"s","source_excerpt":null,"parent_hash":"not-hex","created_at_ms":0}"#;
        let response = handle_line(line, &id, 0);
        match response {
            Response::Err(e) => assert_eq!(e.error, "parse_error"),
            Response::Ok(_) => panic!("expected error on invalid parent_hash"),
        }
    }

    #[test]
    fn run_loop_processes_multiple_lines_and_exits_on_eof() {
        let id = fixed_identity();
        let input = format!("{}\n{}\n", request_line(), request_line());
        let mut output = Vec::new();
        let mut counter = 0u64;
        run_stdin_loop(
            std::io::Cursor::new(input.as_bytes()),
            &mut output,
            &id,
            || {
                counter += 1;
                counter
            },
        )
        .unwrap();

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["fact_id"], "f1");
        }
    }

    #[test]
    fn run_loop_survives_bad_line_between_good_lines() {
        let id = fixed_identity();
        let input = format!("{}\nnot json\n{}\n", request_line(), request_line());
        let mut output = Vec::new();
        run_stdin_loop(
            std::io::Cursor::new(input.as_bytes()),
            &mut output,
            &id,
            || 0,
        )
        .unwrap();

        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "one response per input line");
        // Line 2 is the parse-error response.
        let parsed: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed["error"], "parse_error");
    }

    #[test]
    fn run_loop_skips_blank_lines() {
        let id = fixed_identity();
        let input = format!("\n\n{}\n", request_line());
        let mut output = Vec::new();
        run_stdin_loop(
            std::io::Cursor::new(input.as_bytes()),
            &mut output,
            &id,
            || 0,
        )
        .unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn pubkey_wire_string_format_is_stable() {
        let bytes = [0u8; 32];
        let s = encode_pubkey_wire_string(&bytes);
        assert!(s.starts_with("ed25519:"));
        // 32 bytes → 44 base64 chars (including padding).
        assert_eq!(&s["ed25519:".len()..].len(), &44);
    }
}
