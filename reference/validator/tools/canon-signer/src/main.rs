//! `canon-signer` binary entry-point.
//!
//! Parses minimal CLI args (`--keyfile <path>`, `--help`, `--version`),
//! loads the signing identity, logs a single startup line to stderr,
//! then blocks on the stdin-loop until EOF.
//!
//! Keep this file thin: all meaningful behaviour lives in the library
//! modules so it can be exercised by unit and integration tests.

use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use canon_signer::io as csio;
use canon_signer::key::{self, Source};

const USAGE: &str = "\
canon-signer — Canon fact-signing CLI sidecar

USAGE:
    canon-signer [--keyfile <path>]

OPTIONS:
    --keyfile <path>    Load the Ed25519 seed from <path> (64 hex chars).
    --version           Print version and exit.
    --help              Print this help and exit.

ENVIRONMENT:
    CANON_SIGNER_KEY_HEX    Ed25519 seed as 64 hex chars. Takes priority
                            over --keyfile if both are set.

PROTOCOL:
    One NDJSON request per line on stdin; one response per line on
    stdout.  See <repo>/planning/canon-signer.md for the full schema.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut keyfile: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("canon-signer {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--keyfile" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("ERROR: --keyfile requires a path argument");
                    return ExitCode::from(2);
                }
                keyfile = Some(PathBuf::from(&args[i]));
            }
            other => {
                eprintln!("ERROR: unknown argument: {other}");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let (identity, source) = match key::load(keyfile.as_deref()) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("ERROR: key loading failed: {e}");
            return ExitCode::from(2);
        }
    };

    match &source {
        Source::Env => {
            eprintln!(
                "canon-signer: using key from CANON_SIGNER_KEY_HEX; pubkey={}",
                identity.pubkey_wire_string()
            );
        }
        Source::Keyfile(path) => {
            eprintln!(
                "canon-signer: using key from {}; pubkey={}",
                path.display(),
                identity.pubkey_wire_string()
            );
        }
        Source::Generated { persisted_to } => match persisted_to {
            Some(path) => eprintln!(
                "canon-signer: using ephemeral key (auto-generated, persisted to {}); \
                     pubkey={}",
                path.display(),
                identity.pubkey_wire_string()
            ),
            None => eprintln!(
                "canon-signer: using ephemeral key (auto-generated, NOT persisted — \
                     restart will produce a fresh key); pubkey={}",
                identity.pubkey_wire_string()
            ),
        },
    }
    let _ = io::stderr().flush();

    let stdin = io::stdin().lock();
    let stdout = io::stdout().lock();
    let reader = BufReader::new(stdin);

    if let Err(e) = csio::run_stdin_loop(reader, stdout, &identity, now_ms) {
        eprintln!("canon-signer: stdin-loop terminated with IO error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
