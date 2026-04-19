//! Prints the pinned AWS Nitro Enclave Root G1 SHA-256 fingerprint as
//! lowercase hex on stdout, followed by a newline.
//!
//! This binary exists solely so the `nitro-root-fingerprint` CI job can
//! compare the in-tree constant against the live AWS-published root
//! without parsing Rust source. Linking the constant directly makes the
//! extracted value byte-identical to what `ephemeral-attestation`
//! consumes — no regex, no rustfmt sensitivity, no comment-churn risk.
//!
//! Output contract:
//! - exactly 64 lowercase hex characters (SHA-256 of the DER-encoded root)
//! - terminated by a single `\n`
//! - nothing else on stdout
//!
//! Matching `sha256sum` byte-for-byte is a hard requirement of the CI
//! comparison step; `hex::encode` is contractually lowercase.
//!
//! Returning `io::Result` (vs `expect()`-panic) means a closed stdout
//! or broken pipe causes a clean exit-code-1 rather than a Rust panic
//! trace in CI logs.

#![forbid(unsafe_code)]

use std::io::{self, Write};

use ephemeral_attestation::AWS_NITRO_ROOT_FINGERPRINT;

fn main() -> io::Result<()> {
    let hex = hex::encode(AWS_NITRO_ROOT_FINGERPRINT);
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{hex}")?;
    stdout.flush()
}
