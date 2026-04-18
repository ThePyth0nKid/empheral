//! Harness-internal error surface.
//!
//! Domain reject codes (e.g. `unicode-not-nfc`, `scope-tier-exceeded`) are
//! modeled per-suite as their own enums and **do not** flow through this type.
//! A vector expecting `reject` with `reject_code = "unicode-not-nfc"` is a
//! pass when the executor returns the matching reject-code enum variant.
//! [`ValidatorError`] captures only conditions where the harness itself
//! cannot produce a verdict.

use std::path::PathBuf;

/// Harness error surface.
#[derive(thiserror::Error, Debug)]
pub enum ValidatorError {
    #[error("I/O error reading {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON parse failure in {path}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("schema error")]
    Schema(#[from] SchemaError),

    #[error("codec error: {0}")]
    Codec(String),
}

/// JSON Schema compile/validate failures.
#[derive(thiserror::Error, Debug)]
pub enum SchemaError {
    #[error("schema file could not be read: {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("schema JSON parse failure in {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("schema compilation failed: {reason}")]
    Compile { reason: String },

    #[error("document at {document_path} failed schema validation: {summary}")]
    Invalid {
        document_path: PathBuf,
        summary: String,
        /// One formatted entry per validation error. Deterministic order
        /// (source iteration order, which `jsonschema` already stabilizes).
        errors: Vec<String>,
    },
}
