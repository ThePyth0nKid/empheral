//! EPHEMERAL reference validator — core library.
//!
//! Structural and (in later sessions) semantic conformance validation for the
//! EPHEMERAL Agent-Authority Protocol. The validator loads JSON conformance
//! vector files, validates them against the normative JSON Schema, and routes
//! each vector to its suite-specific execution logic.
//!
//! # Session 1 scope
//!
//! - Types, error surface, suite-file loader
//! - JSON Schema 2020-12 validation of every loaded file
//! - `CoreValue` representation with JSON roundtrip
//!
//! Semantic suite executors (canonicalization, delegation, tariff, PCR, audit
//! replay, fuzz) land in Sessions 2 and 3. Vectors in unimplemented suites
//! surface as [`ValidationOutcome::Skipped`].
//!
//! # Error discipline
//!
//! [`ValidatorError`] is reserved for harness-internal failures (I/O, schema
//! compilation, unexpected parse errors). Domain-level reject codes are
//! modeled per-suite and flow through `Result<AcceptShape, RejectCode>` inside
//! individual executors; they are a pass signal, not an error, when the
//! corresponding vector expects `reject`.

#![doc(html_root_url = "https://docs.rs/ephemeral-core/0.1.0")]

pub mod codec;
pub mod error;
pub mod runner;
pub mod schema;
pub mod suite_file;
pub mod types;

pub use codec::{core_to_json, json_to_core, CoreToJsonError, CoreValue, MAX_JSON_DEPTH};
pub use error::{SchemaError, ValidatorError};
pub use runner::{run_file, run_many, FileRunResult, RunConfig};
pub use suite_file::{load_suite_file, LoadedSuite, MAX_SUITE_FILE_BYTES};
pub use types::{
    ExpectedOutcome, Outcome, Severity, SkipReason, SuiteFile, SuiteReport, TestReport,
    ValidationOutcome, Vector, VectorFailure, VectorSuite,
};
