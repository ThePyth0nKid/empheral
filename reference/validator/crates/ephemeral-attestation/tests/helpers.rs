//! Re-export of `ephemeral-attestation-test-support` for integration tests.
//!
//! Logic lives in the shared test-support crate; this file is a thin facade so
//! existing `tests/nitro.rs`, `tests/rekor.rs`, and `tests/proptest_total.rs`
//! continue to compile without changes to their `use` statements.

pub use ephemeral_attestation_test_support::{build_attestation_doc, BuildParams};
