//! Per-suite semantic executors.
//!
//! Each vector file (one per suite) dispatches through [`crate::runner`] to a
//! suite-specific executor in this module. Each executor returns a
//! [`crate::ValidationOutcome`] for every vector; harness-level failures flow
//! through [`crate::ValidatorError`] instead.
//!
//! Session 2 implements **canonicalization** and **delegation-scope**. The
//! remaining four suites (fuzz-baseline, tariff-reject, pcr-attestation-reject,
//! audit-replay) stay [`crate::ValidationOutcome::Skipped`] with
//! [`crate::SkipReason::SuiteNotImplementedThisSession`].

pub mod canonicalization;
pub mod delegation;
