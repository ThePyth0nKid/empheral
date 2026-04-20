//! EPHEMERAL Classifier WASM execution primitives.
//!
//! This crate hosts the live-WASM classifier pipeline:
//!
//! - **Hash pinning** (Phase C.3-A): SHA-256 verification of WASM
//!   binaries against a Tariff-pinned digest (spec §4.1).
//! - **Hermetic execution** (Phase C.3-A): Deterministic, import-free
//!   execution via [`wasmi`] — an interpreter-only engine chosen for
//!   its small TCB, determinism-by-construction, and absence of JIT
//!   codegen surface.
//! - **Strict ABI v1 load-time validation** (Phase C.3-B): pre-
//!   instantiation rejection of imports, of start-functions, and of
//!   wrong-signature exports.  See [`validate`].
//! - **Resource-capped execution** (Phase C.3-B): every invocation is
//!   bounded by [`ClassifierConfig::fuel_budget`] (CPU),
//!   [`ClassifierConfig::max_memory_pages`] (guest linear memory),
//!   and [`ClassifierConfig::max_output_bytes`] (host receive buffer).
//! - **Post-MVP feature disables** (Phase C.3-B): SIMD, bulk-memory,
//!   reference-types, tail-calls, and every other post-MVP Wasm
//!   proposal that isn't in ABI v1 is rejected at parse time.
//!
//! # Classifier WASM ABI ([`CLASSIFIER_ABI_VERSION`])
//!
//! A conformant classifier module MUST export exactly three items with
//! the signatures below, MUST declare zero imports, and MUST NOT
//! declare a `(start …)` function:
//!
//! - `memory` (linear memory) — the host writes input here and reads
//!   output here.
//! - `alloc(size: i32) -> i32` — returns a byte offset in memory where
//!   the host may write `size` bytes of CBOR-encoded input.  The
//!   returned region MUST NOT overlap any region the module reads
//!   during `classify`.
//! - `classify(input_ptr: i32, input_len: i32) -> i64` — reads
//!   CBOR-encoded classifier context from
//!   `memory[input_ptr .. input_ptr + input_len]`, produces
//!   CBOR-encoded [`ClassifierOutput`] somewhere in memory, and
//!   returns a packed locator:
//!   `(output_ptr as u64) << 32 | (output_len as u64)`.
//!
//! # Example
//!
//! ```no_run
//! use ephemeral_classifier::{
//!     execute_classifier, verify_classifier_hash, ClassifierConfig,
//! };
//!
//! let wasm_bytes: &[u8] = &[]; // classifier WASM, sourced elsewhere
//! let pinned_hash = "0000000000000000000000000000000000000000000000000000000000000000";
//! let context_cbor: &[u8] = &[]; // CBOR-encoded ClassifierContext
//!
//! verify_classifier_hash(wasm_bytes, pinned_hash)?;
//! let output = execute_classifier(
//!     wasm_bytes,
//!     context_cbor,
//!     &ClassifierConfig::default(),
//! )?;
//! println!("tier = {}", output.tier);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

/// ABI revision implemented by this crate's [`execute_classifier`].
///
/// This constant names the contract documented in the crate-level
/// `# Classifier WASM ABI` section above.  A breaking change to
/// the ABI (export shape, signature, or semantics) MUST bump this
/// value; Tariff-level metadata SHOULD record the expected ABI
/// version at sign time so a mismatch is detectable before execution.
///
/// Phase C.3-B does not require an explicit version export from the
/// WASM module itself — version gating is a Tariff-layer concern
/// and would couple this crate to out-of-scope metadata.
pub const CLASSIFIER_ABI_VERSION: u32 = 1;

pub mod config;
pub mod errors;
pub mod hash;
pub mod limiter;
pub mod output;
pub mod runtime;
pub mod signature;
pub mod validate;

/// Test-only fixture module — canned WAT classifier sources, a shared
/// pre-compiled WASM artifact pool, and a deterministic classifier
/// signing helper.  Kept behind the `test_fixtures` feature so its
/// `ed25519-dalek` / `coset` signing surface cannot reach a production
/// consumer.  The `ephemeral-prod-symbol-probe` rlib scan enforces
/// that the feature stays opt-in.
#[cfg(feature = "test_fixtures")]
pub mod test_fixtures;

pub use config::{
    ClassifierConfig, DEFAULT_FUEL_BUDGET, DEFAULT_MAX_MEMORY_PAGES, DEFAULT_MAX_OUTPUT_BYTES,
    WASM_PAGE_SIZE,
};
pub use errors::{ClassifierError, ClassifierExecError, ClassifierLoadError, ClassifierSigError};
pub use hash::verify_classifier_hash;
pub use output::ClassifierOutput;
pub use runtime::execute_classifier;
pub use signature::{
    verify_classifier_signature, ClassifierSigPayload, VerifiedClassifierSignature,
    CLASSIFIER_AAD,
};
