//! EPHEMERAL Classifier WASM execution primitives (Phase C.3-A).
//!
//! This crate hosts the live-WASM classifier pipeline:
//!
//! - SHA-256 hash verification of WASM binaries against a Tariff-pinned
//!   digest (spec §4.1: *"Tariff pins its hash; only this exact WASM runs"*).
//! - Deterministic execution via [`wasmi`] — an interpreter-only engine
//!   chosen for its small TCB, determinism-by-construction, and absence
//!   of JIT codegen surface.
//! - Hermetic sandbox semantics per spec §4.3 (no network, no filesystem,
//!   no host imports).  C.3-A achieves soft-hermeticity via an empty
//!   [`wasmi::Linker`]; the explicit reject-before-execute walk, fuel cap,
//!   memory cap, and forbidden-opcode validation land in Phase C.3-B.
//!
//! # Classifier WASM ABI (v1)
//!
//! A conformant classifier module MUST export three items:
//!
//! - `memory` (linear memory) — the host writes input here and reads output
//!   here.
//! - `alloc(size: i32) -> i32` — returns a byte offset in memory where the
//!   host may write `size` bytes of CBOR-encoded input.  The returned region
//!   MUST NOT overlap any region the module reads during `classify`.
//! - `classify(input_ptr: i32, input_len: i32) -> i64` — reads CBOR-encoded
//!   classifier context from `memory[input_ptr .. input_ptr + input_len]`,
//!   produces CBOR-encoded [`ClassifierOutput`] somewhere in memory, and
//!   returns a packed locator:
//!   `(output_ptr as u64) << 32 | (output_len as u64)`.
//!
//! The module MUST NOT declare any imports.  Phase C.3-A relies on the
//! empty linker to fail instantiation of any importing module; Phase C.3-B
//! adds an explicit pre-instantiation import-section walk with a dedicated
//! reject code.
//!
//! # Example
//!
//! ```no_run
//! use ephemeral_classifier::{execute_classifier, verify_classifier_hash};
//!
//! let wasm_bytes: &[u8] = &[]; // classifier WASM, sourced elsewhere
//! let pinned_hash = "0000000000000000000000000000000000000000000000000000000000000000";
//! let context_cbor: &[u8] = &[]; // CBOR-encoded ClassifierContext
//!
//! verify_classifier_hash(wasm_bytes, pinned_hash)?;
//! let output = execute_classifier(wasm_bytes, context_cbor)?;
//! println!("tier = {}", output.tier);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod errors;
pub mod hash;
pub mod output;
pub mod runtime;

pub use errors::{ClassifierExecError, ClassifierLoadError};
pub use hash::verify_classifier_hash;
pub use output::ClassifierOutput;
pub use runtime::execute_classifier;
