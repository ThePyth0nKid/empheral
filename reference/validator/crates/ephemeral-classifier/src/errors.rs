//! Error surface for classifier loading and execution.
//!
//! Both enums are `#[non_exhaustive]`.  Phase C.3-A defines the minimal
//! variant set required for hash verification and basic execute; the
//! hermeticity-hardening variants (`ForbiddenOpcode`, `ImportNotAllowed`,
//! `FuelExhausted`, `MemoryCapExceeded`) are added in Phase C.3-B.

use thiserror::Error;

/// Failure surface for classifier *loading* — specifically, verification
/// of a WASM binary against a Tariff-pinned SHA-256 digest.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassifierLoadError {
    /// The expected-hash string is not a 64-character lowercase-hex digest.
    #[error("expected hash is not a 64-character lowercase-hex digest")]
    InvalidHashHex,

    /// `SHA-256(wasm_bytes)` does not match the expected digest.
    #[error("classifier WASM hash mismatch")]
    HashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

/// Failure surface for classifier *execution*.
///
/// The variant set in Phase C.3-A collapses categories of instantiation
/// failure (missing imports, start-section trap, link failure) into a
/// single `InstantiationFailed` variant.  Phase C.3-B splits these and
/// adds fuel/memory/import/opcode variants backed by pre-execute walks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassifierExecError {
    /// `wasmi::Module::new` could not parse the supplied WASM bytes.
    #[error("WASM module failed to parse")]
    WasmParseError,

    /// `wasmi::Linker::instantiate` failed.  In C.3-A this covers any
    /// import mismatch (empty linker rejects importing modules), start-
    /// section trap, or other instantiation-phase error.
    #[error("WASM instance could not be created")]
    InstantiationFailed,

    /// A required export (`memory`, `alloc`, or `classify`) is absent from
    /// the module, or its type signature does not match the ABI.
    #[error("required export `{name}` is missing or has the wrong type")]
    MissingExport { name: &'static str },

    /// The `alloc` export trapped (e.g. memory.grow failure).
    #[error("`alloc` trapped")]
    AllocCallTrap,

    /// The `classify` export trapped (e.g. unreachable, div-by-zero,
    /// explicit fuel exhaustion in later phases).
    #[error("`classify` trapped")]
    ClassifyCallTrap,

    /// An input or output memory access was out of bounds.
    #[error("WASM linear-memory access out of bounds")]
    MemoryAccessError,

    /// The caller-supplied context exceeds the `i32::MAX` byte envelope
    /// that the v1 ABI can address.
    #[error("input CBOR context is {len} bytes; ceiling is i32::MAX")]
    InputTooLarge { len: usize },

    /// CBOR deserialization of the classifier's output bytes failed
    /// (malformed CBOR, missing required field, wrong type, etc.).
    #[error("classifier output is not a valid CBOR-encoded ClassifierOutput")]
    OutputDecodeFailed,
}
