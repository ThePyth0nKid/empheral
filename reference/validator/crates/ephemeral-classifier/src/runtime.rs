//! WASM execution for the EPHEMERAL classifier (Phase C.3-A).
//!
//! Execute path:
//!
//! - Parse the module, instantiate with an empty [`wasmi::Linker`].
//! - Call the `alloc` + `classify` v1 ABI.
//! - Decode the CBOR-encoded [`ClassifierOutput`].
//!
//! Safety envelope already enforced in C.3-A:
//!
//! - **Fuel budget** ([`DEFAULT_FUEL_BUDGET`]) on `classify` — traps
//!   infinite loops and quadratic-pathological modules before they
//!   exhaust the validator thread.
//! - **Output-size ceiling** ([`MAX_OUTPUT_BYTES`]) on the packed
//!   locator's length field — guards against an attacker-controlled
//!   4 GiB allocation on the host heap.
//! - **Empty-linker import rejection** — any module declaring imports
//!   fails instantiation because the linker has no symbols to satisfy.
//!
//! The following hermeticity-hardening work is scoped to Phase C.3-B:
//!
//! - Explicit pre-instantiation import-section walk (dedicated reject
//!   code, rather than a generic instantiation failure).
//! - Linear-memory cap via a `ResourceLimiter`.
//! - Forbidden-opcode validation (`f32.*`, `f64.*`, SIMD) to eliminate
//!   the theoretical NaN / SIMD determinism edge even under a pure
//!   interpreter.
//! - Caller-configurable fuel and memory budgets via a `ClassifierConfig`.

use wasmi::{Config, Engine, Linker, Module, Store, TypedFunc};

use crate::errors::ClassifierExecError;
use crate::output::ClassifierOutput;

/// Crate-level fuel ceiling for a single `classify` invocation.
///
/// Rationale: one wasmi instruction consumes one fuel unit. 100 million
/// instructions on the wasmi interpreter completes in roughly one second
/// on modern `x86_64` — several orders of magnitude above any legitimate
/// classifier (spec §4 implies simple table lookups + string comparisons,
/// well under 10k instructions per call). The budget is deliberately
/// generous to absorb future classifier growth, yet still interrupts an
/// infinite loop or a quadratic-pathological module before it stalls
/// the validator thread.
///
/// Phase C.3-B will promote this to a caller-configurable knob on a
/// `ClassifierConfig` struct.
pub const DEFAULT_FUEL_BUDGET: u64 = 100_000_000;

/// Ceiling on the byte length the classifier may claim in the packed
/// output locator.
///
/// Rationale: a valid [`ClassifierOutput`] — even with a generous
/// escalations list — is well under 64 KiB. Capping at 1 MiB gives
/// roughly 16× headroom over any realistic output while rejecting a
/// byte-length field of `0xFFFF_FFFF` (≈ 4 GiB — the maximum the `u32`
/// field can express) before the `vec![0u8; _]` call OOM-kills the
/// validator process.
///
/// A WASM module that returns `output_len > MAX_OUTPUT_BYTES` is
/// rejected with [`ClassifierExecError::MemoryAccessError`] — the same
/// variant used for out-of-bounds linear-memory reads; both represent
/// "the module asked for bytes the host declines to provide".
pub const MAX_OUTPUT_BYTES: usize = 1 << 20;

/// Unpack the `(output_ptr << 32) | output_len` locator returned by
/// `classify` into host-usable byte offsets.
///
/// `packed` is `i64` per the ABI; the bits are reinterpreted as `u64`
/// before shifting. Both halves are `u32`, which fits `usize` on every
/// 32-bit and 64-bit target — the only targets this crate compiles for —
/// so the `usize::try_from` conversions are statically infallible. The
/// `expect` branches are dead code, retained for self-documentation and
/// to make any future port to an exotic target (16-bit `usize`) fail
/// loudly rather than silently truncate.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn unpack_locator(packed: i64) -> (usize, usize) {
    let packed_u64 = packed as u64;
    let ptr_u32 = (packed_u64 >> 32) as u32;
    let len_u32 = packed_u64 as u32;
    (
        usize::try_from(ptr_u32).expect("u32 fits usize on 32/64-bit targets"),
        usize::try_from(len_u32).expect("u32 fits usize on 32/64-bit targets"),
    )
}

/// Execute the classifier WASM against the supplied CBOR-encoded context
/// and return the structured [`ClassifierOutput`].
///
/// The module's ABI is documented at the crate root.
///
/// Each call constructs a fresh [`Engine`], [`Store`], and [`Linker`].
/// The per-call cost is acceptable for C.3-A's throughput target
/// (batch-validated Tariff conformance vectors run at ~100 Hz, not
/// ~10 kHz). Phase C.3-B may introduce a caller-owned, reusable
/// `ClassifierEngine` wrapper for higher-throughput deployments.
///
/// # Errors
/// Returns [`ClassifierExecError`] variants for parse failure, instantiation
/// failure, missing or malformed exports, runtime traps in `alloc` or
/// `classify` (including fuel exhaustion, which surfaces as
/// [`ClassifierExecError::ClassifyCallTrap`] in C.3-A), memory access
/// violations, output-size ceiling violations, and output-decode failures.
pub fn execute_classifier(
    wasm_bytes: &[u8],
    context_cbor: &[u8],
) -> Result<ClassifierOutput, ClassifierExecError> {
    // Explicit config — do NOT collapse to `Engine::default()`. A future
    // wasmi default that flips determinism-relevant knobs (e.g. NaN
    // handling, stack depth) would silently void C.3-A's guarantees;
    // building the config by hand keeps the TCB visible in this file.
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);

    let module =
        Module::new(&engine, wasm_bytes).map_err(|_| ClassifierExecError::WasmParseError)?;
    let mut store = Store::new(&engine, ());
    // `set_fuel` only fails when `consume_fuel` is disabled on the engine,
    // which we just enabled. Any future refactor that accidentally drops
    // the `consume_fuel(true)` call will surface this `expect` loudly
    // rather than silently run an unfueled interpreter.
    store
        .set_fuel(DEFAULT_FUEL_BUDGET)
        .expect("fuel metering is enabled on the engine");

    let linker: Linker<()> = Linker::new(&engine);

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|_| ClassifierExecError::InstantiationFailed)?
        .start(&mut store)
        .map_err(|_| ClassifierExecError::InstantiationFailed)?;

    let memory = instance
        .get_memory(&store, "memory")
        .ok_or(ClassifierExecError::MissingExport { name: "memory" })?;

    let alloc: TypedFunc<i32, i32> = instance
        .get_typed_func(&store, "alloc")
        .map_err(|_| ClassifierExecError::MissingExport { name: "alloc" })?;

    let classify: TypedFunc<(i32, i32), i64> = instance
        .get_typed_func(&store, "classify")
        .map_err(|_| ClassifierExecError::MissingExport { name: "classify" })?;

    // ABI addresses memory with `i32`; caller contexts larger than
    // `i32::MAX` cannot be represented.
    let input_len_i32 =
        i32::try_from(context_cbor.len()).map_err(|_| ClassifierExecError::InputTooLarge {
            len: context_cbor.len(),
        })?;

    let input_ptr = alloc
        .call(&mut store, input_len_i32)
        .map_err(|_| ClassifierExecError::AllocCallTrap)?;

    // WASM ABI convention: an `i32` pointer is an unsigned byte offset.
    // `usize::try_from(u32)` is statically infallible on 32/64-bit
    // targets; see `unpack_locator` for the same invariant.
    #[allow(clippy::cast_sign_loss)]
    let input_offset =
        usize::try_from(input_ptr as u32).expect("u32 fits usize on 32/64-bit targets");

    memory
        .write(&mut store, input_offset, context_cbor)
        .map_err(|_| ClassifierExecError::MemoryAccessError)?;

    let packed = classify
        .call(&mut store, (input_ptr, input_len_i32))
        .map_err(|_| ClassifierExecError::ClassifyCallTrap)?;

    let (output_offset, output_size) = unpack_locator(packed);

    // Enforce the host-side allocation ceiling BEFORE `vec![0u8; _]`.
    // A WASM module that legitimately passes hash-pin verification can
    // still emit an attacker-controlled `output_len`; without this check
    // a 4 GiB length field would OOM-kill the validator process on most
    // 64-bit hosts.
    if output_size > MAX_OUTPUT_BYTES {
        return Err(ClassifierExecError::MemoryAccessError);
    }

    let mut output_bytes = vec![0u8; output_size];
    memory
        .read(&store, output_offset, &mut output_bytes)
        .map_err(|_| ClassifierExecError::MemoryAccessError)?;

    ciborium::from_reader(output_bytes.as_slice())
        .map_err(|_| ClassifierExecError::OutputDecodeFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_locator_preserves_bit_layout() {
        // All-zero: ptr=0, len=0.
        assert_eq!(unpack_locator(0), (0, 0));

        // Identity: (ptr=1, len=2) packs to 0x0000_0001_0000_0002 = 4_294_967_298.
        assert_eq!(unpack_locator(4_294_967_298_i64), (1, 2));

        // All-ones: both halves are 0xFFFF_FFFF (maximum u32).
        assert_eq!(
            unpack_locator(-1_i64),
            (0xFFFF_FFFF_usize, 0xFFFF_FFFF_usize)
        );

        // Sign-bit set in `packed`: the ABI treats the bits as unsigned, so
        // `i64::MIN` (0x8000_0000_0000_0000) must decode to
        // ptr=0x8000_0000, len=0.
        assert_eq!(unpack_locator(i64::MIN), (0x8000_0000_usize, 0));

        // High-half only: packed = 0xFFFF_FFFF_0000_0000_u64 as i64.
        #[allow(clippy::cast_possible_wrap)]
        let hi_only = 0xFFFF_FFFF_0000_0000_u64 as i64;
        assert_eq!(unpack_locator(hi_only), (0xFFFF_FFFF_usize, 0));

        // Low-half only: packed = 0x0000_0000_FFFF_FFFF.
        assert_eq!(
            unpack_locator(0x0000_0000_FFFF_FFFF_i64),
            (0, 0xFFFF_FFFF_usize)
        );
    }

    /// Build a minimal WASM classifier that ignores its input and returns
    /// a fixed CBOR-encoded [`ClassifierOutput`].  Exercises the complete
    /// execute-path end-to-end without depending on a real classifier.
    fn build_fixed_output_wasm(output: &ClassifierOutput) -> Vec<u8> {
        use std::fmt::Write as _;

        let mut cbor = Vec::new();
        ciborium::into_writer(output, &mut cbor).expect("cbor encode");

        let output_offset: u32 = 256;
        let alloc_offset: u32 = 4096; // well clear of the output data segment
        let cbor_len = u32::try_from(cbor.len()).expect("cbor fits u32");
        let packed: u64 = (u64::from(output_offset) << 32) | u64::from(cbor_len);

        // WAT data-segment strings use `\xx` hex escapes per byte.
        let mut cbor_escaped = String::with_capacity(cbor.len() * 4);
        for b in &cbor {
            write!(cbor_escaped, "\\{b:02x}").expect("String write is infallible");
        }

        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const {output_offset}) "{cbor_escaped}")
              (func (export "alloc") (param i32) (result i32)
                i32.const {alloc_offset})
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );

        wat::parse_str(&wat_src).expect("wat parse")
    }

    #[test]
    fn executes_tier0_classifier() {
        let expected = ClassifierOutput {
            tier: 0,
            reason_code: "read-only".into(),
            reason_text: "k8s list pod".into(),
            escalations: Vec::new(),
            justification_tag: "read-only-metadata".into(),
        };
        let wasm = build_fixed_output_wasm(&expected);
        let ctx = b"ignored-by-this-fixture";

        let actual = execute_classifier(&wasm, ctx).expect("execute");
        assert_eq!(actual, expected);
    }

    #[test]
    fn executes_tier5_classifier() {
        let expected = ClassifierOutput {
            tier: 5,
            reason_code: "catastrophic".into(),
            reason_text: "control-plane drain".into(),
            escalations: vec!["is-control-plane-node".into()],
            justification_tag: "destructive broad".into(),
        };
        let wasm = build_fixed_output_wasm(&expected);
        let actual = execute_classifier(&wasm, &[]).expect("execute");
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_malformed_wasm() {
        let garbage = b"\x00\x00\x00\x00not-a-wasm-header";
        let err = execute_classifier(garbage, &[]).unwrap_err();
        assert!(matches!(err, ClassifierExecError::WasmParseError));
    }

    #[test]
    fn rejects_module_without_memory_export() {
        let wat_src = r#"
            (module
              (memory 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(
            err,
            ClassifierExecError::MissingExport { name: "memory" }
        ));
    }

    #[test]
    fn rejects_module_without_alloc_export() {
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(
            err,
            ClassifierExecError::MissingExport { name: "alloc" }
        ));
    }

    #[test]
    fn rejects_module_without_classify_export() {
        // Fails on name lookup (the module has no `classify` export at
        // all); see `rejects_module_with_wrong_classify_signature` for
        // the separate type-mismatch path that uses the same error
        // variant.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(
            err,
            ClassifierExecError::MissingExport { name: "classify" }
        ));
    }

    #[test]
    fn rejects_module_with_wrong_classify_signature() {
        // classify returns i32 instead of i64.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 0)
              (func (export "classify") (param i32 i32) (result i32)
                i32.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(
            err,
            ClassifierExecError::MissingExport { name: "classify" }
        ));
    }

    #[test]
    fn rejects_module_with_imports() {
        // The empty linker cannot satisfy any import, so instantiation
        // fails.  C.3-B will intercept this at a pre-instantiation walk
        // with a dedicated reject code.
        let wat_src = r#"
            (module
              (import "env" "host_log" (func (param i32)))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(err, ClassifierExecError::InstantiationFailed));
    }

    #[test]
    fn rejects_classify_returning_out_of_bounds_output_pointer() {
        // classify returns a packed locator pointing at offset
        // 0x0001_0000 (one page past the single-page memory).
        // Output read must fail with MemoryAccessError.
        let output_offset: u32 = 0x0001_0000; // exactly at page boundary
        let output_len: u32 = 32;
        let packed: u64 = (u64::from(output_offset) << 32) | u64::from(output_len);
        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );
        let wasm = wat::parse_str(&wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(err, ClassifierExecError::MemoryAccessError));
    }

    #[test]
    fn rejects_classify_returning_invalid_cbor() {
        // classify points at memory region containing all-zeros, which is
        // not a valid CBOR map.
        let output_offset: u32 = 0;
        let output_len: u32 = 16;
        let packed: u64 = (u64::from(output_offset) << 32) | u64::from(output_len);
        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 4096)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );
        let wasm = wat::parse_str(&wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(err, ClassifierExecError::OutputDecodeFailed));
    }

    #[test]
    fn rejects_classify_returning_oversized_output_len() {
        // Length field one byte past the host-side ceiling.  Even though
        // the module holds a valid hash pin, a 1-MiB + 1-byte claim must
        // not allocate on the host.
        let output_offset: u32 = 0;
        let output_len = u32::try_from(MAX_OUTPUT_BYTES + 1)
            .expect("ceiling + 1 fits u32 for any realistic cap");
        let packed: u64 = (u64::from(output_offset) << 32) | u64::from(output_len);
        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );
        let wasm = wat::parse_str(&wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(err, ClassifierExecError::MemoryAccessError));
    }

    #[test]
    fn rejects_classify_infinite_loop_via_fuel_exhaustion() {
        // `loop br 0 end` never terminates; the crate-level fuel budget
        // must surface as a trap before it blocks the calling thread.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                (loop $l (br $l))
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[]).unwrap_err();
        assert!(matches!(err, ClassifierExecError::ClassifyCallTrap));
    }

    #[test]
    fn rejects_alloc_returning_oob_pointer() {
        // `alloc` returns i32::MIN (0x8000_0000 as u32 ≈ 2 GiB) — far
        // beyond any feasible linear-memory size. The subsequent
        // `memory.write` must reject with MemoryAccessError, proving
        // that a pathological `alloc` cannot confuse the host into
        // writing at an arbitrary offset.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32)
                i32.const -2147483648)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        // Non-empty context so `memory.write` actually attempts bytes.
        let err = execute_classifier(&wasm, b"x").unwrap_err();
        assert!(matches!(err, ClassifierExecError::MemoryAccessError));
    }

    #[test]
    fn determinism_same_wasm_same_input_same_output() {
        let expected = ClassifierOutput {
            tier: 2,
            reason_code: "bounded-write".into(),
            reason_text: "configmap patch".into(),
            escalations: vec!["sensitive-path".into()],
            justification_tag: "bounded".into(),
        };
        let wasm = build_fixed_output_wasm(&expected);
        let ctx = b"deterministic-input";

        let a = execute_classifier(&wasm, ctx).expect("first run");
        let b = execute_classifier(&wasm, ctx).expect("second run");
        assert_eq!(a, b);
        assert_eq!(a, expected);
    }
}
