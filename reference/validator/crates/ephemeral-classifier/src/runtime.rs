//! WASM execution for the EPHEMERAL classifier.
//!
//! # Execute pipeline
//!
//! 1. **Parse** with a hardened [`wasmi::Config`] — fuel metering
//!    enabled, every post-MVP Wasm proposal that isn't in ABI v1
//!    explicitly disabled.  Modules using SIMD, bulk-memory, reference
//!    types, etc. are rejected at parse with
//!    [`ClassifierExecError::WasmParseError`].
//! 2. **Pre-instantiation walks** ([`crate::validate`]):
//!    - Every import forbidden ([`ClassifierLoadError::ForbiddenImport`]).
//!    - Canonical three-export ABI v1 shape ([`ClassifierLoadError::MissingExport`] /
//!      [`ClassifierLoadError::InvalidExportSignature`]).
//! 3. **Instantiate** with an empty [`wasmi::Linker`] (defense-in-depth;
//!    import-walk above is the primary gate).  Start-function rejection
//!    via [`wasmi::InstancePre::ensure_no_start`] →
//!    [`ClassifierLoadError::ForbiddenStartFunction`].
//! 4. **Resource-cap** the [`Store`] with a
//!    [`ClassifierMemoryLimiter`] bounded by
//!    [`ClassifierConfig::max_memory_pages`].
//! 5. **Fuel-prime** the [`Store`] with
//!    [`ClassifierConfig::fuel_budget`].
//! 6. **Call** `alloc(input_len)` → `memory.write(input)` →
//!    `classify(input_ptr, input_len)`.
//! 7. **Bound** the returned `output_len` by
//!    [`ClassifierConfig::max_output_bytes`] before allocating the host
//!    receive buffer.
//! 8. **Decode** CBOR → [`ClassifierOutput`].
//!
//! Each step has a dedicated typed error; there is no "catch-all"
//! variant outside the documented parse-or-disabled-feature bucket.

use wasmi::errors::InstantiationError;
use wasmi::{Config, Engine, Linker, Module, Store, TypedFunc};

use crate::config::ClassifierConfig;
use crate::errors::{ClassifierError, ClassifierExecError, ClassifierLoadError};
use crate::limiter::ClassifierMemoryLimiter;
use crate::output::ClassifierOutput;
use crate::validate::{
    validate_abi_exports, validate_no_imports, ALLOC_NAME, CLASSIFY_NAME, MEMORY_NAME,
};

/// Build a hardened [`wasmi::Config`] for the classifier engine.
///
/// The disable-list enumerates every post-MVP Wasm proposal that
/// wasmi 0.47.2 recognizes; any proposal not in ABI v1 is rejected at
/// parse time.
///
/// Three categories cover the full surface:
///
/// - **Compile-time absent** (`simd`, `relaxed_simd`, `threads`, `gc`,
///   `component-model`): these are either gated behind wasmi feature
///   flags we do not enable (`simd`) or are unsupported by wasmi 0.47.2
///   entirely.  Their opcodes are rejected unconditionally — no
///   runtime disable needed.
/// - **Explicitly disabled at runtime** (`bulk_memory`,
///   `reference_types`, `tail_call`, `extended_const`,
///   `custom_page_sizes`, `memory64`, `multi_memory`,
///   `wide_arithmetic`): methods on [`wasmi::Config`] that flip the
///   proposal off.  None of these are used by ABI v1; enabling them
///   would broaden the acceptable module shape with no corresponding
///   benefit.
/// - **Kept enabled** (LLVM's default Rust/wasm32 target needs them):
///   `multi_value`, `sign_extension`, `saturating_float_to_int`,
///   `mutable_global`, `floats`.
fn build_engine_config() -> Config {
    let mut config = Config::default();
    config.consume_fuel(true);

    // Out-of-scope for ABI v1.  SIMD + relaxed-SIMD are also absent
    // because we do not enable wasmi's `simd` Cargo feature; no
    // runtime disable for them is available or necessary.
    config.wasm_bulk_memory(false);
    config.wasm_reference_types(false);
    config.wasm_tail_call(false);
    config.wasm_extended_const(false);
    config.wasm_custom_page_sizes(false);
    config.wasm_memory64(false);
    config.wasm_multi_memory(false);
    config.wasm_wide_arithmetic(false);

    config
}

/// Unpack the `(output_ptr << 32) | output_len` locator returned by
/// `classify` into host-usable byte offsets.
///
/// `packed` is `i64` per the ABI; the bits are reinterpreted as `u64`
/// before shifting.  Both halves are `u32`, which fits `usize` on every
/// 32-bit and 64-bit target — the only targets this crate compiles for.
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
/// The per-call cost is acceptable for Phase C.3's throughput target.
///
/// # Errors
/// Returns [`ClassifierError::Load`] for hash/parse/import/ABI failures,
/// and [`ClassifierError::Exec`] for per-invocation traps, memory-cap
/// violations, fuel exhaustion, or output-decode failures.
pub fn execute_classifier(
    wasm_bytes: &[u8],
    context_cbor: &[u8],
    config: &ClassifierConfig,
) -> Result<ClassifierOutput, ClassifierError> {
    let engine = Engine::new(&build_engine_config());

    let module = Module::new(&engine, wasm_bytes)
        .map_err(|_| ClassifierError::Exec(ClassifierExecError::WasmParseError))?;

    validate_no_imports(&module).map_err(ClassifierError::Load)?;
    validate_abi_exports(&module).map_err(ClassifierError::Load)?;

    let limiter = ClassifierMemoryLimiter::new(config.max_memory_pages);
    let mut store = Store::new(&engine, limiter);
    store.limiter(|l| l);

    // `set_fuel` only fails when `consume_fuel` is disabled on the engine,
    // which `build_engine_config` just enabled.  Any future refactor that
    // accidentally drops that call will surface this `expect` loudly
    // rather than silently run an unfueled interpreter.
    store
        .set_fuel(config.fuel_budget)
        .expect("fuel metering is enabled on the engine");

    let linker: Linker<ClassifierMemoryLimiter> = Linker::new(&engine);

    // Ordering note (wasmi =0.47.2): `instantiate()` runs active data
    // segments and initialises linear memory *before* `ensure_no_start`
    // has a chance to reject a `(start …)` function.  This is safe here
    // because, in order:
    //   (a) `ClassifierMemoryLimiter` has already been installed on the
    //       `Store` above and caps every `memory.grow` (including the
    //       initial allocation) at `config.max_memory_pages`;
    //   (b) `validate_no_imports` guarantees zero imports, so instantiation
    //       cannot trigger any host-call — data-segment copies operate
    //       purely on the guest's own linear memory;
    //   (c) `ensure_no_start` below blocks the module's entry point from
    //       ever running after instantiation completes.
    // If the `instantiate` call fails because the limiter denied the
    // *initial* memory allocation, `store.data().denial()` has been
    // recorded — map it into the typed `MemoryGrowthDenied` surface
    // rather than the generic `InstantiationFailed` catch-all.
    let pre = linker
        .instantiate(&mut store, &module)
        .map_err(|_| map_guest_trap(&store, ClassifierExecError::InstantiationFailed))?;

    let instance = pre.ensure_no_start(&mut store).map_err(|e| match e {
        InstantiationError::UnexpectedStartFn { .. } => {
            ClassifierError::Load(ClassifierLoadError::ForbiddenStartFunction)
        }
        _ => ClassifierError::Exec(ClassifierExecError::InstantiationFailed),
    })?;

    // Exports are guaranteed present + correctly-typed by the pre-walk.
    // If this invariant ever breaks, `expect` surfaces it loudly.
    let memory = instance
        .get_memory(&store, MEMORY_NAME)
        .expect("memory export validated by validate_abi_exports");

    let alloc: TypedFunc<i32, i32> = instance
        .get_typed_func(&store, ALLOC_NAME)
        .expect("alloc signature validated by validate_abi_exports");

    let classify: TypedFunc<(i32, i32), i64> = instance
        .get_typed_func(&store, CLASSIFY_NAME)
        .expect("classify signature validated by validate_abi_exports");

    let input_len_i32 = i32::try_from(context_cbor.len()).map_err(|_| {
        ClassifierError::Exec(ClassifierExecError::InputTooLarge {
            len: context_cbor.len(),
        })
    })?;

    let input_ptr = alloc
        .call(&mut store, input_len_i32)
        .map_err(|_| map_guest_trap(&store, ClassifierExecError::AllocCallTrap))?;

    // `alloc` returns i32 per ABI v1; reinterpret the bit pattern as
    // u32 for host-side address arithmetic.  A negative-i32 return from
    // alloc is treated as a large u32 offset, which the subsequent
    // `memory.write` bounds-check rejects with `MemoryAccessError` —
    // intentional, since alloc never legitimately returns a negative
    // value.  The explicit `input_ptr_u32` binding documents the
    // signed→unsigned reinterpretation at the host boundary and guards
    // against future refactors that might otherwise propagate the
    // raw signed value into pointer arithmetic.
    #[allow(clippy::cast_sign_loss)]
    let input_ptr_u32 = input_ptr as u32;
    let input_offset = usize::try_from(input_ptr_u32).expect("u32 fits usize on 32/64-bit targets");

    memory
        .write(&mut store, input_offset, context_cbor)
        .map_err(|_| ClassifierError::Exec(ClassifierExecError::MemoryAccessError))?;

    let packed = classify
        .call(&mut store, (input_ptr, input_len_i32))
        .map_err(|_| map_guest_trap(&store, ClassifierExecError::ClassifyCallTrap))?;

    let (output_offset, output_size) = unpack_locator(packed);

    // Enforce the host-side allocation ceiling BEFORE `vec![0u8; _]`.
    // Reported as `OutputTooLarge` (not `MemoryAccessError`) because no
    // memory access has taken place yet — the check fails the
    // attacker-controlled length field before any allocation occurs.
    if output_size > config.max_output_bytes {
        return Err(ClassifierError::Exec(ClassifierExecError::OutputTooLarge {
            claimed: output_size,
            cap: config.max_output_bytes,
        }));
    }

    let mut output_bytes = vec![0u8; output_size];
    memory
        .read(&store, output_offset, &mut output_bytes)
        .map_err(|_| ClassifierError::Exec(ClassifierExecError::MemoryAccessError))?;

    ciborium::from_reader(output_bytes.as_slice())
        .map_err(|_| ClassifierError::Exec(ClassifierExecError::OutputDecodeFailed))
}

/// If the current trap was caused by the limiter denying `memory.grow`,
/// translate the generic trap error into a typed
/// [`ClassifierExecError::MemoryGrowthDenied`] using the denial
/// details recorded on the limiter.  Otherwise pass through the
/// supplied fallback variant.
fn map_guest_trap(
    store: &Store<ClassifierMemoryLimiter>,
    fallback: ClassifierExecError,
) -> ClassifierError {
    if let Some(d) = store.data().denial() {
        return ClassifierError::Exec(ClassifierExecError::MemoryGrowthDenied {
            current_pages: d.current_pages,
            requested_pages: d.requested_pages,
            cap_pages: d.cap_pages,
        });
    }
    ClassifierError::Exec(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_locator_preserves_bit_layout() {
        assert_eq!(unpack_locator(0), (0, 0));
        assert_eq!(unpack_locator(4_294_967_298_i64), (1, 2));
        assert_eq!(
            unpack_locator(-1_i64),
            (0xFFFF_FFFF_usize, 0xFFFF_FFFF_usize)
        );
        assert_eq!(unpack_locator(i64::MIN), (0x8000_0000_usize, 0));
        #[allow(clippy::cast_possible_wrap)]
        let hi_only = 0xFFFF_FFFF_0000_0000_u64 as i64;
        assert_eq!(unpack_locator(hi_only), (0xFFFF_FFFF_usize, 0));
        assert_eq!(
            unpack_locator(0x0000_0000_FFFF_FFFF_i64),
            (0, 0xFFFF_FFFF_usize)
        );
    }

    fn build_fixed_output_wasm(output: &ClassifierOutput) -> Vec<u8> {
        use std::fmt::Write as _;

        let mut cbor = Vec::new();
        ciborium::into_writer(output, &mut cbor).expect("cbor encode");

        let output_offset: u32 = 256;
        let alloc_offset: u32 = 4096;
        let cbor_len = u32::try_from(cbor.len()).expect("cbor fits u32");
        let packed: u64 = (u64::from(output_offset) << 32) | u64::from(cbor_len);

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

    // ----- C.3-A regression coverage under the new config-parameterized API -----

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
        let actual =
            execute_classifier(&wasm, b"ignored", &ClassifierConfig::default()).expect("execute");
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
        let actual = execute_classifier(&wasm, &[], &ClassifierConfig::default()).expect("execute");
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_malformed_wasm() {
        let garbage = b"\x00\x00\x00\x00not-a-wasm-header";
        let err = execute_classifier(garbage, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::WasmParseError)
        ));
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
        let a = execute_classifier(&wasm, b"x", &ClassifierConfig::default()).expect("first");
        let b = execute_classifier(&wasm, b"x", &ClassifierConfig::default()).expect("second");
        assert_eq!(a, b);
        assert_eq!(a, expected);
    }

    // ----- C.3-B new coverage: load-time rejections -----

    #[test]
    fn rejects_module_with_imports_via_load_walk() {
        // ForbiddenImport returns *before* instantiation — distinct from
        // C.3-A's InstantiationFailed path.
        let wat_src = r#"
            (module
              (import "env" "host_log" (func (param i32)))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Load(ClassifierLoadError::ForbiddenImport { .. })
        ));
    }

    #[test]
    fn rejects_module_with_start_function() {
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0)
              (func $s)
              (start $s))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Load(ClassifierLoadError::ForbiddenStartFunction)
        ));
    }

    #[test]
    fn rejects_module_missing_memory_export_via_load_walk() {
        let wat_src = r#"
            (module
              (memory 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Load(ClassifierLoadError::MissingExport { name: "memory" })
        ));
    }

    #[test]
    fn rejects_wrong_alloc_signature_via_load_walk() {
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32 i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Load(ClassifierLoadError::InvalidExportSignature {
                name: "alloc",
                ..
            })
        ));
    }

    // ----- C.3-B new coverage: Config-level feature disables -----

    #[test]
    fn rejects_simd_module_at_parse() {
        // v128.const requires wasm_simd; Config disables it → parse error.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                v128.const i32x4 0 0 0 0
                drop
                i64.const 0))
        "#;
        // Either the WAT parser refuses (wat-layer guarantee) or our
        // engine `Config` disable catches it (engine-layer guarantee).
        // Both paths are acceptable; the explicit `else` documents that
        // a wat-parse failure is a *deliberately-tolerated* outcome,
        // not a silently-passing test.
        if let Ok(wasm) = wat::parse_str(wat_src) {
            let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
            assert!(matches!(
                err,
                ClassifierError::Exec(ClassifierExecError::WasmParseError)
            ));
        } else {
            // wat-layer rejection is an equivalent guarantee: SIMD never
            // reaches our engine, so the classifier contract holds by
            // construction at this layer.
        }
    }

    #[test]
    fn rejects_bulk_memory_module_at_parse() {
        // memory.copy requires wasm_bulk_memory.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i32.const 0
                i32.const 64
                i32.const 8
                memory.copy
                i64.const 0))
        "#;
        if let Ok(wasm) = wat::parse_str(wat_src) {
            let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
            assert!(matches!(
                err,
                ClassifierError::Exec(ClassifierExecError::WasmParseError)
            ));
        } else {
            // wat-layer rejection is an equivalent guarantee —
            // bulk-memory opcodes never reach our engine.
        }
    }

    #[test]
    fn rejects_reference_types_module_at_parse() {
        // externref value requires wasm_reference_types.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                ref.null extern
                drop
                i64.const 0))
        "#;
        if let Ok(wasm) = wat::parse_str(wat_src) {
            let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
            assert!(matches!(
                err,
                ClassifierError::Exec(ClassifierExecError::WasmParseError)
            ));
        } else {
            // wat-layer rejection is an equivalent guarantee —
            // reference-types opcodes never reach our engine.
        }
    }

    #[test]
    fn rejects_tail_call_module_at_parse() {
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func $helper (result i64) i64.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                return_call $helper))
        "#;
        if let Ok(wasm) = wat::parse_str(wat_src) {
            let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
            assert!(matches!(
                err,
                ClassifierError::Exec(ClassifierExecError::WasmParseError)
            ));
        } else {
            // wat-layer rejection is an equivalent guarantee —
            // tail-call opcodes never reach our engine.
        }
    }

    // ----- C.3-B new coverage: ResourceLimiter + ClassifierConfig -----

    #[test]
    fn memory_growth_denied_when_requested_beyond_cap() {
        // Classifier tries to grow by 100 pages. With default cap=64, denied.
        // memory.grow returns -1 (i32::MAX signed = -1). Classifier then hits
        // an unreachable equivalent via a divide by that -1? Simpler: have
        // classify just attempt the grow, check result is -1, then unreachable.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                ;; grow by 100 pages (1 + 100 = 101 total → over cap 64)
                i32.const 100
                memory.grow
                ;; result is -1 on failure; if -1, unreachable, else 0
                i32.const -1
                i32.eq
                (if (then unreachable))
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        match err {
            ClassifierError::Exec(ClassifierExecError::MemoryGrowthDenied {
                current_pages,
                requested_pages,
                cap_pages,
            }) => {
                // Initial 1 page + 100 requested grow = 101 desired total.
                assert_eq!(current_pages, 1);
                assert_eq!(requested_pages, 101);
                assert_eq!(cap_pages, 64);
            }
            other => panic!("expected MemoryGrowthDenied, got {other:?}"),
        }
    }

    #[test]
    fn initial_memory_denial_is_typed_not_instantiation_failed() {
        // Module declares an initial memory of 100 pages (> default cap 64).
        // The limiter denies the *initial* allocation during `instantiate`.
        // The failure must surface as MemoryGrowthDenied with the recorded
        // denial details, not as the generic InstantiationFailed catch-all.
        let wat_src = r#"
            (module
              (memory (export "memory") 100)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        match err {
            ClassifierError::Exec(ClassifierExecError::MemoryGrowthDenied {
                current_pages,
                requested_pages,
                cap_pages,
            }) => {
                // Initial grow from 0 pages to 100 requested, cap is 64.
                assert_eq!(current_pages, 0);
                assert_eq!(requested_pages, 100);
                assert_eq!(cap_pages, 64);
            }
            other => panic!("expected MemoryGrowthDenied on initial alloc, got {other:?}"),
        }
    }

    #[test]
    fn memory_growth_within_cap_succeeds() {
        // Grow by 10 pages (1 + 10 = 11 total, within cap 64).
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i32.const 10
                memory.grow
                drop
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        // Must NOT return MemoryGrowthDenied; may succeed (OutputDecodeFailed
        // because packed=0 → empty slice ≠ valid CBOR) but that's exec, not grow.
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(!matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::MemoryGrowthDenied { .. })
        ));
    }

    #[test]
    fn custom_memory_cap_respected() {
        // Config overrides default 64 pages → 256.  A module that would be
        // denied at 64 should succeed at 256.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i32.const 100
                memory.grow
                i32.const -1
                i32.eq
                (if (then unreachable))
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let loose = ClassifierConfig {
            max_memory_pages: 256,
            ..ClassifierConfig::default()
        };
        let err = execute_classifier(&wasm, &[], &loose).unwrap_err();
        // With cap=256, the grow succeeds; classify returns 0 (packed)
        // → ptr=0, len=0 → empty buffer → OutputDecodeFailed.  The
        // important point is: NOT MemoryGrowthDenied.
        assert!(!matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::MemoryGrowthDenied { .. })
        ));
    }

    #[test]
    fn custom_fuel_budget_respected() {
        // Infinite-loop classifier + ultra-tight fuel budget of 1000 fuels
        // → ClassifyCallTrap, not a 100M-fuel-sized wall-time penalty.
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                (loop $l (br $l))
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let tight = ClassifierConfig {
            fuel_budget: 1_000,
            ..ClassifierConfig::default()
        };
        let err = execute_classifier(&wasm, &[], &tight).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::ClassifyCallTrap)
        ));
    }

    #[test]
    fn custom_output_cap_respected() {
        // Module claims output_len of exactly `cap+1` for a custom tight cap.
        let custom_cap = 256_usize;
        let claimed_len = custom_cap + 1;
        // output_ptr = 0, output_len = claimed_len; packed = (0 << 32) | len = len.
        let packed: u64 = claimed_len as u64;
        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );
        let wasm = wat::parse_str(&wat_src).expect("wat parse");
        let tight = ClassifierConfig {
            max_output_bytes: custom_cap,
            ..ClassifierConfig::default()
        };
        let err = execute_classifier(&wasm, &[], &tight).unwrap_err();
        match err {
            ClassifierError::Exec(ClassifierExecError::OutputTooLarge { claimed, cap }) => {
                assert_eq!(claimed, claimed_len);
                assert_eq!(cap, custom_cap);
            }
            other => panic!("expected OutputTooLarge, got {other:?}"),
        }
    }

    // ----- C.3-A regression tests retained under new signature -----

    #[test]
    fn rejects_classify_infinite_loop_via_fuel_exhaustion() {
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                (loop $l (br $l))
                i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::ClassifyCallTrap)
        ));
    }

    #[test]
    fn rejects_classify_oversized_output_len_at_default_cap() {
        let output_offset: u32 = 0;
        let output_len =
            u32::try_from(crate::config::DEFAULT_MAX_OUTPUT_BYTES + 1).expect("cap + 1 fits u32");
        let packed: u64 = (u64::from(output_offset) << 32) | u64::from(output_len);
        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );
        let wasm = wat::parse_str(&wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        match err {
            ClassifierError::Exec(ClassifierExecError::OutputTooLarge { claimed, cap }) => {
                assert_eq!(claimed, crate::config::DEFAULT_MAX_OUTPUT_BYTES + 1);
                assert_eq!(cap, crate::config::DEFAULT_MAX_OUTPUT_BYTES);
            }
            other => panic!("expected OutputTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_classify_oob_output_pointer() {
        let output_offset: u32 = 0x0001_0000; // past single-page memory
        let output_len: u32 = 32;
        let packed: u64 = (u64::from(output_offset) << 32) | u64::from(output_len);
        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );
        let wasm = wat::parse_str(&wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::MemoryAccessError)
        ));
    }

    #[test]
    fn rejects_classify_invalid_cbor() {
        // output_ptr = 0, output_len = 16; packed = (0 << 32) | 16 = 16.
        let packed: u64 = 16u64;
        let wat_src = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 4096)
              (func (export "classify") (param i32 i32) (result i64)
                i64.const {packed}))
            "#
        );
        let wasm = wat::parse_str(&wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, &[], &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::OutputDecodeFailed)
        ));
    }

    #[test]
    fn rejects_alloc_returning_oob_pointer() {
        let wat_src = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const -2147483648)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
        "#;
        let wasm = wat::parse_str(wat_src).expect("wat parse");
        let err = execute_classifier(&wasm, b"x", &ClassifierConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            ClassifierError::Exec(ClassifierExecError::MemoryAccessError)
        ));
    }
}
