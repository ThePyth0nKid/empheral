//! Pre-instantiation validation of classifier WASM modules (Phase C.3-B).
//!
//! Three load-time checks, each with a dedicated error variant:
//!
//! - [`validate_no_imports`] — spec §4.3 hermeticity (no host imports).
//!   Runs before instantiation; [`wasmi::InstancePre::ensure_no_start`]
//!   would catch *some* of this, but a typed pre-walk names the offending
//!   entry and fails fast.
//! - [`validate_abi_exports`] — ABI v1 contract: `memory`, `alloc`, and
//!   `classify` all present with exactly-right signatures.
//! - Start-function rejection — delegated to
//!   [`wasmi::InstancePre::ensure_no_start`] at the runtime entry point;
//!   no local helper needed.
//!
//! These checks never mutate the module and run against
//! [`wasmi::Module`]'s already-parsed IR, so the incremental cost over
//! parse alone is negligible.

use wasmi::core::ValType;
use wasmi::{ExternType, FuncType, Module};

use crate::errors::{sanitize_log_string, ClassifierLoadError};

/// Spec-required ABI-v1 export names.  Single source of truth for
/// both the validation walk in this module and the `get_export` calls
/// in [`crate::runtime`].
pub(crate) const MEMORY_NAME: &str = "memory";
pub(crate) const ALLOC_NAME: &str = "alloc";
pub(crate) const CLASSIFY_NAME: &str = "classify";

/// Reject any module that declares imports (spec §4.3 hermeticity).
///
/// The returned [`ClassifierLoadError::ForbiddenImport`] names the first
/// offending import — deterministic ordering matches
/// [`Module::imports`]'s iteration order, which itself matches the
/// order imports appear in the binary.
///
/// # Errors
/// [`ClassifierLoadError::ForbiddenImport`] on the first declared import.
pub fn validate_no_imports(module: &Module) -> Result<(), ClassifierLoadError> {
    if let Some(imp) = module.imports().next() {
        let kind = match imp.ty() {
            ExternType::Func(_) => "function",
            ExternType::Table(_) => "table",
            ExternType::Memory(_) => "memory",
            ExternType::Global(_) => "global",
        };
        // `module`/`name` come straight from the WASM import section and
        // are attacker-controlled; sanitise before they land in Display
        // output or logs.
        return Err(ClassifierLoadError::ForbiddenImport {
            module: sanitize_log_string(imp.module()),
            name: sanitize_log_string(imp.name()),
            kind,
        });
    }
    Ok(())
}

/// Reject any module missing or mis-typing the three ABI-v1 exports.
///
/// - `memory`: any [`wasmi::MemoryType`] (limits are enforced at
///   runtime by [`crate::runtime`]'s `ResourceLimiter`).
/// - `alloc`: `(i32) -> i32`.
/// - `classify`: `(i32, i32) -> i64`.
///
/// # Errors
/// [`ClassifierLoadError::MissingExport`] if any of the three names is
/// absent, or [`ClassifierLoadError::InvalidExportSignature`] if a name
/// is present but of the wrong kind/signature.  Checked in order
/// `memory`, `alloc`, `classify`; the first failure wins.
pub fn validate_abi_exports(module: &Module) -> Result<(), ClassifierLoadError> {
    validate_memory_export(module)?;
    validate_func_export(module, ALLOC_NAME, &[ValType::I32], &[ValType::I32])?;
    validate_func_export(
        module,
        CLASSIFY_NAME,
        &[ValType::I32, ValType::I32],
        &[ValType::I64],
    )?;
    Ok(())
}

fn validate_memory_export(module: &Module) -> Result<(), ClassifierLoadError> {
    let ty = module
        .get_export(MEMORY_NAME)
        .ok_or(ClassifierLoadError::MissingExport { name: MEMORY_NAME })?;
    match ty {
        ExternType::Memory(_) => Ok(()),
        other => Err(ClassifierLoadError::InvalidExportSignature {
            name: MEMORY_NAME,
            expected: "memory",
            actual: sanitize_log_string(extern_kind_label(&other)),
        }),
    }
}

fn validate_func_export(
    module: &Module,
    name: &'static str,
    expected_params: &[ValType],
    expected_results: &[ValType],
) -> Result<(), ClassifierLoadError> {
    let ty = module
        .get_export(name)
        .ok_or(ClassifierLoadError::MissingExport { name })?;
    match ty {
        ExternType::Func(func_ty) => {
            check_func_signature(name, &func_ty, expected_params, expected_results)
        }
        other => Err(ClassifierLoadError::InvalidExportSignature {
            name,
            expected: signature_label(expected_params, expected_results),
            actual: sanitize_log_string(extern_kind_label(&other)),
        }),
    }
}

fn check_func_signature(
    name: &'static str,
    actual: &FuncType,
    expected_params: &[ValType],
    expected_results: &[ValType],
) -> Result<(), ClassifierLoadError> {
    if actual.params() == expected_params && actual.results() == expected_results {
        return Ok(());
    }
    Err(ClassifierLoadError::InvalidExportSignature {
        name,
        expected: signature_label(expected_params, expected_results),
        actual: sanitize_log_string(&format_func_type(actual)),
    })
}

/// Stable human-readable label for a function signature, e.g.
/// `"(i32, i32) -> i64"`.  Used for the `expected` field of
/// [`ClassifierLoadError::InvalidExportSignature`].
///
/// The only legitimate call-sites inside this crate pass fixed slices
/// matching ABI v1 (alloc: `(i32) -> i32`, classify: `(i32, i32) -> i64`);
/// mapping those to string literals lets callers pattern-match on the
/// `expected` field without allocating.  A future ABI revision that
/// introduces a third signature must extend this match — the
/// `debug_assert!` below trips during tests so the omission is caught
/// immediately rather than silently producing an opaque label.
#[cold]
fn signature_label(params: &[ValType], results: &[ValType]) -> &'static str {
    match (params, results) {
        (&[ValType::I32], &[ValType::I32]) => "(i32) -> i32",
        (&[ValType::I32, ValType::I32], &[ValType::I64]) => "(i32, i32) -> i64",
        _ => {
            debug_assert!(
                false,
                "signature_label called with a signature not in ABI v1: \
                 params={params:?} results={results:?}; \
                 add a new arm before introducing a new ABI signature",
            );
            "(unspecified)"
        }
    }
}

/// Human-readable name for a non-function [`ExternType`] — used when
/// a required function export name is shadowed by a memory/table/global.
fn extern_kind_label(ty: &ExternType) -> &'static str {
    match ty {
        ExternType::Func(_) => "function",
        ExternType::Table(_) => "table",
        ExternType::Memory(_) => "memory",
        ExternType::Global(_) => "global",
    }
}

/// Format an actual [`FuncType`] for the `actual` field of
/// [`ClassifierLoadError::InvalidExportSignature`].  Best-effort —
/// value types not representable in ABI v1 become placeholder strings
/// rather than causing a secondary error.
fn format_func_type(ty: &FuncType) -> String {
    let params: Vec<&'static str> = ty.params().iter().copied().map(val_type_label).collect();
    let results: Vec<&'static str> = ty.results().iter().copied().map(val_type_label).collect();
    format!("({}) -> ({})", params.join(", "), results.join(", "))
}

fn val_type_label(ty: ValType) -> &'static str {
    match ty {
        ValType::I32 => "i32",
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "v128",
        ValType::FuncRef => "funcref",
        ValType::ExternRef => "externref",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmi::{Config, Engine};

    fn module_from_wat(src: &str) -> Module {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let wasm = wat::parse_str(src).expect("wat parse");
        Module::new(&engine, &wasm).expect("module parse")
    }

    // ----- validate_no_imports -----

    #[test]
    fn no_imports_accepts_zero_imports() {
        let m = module_from_wat(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        validate_no_imports(&m).expect("no imports");
    }

    #[test]
    fn no_imports_rejects_host_function_import() {
        let m = module_from_wat(
            r#"
            (module
              (import "env" "host_log" (func (param i32)))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = validate_no_imports(&m).unwrap_err();
        match err {
            ClassifierLoadError::ForbiddenImport { module, name, kind } => {
                assert_eq!(module, "env");
                assert_eq!(name, "host_log");
                assert_eq!(kind, "function");
            }
            other => panic!("expected ForbiddenImport, got {other:?}"),
        }
    }

    #[test]
    fn no_imports_rejects_memory_import() {
        let m = module_from_wat(
            r#"
            (module
              (import "env" "mem" (memory 1))
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0)
              (export "memory" (memory 0)))
            "#,
        );
        let err = validate_no_imports(&m).unwrap_err();
        match err {
            ClassifierLoadError::ForbiddenImport { kind, .. } => assert_eq!(kind, "memory"),
            other => panic!("expected ForbiddenImport with kind=memory, got {other:?}"),
        }
    }

    #[test]
    fn no_imports_rejects_global_import() {
        let m = module_from_wat(
            r#"
            (module
              (import "env" "g" (global i32))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = validate_no_imports(&m).unwrap_err();
        match err {
            ClassifierLoadError::ForbiddenImport { kind, .. } => assert_eq!(kind, "global"),
            other => panic!("expected ForbiddenImport with kind=global, got {other:?}"),
        }
    }

    // ----- validate_abi_exports -----

    #[test]
    fn abi_accepts_canonical_shape() {
        let m = module_from_wat(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        validate_abi_exports(&m).expect("canonical ABI");
    }

    #[test]
    fn abi_rejects_missing_memory_export() {
        let m = module_from_wat(
            r#"
            (module
              (memory 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = validate_abi_exports(&m).unwrap_err();
        assert!(matches!(
            err,
            ClassifierLoadError::MissingExport { name: "memory" }
        ));
    }

    #[test]
    fn abi_rejects_missing_alloc_export() {
        let m = module_from_wat(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = validate_abi_exports(&m).unwrap_err();
        assert!(matches!(
            err,
            ClassifierLoadError::MissingExport { name: "alloc" }
        ));
    }

    #[test]
    fn abi_rejects_missing_classify_export() {
        let m = module_from_wat(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0))
            "#,
        );
        let err = validate_abi_exports(&m).unwrap_err();
        assert!(matches!(
            err,
            ClassifierLoadError::MissingExport { name: "classify" }
        ));
    }

    #[test]
    fn abi_rejects_wrong_alloc_arity() {
        // alloc takes two i32s instead of one.
        let m = module_from_wat(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32 i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = validate_abi_exports(&m).unwrap_err();
        match err {
            ClassifierLoadError::InvalidExportSignature {
                name,
                expected,
                actual,
            } => {
                assert_eq!(name, "alloc");
                assert_eq!(expected, "(i32) -> i32");
                assert!(actual.contains("i32, i32"));
            }
            other => panic!("expected InvalidExportSignature for alloc, got {other:?}"),
        }
    }

    #[test]
    fn abi_rejects_wrong_classify_return() {
        // classify returns i32 instead of i64.
        let m = module_from_wat(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i32) i32.const 0))
            "#,
        );
        let err = validate_abi_exports(&m).unwrap_err();
        match err {
            ClassifierLoadError::InvalidExportSignature {
                name,
                expected,
                actual,
            } => {
                assert_eq!(name, "classify");
                assert_eq!(expected, "(i32, i32) -> i64");
                assert!(actual.contains("i32"));
            }
            other => panic!("expected InvalidExportSignature for classify, got {other:?}"),
        }
    }

    #[test]
    fn abi_rejects_memory_exported_as_function_name() {
        // `memory` exports a function instead of linear memory.
        let m = module_from_wat(
            r#"
            (module
              (memory 1)
              (func (export "memory") (result i32) i32.const 0)
              (func (export "alloc") (param i32) (result i32) i32.const 0)
              (func (export "classify") (param i32 i32) (result i64) i64.const 0))
            "#,
        );
        let err = validate_abi_exports(&m).unwrap_err();
        match err {
            ClassifierLoadError::InvalidExportSignature {
                name,
                expected,
                actual,
            } => {
                assert_eq!(name, "memory");
                assert_eq!(expected, "memory");
                assert_eq!(actual, "function");
            }
            other => panic!("expected InvalidExportSignature for memory, got {other:?}"),
        }
    }
}
