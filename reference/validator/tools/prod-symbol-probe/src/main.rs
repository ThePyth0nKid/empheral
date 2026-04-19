//! Feature-leak guard probe — **NOT a production tool.**
//!
//! This binary is built by CI (`feature-leak-guard` job) and by the
//! local integration test `tests/no_leak.rs`. Its sole job is to link
//! against `ephemeral-core` with `default-features = false` and to
//! reference enough of the public API that the linker keeps real
//! `ephemeral-core` code in the final binary (otherwise dead-code
//! elimination would produce an empty binary and the no-leak assertion
//! would be trivially true).
//!
//! What the downstream check asserts:
//! - The symbols `insert_trusted_der_for_test` and `classify_live_nitro`
//!   (both gated behind the `test-fixtures` feature) are ABSENT.
//! - The symbol `run_many` (unconditionally public in ephemeral-core) is
//!   PRESENT — proving the check is not trivially empty.
//!
//! If you add new test-fixtures-gated items to ephemeral-core, extend
//! the assertions in `tests/no_leak.rs` to include them.

use std::hint::black_box;

use ephemeral_core::{run_many, schema::CompiledSchema, RunConfig, VectorSuite};

fn main() {
    // Force the linker to retain the symbols we want to positively detect.
    // `black_box` defeats const-folding / dead-code elimination on the
    // function pointers. We never actually invoke these — we only need
    // their addresses to stay in the binary.
    let load_ptr: fn(&std::path::Path) -> _ = CompiledSchema::load;
    let run_ptr: fn(&[std::path::PathBuf], &RunConfig<'_>) -> _ = run_many;
    let _ = black_box(load_ptr);
    let _ = black_box(run_ptr);
    // Reference an enum variant so name mangling keeps the enum alive.
    let _ = black_box(VectorSuite::PcrAttestationReject);

    eprintln!(
        "ephemeral-prod-symbol-probe: built with ephemeral-core \
         default-features = false; this binary exists only to be \
         inspected by the feature-leak-guard check."
    );
}
