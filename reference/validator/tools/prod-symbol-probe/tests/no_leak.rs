//! Task D-2 local guard — assert that `ephemeral-core`,
//! `ephemeral-attestation`, `ephemeral-classifier`, and
//! `ephemeral-anomaly` built without their respective
//! `test-fixtures` / `test_fixtures` features do NOT leak any of the
//! test-only surfaces into the compiled library:
//!
//! | Surface                         | Crate                 | Phase       |
//! |---------------------------------|-----------------------|-------------|
//! | `insert_trusted_der_for_test`   | ephemeral-attestation | C.2         |
//! | `classify_live_nitro`           | ephemeral-core        | C.2         |
//! | `insert_trusted_key_for_test`   | ephemeral-attestation | C.2.5       |
//! | `classify_live_rekor`           | ephemeral-core        | C.2.5       |
//! | `shared_wasm_artifacts`         | ephemeral-classifier  | C.3-C       |
//! | `sign_classifier_envelope`      | ephemeral-classifier  | C.3-C       |
//! | `fixture_signing_key`           | ephemeral-classifier  | C.3-C       |
//! | `build_classifier_wat`          | ephemeral-classifier  | C.3-C       |
//! | `cbor_encode_payload`           | ephemeral-classifier  | C.3-C Sess2 |
//! | `sign_envelope_raw`             | ephemeral-classifier  | C.3-C Sess2 |
//! | `fixture_anomaly_signing_key`   | ephemeral-anomaly     | C.4 Sess2   |
//! | `fixture_anomaly_verifying_key` | ephemeral-anomaly     | C.4 Sess2   |
//! | `sign_anomaly_library_envelope` | ephemeral-anomaly     | C.4 Sess2   |
//! | `shared_anomaly_artifacts`      | ephemeral-anomaly     | C.4 Sess2   |
//! | `cbor_encode_anomaly_payload`   | ephemeral-anomaly     | C.4 Sess2   |
//! | `minimum_anomaly_library`       | ephemeral-anomaly     | C.4 Sess2   |
//!
//! Phase C.4 Session 1 registered `ephemeral-anomaly` as WATCHED in
//! anticipation of Session 2's `test_fixtures` module.  Session 2
//! populated the forbidden list above with the six anomaly-side
//! fixture primitives: their names must stay absent from the
//! `default-features = false` anomaly rlib.  The
//! `verify_anomaly_library_signature` positive control is retained
//! so the negative checks are not trivially empty.
//!
//! Why a rlib, not a final binary:
//!
//! - On Windows (PE), rustc does not populate a COFF symbol table for
//!   release / dev-style builds by default; symbol names live in the
//!   `.pdb` sidecar which `object` cannot parse.  A byte-substring scan
//!   is equally unreliable because PE does not store Rust-mangled names
//!   as plain ASCII in the `.exe`.
//! - Rust's rlib (an `ar` archive of object files + `.rmeta`) always
//!   carries the per-object symbol tables intact, across ELF / COFF /
//!   Mach-O.  Parsing those object tables directly is the cross-platform
//!   floor that tells us whether a compiled function truly exists in
//!   the build.
//! - We *explicitly* ignore the rlib's `.rmeta` and `.rustc` archive
//!   members because they contain doc-comment metadata (e.g. the
//!   rustdoc intra-link `[classify_live_nitro]` on `execute`) which
//!   would otherwise produce false positives.
//!
//! The CI `feature-leak-guard` job mirrors this by running `nm`
//! against the same rlib on Ubuntu — a second, independent
//! implementation of the same invariant.

use std::path::{Path, PathBuf};
use std::process::Command;

use object::read::archive::{ArchiveFile, ArchiveMember};
use object::{Object, ObjectSymbol};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves")
}

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

/// Build `ephemeral-core` (via the probe crate, which pins
/// `default-features = false`) and collect the rlib paths cargo
/// actually produced for `ephemeral-core` and `ephemeral-attestation`.
/// We parse cargo's JSON diagnostic stream instead of globbing
/// `target/…/deps/` because developers may have rlibs from other
/// feature combinations sitting next to the one we want (including a
/// prior positive-control run that intentionally enabled the feature).
/// Picking the wrong rlib would silently invert the check.
///
/// Building the probe package (not `-p ephemeral-core` directly)
/// guarantees the dependency graph exactly matches a production
/// consumer: the probe's Cargo.toml sets `default-features = false`
/// and never opts into `test-fixtures`. If that ever changes, both
/// rlibs will immediately leak — which is the whole point.
fn build_and_locate_relevant_rlibs() -> Vec<PathBuf> {
    const WATCHED: &[&str] = &[
        "ephemeral_core",
        "ephemeral_attestation",
        "ephemeral_classifier",
        "ephemeral_anomaly",
    ];

    let output = Command::new(cargo())
        .args([
            "build",
            "--profile",
            "symbol-probe",
            "-p",
            "ephemeral-prod-symbol-probe",
            "--message-format=json",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("spawn cargo");

    assert!(
        output.status.success(),
        "cargo build failed: {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let mut found: std::collections::BTreeMap<&str, PathBuf> = std::collections::BTreeMap::new();

    for line in output.stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        let Some(target) = v.get("target").and_then(|t| t.as_object()) else {
            continue;
        };
        let Some(name) = target.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let Some(&watched) = WATCHED.iter().find(|&&w| w == name) else {
            continue;
        };
        let Some(filenames) = v.get("filenames").and_then(|f| f.as_array()) else {
            continue;
        };
        for fname in filenames {
            let Some(p) = fname.as_str() else { continue };
            if Path::new(p).extension().is_some_and(|e| e == "rlib") {
                found.insert(watched, PathBuf::from(p));
                break;
            }
        }
    }

    for w in WATCHED {
        assert!(
            found.contains_key(w),
            "cargo produced no rlib for `{w}`; watched set was {WATCHED:?}. \
             First 10 stdout lines:\n{}",
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .take(10)
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    found.into_values().collect()
}

/// True if this archive member is a rustc-private metadata blob rather
/// than a real object file. Those carry demangled names and doc-link
/// text that is not a reliable signal of compiled code presence.
fn is_rustc_metadata(name: &[u8]) -> bool {
    let n = std::str::from_utf8(name).unwrap_or("");
    n == "lib.rmeta"
        || Path::new(n).extension().is_some_and(|e| e == "rmeta")
        || n.starts_with("rust.metadata")
        || n.starts_with("//")
}

/// Collect symbols from every real object member of the rlib archive.
fn collect_rlib_symbols(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).expect("read rlib");
    let archive = ArchiveFile::parse(&*bytes)
        .unwrap_or_else(|e| panic!("parse {} as archive: {e}", path.display()));

    let mut names = Vec::new();
    for member in archive.members() {
        let member: ArchiveMember<'_> = member.expect("archive member");
        if is_rustc_metadata(member.name()) {
            continue;
        }
        let data = member.data(&*bytes).expect("member data");
        let Ok(obj) = object::File::parse(data) else {
            continue; // skip non-object members silently
        };
        for sym in obj.symbols() {
            if let Ok(n) = sym.name() {
                if !n.is_empty() {
                    names.push(n.to_owned());
                }
            }
        }
    }
    names
}

#[test]
fn test_fixtures_symbols_do_not_leak_into_prod_rlibs() {
    let rlibs = build_and_locate_relevant_rlibs();

    // Negative: these must NEVER appear in either production rlib.
    // All four are gated behind the `test-fixtures` feature.
    //
    // Phase C.2 surface:
    // - `insert_trusted_der_for_test` (ephemeral-attestation) — synthetic
    //   Nitro root anchor installation.
    // - `classify_live_nitro` (ephemeral-core) — live-Nitro classifier.
    //
    // Phase C.2.5 surface:
    // - `insert_trusted_key_for_test` (ephemeral-attestation) — Rekor log
    //   Ed25519 public-key anchor installation.
    // - `classify_live_rekor` (ephemeral-core) — live-Rekor classifier.
    let forbidden = [
        // Phase C.2 / C.2.5 — ephemeral-core / ephemeral-attestation.
        "insert_trusted_der_for_test",
        "classify_live_nitro",
        "insert_trusted_key_for_test",
        "classify_live_rekor",
        // Phase C.3-C — ephemeral-classifier `test_fixtures` surface.
        // Symbols chosen as the most-unique Rust-mangled fragments of
        // the public fixture API.  Any of them appearing in the probe-
        // profile rlib means `features = ["test_fixtures"]` is being
        // activated on a code path that must stay production-clean.
        // The crate-qualified mangling (`ephemeral_classifier` +
        // `test_fixtures`) makes collisions with unrelated symbols
        // astronomically unlikely.
        "shared_wasm_artifacts",
        "sign_classifier_envelope",
        "fixture_signing_key",
        "build_classifier_wat",
        // Phase C.3-C Session 2 — lower-level primitives added to
        // support ephemeral-core's migration to this fixture API.
        // Same invariant as above: they live in `test_fixtures.rs` and
        // MUST NOT appear in a `default-features = false` build.
        "cbor_encode_payload",
        "sign_envelope_raw",
        // Phase C.4 Session 2 — ephemeral-anomaly `test_fixtures`
        // module.  Any of these substrings appearing in a
        // `default-features = false` rlib means the feature gate on
        // `pub mod test_fixtures;` in `crates/ephemeral-anomaly/src/
        // lib.rs` is broken OR an optional dep (ed25519-dalek, coset)
        // leaked past its `test_fixtures`-only activation in
        // `crates/ephemeral-anomaly/Cargo.toml`.  Choice of substrings:
        //
        // - `fixture_anomaly_signing_key` covers the Ed25519 signer
        //   derivation entry point.
        // - `fixture_anomaly_verifying_key` covers both the `VerifyingKey`
        //   accessor and its `_bytes` sibling via substring.
        // - `sign_anomaly_library_envelope` covers both the high-level
        //   signer and its `_raw` lower-level sibling via substring.
        // - `shared_anomaly_artifacts` covers the OnceLock-backed pool.
        // - `cbor_encode_anomaly_payload` covers the exposed CBOR
        //   encoder primitive (test consumers use it to craft tampered
        //   inner-payload bytes; prod must never emit CBOR).
        // - `minimum_anomaly_library` covers both `_payload` and
        //   `_patterns` assembler helpers via substring.
        //
        // Pattern-builder functions (`delete_storm_pattern`, …) are
        // INTENTIONALLY omitted: they construct `PatternEntry` values
        // (a public type) and are low-risk even if leaked, while
        // listing all 15 would noise-up the forbidden set.  The six
        // signing / payload / pool primitives above are the minimum
        // set that makes it impossible to USE the fixture pipeline
        // from a default-features consumer.
        "fixture_anomaly_signing_key",
        "fixture_anomaly_verifying_key",
        "sign_anomaly_library_envelope",
        "shared_anomaly_artifacts",
        "cbor_encode_anomaly_payload",
        "minimum_anomaly_library",
        // Sentinel from the pattern-builder family (15 builders, not
        // listed exhaustively — see the commentary above).  This one
        // string suffices: if ANY `#[cfg(feature = "test_fixtures")]`
        // gate on the whole pattern-builder block ever breaks, this
        // name WILL leak, and we hear about it without polluting the
        // forbidden list with 14 other `_pattern` variants.  Chosen
        // over its siblings because the name — `delete_storm_pattern`
        // — is sufficiently unique that a substring hit cannot
        // collide with unrelated code.
        "delete_storm_pattern",
    ];
    // Positive control per rlib: at least one unconditionally public,
    // non-generic symbol that MUST be monomorphized into the rlib. If
    // absent, the linker stripped too much and the negative checks are
    // not meaningful.
    // NB: pick non-generic functions — generics without a caller live
    // only in `.rmeta`, not in the object code.
    let controls = [
        ("ephemeral_core", "total_failing"),
        ("ephemeral_attestation", "sha256_fingerprint"),
        // `verify_classifier_hash` is unconditionally public
        // (no feature gate, no generics); the probe binary references
        // it through `black_box` in `main.rs`, guaranteeing it survives
        // dead-code elimination under the `symbol-probe` profile.
        ("ephemeral_classifier", "verify_classifier_hash"),
        // `verify_anomaly_library_signature` is unconditionally public
        // (no feature gate, no generics); the probe binary references
        // it through `black_box` in `main.rs`.  Establishing this
        // positive control now guarantees that the Session-2 extensions
        // of the forbidden list below will land on a rlib that actually
        // contains the anomaly crate's compiled code.
        ("ephemeral_anomaly", "verify_anomaly_library_signature"),
    ];

    for rlib in &rlibs {
        let symbols = collect_rlib_symbols(rlib);
        let rlib_name = rlib
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>");

        assert!(
            !symbols.is_empty(),
            "symbol table of {} is empty — the `symbol-probe` profile may be \
             stripping too aggressively, or the rlib has no object members. \
             Fix the build before trusting this test.",
            rlib.display(),
        );

        for f in forbidden {
            let hits: Vec<&String> = symbols.iter().filter(|s| s.contains(f)).collect();
            assert!(
                hits.is_empty(),
                "LEAK DETECTED: {} symbol(s) containing `{f}` found in \
                 {}. The feature-gate around this item is broken — check \
                 #[cfg(feature = \"test-fixtures\")] blocks in \
                 ephemeral-core/src/suites/pcr.rs (classify_live_nitro, \
                 classify_live_rekor) and in ephemeral-attestation \
                 (insert_trusted_der_for_test in anchors.rs, \
                 insert_trusted_key_for_test in rekor.rs), and \
                 #[cfg(feature = \"test_fixtures\")] on \
                 ephemeral-classifier's `pub mod test_fixtures;` in \
                 src/lib.rs.  First 5 hits:\n  {}",
                hits.len(),
                rlib.display(),
                hits.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join("\n  "),
            );
        }

        // Apply the control matching this rlib.
        for (crate_name, control) in &controls {
            if !rlib_name.contains(crate_name) {
                continue;
            }
            let hit = symbols.iter().any(|s| s.contains(control));
            assert!(
                hit,
                "CONTROL FAILED: expected public non-generic symbol \
                 `{control}` not found in {} (crate: {crate_name}). The \
                 feature-leak assertions above cannot be trusted — \
                 investigate linker / DCE. Symbol table has {} entries.",
                rlib.display(),
                symbols.len(),
            );
        }
    }
}
