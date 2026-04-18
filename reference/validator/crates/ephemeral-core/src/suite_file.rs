//! Loader for `conformance/*.json` files.
//!
//! Parses a path into a [`SuiteFile`] plus the raw `serde_json::Value` so
//! downstream schema validation sees exactly the bytes on disk (after JSON
//! parsing — we do NOT re-serialize before schema-checking, which would mask
//! deserializer-level quirks).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::ValidatorError;
use crate::types::SuiteFile;

/// Upper bound on the size of a single conformance file. Real files live
/// around 200-500 KiB; 32 MiB is generous enough to absorb growth while
/// defending against adversarial contributor submissions that would OOM the
/// CI runner before the JSON parser ever sees them.
pub const MAX_SUITE_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// The raw JSON document plus its typed projection.
///
/// Callers that need to run JSON-Schema validation use `raw`; callers that
/// need to execute vectors use `parsed`. Both are guaranteed to come from the
/// same on-disk read.
#[derive(Debug)]
pub struct LoadedSuite {
    pub path: PathBuf,
    pub raw: serde_json::Value,
    pub parsed: SuiteFile,
}

/// Read, parse, and strongly-type a single conformance file.
///
/// Returns [`ValidatorError::Io`] on read failure (including oversize files,
/// which are reported as `io::Error` with `ErrorKind::InvalidData`) and
/// [`ValidatorError::Json`] on either JSON-parse failure or shape mismatch
/// against [`SuiteFile`]. The latter is a hard failure — the schema is
/// authoritative and any deserialization mismatch means either the file or
/// this crate's types have drifted.
pub fn load_suite_file(path: &Path) -> Result<LoadedSuite, ValidatorError> {
    let meta = fs::metadata(path).map_err(|source| ValidatorError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.len() > MAX_SUITE_FILE_BYTES {
        return Err(ValidatorError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "conformance file exceeds {} bytes cap (actual: {})",
                    MAX_SUITE_FILE_BYTES,
                    meta.len()
                ),
            ),
        });
    }
    let bytes = fs::read(path).map_err(|source| ValidatorError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let raw: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|source| ValidatorError::Json {
            path: path.to_path_buf(),
            source,
        })?;

    let parsed: SuiteFile =
        serde_json::from_value(raw.clone()).map_err(|source| ValidatorError::Json {
            path: path.to_path_buf(),
            source,
        })?;

    Ok(LoadedSuite {
        path: path.to_path_buf(),
        raw,
        parsed,
    })
}

/// Default glob for conformance files. This is a pure helper — callers pass
/// the list of file paths explicitly; the CLI is responsible for globbing.
pub const DEFAULT_CONFORMANCE_FILES: &[&str] = &[
    "conformance/canonicalization.json",
    "conformance/delegation-scope.json",
    "conformance/fuzz-baseline.json",
    "conformance/tariff-reject.json",
    "conformance/pcr-attestation-reject.json",
    "conformance/audit-replay.json",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn loads_minimal_valid_file() {
        let tmp = tempdir();
        let body = r#"{
            "schema_version": "1.0.0",
            "vector_suite": "canonicalization",
            "spec_reference": "design-final-v2.md §4.2",
            "spec_version": "test",
            "generated_at": "2026-04-18T00:00:00Z",
            "vectors": [
                {
                    "id": "canon-001",
                    "category": "identity",
                    "description": "baseline identity test",
                    "input": {"raw_intent": {"verb": "get"}},
                    "expected": {"outcome": "accept"},
                    "rationale": "baseline test vector for loader smoke"
                }
            ]
        }"#;
        let p = write_tmp(tmp.path(), "canon.json", body);
        let loaded = load_suite_file(&p).unwrap();
        assert_eq!(loaded.parsed.vectors.len(), 1);
        assert_eq!(loaded.parsed.vectors[0].id, "canon-001");
    }

    #[test]
    fn rejects_missing_file() {
        let p = PathBuf::from("C:/does/not/exist/canon.json");
        let err = load_suite_file(&p).unwrap_err();
        assert!(matches!(err, ValidatorError::Io { .. }));
    }

    #[test]
    fn rejects_invalid_json() {
        let tmp = tempdir();
        let p = write_tmp(tmp.path(), "bad.json", "not json {");
        let err = load_suite_file(&p).unwrap_err();
        assert!(matches!(err, ValidatorError::Json { .. }));
    }

    #[test]
    fn rejects_unknown_fields() {
        let tmp = tempdir();
        let body = r#"{
            "schema_version": "1.0.0",
            "vector_suite": "canonicalization",
            "spec_reference": "§4.2",
            "spec_version": "x",
            "generated_at": "2026-04-18T00:00:00Z",
            "vectors": [],
            "extra_unexpected": true
        }"#;
        let p = write_tmp(tmp.path(), "bad.json", body);
        let err = load_suite_file(&p).unwrap_err();
        assert!(matches!(err, ValidatorError::Json { .. }));
    }

    /// Tiny std-only temp-dir helper so we avoid a tempfile dev-dep.
    fn tempdir() -> TmpDir {
        let base = std::env::temp_dir().join(format!(
            "ephemeral-core-test-{}-{}",
            std::process::id(),
            TMPDIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        fs::create_dir_all(&base).unwrap();
        TmpDir { path: base }
    }

    static TMPDIR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct TmpDir {
        path: PathBuf,
    }
    impl TmpDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
