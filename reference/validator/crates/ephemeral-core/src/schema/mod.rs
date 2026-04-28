//! JSON Schema 2020-12 validation layer.
//!
//! Wraps [`jsonschema`] so the rest of the crate treats schema validation as
//! an opaque "valid or not" check. Errors are serialized into deterministic,
//! human-readable strings so they are stable across runs (the raw
//! `jsonschema::ValidationError` type is tied to a lifetime on the document).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::SchemaError;

/// Upper bound on schema file size. Real schemas live under 16 KiB. A 4 MiB
/// ceiling is defensive-only — it bounds the heap allocation any adversarial
/// contributor can coerce from a `--schema` argument before `jsonschema`
/// begins compilation (which itself can be expensive on pathological inputs).
pub const MAX_SCHEMA_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// A compiled JSON Schema. Compile once, validate many.
#[derive(Debug)]
pub struct CompiledSchema {
    validator: jsonschema::Validator,
    path: PathBuf,
}

impl CompiledSchema {
    /// Load a schema file from disk and compile it.
    pub fn load(path: &Path) -> Result<Self, SchemaError> {
        let meta = fs::metadata(path).map_err(|source| SchemaError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if meta.len() > MAX_SCHEMA_FILE_BYTES {
            return Err(SchemaError::Read {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "schema file exceeds {} bytes cap (actual: {})",
                        MAX_SCHEMA_FILE_BYTES,
                        meta.len()
                    ),
                ),
            });
        }
        let bytes = fs::read(path).map_err(|source| SchemaError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|source| SchemaError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        Self::from_value(&doc, path.to_path_buf())
    }

    /// Compile an already-parsed schema value.
    pub fn from_value(doc: &serde_json::Value, path: PathBuf) -> Result<Self, SchemaError> {
        let validator = jsonschema::options()
            .build(doc)
            .map_err(|e| SchemaError::Compile {
                reason: format!("{e}"),
            })?;
        Ok(Self { validator, path })
    }

    /// Validate a document. Returns `Ok(())` when every check passes; otherwise
    /// returns [`SchemaError::Invalid`] with a deterministic list of per-error
    /// summaries.
    pub fn validate(
        &self,
        document: &serde_json::Value,
        document_path: &Path,
    ) -> Result<(), SchemaError> {
        let errors: Vec<String> = self
            .validator
            .iter_errors(document)
            .map(|e| format_error(&e))
            .collect();
        if errors.is_empty() {
            return Ok(());
        }
        let summary = format!(
            "{} validation error{} against {}",
            errors.len(),
            if errors.len() == 1 { "" } else { "s" },
            self.path.display()
        );
        Err(SchemaError::Invalid {
            document_path: document_path.to_path_buf(),
            summary,
            errors,
        })
    }

    pub fn schema_path(&self) -> &Path {
        &self.path
    }
}

fn format_error(err: &jsonschema::ValidationError<'_>) -> String {
    // jsonschema v0.29's ValidationError exposes a `Display` impl plus an
    // `instance_path` field. Keeping the format short and deterministic
    // matters more than exposing the full structure — `--verbose` callers get
    // the instance path, production callers just want to know something
    // failed.
    format!("{} (at {})", err, err.instance_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_schema() -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": { "type": "string", "minLength": 1 }
            },
            "additionalProperties": false
        })
    }

    #[test]
    fn compiles_and_validates() {
        let s = CompiledSchema::from_value(&tiny_schema(), PathBuf::from("tiny")).unwrap();
        let ok = serde_json::json!({"id": "x"});
        s.validate(&ok, Path::new("doc.json")).unwrap();
    }

    #[test]
    fn rejects_missing_required() {
        let s = CompiledSchema::from_value(&tiny_schema(), PathBuf::from("tiny")).unwrap();
        let bad = serde_json::json!({});
        let err = s.validate(&bad, Path::new("doc.json")).unwrap_err();
        match err {
            SchemaError::Invalid { errors, .. } => {
                assert!(!errors.is_empty(), "expected at least one error");
            }
            other => panic!("wrong error variant: {other}"),
        }
    }

    #[test]
    fn rejects_additional_props() {
        let s = CompiledSchema::from_value(&tiny_schema(), PathBuf::from("tiny")).unwrap();
        let bad = serde_json::json!({"id": "x", "extra": 1});
        let err = s.validate(&bad, Path::new("doc.json")).unwrap_err();
        assert!(matches!(err, SchemaError::Invalid { .. }));
    }

    #[test]
    fn compile_failure_reports_reason() {
        // `type` must be a string or array; number is invalid.
        let bad_schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": 42
        });
        let err = CompiledSchema::from_value(&bad_schema, PathBuf::from("bad")).unwrap_err();
        assert!(matches!(err, SchemaError::Compile { .. }));
    }
}
