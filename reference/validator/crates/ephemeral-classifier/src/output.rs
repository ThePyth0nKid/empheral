//! [`ClassifierOutput`] — structured result per spec §4.5.
//!
//! All five fields are REQUIRED on the wire (`escalations` MAY be empty;
//! `justification_tag` MAY be the empty string, but both MUST be present
//! in the CBOR encoding).  A missing field causes CBOR deserialization to
//! fail, which the runtime surfaces as
//! [`ClassifierExecError::OutputDecodeFailed`](crate::ClassifierExecError).

use serde::{Deserialize, Serialize};

/// Structured classifier output (spec §4.5).
///
/// The struct is intentionally *not* `#[non_exhaustive]`: test code inside
/// `ephemeral-core`'s fuzz suite and the Phase-C.3 conformance harness
/// constructs it via struct-literal syntax.  Spec additions (if any) will
/// be handled via a version bump at the ABI boundary, not by silently
/// extending this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifierOutput {
    /// Assigned tier.  Spec range is `0..=5` (§2); the crate does not
    /// clamp, but the caller's policy layer MAY reject out-of-range values.
    pub tier: u32,

    /// Machine-readable reason identifier (§4.5).
    pub reason_code: String,

    /// Human-readable reason for audit (§4.5).
    pub reason_text: String,

    /// Escalation codes triggered during classification (§4.5, SEQUENCE).
    pub escalations: Vec<String>,

    /// Space-separated justification-tag composition per R8.F2 (§4.5).
    pub justification_tag: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> ClassifierOutput {
        ClassifierOutput {
            tier: 3,
            reason_code: "destructive-uniform".into(),
            reason_text: "delete verb on k8s deployment".into(),
            escalations: vec!["target-invariants-missing".into()],
            justification_tag: "destructive sensitive-path".into(),
        }
    }

    #[test]
    fn cbor_roundtrip_preserves_all_fields() {
        let input = example();
        let mut bytes = Vec::new();
        ciborium::into_writer(&input, &mut bytes).expect("cbor encode");
        let decoded: ClassifierOutput =
            ciborium::from_reader(bytes.as_slice()).expect("cbor decode");
        assert_eq!(input, decoded);
    }

    #[test]
    fn cbor_roundtrip_with_empty_escalations() {
        let input = ClassifierOutput {
            escalations: Vec::new(),
            ..example()
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&input, &mut bytes).unwrap();
        let decoded: ClassifierOutput = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert!(decoded.escalations.is_empty());
        assert_eq!(input, decoded);
    }

    #[test]
    fn cbor_roundtrip_with_empty_justification_tag() {
        let input = ClassifierOutput {
            justification_tag: String::new(),
            ..example()
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&input, &mut bytes).unwrap();
        let decoded: ClassifierOutput = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded.justification_tag, "");
        assert_eq!(input, decoded);
    }

    #[test]
    fn cbor_rejects_missing_required_field() {
        // A CBOR map containing only `tier` — all other required fields
        // absent.  Must fail to deserialize.
        use std::collections::BTreeMap;
        let partial: BTreeMap<&str, u32> = BTreeMap::from([("tier", 2)]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&partial, &mut bytes).unwrap();
        let decoded: Result<ClassifierOutput, _> = ciborium::from_reader(bytes.as_slice());
        assert!(decoded.is_err());
    }

    #[test]
    fn cbor_rejects_wrong_type_for_tier() {
        // tier encoded as a string instead of integer.
        use std::collections::BTreeMap;
        let mut bytes = Vec::new();
        let broken: BTreeMap<&str, ciborium::Value> = BTreeMap::from([
            ("tier", ciborium::Value::Text("zero".into())),
            ("reason_code", ciborium::Value::Text("ok".into())),
            ("reason_text", ciborium::Value::Text("ok".into())),
            ("escalations", ciborium::Value::Array(Vec::new())),
            ("justification_tag", ciborium::Value::Text(String::new())),
        ]);
        ciborium::into_writer(&broken, &mut bytes).unwrap();
        let decoded: Result<ClassifierOutput, _> = ciborium::from_reader(bytes.as_slice());
        assert!(decoded.is_err());
    }
}
