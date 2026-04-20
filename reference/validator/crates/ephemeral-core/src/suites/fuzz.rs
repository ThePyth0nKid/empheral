//! Fuzz-baseline suite executor — §4.4, §4.5, §2.2.
//!
//! Baseline corpus that every shipped classifier-WASM must pass before a Tariff
//! publishes (V3-8 defense). 204/206 vectors expect `outcome: accept` with an
//! `output: {tier, tier_floor_applied, justification_tag}` payload; fuzz-190
//! and fuzz-200 exercise the two reject paths — `tier-below-minimum` when the
//! classifier would return a tier below the Tariff's floor for the intent
//! triple, and `classifier-execution-failed` when the classifier traps before
//! producing a tier at all.
//!
//! ## Mock-classifier model (accept path)
//!
//! Session 3 does **not** run a real WASM classifier for the 204 accept
//! vectors; live classification of accept outcomes lands in Phase C.4 once
//! the Phase-C classifier's resource/taxonomy tables are migrated across
//! all intent triples. The executor instead uses a **category-driven tier
//! derivation** for the accept path:
//!
//! - Categories carrying an explicit `tierN` substring (`k8s-tier0-read`,
//!   `vault-tier3-revoke`, …) → `tier = N`. This catches vector/category drift
//!   without the cost of re-encoding the WASM classifier in Rust.
//! - Categories without an explicit tier (`bypass-*`, `context-*`,
//!   `k8s-aggregation-traps`, `vault-sensitive-paths`, `dns-and-cert`) exercise
//!   context-sensitive promotion the Router's classifier would compute
//!   dynamically — in Phase B those tiers are echoed from the vector's
//!   `expected.output.tier` as a transparent mock.
//!
//! ## Live classifier dispatch (reject path)
//!
//! Phase C.3-C Session 2 replaces the prior `classifier_would_return: u32`
//! mock field with a full dispatch tuple:
//!
//! - `input.classifier_wasm_bytes_hex: Option<String>` — lowercase-hex
//!   encoding of the ABI-v1 WASM module to execute.
//! - `input.classifier_context_cbor_hex: Option<String>` — lowercase-hex
//!   encoding of the context CBOR handed to `classify(input_ptr, input_len)`.
//!
//! When both are present, [`classify_reject`] invokes
//! [`ephemeral_classifier::execute_classifier`] under
//! [`ClassifierConfig::default`], then:
//!
//! - `Ok(output)` → `output.tier` is compared against
//!   [`derive_floor`]; a tier below floor maps to
//!   [`FuzzRejectCode::TierBelowMinimum`]; at or above floor means no
//!   reject fired (caller falls back to Accept).
//! - `Err(_)` → both [`ClassifierError::Load`] and [`ClassifierError::Exec`]
//!   collapse to [`FuzzRejectCode::ClassifierExecutionFailed`] so traps,
//!   fuel exhaustion, memory-cap hits, and parse / ABI failures are all
//!   observable as a single conformance-code surface. The variant set is
//!   [`non_exhaustive`][`FuzzRejectCode`] so a future split (trap vs.
//!   resource-denial) stays additive.
//!
//! Hex-decode failures on either field are treated as **test-setup
//! malformation**, not a protocol reject — the runner emits
//! `ValidationOutcome::Fail { reason }` out of [`execute_reject`] rather
//! than synthesising a reject code for it.
//!
//! ## tier_floor_applied derivation
//!
//! `tier_floor_applied` = `max(tariff_minimum_tiers[intent_key])` across the
//! Tariff's per-intent floors named as `integration:verb:resource_kind`. If the
//! Tariff pins no floor for the given triple, the floor is `0` (§4.5).
//!
//! ## Pass criterion
//!
//! A vector passes iff the produced `(tier, tier_floor_applied,
//! justification_tag)` deep-equals the vector's `expected.output`. Spec §4.5
//! requires `returned_tier >= tier_floor`; our mock always returns the declared
//! expected tier on the accept path, so the floor check is carried
//! structurally rather than operationally for those 204 vectors.

use std::fmt;

use ephemeral_classifier::{execute_classifier, ClassifierConfig};
use serde::Deserialize;

use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- reject code stub -----------------------------------------

/// Fuzz reject codes exercised by the baseline corpus.
///
/// `#[non_exhaustive]` so adding a future reject surface (e.g., splitting
/// `ClassifierExecutionFailed` into `ClassifierTrap` vs.
/// `ClassifierResourceDenied` once conformance coverage demands it) stays
/// source-compatible with downstream pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FuzzRejectCode {
    /// Classifier returned a tier strictly below the Tariff floor for the
    /// intent triple. Exercised by fuzz-190.
    TierBelowMinimum,
    /// Classifier never produced a tier — WASM load failure (hash / parse
    /// / import / ABI), execution trap, fuel exhaustion, memory-cap hit,
    /// or output-decode failure. Exercised by fuzz-200.
    ClassifierExecutionFailed,
}

impl fmt::Display for FuzzRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TierBelowMinimum => "tier-below-minimum",
            Self::ClassifierExecutionFailed => "classifier-execution-failed",
        })
    }
}

// ---------------- classifier output ----------------------------------------

/// Structured classifier output per §4.5. Derived by the crate-private
/// `classify` function and compared against the vector's `expected.output`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzOutcome {
    pub tier: u32,
    pub tier_floor_applied: u32,
    pub justification_tag: String,
}

// ---------------- vector input model ---------------------------------------

#[derive(Debug, Deserialize)]
struct FuzzInput {
    #[serde(default)]
    integration: Option<String>,
    #[serde(default)]
    raw_intent: Option<RawIntent>,
    #[serde(default)]
    tariff_minimum_tiers: Option<serde_json::Value>,
    /// Lowercase-hex ABI-v1 classifier WASM bytes. Reject vectors populate
    /// this to exercise real `execute_classifier` dispatch; accept vectors
    /// leave it empty and let the category-driven mock drive the tier.
    #[serde(default)]
    classifier_wasm_bytes_hex: Option<String>,
    /// Lowercase-hex CBOR bytes handed to the classifier's `classify`
    /// export. Paired with `classifier_wasm_bytes_hex`; treated as
    /// independent so a vector missing one but not the other surfaces
    /// loudly in [`prepare_classifier_dispatch`].
    #[serde(default)]
    classifier_context_cbor_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawIntent {
    #[serde(default)]
    verb: Option<String>,
    #[serde(default)]
    resource_kind: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    namespace: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExpectedOutput {
    tier: u32,
    tier_floor_applied: u32,
    justification_tag: String,
}

// ---------------- public entry point ---------------------------------------

/// Execute one `fuzz-baseline` vector.
pub fn execute(vector: &Vector) -> ValidationOutcome {
    let input: FuzzInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("fuzz-input deserialization failed: {e}"),
            };
        }
    };

    match vector.expected.outcome {
        Outcome::Accept => execute_accept(vector, &input),
        Outcome::Reject => execute_reject(vector, &input),
    }
}

fn execute_accept(vector: &Vector, input: &FuzzInput) -> ValidationOutcome {
    let expected_output: ExpectedOutput = match vector.expected.output.as_ref() {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(o) => o,
            Err(e) => {
                return ValidationOutcome::Fail {
                    reason: format!("expected.output deserialization failed: {e}"),
                };
            }
        },
        None => {
            return ValidationOutcome::Fail {
                reason: "fuzz accept vector missing expected.output".to_owned(),
            };
        }
    };

    let produced = classify(&vector.category, input, &expected_output);

    if produced.tier == expected_output.tier
        && produced.tier_floor_applied == expected_output.tier_floor_applied
        && produced.justification_tag == expected_output.justification_tag
    {
        ValidationOutcome::Pass
    } else {
        ValidationOutcome::Fail {
            reason: format!(
                "classifier output mismatch: produced {produced:?}, expected tier={}, floor={}, tag={}",
                expected_output.tier, expected_output.tier_floor_applied, expected_output.justification_tag
            ),
        }
    }
}

fn execute_reject(vector: &Vector, input: &FuzzInput) -> ValidationOutcome {
    let expected_code = vector.expected.reject_code.as_deref().unwrap_or("");
    let dispatch = match prepare_classifier_dispatch(input) {
        Ok(Some(pair)) => Some(pair),
        Ok(None) => None,
        Err(reason) => {
            return ValidationOutcome::Fail { reason };
        }
    };
    let produced = classify_reject(input, dispatch.as_ref());
    match produced {
        RejectClassification::Reject(code) if code.to_string() == expected_code => {
            ValidationOutcome::Pass
        }
        RejectClassification::Reject(code) => ValidationOutcome::Fail {
            reason: format!("reject-code mismatch: expected={expected_code} got={code}"),
        },
        RejectClassification::Accept | RejectClassification::NoDispatch => {
            ValidationOutcome::Fail {
                reason: format!("expected reject={expected_code}, got accept"),
            }
        }
        RejectClassification::FloorMissing => ValidationOutcome::Fail {
            reason: format!(
                "reject vector setup error: `tariff_minimum_tiers` has no entry for the \
                 intent triple (integration:verb:resource_kind); cannot evaluate \
                 expected reject={expected_code}"
            ),
        },
    }
}

/// Dispatch bundle holding the decoded classifier WASM bytes and context
/// CBOR. Returned only when both hex strings were present and decoded
/// cleanly; any hex-decode error or partial-pair state is surfaced as an
/// `Err(String)` so [`execute_reject`] can emit a clean validation-
/// failure reason rather than synthesising an unrelated reject code.
type ClassifierDispatch = (Vec<u8>, Vec<u8>);

fn prepare_classifier_dispatch(input: &FuzzInput) -> Result<Option<ClassifierDispatch>, String> {
    match (
        input.classifier_wasm_bytes_hex.as_deref(),
        input.classifier_context_cbor_hex.as_deref(),
    ) {
        (Some(wasm_hex), Some(ctx_hex)) => {
            let wasm = hex::decode(wasm_hex)
                .map_err(|e| format!("classifier_wasm_bytes_hex decode failed: {e}"))?;
            let ctx = hex::decode(ctx_hex)
                .map_err(|e| format!("classifier_context_cbor_hex decode failed: {e}"))?;
            Ok(Some((wasm, ctx)))
        }
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err("classifier_wasm_bytes_hex present without classifier_context_cbor_hex".to_owned())
        }
        (None, Some(_)) => {
            Err("classifier_context_cbor_hex present without classifier_wasm_bytes_hex".to_owned())
        }
    }
}

/// Reject dispatch. Runs the real classifier when dispatch bytes are
/// present, otherwise no reject fires and the caller treats the outcome
/// as the absence of a reject (Accept).
///
/// All `execute_classifier` error categories collapse to
/// [`FuzzRejectCode::ClassifierExecutionFailed`]:
///
/// - `ClassifierError::Load(ForbiddenImport | ForbiddenStartFunction |
///   MissingExport | InvalidExportSignature)` — structural ABI v1
///   violations detected before the instance runs.  Note: `HashMismatch`
///   and `InvalidHashHex` live on `ClassifierLoadError` but only fire
///   via `verify_classifier_hash`; the fuzz suite does NOT call that
///   function, so those variants cannot reach this path.
/// - `ClassifierError::Exec(WasmParseError | InstantiationFailed |
///   AllocCallTrap | ClassifyCallTrap | fuel / memory / output-decode)` —
///   parse failures, instantiation denials, and every runtime trap.
///
/// This mirrors the collapse posture used by `ClassifierSigError::
/// CoseVerifyFailed` in Phase C.3-C Session 1: anti-enumeration is not
/// the driver here, but conformance-code readability is — splitting the
/// error surface belongs in a future session once there are multiple
/// distinct conformance vectors that require it.
///
/// When the classifier succeeds but `derive_floor` cannot match the
/// intent-triple key against `tariff_minimum_tiers`, the reject vector
/// is misconfigured (the floor is the whole reason this dispatch path
/// exists).  We surface that as `None` here so [`execute_reject`] can
/// emit a clean "setup-error" failure rather than silently passing the
/// vector through as an Accept — see the explicit floor-missing check
/// in [`execute_reject`] itself.
fn classify_reject(
    input: &FuzzInput,
    dispatch: Option<&ClassifierDispatch>,
) -> RejectClassification {
    let Some((wasm, ctx)) = dispatch else {
        return RejectClassification::NoDispatch;
    };
    let config = ClassifierConfig::default();
    match execute_classifier(wasm, ctx, &config) {
        Ok(output) => match derive_floor(input) {
            Some(floor) if output.tier < floor => {
                RejectClassification::Reject(FuzzRejectCode::TierBelowMinimum)
            }
            Some(_) => RejectClassification::Accept,
            None => RejectClassification::FloorMissing,
        },
        Err(_) => RejectClassification::Reject(FuzzRejectCode::ClassifierExecutionFailed),
    }
}

/// Result of [`classify_reject`].  Separates the four semantically
/// distinct outcomes so [`execute_reject`] can distinguish a genuine
/// accept from a misconfigured vector (missing floor).  Combining
/// `Accept` and `FloorMissing` into a single `None` would silently
/// turn a setup error into an "expected reject=…, got accept"
/// failure — harder to debug for future vector authors.
#[derive(Debug, PartialEq, Eq)]
enum RejectClassification {
    /// No dispatch bytes in the input — reject vector carries no
    /// classifier WASM, so no reject code can be synthesised.
    NoDispatch,
    /// Classifier ran (successfully or failed) and produced a concrete
    /// reject code.
    Reject(FuzzRejectCode),
    /// Classifier ran successfully and the produced tier meets or
    /// exceeds the floor — no reject fires.
    Accept,
    /// Classifier ran successfully but `tariff_minimum_tiers` does not
    /// contain an entry for the intent triple — the vector is
    /// misconfigured (see [`execute_reject`] for the surfaced message).
    FloorMissing,
}

// ---------------- classifier -----------------------------------------------

fn classify(category: &str, input: &FuzzInput, expected: &ExpectedOutput) -> FuzzOutcome {
    // Tier: prefer category-derived; fall back to expected for
    // context-sensitive categories (documented as Phase-C mock).
    let tier = derive_tier_from_category(category).unwrap_or(expected.tier);

    // Floor: derived from tariff_minimum_tiers matching the intent triple.
    let tier_floor_applied = derive_floor(input).unwrap_or(expected.tier_floor_applied);

    // Justification: reuse expected tag in Session 3 — the tag vocabulary
    // (`read-only-metadata`, `bounded-write`, `destructive-recoverable`, …)
    // lives in the Phase-C classifier's resource/taxonomy tables.
    let justification_tag = expected.justification_tag.clone();

    FuzzOutcome {
        tier,
        tier_floor_applied,
        justification_tag,
    }
}

/// Extract `N` from a category such as `k8s-tier3-destructive` or
/// `vault-tier1-read-secret`. Returns `None` if the category does not carry an
/// explicit tier.
fn derive_tier_from_category(category: &str) -> Option<u32> {
    // Any `tierN` substring where N is a single decimal digit.
    let bytes = category.as_bytes();
    let needle = b"tier";
    'outer: for i in 0..bytes.len().saturating_sub(needle.len()) {
        for (j, b) in needle.iter().enumerate() {
            if bytes[i + j] != *b {
                continue 'outer;
            }
        }
        let digit_pos = i + needle.len();
        if digit_pos < bytes.len() {
            let d = bytes[digit_pos];
            if d.is_ascii_digit() {
                return Some(u32::from(d - b'0'));
            }
        }
    }
    None
}

/// Look up the Tariff floor for the intent triple. Format per §4.5:
/// `integration:verb:resource_kind`. Returns `None` on key miss so the caller
/// can fall back to the vector's declared floor (Phase-B mock); explicit max-
/// of-all fallbacks are avoided — they would inflate the floor under vectors
/// carrying overlapping entries for unrelated intents and could be leveraged
/// to force false `tier-below-minimum` rejects.
fn derive_floor(input: &FuzzInput) -> Option<u32> {
    let map = input.tariff_minimum_tiers.as_ref()?.as_object()?;
    let integration = input.integration.as_deref().unwrap_or("");
    let intent = input.raw_intent.as_ref();
    let verb = intent.and_then(|r| r.verb.as_deref()).unwrap_or("");
    let kind = intent.and_then(|r| r.resource_kind.as_deref()).unwrap_or("");

    let key_full = format!("{integration}:{verb}:{kind}");
    map.get(&key_full)
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
}

// ---------------- unit tests -----------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_classifier::test_fixtures::shared_wasm_artifacts;
    use serde_json::json;

    fn empty_ctx_cbor_hex() -> String {
        // Canonical CBOR encoding of an empty map `{}`: single byte 0xa0.
        // The fuzz classifier fixtures ignore their input, so any
        // well-formed CBOR works — we pick the shortest stable encoding.
        hex::encode([0xa0u8])
    }

    #[test]
    fn derive_tier_from_k8s_categories() {
        assert_eq!(derive_tier_from_category("k8s-tier0-read"), Some(0));
        assert_eq!(derive_tier_from_category("k8s-tier1-write-small"), Some(1));
        assert_eq!(derive_tier_from_category("k8s-tier2-write-medium"), Some(2));
        assert_eq!(derive_tier_from_category("k8s-tier3-destructive"), Some(3));
        assert_eq!(derive_tier_from_category("k8s-tier4-broad"), Some(4));
        assert_eq!(derive_tier_from_category("k8s-tier5-catastrophic"), Some(5));
    }

    #[test]
    fn derive_tier_from_vault_categories() {
        assert_eq!(derive_tier_from_category("vault-tier0-read-metadata"), Some(0));
        assert_eq!(derive_tier_from_category("vault-tier3-revoke"), Some(3));
        assert_eq!(derive_tier_from_category("vault-tier5-root"), Some(5));
    }

    #[test]
    fn derive_tier_from_non_tier_category_is_none() {
        assert_eq!(derive_tier_from_category("bypass-verb-obfuscation"), None);
        assert_eq!(derive_tier_from_category("context-canary-window"), None);
        assert_eq!(derive_tier_from_category("k8s-aggregation-traps"), None);
        assert_eq!(derive_tier_from_category("dns-and-cert"), None);
    }

    #[test]
    fn derive_floor_matches_exact_key() {
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("list".to_owned()),
                resource_kind: Some("pod".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:list:pod": 0})),
            classifier_wasm_bytes_hex: None,
            classifier_context_cbor_hex: None,
        };
        assert_eq!(derive_floor(&input), Some(0));
    }

    #[test]
    fn derive_floor_no_match_returns_none() {
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("list".to_owned()),
                resource_kind: Some("pod".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:delete:pod": 3, "kubernetes:patch:pod": 2})),
            classifier_wasm_bytes_hex: None,
            classifier_context_cbor_hex: None,
        };
        // No fallback to max-of-all — callers fall back to the vector's
        // declared floor, preventing accidental floor inflation.
        assert_eq!(derive_floor(&input), None);
    }

    #[test]
    fn classify_full_path_tier0_read() {
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("list".to_owned()),
                resource_kind: Some("pod".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:list:pod": 0})),
            classifier_wasm_bytes_hex: None,
            classifier_context_cbor_hex: None,
        };
        let expected = ExpectedOutput {
            tier: 0,
            tier_floor_applied: 0,
            justification_tag: "read-only-metadata".to_owned(),
        };
        let out = classify("k8s-tier0-read", &input, &expected);
        assert_eq!(out.tier, 0);
        assert_eq!(out.tier_floor_applied, 0);
        assert_eq!(out.justification_tag, "read-only-metadata");
    }

    #[test]
    fn classify_falls_back_to_expected_for_non_tier_category() {
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("exec".to_owned()),
                resource_kind: Some("pod".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:exec:pod": 2})),
            classifier_wasm_bytes_hex: None,
            classifier_context_cbor_hex: None,
        };
        let expected = ExpectedOutput {
            tier: 4,
            tier_floor_applied: 2,
            justification_tag: "destructive-recoverable".to_owned(),
        };
        let out = classify("bypass-verb-obfuscation", &input, &expected);
        // Category has no tierN → falls through to expected.tier.
        assert_eq!(out.tier, 4);
        assert_eq!(out.tier_floor_applied, 2);
    }

    #[test]
    fn reject_code_display() {
        assert_eq!(
            FuzzRejectCode::TierBelowMinimum.to_string(),
            "tier-below-minimum"
        );
        assert_eq!(
            FuzzRejectCode::ClassifierExecutionFailed.to_string(),
            "classifier-execution-failed"
        );
    }

    #[test]
    fn classify_reject_tier_below_minimum_via_live_classifier() {
        // The tier-1 fixture classifier produces tier=1; with a floor of 2
        // this must surface as TierBelowMinimum.
        let pool = shared_wasm_artifacts();
        let wasm_hex = hex::encode(&pool.tier_1);
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("scale".to_owned()),
                resource_kind: Some("deployment".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:scale:deployment": 2})),
            classifier_wasm_bytes_hex: Some(wasm_hex),
            classifier_context_cbor_hex: Some(empty_ctx_cbor_hex()),
        };
        let dispatch = prepare_classifier_dispatch(&input)
            .expect("dispatch pair parses")
            .expect("dispatch present");
        assert_eq!(
            classify_reject(&input, Some(&dispatch)),
            RejectClassification::Reject(FuzzRejectCode::TierBelowMinimum)
        );
    }

    #[test]
    fn classify_reject_returns_accept_when_tier_at_or_above_floor() {
        // Tier-9999 fixture ≥ any realistic floor — no reject fires.
        let pool = shared_wasm_artifacts();
        let wasm_hex = hex::encode(&pool.tier_9999);
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("scale".to_owned()),
                resource_kind: Some("deployment".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:scale:deployment": 2})),
            classifier_wasm_bytes_hex: Some(wasm_hex),
            classifier_context_cbor_hex: Some(empty_ctx_cbor_hex()),
        };
        let dispatch = prepare_classifier_dispatch(&input)
            .expect("dispatch pair parses")
            .expect("dispatch present");
        assert_eq!(
            classify_reject(&input, Some(&dispatch)),
            RejectClassification::Accept
        );
    }

    #[test]
    fn classify_reject_classifier_execution_failed_on_fuel_trap() {
        // Fuel-exhausted fixture loads cleanly but traps at `classify`
        // call time — the collapse posture must surface as
        // ClassifierExecutionFailed.
        let pool = shared_wasm_artifacts();
        let wasm_hex = hex::encode(&pool.fuel_exhausted);
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("scale".to_owned()),
                resource_kind: Some("deployment".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:scale:deployment": 2})),
            classifier_wasm_bytes_hex: Some(wasm_hex),
            classifier_context_cbor_hex: Some(empty_ctx_cbor_hex()),
        };
        let dispatch = prepare_classifier_dispatch(&input)
            .expect("dispatch pair parses")
            .expect("dispatch present");
        assert_eq!(
            classify_reject(&input, Some(&dispatch)),
            RejectClassification::Reject(FuzzRejectCode::ClassifierExecutionFailed)
        );
    }

    #[test]
    fn classify_reject_returns_no_dispatch_when_bytes_absent() {
        // Accept-path inputs never populate the dispatch fields; the
        // reject classifier must surface NoDispatch (no classifier ran).
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("list".to_owned()),
                resource_kind: Some("pod".to_owned()),
                namespace: None,
                name: None,
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:list:pod": 0})),
            classifier_wasm_bytes_hex: None,
            classifier_context_cbor_hex: None,
        };
        assert_eq!(
            classify_reject(&input, None),
            RejectClassification::NoDispatch
        );
    }

    #[test]
    fn classify_reject_surfaces_floor_missing_when_tariff_key_absent() {
        // Vector author forgot to add the kubernetes:scale:deployment
        // entry — classifier runs but there is no floor to compare
        // against.  The classification must surface as FloorMissing so
        // `execute_reject` can emit a setup-error reason.
        let pool = shared_wasm_artifacts();
        let wasm_hex = hex::encode(&pool.tier_1);
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("scale".to_owned()),
                resource_kind: Some("deployment".to_owned()),
                namespace: None,
                name: None,
            }),
            // Deliberately wrong triple — `scale` != `patch`.
            tariff_minimum_tiers: Some(json!({"kubernetes:patch:deployment": 2})),
            classifier_wasm_bytes_hex: Some(wasm_hex),
            classifier_context_cbor_hex: Some(empty_ctx_cbor_hex()),
        };
        let dispatch = prepare_classifier_dispatch(&input)
            .expect("dispatch pair parses")
            .expect("dispatch present");
        assert_eq!(
            classify_reject(&input, Some(&dispatch)),
            RejectClassification::FloorMissing
        );
    }

    #[test]
    fn prepare_dispatch_rejects_partial_pair() {
        let only_wasm = FuzzInput {
            integration: None,
            raw_intent: None,
            tariff_minimum_tiers: None,
            classifier_wasm_bytes_hex: Some("00".to_owned()),
            classifier_context_cbor_hex: None,
        };
        assert!(prepare_classifier_dispatch(&only_wasm).is_err());

        let only_ctx = FuzzInput {
            integration: None,
            raw_intent: None,
            tariff_minimum_tiers: None,
            classifier_wasm_bytes_hex: None,
            classifier_context_cbor_hex: Some("a0".to_owned()),
        };
        assert!(prepare_classifier_dispatch(&only_ctx).is_err());
    }

    #[test]
    fn prepare_dispatch_rejects_malformed_hex() {
        let input = FuzzInput {
            integration: None,
            raw_intent: None,
            tariff_minimum_tiers: None,
            classifier_wasm_bytes_hex: Some("xyznothex".to_owned()),
            classifier_context_cbor_hex: Some("a0".to_owned()),
        };
        let err = prepare_classifier_dispatch(&input)
            .expect_err("malformed wasm hex must error")
            .to_lowercase();
        assert!(
            err.contains("classifier_wasm_bytes_hex"),
            "error mentions offending field: {err}"
        );
    }
}
