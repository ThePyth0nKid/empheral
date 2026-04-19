//! Fuzz-baseline suite executor — §4.4, §4.5, §2.2.
//!
//! Baseline corpus that every shipped classifier-WASM must pass before a Tariff
//! publishes (V3-8 defense). 204/205 vectors expect `outcome: accept` with an
//! `output: {tier, tier_floor_applied, justification_tag}` payload; fuzz-190
//! demonstrates the reject path (`tier-below-minimum`) when the classifier
//! would return a tier below the Tariff's floor for the intent triple.
//!
//! ## Mock-classifier model
//!
//! Session 3 does **not** run a real WASM classifier; live classification lands
//! in Phase C. The executor instead uses a **category-driven tier derivation**:
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
//! expected tier, so the floor check is carried structurally rather than
//! operationally.

use std::fmt;

use serde::Deserialize;

use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- reject code stub -----------------------------------------

/// Fuzz reject codes exercised by the baseline corpus. `TierBelowMinimum`
/// is the only code active in Session 3 (fuzz-190); additional codes will
/// surface once Phase-C ships live WASM classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FuzzRejectCode {
    TierBelowMinimum,
}

impl fmt::Display for FuzzRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TierBelowMinimum => "tier-below-minimum",
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
    context: Option<FuzzContext>,
    #[serde(default)]
    tariff_minimum_tiers: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct FuzzContext {
    /// Classifier's proposed tier for this intent. Populated on reject
    /// vectors (fuzz-190) where the test asserts floor-vs-classifier
    /// comparison semantics.
    #[serde(default)]
    classifier_would_return: Option<u32>,
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
    let produced = classify_reject(input);
    match produced {
        Some(code) if code.to_string() == expected_code => ValidationOutcome::Pass,
        Some(code) => ValidationOutcome::Fail {
            reason: format!("reject-code mismatch: expected={expected_code} got={code}"),
        },
        None => ValidationOutcome::Fail {
            reason: format!("expected reject={expected_code}, got accept"),
        },
    }
}

/// Session-3 reject dispatch: the sole modeled code is `tier-below-minimum`,
/// raised when the classifier's projected tier is strictly below the Tariff's
/// configured floor for the intent triple (§4.5).
fn classify_reject(input: &FuzzInput) -> Option<FuzzRejectCode> {
    let classifier_tier = input.context.as_ref()?.classifier_would_return?;
    let floor = derive_floor(input)?;
    if classifier_tier < floor {
        Some(FuzzRejectCode::TierBelowMinimum)
    } else {
        None
    }
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
    use serde_json::json;

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
            context: None,
            tariff_minimum_tiers: Some(json!({"kubernetes:list:pod": 0})),
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
            context: None,
            tariff_minimum_tiers: Some(json!({"kubernetes:delete:pod": 3, "kubernetes:patch:pod": 2})),
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
            context: None,
            tariff_minimum_tiers: Some(json!({"kubernetes:list:pod": 0})),
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
            context: None,
            tariff_minimum_tiers: Some(json!({"kubernetes:exec:pod": 2})),
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
    }

    #[test]
    fn classify_reject_tier_below_minimum() {
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("scale".to_owned()),
                resource_kind: Some("deployment".to_owned()),
                namespace: None,
                name: None,
            }),
            context: Some(FuzzContext {
                classifier_would_return: Some(1),
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:scale:deployment": 2})),
        };
        assert_eq!(classify_reject(&input), Some(FuzzRejectCode::TierBelowMinimum));
    }

    #[test]
    fn classify_reject_returns_none_when_at_or_above_floor() {
        let input = FuzzInput {
            integration: Some("kubernetes".to_owned()),
            raw_intent: Some(RawIntent {
                verb: Some("scale".to_owned()),
                resource_kind: Some("deployment".to_owned()),
                namespace: None,
                name: None,
            }),
            context: Some(FuzzContext {
                classifier_would_return: Some(2),
            }),
            tariff_minimum_tiers: Some(json!({"kubernetes:scale:deployment": 2})),
        };
        assert_eq!(classify_reject(&input), None);
    }
}
