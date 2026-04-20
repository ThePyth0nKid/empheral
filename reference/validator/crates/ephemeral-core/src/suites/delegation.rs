//! Delegation-scope suite executor — V3-1 scope-match table.
//!
//! See **design-final-v2.md §7.3 / §7.3.0 / §7.3.1 / §3.1 / §7.5**.
//!
//! ## Check order (fail-fast, first-failing wins)
//!
//! 1. **Signature validity** — any `signature_valid == false` on any link or
//!    on the mandate itself → `signature-invalid`. This fires before any
//!    structural chain checks so that a broken cryptographic seal is
//!    reported accurately even when the chain is otherwise suspect.
//! 2. **Structural chain integrity** → `signature-chain-broken`:
//!    - empty chain (ds-019)
//!    - first link's `parent_key` not the pinned trust anchor (ds-020)
//!    - any link's `signed_by` ≠ its own `parent_key` (ds-018, self-signed)
//!    - mandate's `signer_key_hint` ≠ terminal link's `child_key` (ds-022)
//!    - duplicate chain link — same `(parent, child, role)` triple (ds-023)
//!    - scope missing any of the six required fields (ds-058)
//! 3. **Chain depth** — more than 3 links → `chain-depth-exceeded` (§7.3.1).
//! 4. **Role hierarchy** (§7.3.0) — first link's `child_role` is `ops`,
//!    terminal role appears only at the end.
//! 5. **Validity windows** per link — `current_time` must lie in
//!    `[valid_from, valid_until)`, else `expired`.
//! 6. **Revocation** — `child_key`, `parent_key`, or `mandate_id` appears in
//!    `context.revocation_list` → `revoked` (covers ds-050/051).
//! 7. **Mandate structural** — empty cap → `mandate-empty-cap`; mandate
//!    validity window; `version-skew`.
//! 8. **Integrations wildcard** forbidden at every level (R7.D4).
//! 9. **Scope-match** per link (§7.3 seven-row table). First-failing row wins.
//! 10. **§3.1 narrowness rule** — wildcard in `cap.verb`, `cap.resource_kind`,
//!     or `cap.resource_ref` requires `budget.actions ≤
//!     narrowness_threshold` (default 20, ds-066).

use std::fmt;

use ephemeral_crypto::{AnchorRole, CoseError};
use serde::Deserialize;

use super::crypto_support::{verify_with_defs, TrustAnchorKeyDef};
use crate::types::{Outcome, ValidationOutcome, Vector};

// ---------------- constants ------------------------------------------------

/// Router-pinned trust anchor. The top of every valid delegation chain MUST
/// be signed by this key (V3-1 §7.5 root-compromise story).
const TRUST_ANCHOR: &str = "K_cust_root_pk_TEST";

/// Maximum delegation-chain length (§7.3.1).
pub const MAX_CHAIN_LINKS: usize = 3;

/// Default narrowness budget when `context.narrowness_threshold` is absent.
pub const DEFAULT_NARROWNESS_THRESHOLD: i64 = 20;

// ---------------- reject codes ---------------------------------------------

/// Reject codes named by §7.3 / §7.3.0 / §7.3.1 / §7.5 / §3.1.
/// `parent-delegation-revoked` is spec-mandated but not exercised by the
/// current vector set — retained so the enum stays faithful to §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DelegationRejectCode {
    RoleHierarchyViolation,
    ChainDepthExceeded,
    SignatureInvalid,
    SignatureChainBroken,
    Expired,
    Revoked,
    ParentDelegationRevoked,
    VersionSkew,
    ScopeIntegrationMismatch,
    ScopeIntegrationsWildcardForbidden,
    ScopeTierExceeded,
    ScopeVerbForbidden,
    ScopeResourceKindForbidden,
    ScopeBudgetExceeded,
    ScopeExpiryTooLong,
    MandateEmptyCap,
    NarrownessRuleViolation,
}

impl fmt::Display for DelegationRejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RoleHierarchyViolation => "role-hierarchy-violation",
            Self::ChainDepthExceeded => "chain-depth-exceeded",
            Self::SignatureInvalid => "signature-invalid",
            Self::SignatureChainBroken => "signature-chain-broken",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::ParentDelegationRevoked => "parent-delegation-revoked",
            Self::VersionSkew => "version-skew",
            Self::ScopeIntegrationMismatch => "scope-integration-mismatch",
            Self::ScopeIntegrationsWildcardForbidden => "scope-integrations-wildcard-forbidden",
            Self::ScopeTierExceeded => "scope-tier-exceeded",
            Self::ScopeVerbForbidden => "scope-verb-forbidden",
            Self::ScopeResourceKindForbidden => "scope-resource-kind-forbidden",
            Self::ScopeBudgetExceeded => "scope-budget-exceeded",
            Self::ScopeExpiryTooLong => "scope-expiry-too-long",
            Self::MandateEmptyCap => "mandate-empty-cap",
            Self::NarrownessRuleViolation => "narrowness-rule-violation",
        })
    }
}

// ---------------- data model (vector-facing) -------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Ops,
    MandateSigner,
    TariffSigner,
    AuditSigner,
    AnomalyLibrarySigner,
}

impl Role {
    fn is_terminal(self) -> bool {
        !matches!(self, Self::Ops)
    }
}

/// Budget values are signed so that `{"actions": -1}` (ds-042) is accepted
/// by serde but then rejected by scope-match as exceeding any non-negative
/// cap. JSON does not type-tag unsigned ints; enforcing `u64` at the serde
/// layer would surface as a schema-adjacent deserialization error and hide
/// the domain-level `scope-budget-exceeded` verdict the spec expects.
#[derive(Debug, Clone, Copy, Deserialize)]
struct Budget {
    #[serde(default)]
    actions: i64,
    #[serde(default)]
    tokens: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct RawDelegationScope {
    #[serde(default)]
    integrations: Option<Vec<String>>,
    #[serde(default)]
    max_tier_signable: Option<u8>,
    #[serde(default)]
    max_budget: Option<Budget>,
    #[serde(default)]
    max_exp_seconds: Option<u64>,
    #[serde(default)]
    allowed_verbs: Option<Vec<String>>,
    #[serde(default)]
    allowed_resource_kinds: Option<Vec<String>>,
}

/// A fully-materialised scope. `from_raw` returns `None` when any of the
/// six required fields is missing — the harness treats that as a structural
/// chain failure (ds-058).
struct DelegationScope<'a> {
    integrations: &'a [String],
    max_tier_signable: u8,
    max_budget: Budget,
    max_exp_seconds: u64,
    allowed_verbs: &'a [String],
    allowed_resource_kinds: &'a [String],
}

impl<'a> DelegationScope<'a> {
    fn from_raw(raw: &'a RawDelegationScope) -> Option<Self> {
        Some(Self {
            integrations: raw.integrations.as_deref()?,
            max_tier_signable: raw.max_tier_signable?,
            max_budget: raw.max_budget?,
            max_exp_seconds: raw.max_exp_seconds?,
            allowed_verbs: raw.allowed_verbs.as_deref()?,
            allowed_resource_kinds: raw.allowed_resource_kinds.as_deref()?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DelegationLink {
    parent_key: String,
    child_key: String,
    child_role: Role,
    scope: RawDelegationScope,
    valid_from: u64,
    valid_until: u64,
    #[allow(dead_code)]
    #[serde(default)]
    revocation_channel: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    issuer_constraints: serde_json::Value,
    #[serde(default)]
    signed_by: Option<String>,
    signature_valid: bool,
    /// Phase C.1 — optional hex-encoded COSE_Sign1 blob. When paired
    /// with [`VectorInput::trust_anchor_keys`], this link's signature
    /// is verified live via `ephemeral-crypto`.
    #[serde(default)]
    cose_sign1_bytes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CapEntry {
    verb: String,
    resource_kind: String,
    #[serde(default)]
    tier: u8,
    #[serde(default)]
    resource_ref: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    sub_resource: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Mandate {
    mandate_id: String,
    integration_ref: String,
    cap: Vec<CapEntry>,
    budget: Budget,
    issued_at: u64,
    exp: u64,
    min_tariff_version: u64,
    #[allow(dead_code)]
    #[serde(default)]
    purpose: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    operator_id: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    revocation_channel_ref: Option<String>,
    #[serde(default)]
    signer_key_hint: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    signed_by: Option<String>,
    signature_valid: bool,
    /// Phase C.1 — optional hex-encoded COSE_Sign1 blob for the mandate.
    #[serde(default)]
    cose_sign1_bytes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Context {
    current_tariff_version: u64,
    current_time: u64,
    #[serde(default)]
    revocation_list: Vec<String>,
    #[serde(default = "default_narrowness")]
    narrowness_threshold: i64,
}

fn default_narrowness() -> i64 {
    DEFAULT_NARROWNESS_THRESHOLD
}

#[derive(Debug, Clone, Deserialize)]
struct VectorInput {
    delegation_chain: Vec<DelegationLink>,
    mandate: Mandate,
    context: Context,
    /// Phase C.1 — shared trust anchor bag used by live verify for every
    /// link and the mandate. Absent on mock-era vectors.
    #[serde(default)]
    trust_anchor_keys: Option<Vec<TrustAnchorKeyDef>>,
}

// ---------------- pipeline --------------------------------------------------

fn verify(input: &VectorInput) -> Result<(), DelegationRejectCode> {
    let chain = input.delegation_chain.as_slice();

    // 1. Signature validity — any broken cryptographic seal reports as
    //    `signature-invalid`, regardless of position (ds-015/016/017).
    //    Phase C.1: when a link (or the mandate) carries
    //    `cose_sign1_bytes` AND the vector supplies `trust_anchor_keys`,
    //    the signature is verified live via `ephemeral-crypto` with
    //    external AAD domain-separating links (`b"delegation-link"`)
    //    from mandates (`b"mandate"`). Otherwise the mock
    //    `signature_valid` bool is honoured so the mock-era vectors
    //    stay green without mutation.
    let anchor_defs = input.trust_anchor_keys.as_deref();
    for link in chain {
        check_link_signature(link, anchor_defs)?;
    }
    check_mandate_signature(&input.mandate, anchor_defs)?;

    // 2. Structural chain integrity → `signature-chain-broken`.
    //    Must run BEFORE chain-depth / role-hierarchy so that duplicate-link
    //    chains (ds-023) report as chain-broken instead of role-hierarchy.
    structural_chain_check(input)?;

    // 3. Chain depth (§7.3.1).
    if chain.len() > MAX_CHAIN_LINKS {
        return Err(DelegationRejectCode::ChainDepthExceeded);
    }

    // 4. Role hierarchy (§7.3.0).
    role_hierarchy_check(chain)?;

    // 5. Per-link validity window.
    for link in chain {
        if input.context.current_time >= link.valid_until {
            return Err(DelegationRejectCode::Expired);
        }
        if input.context.current_time < link.valid_from {
            return Err(DelegationRejectCode::Expired);
        }
    }

    // 6. Revocation — covers child keys, parent keys, and the mandate ID
    //    itself (ds-050 mandate-level, ds-051 root-level).
    revocation_check(input)?;

    // 7. Mandate structural checks.
    if input.mandate.cap.is_empty() {
        return Err(DelegationRejectCode::MandateEmptyCap);
    }
    if input.context.current_time >= input.mandate.exp {
        return Err(DelegationRejectCode::Expired);
    }
    if input.context.current_time < input.mandate.issued_at {
        return Err(DelegationRejectCode::Expired);
    }
    if input.mandate.min_tariff_version > input.context.current_tariff_version {
        return Err(DelegationRejectCode::VersionSkew);
    }

    // 8. R7.D4: wildcard `integrations: ["*"]` forbidden at every level.
    for link in chain {
        if let Some(ints) = link.scope.integrations.as_ref() {
            if ints.iter().any(|s| s == "*") {
                return Err(DelegationRejectCode::ScopeIntegrationsWildcardForbidden);
            }
        }
    }

    // 9. §7.3 scope-match table per link.
    for link in chain {
        // `from_raw` is Some(…) here because the structural check already
        // rejected any link with incomplete scope.
        let scope = DelegationScope::from_raw(&link.scope)
            .ok_or(DelegationRejectCode::SignatureChainBroken)?;
        scope_match(&input.mandate, &scope)?;
    }

    // 10. §3.1 narrowness — wildcard anywhere in cap triggers the budget cap.
    if mandate_has_wildcard_cap(&input.mandate)
        && input.mandate.budget.actions > input.context.narrowness_threshold
    {
        return Err(DelegationRejectCode::NarrownessRuleViolation);
    }

    Ok(())
}

/// Phase C.1 — gate one link's signature. Four-way dispatch: (bytes,
/// anchors) → live verify; (bytes, no-anchors) and (no-bytes, anchors)
/// → reject with `SignatureInvalid` (these are authoring errors that
/// must not silently fall through to the mock `signature_valid` bool);
/// (no-bytes, no-anchors) → legacy mock path.
///
/// Why strict: if a vector advertises `trust_anchor_keys` it is opting
/// in to live crypto for every signature in scope. A link that omits
/// `cose_sign1_bytes` under that regime would be an unverified assertion
/// and must not accept on the mock bool alone.
fn check_link_signature(
    link: &DelegationLink,
    anchor_defs: Option<&[TrustAnchorKeyDef]>,
) -> Result<(), DelegationRejectCode> {
    match (&link.cose_sign1_bytes, anchor_defs) {
        (Some(hex_bytes), Some(defs)) => verify_with_defs(
            hex_bytes,
            defs,
            b"delegation-link",
            AnchorRole::DelegationSigner,
        )
        .map(|_| ())
        .map_err(|e| map_cose_error_to_delegation(&e)),
        (Some(_), None) | (None, Some(_)) => Err(DelegationRejectCode::SignatureInvalid),
        (None, None) => {
            if link.signature_valid {
                Ok(())
            } else {
                Err(DelegationRejectCode::SignatureInvalid)
            }
        }
    }
}

/// Phase C.1 — gate the mandate's signature. Same four-way dispatch as
/// [`check_link_signature`] but with the mandate's domain separation
/// AAD (`b"mandate"`) so mandate bytes cannot be replayed as link bytes
/// or vice versa.
fn check_mandate_signature(
    mandate: &Mandate,
    anchor_defs: Option<&[TrustAnchorKeyDef]>,
) -> Result<(), DelegationRejectCode> {
    match (&mandate.cose_sign1_bytes, anchor_defs) {
        (Some(hex_bytes), Some(defs)) => verify_with_defs(
            hex_bytes,
            defs,
            b"mandate",
            AnchorRole::DelegationSigner,
        )
        .map(|_| ())
        .map_err(|e| map_cose_error_to_delegation(&e)),
        (Some(_), None) | (None, Some(_)) => Err(DelegationRejectCode::SignatureInvalid),
        (None, None) => {
            if mandate.signature_valid {
                Ok(())
            } else {
                Err(DelegationRejectCode::SignatureInvalid)
            }
        }
    }
}

/// Map any live-crypto [`CoseError`] onto the delegation suite's reject
/// codes. Delegation's error surface is coarser than tariff's: the suite
/// exposes only `signature-invalid` and `signature-chain-broken` at the
/// crypto step, so any decode / alg / kid failure folds to
/// `signature-invalid` (§7.3 — "crypto failure is indistinguishable from
/// tamper for the receiver").
fn map_cose_error_to_delegation(_e: &CoseError) -> DelegationRejectCode {
    DelegationRejectCode::SignatureInvalid
}

fn structural_chain_check(input: &VectorInput) -> Result<(), DelegationRejectCode> {
    let chain = input.delegation_chain.as_slice();

    // Empty chain: no path from trust anchor to mandate signer (ds-019).
    if chain.is_empty() {
        return Err(DelegationRejectCode::SignatureChainBroken);
    }

    // First link must anchor at the Router-pinned root (ds-020).
    if chain[0].parent_key != TRUST_ANCHOR {
        return Err(DelegationRejectCode::SignatureChainBroken);
    }

    // Each link's `signed_by` must equal its own `parent_key` — self-signed
    // links attempting to impersonate a parent are rejected (ds-018). A
    // missing `signed_by` breaks the chain-linkage invariant outright (an
    // attacker could otherwise forge a link anchored at TRUST_ANCHOR by
    // omitting the signer field).
    for link in chain {
        let signed_by = link
            .signed_by
            .as_deref()
            .ok_or(DelegationRejectCode::SignatureChainBroken)?;
        if signed_by != link.parent_key {
            return Err(DelegationRejectCode::SignatureChainBroken);
        }
    }

    // Terminal child_key must match the mandate's signer hint (ds-022).
    let terminal_child = chain
        .last()
        .map_or("", |l| l.child_key.as_str());
    if let Some(hint) = input.mandate.signer_key_hint.as_deref() {
        if hint != terminal_child {
            return Err(DelegationRejectCode::SignatureChainBroken);
        }
    }

    // Duplicate link detection (ds-023). Chain length is bounded by 3 so
    // O(n²) pairwise comparison is fine; no hashing dependency pulled in.
    for i in 0..chain.len() {
        for j in (i + 1)..chain.len() {
            if chain[i].parent_key == chain[j].parent_key
                && chain[i].child_key == chain[j].child_key
                && chain[i].child_role == chain[j].child_role
            {
                return Err(DelegationRejectCode::SignatureChainBroken);
            }
        }
    }

    // Scope-field completeness (ds-058): missing fields must reject rather
    // than silently default to permissive values.
    for link in chain {
        if DelegationScope::from_raw(&link.scope).is_none() {
            return Err(DelegationRejectCode::SignatureChainBroken);
        }
    }

    Ok(())
}

fn role_hierarchy_check(chain: &[DelegationLink]) -> Result<(), DelegationRejectCode> {
    let first = &chain[0];
    let last = &chain[chain.len() - 1];
    if first.child_role != Role::Ops {
        return Err(DelegationRejectCode::RoleHierarchyViolation);
    }
    if !last.child_role.is_terminal() && chain.len() > 1 {
        return Err(DelegationRejectCode::RoleHierarchyViolation);
    }
    for link in &chain[..chain.len() - 1] {
        if link.child_role != Role::Ops {
            return Err(DelegationRejectCode::RoleHierarchyViolation);
        }
    }
    Ok(())
}

fn revocation_check(input: &VectorInput) -> Result<(), DelegationRejectCode> {
    let rl = &input.context.revocation_list;
    // Mandate-level revocation (ds-050).
    if rl.iter().any(|x| x == &input.mandate.mandate_id) {
        return Err(DelegationRejectCode::Revoked);
    }
    // Every key in the chain is subject to revocation (ds-051 covers the
    // root, but the same rule applies to any parent/child key appearing in
    // the revocation list).
    for link in &input.delegation_chain {
        if rl.iter().any(|x| x == &link.child_key) {
            return Err(DelegationRejectCode::Revoked);
        }
        if rl.iter().any(|x| x == &link.parent_key) {
            return Err(DelegationRejectCode::Revoked);
        }
    }
    Ok(())
}

fn scope_match(
    mandate: &Mandate,
    scope: &DelegationScope<'_>,
) -> Result<(), DelegationRejectCode> {
    // Row 1: integration_ref must be in the link's allowlist.
    if !scope
        .integrations
        .iter()
        .any(|s| s == &mandate.integration_ref)
    {
        return Err(DelegationRejectCode::ScopeIntegrationMismatch);
    }
    // Row 2: highest-tier entry in cap must fit the link's tier cap.
    if let Some(max_tier) = mandate.cap.iter().map(|c| c.tier).max() {
        if max_tier > scope.max_tier_signable {
            return Err(DelegationRejectCode::ScopeTierExceeded);
        }
    }
    // Row 3: verb allowlist (supports wildcard on either side).
    let verbs_wildcard = scope.allowed_verbs.iter().any(|v| v == "*");
    if !verbs_wildcard {
        for c in &mandate.cap {
            if c.verb == "*"
                || !scope.allowed_verbs.iter().any(|v| v == &c.verb)
            {
                return Err(DelegationRejectCode::ScopeVerbForbidden);
            }
        }
    }
    // Row 4: resource_kind allowlist.
    let kinds_wildcard = scope.allowed_resource_kinds.iter().any(|v| v == "*");
    if !kinds_wildcard {
        for c in &mandate.cap {
            if c.resource_kind == "*"
                || !scope
                    .allowed_resource_kinds
                    .iter()
                    .any(|k| k == &c.resource_kind)
            {
                return Err(DelegationRejectCode::ScopeResourceKindForbidden);
            }
        }
    }
    // Row 5+6: budget. Negative mandate budgets (ds-042) are treated as
    // exceeding any non-negative cap.
    if mandate.budget.actions < 0 || mandate.budget.actions > scope.max_budget.actions {
        return Err(DelegationRejectCode::ScopeBudgetExceeded);
    }
    if mandate.budget.tokens < 0 || mandate.budget.tokens > scope.max_budget.tokens {
        return Err(DelegationRejectCode::ScopeBudgetExceeded);
    }
    // Row 7: exp lifetime.
    if mandate.exp.saturating_sub(mandate.issued_at) > scope.max_exp_seconds {
        return Err(DelegationRejectCode::ScopeExpiryTooLong);
    }
    Ok(())
}

fn mandate_has_wildcard_cap(mandate: &Mandate) -> bool {
    mandate.cap.iter().any(|c| {
        c.verb == "*"
            || c.resource_kind == "*"
            || c.resource_ref.as_deref().is_some_and(|r| r.contains('*'))
    })
}

// ---------------- executor entry point -------------------------------------

/// Harness-facing executor for a single delegation-scope vector.
pub fn execute(vector: &Vector) -> ValidationOutcome {
    let parsed: VectorInput = match serde_json::from_value(vector.input.clone()) {
        Ok(v) => v,
        Err(e) => {
            return ValidationOutcome::Fail {
                reason: format!("delegation vector {} deserialize: {e}", vector.id),
            };
        }
    };

    let result = verify(&parsed);
    match (vector.expected.outcome, result) {
        (Outcome::Accept, Ok(())) => ValidationOutcome::Pass,
        (Outcome::Accept, Err(code)) => ValidationOutcome::Fail {
            reason: format!("expected accept, got reject {code}"),
        },
        (Outcome::Reject, Ok(())) => {
            let want = vector.expected.reject_code.as_deref().unwrap_or("?");
            ValidationOutcome::Fail {
                reason: format!("expected reject {want}, got accept"),
            }
        }
        (Outcome::Reject, Err(code)) => {
            let want = vector.expected.reject_code.as_deref().unwrap_or("");
            if code.to_string() == want {
                ValidationOutcome::Pass
            } else {
                ValidationOutcome::Fail {
                    reason: format!("expected reject {want}, got {code}"),
                }
            }
        }
    }
}

// ---------------- tests -----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ExpectedOutcome;
    use serde_json::json;

    fn build_vector(input: serde_json::Value, expected: ExpectedOutcome) -> Vector {
        Vector {
            id: "ds-test".into(),
            category: "unit".into(),
            description: String::new(),
            input,
            expected,
            rationale: String::new(),
            redteam_refs: vec![],
            severity_if_failed: None,
        }
    }

    fn happy_single_link_input() -> serde_json::Value {
        json!({
            "delegation_chain": [{
                "parent_key": "K_cust_root_pk_TEST",
                "child_key": "K_cust_ops_pk_TEST",
                "child_role": "ops",
                "scope": {
                    "integrations": ["k8s"],
                    "max_tier_signable": 3,
                    "max_budget": {"actions": 100, "tokens": 50000},
                    "max_exp_seconds": 14400,
                    "allowed_verbs": ["patch"],
                    "allowed_resource_kinds": ["deployment"]
                },
                "valid_from": 1_700_000_000,
                "valid_until": 2_000_000_000,
                "signed_by": "K_cust_root_pk_TEST",
                "signature_valid": true
            }],
            "mandate": {
                "mandate_id": "m1",
                "integration_ref": "k8s",
                "cap": [{"verb": "patch", "resource_kind": "deployment", "tier": 3}],
                "budget": {"actions": 20, "tokens": 5000},
                "issued_at": 1_712_000_000_u64,
                "exp": 1_712_010_800_u64,
                "min_tariff_version": 5,
                "signer_key_hint": "K_cust_ops_pk_TEST",
                "signature_valid": true
            },
            "context": {
                "current_tariff_version": 5,
                "current_time": 1_712_000_000_u64,
                "revocation_list": []
            }
        })
    }

    #[test]
    fn reject_code_display_strings() {
        let pairs: &[(DelegationRejectCode, &str)] = &[
            (DelegationRejectCode::RoleHierarchyViolation, "role-hierarchy-violation"),
            (DelegationRejectCode::ChainDepthExceeded, "chain-depth-exceeded"),
            (DelegationRejectCode::SignatureInvalid, "signature-invalid"),
            (DelegationRejectCode::SignatureChainBroken, "signature-chain-broken"),
            (DelegationRejectCode::Expired, "expired"),
            (DelegationRejectCode::Revoked, "revoked"),
            (DelegationRejectCode::ParentDelegationRevoked, "parent-delegation-revoked"),
            (DelegationRejectCode::VersionSkew, "version-skew"),
            (DelegationRejectCode::ScopeIntegrationMismatch, "scope-integration-mismatch"),
            (DelegationRejectCode::ScopeIntegrationsWildcardForbidden, "scope-integrations-wildcard-forbidden"),
            (DelegationRejectCode::ScopeTierExceeded, "scope-tier-exceeded"),
            (DelegationRejectCode::ScopeVerbForbidden, "scope-verb-forbidden"),
            (DelegationRejectCode::ScopeResourceKindForbidden, "scope-resource-kind-forbidden"),
            (DelegationRejectCode::ScopeBudgetExceeded, "scope-budget-exceeded"),
            (DelegationRejectCode::ScopeExpiryTooLong, "scope-expiry-too-long"),
            (DelegationRejectCode::MandateEmptyCap, "mandate-empty-cap"),
            (DelegationRejectCode::NarrownessRuleViolation, "narrowness-rule-violation"),
        ];
        for (c, s) in pairs {
            assert_eq!(c.to_string(), *s);
        }
    }

    #[test]
    fn happy_path_accepts() {
        let v = build_vector(
            happy_single_link_input(),
            ExpectedOutcome {
                outcome: Outcome::Accept,
                reject_code: None,
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn integration_mismatch_rejects() {
        let mut input = happy_single_link_input();
        input["mandate"]["integration_ref"] = json!("other");
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("scope-integration-mismatch".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn empty_chain_rejects_as_chain_broken() {
        let mut input = happy_single_link_input();
        input["delegation_chain"] = json!([]);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-chain-broken".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn rogue_root_rejects_as_chain_broken() {
        let mut input = happy_single_link_input();
        input["delegation_chain"][0]["parent_key"] = json!("K_cust_ROGUE_pk");
        input["delegation_chain"][0]["signed_by"] = json!("K_cust_ROGUE_pk");
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-chain-broken".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn self_signed_link_rejects_as_chain_broken() {
        let mut input = happy_single_link_input();
        input["delegation_chain"][0]["signed_by"] = json!("K_cust_ops_pk_TEST");
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-chain-broken".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn mandate_signer_hint_mismatch_rejects_as_chain_broken() {
        let mut input = happy_single_link_input();
        input["mandate"]["signer_key_hint"] = json!("K_cust_DIFFERENT_pk");
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-chain-broken".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn mandate_signature_invalid_rejects_as_signature_invalid() {
        let mut input = happy_single_link_input();
        input["mandate"]["signature_valid"] = json!(false);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-invalid".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn link_signature_invalid_rejects_as_signature_invalid() {
        let mut input = happy_single_link_input();
        input["delegation_chain"][0]["signature_valid"] = json!(false);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-invalid".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn negative_budget_rejects_as_budget_exceeded() {
        let mut input = happy_single_link_input();
        input["mandate"]["budget"]["actions"] = json!(-1);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("scope-budget-exceeded".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn missing_scope_fields_reject_as_chain_broken() {
        let mut input = happy_single_link_input();
        // Strip all scope fields except integrations + max_tier_signable.
        input["delegation_chain"][0]["scope"] = json!({
            "integrations": ["k8s"],
            "max_tier_signable": 3
        });
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-chain-broken".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn mandate_id_revocation_rejects() {
        let mut input = happy_single_link_input();
        input["context"]["revocation_list"] = json!(["m1"]);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("revoked".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn parent_key_revocation_rejects() {
        let mut input = happy_single_link_input();
        input["context"]["revocation_list"] = json!(["K_cust_root_pk_TEST"]);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("revoked".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn duplicate_link_rejects_as_chain_broken() {
        let mut input = happy_single_link_input();
        let link = input["delegation_chain"][0].clone();
        input["delegation_chain"] = json!([link.clone(), link]);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("signature-chain-broken".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }

    #[test]
    fn resource_ref_wildcard_narrowness_violation() {
        let mut input = happy_single_link_input();
        input["delegation_chain"][0]["scope"]["allowed_verbs"] = json!(["*"]);
        input["delegation_chain"][0]["scope"]["allowed_resource_kinds"] = json!(["*"]);
        input["delegation_chain"][0]["scope"]["max_budget"]["actions"] = json!(10_000);
        input["mandate"]["cap"][0]["resource_ref"] = json!("ns/*/*");
        input["mandate"]["budget"]["actions"] = json!(100);
        let v = build_vector(
            input,
            ExpectedOutcome {
                outcome: Outcome::Reject,
                reject_code: Some("narrowness-rule-violation".into()),
                output: None,
            },
        );
        assert!(matches!(execute(&v), ValidationOutcome::Pass));
    }
}
