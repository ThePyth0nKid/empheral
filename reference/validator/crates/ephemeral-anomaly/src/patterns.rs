//! Value types for a single anomaly-library pattern entry.
//!
//! A [`PatternEntry`] is one SET-typed row of
//! `AnomalyLibraryPayload.patterns` (§4.2.1 R7.C6, keyed by
//! `pattern_id`).  The normative §3.5.4 MINIMUM library carries ten
//! such rows plus their anti-walk-under companions.
//!
//! # Enum-variant stability
//!
//! Every public enum in this module is `#[non_exhaustive]` so Session
//! 4+ can add firing rules or threshold shapes without breaking
//! downstream exhaustive matches.  Additive variant additions are
//! backward-compatible on the wire because ciborium's externally-
//! tagged encoding (`{"first_match": {...}}`-style) degrades cleanly
//! when a decoder sees an unknown tag — an older decoder would surface
//! an envelope-shape mismatch via
//! [`crate::errors::AnomalyLibError::PayloadDecodeFailed`], preserving
//! fail-closed semantics.
//!
//! # `Serialize` gating
//!
//! All types derive `Deserialize` unconditionally but `Serialize` only
//! under `#[cfg(any(test, feature = "test_fixtures"))]`.  Production
//! builds of `ephemeral-anomaly` never re-encode a library envelope
//! they received over the wire — only the signer does, and the signer
//! uses the `test_fixtures` feature (in tests) or a dedicated signing
//! tool (`prod-vector-signer`) which enables the feature explicitly.
//! This keeps the prod rlib surface minimal; the `prod-symbol-probe`
//! feature-leak guard enforces it (see
//! `tools/prod-symbol-probe/tests/no_leak.rs`).

use serde::Deserialize;

#[cfg(any(test, feature = "test_fixtures"))]
use serde::Serialize;

use crate::scope::ScopePredicate;

/// A single pattern row from `AnomalyLibraryPayload.patterns`.
///
/// Pattern rows are keyed by `pattern_id` under SET semantics
/// (§4.2.1 R7.C6).  Duplicates reject at verification time via
/// [`crate::invariants::check_pattern_id_uniqueness`]; relative
/// ordering inside the decoded `Vec` is therefore information only.
///
/// # Field semantics
///
/// - `pattern_id` — SET key.  Human-readable identifier, sanitised on
///   log/display via [`crate::errors::sanitize_log_string`].  Session-
///   2 does not cap `pattern_id` length explicitly; the 128 KiB outer
///   envelope cap and 256-byte `signer_kid`/`library_id` cap are the
///   only structural bounds, plus the 64-char convention adopted in
///   the §3.5.4 fixture library.
/// - `window_seconds` — sliding-window length for the firing rule in
///   seconds.  Optional because a few MINIMUM patterns
///   (`unusual-delegation-depth`) are windowless — they fire on a
///   static property of the event, not a temporal rate.  Anti-walk-
///   under (§3.5.3) only applies when `window_seconds` is `Some(_)`.
/// - `threshold` — firing threshold shape.  See [`Threshold`].
/// - `scope` — filter predicate selecting which events are candidates
///   for this pattern's counter.  See [`ScopePredicate`].
/// - `action` — audit-pipeline response on firing.  See [`Action`].
/// - `severity` — severity grading that gates the severity-action
///   invariant (§3.5.2).  See [`Severity`].
/// - `firing_rule` — evaluation mode for counter-against-threshold.
///   See [`FiringRule`].
/// - `firing_rule_companions` — ordered list of `pattern_id` strings
///   referencing longer-window cumulative-over-baseline companions.
///   Required on short-window (`≤ 3600s`) `FirstMatch` patterns per
///   §3.5.3 anti-walk-under.  Defaulted to empty so long-window
///   patterns can omit the field on the wire.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct PatternEntry {
    /// Stable SET key for this pattern.
    pub pattern_id: String,
    /// Sliding-window length in seconds, or `None` for windowless
    /// patterns (`unusual-delegation-depth` in §3.5.4).
    #[serde(default)]
    pub window_seconds: Option<u32>,
    /// Firing-threshold shape.  Semantics depend on `firing_rule`.
    pub threshold: Threshold,
    /// Scope predicate selecting candidate events.
    pub scope: ScopePredicate,
    /// Action applied on firing.
    pub action: Action,
    /// Severity grade.  Interacts with `action` via §3.5.2.
    pub severity: Severity,
    /// Firing-rule evaluation mode.
    pub firing_rule: FiringRule,
    /// `pattern_id` references of anti-walk-under companions
    /// (§3.5.3).  Required on short-window `FirstMatch`; empty
    /// otherwise.
    #[serde(default)]
    pub firing_rule_companions: Vec<String>,
}

/// Shape of a pattern's firing threshold.
///
/// Each variant pairs with one or more [`FiringRule`] variants at the
/// evaluator layer (Session 4+).  At the Session-2 schema layer the
/// variants are opaque — they travel from signer to verifier without
/// semantic inspection beyond structural deserialization.
///
/// # Wire form
///
/// Serializes as an externally-tagged enum (`{"count": 5}`) under
/// ciborium's default treatment.  The `rename_all = "snake_case"`
/// attribute makes the tag names match the spec's identifier
/// convention (`count`, not `Count`).
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Threshold {
    /// Plain event count within the sliding window (e.g.
    /// `delete-storm` fires at 5 deletes in 60s).
    Count(u32),
    /// Count of *distinct* field values within the window (e.g.
    /// `fanout-distinct-resources` fires at 10 distinct resource
    /// references).
    DistinctCount(u32),
    /// Count of completed sequence matches of the scope's sequence
    /// template (e.g. `cross-tier-escalation` fires on 1 sequence).
    Sequence(u32),
    /// Minimum observed delegation-chain depth triggering firing
    /// (e.g. `unusual-delegation-depth` fires at depth > 3).  Uses
    /// `u8` because R7.D3 hard-caps chain depth at 4.
    ChainDepth(u8),
}

/// Audit-pipeline response applied on pattern firing.
///
/// Only two variants are normative per §3.5.2 — the taxonomy is
/// intentionally narrow.  `Alert` escalates to revoke after a 300s
/// operator-ack SLA; `AutoRevoke` pushes revocation within the 5-30s
/// SLA and emits `AnomalyDetected`.
///
/// The severity-action consistency invariant (§3.5.2) forbids
/// `(severity ∈ {High, Critical}, action = Alert)` — that pair
/// rejects at Stage 7b via
/// [`crate::errors::AnomalyLibError::SeverityActionInconsistent`].
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Action {
    /// Emit an alert and wait up to 300s for operator
    /// acknowledgment; auto-escalate to revocation on SLA elapse.
    /// Permitted for `severity ∈ {Low, Medium}` only.
    Alert,
    /// Push revocation within the 5-30s SLA.  Required when
    /// `severity ∈ {High, Critical}`.
    AutoRevoke,
}

impl Action {
    /// Stable discriminant suitable for `&'static str` error fields.
    ///
    /// Matches the `kebab-case` wire form so logs stay consistent
    /// between deserialized enum values and error messages.
    pub(crate) const fn discriminant_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::AutoRevoke => "auto-revoke",
        }
    }
}

/// Severity grade of a pattern firing.
///
/// The grade drives the §3.5.2 severity-action invariant and Session
/// 6's 72h-expiry-grace behaviour (expired libraries keep firing
/// `High`/`Critical` patterns but stop firing `Low`/`Medium`).
///
/// # Why `Copy`
///
/// Severity is a one-byte discriminant; `Copy` lets
/// [`Severity::requires_auto_revoke`] operate on `self` without
/// borrow noise at the invariant-check call sites.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    /// Low severity — may pair with either action.
    Low,
    /// Medium severity — may pair with either action.
    Medium,
    /// High severity — MUST pair with [`Action::AutoRevoke`].
    High,
    /// Critical severity — MUST pair with [`Action::AutoRevoke`].
    Critical,
}

impl Severity {
    /// Returns `true` iff this severity MUST imply auto-revoke per
    /// §3.5.2.  `const fn` so it can participate in compile-time
    /// checks (e.g. `#[cfg]`-gated test assertions) and the
    /// invariant checker can call it from a non-allocating loop.
    pub const fn requires_auto_revoke(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }

    /// Stable discriminant for error-variant fields.  Matches the
    /// `snake_case` wire form.
    pub(crate) const fn discriminant_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Firing-rule taxonomy per §3.5.3.
///
/// Three variants, `#[non_exhaustive]`: Session 4+ may introduce
/// additional rules (e.g. `PercentilePace`) without breaking this
/// module's downstream matches.  The legacy "N-consecutive" firing
/// mode is NEVER valid (§3.5.3 explicit prohibition); we do not and
/// will not add a variant for it.
///
/// Window length and threshold live on [`PatternEntry`], not inside
/// the enum variants — every rule operates against the same
/// `(window_seconds, threshold)` tuple, differing only in the
/// evaluation procedure.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum FiringRule {
    /// Fire on the first event crossing the threshold within the
    /// sliding window.  Default choice for stormy-access patterns
    /// (`delete-storm`, `iam-attach-policy-storm`, etc.).  Short-
    /// window variants (`window_seconds ≤ 3600`) MUST declare
    /// anti-walk-under companions.
    FirstMatch,
    /// Fire on ordered event-sequence completion per the scope's
    /// sequence template.  Threshold counts completed sequences.
    SequenceMatch,
    /// Fire when rolling count ≥ threshold at any evaluation step.
    /// Backstop shape for short-window `FirstMatch` patterns per
    /// §3.5.3 anti-walk-under; the companion check requires a
    /// `CumulativeOverBaseline` counterpart at `≥ 10×` the first-
    /// match window.
    CumulativeOverBaseline,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_requires_auto_revoke_matches_spec() {
        // §3.5.2: only High and Critical require auto-revoke.
        assert!(!Severity::Low.requires_auto_revoke());
        assert!(!Severity::Medium.requires_auto_revoke());
        assert!(Severity::High.requires_auto_revoke());
        assert!(Severity::Critical.requires_auto_revoke());
    }

    #[test]
    fn severity_discriminant_str_matches_wire_form() {
        // The const str MUST match the serde rename_all = "snake_case"
        // projection so error messages line up with decoded values.
        assert_eq!(Severity::Low.discriminant_str(), "low");
        assert_eq!(Severity::Medium.discriminant_str(), "medium");
        assert_eq!(Severity::High.discriminant_str(), "high");
        assert_eq!(Severity::Critical.discriminant_str(), "critical");
    }

    #[test]
    fn action_discriminant_str_matches_wire_form() {
        // kebab-case projection: "auto-revoke" not "auto_revoke".
        assert_eq!(Action::Alert.discriminant_str(), "alert");
        assert_eq!(Action::AutoRevoke.discriminant_str(), "auto-revoke");
    }

    #[test]
    fn severity_roundtrips_through_ciborium() {
        // Lock wire-form stability: the signer emits snake_case
        // discriminants and the verifier decodes them byte-exactly.
        for sev in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let mut buf = Vec::new();
            ciborium::into_writer(&sev, &mut buf).unwrap();
            let back: Severity = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn action_roundtrips_through_ciborium() {
        for act in [Action::Alert, Action::AutoRevoke] {
            let mut buf = Vec::new();
            ciborium::into_writer(&act, &mut buf).unwrap();
            let back: Action = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(act, back);
        }
    }

    #[test]
    fn firing_rule_roundtrips_through_ciborium() {
        for rule in [
            FiringRule::FirstMatch,
            FiringRule::SequenceMatch,
            FiringRule::CumulativeOverBaseline,
        ] {
            let mut buf = Vec::new();
            ciborium::into_writer(&rule, &mut buf).unwrap();
            let back: FiringRule = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(rule, back);
        }
    }

    #[test]
    fn threshold_variants_roundtrip_through_ciborium() {
        let cases = [
            Threshold::Count(5),
            Threshold::DistinctCount(10),
            Threshold::Sequence(1),
            Threshold::ChainDepth(4),
        ];
        for thr in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&thr, &mut buf).unwrap();
            let back: Threshold = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(thr, back);
        }
    }

    #[test]
    fn unknown_severity_string_rejects_cleanly() {
        // ciborium surfaces unknown variant as a decode error, NOT
        // a silent fallback.  This anchors the invariant that
        // Session-4+ additive variants will surface as decode
        // failures in Session-2 validators.
        let mut buf = Vec::new();
        ciborium::into_writer(&"unknown-future-variant", &mut buf).unwrap();
        let decoded: Result<Severity, _> = ciborium::from_reader(buf.as_slice());
        assert!(decoded.is_err());
    }
}
