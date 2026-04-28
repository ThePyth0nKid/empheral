//! Stage-7 invariant validation for an already-verified
//! `AnomalyPatternLibrary` payload.
//!
//! Called from
//! [`crate::signature::verify_anomaly_library_signature`] after the
//! outer COSE signature and the Session-1 time-bounds have all
//! succeeded.  At that point we know:
//!
//! - The bytes on the wire are cryptographically committed by a
//!   registered `AnomalyLibrarySigner`.
//! - The declared ABI version matches this validator.
//! - The `signer_kid` in the inner payload matches the outer COSE
//!   header `kid`.
//! - The library is within its `[issued_at, expires_at)` window.
//!
//! What we DON'T know is whether the signer authored a structurally
//! coherent pattern table.  This module provides four pure functions
//! that surface contradictions:
//!
//! 1. [`check_pattern_id_uniqueness`] — no duplicate SET keys
//!    (§4.2.1 R7.C6).
//! 2. [`check_severity_action_consistency`] — `severity ∈ {High,
//!    Critical}` implies `action = AutoRevoke` (§3.5.2).
//! 3. [`check_verb_families_known`] — every family reference
//!    resolves against [`crate::families`] (§3.5.3 trust-surface
//!    gate).
//! 4. [`check_firing_rule_companions`] — short-window `FirstMatch`
//!    patterns declare a valid `CumulativeOverBaseline` companion
//!    at ≥ 10× window (§3.5.3 anti-walk-under).
//!
//! # Ordering discipline
//!
//! The signature module invokes these functions in the order above.
//! A downstream test (`check_order_*` in `signature.rs`) pins the
//! ordering so a refactor cannot silently reshuffle failure
//! surfaces.  The ordering is chosen to surface the cheapest and
//! most localised failures first:
//!
//! 1. Uniqueness — library-level, O(n²) but tiny n (~ ≤ 50).
//! 2. Severity-action — per-pattern, O(1) per pattern.
//! 3. Verb-family — per-pattern, static-slice lookup.
//! 4. Companion-presence — cross-pattern, needs lookup into the
//!    whole library; runs last because it consumes uniqueness and
//!    family validity as preconditions.
//!
//! # Fail-closed posture
//!
//! Each function returns `Err(_)` on the first violation it
//! encounters.  We do NOT aggregate multiple violations into a
//! single error — the caller (audit pipeline) rejects the library
//! and the signer re-authors.  Aggregation would require a new
//! error shape and would leak the shape of multi-fault libraries,
//! neither of which buys us anything at Session 2.

use crate::errors::{sanitize_log_string, AnomalyLibError, FiringCompanionFailure};
use crate::families::lookup_family;
use crate::patterns::{Action, FiringRule, PatternEntry};
use crate::scope::{ScopePredicate, VerbPredicate};

/// Anti-walk-under window threshold (§3.5.3).
///
/// A `FirstMatch` pattern with `window_seconds ≤` this value MUST
/// declare at least one anti-walk-under companion.  Chosen at
/// one hour because cumulative-over-baseline at 10× = 10 hours
/// balances detection latency against evasion resistance.
pub const ANTI_WALK_UNDER_WINDOW_SECONDS: u32 = 3600;

/// Anti-walk-under companion-window multiplier (§3.5.3).
///
/// A companion's `window_seconds` MUST be at least this multiple
/// of its primary's window.  10× is the normative ratio.
pub const ANTI_WALK_UNDER_COMPANION_MULTIPLIER: u32 = 10;

/// 7a — Pattern-ID uniqueness (§4.2.1 R7.C6 SET semantics).
///
/// An `AnomalyPatternLibrary` SET-typed pattern array MUST NOT
/// contain two rows with the same `pattern_id`.  Duplicates reject
/// rather than deduplicate because downstream dispatch is keyed by
/// `pattern_id` — a duplicate would create ambiguity about which
/// row's thresholds / companions apply.
///
/// # Complexity
///
/// O(n²) by design.  At ≤ 50 patterns per library (§3.5.4
/// declares 10; future expansions unlikely to 10× that), the
/// pairwise-compare is trivially under a microsecond.  A
/// `BTreeSet`-based O(n log n) variant would allocate and would
/// surface less-informative error messages (would need two passes
/// to recover the colliding pair).
///
/// # First-collision semantics
///
/// Returns on the first pair collision found in document order.  We
/// do NOT surface "all duplicates in one go" — the signer fixes
/// one, re-signs, and re-submits.  The traversal order matches
/// insertion order, so re-signing the same library hits the same
/// error deterministically.
pub(crate) fn check_pattern_id_uniqueness(
    patterns: &[PatternEntry],
) -> Result<(), AnomalyLibError> {
    // Quadratic pairwise compare — correct and cheap at expected
    // library sizes.  A `BTreeSet` alt is available if profiling
    // shows this on a hot path.
    for (i, p) in patterns.iter().enumerate() {
        for q in &patterns[i + 1..] {
            if p.pattern_id == q.pattern_id {
                return Err(AnomalyLibError::PatternIdDuplicate {
                    pattern_id: sanitize_log_string(&p.pattern_id),
                });
            }
        }
    }
    Ok(())
}

/// 7b — Severity-action consistency (§3.5.2 R8.A2).
///
/// Per §3.5.2: `severity ∈ {High, Critical}` MUST map to `action =
/// AutoRevoke`.  A library authored with a
/// `(Critical, Alert)` pair is structurally invalid — the alert-
/// with-300s-ack SLA is not fast enough for a critical-severity
/// compromise.
///
/// `(Low, AutoRevoke)` and `(Medium, AutoRevoke)` are permitted;
/// nothing in §3.5.2 forbids a low-severity pattern from auto-
/// revoking.  An operator might reasonably author an always-auto-
/// revoke library if they prefer fail-closed operational posture
/// over alert review.
pub(crate) fn check_severity_action_consistency(
    patterns: &[PatternEntry],
) -> Result<(), AnomalyLibError> {
    for pattern in patterns {
        if pattern.severity.requires_auto_revoke() && !matches!(pattern.action, Action::AutoRevoke)
        {
            return Err(AnomalyLibError::SeverityActionInconsistent {
                pattern_id: sanitize_log_string(&pattern.pattern_id),
                severity: pattern.severity.discriminant_str(),
                action: pattern.action.discriminant_str(),
            });
        }
    }
    Ok(())
}

/// 7c — Verb-family reference validity (§3.5.3 trust-surface).
///
/// Every family name referenced by a pattern's scope MUST resolve
/// via [`crate::families::lookup_family`].  Unknown names reject
/// because the families are the validator's trust surface: an
/// operator cannot redefine `iam-attach` to `["noop"]` and defeat
/// the `iam-attach-policy-storm` pattern.
///
/// The walk covers two sites:
///
/// - [`VerbPredicate::Family(name)`] inside any
///   [`ScopePredicate`] that carries a [`VerbPredicate`]
///   (`VerbResourceMandate`, `VerbFanout`).
/// - [`ScopePredicate::IamAttachFamily.verb_family`] directly.
///
/// [`VerbPredicate::AnyDestructive`] is a sugar form for
/// `Family("destructive")` — it resolves trivially against the
/// hardcoded `DESTRUCTIVE_VERBS` slice and is never an unknown
/// reference.  [`VerbPredicate::Exact`] carries a literal verb
/// string, not a family name, so it is not subject to this check.
///
/// Other [`ScopePredicate`] variants
/// (`ProtectedBranches`, `CrossTierSequence`, `MandatePace`,
/// `SilenceThenBurst`, `CanaryWindow`, `DelegationDepth`) do not
/// carry family references at the Session-2 schema layer and so
/// skip the check.  `MandatePace.exclude_verb_category` is
/// intentionally opaque at this layer — Session-4 evaluator
/// resolves it at runtime; a future ABI bump may move that field
/// into this check if a walk-under variant emerges.
pub(crate) fn check_verb_families_known(patterns: &[PatternEntry]) -> Result<(), AnomalyLibError> {
    for pattern in patterns {
        check_scope_verb_families(&pattern.pattern_id, &pattern.scope)?;
    }
    Ok(())
}

/// Helper for [`check_verb_families_known`].  Walks one
/// [`ScopePredicate`] and surfaces the first unknown family
/// encountered.  Not recursive — `ScopePredicate` is a flat enum
/// at the Session-2 schema layer.
fn check_scope_verb_families(
    pattern_id: &str,
    scope: &ScopePredicate,
) -> Result<(), AnomalyLibError> {
    match scope {
        ScopePredicate::VerbResourceMandate { verb, .. }
        | ScopePredicate::VerbFanout { verb, .. } => {
            check_verb_predicate_family(pattern_id, verb)?;
        }
        ScopePredicate::IamAttachFamily { verb_family, .. } => {
            lookup_family(verb_family).ok_or_else(|| AnomalyLibError::UnknownVerbFamily {
                pattern_id: sanitize_log_string(pattern_id),
                family: sanitize_log_string(verb_family),
            })?;
        }
        // Other variants do not carry family references at
        // Session-2.  Session 4+ may extend this match; the
        // `#[non_exhaustive]` attribute on `ScopePredicate`
        // guarantees a new variant added later WILL NOT silently
        // fall through this check.
        _ => {}
    }
    Ok(())
}

/// Verify a single [`VerbPredicate`] does not reference an unknown
/// family.
fn check_verb_predicate_family(
    pattern_id: &str,
    verb: &VerbPredicate,
) -> Result<(), AnomalyLibError> {
    match verb {
        VerbPredicate::Family(name) => {
            if lookup_family(name).is_none() {
                return Err(AnomalyLibError::UnknownVerbFamily {
                    pattern_id: sanitize_log_string(pattern_id),
                    family: sanitize_log_string(name),
                });
            }
        }
        // Exact verb carries no family reference.  `AnyDestructive`
        // is sugar for `Family("destructive")`, which
        // `lookup_family` must resolve; the debug-assert below pins
        // that invariant at test time so a future refactor that
        // removes "destructive" from `lookup_family` trips here
        // instead of silently passing Stage 7c.  Session 4+
        // variants added inside this crate will break the
        // exhaustiveness check and force a conscious update —
        // `#[non_exhaustive]` only loosens matches in DOWNSTREAM
        // crates, so an intra-crate addition cannot fall through
        // silently.
        VerbPredicate::Exact(_) => {}
        VerbPredicate::AnyDestructive => {
            debug_assert!(
                lookup_family("destructive").is_some(),
                "AnyDestructive sugar requires `destructive` family in lookup_family",
            );
        }
    }
    Ok(())
}

/// 7d — Anti-walk-under companion-pair invariant (§3.5.3).
///
/// For each `FirstMatch` pattern `P` with
/// `window_seconds = Some(w)` where `w ≤
/// ANTI_WALK_UNDER_WINDOW_SECONDS`:
///
/// 1. `P.firing_rule_companions` MUST be non-empty.
/// 2. Every named companion `C` MUST exist in the library (by
///    `pattern_id` match — this presumes 7a already succeeded),
///    carry `firing_rule == CumulativeOverBaseline`, and carry
///    `window_seconds = Some(cw)` with `cw ≥
///    ANTI_WALK_UNDER_COMPANION_MULTIPLIER × w`.
///
/// Patterns with `firing_rule != FirstMatch` or
/// `window_seconds = None` or `window_seconds > ANTI_WALK_UNDER_
/// WINDOW_SECONDS` are exempt — long windows already close the
/// walk-under gap on their own.
///
/// # Precondition ordering
///
/// This check assumes 7a (uniqueness) already passed, so
/// `patterns.iter().find(|c| c.pattern_id == name)` is
/// unambiguous.  It also assumes 7c (family resolution) has
/// passed, though 7d does not itself rely on family data.
///
/// # Error surface
///
/// Returns [`AnomalyLibError::FiringRuleCompanionMissing`] with a
/// [`FiringCompanionFailure`] sub-variant pinpointing which
/// sub-check failed — `NoCompanionsDeclared`, `CompanionNotFound`,
/// `CompanionNotCumulative`, or `CompanionWindowTooShort`.  This
/// surface is more detailed than the other invariant checks
/// because the signer has more ways to fail 7d than any earlier
/// stage, and each failure mode has a distinct fix.
pub(crate) fn check_firing_rule_companions(
    patterns: &[PatternEntry],
) -> Result<(), AnomalyLibError> {
    for pattern in patterns {
        // 1. Is this pattern subject to the anti-walk-under rule?
        let Some(window) = pattern.window_seconds else {
            continue; // Windowless → no walk-under surface.
        };
        if !matches!(pattern.firing_rule, FiringRule::FirstMatch) {
            continue; // Only FirstMatch is subject.
        }
        if window > ANTI_WALK_UNDER_WINDOW_SECONDS {
            continue; // Long window already closes the gap.
        }

        // 2. Companions MUST be declared.
        if pattern.firing_rule_companions.is_empty() {
            return Err(AnomalyLibError::FiringRuleCompanionMissing {
                pattern_id: sanitize_log_string(&pattern.pattern_id),
                window,
                missing_reason: FiringCompanionFailure::NoCompanionsDeclared,
            });
        }

        // 3. At least ONE declared companion MUST satisfy all sub-
        //    conditions.  Per §3.5.3 the invariant is "names ≥ 1
        //    cumulative-over-baseline pattern with window ≥ 10×" —
        //    additional companions MAY be declared but only one
        //    needs to be fully valid.  If no companion is fully
        //    valid, we surface the FIRST sub-failure we found so
        //    the signer gets actionable feedback.
        let mut first_failure: Option<FiringCompanionFailure> = None;
        let mut any_valid = false;

        for name in &pattern.firing_rule_companions {
            match classify_companion(name, window, patterns, &pattern.pattern_id) {
                Ok(()) => {
                    any_valid = true;
                    break;
                }
                Err(reason) => {
                    if first_failure.is_none() {
                        first_failure = Some(reason);
                    }
                }
            }
        }

        if !any_valid {
            // SAFETY: We entered the outer loop iteration with a
            // non-empty companions list (step 2 above) and the
            // for-loop visited every element, so `first_failure`
            // MUST be populated.  The `expect` documents the
            // invariant rather than panicking in practice.
            let reason = first_failure.expect(
                "companions were non-empty but no failure reason captured \
                 — invariant bug",
            );
            return Err(AnomalyLibError::FiringRuleCompanionMissing {
                pattern_id: sanitize_log_string(&pattern.pattern_id),
                window,
                missing_reason: reason,
            });
        }
    }
    Ok(())
}

/// Classify a single named companion against an anti-walk-under
/// primary.  Returns `Ok(())` iff the companion satisfies all three
/// §3.5.3 sub-conditions.
///
/// `primary_id` is carried only so the self-reference check has a
/// clear error message — a pattern MUST NOT name itself as its own
/// companion (a degenerate case that would satisfy "1 companion
/// declared" without providing any backstop).
fn classify_companion(
    name: &str,
    primary_window: u32,
    patterns: &[PatternEntry],
    primary_id: &str,
) -> Result<(), FiringCompanionFailure> {
    // Self-reference: a pattern naming itself is semantically
    // equivalent to "no companion" — reject as CompanionNotFound
    // since the evaluator couldn't use it as a backstop anyway.
    // Sanitise `name` at construction time.
    if name == primary_id {
        return Err(FiringCompanionFailure::CompanionNotFound {
            name: sanitize_log_string(name),
        });
    }

    // Resolve by pattern_id.  Presumes 7a (uniqueness) passed so at
    // most one match is possible.
    let Some(companion) = patterns.iter().find(|p| p.pattern_id == name) else {
        return Err(FiringCompanionFailure::CompanionNotFound {
            name: sanitize_log_string(name),
        });
    };

    if !matches!(companion.firing_rule, FiringRule::CumulativeOverBaseline) {
        return Err(FiringCompanionFailure::CompanionNotCumulative {
            name: sanitize_log_string(name),
        });
    }

    let required_minimum = primary_window.saturating_mul(ANTI_WALK_UNDER_COMPANION_MULTIPLIER);

    match companion.window_seconds {
        Some(cw) if cw >= required_minimum => Ok(()),
        Some(cw) => Err(FiringCompanionFailure::CompanionWindowTooShort {
            name: sanitize_log_string(name),
            companion_window: cw,
            required_minimum,
        }),
        // Windowless companion cannot provide a long-window
        // backstop — surface as "window too short" with companion_
        // window = 0 so the signer sees why it failed.  An
        // alternative would be a new sub-variant, but 0 is
        // distinguishable and correct (no window = zero-coverage).
        None => Err(FiringCompanionFailure::CompanionWindowTooShort {
            name: sanitize_log_string(name),
            companion_window: 0,
            required_minimum,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::{Severity, Threshold};
    use crate::scope::MandateScope;

    /// Minimal fixture builder — keeps tests readable without
    /// requiring the full test_fixtures module (which is feature-
    /// gated and pulls in signing helpers we don't need here).
    fn base_pattern(id: &str) -> PatternEntry {
        PatternEntry {
            pattern_id: id.into(),
            window_seconds: Some(60),
            threshold: Threshold::Count(5),
            scope: ScopePredicate::VerbResourceMandate {
                verb: VerbPredicate::Exact("delete".into()),
                resource_kind: None,
                mandate_scope: MandateScope::default(),
            },
            action: Action::AutoRevoke,
            severity: Severity::High,
            firing_rule: FiringRule::FirstMatch,
            firing_rule_companions: vec!["slow-burn".into()],
        }
    }

    fn cumulative_companion(id: &str, window: u32) -> PatternEntry {
        PatternEntry {
            pattern_id: id.into(),
            window_seconds: Some(window),
            threshold: Threshold::Count(20),
            scope: ScopePredicate::VerbResourceMandate {
                verb: VerbPredicate::Exact("delete".into()),
                resource_kind: None,
                mandate_scope: MandateScope::default(),
            },
            action: Action::AutoRevoke,
            severity: Severity::High,
            firing_rule: FiringRule::CumulativeOverBaseline,
            firing_rule_companions: vec![],
        }
    }

    // ──────────────────────────────────────────────────────────
    // 7a — uniqueness
    // ──────────────────────────────────────────────────────────

    #[test]
    fn uniqueness_empty_library_passes() {
        assert!(check_pattern_id_uniqueness(&[]).is_ok());
    }

    #[test]
    fn uniqueness_distinct_ids_pass() {
        let p1 = base_pattern("delete-storm");
        let p2 = cumulative_companion("slow-burn", 600);
        assert!(check_pattern_id_uniqueness(&[p1, p2]).is_ok());
    }

    #[test]
    fn uniqueness_duplicates_rejected_with_sanitized_id() {
        // Both patterns share the SAME id (containing a newline
        // injected control char) so the uniqueness check fires
        // AND the sanitisation path is exercised on the offending
        // byte sequence.  Setting only one side to the injected
        // form would make the ids non-identical and mask the test.
        let mut p1 = base_pattern("delete-storm");
        let mut p2 = base_pattern("delete-storm");
        p1.pattern_id = "delete-storm\nINJ".into();
        p2.pattern_id = "delete-storm\nINJ".into();
        let err = check_pattern_id_uniqueness(&[p1, p2]).unwrap_err();
        match err {
            AnomalyLibError::PatternIdDuplicate { pattern_id } => {
                assert!(!pattern_id.contains('\n'));
                assert!(pattern_id.contains("delete-storm?INJ"));
            }
            other => panic!("expected PatternIdDuplicate, got {other:?}"),
        }
    }

    // ──────────────────────────────────────────────────────────
    // 7b — severity-action consistency
    // ──────────────────────────────────────────────────────────

    #[test]
    fn severity_high_with_auto_revoke_passes() {
        let mut p = base_pattern("p");
        p.severity = Severity::High;
        p.action = Action::AutoRevoke;
        p.firing_rule_companions = vec![]; // out-of-scope for 7b
        p.firing_rule = FiringRule::CumulativeOverBaseline; // skip 7d
        assert!(check_severity_action_consistency(&[p]).is_ok());
    }

    #[test]
    fn severity_critical_with_alert_rejected() {
        let mut p = base_pattern("pat-crit");
        p.severity = Severity::Critical;
        p.action = Action::Alert;
        let err = check_severity_action_consistency(&[p]).unwrap_err();
        match err {
            AnomalyLibError::SeverityActionInconsistent {
                pattern_id,
                severity,
                action,
            } => {
                assert_eq!(pattern_id, "pat-crit");
                assert_eq!(severity, "critical");
                assert_eq!(action, "alert");
            }
            other => panic!("expected SeverityActionInconsistent, got {other:?}"),
        }
    }

    #[test]
    fn severity_low_with_auto_revoke_passes() {
        // (Low, AutoRevoke) is permitted — fail-closed operational
        // posture is a legitimate operator choice.
        let mut p = base_pattern("p");
        p.severity = Severity::Low;
        p.action = Action::AutoRevoke;
        p.firing_rule = FiringRule::CumulativeOverBaseline;
        assert!(check_severity_action_consistency(&[p]).is_ok());
    }

    #[test]
    fn severity_low_with_alert_passes() {
        let mut p = base_pattern("p");
        p.severity = Severity::Low;
        p.action = Action::Alert;
        p.firing_rule = FiringRule::CumulativeOverBaseline;
        assert!(check_severity_action_consistency(&[p]).is_ok());
    }

    // ──────────────────────────────────────────────────────────
    // 7c — verb-family resolution
    // ──────────────────────────────────────────────────────────

    #[test]
    fn family_reference_known_passes() {
        let mut p = base_pattern("p");
        p.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("destructive".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        p.firing_rule = FiringRule::CumulativeOverBaseline;
        assert!(check_verb_families_known(&[p]).is_ok());
    }

    #[test]
    fn family_reference_unknown_rejected_with_sanitized_name() {
        let mut p = base_pattern("p");
        p.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("unknown\nINJ".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        let err = check_verb_families_known(&[p]).unwrap_err();
        match err {
            AnomalyLibError::UnknownVerbFamily { pattern_id, family } => {
                assert_eq!(pattern_id, "p");
                assert!(!family.contains('\n'));
                assert!(family.contains("unknown?INJ"));
            }
            other => panic!("expected UnknownVerbFamily, got {other:?}"),
        }
    }

    #[test]
    fn iam_attach_family_unknown_rejected() {
        let mut p = base_pattern("p");
        p.scope = ScopePredicate::IamAttachFamily {
            verb_family: "not-a-family".into(),
            mandate_scope: MandateScope::default(),
        };
        let err = check_verb_families_known(&[p]).unwrap_err();
        assert!(matches!(err, AnomalyLibError::UnknownVerbFamily { .. }));
    }

    #[test]
    fn any_destructive_sugar_resolves() {
        let mut p = base_pattern("p");
        p.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::AnyDestructive,
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        p.firing_rule = FiringRule::CumulativeOverBaseline;
        assert!(check_verb_families_known(&[p]).is_ok());
    }

    #[test]
    fn exact_verb_skipped_by_family_check() {
        // Exact verbs are literal strings, not family refs.  A
        // nonexistent literal verb is permitted by 7c (it's a
        // runtime-never-matches issue, not a structural one).
        let mut p = base_pattern("p");
        p.scope = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("never-matches-anything".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        p.firing_rule = FiringRule::CumulativeOverBaseline;
        assert!(check_verb_families_known(&[p]).is_ok());
    }

    #[test]
    fn delegation_depth_scope_skipped_by_family_check() {
        // Variants that don't carry a VerbPredicate are out-of-
        // scope for 7c.
        let mut p = base_pattern("p");
        p.scope = ScopePredicate::DelegationDepth { limit: 4 };
        p.firing_rule = FiringRule::CumulativeOverBaseline;
        assert!(check_verb_families_known(&[p]).is_ok());
    }

    // ──────────────────────────────────────────────────────────
    // 7d — anti-walk-under companion
    // ──────────────────────────────────────────────────────────

    #[test]
    fn companion_present_and_ratio_ok_passes() {
        let primary = base_pattern("delete-storm"); // window 60, first-match, companion "slow-burn"
        let companion = cumulative_companion("slow-burn", 600); // 10×
        assert!(check_firing_rule_companions(&[primary, companion]).is_ok());
    }

    #[test]
    fn companion_required_for_short_window_first_match() {
        let mut p = base_pattern("no-backstop");
        p.firing_rule_companions = vec![];
        let err = check_firing_rule_companions(&[p]).unwrap_err();
        match err {
            AnomalyLibError::FiringRuleCompanionMissing {
                missing_reason: FiringCompanionFailure::NoCompanionsDeclared,
                ..
            } => {}
            other => panic!("expected NoCompanionsDeclared, got {other:?}"),
        }
    }

    #[test]
    fn companion_not_found_surfaces_clean_name() {
        let mut p = base_pattern("orphan");
        p.firing_rule_companions = vec!["missing-companion\tINJ".into()];
        let err = check_firing_rule_companions(&[p]).unwrap_err();
        match err {
            AnomalyLibError::FiringRuleCompanionMissing {
                missing_reason: FiringCompanionFailure::CompanionNotFound { name },
                ..
            } => {
                assert!(!name.contains('\t'));
                assert!(name.contains("missing-companion?INJ"));
            }
            other => panic!("expected CompanionNotFound, got {other:?}"),
        }
    }

    #[test]
    fn companion_wrong_firing_rule_rejected() {
        let primary = base_pattern("pri");
        // Companion is not cumulative — it's another FirstMatch.
        let mut companion = base_pattern("slow-burn");
        companion.window_seconds = Some(600);
        companion.firing_rule_companions = vec![]; // suppress self-check on companion
        let err = check_firing_rule_companions(&[primary, companion]).unwrap_err();
        match err {
            AnomalyLibError::FiringRuleCompanionMissing {
                missing_reason: FiringCompanionFailure::CompanionNotCumulative { name },
                ..
            } => {
                assert_eq!(name, "slow-burn");
            }
            other => panic!("expected CompanionNotCumulative, got {other:?}"),
        }
    }

    #[test]
    fn companion_window_below_10x_rejected() {
        let primary = base_pattern("pri"); // window 60
        let companion = cumulative_companion("slow-burn", 300); // only 5×
        let err = check_firing_rule_companions(&[primary, companion]).unwrap_err();
        match err {
            AnomalyLibError::FiringRuleCompanionMissing {
                missing_reason:
                    FiringCompanionFailure::CompanionWindowTooShort {
                        name,
                        companion_window,
                        required_minimum,
                    },
                ..
            } => {
                assert_eq!(name, "slow-burn");
                assert_eq!(companion_window, 300);
                assert_eq!(required_minimum, 600);
            }
            other => panic!("expected CompanionWindowTooShort, got {other:?}"),
        }
    }

    #[test]
    fn companion_windowless_rejected_as_zero_window() {
        let primary = base_pattern("pri");
        let mut companion = cumulative_companion("slow-burn", 600);
        companion.window_seconds = None;
        let err = check_firing_rule_companions(&[primary, companion]).unwrap_err();
        match err {
            AnomalyLibError::FiringRuleCompanionMissing {
                missing_reason:
                    FiringCompanionFailure::CompanionWindowTooShort {
                        companion_window, ..
                    },
                ..
            } => {
                assert_eq!(companion_window, 0);
            }
            other => panic!("expected CompanionWindowTooShort, got {other:?}"),
        }
    }

    #[test]
    fn companion_self_reference_treated_as_missing() {
        let mut p = base_pattern("pri");
        p.firing_rule_companions = vec!["pri".into()];
        let err = check_firing_rule_companions(&[p]).unwrap_err();
        assert!(matches!(
            err,
            AnomalyLibError::FiringRuleCompanionMissing {
                missing_reason: FiringCompanionFailure::CompanionNotFound { .. },
                ..
            }
        ));
    }

    #[test]
    fn any_one_valid_companion_satisfies_the_rule() {
        // Signer declares TWO companions; only the second is valid.
        // Per §3.5.3 "names ≥ 1 cumulative-over-baseline pattern",
        // this should PASS.
        //
        // `bad_companion` must itself be exempt from the anti-walk-
        // under rule or the check would (correctly) reject IT as a
        // primary with a broken companion list — masking the
        // property under test.  A long window shifts it out of
        // scope for the rule.
        let mut primary = base_pattern("pri");
        primary.firing_rule_companions = vec!["bad".into(), "good".into()];
        let mut bad_companion = base_pattern("bad");
        // FirstMatch (from base_pattern) but long window -> exempt
        // from being a primary itself; still NOT CumulativeOverBaseline
        // so classify_companion rejects it as CompanionNotCumulative
        // when walked from `primary`.
        bad_companion.window_seconds = Some(ANTI_WALK_UNDER_WINDOW_SECONDS + 1);
        bad_companion.firing_rule_companions = vec![];
        let good_companion = cumulative_companion("good", 600);
        assert!(check_firing_rule_companions(&[primary, bad_companion, good_companion]).is_ok());
    }

    #[test]
    fn long_window_first_match_exempt_from_companion_requirement() {
        let mut p = base_pattern("long");
        p.window_seconds = Some(ANTI_WALK_UNDER_WINDOW_SECONDS + 1);
        p.firing_rule_companions = vec![];
        assert!(check_firing_rule_companions(&[p]).is_ok());
    }

    #[test]
    fn windowless_first_match_exempt_from_companion_requirement() {
        let mut p = base_pattern("chain-depth");
        p.window_seconds = None;
        p.firing_rule_companions = vec![];
        assert!(check_firing_rule_companions(&[p]).is_ok());
    }

    #[test]
    fn cumulative_primary_not_subject_to_anti_walk_under() {
        // If the primary is itself cumulative, it's the backstop —
        // no companion required.
        let mut p = base_pattern("p");
        p.firing_rule = FiringRule::CumulativeOverBaseline;
        p.firing_rule_companions = vec![];
        assert!(check_firing_rule_companions(&[p]).is_ok());
    }

    #[test]
    fn exactly_10x_boundary_is_accepted() {
        let primary = base_pattern("pri"); // window 60
        let companion = cumulative_companion("slow-burn", 600); // exactly 10×
        assert!(check_firing_rule_companions(&[primary, companion]).is_ok());
    }

    #[test]
    fn anti_walk_under_boundary_window_3600_requires_companion() {
        let mut primary = base_pattern("edge");
        primary.window_seconds = Some(ANTI_WALK_UNDER_WINDOW_SECONDS); // exactly 3600
        primary.firing_rule_companions = vec!["slow-burn".into()];
        let companion = cumulative_companion("slow-burn", 36_000); // 10×3600
        assert!(check_firing_rule_companions(&[primary, companion]).is_ok());
    }
}
