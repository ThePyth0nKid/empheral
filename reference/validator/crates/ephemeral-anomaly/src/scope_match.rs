//! Stateless per-event predicate matching for [`ScopePredicate`].
//!
//! Session 5-A deliverable (plan §14).  Given a
//! [`CanonicalizedEvent`] and a [`ScopePredicate`], returns `true` iff
//! the event participates in this pattern's counter bucket.  The
//! function is stateless — it does NOT evaluate firing thresholds,
//! sequences, or sliding-window semantics; those land in Session 5-B
//! inside the state machine.
//!
//! # Bucket-membership vs firing semantics
//!
//! [`ScopePredicate::matches`] answers "can this event contribute to
//! this pattern's counter?" — it is a *gate* at state-machine
//! ingestion time.  Patterns with stateful firing rules (e.g.
//! [`ScopePredicate::CrossTierSequence`], [`ScopePredicate::SilenceThenBurst`])
//! return `true` for any event that could ever contribute to a firing
//! trajectory; Session 5-B then walks the buffered events per pattern
//! to decide if a trajectory has completed.  Splitting membership
//! from firing keeps the hot-path matcher branchless-per-variant and
//! leaves all temporal reasoning in one place.
//!
//! # Session-5-A posture on unresolvable predicates
//!
//! Some variants reference data the Session-5-A
//! [`CanonicalizedEvent`] does not yet carry:
//!
//! - [`ScopePredicate::CanaryWindow`] — scoped by a shared PCR
//!   attestor set (§3.5.4 canary-window).  Session 5-A has no
//!   attestation surface.
//! - [`ScopePredicate::DelegationDepth`] — scoped by delegation-chain
//!   depth (§3.5.4 unusual-delegation-depth).  Session 5-A
//!   events do not carry chain depth.
//! - [`crate::scope::MandateScope`]'s `operator_id` dimension —
//!   Session 5-A events do not carry an `operator_id` field.
//!
//! The two predicate-level cases ([`ScopePredicate::CanaryWindow`],
//! [`ScopePredicate::DelegationDepth`]) return `false`
//! unconditionally: no event matches, no bucket accumulates, the
//! pattern cannot fire.  This is fail-closed by design — a future
//! session wiring up PCR attestation or delegation tracking will add
//! the relevant fields to [`CanonicalizedEvent`] under its
//! `#[non_exhaustive]` marker and flip these match arms over to real
//! predicates.  The contract pin
//! `canary_window_unconditional_false_at_session_5a` below surfaces
//! any silent regression.
//!
//! The `operator_id` dimension of [`MandateScope`] is treated as
//! forward-compat wildcard: a `Some(operator_id)` binding is ignored
//! at Session 5-A because the event stream carries no operator
//! attribution.  When Session 6+ adds `operator_id` to
//! [`CanonicalizedEvent`], this match arm extends to honour the
//! binding without a signature change.  The pin
//! `mandate_scope_operator_id_is_ignored_at_session_5a` documents the
//! current semantic.
//!
//! # Log-safety
//!
//! This module never logs.  Error surfaces for
//! pattern-library-invalid states (unknown family names, shape
//! violations) are caught at Stage 7 envelope verification; by the
//! time a [`ScopePredicate`] reaches this matcher, its family names
//! have already been vetted against [`crate::families::lookup_family`].
//! A defense-in-depth re-lookup here still returns `false` on a
//! hypothetical unknown family rather than panicking — see
//! `verb_predicate_family_unknown_is_false_as_defense_in_depth`.

use crate::event::CanonicalizedEvent;
use crate::families::lookup_family;
use crate::scope::{MandateScope, ScopePredicate, VerbPredicate};

impl VerbPredicate {
    /// Returns `true` iff `verb` satisfies this verb predicate.
    ///
    /// - [`VerbPredicate::Exact(s)`] → byte-eq against `s` (no
    ///   case-folding; canonicalisation happens upstream, see
    ///   [`crate::event`] module-doc).
    /// - [`VerbPredicate::Family(name)`] → `verb` ∈
    ///   [`lookup_family(name)`].  Unknown family names return
    ///   `false` (defense-in-depth; Stage-7c invariants already
    ///   reject libraries referencing unknown family names).
    /// - [`VerbPredicate::AnyDestructive`] → `verb` ∈
    ///   [`lookup_family("destructive")`].
    #[must_use]
    pub fn matches(&self, verb: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == verb,
            Self::Family(name) => family_contains(name.as_str(), verb),
            Self::AnyDestructive => family_contains("destructive", verb),
        }
    }
}

impl MandateScope {
    /// Returns `true` iff `event` satisfies this mandate-scope
    /// binding.
    ///
    /// - `mandate_id`: `Some(m)` → byte-eq against `event.mandate_id`;
    ///   `None` → wildcard.
    /// - `operator_id`: IGNORED at Session 5-A — the event stream
    ///   carries no operator attribution.  Session 6+ will add the
    ///   field and honour the binding without changing this API.
    /// - `integration_ref`: `Some(r)` → byte-eq against
    ///   `event.integration`; `None` → wildcard.
    ///
    /// All three dimensions `None` = fully-unbound wildcard that
    /// matches every event (§3.5.4 "any mandate" shapes like
    /// `unusual-delegation-depth`).
    #[must_use]
    pub fn matches_event(&self, event: &CanonicalizedEvent) -> bool {
        if let Some(m) = self.mandate_id.as_deref() {
            if m != event.mandate_id {
                return false;
            }
        }
        if let Some(r) = self.integration_ref.as_deref() {
            if r != event.integration {
                return false;
            }
        }
        // operator_id: Session 5-A forward-compat wildcard.  See
        // module-doc "Session-5-A posture on unresolvable predicates".
        true
    }
}

impl ScopePredicate {
    /// Returns `true` iff `event` is a bucket-membership candidate
    /// for this pattern's counter.
    ///
    /// Stateless; see module-doc for the membership-vs-firing split.
    ///
    /// # Variant semantics
    ///
    /// - [`Self::VerbResourceMandate`] — all three: verb predicate
    ///   matches, `resource_kind` matches (`Some(k)` byte-eq,
    ///   `None` wildcard), and mandate-scope matches.
    /// - [`Self::IamAttachFamily`] — `event.verb` is in the
    ///   `verb_family` slice and mandate-scope matches.
    /// - [`Self::ProtectedBranches`] — mandate-scope matches;
    ///   per-branch `protected_patterns` filtering lands at Session
    ///   5-B's evaluator (needs resource_ref globbing).
    /// - [`Self::CrossTierSequence`] — mandate-scope matches; the
    ///   tier-progression walk is stateful (Session 5-B).
    /// - [`Self::MandatePace`] — `event.tier >= tier_floor` and, if
    ///   `exclude_verb_category` is set, `event.verb` is NOT in the
    ///   excluded family.  An unknown excluded-family name is
    ///   conservatively treated as empty (no verbs excluded), which
    ///   mirrors Session 2 Stage-7c resolving family names at
    ///   verification time.
    /// - [`Self::SilenceThenBurst`] — system-wide temporal pattern
    ///   with no scope binding; every event is a membership
    ///   candidate.  Firing is evaluated by Session 5-B's temporal
    ///   walker.
    /// - [`Self::CanaryWindow`] — fail-closed `false` at Session 5-A
    ///   (no PCR attestation surface).
    /// - [`Self::DelegationDepth`] — fail-closed `false` at Session
    ///   5-A (events carry no delegation depth).
    /// - [`Self::VerbFanout`] — verb predicate matches and
    ///   mandate-scope matches.  Distinct-resource counting is
    ///   Session 5-B's state-machine work.
    #[must_use]
    pub fn matches(&self, event: &CanonicalizedEvent) -> bool {
        match self {
            Self::VerbResourceMandate {
                verb,
                resource_kind,
                mandate_scope,
            } => {
                if !verb.matches(&event.verb) {
                    return false;
                }
                if let Some(k) = resource_kind.as_deref() {
                    if k != event.resource_kind {
                        return false;
                    }
                }
                mandate_scope.matches_event(event)
            }
            Self::IamAttachFamily {
                verb_family,
                mandate_scope,
            } => {
                if !family_contains(verb_family.as_str(), &event.verb) {
                    return false;
                }
                mandate_scope.matches_event(event)
            }
            Self::ProtectedBranches { mandate_scope, .. }
            | Self::CrossTierSequence { mandate_scope, .. } => mandate_scope.matches_event(event),
            Self::MandatePace {
                tier_floor,
                exclude_verb_category,
            } => {
                if event.tier < *tier_floor {
                    return false;
                }
                if let Some(category) = exclude_verb_category.as_deref() {
                    if family_contains(category, &event.verb) {
                        return false;
                    }
                }
                true
            }
            Self::SilenceThenBurst { .. } => true,
            Self::CanaryWindow { .. } | Self::DelegationDepth { .. } => false,
            Self::VerbFanout {
                verb,
                mandate_scope,
            } => {
                if !verb.matches(&event.verb) {
                    return false;
                }
                mandate_scope.matches_event(event)
            }
        }
    }
}

/// Defense-in-depth family lookup.  Unknown names return `false`
/// (no match) rather than panicking; Stage-7c invariants already
/// reject libraries referencing unknown families at verification
/// time, so reaching this path at runtime implies either a Session-2
/// invariant-check bug or a freshly-added family name that Stage 7c
/// did not enumerate.
#[inline]
fn family_contains(family_name: &str, verb: &str) -> bool {
    match lookup_family(family_name) {
        Some(members) => members.contains(&verb),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Outcome;
    use crate::scope::{MandateScope, ScopePredicate, VerbPredicate};

    fn base_event() -> CanonicalizedEvent {
        CanonicalizedEvent {
            event_id: "e-1".into(),
            timestamp: 1_700_000_000,
            mandate_id: "m-42".into(),
            tier: 2,
            integration: "kubernetes".into(),
            verb: "delete".into(),
            resource_kind: "pod".into(),
            resource_ref: "ns/app/pod-7".into(),
            outcome: Outcome::Executed,
        }
    }

    // ------------ VerbPredicate --------------------------------------

    #[test]
    fn verb_predicate_exact_matches_byte_eq() {
        let vp = VerbPredicate::Exact("delete".into());
        assert!(vp.matches("delete"));
        assert!(!vp.matches("deletes"));
        assert!(!vp.matches("Delete"));
        assert!(!vp.matches(""));
    }

    #[test]
    fn verb_predicate_family_matches_registered_members() {
        let vp = VerbPredicate::Family("iam-attach".into());
        assert!(vp.matches("attachrolepolicy"));
        assert!(vp.matches("attachuserpolicy"));
        assert!(vp.matches("attachgrouppolicy"));
        assert!(!vp.matches("detachrolepolicy"));
        assert!(!vp.matches("delete"));
    }

    #[test]
    fn verb_predicate_family_unknown_is_false_as_defense_in_depth() {
        // Stage-7c invariants reject unknown family names at library
        // verification.  Reaching this matcher at runtime with an
        // unknown family name implies a verification-layer bug — the
        // matcher MUST NOT panic and MUST NOT match anything.
        let vp = VerbPredicate::Family("not-a-real-family".into());
        assert!(!vp.matches("delete"));
        assert!(!vp.matches("attachrolepolicy"));
        assert!(!vp.matches(""));
    }

    #[test]
    fn verb_predicate_any_destructive_matches_destructive_family() {
        let vp = VerbPredicate::AnyDestructive;
        assert!(vp.matches("delete"));
        assert!(vp.matches("destroy"));
        assert!(vp.matches("drop"));
        assert!(vp.matches("truncate"));
        assert!(vp.matches("rotate"));
        assert!(!vp.matches("get"));
        assert!(!vp.matches("attachrolepolicy"));
    }

    // ------------ MandateScope ---------------------------------------

    #[test]
    fn mandate_scope_fully_unbound_matches_any_event() {
        let ms = MandateScope::default();
        let e1 = base_event();
        let mut e2 = base_event();
        e2.mandate_id = "m-99".into();
        e2.integration = "aws-iam".into();
        assert!(ms.matches_event(&e1));
        assert!(ms.matches_event(&e2));
    }

    #[test]
    fn mandate_scope_mandate_id_binds_byte_exact() {
        let ms = MandateScope {
            mandate_id: Some("m-42".into()),
            ..Default::default()
        };
        let e1 = base_event();
        let mut e2 = base_event();
        e2.mandate_id = "m-99".into();
        assert!(ms.matches_event(&e1));
        assert!(!ms.matches_event(&e2));
    }

    #[test]
    fn mandate_scope_integration_ref_binds_against_event_integration_field() {
        // MandateScope uses `integration_ref` as the field name;
        // CanonicalizedEvent uses `integration`.  Pin that the
        // matcher does the cross-name comparison correctly.
        let ms = MandateScope {
            integration_ref: Some("kubernetes".into()),
            ..Default::default()
        };
        let e1 = base_event();
        let mut e2 = base_event();
        e2.integration = "aws-iam".into();
        assert!(ms.matches_event(&e1));
        assert!(!ms.matches_event(&e2));
    }

    #[test]
    fn mandate_scope_operator_id_is_ignored_at_session_5a() {
        // Session 5-A forward-compat posture: a Some(operator_id)
        // binding is silently ignored because CanonicalizedEvent
        // carries no operator_id field.  This pin surfaces any
        // future change — Session 6+ must EITHER add operator_id to
        // the event OR explicitly choose to fail-closed on this
        // binding.
        let ms = MandateScope {
            operator_id: Some("op-any-value".into()),
            ..Default::default()
        };
        let e = base_event();
        assert!(ms.matches_event(&e));
    }

    #[test]
    fn mandate_scope_all_dimensions_bound_and_matching_is_true() {
        let ms = MandateScope {
            mandate_id: Some("m-42".into()),
            operator_id: Some("op-whatever".into()),
            integration_ref: Some("kubernetes".into()),
        };
        let e = base_event();
        assert!(ms.matches_event(&e));
    }

    #[test]
    fn mandate_scope_mandate_id_mismatch_short_circuits_before_integration() {
        // A mandate_id miss returns false even if integration would
        // also fail — defensive correctness: neither ordering
        // produces a different answer.
        let ms = MandateScope {
            mandate_id: Some("m-99".into()),
            integration_ref: Some("aws-iam".into()),
            ..Default::default()
        };
        let e = base_event();
        assert!(!ms.matches_event(&e));
    }

    // ------------ ScopePredicate::VerbResourceMandate ----------------

    #[test]
    fn verb_resource_mandate_full_match() {
        let sp = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: Some("pod".into()),
            mandate_scope: MandateScope {
                mandate_id: Some("m-42".into()),
                ..Default::default()
            },
        };
        assert!(sp.matches(&base_event()));
    }

    #[test]
    fn verb_resource_mandate_verb_miss_is_false() {
        let sp = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("rotate".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        assert!(!sp.matches(&base_event()));
    }

    #[test]
    fn verb_resource_mandate_resource_kind_none_is_wildcard() {
        let sp = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        let mut e = base_event();
        e.resource_kind = "deployment".into();
        assert!(sp.matches(&e));
    }

    #[test]
    fn verb_resource_mandate_resource_kind_some_must_byte_match() {
        let sp = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: Some("pod".into()),
            mandate_scope: MandateScope::default(),
        };
        let mut e = base_event();
        e.resource_kind = "deployment".into();
        assert!(!sp.matches(&e));
    }

    #[test]
    fn verb_resource_mandate_mandate_id_miss_is_false() {
        let sp = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: Some("pod".into()),
            mandate_scope: MandateScope {
                mandate_id: Some("m-other".into()),
                ..Default::default()
            },
        };
        assert!(!sp.matches(&base_event()));
    }

    #[test]
    fn verb_resource_mandate_family_verb_matches_via_family_lookup() {
        let sp = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Family("destructive".into()),
            resource_kind: None,
            mandate_scope: MandateScope::default(),
        };
        let mut e = base_event();
        e.verb = "rotate".into();
        assert!(sp.matches(&e));
        e.verb = "get".into();
        assert!(!sp.matches(&e));
    }

    // ------------ ScopePredicate::IamAttachFamily --------------------

    #[test]
    fn iam_attach_family_matches_family_member() {
        let sp = ScopePredicate::IamAttachFamily {
            verb_family: "iam-attach".into(),
            mandate_scope: MandateScope::default(),
        };
        let mut e = base_event();
        e.verb = "attachrolepolicy".into();
        assert!(sp.matches(&e));
    }

    #[test]
    fn iam_attach_family_rejects_non_member_verbs() {
        let sp = ScopePredicate::IamAttachFamily {
            verb_family: "iam-attach".into(),
            mandate_scope: MandateScope::default(),
        };
        let mut e = base_event();
        e.verb = "detachrolepolicy".into();
        assert!(!sp.matches(&e));
        e.verb = "delete".into();
        assert!(!sp.matches(&e));
    }

    #[test]
    fn iam_attach_family_unknown_name_fails_closed() {
        // Stage-7c invariants reject unknown family names; defense-
        // in-depth at the matcher returns false.
        let sp = ScopePredicate::IamAttachFamily {
            verb_family: "does-not-exist".into(),
            mandate_scope: MandateScope::default(),
        };
        let mut e = base_event();
        e.verb = "attachrolepolicy".into();
        assert!(!sp.matches(&e));
    }

    // ------------ ScopePredicate::ProtectedBranches ------------------

    #[test]
    fn protected_branches_session_5a_mandate_scope_membership_only() {
        // Session 5-A filters on mandate_scope only; per-branch
        // filtering via protected_patterns lands in Session 5-B.
        let sp = ScopePredicate::ProtectedBranches {
            mandate_scope: MandateScope {
                mandate_id: Some("m-42".into()),
                ..Default::default()
            },
            protected_patterns: vec!["refs/heads/main".into()],
        };
        assert!(sp.matches(&base_event()));
        let mut e = base_event();
        e.mandate_id = "m-other".into();
        assert!(!sp.matches(&e));
    }

    // ------------ ScopePredicate::CrossTierSequence ------------------

    #[test]
    fn cross_tier_sequence_session_5a_mandate_scope_membership_only() {
        // Session 5-A: every event in the mandate is a membership
        // candidate; Session 5-B walks tier_progression statefully.
        let sp = ScopePredicate::CrossTierSequence {
            mandate_scope: MandateScope {
                mandate_id: Some("m-42".into()),
                ..Default::default()
            },
            tier_progression: vec![0, 2, 3],
        };
        assert!(sp.matches(&base_event()));
    }

    // ------------ ScopePredicate::MandatePace ------------------------

    #[test]
    fn mandate_pace_respects_tier_floor() {
        let sp = ScopePredicate::MandatePace {
            tier_floor: 2,
            exclude_verb_category: None,
        };
        let mut e = base_event();
        e.tier = 1;
        assert!(!sp.matches(&e));
        e.tier = 2;
        assert!(sp.matches(&e));
        e.tier = 4;
        assert!(sp.matches(&e));
    }

    #[test]
    fn mandate_pace_excludes_read_only_verbs() {
        let sp = ScopePredicate::MandatePace {
            tier_floor: 0,
            exclude_verb_category: Some("read-only".into()),
        };
        let mut e = base_event();
        e.verb = "get".into();
        assert!(!sp.matches(&e));
        e.verb = "list".into();
        assert!(!sp.matches(&e));
        e.verb = "delete".into();
        assert!(sp.matches(&e));
    }

    #[test]
    fn mandate_pace_unknown_exclude_family_behaves_as_no_exclusion() {
        // Stage-7c rejects unknown families at verification; defense-
        // in-depth at runtime treats unknown as empty-set, so no
        // verbs are excluded.
        let sp = ScopePredicate::MandatePace {
            tier_floor: 0,
            exclude_verb_category: Some("mystery-family".into()),
        };
        let e = base_event();
        assert!(sp.matches(&e));
    }

    // ------------ ScopePredicate::SilenceThenBurst -------------------

    #[test]
    fn silence_then_burst_every_event_is_a_membership_candidate() {
        let sp = ScopePredicate::SilenceThenBurst {
            silence_seconds: 604_800,
            burst_seconds: 300,
            burst_threshold: 20,
        };
        assert!(sp.matches(&base_event()));
        let mut e = base_event();
        e.verb = "get".into();
        assert!(sp.matches(&e));
        e.tier = 0;
        assert!(sp.matches(&e));
    }

    // ------------ ScopePredicate::CanaryWindow -----------------------

    #[test]
    fn canary_window_unconditional_false_at_session_5a() {
        // Fail-closed: Session 5-A has no PCR attestation surface.
        // A later session wiring up attestation flips this arm; the
        // pin surfaces the regression.
        let sp = ScopePredicate::CanaryWindow {
            pcr_attestor_set: "canary-signers".into(),
            observation_threshold: 3,
        };
        assert!(!sp.matches(&base_event()));
    }

    // ------------ ScopePredicate::DelegationDepth --------------------

    #[test]
    fn delegation_depth_unconditional_false_at_session_5a() {
        let sp = ScopePredicate::DelegationDepth { limit: 4 };
        assert!(!sp.matches(&base_event()));
    }

    // ------------ ScopePredicate::VerbFanout -------------------------

    #[test]
    fn verb_fanout_matches_on_verb_and_mandate() {
        let sp = ScopePredicate::VerbFanout {
            verb: VerbPredicate::Exact("delete".into()),
            mandate_scope: MandateScope {
                mandate_id: Some("m-42".into()),
                ..Default::default()
            },
        };
        assert!(sp.matches(&base_event()));
        let mut e = base_event();
        e.verb = "get".into();
        assert!(!sp.matches(&e));
        let mut e = base_event();
        e.mandate_id = "m-99".into();
        assert!(!sp.matches(&e));
    }

    // ------------ integration / cross-variant pins -------------------

    #[test]
    fn family_contains_helper_rejects_unknown_family_without_panic() {
        assert!(!family_contains("", "delete"));
        assert!(!family_contains("\0", "delete"));
        assert!(!family_contains("DESTRUCTIVE", "delete"));
    }

    #[test]
    fn family_contains_helper_matches_registered_family() {
        assert!(family_contains("destructive", "delete"));
        assert!(family_contains("read-only", "get"));
        assert!(family_contains("iam-attach", "attachrolepolicy"));
        assert!(!family_contains("destructive", "get"));
    }
}
