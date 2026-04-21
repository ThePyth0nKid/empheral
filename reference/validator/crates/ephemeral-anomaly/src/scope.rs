//! Scope predicates for anomaly-library patterns.
//!
//! A [`ScopePredicate`] filters which events participate in a given
//! pattern's counter.  The variant set enumerates §3.5.4's MINIMUM-
//! library shapes: verb-resource-mandate tuples (`delete-storm`,
//! `vault-rotate-storm`), verb-family matches
//! (`iam-attach-policy-storm`), branch-protection patterns
//! (`git-force-push-storm`), cross-tier sequences, machine-pace
//! denormalisations, silence-then-burst sequences, canary-window
//! PCR-group observations, delegation-depth snapshots, and fanout
//! counters.
//!
//! # Session 2 posture: structurally-typed but semantically opaque
//!
//! Session 2 only decodes and structurally validates these
//! predicates.  The *evaluation* logic (matching a predicate against
//! a normalized event stream) lands in Session 4.  Sequence-template
//! and tier-progression fields are therefore opaque `Vec<_>` at this
//! layer — downstream sessions interpret them.
//!
//! The invariant check at Stage 7c
//! ([`crate::invariants::check_verb_families_known`]) does walk into
//! [`VerbPredicate::Family`] and
//! [`ScopePredicate::IamAttachFamily.verb_family`] to enforce that
//! referenced verb-family names resolve via
//! [`crate::families::lookup_family`].  That is the only semantic
//! traversal this module participates in at Session 2.
//!
//! # Structural caps
//!
//! String and vector fields in these types are attacker-controlled
//! via the signed CBOR payload.  The outer 128 KiB envelope cap
//! (`MAX_ANOMALY_LIBRARY_BYTES`) provides a coarse backstop, but the
//! invariant layer also enforces per-field caps (strings ≤ 256
//! bytes, vectors ≤ 64 entries) so an oversized pattern row cannot
//! expand validator memory by two orders of magnitude below the
//! envelope cap.  Those checks live in `invariants.rs` rather than
//! at the serde layer because ciborium does not expose a native
//! per-field-length hook.

use serde::Deserialize;

#[cfg(any(test, feature = "test_fixtures"))]
use serde::Serialize;

/// Per-pattern scope predicate.  One variant per distinct §3.5.4
/// pattern shape plus generic catch-alls for Session 4 expansion.
///
/// # Variant taxonomy
///
/// - [`Self::VerbResourceMandate`] — the bread-and-butter three-tuple
///   of `(verb, resource_kind, mandate binding)`.  Covers
///   `delete-storm`, `vault-rotate-storm`.
/// - [`Self::IamAttachFamily`] — verb-family-based IAM storm
///   detection.  Separate from `VerbResourceMandate` because the
///   family name is the primary key and
///   [`VerbPredicate::Family`] is the cross-cutting mechanism.
/// - [`Self::ProtectedBranches`] — scoped to branches enumerated in
///   `Tariff.integration_config.protected_branches`.
/// - [`Self::CrossTierSequence`] — ordered tier-progression template
///   (e.g. `T0→T2+→T3+` for `cross-tier-escalation`).
/// - [`Self::MandatePace`] — rate-limit shape with a tier-floor and
///   an optional excluded verb category (read-only for `machine-
///   pace`).
/// - [`Self::SilenceThenBurst`] — long-silence followed by a burst,
///   per `long-silence-before-burst`.
/// - [`Self::CanaryWindow`] — observations across a shared Signer
///   PCR attestor set, per `canary-window-second-tier3`.
/// - [`Self::DelegationDepth`] — chain-depth ceiling check for
///   `unusual-delegation-depth`.
/// - [`Self::VerbFanout`] — same `(verb, mandate_id)` with distinct
///   resource refs, for `fanout-distinct-resources`.
///
/// # Wire form
///
/// External tag via ciborium's default serde treatment.  `rename_all
/// = "snake_case"` makes tags match spec identifiers
/// (`verb_resource_mandate`, `iam_attach_family`, …).
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScopePredicate {
    /// Tuple predicate `(verb, resource_kind?, mandate binding)`.
    ///
    /// Used by `delete-storm`, `vault-rotate-storm` in §3.5.4.
    /// `resource_kind` is optional because some patterns (e.g.
    /// `delete-storm`) match across all kinds bound to a given verb.
    VerbResourceMandate {
        verb: VerbPredicate,
        #[serde(default)]
        resource_kind: Option<String>,
        mandate_scope: MandateScope,
    },
    /// IAM attach-policy family match.  `verb_family` is the family
    /// name resolved against [`crate::families`] at Stage 7c
    /// (unknown names reject with
    /// [`crate::errors::AnomalyLibError::UnknownVerbFamily`]).
    IamAttachFamily {
        verb_family: String,
        mandate_scope: MandateScope,
    },
    /// Scoped to branches enumerated in
    /// `Tariff.integration_config.protected_branches`.  Used by
    /// `git-force-push-storm`.  `protected_patterns` is carried here
    /// for Session-4 evaluator independence; Session 2 only checks
    /// structural shape.
    ProtectedBranches {
        mandate_scope: MandateScope,
        #[serde(default)]
        protected_patterns: Vec<String>,
    },
    /// Ordered tier-progression sequence (`cross-tier-escalation`).
    /// `tier_progression` is a `Vec<u8>` of tier thresholds in
    /// match order.  Opaque at Session 2.
    CrossTierSequence {
        mandate_scope: MandateScope,
        tier_progression: Vec<u8>,
    },
    /// Rate-limit shape with a tier floor.  Used by `machine-pace`:
    /// `tier_floor = 1` plus `exclude_verb_category = Some("read-
    /// only")` rejects read-only verbs from the counter.
    MandatePace {
        tier_floor: u8,
        #[serde(default)]
        exclude_verb_category: Option<String>,
    },
    /// Long-silence-then-burst template.  Used by
    /// `long-silence-before-burst`.
    SilenceThenBurst {
        silence_seconds: u32,
        burst_seconds: u32,
        burst_threshold: u32,
    },
    /// Canary-window observation across a shared PCR attestor set.
    /// `pcr_attestor_set` names the Tariff-declared set.
    CanaryWindow {
        pcr_attestor_set: String,
        observation_threshold: u32,
    },
    /// Delegation-chain depth ceiling.  `unusual-delegation-depth`
    /// fires at `limit = 4` per R7.D3.
    DelegationDepth { limit: u8 },
    /// Fanout-across-distinct-resources for a fixed `(verb, mandate
    /// binding)`.  Used by `fanout-distinct-resources`.
    VerbFanout {
        verb: VerbPredicate,
        mandate_scope: MandateScope,
    },
}

/// Verb-level sub-predicate.
///
/// Three variants, `#[non_exhaustive]`:
///
/// - [`Self::Exact`] — literal verb string (e.g. `"delete"`).  The
///   escape hatch for verbs that don't belong to a hardcoded family.
/// - [`Self::Family`] — verb-family name (e.g. `"iam-attach"`,
///   `"destructive"`, `"read-only"`).  Resolved against
///   [`crate::families::lookup_family`] at Stage 7c — unknown names
///   reject.  Operator-supplied family definitions are FORBIDDEN per
///   D2 design decision (plan §2 D2, §3.5.3 walk-under posture).
/// - [`Self::AnyDestructive`] — sugar for the destructive family.
///   Equivalent to `Family("destructive".into())` but lets signers
///   avoid spelling the family name; reduces typo surface in
///   hand-authored libraries.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerbPredicate {
    /// Literal verb string (post-R7.C1 case-folding).
    Exact(String),
    /// Verb-family name; resolved via
    /// [`crate::families::lookup_family`].
    Family(String),
    /// Sugar for `Family("destructive")`.
    AnyDestructive,
}

/// Mandate-binding fields carried by most [`ScopePredicate`]
/// variants.
///
/// All three fields are optional with `#[serde(default)]`.  A
/// predicate with all three `None` matches across any mandate /
/// operator / integration (equivalent to §3.5.4's "any mandate" in
/// e.g. `unusual-delegation-depth`).  A predicate with one field
/// `Some(x)` binds the counter to events sharing that field value.
///
/// `Some("*")` is NOT a wildcard — it is a literal string `"*"`.
/// The wildcard shape is `None`.  Signers SHOULD use `None` for
/// unbound dimensions; a literal `"*"` string will never match a
/// real mandate id.  This convention is enforced at the Session-4
/// evaluator layer, not at the schema layer, because the schema
/// cannot distinguish literal `"*"` from "operator meant wildcard".
///
/// The `#[derive(Default)]` is load-bearing — it lets the
/// deserializer populate missing fields via `#[serde(default)]` and
/// lets fixture builders write `MandateScope { mandate_id: ...,
/// ..Default::default() }` without ceremony.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct MandateScope {
    /// Mandate-id binding.  `None` = match across any mandate.
    #[serde(default)]
    pub mandate_id: Option<String>,
    /// Operator-id binding.  `None` = match across any operator.
    #[serde(default)]
    pub operator_id: Option<String>,
    /// Integration-ref binding.  `None` = match across any
    /// integration.
    #[serde(default)]
    pub integration_ref: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mandate_scope_default_is_fully_unbound() {
        let ms = MandateScope::default();
        assert!(ms.mandate_id.is_none());
        assert!(ms.operator_id.is_none());
        assert!(ms.integration_ref.is_none());
    }

    #[test]
    fn verb_predicate_exact_round_trips_through_ciborium() {
        let cases = [
            VerbPredicate::Exact("delete".into()),
            VerbPredicate::Family("iam-attach".into()),
            VerbPredicate::AnyDestructive,
        ];
        for case in cases {
            let mut buf = Vec::new();
            ciborium::into_writer(&case, &mut buf).unwrap();
            let back: VerbPredicate = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(case, back);
        }
    }

    #[test]
    fn mandate_scope_round_trips_through_ciborium_with_missing_fields() {
        // Fully-unbound (all None) MUST encode+decode byte-exactly
        // and the #[serde(default)] on every field MUST allow a
        // signer to omit all three and still decode.
        let ms = MandateScope::default();
        let mut buf = Vec::new();
        ciborium::into_writer(&ms, &mut buf).unwrap();
        let back: MandateScope = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(ms, back);
    }

    #[test]
    fn mandate_scope_round_trips_with_some_fields() {
        let ms = MandateScope {
            mandate_id: Some("m-123".into()),
            operator_id: None,
            integration_ref: Some("int-gh".into()),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&ms, &mut buf).unwrap();
        let back: MandateScope = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(ms, back);
    }

    #[test]
    fn scope_predicate_verb_resource_mandate_round_trips() {
        let sp = ScopePredicate::VerbResourceMandate {
            verb: VerbPredicate::Exact("delete".into()),
            resource_kind: Some("pod".into()),
            mandate_scope: MandateScope {
                mandate_id: Some("m-x".into()),
                ..Default::default()
            },
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&sp, &mut buf).unwrap();
        let back: ScopePredicate = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(sp, back);
    }

    #[test]
    fn scope_predicate_iam_attach_family_round_trips() {
        let sp = ScopePredicate::IamAttachFamily {
            verb_family: "iam-attach".into(),
            mandate_scope: MandateScope::default(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&sp, &mut buf).unwrap();
        let back: ScopePredicate = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(sp, back);
    }

    #[test]
    fn scope_predicate_cross_tier_sequence_round_trips() {
        let sp = ScopePredicate::CrossTierSequence {
            mandate_scope: MandateScope::default(),
            tier_progression: vec![0, 2, 3],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&sp, &mut buf).unwrap();
        let back: ScopePredicate = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(sp, back);
    }

    #[test]
    fn scope_predicate_delegation_depth_round_trips() {
        let sp = ScopePredicate::DelegationDepth { limit: 4 };
        let mut buf = Vec::new();
        ciborium::into_writer(&sp, &mut buf).unwrap();
        let back: ScopePredicate = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(sp, back);
    }

    #[test]
    fn scope_predicate_silence_then_burst_round_trips() {
        let sp = ScopePredicate::SilenceThenBurst {
            silence_seconds: 604_800,
            burst_seconds: 300,
            burst_threshold: 20,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&sp, &mut buf).unwrap();
        let back: ScopePredicate = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(sp, back);
    }

    #[test]
    fn scope_predicate_mandate_pace_round_trips_with_exclude() {
        let sp = ScopePredicate::MandatePace {
            tier_floor: 1,
            exclude_verb_category: Some("read-only".into()),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&sp, &mut buf).unwrap();
        let back: ScopePredicate = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(sp, back);
    }
}
