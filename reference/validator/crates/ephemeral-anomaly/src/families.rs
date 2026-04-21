//! Hardcoded verb-family tables.
//!
//! Pattern scopes reference verb-family names via
//! [`crate::scope::VerbPredicate::Family`] and
//! [`crate::scope::ScopePredicate::IamAttachFamily`].  Those names
//! resolve against the static tables in this module — they are NOT
//! operator-supplied.
//!
//! # D2: why families are hardcoded, not signer-defined (§ plan 2.D2)
//!
//! Allowing a signed library to supply its own family definitions
//! would defeat the §3.5.3 anti-walk-under property.  A compromised
//! signer (or an operator misunderstanding the spec) could, for
//! example, redefine the `iam-attach` family to `["noop"]` — then
//! the `iam-attach-policy-storm` pattern would count events that
//! never occur, effectively disabling detection.  Hardcoding the
//! families makes them part of the validator's trust surface and
//! couples their definitions to `ANOMALY_LIBRARY_ABI_VERSION`: any
//! spec change to a family's contents MUST bump the ABI version
//! and force a recompile, so the walk-under attack surface is
//! closed off at the binary boundary.
//!
//! The escape hatch for verbs that don't fit a family is
//! [`crate::scope::VerbPredicate::Exact`] — signers can always pin
//! a specific literal verb string without going through a family.
//!
//! # Canonicalisation
//!
//! Family member strings are stored in their canonical form per
//! R7.C1 + R7.C10:
//!
//! - lowercase (Unicode Default Case Folding)
//! - NFC-normalised (enforced upstream at the classifier's event
//!   normalisation layer, so by the time a verb hits
//!   `lookup_family`, it is guaranteed NFC or the event was already
//!   rejected)
//!
//! Family MEMBERSHIP is byte-exact against the canonical form.  A
//! table entry carrying an uppercase letter is a spec-violation bug
//! in *this file* — the regression test
//! `all_family_members_are_canonical_lowercase_ascii` catches it.

/// IAM attach-policy verb family (§3.5.4 `iam-attach-policy-storm`).
///
/// Covers AWS IAM attach-*-policy verbs in canonical `snake_case →
/// lowercase-concatenated` form.  Drawn from the AWS IAM verb set
/// referenced in the conformance corpus; Session-2 scope keeps this
/// to the three canonical members and leaves room for later
/// additions under an ABI-version bump.
pub const IAM_ATTACH_VERBS: &[&str] = &[
    "attachrolepolicy",
    "attachuserpolicy",
    "attachgrouppolicy",
];

/// Destructive-verb family covering destroy/drop/truncate/rotate
/// semantics.  Targeted by
/// [`crate::scope::VerbPredicate::AnyDestructive`] and referenced
/// indirectly by `vault-rotate-storm` and `delete-storm` companion
/// slow-burn patterns.
pub const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete", "destroy", "drop", "truncate", "purge", "rotate", "revoke", "forceremove",
];

/// Read-only verb family — the negative filter for
/// `machine-pace` (§3.5.4).  A pattern using
/// `MandatePace { exclude_verb_category: Some("read-only") }`
/// subtracts these verbs from its counter, so inflating the list
/// weakens the pattern: a verb added here stops contributing to
/// machine-pace detection.
///
/// Keep this list CONSERVATIVE.  New read-only candidates require
/// an ABI-version bump precisely because adding a verb here is a
/// detection-relaxation.
pub const READ_ONLY_VERBS: &[&str] = &[
    "get", "list", "describe", "read", "head", "peek", "exists",
];

/// Resolve a family name to its canonical verb slice, or `None` if
/// the name is not a registered family.  Session 2 callers are
/// [`crate::invariants::check_verb_families_known`].
///
/// Name matching is byte-exact.  The three registered names
/// (`iam-attach`, `destructive`, `read-only`) are kebab-case because
/// that matches the spec identifiers §3.5.4 uses (`iam-attach-policy-
/// storm`, `read_only_verbs` cited with a hyphen in prose).
///
/// # Returns
///
/// - `Some(slice)` when `name` matches one of the three registered
///   families.  The returned slice is `&'static` — no allocation.
/// - `None` when `name` is unregistered.  Signers hit this when they
///   typo a family name or author a library against a future ABI;
///   the invariant layer surfaces it as
///   [`crate::errors::AnomalyLibError::UnknownVerbFamily`] with the
///   offending name sanitised for logs.
#[must_use]
pub fn lookup_family(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "iam-attach" => Some(IAM_ATTACH_VERBS),
        "destructive" => Some(DESTRUCTIVE_VERBS),
        "read-only" => Some(READ_ONLY_VERBS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_family_resolves_registered_names() {
        assert!(lookup_family("iam-attach").is_some());
        assert!(lookup_family("destructive").is_some());
        assert!(lookup_family("read-only").is_some());
    }

    #[test]
    fn lookup_family_rejects_unregistered_names() {
        assert!(lookup_family("").is_none());
        assert!(lookup_family("iam_attach").is_none()); // wrong separator
        assert!(lookup_family("IAM-ATTACH").is_none()); // wrong case
        assert!(lookup_family("read only").is_none()); // wrong separator
        assert!(lookup_family("unknown-family-x").is_none());
    }

    #[test]
    fn lookup_family_is_byte_exact_not_fuzzy() {
        // Defensive: no accidental trim/normalisation.  A leading or
        // trailing whitespace MUST NOT resolve, because an adversary
        // could then inject a control character that the sanitised
        // log output strips — producing a seemingly-clean log line
        // for an attack that was really resolved under a different
        // spelling.
        assert!(lookup_family(" iam-attach").is_none());
        assert!(lookup_family("iam-attach ").is_none());
        assert!(lookup_family("iam-attach\n").is_none());
        assert!(lookup_family("iam-attach\0").is_none());
    }

    #[test]
    fn iam_attach_family_matches_spec_canonical_verbs() {
        // §3.5.4 iam-attach-policy-storm target set.  Locked here as
        // a tripwire: if a future PR renames or drops a canonical
        // verb, this test surfaces the contract change before the
        // classifier corpus drifts.
        assert_eq!(
            IAM_ATTACH_VERBS,
            &["attachrolepolicy", "attachuserpolicy", "attachgrouppolicy"]
        );
    }

    #[test]
    fn all_family_members_are_canonical_lowercase_ascii() {
        // Load-bearing: family membership is byte-exact against
        // R7.C1-lowercased event verbs.  Any non-lowercase or non-
        // ASCII member would be unreachable from canonical events.
        for (fam, slice) in [
            ("iam-attach", IAM_ATTACH_VERBS),
            ("destructive", DESTRUCTIVE_VERBS),
            ("read-only", READ_ONLY_VERBS),
        ] {
            for verb in slice {
                assert!(
                    verb.chars().all(|c| c.is_ascii_lowercase()),
                    "family `{fam}` contains non-lowercase-ASCII verb `{verb}`"
                );
            }
        }
    }

    #[test]
    fn no_family_is_empty() {
        // An empty family would silently disable every pattern
        // referencing it — a latent detection-gap.  Reject via
        // compile-time visible `.is_empty()` check here.
        assert!(!IAM_ATTACH_VERBS.is_empty());
        assert!(!DESTRUCTIVE_VERBS.is_empty());
        assert!(!READ_ONLY_VERBS.is_empty());
    }

    #[test]
    fn family_names_are_distinct() {
        // No two registered names may resolve to the same slice
        // pointer (would break error-surface clarity: "unknown
        // family `X`" vs. lookup returning some).
        let a = lookup_family("iam-attach").unwrap();
        let b = lookup_family("destructive").unwrap();
        let c = lookup_family("read-only").unwrap();
        assert_ne!(a.as_ptr(), b.as_ptr());
        assert_ne!(b.as_ptr(), c.as_ptr());
        assert_ne!(a.as_ptr(), c.as_ptr());
    }
}
