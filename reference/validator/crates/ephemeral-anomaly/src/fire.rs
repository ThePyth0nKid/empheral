//! §11.2 `AnomalyDetected` output-shape DTO + multi-tenant container.
//!
//! Session 5-A publishes the *wire contract* — downstream consumers
//! (Session 5-B Commit C `audit.rs`, future revocation-pusher, etc.)
//! can build against this shape today.  Session 5-B Commit A filled
//! [`crate::state::DetectorState::evaluate_all`] with the firing-rule
//! evaluators that actually produce [`AnomalyFire`] values; Session
//! 5-B Commit B exercised them against a conformance corpus.
//!
//! Session 5-B Commit C adds [`AnomalyDetectedRecord`] — the
//! multi-tenant audit-stream container that [`crate::orchestrator`]
//! emits.  [`AnomalyFire`] remains the §11.2 *payload* (unchanged);
//! the record wraps it with the tenant identity and the wall-clock
//! timestamp the orchestrator observed at fire time.
//!
//! # Why publish the DTO now
//!
//! Freezing the output shape early lets the downstream `audit.rs` be
//! written in parallel with the firing evaluator without waiting on
//! Session 5-B.  A Session 5-B evaluator that wanted to extend the
//! shape would have to change both crates in lockstep, which is a
//! healthy forcing function: the `#[non_exhaustive]` marker makes
//! additive extensions backward-compatible for downstream consumers
//! that don't care about the new field.
//!
//! # §11.2 payload mapping
//!
//! > `AnomalyDetected` (payload: `{pattern_id, library_version,
//! > severity, firing_rule, match_scope}`)
//!
//! Each spec field maps 1-for-1 onto a field of [`AnomalyFire`].
//! `match_scope` is the sub-object that names which mandate /
//! operator / integration / resource-kind / verb combination the
//! firing counter saw — the detector's evidence for the fire.
//!
//! # Name disambiguation
//!
//! [`AnomalyFire`] is the *output* shape for a successful pattern
//! firing.  It is distinct from
//! [`crate::errors::FiringCompanionFailure`], which is an *error*
//! sub-enum for the anti-walk-under companion-check at library
//! verification time.  They never appear in the same context:
//! `FiringCompanionFailure` is raised at Stage 7 of envelope
//! verification (before any events are ingested);
//! `AnomalyFire` is emitted by the runtime after events have been
//! ingested and matched against a verified library.

use serde::Deserialize;

#[cfg(any(test, feature = "test_fixtures"))]
use serde::Serialize;

use crate::patterns::{FiringRule, Severity};

/// Single firing of one anomaly-library pattern.
///
/// Wire-form corresponds to the `AnomalyDetected` audit-event payload
/// in spec §11.2.  Produced by
/// [`crate::state::DetectorState::evaluate_all`] (Session 5-B) after a
/// pattern's threshold has been crossed within its sliding window.
///
/// # Field invariants
///
/// - `pattern_id` is the exact pattern_id from the verified
///   anomaly-library payload — case-preserved, byte-identical.  It
///   is attacker-derived only insofar as the library signer chose
///   it; the outer COSE signature binds it to a registered
///   [`crate::ledger::AnomalyLedger`]-committed library, so it is
///   NOT log-sanitised at storage time.
/// - `library_version` is copied from the verified library payload.
///   The state machine stores an `Arc<VerifiedAnomalyLibrarySignature>`
///   so this field always matches the ledger's HWM at fire time.
/// - `severity` and `firing_rule` are taken directly from the
///   firing `PatternEntry`.
/// - `match_scope` captures the observed values the counter saw —
///   see [`MatchScope`].
///
/// # Non-exhaustive
///
/// `#[non_exhaustive]` guards against downstream exhaustive matches
/// breaking when Session 5-B+ adds evidence fields (e.g. matched
/// `event_id` window, cumulative count at fire time).  Additive
/// extensions MUST land with a default/optional serde attribute so
/// the wire shape stays backward-compatible.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnomalyFire {
    /// Pattern identifier from the verified library payload.
    pub pattern_id: String,
    /// Version of the library that authored this pattern.
    /// Monotonic under the replay ledger (§3.5.1).
    pub library_version: u64,
    /// Severity grade carried on the firing `PatternEntry`.
    pub severity: Severity,
    /// Firing rule the evaluator used (`FirstMatch`,
    /// `SequenceMatch`, `CumulativeOverBaseline`).
    pub firing_rule: FiringRule,
    /// Observed scope values the counter saw.
    pub match_scope: MatchScope,
}

/// Observed field values of the events that made up the firing
/// counter, captured at fire time.
///
/// Every field is `Option<String>` / `Option<u8>` because the firing
/// [`crate::scope::ScopePredicate`] may be unbound on a given
/// dimension (see [`crate::scope::MandateScope`]'s `None` = wildcard
/// convention).  Fields that the predicate bound to a specific value
/// are `Some(value)`; fields the predicate left unbound are `None`.
///
/// For predicates that bind on `(verb, resource_kind, mandate_id)`
/// (e.g. `delete-storm`), `verb`, `resource_kind`, and `mandate_id`
/// are `Some(_)` and `operator_id` / `integration_ref` are `None`.
///
/// # Log-safety
///
/// All `String` fields are attacker-derivable from either the signed
/// library (the predicate's bound values) or the ingested events
/// (values the counter observed).  Downstream log rendering at
/// `audit.rs` MUST sanitise via
/// [`crate::errors::sanitize_log_string`] — the DTO itself stores
/// the raw bytes so audit-correlation keeps byte-identity.
///
/// # Default value = fully-unbound
///
/// The `#[derive(Default)]` impl produces an all-`None` match scope
/// which is load-bearing for test fixtures that construct
/// [`AnomalyFire`] values with the struct-update syntax.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct MatchScope {
    /// Mandate id the counter saw; `None` if the predicate was
    /// unbound on the mandate dimension.
    #[serde(default)]
    pub mandate_id: Option<String>,
    /// Operator id the counter saw; `None` if unbound.
    #[serde(default)]
    pub operator_id: Option<String>,
    /// Integration reference the counter saw; `None` if unbound.
    #[serde(default)]
    pub integration_ref: Option<String>,
    /// Resource kind the counter saw; `None` if unbound.
    #[serde(default)]
    pub resource_kind: Option<String>,
    /// Verb the counter saw; `None` if the predicate bound on a
    /// verb-family (which does not pin a specific verb).
    #[serde(default)]
    pub verb: Option<String>,
    /// Impact tier of the event stream; `None` if the predicate
    /// was not tier-bound.
    #[serde(default)]
    pub tier: Option<u8>,
}

/// Multi-tenant audit-stream container wrapping one `AnomalyFire` payload.
///
/// §11.2 defines `AnomalyDetected` as a named audit-event carrying
/// `{pattern_id, library_version, severity, firing_rule, match_scope}`.
/// The spec is silent on the *container* that the audit service persists
/// around that payload — concrete deployments vary (S3 Object Lock
/// records, immutable Kafka messages, etc.).  This reference
/// implementation pins one container shape: the minimum fields a
/// multi-tenant Router+Audit-Worker needs to route, correlate, and
/// de-duplicate fires across tenants.
///
/// # Fields
///
/// - `tenant_id`: routing key.  One [`crate::orchestrator::AuditOrchestrator`]
///   may host multiple tenants (per-deployment), each with its own
///   [`crate::state::DetectorState`] instance.  The tenant_id names
///   which state produced the fire.  **Attacker-influence-bounded:**
///   the tenant_id is chosen by the Router operator at orchestrator-
///   build time, never by an ingested event — so a malicious event
///   cannot forge a tenant attribution.
/// - `record_timestamp`: the detector's current wall-clock (unix
///   seconds) at the moment `evaluate_all` returned the fire.  Stable
///   for conformance tests because it is pinned to the last event's
///   `advance_clock`, not to `SystemTime::now()`.
/// - `payload`: the §11.2 `AnomalyDetected` payload, verbatim.
///
/// # Duplicate-tolerance contract (load-bearing)
///
/// [`crate::orchestrator::AuditOrchestrator`] does NOT persist the
/// [`crate::dedup_ledger::DedupLedger`] held inside its per-tenant
/// [`crate::state::DetectorState`].  The default
/// [`crate::dedup_ledger::InMemoryDedupLedger`] backend lives in
/// process memory only, so a restart re-initialises an empty ledger
/// and a pattern may fire again within its dedup window.  Downstream
/// audit consumers MUST be duplicate-tolerant on the
/// `(tenant_id, pattern_id, match_scope, ~record_timestamp)` tuple —
/// idempotent alert fan-out at the dashboard layer is the canonical
/// approach.  Persistent backends may be plugged in via
/// [`crate::state::DetectorState::with_ledger`] but are out of scope
/// for the reference validator's default configuration.
///
/// # Non-exhaustive
///
/// `#[non_exhaustive]` so future operational fields (e.g. an
/// orchestrator-generated `record_id` for dashboard de-dup) can land
/// without a semver bump.  Wire-form: snake_case JSON via serde.
#[cfg_attr(any(test, feature = "test_fixtures"), derive(Serialize))]
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnomalyDetectedRecord {
    /// Routing key identifying which [`crate::state::DetectorState`]
    /// instance produced this fire.  Operator-controlled at
    /// orchestrator-build time.
    pub tenant_id: String,
    /// Unix-seconds wall-clock at fire time (detector's
    /// `current_time`).  Deterministic under conformance replay.
    pub record_timestamp: i64,
    /// §11.2 `AnomalyDetected` payload.
    pub payload: AnomalyFire,
}

impl AnomalyDetectedRecord {
    /// Construct a record around a payload the orchestrator just observed.
    ///
    /// `tenant_id` moves in (no clone at wrap time); `record_timestamp`
    /// is the orchestrator's snapshot of the detector clock.
    #[must_use]
    pub fn new(tenant_id: String, record_timestamp: i64, payload: AnomalyFire) -> Self {
        Self {
            tenant_id,
            record_timestamp,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_scope_default_is_fully_unbound() {
        let ms = MatchScope::default();
        assert!(ms.mandate_id.is_none());
        assert!(ms.operator_id.is_none());
        assert!(ms.integration_ref.is_none());
        assert!(ms.resource_kind.is_none());
        assert!(ms.verb.is_none());
        assert!(ms.tier.is_none());
    }

    #[test]
    fn match_scope_roundtrips_through_json_with_all_fields_some() {
        // Pin the wire form for a fully-bound match_scope: five
        // string fields and a tier byte, all omitted defaults
        // allowed but all `Some` here.  A serde refactor that
        // silently dropped a field from MatchScope would fail this.
        let ms = MatchScope {
            mandate_id: Some("m-42".into()),
            operator_id: Some("op-3".into()),
            integration_ref: Some("int-gh".into()),
            resource_kind: Some("pod".into()),
            verb: Some("delete".into()),
            tier: Some(1),
        };
        let encoded = serde_json::to_string(&ms).unwrap();
        let back: MatchScope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(ms, back);
    }

    #[test]
    fn match_scope_deserialises_with_missing_fields_as_none() {
        // Wire fixtures emitted by a Session-5-B evaluator that
        // only bound `verb` MUST decode: every field has
        // `#[serde(default)]`.  This pins the forward-compat
        // contract: a decoder running against a wire payload that
        // elides an unbound dimension falls back to `None`.
        let json = r#"{"verb": "delete"}"#;
        let ms: MatchScope = serde_json::from_str(json).unwrap();
        assert_eq!(ms.verb.as_deref(), Some("delete"));
        assert!(ms.mandate_id.is_none());
        assert!(ms.operator_id.is_none());
    }

    fn example_fire() -> AnomalyFire {
        AnomalyFire {
            pattern_id: "delete-storm".into(),
            library_version: 42,
            severity: Severity::High,
            firing_rule: FiringRule::FirstMatch,
            match_scope: MatchScope {
                mandate_id: Some("m-42".into()),
                verb: Some("delete".into()),
                resource_kind: Some("pod".into()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn anomaly_fire_roundtrips_through_json() {
        let fire = example_fire();
        let encoded = serde_json::to_string(&fire).unwrap();
        let back: AnomalyFire = serde_json::from_str(&encoded).unwrap();
        assert_eq!(fire, back);
    }

    #[test]
    fn anomaly_fire_json_has_spec_payload_field_names() {
        // Pin the exact JSON key names against spec §11.2:
        // `{pattern_id, library_version, severity, firing_rule,
        // match_scope}`.  A serde rename that silently shifted one
        // key to camelCase would break downstream log parsers.
        let fire = example_fire();
        let encoded = serde_json::to_string(&fire).unwrap();
        assert!(encoded.contains("\"pattern_id\":"));
        assert!(encoded.contains("\"library_version\":"));
        assert!(encoded.contains("\"severity\":"));
        assert!(encoded.contains("\"firing_rule\":"));
        assert!(encoded.contains("\"match_scope\":"));
    }

    #[test]
    fn anomaly_fire_severity_uses_snake_case_wire_form() {
        // `patterns::Severity` serialises as `snake_case`; pin that
        // the pass-through through AnomalyFire preserves this.
        let mut fire = example_fire();
        fire.severity = Severity::Critical;
        let encoded = serde_json::to_string(&fire).unwrap();
        assert!(encoded.contains("\"critical\""));
    }

    #[test]
    fn anomaly_fire_firing_rule_uses_kebab_case_wire_form() {
        // `patterns::FiringRule` serialises as `kebab-case`; pin
        // that pass-through preserves this.
        let mut fire = example_fire();
        fire.firing_rule = FiringRule::CumulativeOverBaseline;
        let encoded = serde_json::to_string(&fire).unwrap();
        assert!(encoded.contains("\"cumulative-over-baseline\""));
    }

    #[test]
    fn anomaly_fire_implements_standard_bounds() {
        fn assert_bounds<T: std::fmt::Debug + Clone + PartialEq + Eq + Send + Sync>() {}
        assert_bounds::<AnomalyFire>();
        assert_bounds::<MatchScope>();
    }

    // ---------------- AnomalyDetectedRecord container -------------------

    fn example_record() -> AnomalyDetectedRecord {
        AnomalyDetectedRecord::new("tenant-A".into(), 1_800_000_000, example_fire())
    }

    #[test]
    fn anomaly_detected_record_roundtrips_through_json() {
        let rec = example_record();
        let encoded = serde_json::to_string(&rec).unwrap();
        let back: AnomalyDetectedRecord = serde_json::from_str(&encoded).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn anomaly_detected_record_wire_shape_pins_field_names() {
        // Pin the exact JSON keys: tenant_id, record_timestamp, payload.
        // A rename to camelCase would silently break third-party audit
        // consumers — catch it here.
        let rec = example_record();
        let encoded = serde_json::to_string(&rec).unwrap();
        assert!(encoded.contains("\"tenant_id\":"), "{encoded}");
        assert!(encoded.contains("\"record_timestamp\":"), "{encoded}");
        assert!(encoded.contains("\"payload\":"), "{encoded}");
        // Payload inlines the full §11.2 fire shape; spot-check one key.
        assert!(encoded.contains("\"pattern_id\":"), "{encoded}");
    }

    #[test]
    fn anomaly_detected_record_constructor_moves_tenant_id() {
        // `new` takes ownership of `tenant_id: String` so callers do
        // not clone at wrap time.  This is the load-bearing allocation
        // shape for the orchestrator's hot path.
        let fire = example_fire();
        let rec = AnomalyDetectedRecord::new("tenant-X".to_owned(), 42, fire);
        assert_eq!(rec.tenant_id, "tenant-X");
        assert_eq!(rec.record_timestamp, 42);
        assert_eq!(rec.payload.pattern_id, "delete-storm");
    }

    #[test]
    fn anomaly_detected_record_implements_standard_bounds() {
        fn assert_bounds<T: std::fmt::Debug + Clone + PartialEq + Eq + Send + Sync>() {}
        assert_bounds::<AnomalyDetectedRecord>();
    }
}
