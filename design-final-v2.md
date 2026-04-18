# design-final-v2.md — EPHEMERAL Final Specification (R7 + R8 integrated)

**Role**: The Architect, final consolidation after three adversarial rounds and two operational tightening rounds.
**Status**: Promoted from `design-final.md` with R7 canonicalization + delegation tightenings (15 items) and R8 operational tightenings (23 items) integrated. Pre-Integration Blockers B-1 through B-4 resolved inline.
**Date**: 2026-04-18
**Audit trail**: `no-go-preemptive.md` → `design-v1.md` → `redteam-round1.md` → `design-v2.md` → `redteam-round2.md` → `design-v3.md` → `redteam-round3.md` → `design-final.md` → `design-round7-tightenings.md` → `design-round8-operational-tightenings.md` → this file.

---

## 0. What this document is

This is the final technical specification for EPHEMERAL, the cross-organization autonomous-agent authorization architecture. It is the product of three red-team rounds, one major architectural pivot (Proportional Authority Protocol, introduced in v2), and two operational tightening rounds (R7 bounded spec ambiguities, R8 operationally-dependent spec ambiguities). It is organized for implementers, not for review — review artifacts remain in the redteam + round files.

The document is self-contained. It does not require reading v1/v2/v3/R7/R8 to implement, but it inherits their residuals and acknowledges them explicitly in §14.

**Target reader**: a platform/security engineer at either the SaaS vendor ("DeployCo") or the customer ("Acme") who will implement this.

**Integration provenance**: §§ marked "(R7.Cn)", "(R7.Dn)", "(R8.Pn)", "(R8.An)", "(R8.Tn)", "(R8.Fn)" are normative content introduced by R7/R8. Content without such markers is inherited from design-final.md. See §19 for the full integration changelog.

---

## 1. Premise recap (one paragraph)

A SaaS vendor operates an LLM-driven agent on a customer's infrastructure. The customer is the authority over what the agent can do; the vendor runs the agent's software; the LLM provider serves inference. The agent executes actions with asymmetric blast radii — reading status is safe, patching production is not, deleting data is catastrophic. EPHEMERAL's thesis: **authorization ceremony should match the action's blast radius, not average it**. Low-impact actions use simple short-lived tokens (the "80% alternative"); high-impact actions require cryptographic capabilities; irreversible actions require human-in-the-loop; existential actions require multi-party ceremony. This *proportional* design reconciles the Skeptic's objection (most actions don't need expensive machinery) with the original ambition (some actions genuinely do).

**Threat model carried forward from Round 0**: A1 malicious LLM insider, A2 supply-chain compromise of DeployCo, A3 network attacker, A4 compromised agent runtime, A5 compromised target API. Plus Round-1-introduced A6: compromised DeployCo operator (insider at vendor side). R7 and R8 did not introduce new threat actors; they tightened defenses against the same set by closing operational ambiguities.

---

## 2. The Proportional Authority Protocol

### 2.1 Impact Tiers (normative)

Every possible intent (action + resource + parameters) maps to exactly one tier via the customer-authored Classifier (§4).

| Tier | Name | Examples | Authority Mechanism | Revocability |
|---|---|---|---|---|
| 0 | Read | `GET /deployments`, `kubectl get pods` | OIDC+DPoP bearer | N/A (no effect) |
| 1 | Idempotent write | apply-if-drift, `kubectl apply` of unchanged manifest | OIDC+DPoP+OPA | Re-apply produces same state |
| 2 | Stateful reversible | scale +1 replica, add non-privileged firewall rule | **Mandate → Capability** | Reverse action possible |
| 3 | Destructive recoverable | delete pod (controller recreates), rotate secret | **Mandate → Capability + push-revocation + resource-version binding** | Backup/snapshot recovery |
| 4 | Irreversible | `DELETE Deployment`, `DROP TABLE`, `rm -rf pv-*` | All of Tier 3 **+ WebAuthn step-up** | Data restore only |
| 5 | Authority-granting | "add signer to customer root", modify Tariff | Tier 4 **+ M-of-N ceremony** via multiple customer officers | Requires re-ceremony |

**Tier escalation triggers** (automatic, Router-enforced):
- `target_invariants_documented: false` in Tariff → Tier 3+ auto-escalates one level (effectively Tier 3 → Tier 4).
- Classifier returns "pattern-matched aggregation risk" (per §3.3.1 window semantics) → escalates one level.
- Fresh canary window for new Signer PCR set → Tier 3+ escalates to step-up during canary; carve-out for Tier 2 sensitive-path per §4.4 (R8.F5).
- `operating_hours` violation (per §2.2.1, R8.A4) → escalates per Tariff's `default_action`.

**Additive bump composition (R8.F2)**: Tier assignment for ambiguous intents composes additively, capped at Tier 5: `final_tier = min(5, floor + Σ bumps)`. Bumps are mutually independent:
- `sensitive-path` (+1) — `sensitive_path_patterns` default `{prod/*, root/*, admin/*, ceremony/*}`; operators SHOULD adopt the reference set in `conformance/reference-sensitive-paths.json` (v1.0.0, ~190 globs across 7 categories: Git refs, CI/CD workflows, build/container files, dependency manifests, secrets/credentials, IaC, legacy defaults) or equivalent coverage (see §14 residual flag Sec-N5)
- `aggregation` (+1) — §3.3.1 threshold met within window (R8.F3)
- `canary-window` (+1) — applies iff pre-bump tier ≥ 3 (default) OR pre-bump = 2 AND sensitive-path already applied (R8.F5 carve-out)
- `target-invariants-missing` (+1) — Tier 3+ with `target_invariants_documented: false`
- `resource-state` (+1) — snapshot contains escalation trigger (e.g., stateful pods for drain, control-plane node)

The classifier's `justification_tag` field lists every bump applied, space-separated, preserved in audit events.

### 2.2 The Tariff (customer-signed policy document)

The Tariff is a COSE_Sign1 CBOR document signed by **`K_tariff_signer`** (a dedicated 7-day-rotated child of `K_cust_ops`, per §7.1; resolves Pre-Integration Blocker B-1). It is pinned in each Router instance and enforced at every decision point.

```cbor
Tariff = COSE_Sign1({
  "version":                   uint,
  "issued_at":                 uint,          // unix seconds (R7.D2 half-open)
  "not_before":                uint,          // unix seconds; Tariff inactive before
  "valid_until":               uint,          // unix seconds; Tariff expired at-or-after
  "key_epoch":                 uint,          // K_tariff_signer rotation epoch (R8.T2)
  "integration_ref":           tstr,          // e.g., "k8s-prod", "vault-prod"
  "signer_image_pcr_set":      {pcr0, pcr1, pcr2},
  "pcr_requirement":           PCRRequirement,  // see §9.4.1-§9.4.6 (R8.P1-P6)
  "pcr_canary":                {duration_days: uint, max_actions: uint},
  "pcr_attestation_evidence":  PCRAttestationEvidence,  // §9.4
  "classifier_wasm_hash":      bstr,
  "classifier_fuzz_attestation": bstr,       // hash of §4.4 fuzz report
  "tier_map_defaults":         {verb_pattern → tier},
  "minimum_tiers":             {specific_action → min_tier},  // override floor
  "narrowness_rules":          {...},        // §3.1
  "rate_matrix":               {...},        // §3.2
  "verb_aliases":              {...},        // §4.2 canonicalization
  "target_invariants_documented": bool,      // §3.4 attestation
  "tariff_update_channel":     tstr,         // push endpoint
  "revocation_channel":        tstr,         // §8.3
  "revocation_channel_ha":     {...},        // §8.4 HA spec
  "anomaly_channel":           tstr,         // §3.5
  "anomaly_library_ref":       tstr,         // §3.5.1 AnomalyPatternLibrary endpoint
  "operating_hours":           OperatingHours?,  // §2.2.1 (R8.A4, optional)
  "user_device_protocol_version": uint,      // §6
  "step_up_allowlist":         [pubkey],     // WebAuthn-capable officers (SET)
  "ceremony_quorum":           {n: uint, m: uint, diversity_rules: {...}, signers: [pubkey]},
  "integration_config":        {             // integration-specific pinned config
    "default_branch":          tstr,         // §4.4 R8.F6 Git default-branch
    "protected_branches":      [tstr],       // SET
    "acme":                    {"ct_compliant_cas": [tstr]}  // §4.4 R8.F8
  }
}, signed_by: K_tariff_signer)
```

A Tariff with missing or invalid signature is rejected at Router startup and on every push update.

**Structural limits (R8.T1–T5, normative)**:
- **R8.T1 Size cap**: Tariff COSE envelope MUST be ≤ 262144 bytes (256 KiB). Checked BEFORE signature verification. Exceeding → `tariff-oversize`. Not operator-configurable. Customers needing larger policy split per §10.2.
- **R8.T2 `iat`→`not_before` gap**: `(not_before - iat) > 2592000s (30d)` → `tariff-iat-nbf-gap-excessive`. `iat > not_before` → `tariff-iat-after-nbf`. `iat > current_time + clock_skew` → `clock-skew-exceeded`. **Companion key-epoch cap**: Router tracks consumed-epoch ledger per `(customer_id, key_epoch)`; max 2 Tariffs per epoch; third → `tariff-key-epoch-cap-exceeded`. Any Tariff with `not_before > current_time + 604800s (7d)` MUST carry ceremony_quorum co-signature block; absence → `tariff-future-dated-requires-ceremony-quorum`. **Bound semantics**: the 2-per-epoch cap bounds non-adversarial operator error and chained-pre-signed-Tariff drift under non-compromised signer conditions. Because `key_epoch` is a signed payload field chosen by the signer, a compromised `K_tariff_signer` may enumerate distinct epoch values; the 2-per-epoch cap does NOT by itself bound adversary-issued Tariffs under key compromise (see §14 residual flag 9 / Sec-N4). Under key compromise, the binding bound is R8.T3 validity cap (≤30d) × revocation-channel propagation latency (§8), not R8.T2.
- **R8.T3 Validity period cap**: `(valid_until - not_before) > 2592000s (30d)` → `tariff-validity-period-excessive`. `valid_until ≤ not_before` → `tariff-validity-window-empty`. Not operator-configurable. Combined with R8.T2, total `iat`→`valid_until` ≤ 60d.
- **R8.T4 Strict unknown fields**: Top-level Tariff field set is a STRICT closed enum per this section. Unknown keys → `tariff-unknown-field`. Applies recursively to nested objects. No `extensions` map permitted. Schema evolution is via `version` only; unsupported `version` → `tariff-version-unsupported`.
- **R8.T5 Unknown integration_ref**: Unknown `integration_ref` (top-level, in `minimum_tiers` keys, in `rate_matrix` keys, any nested integration-scoped reference) MUST REJECT with `tariff-integration-unknown`. Router MUST NOT log-and-accept. Rollout ordering: deploy integration catalog updates to Routers BEFORE publishing Tariffs that reference them.

### 2.2.1 Operating hours schema (R8.A4, resolves B-3 adjacent)

Optional Tariff field `operating_hours` MAY express business-hours-only authorization:

```cbor
OperatingHours = {
  "timezone":          tstr,         // IANA name REQUIRED (e.g., "Europe/Berlin", not "+01:00")
  "windows":           [OpHoursWindow],  // SET-typed (R7.C6 §4.2.1)
  "default_action":    "allow" | "escalate-one-tier" | "require-step-up" | "reject",
  "applies_to_tiers":  [uint],       // e.g., [3, 4, 5]
  "exempt_mandate_ids": [tstr]       // break-glass exemptions for specific mandates
}

OpHoursWindow = {
  "day_of_week":       uint,         // 0 = Monday .. 6 = Sunday (ISO 8601)
  "start_minute":      uint,         // 0..1439
  "end_minute":        uint,         // 0..1440 (exclusive; 1440 = end of day)
  "label":             tstr?         // human-readable, e.g., "Mon-Fri business"
}
```

**Validation (at Tariff publish)**:
- `timezone` not a valid IANA zone name → `tariff-invalid-timezone`
- Two `windows` with same `day_of_week` whose `(start_minute, end_minute)` intervals overlap → `operating-hours-overlap`
- `end_minute ≤ start_minute` → `operating-hours-window-inverted`
- `day_of_week > 6` → `operating-hours-day-invalid`

**Semantics**: Windows do NOT cross midnight. Express "Mon 22:00 → Tue 06:00" as two windows. Router bundles IANA tzdata release ID in startup attestation; tzdata older than 180 days emits `TzdataStale` warning event (§11.2). Outside-hours intents invoke `default_action`; companion pattern `operating-hours-violation` (first-match, threshold=1, severity=high, auto-revoke) fires in the AnomalyPatternLibrary (§3.5).

**Full-day coverage check**: Multiple windows with the same `day_of_week` whose union covers `[0, 1440]` completely (with or without shared boundaries) REJECT with `operating-hours-full-day-coverage`. Operators seeking no time restriction for a given day MUST omit windows for that day entirely and rely on `default_action` (effectively "allow" if the day has no windows), rather than tiling adjacent windows to cover the full 24 hours. Prevents silent bypass of business-hours authorization by adjacent-tiled windows.

---

## 3. Aggregation Defense-in-Depth (six layers)

The Tariff mandates six layers to bound aggregation attacks (an attacker composing low-tier actions into a high-tier effect). Each layer has a specific role.

### 3.1 Layer 1 — Narrow mandates (protocol-enforced)
- Mandates with wildcard `*` in `cap` MUST have `budget.actions ≤ narrowness_threshold` (default 20).
- Mandates MUST specify `sub_resource` where the target API supports it.
- **Enforcement**: Router rejects non-compliant mandates at acceptance with `narrowness-rule-violation`.

### 3.2 Layer 2 — Cumulative rate matrix
Rate limits by verb × resource-kind × namespace × time-window. Enforced by Router in addition to per-tier limits.

### 3.3 Layer 3 — Stateful classifier with history
Classifier WASM reads `{current_intent, recent_actions, resource_state_snapshot, mandate_budget_remaining}`. May escalate tier based on aggregation pattern (e.g., "5× replica→0 in 60s" → Tier 4). Pattern-match threshold semantics normatively specified in §3.3.1.

### 3.3.1 Aggregation window semantics (R8.F3, resolves B-3)

**Normative**: Classifier aggregation window is 300 seconds by default, Tariff-configurable within range `[60, 900]` seconds via `aggregation_window_seconds` (optional Tariff field, default applies when absent).

**Window measurement**: `[now - window_seconds, now]`. Actions at exactly `t_offset = -window_seconds` are INCLUDED (closed-below). Classifier MUST drop actions older than the window to bound memory.

**Distinct from anomaly-detection thresholds**: §3.3.1 governs mid-stream tier bump decisions (single-intent classification with history). The AnomalyPatternLibrary at §3.5.1 governs revocation-firing thresholds (pattern-match across multiple actions). These operate at different lifecycle stages and MUST NOT be conflated.

### 3.4 Layer 4 — Target-level invariants (customer-domain precondition)
Strongest defense. K8s admission controllers, DB constraints, immutable backup rules. Tariff field `target_invariants_documented: bool` is customer attestation that these exist. If `false`, Tier 3+ auto-escalates to step-up.

### 3.5 Layer 5 — Anomaly detection on audit stream
Customer-operated service consumes signed audit stream, matches patterns from the AnomalyPatternLibrary, pushes revocation. Reference pattern library structure and MINIMUM patterns are normative (§3.5.1–§3.5.4).

### 3.5.1 AnomalyPatternLibrary artifact (R8.A1)

Anomaly detection MUST operate against a versioned signed artifact, NOT hardcoded pattern constants.

```cbor
AnomalyPatternLibrary = COSE_Sign1({
  "library_version":    uint,            // monotonic; distinct from Tariff version field
  "issued_at":          uint,
  "valid_until":        uint,
  "patterns":           [PatternEntry],  // SET-typed by pattern_id (R7.C6 §4.2.1)
  "issuer_constraints": {...}
}, signed_by: K_cust_anomaly_library_signer)
```

**Distinct signing key role (MANDATORY, resolves B-2)**: `K_cust_anomaly_library_signer` is a distinct child role under `K_cust_ops` in the delegation hierarchy (§7.1, §7.2). Libraries signed by `K_cust_ops` or any other delegation key REJECT with `pattern-library-signer-role-violation`. This prevents a single `K_cust_ops` compromise from both expanding mandate scope AND raising detection thresholds in one act.

**Chain shape**: `K_cust_root → K_cust_ops → K_cust_anomaly_library_signer` (three-level per R7.D1 §7.3.0). `anomaly_library_signer` is a terminal role — no sub-delegation.

**Threshold high-water-mark enforcement**: Router MUST track per-`pattern_id` high-water-mark of threshold strictness (smaller threshold = stricter; shorter window = stricter). A new library version that relaxes any pattern's threshold below its high-water-mark REJECTS with `pattern-library-relaxation-without-exception` UNLESS accompanied by a `PatternRelaxationException` co-signed by `ceremony_quorum` per §2.2. Tightening (lowering threshold, shortening window) is always accepted.

**Version monotonicity**: Libraries with `library_version ≤ current_pinned` reject with `pattern-library-version-too-old` (distinct from Tariff's `version-too-old` to discriminate artifact types in audit logs).

**Bootstrap high-water-mark (Sec-N7 mitigation)**: Router MUST bootstrap with a fixed spec-embedded HWM set derived from the MINIMUM pattern table at §3.5.4. Fresh Router nodes MUST NOT accept a library revision below that HWM as their first pinned baseline. Prevents attacker-race-to-loose-library bootstrap attack.

**Expiry semantics (normative)**: When `current_time ≥ AnomalyPatternLibrary.valid_until`, the library is EXPIRED. Router MUST emit `PatternLibraryExpired` high-severity audit event (§11.2) on expiry detection and on every subsequent Tier 3+ decision until a non-expired library is pinned. During the first 72 hours post-expiry, the Router MAY continue operating against the expired library BUT MUST treat every `severity ∈ {high, critical}` pattern evaluation as if it matched (fail-closed on high-severity detection). After 72 hours post-expiry with no fresh library, the Router MUST fail-closed on all Tier 3+ requests with `pattern-library-expired` until a non-expired library is pinned. Silent operation against a stale library is FORBIDDEN — expiry never silently continues.

### 3.5.2 Detector output semantics — severity-gated auto-revoke (R8.A2)

Each PatternEntry declares `action ∈ {alert, auto-revoke}` and `severity ∈ {low, medium, high, critical}`:

- `severity ∈ {high, critical}` MUST have `action = auto-revoke`. Revocation push SLA: 5s default, max 30s. Emit `AnomalyDetected` audit event (§11.2).
- `severity ∈ {low, medium}` MAY have `action = alert`. Operator response SLA: **300s**; on SLA elapse without acknowledgment or `AnomalyFalsePositiveDeclaration`, auto-escalate to revocation and emit `AnomalyAlertEscalatedToRevoke`.

**False-positive governance**:
1. Auto-revoked mandates restored via `ceremony_quorum`-cosigned `AnomalyFalsePositiveDeclaration`.
2. ≥3 FP declarations per `(pattern_id, match_scope)` in 30-day rolling window emits `PatternTuningRecommended` high-severity event.
3. A single detector instance revokes at most one `mandate_id` (or one `operator_id`'s mandates) per match; cross-customer or cross-operator revocation requires `ceremony_quorum`.
4. During revocation-channel grace period (§8.4), detector continues emitting for queued delivery.

### 3.5.3 Firing rule taxonomy (R8.A3)

Each PatternEntry declares `firing_rule ∈ {first-match, sequence-match, cumulative-over-baseline}`. The legacy "N-consecutive" firing mode is NEVER valid.

- **`first-match`**: Fire on the first event crossing threshold within sliding window. Applies to: `delete-storm`, `iam-attach-policy-storm`, `vault-rotate-storm`, `git-force-push-storm`, `fanout-distinct-resources`, `machine-pace`.
- **`sequence-match`**: Fire on ordered event-sequence completion. Applies to: `cross-tier-escalation`, `dwell-then-strike`, `canary-window-second-tier3`, `long-silence-before-burst`.
- **`cumulative-over-baseline`**: Fire when rolling-count ≥ threshold at any evaluation step. Applies to: `slow-burn-*`, `spread-across-*` variants.

**Anti-walk-under property (normative)**: Every `first-match` pattern with window ≤ 3600s MUST declare `firing_rule_companions: [pattern_id]` naming ≥1 `cumulative-over-baseline` pattern with window ≥ 10× its own window. Orphaned short-window patterns emit `PatternLibraryIncomplete` warning; Router refuses to load such a library into production. Closes "operate just below N-threshold in slower cadence" walk-under attack.

**PatternRelaxationException enforcement**: When a `PatternRelaxationException` removes or loosens a `cumulative-over-baseline` pattern, the Router MUST re-run the anti-walk-under companion-pair check across the resulting library state BEFORE applying the exception. Any exception that would orphan a short-window `first-match` pattern (by removing or weakening its sole companion) REJECTS with `pattern-relaxation-orphans-companion`, regardless of the exception's `ceremony_quorum` cosignature. The ceremony co-signature authorizes threshold relaxation on individual patterns; it does not authorize dismantling the companion-pair invariant.

### 3.5.4 MINIMUM pattern library (R8.A1 §3.5.4)

A v3-conformant deployment MUST enforce a library covering at least these ten MINIMUM patterns:

| pattern_id | window | threshold | scope | action |
|---|---:|---:|---|---|
| `delete-storm` | 60s | 5 | `(verb=delete, resource_kind, mandate_id)` | auto-revoke |
| `iam-attach-policy-storm` | 30s | 3 | IAM Attach* verbs, same mandate | auto-revoke |
| `vault-rotate-storm` | 300s | 5 | `(verb=rotate, resource_kind=secret, mandate_id)` | auto-revoke |
| `git-force-push-storm` | 60s | 3 | protected branches, same mandate | auto-revoke |
| `fanout-distinct-resources` | 60s | 10 distinct refs | same `(verb, mandate_id)` | auto-revoke |
| `cross-tier-escalation` | 300s | 1 sequence | T0→T2+→T3+ overlapping scope, same mandate OR operator | auto-revoke |
| `canary-window-second-tier3` | Tariff-declared, default 600s | 2 (second observation) | any mandate under same Signer PCR set | auto-revoke |
| `unusual-delegation-depth` | — | chain_depth > 3 | any mandate | auto-revoke (fires at depth 4, hard cap 4 per R7.D3) |
| `machine-pace` | 1s | 10 | `tier ≥ 1 AND verb ∉ read_only_verbs`, same mandate | auto-revoke |
| `long-silence-before-burst` | 300s burst | 20 | silent ≥ 604800s then burst | auto-revoke |

Operators MAY tighten (lower N, shorter window); loosening requires `PatternRelaxationException` co-signed by `ceremony_quorum`, itself audit-logged via `PatternRelaxationDeclared` event.

### 3.6 Layer 6 — Network kill switch
Customer can cut Router egress to target APIs via cloud NACL/SG. Last-resort response.

**Explicitly acknowledged residual**: an attacker operating strictly below rate-matrix thresholds, using no known aggregation pattern, with `target_invariants_documented: true` does eventually succeed in accumulated damage. This is a fundamental limit of tier-based schemes (see `redteam-round3.md` V3-2).

---

## 4. The Classifier

### 4.1 Role
Customer-authored WebAssembly module. Inputs an intent + context; outputs a tier recommendation. Tariff pins its hash; only this exact WASM runs.

### 4.2 Intent normalization (Router-side, pre-classifier)

Router applies canonicalization before passing intent to classifier. The pipeline is normative; non-conformant Routers are non-compliant with v3.

**Canonicalization rules (R7.C1–C5, C9, C10)**:

- **R7.C1 Case-folding scope**: `verb` and `resource_kind` MUST be lowercased (full Unicode Default Case Folding). `namespace` and `name` MUST be case-PRESERVED (treated as opaque identifiers per RFC 3986 §6.2.2.1). Non-ASCII case mapping uses Unicode Default Case Folding (UTS #39 §5, `toCasefold`), locale-independent.
- **R7.C2 Parameter keys**: Two parameter keys that differ only by Unicode Default Case Folding MUST cause REJECT with `normalization-not-applied`. Router MUST NOT auto-lowercase parameter keys; case-collision is an authoring error.
- **R7.C3 Unicode normalization form**: Canonical form is **NFC**. Inputs failing `input == nfc(input)` byte-equality are REJECTED with `unicode-not-nfc`. Silent conversion is forbidden.
- **R7.C4 Null vs missing key**: An explicit null value (`{"x": null}`) is REJECTED with `null-value-forbidden`. Canonical intent contains only present, non-null keys. Missing-key is not null; explicit-null-value is never canonical.
- **R7.C5 Size limits**: `max_string_bytes = 4096`; `max_key_bytes = 256`; `max_object_depth = 8`; `max_array_length = 256`; `max_total_intent_bytes = 65536`. Exceeding each produces a specific reject code: `max-string-length-exceeded`, `max-key-length-exceeded`, `max-depth-exceeded`, `max-array-length-exceeded`, `max-intent-size-exceeded`.
- **R7.C9 Identifier separator escaping**: Canonical identifier form is `<kind>/<namespace>/<name>` with solidus `/` as an exclusively structural separator. No `/` is permitted in any component. Reject code: `identifier-separator-forbidden`.
- **R7.C10 Locale neutrality**: All case operations use Unicode Default Case Folding per UTS #39 §5. Locale-specific mappings (Turkish `tr`/`az`, Lithuanian `lt`, German `de-DE-1996`) are FORBIDDEN.

**Pipeline ordering**: §4.2.2 specifies the four-step canonicalization pipeline. Control-character handling (§4.2.3) MUST execute BEFORE NFC validation (R7.C3) to prevent malicious NFC-bypass via invisible code points.

### 4.2.1 Array shape typing — SET vs SEQUENCE (R7.C6, resolves B-4)

Arrays in canonical intent and in signed artifacts (Tariff, Mandate, DelegationDocument, AnomalyPatternLibrary, PCRRequirement) have field-specific typing:

**SET-typed fields** (canonicalized by byte-lexicographic sort + deduplication; membership by byte-compare post-NFC — all members are already NFC per R7.C3 enforcement in step 2(b), so post-NFC byte-compare is complete for deduplication):

- `Mandate.cap[].verb` (and `.resource_kind`, `.sub_resource`)
- `DelegationScope.integrations` (explicit enumeration; no wildcard per R7.D4)
- `DelegationScope.allowed_verbs`
- `DelegationScope.allowed_resource_kinds`
- `Tariff.step_up_allowlist`
- `Tariff.pcr_attestors`
- `Tariff.ceremony_quorum.signers`
- `Tariff.integration_config.protected_branches`
- `Tariff.integration_config.acme.ct_compliant_cas`
- `PCRRequirement.trusted_transparency_logs` (R8.P3; members keyed by `log_id`)
- `PCRRequirement.trusted_witnesses` (R8.P6; members keyed by `log_id`; `provider` is informational)
- `OperatingHours.windows` (R8.A4; members keyed by tuple `(day_of_week, start_minute, end_minute)`)
- `AnomalyPatternLibrary.patterns` (R8.A1; members keyed by `pattern_id`)

**SEQUENCE-typed fields** (order preserved; duplicates permitted; membership by positional index):
- `recent_actions` (chronology)
- `delegation_chain` (parent-to-child priority; depth-limited per R7.D3)
- audit event streams (causal order)
- positional parameter arrays in intent payloads

**Extension policy**: Future SET-typed fields introduced in subsequent rounds MUST be added to this enumeration explicitly. Validator harnesses MUST apply byte-compare post-NFC SET semantics only to fields enumerated here; silent extension is a specification violation.

### 4.2.2 Canonicalization pipeline ordering (R7.C7)

The canonicalization pipeline is normative and ordered:

1. **Parse external format** → in-memory structural representation (UTF-8 strings, typed numbers, arrays, objects). Reject malformed encoding at this stage.
2. **Canonicalize in-memory structure** → apply rules in this intra-step order:
   (a) R7.C8 (control-char reject — rejects invisible and bidi code points)
   (b) R7.C3 (NFC validation — rejects non-NFC inputs)
   (c) R7.C1 (case folding — applied to `verb` and `resource_kind` only)
   (d) R7.C10 (locale neutrality — enforced alongside R7.C1)
   (e) R7.C4 (null-value reject)
   (f) R7.C5 (size limits)
   (g) R7.C9 (identifier-separator enforcement)
   (h) R7.C6 (array shape: SET sort + dedup; membership by byte-compare post-NFC).

   The R7.C8 → R7.C3 ordering is load-bearing: invisible code points that would NFC-compose with adjacent characters MUST reject before any normalization attempt. Implementations reversing this order permit NFC-bypass via ZWJ/ZWNJ injection.
3. **Serialize to deterministic CBOR** per RFC 8949 §4.2 (deterministic encoding: sorted map keys, no indefinite lengths, shortest-form integers).
4. **Compute hash / COSE_Sign1** over the deterministic CBOR bytes.

Canonicalization NEVER happens on JSON or CBOR byte streams directly. Attempts to canonicalize at the byte level (e.g., "sort JSON keys as strings") are a specification violation — canonicalization is structural, serialization is byte-level.

### 4.2.3 Invisible and bidi character policy (R7.C8)

Any string-typed field (intent params, identifiers, Tariff string fields, Mandate fields, etc.) containing any of the following Unicode code points REJECTS with `invalid-control-char`:

- Soft Hyphen: `U+00AD`
- Combining Grapheme Joiner: `U+034F`
- Zero-Width Space, Zero-Width Non-Joiner, Zero-Width Joiner: `U+200B..U+200D`
- Word Joiner: `U+2060`
- Zero-Width No-Break Space / Byte Order Mark: `U+FEFF`
- Bidi overrides: `U+202A..U+202E` (LRE, RLE, PDF, LRO, RLO)
- Bidi isolates: `U+2066..U+2069` (LRI, RLI, FSI, PDI)
- Tag characters: `U+E0000..U+E007F`

**Ordering**: This check MUST execute BEFORE R7.C3 NFC validation in the pipeline. A string containing Zero-Width Joiner that would NFC-normalize to a visually distinct sequence is rejected upfront, not silently re-normalized.

**Rationale**: Closes UI spoofing (homoglyph attacks), signed-value drift (invisible characters in `name` field causing scope-match false-positive), and NFC-bypass injection. See UTS #39 §5.5 confusable detection.

### 4.3 Context provided to classifier
```
ClassifierContext = {
  canonical_intent:          CanonicalIntent,
  recent_actions:            [ActionSummary],   // SEQUENCE, capped N
  resource_state_snapshot:   {...},             // Router-cached, populated at intent creation
  mandate_budget_remaining:  int
}
```

Classifier MUST be hermetic: no network access, no target-API queries (populated by Router per §5.3). This preserves enclave-verifiability, eliminates TOCTOU windows, and avoids latency-coupling.

### 4.4 Classifier baseline fuzz corpus (Round-6 V3-8 tightening, extended by R8.F1–F8)

**Normative**: Every v3-conformant reference implementation ships with a baseline fuzz corpus published at `fuzz-baseline.cbor` (hash `H_baseline_fuzz`). The corpus covers:
- All destructive verbs recognized by the target-API schema.
- All known resource-kind synonyms (e.g., `deploy`, `deployment`, `deployments.apps`).
- All historical attack patterns from the anomaly-detection pattern library.
- Edge cases: null values, empty strings, maximum-length params, nested object permutations at depth 4.
- Boundary cases for each R8.F1–F8 tier-floor rule below.

A Tariff publish action MUST include `classifier_fuzz_attestation` — the hash of a fuzz report produced by running the specified `classifier_wasm_hash` against the union of (a) `fuzz-baseline.cbor` and (b) customer-augmented corpus. Router verifies: (a) `classifier_wasm_hash` is correct, (b) baseline fuzz was included (by checking the report references `H_baseline_fuzz`), (c) no baseline case returned a tier below `minimum_tiers` expectation. A Tariff whose fuzz report fails any baseline case is REJECTED at Router startup.

Customer's custom fuzz patterns **augment** but do not **replace** the baseline.

**Tier assignments (R8.F1–F8, normative baseline)**:

- **R8.F1 fieldSelector on nodeName**: Single `list` on a `resource_kind` = Tier 0 (K8s RBAC treats selector filters uniformly). Classifier emits `justification_tag = reconnaissance-pattern-detected` and assigns Tier 1 when ≥5 `list` ops on same `resource_kind` within 120s with varying selector field values. Applies to `spec.nodeName`, `metadata.ownerReferences.uid`, `spec.serviceAccountName`, Vault variable-prefix paths, cloud resource-lister filters. Router-side rate-limit 100 list-ops per mandate per hour.
- **R8.F2 Sensitive-path bump**: Single `prod/*` secret read = Tier 2 baseline. Bumps compose additively per §2.1. Default `sensitive_path_patterns` = `{prod/*, root/*, admin/*, ceremony/*}` (legacy-compatible minimum). Operators SHOULD adopt the reference set shipped at `conformance/reference-sensitive-paths.json` (v1.0.0) — ~190 gitignore/CODEOWNERS-style globs (114 MUST, 74 SHOULD) across 7 categories (Git refs, CI/CD workflows, build/container files, dependency manifests, secrets/credentials, IaC, legacy defaults) with MUST/SHOULD/WHITELIST classifications and tariff-embedding guidance — or equivalent coverage demonstrably mitigating the Sec-N5 Git/supply-chain dead-zone (see §14 residual flag Sec-N5). Match-grammar (gitignore-style + Git refspec with `~DEFAULT_BRANCH` sentinel), false-positive hotspots, and incident-to-category mapping (xz-utils CVE-2024-3094, tj-actions CVE-2025-30066, SpotBugs/reviewdog chain, Shai-Hulud, axios 2026, event-stream, ua-parser-js, node-ipc, Codecov) are documented in the reference artifact.
- **R8.F3 Aggregation window**: Default 300s, range `[60, 900]`, closed-below semantics. See §3.3.1 for full specification.
- **R8.F4 kubectl drain**: Drain = Tier 3 floor uniformly. State-snapshot bumps: `has_stateful_pods=true` (+1 → Tier 4); `pdb_violation_imminent=true` (+1); `is_control_plane_node=true` (+2 → Tier 5). Missing snapshot on Tier 3+ triggers `target-invariants-missing` bump. Classifier MUST NOT query K8s API; Router populates snapshot at intent creation per §5.3.
- **R8.F5 Canary-window bump**: +1 uniform with sensitive-path carve-out. Rules: (a) pre-bump tier ≥ 3 → +1 (default); (b) pre-bump = 2 AND sensitive-path already applied → +1 (closes prod/* Tier 2 secret-read dead-zone); (c) pre-bump = 2 without sensitive-path → no bump (routine frictionless); (d) pre-bump ≤ 1 → no bump. Cap Tier 5; no per-integration variance. Companion pattern `canary-window-sensitive-path-repeat` (first-match, high severity, auto-revoke) fires on ≥3 distinct sensitive-path Tier 2 actions within the canary window.
- **R8.F6 Git default-branch frozen-at-issuance**: `git:push:default_branch` = Tier 2 bound to `integration_config.default_branch` frozen at Tariff issuance. Classifier consults pinned value regardless of literal name (main, master, trunk, develop, release/current). Rename on hosting provider does NOT take effect until next Tariff refresh — prevents mid-session rename-escape. Also: `git:push:protected_branch` = Tier 2 from `integration_config.protected_branches`; `git:push:branch` (other) = Tier 1.
- **R8.F7 DNS apex uniform Tier 4**: Apex records (A, AAAA, CNAME, MX, NS, TXT including SPF/DKIM/DMARC) = Tier 4. TTL-conditional tiering is REJECTED: TTL is informational only and MUST NOT alter tier. `dns:update:ns` at any zone level = Tier 4. Subdomain A/AAAA = Tier 3.
- **R8.F8 ACME wildcard issuance**: `acme:issue_wildcard:certificate` = Tier 3 floor IFF issuing CA is in `integration_config.acme.ct_compliant_cas` (Tariff-frozen allowlist; default set: Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, DigiCert, Sectigo). Non-CT-compliant CA → Tier 4. `acme:revoke:certificate` = Tier 3 (fast revocation mitigates blast radius). Classifier MUST NOT perform live CT lookups; it consults the frozen allowlist only.

### 4.5 Classifier output
```
ClassifierOutput = {
  tier:             0..5,
  reason_code:      tstr,                  // machine-readable
  reason_text:      tstr,                  // human-readable for audit
  escalations:      [tstr],                // triggered escalation codes (SEQUENCE)
  justification_tag: tstr                  // space-separated bump names (R8.F2 composition)
}
```

---

## 5. Mandate and Capability (Tier 2+)

### 5.1 Mandate

```cbor
Mandate = COSE_Sign1({
  "mandate_id":            ulid,
  "integration_ref":       tstr,
  "cap":                   [cap_entry],      // SET-typed (R7.C6 §4.2.1); narrow scope
  "budget":                {actions, tokens, $currency},
  "issued_at":             uint,
  "exp":                   uint,             // typ 4h (R7.D2 half-open)
  "min_tariff_version":    uint,
  "purpose":               tstr,             // human context
  "operator_id":           tstr,
  "revocation_channel_ref": tstr,
  "signer_key_hint":       tstr              // which K_cust_mandate_N
}, signed_by: K_cust_mandate_N)
```

**Mandate structural constraints (R7.D5)**:
- `cap` MUST be non-empty: `len(cap) ≥ 1`. An empty cap list rejects with `mandate-empty-cap`.
- Each `cap[i]` MUST have non-empty `verb` AND non-empty `resource_kind`. Malformed entries reject with `mandate-cap-malformed`.
- Because `cap` is SET-typed (R7.C6), duplicates are eliminated at canonicalization. After deduplication, `len(cap) ≥ 1` still applies (a cap list of all duplicates reducing to 1 remains valid).

**Validity window (R7.D2)**: `[issued_at, exp)` is half-open. At `current_time ≥ exp`, the mandate is expired and rejects with `expired`. `exp > issued_at` required (strict); violation rejects with `validity-window-empty`. Same rule applied uniformly to DelegationDocument (`[valid_from, valid_until)`) and Capability (`[issued_at, exp)`).

**Verification**: signature chain (see §7.3 scope-match + §7.3.0 role hierarchy + §7.3.1 chain depth) + validity window + Tariff-version-adequate + narrowness check.

### 5.2 Capability (per-action, Router-issued after Signer blessing)

```cbor
Capability = COSE_Sign1({
  "capability_id":         ulid,
  "mandate_ref":           ulid,
  "canonical_intent":      {verb, resource, params},
  "resource_version":      tstr,             // Tier 3+: target-API etag/rv
  "exp":                   uint,             // typ 90s
  "dpop_jkt":              jwk_thumbprint,   // sender-constrained
  "pdp_decision_log_ref":  tstr
}, signed_by: K_signer_ephemeral)
```

`K_signer_ephemeral` is held by the Signer Service enclave (§9).

### 5.3 Resource-version binding (Tier 3+)
Router reads target API's current resource version BEFORE minting capability. Capability includes it. Target API rejects the action if its current version differs — prevents blind destructive operations against unexpected state.

---

## 6. User-device step-up (Tier 4+)

### 6.1 WebAuthn protocol v3 (from v3 §3.3, unchanged)
- Device UI MUST show intent params verbatim.
- Mandatory ≥8s review delay before approve is enabled.
- Challenge payload includes 6-digit confirmation code; user types it (not taps).
- Per-user per-hour Tier 4+ limit (default 5). Exceeding triggers fresh biometric + password.
- Device UI shows last-5-approvals history for this mandate.

### 6.2 Device attestation
Device must be in Tariff's `step_up_allowlist` (WebAuthn credential public key). Assumption B16: device uncompromised as a system.

---

## 7. Key hierarchy and delegation

### 7.1 Three-level hierarchy (resolves B-1)

```
K_cust_root                       — HSM, rare use, ceremony-only, 2-5 year rotation
K_cust_ops                        — HSM with M-of-N officer policy, 90-day rotation
K_cust_mandate_*                  — Operational mandate-signing keys, 7-day rotation
K_tariff_signer                   — Operational Tariff-signing key (NEW, B-1 resolution)
                                    Child of K_cust_ops, 7-day rotation, dedicated role
K_cust_anomaly_library_signer     — Operational AnomalyPatternLibrary-signing key (NEW, B-2)
                                    Child of K_cust_ops, 7-day rotation, dedicated role
```

Plus supplementary keys:
```
K_cust_root_spare                 — Offline, geographically separated, pre-activated
K_cust_audit                      — Customer HSM, signs audit countersignatures (§9.4)
```

**Rationale for distinct operational roles** (R8 integration): Each of `K_cust_mandate_*`, `K_tariff_signer`, and `K_cust_anomaly_library_signer` is a distinct child role under `K_cust_ops`. The separation prevents a single operational-key compromise from achieving multiple attack objectives simultaneously — e.g., expanding mandate scope AND raising detection thresholds, or emitting a chained-pre-signed Tariff sequence AND weakening the pattern library.

### 7.2 DelegationDocument (resolves B-2)

```cbor
DelegationDocument = COSE_Sign1({
  "parent_key":            pubkey,                  // must match verifier's trust anchor
  "child_key":             pubkey,
  "child_role":            ChildRole,               // enum, see below
  "scope":                 DelegationScope,
  "valid_from":            uint,                    // R7.D2 half-open
  "valid_until":           uint,
  "revocation_channel":    tstr,
  "issuer_constraints":    {...}
}, signed_by: parent_key)

ChildRole = "ops"
          | "mandate_signer"
          | "tariff_signer"
          | "audit_signer"
          | "anomaly_library_signer"              // NEW (B-2 resolution)
```

**Role semantics**:
- `ops`: intermediate role; MAY sub-delegate to `mandate_signer`, `tariff_signer`, `audit_signer`, or `anomaly_library_signer`.
- `mandate_signer`, `tariff_signer`, `audit_signer`, `anomaly_library_signer`: terminal roles; MUST NOT sub-delegate.

### 7.3 Delegation scope-match table (V3-1, extended by R7.D1/D3/D4)

**Normative**: Router MUST verify at mandate acceptance that the mandate's assertions are in-scope for its signing-key's delegation. Implementation is a field-by-field match table:

```
DelegationScope = {
  "integrations":          [tstr],        // SET; explicit enumeration required (R7.D4)
  "max_tier_signable":     0..5,          // ceiling for any mandate.cap
  "max_budget":            Budget,        // per-mandate budget ceiling
  "max_exp_seconds":       uint,          // mandate.exp must be ≤ issued_at + this
  "allowed_verbs":         [tstr],        // SET; strict allowlist of canonical verbs
  "allowed_resource_kinds":[tstr]         // SET; strict allowlist of canonical kinds
}
```

**R7.D4 Wildcard restriction on integrations**: `integrations: ["*"]` is FORBIDDEN at every delegation level. Explicit enumeration of each integration_ref is required. Wildcard REJECTS with `scope-integrations-wildcard-forbidden`. Wildcard is still permitted in `allowed_verbs` and `allowed_resource_kinds` (subject to §3.1 narrowness rule).

Verification checks (must ALL pass after §7.3.0 role-hierarchy and §7.3.1 chain-depth pre-checks; any failure = REJECT):

| Mandate field | Scope check | Reject code on failure |
|---|---|---|
| `integration_ref` | `∈ scope.integrations` | `scope-integration-mismatch` |
| `cap[].tier` (resolved via Tariff) | `max(tiers) ≤ scope.max_tier_signable` | `scope-tier-exceeded` |
| `cap[].verb` | `∈ scope.allowed_verbs` | `scope-verb-forbidden` |
| `cap[].resource_kind` | `∈ scope.allowed_resource_kinds` | `scope-resource-kind-forbidden` |
| `budget.actions` | `≤ scope.max_budget.actions` | `scope-budget-exceeded` |
| `budget.tokens` | `≤ scope.max_budget.tokens` | `scope-budget-exceeded` |
| `exp - issued_at` | `≤ scope.max_exp_seconds` | `scope-expiry-too-long` |

**Conformance test vectors**: v3 reference implementation ships with `delegation-scope.json` — 68 (delegation, mandate) pairs labeled allow/deny. Any v3-conformant Router MUST match all labels.

### 7.3.0 Role hierarchy enforcement (R7.D1)

**Normative**: Chain shape MUST be `root → ops* → mandate_signer` for mandate verification (0..N intermediate `ops` sub-delegations between root and the terminal `mandate_signer`). Direct `K_cust_root → mandate_signer` delegation is REJECTED with `role-hierarchy-violation`. Chains terminating at `tariff_signer`, `audit_signer`, or `anomaly_library_signer` follow the same `root → ops* → <terminal>` shape (see "Analogous constraints" below). Terminal roles (`mandate_signer`, `tariff_signer`, `audit_signer`, `anomaly_library_signer`) MUST NEVER appear as the first delegation link from `K_cust_root`; they are reachable only via at least one intermediate `ops` delegation.

**Formal constraint**: Let `R(k)` denote the `child_role` of the delegation link whose `child_key = k`. A chain `[d1, d2, ..., dN]` from `K_cust_root` to `K_cust_mandate_X` (or any terminal role) is valid only if:
- The first delegation link's `child_role` MUST be `ops`. A first link with any terminal role (`mandate_signer`, `tariff_signer`, `audit_signer`, `anomaly_library_signer`) directly under `K_cust_root` REJECTS with `role-hierarchy-violation` — this closes the single-compromise-at-root → terminal-role collapse attack path.
- The final delegation link's `child_role` is the intended terminal (`mandate_signer` for mandate chains; `tariff_signer`, `audit_signer`, or `anomaly_library_signer` for their respective chains).
- For intermediate links `di` (where `1 < i < N`): `R(di.child_key) = "ops"` (intermediates preserve the `ops` role; the chain cannot change role mid-traverse).
- A terminal-role `child_role` may NOT be followed by a further delegation — terminal-role keys do not sub-delegate.

**Analogous constraints for terminal non-mandate roles**:
- A chain terminating at `K_tariff_signer` has final `child_role = "tariff_signer"`. First link is `ops` (via `root → ops`), subsequent intermediates preserve `ops`, terminal is `tariff_signer`. Tariff-signing keys do not sub-delegate.
- A chain terminating at `K_cust_audit` has final `child_role = "audit_signer"`; same shape.
- A chain terminating at `K_cust_anomaly_library_signer` has final `child_role = "anomaly_library_signer"`; same shape.

This check MUST execute BEFORE the §7.3 scope-match evaluation. Role-hierarchy failure is a structural rejection and logs prominently in audit.

### 7.3.1 Chain depth limit (R7.D3)

**Normative**: `delegation_chain` MUST contain at most 3 DelegationDocument entries (4 keys total: root + up to 2 intermediates + terminal). Chains exceeding this REJECT with `chain-depth-exceeded`.

**Valid chain shapes** (mandate-signing example):
- `root → ops → mandate_signer` (3 keys, 2 links) — standard.
- `root → ops → ops' → mandate_signer` (4 keys, 3 links) — `ops` sub-delegation for delegated administration.
- Chains longer than 3 links are forbidden.

**Rationale**: Bounds verification complexity, bounds operational-key-compromise blast radius, matches operator deployment patterns observed across HashiCorp Vault delegation, AWS IAM assume-role chains (typically ≤3 hops), and SPIFFE trust domain federation.

### 7.4 Verification chain (mandate verification)
1. Fetch delegation from `K_cust_mandate_N` upward to `K_cust_root`.
2. Verify chain shape (§7.3.0 role hierarchy — reject on violation).
3. Verify chain depth ≤ 3 links / 4 keys (§7.3.1 — reject on excess).
4. For each link: verify signature, validity window, revocation status.
5. For each link: perform scope-match check against the next-closer-to-mandate link's scope (per §7.3 table).
6. For the mandate itself: perform scope-match against `K_cust_mandate_N`'s delegation.
7. If any check fails: REJECT with specific failure reason (logged).

### 7.5 Rotation and revocation
- `K_cust_root`: 2-5 year rotation via coordinated Router-image rebuild.
- `K_cust_ops`: 90-day rotation via new delegation doc.
- `K_cust_mandate_*`: 7-day rotation via new delegation from `K_cust_ops`.
- `K_tariff_signer`: 7-day rotation via new delegation from `K_cust_ops`; rotation epoch tracked per R8.T2 `key_epoch` field in Tariff.
- `K_cust_anomaly_library_signer`: 7-day rotation via new delegation from `K_cust_ops`.
- `K_cust_audit`: 90-day rotation via new delegation from `K_cust_ops`.
- Revocation: level N publishes revocation list signed by level N-1 (or itself for root) to `revocation_channel`. Push-notified to Router (§8).

**Revocation cascade semantics** (resolves Sec-N6 residual): When `K_cust_root` revokes a `K_cust_ops` delegation, propagation to downstream child delegations is EXPLICIT per-child. Router MUST NOT implicitly assume that a parent-delegation revocation cascades to all children; each downstream revocation MUST be explicitly issued and distributed via the same `revocation_channel` mechanism. Conservative default: operators explicitly revoke each downstream key after parent revocation. This prevents race conditions between partial revocation distribution and active mandate acceptance.

**Chain-revocation inference (normative)**: Independent of explicit child-revocation distribution, any delegation chain whose traversal encounters a parent key present in ANY revocation list MUST REJECT with `parent-delegation-revoked`, even if the specific child link has not yet been explicitly revoked. Routers MUST recompute delegation-chain validity on every revocation-list update (not only on per-child revocation events). This closes the race window between parent revocation and child-revocation propagation: a compromised `K_tariff_signer` whose parent `K_cust_ops` has been revoked cannot continue issuing accepted Tariffs while awaiting its own explicit revocation.

### 7.5.1 Rotation cadence rationale (Phase 4 Review addition, informational)

The three-level hierarchy intentionally asymmetrizes rotation cadence. This table documents the tradeoffs; each row is a deliberate choice, not accidental inheritance:

| Key | Cadence | Rationale |
|---|---|---|
| `K_cust_root` | 2–5 years | Ceremony-bound. Rotation requires re-ceremony per §7.6; operational burden is high. Blast-radius on silent compromise is bounded by root-revocation list authority and by the out-of-band confirmation requirement in §7.6. |
| `K_cust_ops` | 90 days | Intermediate. Under M-of-N officer policy. 90d balances officer-ceremony cost against the cadence ratio with children. Silent compromise becomes stale within ~4 child rotations. |
| `K_cust_mandate_*`, `K_tariff_signer`, `K_cust_anomaly_library_signer` | 7 days | Terminal operational roles. Rapid rotation bounds blast radius: a compromised terminal key is stale within one week, and each successor is issued by an independently rotating parent credential. |
| `K_cust_audit` | 90 days | Audit countersignature is availability-critical (§11.3), not authorization-critical. Fast rotation risks write-unavailability without reducing authorization-compromise risk. |

**Acknowledged weak point**: `K_cust_ops` rotates 13× slower than its children. Child rotation cannot outpace silent parent compromise. Defense-in-depth compensates via: (a) audit-stream anomaly detection (§3.5) catches post-compromise anomalous delegation issuance; (b) push-revocation channel (§8) propagates compromise declarations in seconds; (c) root-level revocation list is authoritative and not gated by ops-key validity; (d) chain-revocation inference (§7.5) invalidates all downstream artifacts on parent revocation regardless of explicit per-child distribution.

**Operator guidance**: Operators who judge the 90d/7d parent/child ratio acceptable for their threat model MAY deploy as-specified. Operators requiring tighter ratios MAY configure `K_cust_ops` rotation to 30 days at ~3× increased officer-ceremony frequency. Shorter than 30d is not recommended: ceremony friction degrades compliance and introduces operational-mistake risk that typically exceeds the marginal compromise-latency improvement.

### 7.6 Root compromise recovery
1. Confirm root compromise via out-of-band trusted channels.
2. Coordinate Router-image rebuild with `K_cust_root_spare` as pinned trust anchor.
3. All DelegationDocuments re-issued under spare root (for `K_cust_ops`, then cascading explicit revocations for `K_tariff_signer`, `K_cust_anomaly_library_signer`, `K_cust_audit`, and all `K_cust_mandate_*`).
4. Former root added to root-revocation list.

Spare-activation is itself a multi-party ceremony (min 3 signers from geographically separate key custodians). Prevents Round-6 V3-4 social-engineering attack on spare activation.

---

## 8. Push revocation and its availability

### 8.1 Revocation mechanics (from v3)
Router subscribes to `revocation_channel` at startup. On revocation event:
1. Fetch revocation list (signed by issuer of the delegation being revoked).
2. Verify signature.
3. Apply: reject all future mandate uses referencing revoked keys.

### 8.2 Mandate-specific revocation
Router also subscribes to `mandate.revocation_channel_ref` for each active mandate. Same mechanism, finer-grained.

### 8.3 Fail-closed on Tier 3+
If push channel connection lost for more than `grace_period_seconds` (default 30s), Router fails-closed on Tier 3+ actions. Tier 0-1 continues on stale cache (bounded damage, already gated by OPA).

### 8.4 Round-6 tightening (V3-6): HA requirements for revocation channel

**Normative**: Tariff MUST specify `revocation_channel_ha`:

```cbor
revocation_channel_ha = {
  "primary_endpoint":      tstr,
  "secondary_endpoints":   [tstr],       // SET; min 2, different regions
  "multi_provider":        bool,         // must be true for Tier 4+ in Tariff
  "grace_period_seconds":  uint,         // default 30, max 300
  "admin_bypass_protocol": {             // explicit bypass, not silent
    "required_signers":    uint,         // min 3 from ceremony_quorum
    "max_duration":        uint          // max 3600 seconds
  }
}
```

Router behaviour:
- At startup: connect to primary. On failure: connect to all secondaries in parallel.
- If ALL endpoints unreachable for `grace_period_seconds`: fail-closed on Tier 3+.
- An admin can invoke `admin_bypass_protocol`: N-of-M customer signers co-sign a bounded-duration bypass declaration. Router resumes Tier 3+ operations with per-action audit flag `revocation_channel_bypassed: true`.
- Silent bypass (no `admin_bypass_protocol` invocation) is a protocol violation.

**Conformance**: Router MUST log a high-priority audit event on entering and leaving grace period, and when admin bypass is invoked.

---

## 9. Signer Service enclave

### 9.1 Role
Holds `K_signer_ephemeral` (Ed25519). Mints Capabilities for Tier 2+ intents. Isolated from the Router to bound RCE blast radius.

### 9.2 Isolation model
- Separate process (preferably separate Nitro Enclave instance).
- IPC only: receives PDP-approved intent + mandate ref, returns COSE_Sign1 capability.
- No network access beyond IPC channel.
- No LLM-client dependencies (key-loaded only after attestation).

### 9.3 Reproducible builds + multi-party PCR attestation (v3 §3.4)

Signer Service must be reproducibly built. Tariff's `signer_image_pcr_set` changes require quorum attestation from `pcr_attestors`. Canary window bounds blast radius of a subtly-modified image.

### 9.4 Round-6 tightening (V3-3): mandatory automated attestation pipeline

**Normative**: Every entry in `pcr_attestors` MUST be an **attestor service endpoint**, not a human identity. The attestor service:
1. Clones Signer source at specified commit hash.
2. Runs reproducible build pipeline in a fresh isolated environment (different from DeployCo's).
3. Computes PCR values from resulting artifact.
4. Signs `{commit_hash, pcr_values, attestor_id, timestamp}` with attestor's signing key.
5. Publishes signed attestation to a public transparency log (e.g., Sigstore's Rekor or equivalent).

Tariff's `pcr_attestation_evidence` field (mandatory for PCR changes) contains:
- Quorum of attestor signatures.
- Transparency-log inclusion proofs.
- Mismatch detection: any attestor whose computed PCR differs from Tariff's claimed value invalidates the entire attestation.

**Customer MUST verify** before Tariff signing:
- Quorum met.
- All attestors independently computed matching PCRs.
- Transparency-log inclusion proofs verify.

This closes the "rubber-stamp attestor" gap — human review is replaced by mechanized independent verification.

### 9.4.1 Normative PCR indices for Signer image hash (R8.P1)

Tariff MUST pin the exact PCR index set via `Tariff.pcr_requirement.expected_pcrs`:

```cbor
Tariff.pcr_requirement.expected_pcrs : {
  tstr → tstr       // PCR-index-label → 64-char lowercase SHA-256 hex
}
```

Recommended defaults for AWS Nitro: `PCR0` (image), `PCR4` (kernel/boot), `PCR8` (application payload). Router MUST treat every pinned index as mandatory; a bundle omitting any REJECTS with `pcr-expected-missing-in-bundle`. A bundle reporting PCR indices outside TPM 2.0 `[0,23]` or Nitro `[0,15]` REJECTS with `pcr-bundle-malformed`. An empty `expected_pcrs` map rejects with `tariff-pcr-expected-empty`.

### 9.4.2 Transparency-log Signed Tree Head maximum age (R8.P2)

Tariff MUST declare `pcr_requirement.transparency_log_max_root_age_seconds`:

```cbor
Tariff.pcr_requirement.transparency_log_max_root_age_seconds : uint  // range [1, 604800]
```

- Absence REJECTS with `tariff-pcr-sth-age-unset`.
- Value > 604800 (7 days) → `tariff-pcr-sth-age-too-lax`.
- Value ≤ 0 → `tariff-pcr-sth-age-invalid`.
- Recommended default: 86400 (24 hours).

At verification time, Router computes `root_age = current_time - sth_timestamp`:
- `root_age > max` → `pcr-attestation-transparency-stale`.
- `root_age < 0` (STH from future) → `pcr-attestation-transparency-invalid` (residual code).

### 9.4.3 Trusted transparency-log set pinning (R8.P3)

Tariff MUST declare `pcr_requirement.trusted_transparency_logs` as a non-empty SET-typed (R7.C6 §4.2.1) array:

```cbor
TrustedTransparencyLog = {
  "log_id":           tstr,         // e.g., "rekor.sigstore.dev/2024a"
  "public_key":       bstr,         // SubjectPublicKeyInfo DER per RFC 5280
  "key_alg":          tstr,         // "ed25519" | "ecdsa-p256-sha256" | "ecdsa-p384-sha384"
  "origin_url":       tstr?,        // optional
  "valid_from":       uint?,        // optional, half-open per R7.D2
  "valid_until":      uint          // required
}
```

- Members form a SET keyed by `log_id` (byte-compare post-NFC). Duplicate `log_id` → `tariff-pcr-trusted-logs-duplicate`.
- Empty array → `tariff-pcr-trusted-logs-empty`.
- Unsupported `key_alg` → `tariff-pcr-trusted-log-alg-unsupported`.
- At verify: bundle proof referencing `log_id` NOT in pinned set → `pcr-attestation-transparency-log-unknown`.
- STH signature verification failure → `pcr-attestation-transparency-invalid`.

### 9.4.4 Router-issued nonce binding (R8.P4)

Every `attestations[i]` in a PCR bundle MUST include a `nonce` field byte-equal to the Router's cycle nonce. Router maintains a consumed-nonce ledger.

**Nonce requirements**:
- ≥128 bits from CSPRNG.
- Tariff declares `pcr_requirement.nonce_ttl_seconds` (default 300, range [30, 3600]).
- Router rejects on first-seen reuse OR after `nonce_ttl_seconds` elapsed.

**Reject codes**:
- Nonce field missing → `pcr-attestation-nonce-missing`.
- Nonce ≠ Router's current challenge → `pcr-attestation-nonce-mismatch` (also serves TTL-elapsed case).
- Nonce present in consumed-ledger → `pcr-attestation-nonce-reuse`.
- Distinct nonces across `attestations[*]` within one bundle → `pcr-attestation-nonce-inconsistent` (closes split-attestor forgery).

**Rationale for TTL/mismatch conflation**: The TTL-elapsed case and value-mismatch case are deliberately indistinguishable to external callers to prevent timing oracles on the nonce-TTL boundary. For internal audit and operational diagnosis, Routers MAY emit a richer audit payload carrying `{reject_reason: "ttl-elapsed" | "value-mismatch"}` inside the audit event (§11.2) — operators analyzing rejections from the audit stream use this distinction; external parties observe only the indistinguishable `pcr-attestation-nonce-mismatch` response.

### 9.4.5 PCR bundle size cap (R8.P5)

Tariff MUST declare `pcr_requirement.bundle_max_size_bytes` in range `[4096, 1048576]`:

- Recommended default: 262144 (256 KiB).
- Value < 4096 → `tariff-pcr-bundle-max-size-too-strict`.
- Value > 1048576 → `tariff-pcr-bundle-max-size-too-lax`.
- Router MUST measure byte length BEFORE CBOR decoding; oversized → `pcr-bundle-too-large`.

Calibration: AWS Nitro single attestation is ~4-8 KiB; 5-attestor bundle ~50 KiB; 256 KiB default provides 5× headroom over practical deployments.

### 9.4.6 Split-view defense via witness cosignatures (R8.P6)

Tariff MAY declare `pcr_requirement.required_witness_cosignatures: uint` (default 0) and `trusted_witnesses` (SET-typed, see §4.2.1):

```cbor
TrustedWitness = {
  "log_id":           tstr,
  "public_key":       bstr,
  "key_alg":          tstr,
  "origin_url":       tstr?,
  "valid_from":       uint?,
  "valid_until":      uint,
  "provider":         tstr            // informational; "sigsum", "armored-witness", etc.
}
```

**Rules**:
- `required == 0`: no witness check (pre-Tier-4 configurations).
- `required > 0`: bundle MUST include `witness_cosignatures` array with ≥N distinct cosignatures verifying under distinct `trusted_witnesses` entries, each signing the same `(sth_tree_hash, sth_tree_size)`.
- Missing or undersized → `pcr-attestation-witness-cosignature-missing`.
- Signature verification failure on any cosignature → `pcr-attestation-witness-cosignature-invalid`.

**Tier 4+ MANDATORY**: For Tariffs supporting any Tier ≥ 4 intents, `required ≥ 2` AND `trusted_witnesses.length ≥ 3` spanning ≥2 distinct `provider` labels. Violation at Tariff publish:
- `required < 2` or `trusted_witnesses.length < 3` → `tariff-pcr-witnessing-insufficient-for-tier`.
- Witnesses span fewer than 2 distinct `provider` labels → `tariff-pcr-witnessing-single-provider`.

This mirrors §8.4 revocation-channel HA multi-provider requirement at the transparency-log tier.

### 9.5 Key lifecycle
- `K_signer_ephemeral` generated on Signer Service startup, non-exportable.
- Capabilities signed during normal operation.
- On Signer restart: old key discarded; new key generated.
- Router handles capability key rotation transparently (Capabilities reference the Signer's current public key, which Router binds to its attestation).

---

## 10. Router

### 10.1 Role
Orchestrates authorization flow per tier: classification → (optional) delegation verification → (optional) Signer call → (optional) step-up → action issuance → audit.

### 10.2 Per-integration isolation (v3 §3.5)
Separate Router process per integration. An RCE in one Router compromises Tier 0-1 for one integration only.

### 10.3 Tariff lifecycle
- Loaded at startup (signed, pinned).
- Updated via push to `tariff_update_channel` with monotonic `version`.
- Tariff update with `version ≤ current`: REJECTED with `version-too-old`.
- Tariff update during action flight: active action uses originally-pinned Tariff; next action uses new.
- R8.T2 `key_epoch` ledger: Router tracks consumed epochs per `(customer_id, key_epoch)`; max 2 Tariffs per epoch; third → `tariff-key-epoch-cap-exceeded`.

### 10.4 Decision flow (pseudocode)

```
on receive intent:
  canonical = normalize(intent)              // §4.2 + §4.2.1-§4.2.3
  tier = classifier.classify(canonical, context)

  apply_automatic_escalations(tier)          // §2.1 + R8.F composition
  check_operating_hours(tier, canonical)      // §2.2.1 R8.A4

  match tier:
    0: oidc_dpop_call(); audit(); return
    1: oidc_dpop_opa_call(); audit(); return
    2,3: require mandate; verify_delegation(mandate);   // §7.3.0 + §7.3.1 + §7.3
         if tier == 3: fetch resource_version
         cap = signer.mint(mandate, canonical, resource_version)
         bound_call(cap); audit(); return
    4: require mandate + step_up(user_device); ... as tier 3
    5: require mandate + ceremony(M-of-N signers); ... as tier 4
```

---

## 11. Audit log

### 11.1 Structure
Every decision point emits a signed audit event:
- Router-originated events signed by Router's ephemeral key.
- Audit-service countersignature with `K_cust_audit` (HSM, customer-held) before persist.
- Persistence: customer-chosen append-only store (S3 Object Lock, immutable Kafka, etc.).

### 11.2 Event types

**Authorization lifecycle** (from v3, unchanged):
- `MandateAccepted`, `MandateRejected`
- `CapabilityMinted`, `CapabilityUsed`, `CapabilityExpired`
- `TierEscalated` (with reason)
- `RevocationReceived`, `RevocationChannelGracePeriodEntered/Exited`
- `StepUpRequested`, `StepUpApproved`, `StepUpDenied`
- `CeremonyInitiated`, `CeremonyQuorumReached`, `CeremonyTimedOut`
- `TariffPublished`, `TariffRejected` (with reason)
- `AdminBypassInvoked`

**Anomaly + pattern-library lifecycle** (R8.A1–A2, new):
- `PatternLibraryLoaded`, `PatternLibraryRejected` (with reason, e.g., `pattern-library-version-too-old`, `pattern-library-relaxation-without-exception`)
- `AnomalyDetected` (payload: `{pattern_id, library_version, severity, firing_rule, match_scope}`)
- `AnomalyAlertEscalatedToRevoke` (SLA-timeout escalation)
- `AnomalyFalsePositiveDeclaration` (ceremony-cosigned restoration)
- `PatternTuningRecommended` (≥3 FP declarations in 30d rolling window)
- `PatternRelaxationDeclared` (ceremony-cosigned HWM exception)
- `PatternLibraryIncomplete` (R8.A3 anti-walk-under warning on library load)

**Operational context** (R8.A4, R8.T2, new):
- `TzdataStale` (tzdata release > 180d on Router)
- `TariffKeyEpochAdvanced` (new epoch observed)
- `TariffFutureDatedCeremonyInvoked` (not_before > now+7d, ceremony_quorum present)

### 11.3 Countersignature ensures integrity
An RCE'd Router cannot fabricate events indistinguishable from real ones — the audit service signs them with a key the Router never holds.

---

## 12. Minimum Viable variants (MV-0 through MV-3, graceful degradation)

Customers deploy progressively; not all deploy the full stack day one.

### MV-0: Tier 0-1 only, no EPHEMERAL machinery beyond audit
- Use: early customer without high-risk automation.
- Implementation: OIDC+DPoP+OPA+audit. This is the 80% alternative plus the Tariff-as-documentation.
- Forbidden: any action that Classifier would rate Tier 2+. Router rejects.
- Key hierarchy: `K_cust_root`, `K_cust_audit` only (no `K_cust_ops`, `K_tariff_signer`, etc.).

### MV-1: Add Tier 2 — Mandate+Capability
- Adds: Signer Service, Mandate/Capability format, `K_cust_ops`, `K_cust_mandate_*`, `K_tariff_signer`.
- Still forbids Tier 3+.
- AnomalyPatternLibrary optional (monitoring only, no auto-revoke).

### MV-2: Add Tier 3-4 — destructive + step-up
- Adds: push-revocation HA, WebAuthn protocol, device allowlist, mandatory `K_cust_anomaly_library_signer` with full MINIMUM pattern enforcement.
- Customer begins deploying target-level invariants.
- PCR attestation with 1-of-1 witness acceptable for initial deployment; 2-of-3 multi-provider target by 2027 (see §14 residual).

### MV-3: Full — add Tier 5 ceremony
- Adds: multi-party ceremony infrastructure, expanded `step_up_allowlist`, Tier-4+ mandatory multi-provider witness cosignatures (§9.4.6).

Each MV level is a valid v3-conformant deployment. Tariff's declared `maximum_tier` field is how Router knows which MV level applies.

---

## 13. What is novel vs. what is assembled

**Assembled from existing primitives**:
- Nitro Enclaves, SPIFFE/SPIRE, Ed25519, COSE_Sign1 (RFC 9052), DPoP, OIDC federation, OPA, WebAuthn, HSM, reproducible builds, Sigstore, S3 Object Lock, RFC 6962/9162 (Certificate Transparency 2.0 + witness cosignatures), UTS #39 (Unicode confusable detection), RFC 8949 (deterministic CBOR).

**Novel (as far as I know; external review needed)**:
1. **Proportional Authority Protocol / Impact Tiers**: the synthesis of tiered authority with automatic escalation based on context (target invariants, canary, aggregation patterns). Prior art: step-up authentication in OIDC (CIBA), capability hierarchies in Macaroons. Neither composes into a classification-driven proportional system.
2. **Tariff as customer-signed policy-and-authority document**: a single cryptographic artifact that declares action semantics + key hierarchy delegation + operational HA requirements. Prior art: OPA bundles (policy only), PKI delegation docs (trust only). The combination is new.
3. **Classifier-as-WASM with Router-provided stateful context**: customer-authored, cryptographically pinned tier classifier with access to recent-action history and resource state snapshot. Prior art: OPA data documents are stateless; Cedar has entity stores but not event history.
4. **Mandatory baseline fuzz corpus as Tariff precondition** (V3-8): spec-level requirement that a customer's classifier pass a shared reference corpus before a Tariff can publish. Closes the "forgotten pattern" gap.
5. **Automated attestation pipeline with transparency log for PCR changes** (V3-3, R8.P1–P6 extensions): replaces human-review attestors with mechanized independent builders whose outputs are publicly verifiable, extended with witness cosignatures to defend against log split-view attacks.
6. **Additive tier-bump composition with sensitive-path carve-out** (R8.F2/F5): tier assignment composes additively with a carve-out that closes Tier-2 prod-read dead-zones without over-friction on routine Tier-2 reads. New synthesis.
7. **Versioned signed AnomalyPatternLibrary with high-water-mark ratchet** (R8.A1): anomaly detection operates against a signed, tightening-only artifact with ceremony-quorum relaxation exceptions. Prior art: Sigma rules (no ratchet), fail2ban (unsigned), AWS GuardDuty (vendor-only).

Points 4–7 are Round-6/R8 operational tightenings. They close the gap between "protocol is sound" and "deployed system is sound" against realistic attackers.

---

## 14. Residuals (carried forward, not fixed)

1. **Sub-threshold aggregation**. Attacker within all rate limits, no known pattern, `target_invariants_documented: true` → slow accumulated damage possible. Bound by anomaly detection latency + rate matrix + mandate narrowness + AnomalyPatternLibrary `slow-burn` patterns. Not prevented. (V3-2, fundamental to tier-based schemes.)
2. **Root-of-trust compromise**. Standard PKI residual. Recovery via `K_cust_root_spare` + ceremony.
3. **Prompt injection via ingested content**. Mandate narrowness is primary mitigation; no cryptographic prevention.
4. **Target API compromise** (A5). Out of scope, audit-only.
5. **User-device malware** (B16). Out of scope beyond step-up UX protocol.
6. **Side channels, hardware attacks, model poisoning**. Out of scope.

**R8 operator-feedback residual flags** (pre-production concerns, tracked for Phase B instrumentation):

7. **R8.P6 Tier-4 witness-cosignature minimum (2-of-3 multi-provider)**: Witness supply-side (sigsum, armored-witness) is consolidating in 2026. Recommend Nitro-operator feedback round or phased rollout (1-of-1 → 2-of-3 between 2026 and 2027). MV-2 deployments in 2026 MAY operate at 1-of-1 with explicit operator acknowledgment; MV-3 by 2027 MUST reach 2-of-3 multi-provider.

8. **R8.F2 sensitive-path + canary composition on routine prod reads**: This is the largest operator-friction surface. The canary-bump precondition (pre-bump tier ≥ 3 from R8.F5) partly contains friction. Recommend Phase B instrumentation surfacing composition-above-Tier-3 rates with 30-day review before declaring operational stability.

9. **R8.T2 `key_epoch` self-declared attack surface** (Sec-N4): `key_epoch: uint` is written by the `K_tariff_signer` into the signed Tariff payload. An attacker with `K_tariff_signer` compromise can choose arbitrary values, making the 2-Tariff-per-epoch ledger a soft-defense only — it prevents drift-style mistakes but not deliberate adversary misuse. Future hardening SHOULD derive `key_epoch` from the signed delegation document (R7.D1 issuance time) or from the COSE `kid` structure rather than from the Tariff payload itself. Until derived, the cap is pseudo-protection against operator drift, not against key compromise.

10. **R8.F2/F6 canary dead-zone for Git branch operations** (Sec-N5): **PARTIALLY MITIGATED (2026-04-18).** The legacy default `sensitive_path_patterns` (`prod/*, root/*, admin/*, ceremony/*`) do not cover Git refs like `refs/heads/main` or `refs/heads/master`, CI/CD workflow files, dependency manifests, or IaC state. An attacker targeting `git:push:default_branch` at pre-bump Tier 2, or package.json/Dockerfile/workflow modifications in supply-chain attack patterns, slips under the sensitive-path carve-out. **Mitigation shipped:** `conformance/reference-sensitive-paths.json` (v1.0.0) — an operator-reference artifact providing ~190 patterns across 7 categories (Git refs with `~DEFAULT_BRANCH` sentinel, CI/CD workflows including reusable `action.yml` and GitLab include-local fragments, build/container files including generic `Makefile`, dependency manifests per ecosystem incl. Node/Python/Bun/Swift/Dart, secrets/credentials incl. SOPS-encrypted variants, IaC manifests incl. ArgoCD lowercase + AppProject, legacy defaults) with MUST/SHOULD/WHITELIST classifications, gitignore-style match grammar, false-positive hotspot guidance, scoped `!**/examples/**` and `!**/vendor/**` whitelist exceptions, and incident-to-category mapping covering OWASP 2025 A03 and 9 historical incidents (xz-utils CVE-2024-3094, tj-actions CVE-2025-30066, SpotBugs/reviewdog chain 2024-25, Shai-Hulud 2025, axios 2026, event-stream 2018, ua-parser-js 2021, node-ipc 2022, Codecov 2021). **Remaining residual:** the reference is an operator-facing default — individual Tariff authors still choose whether to inherit it or equivalent. Full closure requires (a) Phase B reference validator enforcing minimum coverage attestation at Tariff publish, and (b) annual refresh cadence against new incident telemetry. Reference artifact is not yet independently human-reviewed for false-negative gaps; second-pass review is a Phase B entry item.

11. **R8.A1 HWM bootstrap attack surface** (Sec-N7): A fresh Router node with no pinned high-water-mark accepts the first AnomalyPatternLibrary it observes as its baseline. An attacker able to race a relaxed library into initial sync establishes a loose baseline. §3.5.1 now requires Router nodes to bootstrap with the spec-embedded MINIMUM pattern table HWM (derived from §3.5.4). Phase B vectors MUST cover bootstrap-HWM-enforcement against attacker-first-library scenarios.

---

## 15. Conformance test suite (required for any implementation claiming v3-compliance)

Delivered with reference implementation (515 vectors across 6 files, spec_version `round8-delta-applied`):

1. `conformance/canonicalization.json` — 93 intent-normalization equivalence vectors (§4.2 + §4.2.1-§4.2.3).
2. `conformance/delegation-scope.json` — 68 (delegation, mandate) allow/deny pairs (§7.3 + §7.3.0-§7.3.1).
3. `conformance/fuzz-baseline.json` — 205 classifier fuzz-corpus tier-assignment vectors (§4.4 + R8.F1-F8).
4. `conformance/tariff-reject.json` — 68 malformed-Tariff rejection vectors (§2.2 + §2.2.1 + R8.T1-T5).
5. `conformance/pcr-attestation-reject.json` — 49 invalid-attestation rejection vectors (§9.4.1-§9.4.6).
6. `conformance/audit-replay.json` — 32 attack-audit-stream anomaly-detection vectors (§3.5.1-§3.5.4).

**Total new reject codes introduced by R7 + R8**: 50 (R7: 18, R8: 32). Full taxonomy cross-reference lives in `conformance/README.md`.

An implementation is v3-conformant only if it passes 100% of these vectors.

**Phase B boundary vectors** (~34 flagged for operator-led validator-harness scaffolding) extend coverage for R7.C9 identifier-separator, R7.D3 chain-depth boundary, R8.T2 key-epoch-cap boundary, R8.P6 witness-provider-diversity boundary, R8.F5 canary-sensitive-path carve-out, etc. These are authored in Phase B against the reference validator harness.

---

## 16. Deployment prerequisites (customer side, non-negotiable)

Before Tier 3+ is enabled:
1. `K_cust_root` generated in HSM, ceremony-attested.
2. `K_cust_root_spare` generated in geographically separate HSM.
3. `K_cust_audit` generated in HSM.
4. `K_tariff_signer` generated with 7-day rotation delegation from `K_cust_ops`.
5. `K_cust_anomaly_library_signer` generated with 7-day rotation delegation from `K_cust_ops`.
6. Target-level invariants deployed OR `target_invariants_documented: false` (with escalation understood).
7. Push-revocation endpoints deployed per `revocation_channel_ha` spec.
8. Anomaly-detection service deployed and consuming audit stream; AnomalyPatternLibrary covering all 10 MINIMUM patterns (§3.5.4) signed by `K_cust_anomaly_library_signer`.
9. At least 3 attestor services configured (automated, per §9.4).
10. At least 3 trusted transparency logs pinned in Tariff (§9.4.3).
11. Step-up device allowlist populated for Tier 4+ operators.
12. Ceremony signer registry populated for Tier 5.
13. Kill-switch runbook tested (network cut + effect).
14. Operating-hours IANA tzdata kept current (< 180d stale per §2.2.1).

Before Tier 5:
15. M-of-N ceremony quorum defined, diversity rules documented.
16. At least 3 trusted witnesses from ≥2 distinct providers pinned in Tariff (§9.4.6 mandatory for Tier 4+).
17. Periodic red-team ceremony tabletop exercises in place.

---

## 17. Honest limits (same as v3, reaffirmed)

- Still reviewed only by one LLM across six rounds (3 adversarial + 1 final consolidation + 2 operational tightening). External audit by an offensive security firm remains required before production deployment.
- No formal verification of the protocol composition.
- The aggregation residual (V3-2) is real and operational mitigations are the only meaningful defense.
- The novel parts (especially Proportional Authority, AnomalyPatternLibrary HWM ratchet, additive bump composition) have no production track record. Early deployments should treat MV-0 and MV-1 as genuine learning opportunities, not rubber-stamp pilots.
- R7/R8 residual flags (§14 items 9–11) are not fixed; they await operational feedback or future hardening passes.

---

## 18. Decision

With Round 6 Red Team producing no new showstoppers, with the Round 6 spec tightenings integrated (V3-1 scope-match table, V3-3 automated attestation, V3-6 HA spec, V3-8 baseline fuzz), with R7 + R8 operational tightenings landed (15 canonicalization/delegation + 23 operational = 38 spec-ambiguity resolutions), and with a 4-agent Phase 4 Review Swarm having validated the integrated specification and surfaced 2 CRIT / 4 HIGH / 3 MED findings that were resolved inline (see §19.6), **`design-final-v2.md` is the reference specification** for EPHEMERAL.

`decision.md` remains in **conditional YES** under the documented conditions, with the Pre-Integration Blocker resolution (B-1 through B-4 in §§2.2, 7.1, 7.2, 3.3.1, 4.2.1) now inlined rather than deferred.

The remaining evaluations are (a) the Skeptic's final pass (`skeptic-review.md`): adoption economics, migration path, incentives, and the cost-vs-80%-alt calculation; and (b) external offensive-security audit against the conformance suite (515 vectors + ~34 Phase B boundary vectors).

Phase B (reference validator harness scaffolding) enters **UNCONDITIONALLY** with `design-final-v2.md` as the sole authoritative specification. The "CONDITIONAL on B-1–B-4" gate from R8 is now SATISFIED by this integration pass.

---

## 19. R7 + R8 integration summary (changelog) [INFORMATIONAL — non-normative]

**Scope**: This section is INFORMATIONAL, not normative. Implementers need only §0–§18 for v3-conformance. §19 is retained as an audit trail of the R7 and R8 integration process — specifically, what changed between `design-final.md` and `design-final-v2.md`, how Pre-Integration Blockers B-1 through B-4 were resolved, and the Phase B entry rationale.

### 19.1 Pre-Integration Blockers resolved

| Blocker | Resolution location | Action taken |
|---|---|---|
| **B-1** `K_tariff_signer` role missing from §7.1 and `key_epoch` grounding absent | §2.2 + §7.1 | §2.2 amended: Tariff "signed by `K_tariff_signer`" (replacing `K_cust_ops`). §7.1 amended: add `K_tariff_signer` (child of `K_cust_ops`, 7-day rotation). `key_epoch` field added to Tariff schema with 2-per-epoch ledger semantics. |
| **B-2** `anomaly_library_signer` not in `child_role` enum | §7.2 | §7.2 `ChildRole` enum extended to include `"anomaly_library_signer"` as a fifth terminal role. §7.3.0 role-hierarchy constraints extended to cover chains terminating at `K_cust_anomaly_library_signer`. §7.5 rotation cadence specified (7-day). |
| **B-3** §3.3 aggregation-window spec-patch target ambiguity | §3.3.1 | New subsection §3.3.1 created as dedicated normative landing zone for R8.F3 aggregation-window semantics. §3.3 remains free-form prose with explicit forward reference to §3.3.1. R8.F3 spec-patch target changed from `§4.4 / §3.3` to `§3.3.1`. |
| **B-4** R7.C6 SET-field enumeration closure conflict with R8 extensions | §4.2.1 | §4.2.1 SET-field enumeration extended with 4 new R8-introduced fields: `operating_hours.windows` (R8.A4), `trusted_transparency_logs` (R8.P3), `trusted_witnesses` (R8.P6), `AnomalyPatternLibrary.patterns` (R8.A1). Each entry specifies membership-keying rule. |

### 19.2 R7 integrations

| Tightening | Location | Patch type |
|---|---|---|
| R7.C1 Case-folding scope | §4.2 | Expand |
| R7.C2 Parameter keys | §4.2 | Expand |
| R7.C3 Unicode NFC | §4.2 | Expand |
| R7.C4 Null vs missing | §4.2 | Expand |
| R7.C5 Size limits | §4.2 | Expand (5 new reject codes) |
| R7.C6 SET vs SEQUENCE | §4.2.1 | New subsection |
| R7.C7 Pipeline ordering | §4.2.2 | New subsection |
| R7.C8 Invisible/bidi chars | §4.2.3 | New subsection |
| R7.C9 Identifier separator | §4.2 | Expand |
| R7.C10 Locale neutrality | §4.2 | Expand |
| R7.D1 Role hierarchy | §7.3.0 | New subsection |
| R7.D2 valid_until inclusivity | §5.1, §7.2, §7.3 | Expand (half-open `[from, until)`) |
| R7.D3 Chain depth | §7.3.1 | New subsection |
| R7.D4 Integrations wildcard | §7.3 | Expand (`scope-integrations-wildcard-forbidden`) |
| R7.D5 Empty-cap mandates | §5.1 | Expand (`mandate-empty-cap`, `mandate-cap-malformed`) |

### 19.3 R8 integrations

| Tightening | Location | Patch type |
|---|---|---|
| R8.P1 PCR indices | §9.4.1 | New subsection |
| R8.P2 STH max age | §9.4.2 | New subsection |
| R8.P3 Trusted logs | §9.4.3 | New subsection |
| R8.P4 Nonce binding | §9.4.4 | New subsection |
| R8.P5 Bundle size cap | §9.4.5 | New subsection |
| R8.P6 Witness cosignatures | §9.4.6 | New subsection |
| R8.A1 AnomalyPatternLibrary | §3.5.1 | New subsection |
| R8.A2 Severity-gated auto-revoke | §3.5.2 | New subsection |
| R8.A3 Firing rule taxonomy | §3.5.3 | New subsection |
| R8.A4 Operating hours | §2.2.1 | New subsection |
| R8.T1 Size cap | §2.2 | Expand |
| R8.T2 iat→not_before gap + key_epoch | §2.2 + §10.3 | Expand |
| R8.T3 Validity period cap | §2.2 | Expand |
| R8.T4 Strict unknown fields | §2.2 | Expand |
| R8.T5 Unknown integration_ref | §2.2 | Expand |
| R8.F1 fieldSelector | §4.4 | Expand |
| R8.F2 Sensitive-path bump | §2.1 + §4.4 | Expand (composition rules) |
| R8.F3 Aggregation window | §3.3.1 | New subsection (B-3) |
| R8.F4 kubectl drain | §4.4 | Expand |
| R8.F5 Canary carve-out | §4.4 | Expand |
| R8.F6 Git default-branch | §4.4 + §2.2 | Expand |
| R8.F7 DNS apex | §4.4 | Expand |
| R8.F8 ACME wildcard + CT-compliant CAs | §4.4 + §2.2 | Expand |

### 19.4 Summary statistics

- Total tightenings integrated: 38 (R7: 15, R8: 23).
- Strength direction: **37 STRENGTHEN, 1 NEUTRAL, 0 WEAKEN** — sum 38 (R7.D2 is the sole NEUTRAL — removes ambiguity via half-open `[from, until)` semantics without changing defense posture; counted within the 38 total as NEUTRAL, not STRENGTHEN).
- New reject codes introduced: **50** (R7: 18, R8: 32).
- New subsections created: **17** — R7: 5 (§4.2.1, §4.2.2, §4.2.3, §7.3.0, §7.3.1); R8: 11 (§2.2.1, §3.3.1 [B-3 landing zone], §3.5.1, §3.5.2, §3.5.3, §9.4.1–§9.4.6); Phase 4 Review: 1 (§7.5.1 — rotation cadence rationale, informational). §3.5.4 (MINIMUM pattern library table) is treated as an appendix to §3.5.1 (R8.A1) and not separately counted.
- Outcome flips applied to conformance vectors: **2** (`ds-054`, `ds-057`).
- Reject-code flips applied to conformance vectors: **6** (`ds-021`, `ds-055`, `pcrrej-045`, `trej-023`, `trej-030`, + 1 R7 audit flip).
- Schema migrations applied: **3** (`pcrrej-023`, `arep-025`, `arep-032`).
- Pre-Integration Blockers resolved: **4** (B-1, B-2, B-3, B-4).

### 19.5 Phase B entry status (revised)

**Phase B entry: SATISFIED** (unconditional, post-Phase 4 Review).

The reference validator harness is scaffolded against `design-final-v2.md` as the single authoritative specification. No conditional "requires integration" gate remains. R7 and R8 delta documents (`design-round7-tightenings.md`, `design-round8-operational-tightenings.md`) are preserved in the repository for audit-trail purposes but are no longer operative for validator implementation — `design-final-v2.md` supersedes.

Conformance suite counts and coverage (515 vectors + ~34 Phase B boundary additions) remain as documented in `conformance-plan.md` and `conformance/README.md`.

### 19.6 Phase 4 Review Swarm (2026-04-18)

Four parallel specialized agents (security-reviewer, code-reviewer, architect, Explore) validated `design-final-v2.md` after the R7+R8 integration pass. Consolidated findings and resolutions applied inline:

| ID | Severity | Location | Finding | Resolution |
|---|---|---|---|---|
| CRIT-1 | CRITICAL | §7.3.0 | First-link constraint permitted `root → {tariff_signer, audit_signer, anomaly_library_signer}` direct delegation, bypassing `K_cust_ops` and collapsing three-level hierarchy to two levels under compromise. | §7.3.0 narrowed: first delegation link's `child_role` MUST be `ops`. Chain shape is `root → ops* → <terminal>` for all terminal roles. |
| CRIT-2 | CRITICAL | §2.2 R8.T2 | "14d worst-case exposure" claim invalid under `K_tariff_signer` compromise because `key_epoch` is signer-chosen payload field. | §2.2 amended: R8.T2 cap is drift-prevention bound under non-compromised signer; under key compromise, binding bound is R8.T3 (30d) × revocation latency. Sec-N4 explicitly cross-referenced. |
| HIGH-1 | HIGH | §4.2.2 | Pipeline Step 2 enumeration listed R7.C3 (NFC) before R7.C8 (control-char), contradicting §4.2.3 prose requiring C8 before C3. | §4.2.2 Step 2 reordered with explicit intra-step (a)-(h) sequence; control-char → NFC ordering stated as load-bearing. |
| HIGH-2 | HIGH | §4.2.1 | SET dedup semantics under-specified for byte-equal but distinct-code-point inputs. | §4.2.1 clarified: R7.C3 enforcement in step 2(b) guarantees all SET members are NFC at dedup time, so post-NFC byte-compare is complete. |
| HIGH-3 | HIGH | §7.5 | Non-cascading revocation left child keys valid between parent revocation and explicit child revocation. | §7.5 added chain-revocation inference: any chain containing a revoked parent REJECTS with `parent-delegation-revoked`, independent of explicit child revocation distribution. |
| HIGH-4 | HIGH | §9.4.4 | Nonce-reuse vs. TTL-elapsed audit specificity lost by reject-code conflation. | §9.4.4 added: internal audit payload MAY carry `{reject_reason}` distinction; external callers see indistinguishable `nonce-mismatch` (prevents TTL timing oracle). |
| MED-1 | MED | §2.2.1 | Full-day window tiling (adjacent windows covering [0,1440]) bypassed operating-hours restriction. | §2.2.1 added `operating-hours-full-day-coverage` reject: adjacent-tiled windows covering full day REJECT. |
| MED-2 | MED | §3.5.1 | `AnomalyPatternLibrary.valid_until` expiry behavior undefined; silent continuation against stale library possible. | §3.5.1 added normative expiry semantics: `PatternLibraryExpired` audit event on expiry; 72h grace window with high-severity pattern fail-close; after 72h hard fail-close on Tier 3+. |
| MED-3 | MED | §3.5.3 | Companion-pair check ran only at library load; `PatternRelaxationException` could silently orphan short-window patterns. | §3.5.3 added `pattern-relaxation-orphans-companion` reject: exception processing MUST re-run companion-pair check regardless of ceremony_quorum cosignature. |
| COUNT-1 | LOW | §19.4 | STRENGTHEN count arithmetic inconsistent (38 STRENGTHEN + 1 NEUTRAL = 39 ≠ 38 total). | Corrected to "37 STRENGTHEN, 1 NEUTRAL, 0 WEAKEN — sum 38". |
| COUNT-2 | LOW | §19.4 | Subsection count (14) mismatched actual new-subsection total (17). | Corrected to 17 with explicit §-list; §3.5.4 treated as appendix to §3.5.1. |
| ARCH-1 | ADVISORY | §7.5 | Rotation cadence asymmetry (90d ops vs 7d children) unjustified. | Added §7.5.1 "Rotation cadence rationale" — tradeoff table, acknowledged weak point, operator guidance. |
| STRUCT-1 | LOW | §19 | Section not marked as informational despite being changelog content. | §19 header marked `[INFORMATIONAL — non-normative]`; added scope statement. |

**Residuals preserved** (not resolved inline; tracked as §14 operator-feedback flags):
- Sec-N4 (`key_epoch` self-declared): explicitly documented in CRIT-2 fix. Future hardening path: derive `key_epoch` from COSE `kid` or delegation doc `valid_from`.
- Sec-N5 (Git dead-zone in `sensitive_path_patterns`): **PARTIALLY MITIGATED** via `conformance/reference-sensitive-paths.json` (v1.0.0, shipped 2026-04-18). Reference set provides ~190 patterns across 7 categories with Git + supply-chain coverage (OWASP 2025 A03, 9 incident references). Post-v1.0 internal security-review pass applied 3 CRITICAL + 5 HIGH + 3 MEDIUM false-negative fixes in-place before ship. Remaining residual tracked in §14 item 10: full closure requires Phase B reference validator enforcing coverage attestation at Tariff publish, plus second-pass independent review of the reference artifact for any additional false-negative gaps.

**Review coverage**: All 4 Pre-Integration Blockers (B-1..B-4) re-verified post-edit. All 38 R7+R8 tightening references validated. All §-references, ChildRole enum, SET-field enumeration, and reject-code taxonomy found internally consistent.

---

**End of design-final-v2.md — EPHEMERAL Final Specification (R7 + R8 integrated).**
