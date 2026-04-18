# design-v3.md — EPHEMERAL, Round 5 Architect Revision

**Role**: The Architect. Responding to Round 4 Red Team findings on `design-v2.md`.

**Scope**: Focused revision, not full rewrite. Two showstoppers (V2-1 CROSS-TIER-AGGREGATION, V2-7 TARIFF-SIGNING-KEY-COMPROMISE) plus promotable-to-"accepted" mitigations for the five SERIOUS findings (V2-2 through V2-6, V2-8). v3 **extends** v2 rather than replacing it — the six-tier architecture stands.

Hard-trigger check before writing: do the Round 4 showstoppers require out-of-scope mitigations? V2-1 needs operational mitigations + target-side invariants; V2-7 needs standard PKI delegation. Neither requires confidential LLM inference, formal verification, or novel crypto. Proceeding.

---

## 1. Response to V2-1 CROSS-TIER-AGGREGATION

### 1.1 Explicit acceptance: this is a residual, not a solved problem

The Red Team is correct. **No cryptographic primitive can prevent an attacker who operates entirely within authorized actions from composing low-tier actions into a high-tier effect.** Any architecture that claims to solve this claim-by-claim is lying.

v3's honest position: **aggregation is a limit of all tier-based schemes and we treat it as a first-class residual with a mandatory mitigation stack**. Customers who skip the stack are operating an insecure system.

### 1.2 The Aggregation Defense-in-Depth Stack (mandatory, spec-level)

Six layers, ordered by prevention → detection → response:

**Layer 1 — Narrow mandates** (prevention, operator-authored)

- Mandates must not use wildcard `*` in `cap` without an accompanying `budget.actions ≤ N` where N is small (default ≤20; Tariff may override).
- Mandates must specify `sub_resource` constraints where the target API supports it. Example: `cap: ["k8s:patch:deployment/prod/foo"]` instead of `cap: ["k8s:patch:deployment/prod/*"]`.
- Router validates mandate-narrowness at acceptance: if `cap` uses `*` at any path segment and `budget.actions > narrowness_threshold`, REJECT the mandate. Threshold defined in Tariff.
- **Enforcement**: a mandate with `cap: ["*"]` and `budget.actions: 10000` cannot be accepted by any v3-compliant Router. This is a protocol-level check, not a suggestion.

**Layer 2 — Cumulative resource rate limits** (prevention, Router)

- Rate limits shift from "per-intent" (v2) to "per resource-state-change":
  - `per_resource_kind_per_window`: max N state-changing actions on deployments in `prod` per 10 minutes.
  - `per_namespace_per_window`: max N destructive-class actions in `prod` per 10 minutes.
  - `per_destructive_verb_per_window`: max N `delete`-verb actions per hour.
- Defined per-integration in Tariff as `rate_matrix`. Applied by Router in addition to per-tier rate limits.

**Layer 3 — Stateful classifier with history access** (prevention, classifier-extensible)

- Classifier WASM gains read-only access to a Router-provided context:
  ```
  ClassifierContext = {
    current_intent: Intent,
    recent_actions: [ActionSummary],   // last N actions, same mandate
    resource_state_snapshot: {...},    // current counts: deployments in ns, etc.
    mandate_budget_remaining: int
  }
  ```
- Classifier can raise tier based on pattern:
  ```
  if recent_actions has ≥5 replica→0 patches in last 60s:
      return Tier 4, reason="replica-collapse pattern"
  ```
- `recent_actions` is capped (Router-side) to prevent classifier bloat.
- Customer-written classifier is the place to encode pattern knowledge.

**Layer 4 — Target-level invariants** (prevention, outside EPHEMERAL)

- The strongest defense against aggregation is **the target API enforcing state invariants independently of action authorization.**
- K8s: admission controllers (Kyverno / OPA Gatekeeper) that reject state transitions: "Namespace `prod` must always have ≥2 running Deployments" → blocks replica-collapse aggregation even if authorized.
- Databases: declarative constraints ("production schema cannot be dropped without compliance ticket" enforced at DB level).
- Every Tariff MUST document which target-level invariants are expected. If target-level invariants are absent, **the Tariff explicitly acknowledges reduced aggregation protection in writing.**
- This is not an EPHEMERAL feature but a **precondition**. Documented as such.

**Layer 5 — Anomaly detection on audit stream** (detection, real-time)

- Dedicated service (customer-operated) consumes the audit stream. Matches patterns: rate spikes, resource-state drift rate, repeated failed actions.
- On pattern match: pushes revocation to the mandate's `revocation_channel_ref`. Router receives revocation within ≤5s (per push-revocation spec).
- Optional: pre-baked pattern library shipped with v3 reference implementation (top 20 aggregation patterns with tunable thresholds).

**Layer 6 — Kill switch at network boundary** (response, catastrophic)

- Customer can cut the Router's egress to all target APIs via cloud-level NACL / security group update. Stops all actions immediately; bypasses mandate / capability semantics.
- Documented as last-resort response.

### 1.3 Formalization in spec

v3 Tariff mandatory field additions:

```cbor
Tariff = { ... v2 fields ...,
  "narrowness_rules": {
    "max_budget_actions_with_wildcard": 20,
    "required_specificity_per_tier": { 2: "resource-type", 3: "named-resource", 4: "named-resource", 5: "named-resource" }
  },
  "rate_matrix": {
    "k8s:patch:deployment:prod/*": {"per_minute": 10, "per_hour": 50},
    "k8s:delete:*:prod/*":         {"per_minute": 2,  "per_hour": 5},
    "vault:write:secret/prod/*":   {"per_minute": 5,  "per_hour": 20}
  },
  "target_invariants_documented": true,  // customer attestation
  "anomaly_channel": "https://anomaly.acme.internal/push"
}
```

A Tariff with `target_invariants_documented: false` is accepted by Router but **causes every Tier 3+ action to require WebAuthn step-up**, regardless of the Tariff's tier spec. This is a protocol-level incentive to deploy target-level invariants.

### 1.4 Honest limits

- Layer 3 (stateful classifier) catches KNOWN patterns. Novel aggregation patterns not in the classifier are not caught until Layer 5 (anomaly detection) sees them. Layer 5 is eventually-consistent; some aggregation events will complete before detection.
- Layer 4 is the only layer that provides pre-action prevention by target-state-shape. Without Layer 4, aggregation is bounded by Layer 1-2 but not prevented.
- **v3 makes the limit visible**: `target_invariants_documented: false` triggers elevated ceremony, a protocol-level signal to operators that their setup is weaker.

**The claim of v3 is therefore**: *with Layers 1-4 in place, aggregation attacks are bounded to effects reachable within narrow mandates, small budgets, rate limits, and target-side state invariants. Layers 5-6 detect and respond to remaining cases. This is the strongest claim a tier-based system can honestly make.*

---

## 2. Response to V2-7 TARIFF-SIGNING-KEY-COMPROMISE

### 2.1 Key hierarchy (mandatory in v3)

v2 used `K_cust` for everything. v3 introduces a three-level hierarchy:

```
K_cust_root           — HSM only; multi-person ceremony; used rarely
      │
      │ signs DelegationDocument
      ▼
K_cust_ops            — HSM with M-of-N officer policy; used to sign Tariffs
      │
      │ signs DelegationDocument
      ▼
K_cust_mandate[1..n]  — Rotated operational keys; used to sign Mandates
```

### 2.2 DelegationDocument

A DelegationDocument is a COSE_Sign1 CBOR record:

```cbor
DelegationDocument = {
  "parent_key": "K_cust_root" | "K_cust_ops",
  "child_key":  <Ed25519 pubkey>,
  "child_role": "ops" | "mandate_signer" | "tariff_signer",
  "scope": [ <scope strings> ],          // what the child can sign
  "valid_from": uint,
  "valid_until": uint,                   // typ. 90 days for ops, 7 days for mandate_signer
  "revocation_channel": tstr,
  "issuer_constraints": {
    "min_signers":          uint,         // M-of-N for issuer use, inherited
    "require_hsm_evidence": bool
  }
}
```

### 2.3 Verification chain

When Router receives a Mandate signed by `K_cust_mandate_5`, verification:

1. Fetch delegation chain: `K_cust_mandate_5` → delegated by `K_cust_ops` → delegated by `K_cust_root`.
2. Verify each DelegationDocument is:
   - Signed by the claimed parent.
   - Currently valid (within `valid_from` / `valid_until`).
   - Not revoked.
   - Scope-appropriate for the Mandate's intent.
3. Verify the Mandate itself is signed by `K_cust_mandate_5` and within `K_cust_mandate_5`'s scope.
4. If any link fails: REJECT.

### 2.4 Trust root pinning

Only `K_cust_root` is pinned in the Router image (via the customer-signed build path from v2 §2.4). Everything else is derivable via delegation.

### 2.5 Rotation and revocation

- `K_cust_root`: rotated every 2-5 years; announced via coordinated rebuild of Router image.
- `K_cust_ops`: rotated every 90 days; new delegation doc signed by `K_cust_root`.
- `K_cust_mandate_*`: rotated every 7 days; new delegation signed by `K_cust_ops`.
- Revocation: any level can revoke its descendants via revocation list published to `revocation_channel`. Push notification to Router.

### 2.6 Compromise response

If `K_cust_mandate_i` compromised: revoke immediately; all outstanding mandates signed by it die; max damage window = mandate `exp` (typ. 4h) + 5s push-revocation latency.

If `K_cust_ops` compromised: revoke; re-delegate from `K_cust_root`; all downstream mandate signers must be re-delegated; max damage window ≤ time to ceremony.

If `K_cust_root` compromised: catastrophe. Requires out-of-band communication to Router operators + Router image rebuild with new root. Customers should have two roots (primary + hot spare) — spare delegation document pre-signed and stored offline. Activate by Router-image rebuild with spare-first ordering. Still multi-hour recovery.

### 2.7 Cost

Key hierarchy adds:
- ~3 Ed25519 key generations per customer onboarding (one-time).
- Per-Tariff-update: 1 delegation verification.
- Per-mandate-verification: 2 additional signature verifications (child delegation + parent delegation), each ~30µs. Negligible.

---

## 3. Promoted mitigations for V2-2 through V2-6, V2-8

### 3.1 V2-2 CLASSIFIER-BYPASS (normalization)

**v3 mandatory**: Router applies a canonicalization pass to every intent before passing to classifier:

- Verbs: lowercase + mapped via Tariff's `verb_aliases` dictionary.
- Resource kinds: resolved via target-API schema (e.g., K8s discovery). Multiple spellings mapped to canonical kind.
- Resource identifiers: canonical form (e.g., K8s `<kind>/<namespace>/<name>` triple).
- Parameter keys: no case variation; forbidden on classifier input.

**Tariff fuzz-harness requirement**: during Tariff publish, Router publishes fuzz-test results to customer. 10k+ synthetic intents run through the normalizer + classifier + `minimum_tiers` pipeline. Failed expectations block publish.

### 3.2 V2-3 TARIFF-VERSION-SKEW

**v3 mandatory**:
- **Push-based Tariff updates**: Router subscribes to customer's `tariff_update_channel` at startup. On update event: fetch, verify, pin.
- **Monotonic version**: Router refuses Tariff with version ≤ last-seen.
- **Mandate-Tariff-binding**: each Mandate includes `min_tariff_version: N`. Router rejects mandates if `current_tariff.version < N`.
- **Fail-closed on Tariff fetch error** for Tier 2+ actions. Tier 0-1 continues on stale cache for availability (bounded damage; already gated by OPA).

### 3.3 V2-4 WEBAUTHN-PROMPT-FATIGUE

**v3 mandatory (UX-layer but spec'd)**:
- Device UI MUST show intent params verbatim (not paraphrased).
- Mandatory review-delay: minimum 8 seconds before approve button enables (time for user to read).
- Challenge payload MUST include a 6-digit confirmation code; user types it, not taps.
- Per-user per-hour Tier 4+ approval rate limit (default: 5). Exceeding requires fresh biometric + password re-auth.
- Device UI shows approval history for THIS mandate visually (last 5 approvals, timestamps).

These are specifications on the user-device side of EPHEMERAL. Compliance-measured by Tariff's `user_device_protocol_version`.

### 3.4 V2-5 SIGNER-IMAGE-PCR-PINNING-TRICKERY

**v3 mandatory**:
- Signer Service source code is **public** (open-source license).
- Reproducible build pipeline specified (Nix-based or equivalent; produces bit-identical artifacts from given commit).
- PCR values for any image version MUST be independently computable from source.
- Tariff PCR changes require **multi-party PCR-attestation**: the PCR values must be co-signed by at least 2 independent reviewers (from Tariff's `pcr_attestors` allowlist). Customer verifies co-signatures before Tariff signing.
- **Canary window**: a new PCR set is accepted for Tier 2 actions only (not Tier 3+) for a configurable canary period (default 7 days or 1000 actions, whichever comes first).

### 3.5 V2-6 ROUTER-RCE-WITHIN-TIER-0/1

**v3 mandatory**:
- Per-integration Router processes (or at minimum, per-integration-group isolation). One Router RCE = one integration's Tier 0-1 authority.
- Router's audit log stream is **signed by a separate Audit Key** (HSM-held by customer, independent of Router process). Router forwards signed-by-router events; audit log service countersigns with Audit Key before persisting. Fabricated events fail countersignature.
- Router codebase MUST be memory-safe (Rust/Go, no unsafe without review), SBOM-published, reproducibly built.

### 3.6 V2-8 CEREMONY-QUORUM-CAPTURE

**v3 recommendations (operator-domain, documented in spec)**:
- Signer allowlist diversity requirements (different teams, different geographies).
- Ceremony side-signals: geolocation of each signer's device, device risk score. Recorded in ceremony record.
- Periodic red-team ceremonies (tabletop + live) — tested signer recognition of anomalous requests.

Not spec-level architectural; but Tariff's Tier 5 config documents signer diversity requirements.

---

## 4. Revised assumptions (from v2 B1-B13)

Superseded v2 assumptions and their v3 replacements:

| v2 # | v2 content | v3 replacement |
|---|---|---|
| B1 | `K_cust` uncompromised | **B1'**: `K_cust_root` uncompromised; `K_cust_ops` protected by M-of-N; `K_cust_mandate_*` rotated ≤7 days. Compromise at any non-root level is recoverable via revocation within bounded window. |
| — | (new) | **B14**: `target_invariants_documented=true` in Tariff means customer has implemented target-side invariants commensurate with the Tariff's claims. |
| — | (new) | **B15**: Anomaly detection service consumes audit stream within ≤30s and triggers revocation on detected patterns. |
| — | (new) | **B16**: User device running WebAuthn protocol v3 (minimum 8s review delay, 6-digit code, per-hour rate limit) is uncompromised as a system, not just as a key. |

Other v2 assumptions (B2-B13) carry forward unchanged.

---

## 5. Summary of what changed from v2 to v3

1. **Aggregation stack** — explicit 6-layer defense. Treat cross-tier aggregation as a named residual with operational mitigation. Mandatory enforcement where possible (narrowness rules, rate matrix, anomaly channel).
2. **Key hierarchy** — `K_cust_root` / `K_cust_ops` / `K_cust_mandate_*` with delegation. Root compromise becomes a recovery-from-offline-spare scenario, not an instant-catastrophe.
3. **Intent normalization** — Router-level canonicalization before classifier.
4. **Push-based Tariff updates** + version monotonicity.
5. **WebAuthn protocol v3** — mandatory delay, code, rate limit.
6. **Reproducible builds + PCR multi-attestation** for Signer Service.
7. **Per-integration Router processes**; separate audit signing key.
8. **Target-invariant attestation** in Tariff — operator declares target-side protections; absence triggers elevated ceremony for Tier 3+.

v3 is **not** more cryptographically complex than v2. The added surface is policy / operations: normalizers, delegation chains, rate matrices, canary windows. All built from known primitives.

---

## 6. Residuals deliberately acknowledged

These are not fixed in v3 and we say so:

1. **Aggregation attacks below anomaly-detection threshold**. If an attacker stays within cumulative rate limits and doesn't match a known pattern, they operate invisibly within the mandate. Only mitigated by narrow mandates + target invariants.
2. **Root-of-trust compromise** (K_cust_root). Any hierarchical PKI has this property.
3. **Prompt injection via ingested content**. Mandate tightness still primary mitigation; no cryptographic prevention.
4. **WebAuthn social engineering**. Mitigations raise the bar but do not eliminate. Ceremony-and-education are the long tail.
5. **Target API compromise** (threat A5). Not in scope.
6. **Side channels, hardware attacks, model poisoning**. Per original threat model, out of scope.

---

## 7. What v3 is ready for

v3 is ready for a **third and final Red Team round**. If Round 6 Red Team finds no new showstoppers — and no new serious attacks that aren't fixable as residuals — v3 becomes `design-final.md`.

If Round 6 finds new showstoppers requiring out-of-scope mitigations → `no-go.md` per procedure.

---

## 8. Caveat

Still a single-LLM adversarial review. v3 incorporates findings from two Red Team rounds and addresses the Round 0 Skeptic's original critique (via MV-0 degradation). External audit still required before production use.
