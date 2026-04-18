# design-final.md — EPHEMERAL Final Specification

**Role**: The Architect, final consolidation after three adversarial rounds.
**Status**: Promoted from `design-v3.md` with Round 6 spec tightenings (V3-1, V3-3, V3-6, V3-8) integrated.
**Date**: 2026-04-18
**Audit trail**: `no-go-preemptive.md` → `design-v1.md` → `redteam-round1.md` → `design-v2.md` → `redteam-round2.md` → `design-v3.md` → `redteam-round3.md` → this file.

---

## 0. What this document is

This is the final technical specification for EPHEMERAL, the cross-organization autonomous-agent authorization architecture. It is the product of three red-team rounds and one major architectural pivot (Proportional Authority Protocol, introduced in v2). It is organized for implementers, not for review — review artifacts are in the redteam files.

The document is self-contained. It does not require reading v1/v2/v3 to implement, but it inherits their residuals and acknowledges them explicitly.

**Target reader**: a platform/security engineer at either the SaaS vendor ("DeployCo") or the customer ("Acme") who will implement this.

---

## 1. Premise recap (one paragraph)

A SaaS vendor operates an LLM-driven agent on a customer's infrastructure. The customer is the authority over what the agent can do; the vendor runs the agent's software; the LLM provider serves inference. The agent executes actions with asymmetric blast radii — reading status is safe, patching production is not, deleting data is catastrophic. EPHEMERAL's thesis: **authorization ceremony should match the action's blast radius, not average it**. Low-impact actions use simple short-lived tokens (the "80% alternative"); high-impact actions require cryptographic capabilities; irreversible actions require human-in-the-loop; existential actions require multi-party ceremony. This *proportional* design reconciles the Skeptic's objection (most actions don't need expensive machinery) with the original ambition (some actions genuinely do).

**Threat model carried forward from Round 0**: A1 malicious LLM insider, A2 supply-chain compromise of DeployCo, A3 network attacker, A4 compromised agent runtime, A5 compromised target API. Plus Round-1-introduced A6: compromised DeployCo operator (insider at vendor side).

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
- Classifier returns "pattern-matched aggregation risk" → escalates one level.
- Fresh canary window for new Signer PCR set → Tier 3+ escalates to step-up during canary.

### 2.2 The Tariff (customer-signed policy document)

The Tariff is a COSE_Sign1 CBOR document signed by `K_cust_ops` (§7). It is pinned in each Router instance and enforced at every decision point.

```cbor
Tariff = {
  "version":                   uint,
  "issued_at":                 uint,          // unix seconds
  "valid_until":               uint,
  "integration_ref":           tstr,          // e.g., "k8s-prod", "vault-prod"
  "signer_image_pcr_set":      {pcr0, pcr1, pcr2},
  "pcr_attestors":             [pubkey],      // min 3; quorum 2-of-3
  "pcr_canary":                {duration_days: uint, max_actions: uint},
  "classifier_wasm_hash":      bstr,
  "classifier_fuzz_attestation": bstr,       // hash of §4.4 fuzz report
  "tier_map_defaults":         {verb_pattern → tier},
  "minimum_tiers":             {specific_action → min_tier},  // override floor
  "narrowness_rules":          {...},        // §3.1
  "rate_matrix":               {...},        // §3.2
  "verb_aliases":              {...},        // §3.3 canonicalization
  "target_invariants_documented": bool,      // §3.4 attestation
  "tariff_update_channel":     tstr,         // push endpoint
  "revocation_channel":        tstr,         // §8.3
  "revocation_channel_ha":     {...},        // §8.4 HA spec
  "anomaly_channel":           tstr,         // §3.5
  "user_device_protocol_version": uint,      // §6
  "step_up_allowlist":         [pubkey],     // WebAuthn-capable officers
  "ceremony_quorum":           {n: uint, m: uint, diversity_rules: {...}}
}
```

A Tariff with missing or invalid signature is rejected at Router startup and on every push update.

---

## 3. Aggregation Defense-in-Depth (six layers, from v3 §1.2, unchanged)

The Tariff mandates six layers to bound aggregation attacks (an attacker composing low-tier actions into a high-tier effect). Each layer has a specific role.

### 3.1 Layer 1 — Narrow mandates (protocol-enforced)
- Mandates with wildcard `*` in `cap` MUST have `budget.actions ≤ narrowness_threshold` (default 20).
- Mandates MUST specify `sub_resource` where the target API supports it.
- **Enforcement**: Router rejects non-compliant mandates at acceptance.

### 3.2 Layer 2 — Cumulative rate matrix
Rate limits by verb × resource-kind × namespace × time-window. Enforced by Router in addition to per-tier limits.

### 3.3 Layer 3 — Stateful classifier with history
Classifier WASM reads `{current_intent, recent_actions, resource_state_snapshot, mandate_budget_remaining}`. May escalate tier based on pattern (e.g., "5× replica→0 in 60s" → Tier 4).

### 3.4 Layer 4 — Target-level invariants (customer-domain precondition)
Strongest defense. K8s admission controllers, DB constraints, immutable backup rules. Tariff field `target_invariants_documented: bool` is customer attestation that these exist. If `false`, Tier 3+ auto-escalates to step-up.

### 3.5 Layer 5 — Anomaly detection on audit stream
Customer-operated service consumes signed audit stream, matches patterns, pushes revocation. Reference pattern library shipped with v3 implementation.

### 3.6 Layer 6 — Network kill switch
Customer can cut Router egress to target APIs via cloud NACL/SG. Last-resort response.

**Explicitly acknowledged residual**: an attacker operating strictly below rate-matrix thresholds, using no known aggregation pattern, with `target_invariants_documented: true` does eventually succeed in accumulated damage. This is a fundamental limit of tier-based schemes (see `redteam-round3.md` V3-2).

---

## 4. The Classifier

### 4.1 Role
Customer-authored WebAssembly module. Inputs an intent + context; outputs a tier recommendation. Tariff pins its hash; only this exact WASM runs.

### 4.2 Intent normalization (Router-side, pre-classifier)
Router applies canonicalization before passing to classifier:
- Verbs: lowercased and mapped via `verb_aliases`.
- Resource kinds: resolved via target-API schema (e.g., K8s discovery).
- Identifiers: canonical form `<kind>/<namespace>/<name>`.
- Parameter keys: forbidden case variation.

A Router implementation failing normalization is non-conformant.

### 4.3 Context provided to classifier
```
ClassifierContext = {
  canonical_intent:          CanonicalIntent,
  recent_actions:            [ActionSummary],   // capped N
  resource_state_snapshot:   {...},             // Router-cached
  mandate_budget_remaining:  int
}
```

### 4.4 Classifier baseline fuzz corpus (Round-6 tightening, V3-8)

**Normative**: Every v3-conformant reference implementation ships with a baseline fuzz corpus published at `fuzz-baseline.cbor` (hash `H_baseline_fuzz`). The corpus covers:
- All destructive verbs recognized by the target-API schema.
- All known resource-kind synonyms (e.g., `deploy`, `deployment`, `deployments.apps`).
- All historical attack patterns from the anomaly-detection pattern library.
- Edge cases: null values, empty strings, maximum-length params, nested object permutations at depth 4.

A Tariff publish action MUST include `classifier_fuzz_attestation` — the hash of a fuzz report produced by running the specified `classifier_wasm_hash` against the union of (a) `fuzz-baseline.cbor` and (b) customer-augmented corpus. Router verifies: (a) `classifier_wasm_hash` is correct, (b) baseline fuzz was included (by checking the report references `H_baseline_fuzz`), (c) no baseline case returned a tier below `minimum_tiers` expectation. A Tariff whose fuzz report fails any baseline case is REJECTED at Router startup.

Customer's custom fuzz patterns **augment** but do not **replace** the baseline.

### 4.5 Classifier output
```
ClassifierOutput = {
  tier:         0..5,
  reason_code:  tstr,        // machine-readable
  reason_text:  tstr,        // human-readable for audit
  escalations:  [tstr]       // any triggered escalation codes
}
```

---

## 5. Mandate and Capability (Tier 2+)

### 5.1 Mandate

```cbor
Mandate = COSE_Sign1({
  "mandate_id":            ulid,
  "integration_ref":       tstr,
  "cap":                   [cap_string],     // narrow scope
  "budget":                {actions, tokens, $currency},
  "issued_at":             uint,
  "exp":                   uint,             // typ 4h
  "min_tariff_version":    uint,
  "purpose":               tstr,             // human context
  "operator_id":           tstr,
  "revocation_channel_ref": tstr,
  "signer_key_hint":       tstr              // which K_cust_mandate_N
}, signed_by: K_cust_mandate_N)
```

Verification: signature chain (see §7.3 delegation verification, Round-6 tightening) + not-expired + Tariff-version-adequate + narrowness check.

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

### 7.1 Three-level hierarchy (from v3 §2.1)
```
K_cust_root           — HSM, rare use, ceremony-only
K_cust_ops            — HSM with M-of-N officer policy, 90-day rotation
K_cust_mandate_*      — Operational keys, 7-day rotation
```

Plus supplementary keys:
```
K_cust_root_spare     — Offline, geographically separated, pre-activated
K_cust_audit          — Customer HSM, signs audit countersignatures (§9.4)
```

### 7.2 DelegationDocument

```cbor
DelegationDocument = COSE_Sign1({
  "parent_key":            pubkey,                  // must match verifier's trust anchor
  "child_key":             pubkey,
  "child_role":            "ops" | "mandate_signer" | "tariff_signer" | "audit_signer",
  "scope":                 DelegationScope,
  "valid_from":            uint,
  "valid_until":           uint,
  "revocation_channel":    tstr,
  "issuer_constraints":    {...}
}, signed_by: parent_key)
```

### 7.3 Round-6 tightening (V3-1): delegation scope-match table

**Normative**: Router MUST verify at mandate acceptance that the mandate's assertions are in-scope for its signing-key's delegation. Implementation is a field-by-field match table:

```
DelegationScope = {
  "integrations":          [tstr],        // integration_refs child may sign for
  "max_tier_signable":     0..5,          // ceiling for any mandate.cap
  "max_budget":            Budget,        // per-mandate budget ceiling
  "max_exp_seconds":       uint,          // mandate.exp must be ≤ issued_at + this
  "allowed_verbs":         [tstr],        // strict allowlist of canonical verbs
  "allowed_resource_kinds":[tstr]         // strict allowlist of canonical kinds
}
```

Verification checks (must ALL pass; any failure = REJECT):

| Mandate field | Scope check |
|---|---|
| `integration_ref` | `∈ scope.integrations` |
| `cap[].tier` (resolved via Tariff) | `max(tiers) ≤ scope.max_tier_signable` |
| `cap[].verb` | `∈ scope.allowed_verbs` |
| `cap[].resource_kind` | `∈ scope.allowed_resource_kinds` |
| `budget.actions` | `≤ scope.max_budget.actions` |
| `budget.tokens` | `≤ scope.max_budget.tokens` |
| `exp - issued_at` | `≤ scope.max_exp_seconds` |

**Conformance test vectors**: v3 reference implementation ships with `delegation-scope-test-vectors.cbor` — 200+ (delegation, mandate) pairs labeled allow/deny. Any v3-conformant Router MUST match all labels.

### 7.4 Verification chain (mandate verification)
1. Fetch delegation from `K_cust_mandate_N` upward to `K_cust_root`.
2. For each link: verify signature, validity window, revocation status.
3. For each link: perform scope-match check against the next-closer-to-mandate link.
4. For the mandate itself: perform scope-match against `K_cust_mandate_N`'s delegation.
5. If any check fails: REJECT with specific failure reason (logged).

### 7.5 Rotation and revocation
- `K_cust_root`: 2-5 year rotation via coordinated Router-image rebuild.
- `K_cust_ops`: 90-day rotation via new delegation doc.
- `K_cust_mandate_*`: 7-day rotation via new delegation from `K_cust_ops`.
- Revocation: level N publishes revocation list signed by level N-1 (or itself for root) to `revocation_channel`. Push-notified to Router (§8).

### 7.6 Root compromise recovery
1. Confirm root compromise via out-of-band trusted channels.
2. Coordinate Router-image rebuild with `K_cust_root_spare` as pinned trust anchor.
3. All DelegationDocuments re-issued under spare root.
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
  "secondary_endpoints":   [tstr],       // min 2, different regions
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
- Updated via push to `tariff_update_channel` with monotonic version.
- Tariff update with version ≤ current: REJECTED.
- Tariff update during action flight: active action uses originally-pinned Tariff; next action uses new.

### 10.4 Decision flow (pseudocode)

```
on receive intent:
  canonical = normalize(intent)
  tier = classifier.classify(canonical, context)

  apply_automatic_escalations(tier)

  match tier:
    0: oidc_dpop_call(); audit(); return
    1: oidc_dpop_opa_call(); audit(); return
    2,3: require mandate; verify_delegation(mandate);
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
- `MandateAccepted`, `MandateRejected`
- `CapabilityMinted`, `CapabilityUsed`, `CapabilityExpired`
- `TierEscalated` (with reason)
- `RevocationReceived`, `RevocationChannelGracePeriodEntered/Exited`
- `StepUpRequested`, `StepUpApproved`, `StepUpDenied`
- `CeremonyInitiated`, `CeremonyQuorumReached`, `CeremonyTimedOut`
- `TariffPublished`, `TariffRejected` (with reason)
- `AdminBypassInvoked`

### 11.3 Countersignature ensures integrity
An RCE'd Router cannot fabricate events indistinguishable from real ones — the audit service signs them with a key the Router never holds.

---

## 12. Minimum Viable variants (MV-0 through MV-3, graceful degradation)

Customers deploy progressively; not all deploy the full stack day one.

### MV-0: Tier 0-1 only, no EPHEMERAL machinery beyond audit
- Use: early customer without high-risk automation.
- Implementation: OIDC+DPoP+OPA+audit. This is the 80% alternative plus the Tariff-as-documentation.
- Forbidden: any action that Classifier would rate Tier 2+. Router rejects.

### MV-1: Add Tier 2 — Mandate+Capability
- Adds: Signer Service, Mandate/Capability format, `K_cust_ops`.
- Still forbids Tier 3+.

### MV-2: Add Tier 3-4 — destructive + step-up
- Adds: push-revocation HA, WebAuthn protocol, device allowlist.
- Customer begins deploying target-level invariants.

### MV-3: Full — add Tier 5 ceremony
- Adds: multi-party ceremony infrastructure, expanded `step_up_allowlist`.

Each MV level is a valid v3-conformant deployment. Tariff's declared `maximum_tier` field is how Router knows which MV level applies.

---

## 13. What is novel vs. what is assembled

**Assembled from existing primitives**:
- Nitro Enclaves, SPIFFE/SPIRE, Ed25519, COSE_Sign1, DPoP, OIDC federation, OPA, WebAuthn, HSM, reproducible builds, Sigstore, S3 Object Lock.

**Novel (as far as I know; external review needed)**:
1. **Proportional Authority Protocol / Impact Tiers**: the synthesis of tiered authority with automatic escalation based on context (target invariants, canary, aggregation patterns). Prior art: step-up authentication in OIDC (CIBA), capability hierarchies in Macaroons. Neither composes into a classification-driven proportional system.
2. **Tariff as customer-signed policy-and-authority document**: a single cryptographic artifact that declares action semantics + key hierarchy delegation + operational HA requirements. Prior art: OPA bundles (policy only), PKI delegation docs (trust only). The combination is new.
3. **Classifier-as-WASM with Router-provided stateful context**: customer-authored, cryptographically pinned tier classifier with access to recent-action history and resource state snapshot. Prior art: OPA data documents are stateless; Cedar has entity stores but not event history.
4. **Mandatory baseline fuzz corpus as Tariff precondition**: spec-level requirement that a customer's classifier pass a shared reference corpus before a Tariff can publish. Closes the "forgotten pattern" gap (V3-8).
5. **Automated attestation pipeline with transparency log for PCR changes**: replaces human-review attestors with mechanized independent builders whose outputs are publicly verifiable (Round-6 V3-3 tightening).

Points 4 and 5 specifically are what the Round-6 spec tightenings contribute beyond v3. They're operational rather than cryptographic, but they close the real-world-attacker gap between "protocol is sound" and "deployed system is sound."

---

## 14. Residuals (carried forward, not fixed)

1. **Sub-threshold aggregation**. Attacker within all rate limits, no known pattern, `target_invariants_documented: true` → slow accumulated damage possible. Bound by anomaly detection latency + rate matrix + mandate narrowness. Not prevented. (V3-2, fundamental to tier-based schemes.)
2. **Root-of-trust compromise**. Standard PKI residual. Recovery via `K_cust_root_spare` + ceremony.
3. **Prompt injection via ingested content**. Mandate narrowness is primary mitigation; no cryptographic prevention.
4. **Target API compromise** (A5). Out of scope, audit-only.
5. **User-device malware** (B16). Out of scope beyond step-up UX protocol.
6. **Side channels, hardware attacks, model poisoning**. Out of scope.

---

## 15. Conformance test suite (required for any implementation claiming v3-compliance)

Delivered with reference implementation:
1. `fuzz-baseline.cbor` — classifier baseline fuzz corpus (§4.4).
2. `delegation-scope-test-vectors.cbor` — 200+ (delegation, mandate) allow/deny pairs (§7.3).
3. `canonicalization-test-vectors.cbor` — intent normalization equivalences (§4.2).
4. `audit-replay-tests.cbor` — known-attack audit streams anomaly detector should flag (§3.5).
5. `tariff-reject-tests.cbor` — malformed Tariffs Router must reject at startup.
6. `pcr-attestation-reject-tests.cbor` — attestation evidence that must be rejected (missing transparency proof, quorum-short, mismatch).

An implementation is v3-conformant only if it passes 100% of these vectors.

---

## 16. Deployment prerequisites (customer side, non-negotiable)

Before Tier 3+ is enabled:
1. `K_cust_root` generated in HSM, ceremony-attested.
2. `K_cust_root_spare` generated in geographically separate HSM.
3. `K_cust_audit` generated in HSM.
4. Target-level invariants deployed OR `target_invariants_documented: false` (with escalation understood).
5. Push-revocation endpoints deployed per `revocation_channel_ha` spec.
6. Anomaly-detection service deployed and consuming audit stream.
7. At least 3 attestor services configured (human or automated).
8. Step-up device allowlist populated for Tier 4+ operators.
9. Ceremony signer registry populated for Tier 5.
10. Kill-switch runbook tested (network cut + effect).

Before Tier 5:
11. M-of-N ceremony quorum defined, diversity rules documented.
12. Periodic red-team ceremony tabletop exercises in place.

---

## 17. Honest limits (same as v3, reaffirmed)

- Still reviewed only by one LLM over three rounds. External audit by an offensive security firm remains required before production deployment.
- No formal verification of the protocol composition.
- The aggregation residual (V3-2) is real and operational mitigations are the only meaningful defense.
- The novel parts (especially Proportional Authority) have no production track record. Early deployments should treat MV-0 and MV-1 as genuine learning opportunities, not rubber-stamp pilots.

---

## 18. Decision

With Round 6 Red Team producing no new showstoppers, and with the Round 6 spec tightenings integrated (V3-1 scope-match table, V3-3 automated attestation, V3-6 HA spec, V3-8 baseline fuzz), **`design-final.md` is the reference specification** for EPHEMERAL.

`decision.md` is updated to reflect the revised verdict: **conditional YES** under the conditions documented there, citing the Proportional Authority pivot as the architectural resolution of the Round 0 Skeptic's original objection.

The remaining evaluation is the Skeptic's final pass (`skeptic-review.md`): adoption economics, migration path, incentives, and the cost-vs-80%-alt calculation with the v3/final design substituted in.
