# redteam-round2.md — EPHEMERAL, Round 4 Red Team

**Role**: The Red Team, fresh eyes on `design-v2.md`. Not re-checking Round 2 — looking for new attacks that v2's Proportional Authority / Tariff structure introduces or fails to address.

**Ground rules**: Severity is frozen after this document. Confidence is my estimate that a competent external reviewer would find the same attack.

---

## Attack V2-1 — CROSS-TIER-AGGREGATION: many low-tier actions achieve a high-tier effect

**Preconditions**
- Classifier is stateless (sees only the current intent, not history).
- Mandate's `cap` list or Tariff's tier assignments do not constrain *aggregate* effect.
- Attacker-controlled LLM (prompt-injected or dep-compromised) can emit many intents.

**Steps**
1. Target objective: render `Namespace prod` unusable. This is a Tier 4 action ("delete namespace") under any reasonable Tariff.
2. Attacker does NOT issue `delete namespace`. Instead:
   - N x Tier-2 `patch deployment` actions setting `replicas: 0` on every deployment in `prod`.
   - N x Tier-1 `apply configmap` actions overwriting critical configmaps with empty content.
   - N x Tier-2 `patch ingress` actions redirecting traffic to `/dev/null`.
3. Each individual action passes classifier → appropriate tier → mandate permits → capability minted → executed.
4. Aggregate effect: `Namespace prod` is functionally down. Equivalent to `delete namespace`, which would have required Tier 4 WebAuthn step-up.
5. No cryptographic check fires. No policy denies. Budget counter (if set) may prevent it — *if and only if* the operator sized the budget correctly.

**What is violated**
- The core claim of v2: "authorization is proportional to impact." An attacker has achieved Tier 4-level impact with only Tier 1-2 authorization.
- The claim that "the dangerous 5% of actions are gated by human-in-loop." The dangerous outcome was reached without any human step-up.

**Severity: SHOWSTOPPER**.

The proportionality argument is the core distinguishing feature of v2. If an attacker can trivially compose sub-tier actions into high-tier outcomes, proportionality is a polite fiction. This is worse than v1's issues because v1 at least aspired to uniform treatment of authority — v2 explicitly claims tier-appropriate gating, and this attack breaks that claim.

**Confidence: HIGH.**
This attack class is well-known in authorization theory (it's the "aggregation problem" or "capability composition problem"). Any external reviewer with authorization-model background will raise it immediately.

**Is it fixable within scope?**
Not with cryptography. No architectural primitive can prevent an attacker operating *within* authorized actions at every step. Mitigation requires a combination of:

1. **Resource-level cumulative rate limits** — per-namespace, per-kind, per-destructive-verb. Not per-intent rate limits (which v2 has) but per-resource-state-change rate.
2. **Stateful classifier** — classifier gains access to a recent action history for the same mandate / resource / namespace. It can then raise tier if it sees a pattern: "5 replica changes to 0 in 30 seconds → this is effectively a namespace takedown → Tier 4."
3. **Budget tightness** — mandates should be narrowly scoped. A mandate with `cap: ["*:patch:*:prod/*"]` and `budget.actions: 1000` is too loose. Tighter: `cap: ["k8s:patch:deployment/prod/foo-only"]` and `budget.actions: 5`.
4. **Anomaly detection on audit stream** — a parallel system watches the audit log and raises alerts (or kills the mandate via push revocation) on patterns. This is detection, not prevention, but bounds the blast radius in time.
5. **Invariants at target** — target API can enforce invariants that mandate-level rules can't: "namespace `prod` must always have ≥2 running deployments" can be enforced as a K8s admission policy, entirely outside EPHEMERAL. This is the strongest mitigation, because it's target-state-based, not action-based.

**Honest conclusion on this attack**:

v2 cannot prevent aggregation cryptographically. The architecture must **explicitly acknowledge** this and make operators responsible for narrow mandates + target-level invariants + anomaly-detection. This should be documented prominently, not buried. **Until this is acknowledged and the mitigation stack is spelled out, v2 should not be called "proportional."**

If the Architect accepts this attack as a known-limit-of-any-tier-based-scheme and documents it, v2 survives. If the Architect tries to argue "budgets solve it" or "classifier can see history," v2 fails — those are partial mitigations, not solutions.

---

## Attack V2-2 — CLASSIFIER-BYPASS: adversarial intent crafted to misclassify

**Preconditions**
- Classifier WASM is customer-written.
- Classifier has any logic gap: missing verb, synonym handling, case sensitivity, missing resource type.

**Steps**
1. Tariff's Tier 4 includes `minimum_tiers: {"verb:delete-namespace": 4}`.
2. Classifier checks `action == "delete" && resource.kind == "Namespace"` → Tier 4.
3. Attacker's intent: `{action: "DELETE", resource: {kind: "namespace"}}` — note capitalization differences. If classifier is case-sensitive and `minimum_tiers` is case-sensitive, both miss. Default tier (e.g., Tier 2) applies.
4. More subtly: K8s API accepts multiple kind spellings in some contexts (via kubectl aliases). If classifier doesn't canonicalize, gaps exist.
5. Or: attacker emits `action: "remove"` (valid synonym in some tools) expecting classifier to match "delete" — misses.

**What is violated**
- Tier assignment integrity. Resource protections based on `minimum_tiers` depend on classifier correctly identifying the resource.

**Severity: SERIOUS**.

Not showstopper because `ambiguity_resolution: up` mitigates many cases, and because `minimum_tiers` is a floor — classifier gives tier X, router applies `max(X, floor)`. But floors rely on the customer having written rules that match ALL naming variants, which is unrealistic.

**Confidence: HIGH.**
Normalization bugs are endemic to every input-classifier in history.

**Mitigation**
1. **Classifier input canonicalization is part of the protocol, not the classifier**. Router normalizes intent (lowercase verbs, resolve aliases via API schema, resolve resource types via target API's schema) before passing to classifier.
2. **Classifier fuzz test harness**: during Tariff publish, a fuzz corpus of 10k+ synthetic intents is run through the classifier, and tier assignments are compared against a declarative expected-tier table. Failed fuzzes block the Tariff publish.
3. **`minimum_tiers` operates on normalized form**, not raw intent.
4. **Tariff reviewer UI**: when publishing, show operator "these specific intents would be classified as Tier N — confirm."

With these, SERIOUS stands but is operationally manageable.

---

## Attack V2-3 — TARIFF-VERSION-SKEW: stale Tariff admits downgraded actions

**Preconditions**
- Router caches Tariff with any TTL > 0 (required for performance).
- Customer publishes Tariff v_{n+1} raising some actions from Tier 2 to Tier 4.

**Steps**
1. At T=0, customer publishes Tariff v4, moving `vault:write:secret/prod/*` from Tier 2 to Tier 4.
2. Router has Tariff v3 cached, TTL expires at T=+60s.
3. Attacker (compromised LLM) submits `vault write secret/prod/critical` intent at T=+30s.
4. Router still uses v3 → classifies as Tier 2 → capability minted → secret written. No WebAuthn step-up occurred.
5. At T=+60s Router refreshes to v4. Future writes require step-up. But the damage is done.

**What is violated**
- Tariff change is not immediate; there's a propagation window.
- Customer's intent to raise the bar was defeated by caching.

**Severity: SERIOUS**.

**Confidence: MEDIUM-HIGH.**
Cache-invalidation bugs are classic. v2's spec is ambiguous about Tariff refresh semantics — a reviewer would press on this.

**Mitigation**
1. **Push-based Tariff updates**: Router subscribes to a customer-controlled channel (WebSocket / SSE). Tariff-update events trigger immediate re-verification.
2. **Tariff version pinned in every Mandate**: a mandate issued under Tariff v3 is valid only while Router sees Tariff v3 or higher. If Router has v4, it should re-evaluate the mandate against v4's tier map.
3. **Fail-closed on Tariff-fetch-error**: Router cannot execute Tier 2+ actions with a stale or unverifiable Tariff.
4. **Monotonic version check**: Router refuses Tariffs with version numbers lower than last-seen. Prevents rollback.

---

## Attack V2-4 — WEBAUTHN-PROMPT-FATIGUE: user habitually approves hostile requests

**Preconditions**
- Tier 4 actions happen with meaningful frequency (multiple per day).
- User's device UI is consistent across legitimate and hostile requests.
- LLM is prompt-injected or compromised.

**Steps**
1. Over weeks, user approves N legitimate Tier 4 requests (e.g., "rotate KMS root key" during scheduled maintenance).
2. Device UI shows: "Agent requests: rotate KMS root key. Approve?" User taps yes out of habit.
3. Attacker-compromised LLM submits intent: "rotate KMS root key in account *adversary-owned-account*" — if Tariff allows cross-account at all, or if resource-scoping is weak, this passes classifier as Tier 4.
4. Device UI shows same wording. User taps yes.
5. Damage done.

More subtly: attacker piggybacks on a legitimate request period. User is doing maintenance and expects 5 step-ups. Attacker inserts a 6th, semantically different one. User taps all 6 quickly.

**What is violated**
- The claim "human-in-loop prevents hostile Tier 4 actions." It prevents blind attacks; it does not prevent social engineering or fatigue.

**Severity: SERIOUS**.

**Confidence: HIGH.**
MFA fatigue attacks are a top 5 attack category in 2024-2026 OWASP / MITRE updates. Push-approval fatigue against Microsoft / Duo / etc. is well-documented.

**Mitigation**
1. **Intent-verbatim display**: device shows the ACTUAL intent payload, not a paraphrase. "DELETE namespace `prod` containing 47 deployments, 23 services, 5 pvcs." The full context.
2. **Non-modal delay**: each Tier 4 prompt has a mandatory review-time (e.g., 10 seconds) before the approve button enables. Breaks tap-through.
3. **Per-session limits**: no more than N Tier 4 approvals per hour without a "fresh" re-authentication.
4. **Risk scoring on intent**: compare intent to user's approval history. Anomalous intents (novel resources, novel accounts) get elevated to Tier 5 or require explicit typed confirmation.
5. **Decoupled approval**: approval request includes a 6-digit code. User must type it, not just tap. Slows tap-through drastically.

None fully eliminate the attack. This is an operator-UX concern that the design must explicitly address, not hand-wave.

---

## Attack V2-5 — SIGNER-IMAGE-PCR-PINNING-TRICKERY

**Preconditions**
- Tariff contains `attester_required.pcr0/pcr1/pcr2` for the Signer Service.
- Customer relies on DeployCo (or whoever publishes the enclave image) to report accurate PCR values.

**Steps**
1. DeployCo publishes enclave image v1. Reports PCR values (computed deterministically from the image bytes).
2. Customer pins PCRs in Tariff v3.
3. DeployCo privately publishes a second image v1' with a backdoor + *also* an unrelated legitimate change (e.g., Go runtime version bump). Customer receives a notice "new version available, PCRs updated."
4. Customer — under time pressure or through over-trust — signs Tariff v4 with new PCRs without reproducibly rebuilding the image themselves.
5. Signer Service now runs v1' in production. All attestations pass. Backdoor is active.

**What is violated**
- The attestation chain is meaningless if the customer doesn't independently verify what PCRs correspond to.

**Severity: SERIOUS.**

**Confidence: MEDIUM-HIGH.**
This is a known TEE-supply-chain issue. SEV-SNP and TDX have similar reproducible-build concerns.

**Mitigation**
1. **Reproducible builds**: Signer Service's source code is public; customer can build from source and derive expected PCRs independently. Customer compares to vendor-reported PCRs. Discrepancy = refuse to sign.
2. **Multi-party PCR attestation**: N independent reviewers (community, auditors, customer) sign a `PCR-digest-attestation` artifact. Customer's Tariff trusts N-of-M signatures for PCR changes.
3. **Hysteresis**: PCR changes require higher ceremony than regular Tariff updates (e.g., always multi-party).
4. **Canary deployment**: new PCRs trusted only for a limited action-count window before promotion to full trust.

---

## Attack V2-6 — ROUTER-RCE-WITHIN-TIER-0/1

**Preconditions**
- Router RCE (supply chain, dep compromise, or input bug).

**Steps**
1. Attacker gets code execution in Router process.
2. Router holds short-lived OIDC-fed tokens for Tier 0-1 actions.
3. Attacker can execute any Tier 0-1 action without going through classifier / policy / mandate.
4. What they cannot do:
   - Mint capabilities (those require Signer Service, which requires valid mandate signature; attacker doesn't have `K_cust`).
   - Trigger WebAuthn step-ups as "approved" (those require user device).
   - Modify Tariff (requires `K_cust`).
5. But: arbitrary Tier 0-1 actions + audit log writes. Audit log writes by a compromised Router could be fabricated to hide Tier 0-1 misuse. However, S3 Object Lock prevents deletion; fabricated events appear alongside real ones.

**What is violated**
- Bounded but real blast radius: all Tier 0-1 authority in the Router's scope.

**Severity: SERIOUS** (bounded — this is the acknowledged "Router is the new concentration point for Tier 0-1 authority" trade-off).

**Confidence: MEDIUM.**
Any reviewer will ask about Router-RCE; the v2 design should explicitly characterize its blast radius. Currently §8 of `design-v2.md` mentions it; needs expansion.

**Mitigation**
1. **Router as memory-safe, minimal codebase**: Rust, <5k LOC, no optional features, no unmeasured deps, reproducible build.
2. **Per-integration sub-routers**: separate Router process per integration (k8s-prod, vault-prod, stripe). One RCE = one integration's Tier 0-1 authority, not all.
3. **Tier 0-1 actions also go through OPA policy** (already in design); OPA decisions logged; Router cannot fabricate OPA evaluations without also compromising OPA.
4. **Rate limits at target API level** (defense in depth): even with RCE, target-API rate limits cap damage velocity.
5. **Anomaly detection on audit stream**: deviation from normal traffic pattern = alert → kill switch.

Acceptable residual with proper operational posture.

---

## Attack V2-7 — TARIFF-SIGNING-KEY-COMPROMISE

**Preconditions**
- `K_cust` compromise.

**Steps**
1. Attacker obtains `K_cust` (HSM exploit, insider, social engineering customer's signing officer).
2. Attacker signs a malicious Tariff: all tiers collapsed to Tier 0, no step-ups, no multi-party.
3. Attacker signs a malicious mandate with unlimited budget.
4. Router / Signer Service accept the signed artifacts.
5. Attacker has full authority over all integrations.

**What is violated**
- The entire chain.

**Severity: SHOWSTOPPER** (acknowledged root-of-trust assumption).

**Confidence: HIGH** — trivially found by any reviewer.

**Mitigation**
- This is the fundamental "protect the HSM" problem. Mitigations are operational, not architectural:
  - HSM with geographic + personnel separation
  - Multi-person signing on `K_cust` use (M-of-N HSM policies; supported by AWS KMS, HashiCorp Vault, etc.)
  - Tariff-version signing requires additional co-signers
  - Out-of-band notification to multiple officers on any Tariff change
- **Architectural mitigation**: `K_cust` should NEVER be used to sign individual mandates. Instead:
  - `K_cust` signs only a **Delegation Document**: "these sub-keys may sign mandates with these scopes."
  - Sub-keys (`K_delegate_*`) are used for regular mandate signing, rotated frequently.
  - `K_cust` compromise is detectable (any new delegation out of policy) but not always preventable.

This sharpens v2: **introduce key hierarchy** — `K_cust` (root, rare use, hardware-custody) and `K_delegate_*` (operational, rotated). Not in v2 spec; should be.

---

## Attack V2-8 — CEREMONY-QUORUM-CAPTURE (Tier 5)

**Preconditions**
- Tier 5 requires M-of-N signers from an allowlist.
- Attacker has influence over N signers (e.g., stolen devices, insider on compliance team, coerced signer).

**Steps**
1. Signer list: user, compliance, on-call lead. Required: 2 of 3.
2. Attacker steals user's phone (with WebAuthn credential) AND socially engineers on-call lead.
3. 2 of 3 signatures obtained. Ceremony succeeds.

**Severity: SERIOUS** (operational).

**Confidence: HIGH** for the attack pattern; mitigation is organizational.

**Mitigation**
- Diverse signer roles (not all engineers on the same team).
- Geographic separation.
- Decoy / red-team ceremonies regularly.
- Ceremony-side risk signal: geolocation, time-of-day, prior signing cadence.

Not architectural. Must be documented as operator concern.

---

## Supplementary concerns (less-detailed)

- **SUPPLY-V2-S1**: Classifier WASM runtime (wasmtime / wasmer) has had CVEs. Sandboxing must be strict; resource limits (memory, CPU time, no host access).
- **TIME-V2-S2**: Ceremony timing in Tier 5 depends on each signer's clock. Define canonical clock (ceremony initiator's timestamp, signed into the ceremony record); reject signatures whose timestamps are > skew tolerance from ceremony_id timestamp.
- **AUDIT-V2-S3**: Tier 0-1 audit volume can dominate Tier 2+ audit. Separate streams for cost / queryability.
- **MANDATE-KEY-HIERARCHY-V2-S4**: as noted in Attack V2-7 mitigation, introduce delegation hierarchy.

---

## Summary

| # | Attack | Severity | Confidence |
|---|---|---|---|
| V2-1 | CROSS-TIER-AGGREGATION | **SHOWSTOPPER** | HIGH |
| V2-2 | CLASSIFIER-BYPASS via normalization | SERIOUS | HIGH |
| V2-3 | TARIFF-VERSION-SKEW | SERIOUS | MEDIUM-HIGH |
| V2-4 | WEBAUTHN-PROMPT-FATIGUE | SERIOUS | HIGH |
| V2-5 | SIGNER-IMAGE-PCR-PINNING-TRICKERY | SERIOUS | MEDIUM-HIGH |
| V2-6 | ROUTER-RCE-WITHIN-TIER-0/1 | SERIOUS (bounded) | MEDIUM |
| V2-7 | TARIFF-SIGNING-KEY-COMPROMISE | **SHOWSTOPPER** (root-of-trust) | HIGH |
| V2-8 | CEREMONY-QUORUM-CAPTURE | SERIOUS (operational) | HIGH |

**Two showstoppers**:

- V2-1 (CROSS-TIER-AGGREGATION) — cannot be fixed cryptographically. **Can be bounded operationally** but architecture must acknowledge this is a known limit. If the Architect declares it as residual-with-mitigation-stack, v2 survives. If papers-over, v2 fails.

- V2-7 (TARIFF-SIGNING-KEY-COMPROMISE) — fundamental root-of-trust concern. **Fixable in-design** via introduction of key hierarchy (delegation). The Architect must add this in v3.

Hard-trigger check:
- Do the showstoppers require out-of-scope mitigations (confidential LLM inference, formal verification of full system, novel crypto)?
- V2-1: no. Telemetry + narrow mandates + target-level invariants. All established.
- V2-7: no. Key hierarchy is a well-understood pattern (PKI).

**Round 3 Architect revision is warranted.** Expected deliverable: v3 acknowledges V2-1 with explicit mitigation stack; v3 adds delegation hierarchy for V2-7. If v3 does both honestly, further Red Team rounds can proceed. If v3 pretends these don't exist, v3 fails by Round 4 hard-trigger.

---

## Meta-observation

v2 is architecturally much cleaner than v1. The attack surface has shifted from "cryptographic protocol bugs" (which Round 2 found in force) to "policy and operational integrity" (which Round 4 finds). This is the normal evolution of a hardening design: early rounds kill the low-level crypto bugs; later rounds expose the harder, higher-layer concerns.

The remaining showstoppers are not cryptographic. They are:
- A fundamental limit of tier-based schemes (aggregation)
- A key management hygiene issue (root-of-trust concentration)

Both are **well-understood categories** in the literature. Neither is unique to EPHEMERAL. Both have known mitigation patterns.

This suggests v2 is approaching a **"it's not broken, it's just hard to operate well"** equilibrium — which is roughly where every mature security architecture lives.
