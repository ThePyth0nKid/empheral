# redteam-round3.md — EPHEMERAL, Round 6 Red Team (final round allowed)

**Role**: Red Team, third and final round per procedure cap. Fresh attacks against `design-v3.md`. Not re-checking v2 issues — those are either fixed or explicitly acknowledged residuals.

**Goal**: find new showstoppers if they exist. If none, v3 proceeds to Skeptic + Synthesis.

---

## Attack V3-1 — DELEGATION-SCOPE-DRIFT: child key used outside intended scope

**Preconditions**
- `K_cust_mandate_N` exists with a delegation document scoping it to, say, "mandates for k8s-prod integration only."
- Implementation bug or spec ambiguity in scope verification.

**Steps**
1. Attacker obtains `K_cust_mandate_N` (realistic: ops-side key with weaker custody than root).
2. Attacker signs a mandate for `vault-prod` integration using it.
3. Router verifies signature chain: mandate → `K_cust_mandate_N` → `K_cust_ops` → `K_cust_root`. Signatures are all valid.
4. **If Router checks only signature validity, not scope match**, the mandate is accepted for vault-prod despite the delegation restricting to k8s-prod.

**What is violated**
- Delegation scope integrity. Attacker escalates a narrow operational key into a broad one.

**Severity: SERIOUS**.

**Confidence: HIGH**.
This is the classic "delegation scope enforcement" bug; has appeared in many X.509 chain validators (Name Constraints violations) and in OAuth scope verification.

**Mitigation (must be spec-level, not implementation)**
- The v3 spec says "Scope-appropriate for the Mandate's intent" but doesn't specify WHAT scope-appropriate means in CBOR form.
- Mandate's content MUST be matched field-by-field against the delegation's scope:
  - Integration-id match: `mandate.integration_id ∈ delegation.scope.integrations`.
  - Tier cap: `max(mandate.cap.tiers) ≤ delegation.scope.max_tier_signable`.
  - Budget cap: `mandate.budget ≤ delegation.scope.max_budget`.
- Publish conformance tests: vectors of mandate + delegation pairs labeled allow/deny; v3-compliant router must match the table.

**Status**: SERIOUS. Addressable by spec precision. If v3 adds the scope-match table, resolved.

---

## Attack V3-2 — SUB-THRESHOLD AGGREGATION (acknowledged residual, confirmed)

**Preconditions**: as V2-1 but now with v3's aggregation stack.

**Steps**
1. Attacker knows `rate_matrix`. Chooses an intent pattern just under every defined rate limit.
2. Attacker knows anomaly-detection patterns (either via inference or via the published pattern library).
3. Attacker crafts a progression of small-impact actions that stays below every layer's threshold.
4. Aggregate damage slow but accumulating.

**What is violated**
- The aggregation-protection claim, at the margin.

**Severity: SERIOUS but explicitly acknowledged in v3 §6.1**.

**Confidence: HIGH**.

**Assessment**
v3 acknowledges this as a residual and specifies Layer 4 (target-level invariants) as the only real prevention. If the customer skips Layer 4, they are explicitly operating a weaker system (and their Tariff must acknowledge `target_invariants_documented: false`, which in turn escalates Tier 3+ to step-up). This is the strongest claim possible for any tier-based scheme.

**Status**: SERIOUS-acknowledged. No further mitigation possible without leaving scope.

---

## Attack V3-3 — REPRODUCIBLE-BUILD VERIFICATION GAP

**Preconditions**
- Tariff's PCR changes require multi-party attestation.
- Attestors do not actually perform the reproducible build independently.

**Steps**
1. DeployCo publishes a new Signer Service image with a backdoor.
2. DeployCo (or compromised insider) asks attestors to sign the PCR update.
3. Attestors — as is common in real-world review workflows — rubber-stamp without independent build verification.
4. Customer sees N-of-M attestor signatures, signs Tariff, rolls out backdoored Signer.
5. After canary window passes, Tier 3+ actions can be abused.

**What is violated**
- The integrity of the PCR attestation chain.

**Severity: SERIOUS**.

**Confidence: HIGH**.
"Attestors who don't actually verify" is endemic in real-world security: Certificate Authority mis-issuance, SBOM rubber-stamping, code review fatigue.

**Mitigation**
- Automate attestation: each attestor runs a scripted pipeline (official CI) that independently builds and publishes computed PCRs. Signature is of the computed output, not a human claim.
- Publish attestor attestations publicly (transparency-log style). Mismatch across attestors is an alarm.
- Canary window is backstop (Tier 2 only during canary), but does not resolve the root issue — it bounds damage velocity.

**Status**: SERIOUS — an operational-honesty concern. Addressable by *requiring* automation in the attestation process. v3's spec should specify this.

---

## Attack V3-4 — ROOT-SPARE SOCIAL ENGINEERING

**Preconditions**
- Customer has `K_cust_root_spare` offline.
- Attacker has physical or social access to customer's key custody.

**Steps**
1. Attacker obtains spare root key through physical theft, insider, or social engineering.
2. Attacker declares fake "emergency" to customer operations: "primary root is compromised, activate spare."
3. Customer activates spare per runbook; rebuilds Router image with new root pubkey.
4. Attacker now controls the root.

**What is violated**
- The root-of-trust compromise recovery story assumes the spare is trustworthy.

**Severity: SERIOUS**.

**Confidence: MEDIUM-HIGH**.
Plausible in practice; organizations with HSM-backed roots have had key-custody incidents documented.

**Mitigation**
- Spare activation requires multi-party attestation (can't just be the ops team).
- Spare stored geographically separate, not just "offline."
- Spare activation is itself a ceremony (multi-signer attestation to the reason + timestamp).
- Dual-control on any HSM holding root material.

Operational, not architectural. v3 documents spare-activation procedure requirements.

**Status**: SERIOUS — operational concern. Spec should require documented spare-activation procedure; specifics are customer-domain.

---

## Attack V3-5 — WEBAUTHN CODE LEAK VIA SHOULDER SURFING / SMISHING

**Preconditions**
- Tier 4 requires user to type a 6-digit code from device UI.
- Attacker has visual access to user's device (over-shoulder in open office) or has phished user via SMS/call.

**Steps**
1. User receives WebAuthn prompt on device.
2. Attacker sees / obtains the 6-digit code.
3. Attacker (who has already submitted the intent) now has the code.

Wait. This attack doesn't quite work. The 6-digit code is shown on the user's device UI; the user types it into the **same device's approval prompt** (not cross-channel). It's not transmitted anywhere the attacker can intercept. Shoulder surfing gives you the code, but you'd also need the user's device — at which point you'd just tap approve.

Let me reconsider. The v3 spec says "Challenge payload MUST include a 6-digit confirmation code; user types it, not taps." This is a delay-enforcement mechanism, not cross-channel verification. The code serves to break tap-through fatigue, not to authenticate to a separate channel.

**Assessment**: The 6-digit code mitigation does NOT add cross-channel authentication. It's a UX delay mechanism. Attack as described doesn't apply.

**Status**: ATTACK DOES NOT APPLY as I initially framed it. But there IS a real concern: if a user's device is compromised (malware), the malware can read the code and auto-submit. v3 assumption B16 covers this ("user device is uncompromised as a system"). Confirmed as assumption-bounded.

---

## Attack V3-6 — PUSH-REVOCATION DENIAL OF SERVICE

**Preconditions**
- Router fails-closed on Tier 3+ if push-revocation channel unavailable.
- Attacker can DoS the channel.

**Steps**
1. Attacker DoSes customer's `revocation_channel_ref` endpoint.
2. Router loses push subscription; fails-closed on all Tier 3+ actions.
3. Legitimate deploy operations halt. Operational pressure to bypass mounts.
4. Operator might loosen Tariff or bypass Router → security degraded.

**What is violated**
- Availability. Not integrity directly, but creates pressure to bypass security controls.

**Severity: MINOR (availability) to SERIOUS (if bypass cultural norms establish)**.

**Confidence: MEDIUM**.

**Mitigation**
- Revocation channel must be HA (multi-region, multi-provider).
- Router has a small grace period (e.g., 30s) after losing channel during which actions still execute but emit high-priority alerts.
- Documented playbook for channel-down: ADMIN explicit step-up (like Tier 5 multi-party) to continue operations; never silent bypass.

**Status**: MINOR — operational resilience. v3 should specify HA requirements for revocation channel.

---

## Attack V3-7 — MANDATE-TARIFF-VERSION-LOCK-OUT

**Preconditions**
- Mandate has `min_tariff_version: N`.
- Customer updates Tariff rarely; attacker creates mandate with high N that was never reached.

**Steps**
1. Attacker signs a mandate (needs key access) with `min_tariff_version: 999` where current Tariff is version 5.
2. Router rejects mandate (Tariff version too low).
3. No attack — attacker just got their own mandate rejected.

Not really an attack. Unless attacker's goal is DoS: tie up Router processing with mandates that always fail version check. But Router rejects early; cost is minimal.

**Status**: NOT AN ATTACK — mitigation works as intended.

---

## Attack V3-8 — TARIFF FUZZ-HARNESS BYPASS

**Preconditions**
- v3 requires 10k+ synthetic intent fuzz before Tariff publish.
- Fuzz corpus is customer-authored.

**Steps**
1. Customer writes a fuzz corpus that doesn't include the attack patterns (because customer didn't think of them).
2. Fuzz passes. Tariff publishes.
3. Attacker submits intents matching the un-fuzzed pattern.
4. Classifier gives wrong tier.

**Severity: SERIOUS** (already V2-2 adjacent).

**Confidence: MEDIUM**.

**Mitigation**
- Fuzz corpus should include a **required** baseline of patterns published with v3 reference implementation. Customer's custom patterns augment but do not replace.
- Baseline covers: all destructive verbs, all resource-kind synonyms, all known attack patterns.

**Status**: SERIOUS — addressable by spec'ing the baseline fuzz corpus requirement.

---

## Summary

| # | Attack | Severity | Confidence | Status |
|---|---|---|---|---|
| V3-1 | DELEGATION-SCOPE-DRIFT | SERIOUS | HIGH | Spec precision needed (scope-match table) |
| V3-2 | SUB-THRESHOLD AGGREGATION | SERIOUS | HIGH | Acknowledged residual |
| V3-3 | REPRODUCIBLE-BUILD VERIFICATION GAP | SERIOUS | HIGH | Spec should require automated attestation |
| V3-4 | ROOT-SPARE SOCIAL ENGINEERING | SERIOUS | MEDIUM-HIGH | Operational; spec procedures |
| V3-5 | WEBAUTHN CODE LEAK | — | — | Attack doesn't apply; assumption-bounded |
| V3-6 | PUSH-REVOCATION DoS | MINOR-SERIOUS | MEDIUM | Spec HA requirement |
| V3-7 | MANDATE-TARIFF-VERSION-LOCK-OUT | — | — | Not an attack |
| V3-8 | TARIFF FUZZ-HARNESS BYPASS | SERIOUS | MEDIUM | Spec baseline fuzz corpus |

**NO new showstoppers in Round 6.**

All findings are SERIOUS-or-lower, and all are spec-tightenings or operational-concerns already partially covered. No attack requires out-of-scope mitigations (confidential LLM, formal verification, novel crypto).

---

## Red Team verdict (procedural)

Per the procedure:
> "Continue architect↔red-team iteration until a red team round produces no new showstoppers and no new serious attacks. **Cap: three red team rounds total.**"

This was round 3. It produced NO new showstoppers. It did produce five new SERIOUS findings (V3-1, V3-3, V3-4, V3-6, V3-8), four of which are spec-precision items and one of which is operational.

The architecture is **stable**. Remaining concerns are:
1. Tightening of spec precision (V3-1, V3-8)
2. Operational procedures customer-side (V3-3, V3-4, V3-6)
3. Acknowledged residuals inherent to tier-based schemes (V3-2)

None of these prevent `design-v3.md` from being promoted to `design-final.md` after one more Architect pass that incorporates the Round 6 spec tightenings.

---

## Honest meta-observation

Three rounds in, the attack surface has migrated:

- **Round 2** (v1): cryptographic protocol bugs. Plenty. Serious.
- **Round 4** (v2): architectural composition bugs. Fewer but still fundamental.
- **Round 6** (v3): spec precision and operational integrity. Most findings are "implementers could get this wrong" rather than "the design is wrong."

This trajectory is the hallmark of a design converging on something buildable. It is NOT proof that the design is correct — a real external audit with offensive capability might find crypto-level issues I missed. But the trajectory supports proceeding to Skeptic + Synthesis rather than declaring no-go.

**Recommendation**: one more architect pass (compact) to incorporate V3-1, V3-3, V3-6, V3-8 spec tightenings, then `design-final.md` + `decision.md`.
