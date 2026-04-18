# skeptic-review.md — EPHEMERAL Round 5 Skeptic Final Review

**Role**: The Skeptic, same voice as Round 0. Returning after three architect/redteam rounds and one major pivot to evaluate whether my original no-go holds against `design-final.md`.

**Method**: I re-read my Round 0 no-go (`no-go-preemptive.md`). I re-read `design-final.md`. I ignore the interim v1/v2/v3 docs and the red-team findings — the final spec should stand on its own. I test it against the bar I originally set, **plus** bars Round 0 didn't have to test because the premise was narrower.

**Verdict preview**: **Conditional flip from NO to YES**, but with caveats sharp enough that I want them in the executive summary. Read §9 before skipping to the bottom line.

---

## 1. What changed that matters

My Round 0 no-go was based on: "for an agent inside a single trust boundary, the 80% alternative achieves ~96% of claims at ~5–7% complexity." I listed five conditions for reconsidering. Of those, the v3/final design explicitly inhabits condition #1 — **cross-organization delegation** — as its premise. That's not me moving the goalposts; it's the Architect acknowledging my trigger was correct and pivoting to a use case where it doesn't apply.

That's a legitimate pivot. It means the no-go **for the original premise** stands. What I'm evaluating now is whether the **pivoted premise** supports a yes.

A meaningful evaluation requires me to revisit:
1. Is the cross-org premise real, or engineered to justify the architecture?
2. For the cross-org case, is the v3/final design actually better than a thoughtful 80% alt?
3. Are the adoption economics plausible?
4. Does the migration path survive first contact with real customers?
5. What's the honest "could this ship?" probability?

---

## 2. Is the cross-org premise real?

**The claim**: a SaaS vendor (DeployCo) runs an LLM-driven agent on customer infrastructure (Acme's cloud). The customer wants authority over what the agent does; the vendor wants to ship software without holding customer keys.

**Prior art supporting the premise**:
- Datadog, New Relic, Honeycomb run agents on customer infra today. They solve the auth problem crudely: the customer gives them an API key or installs a cross-account IAM role with broad permissions. Every incident report ("Datadog agent had a vuln → customers should rotate their API keys") is an instance of the problem EPHEMERAL targets.
- Harness, Octopus, Spacelift operate IaC/CD services that execute destructive operations on customer infra. They use short-lived AWS sessions, but authority is brokered by the vendor, not the customer.
- MCP-style agent-on-customer-infra patterns (Anthropic's own MCP servers when deployed as SaaS) are nascent but heading this way.
- Auditor and compliance vendors running scanning agents on regulated customers.

**So is the premise real?** Yes. The failure mode ("vendor's software has broad authority; vendor gets compromised; customer's infra is exposed") is a documented pattern, not invented.

**Is EPHEMERAL solving it, or rearranging deck chairs?** Partially solving it. The proportional design does genuinely move authority from "vendor holds API key" to "vendor holds nothing; customer cryptographically authorizes each high-tier action." For Tier 3+ actions that's real progress. For Tier 0-1 the design degrades to the 80% alt, which is fine — it's what I advocated in Round 0.

**Remaining concern**: most cross-org vendor agents today don't need Tier 3+ authority day one. They read status, file tickets, send notifications. If EPHEMERAL is pitched as "you need this now" to vendors doing Tier 0-1 work, the economics collapse — Tariff + Classifier + audit infrastructure is overkill for agents that could run on IRSA-equivalent cross-account setups.

**Resolution**: MV-0 variant in `design-final.md` §12 handles this. MV-0 *is* the 80% alternative plus documentation. Customers who never need Tier 2+ never pay for Tier 2+ infrastructure. This is the key concession that makes the design economically defensible.

---

## 3. Revised cost comparison (cross-org premise)

My Round 0 table compared 80% alt vs EPHEMERAL for in-cloud deployment agent. For the cross-org case the comparison is different.

### 3.1 The cross-org 80% alternative

The cross-org equivalent of Round 0's 80% alt:
- Customer deploys a cross-account IAM role the vendor can assume.
- Vendor's agent uses `sts:AssumeRoleWithWebIdentity` from the vendor's OIDC issuer into the customer's IAM.
- Customer attaches a scoped session policy; further narrowing via `SessionPolicy` per call.
- Vendor provides OPA-like policy bundle; customer trusts vendor to enforce it.
- Audit: CloudTrail + vendor-sent structured logs.
- Kill-switch: customer revokes trust relationship.

This works. It's what Harness and similar tools already do. Its weakness is the one EPHEMERAL targets: **the customer has to trust the vendor's orchestrator**. An RCE in the vendor's orchestrator gives an attacker the full authority the customer granted, for as long as the kill-switch isn't triggered. The cross-org 80% alt doesn't close this gap.

### 3.2 Cost vs. EPHEMERAL final

| Component | Cross-org 80% alt | EPHEMERAL MV-1 | EPHEMERAL full (MV-3) |
|---|---|---|---|
| Customer-side setup | 3–5 dev-days | 15–25 dev-days | 40–80 dev-days |
| Vendor-side setup | 20–40 dev-days | 100–180 dev-days | 250–400 dev-days |
| Ongoing per-integration onboarding (customer) | 1 day | 3–5 days | 5–10 days |
| Key custody ops | Existing IAM | New: customer HSM for K_cust_* | Plus audit key, spare root, ceremony signers |
| Tariff authoring | N/A | 2–5 days per integration | 5–15 days per integration |
| Target-level invariants | Optional | Optional (reduced protection if absent) | Required for Tier 3+ |
| Attestation pipeline | None | Manual-optional | Automated, public transparency log |

**The gap is still large** — MV-3 is 10-20× the cross-org 80% alt's customer effort. That's down from Round 0's 15-25× but still a lot.

**Where does that gap earn its keep?**
- For agents that only do Tier 0-1: it doesn't, and MV-0 is the correct variant. (The Architect acknowledges this.)
- For agents that do Tier 2-3: roughly 5-10× cost over 80% alt. Earns its keep if the threat model includes vendor compromise AND the customer cares about damage from compromised-vendor-led destructive actions.
- For agents that do Tier 4-5: the step-up and ceremony costs are comparable to what a careful customer would build anyway (HSM + quorum + change-control approval workflow). EPHEMERAL formalizes them.

**Updated verdict on economics**: The cost is defensible **if** the agent actually performs Tier 2+ work AND the customer has significant blast-radius exposure. Excluded: vendors doing only read/status work, vendors acting on non-critical resources, customers whose compliance/regulatory bar is low.

---

## 4. Adoption economics: who pays, who benefits

This is where I want to push hardest, because it's where most security standards die.

### 4.1 Who benefits

- **Customer**: more confidence in vendor-operated agents. Bounded blast radius from vendor compromise. Real cryptographic audit trail.
- **Vendor**: differentiated security story. "We can't exfiltrate your keys because we don't have them." Enterprise-sales enabler for regulated customers.
- **LLM provider**: marginal. They never held customer credentials even in the 80% alt. They don't actively benefit.
- **Regulator / auditor**: offline-verifiable cryptographic authority chains. Real progress over "check our SIEM logs."

### 4.2 Who pays

- **Customer**: significant setup cost (§3.2). Ongoing key custody.
- **Vendor**: larger setup cost. Must operate enclave infrastructure, attestor services, Tariff tooling, etc.
- **LLM provider**: trivial (no changes required on their side for MV-0/MV-1; none at all really until confidential inference becomes standard).

### 4.3 The vendor adoption problem

This is the hard one. A vendor asking "should I implement EPHEMERAL?" faces:
- Development cost: 100-400 dev-days.
- Operational cost: enclave infrastructure, HSM-adjacent tooling, Tariff conformance test suite.
- Customer onboarding friction: each customer needs 15-80 dev-days of their own work.
- Competitive pressure: most competitors are using the cross-org 80% alt; EPHEMERAL customers pay more upfront for the same (or better) security.

**Why would a vendor do this?**
- Regulated verticals where the competing offering is "compliant by exception"; EPHEMERAL makes compliance structural.
- Large customers with security-engineering teams that will audit the vendor's authorization architecture anyway; EPHEMERAL turns that audit into a one-time review instead of continuous relitigation.
- Post-incident retrofits. A vendor that suffered a breach and exposed customer credentials has strong incentive.

**Why would a vendor NOT do this?**
- Early-stage vendor shipping fast. Time-to-market is everything. 100-400 dev-days is an existential cost.
- Vendor whose agents are genuinely low-privilege (read-only dashboards, notifications). 80% alt is adequate.
- Vendor whose customers don't ask about the authorization model. (Most SMB customers don't.)

**Net assessment**: Adoption will come from enterprise-vertical-with-regulated-customers segment first (financial services, healthcare, government). It will not come from mainstream SaaS. This is fine for a standards play but it's not mass adoption, and the reference implementation needs to be correspondingly careful — errors will be discovered by customers with compliance obligations, not by tolerant early adopters.

### 4.4 LLM-provider incentives

The design doesn't require LLM-provider cooperation for MV-0/MV-1. LLM-provider-side involvement would matter for:
- Confidential inference (still far off for frontier models; premium products at best).
- Signed attestation of the provider's inference runtime (partial attestation already available in some tiers — e.g., AWS Bedrock VPC attestation).
- Commitment not to store/train on agent prompts (contractual, not cryptographic).

**EPHEMERAL doesn't depend on LLM-provider cooperation.** That's a feature — it ships without coordination. It's also a limit — it can't claim the LLM itself is uncorrupted; it can only claim that a corrupted LLM can't wield authority.

---

## 5. Migration path realism

The `design-final.md` §12 MV-0 → MV-3 path is well-structured on paper. Reality check:

### 5.1 MV-0 → MV-1 (adding Tier 2 — Mandate+Capability)

This is the first real jump. Customer needs:
- HSM or equivalent for `K_cust_root` (non-trivial; many cloud customers use KMS, not HSM).
- `K_cust_ops` ceremony defined and tested.
- First Tariff authored.
- First Classifier WASM authored or adopted from reference library.

**Friction estimate**: 15-25 days customer effort, 1-2 weeks elapsed. Most customers can do this if motivated; first customer per vendor will set a lot of precedent.

### 5.2 MV-1 → MV-2 (adding Tier 3-4 — destructive + step-up)

Adds:
- Push-revocation HA (multi-region deployment).
- WebAuthn device enrollment for operators.
- Target-level invariants deployed.

**The hard part is target-level invariants.** K8s admission controllers are mature; DB constraints are case-by-case; non-K8s/non-DB targets are often impoverished. Customers will skip target-level invariants ("we'll accept `target_invariants_documented: false`") and then be surprised their Tier 3+ actions auto-escalate to step-up, which is noisy.

**Concern**: the protocol-level penalty for missing target invariants is a good incentive, but if step-up is too noisy, customers will revert to MV-1 and confine agents to Tier 2. That's fine behaviorally but defeats the design's ambition.

**Mitigation suggested back to the Architect**: the reference implementation should ship pre-baked Target-Invariant bundles for common scenarios (Kyverno policy packs for K8s, SQL triggers for Postgres, etc.) so customers can check the "documented" box for 70% of cases without writing their own.

### 5.3 MV-2 → MV-3 (adding Tier 5 ceremony)

Ceremony infrastructure is heavy. In practice very few actions will be Tier 5 (Tariff modifications, root-signer changes). Most customers won't reach MV-3 for operational reasons. That's acceptable as long as Tier 5 actions remain rare-by-design — which `design-final.md` does ensure.

### 5.4 Expected real-world adoption shape

- 80% of adopters stop at MV-0 (they didn't actually need Tier 2+).
- 15% reach MV-1 (enough for their use case).
- 5% reach MV-2/MV-3 (the intended long tail).

This is not a failure — it's a reasonable power-law adoption for security infrastructure. But it means EPHEMERAL's value is heavily concentrated in the 5% tail. The reference implementation and docs must make MV-0/MV-1 feel valuable in themselves, not just a stepping stone.

---

## 6. The 80% alt still matters

Here's where I want to be explicit about what hasn't changed.

**For the in-cloud deployment agent** (the original Round 0 use case), **the 80% alt still wins**. If someone brings me "we want to deploy an autonomous deployment agent inside our own cloud," I still recommend IRSA + Vault JWT + OPA + DPoP + audit. Every round of EPHEMERAL review has confirmed this rather than refuted it.

**The v3/final design acknowledges this via MV-0**, which is literally the 80% alt with Tariff-as-documentation. So the Architect and I agree on that case.

The disagreement is resolved by recognizing different premises need different solutions.

---

## 7. The condition check (Round 0 §7)

Round 0 listed five conditions for reconsidering. Checking each:

| Condition | Status against design-final |
|---|---|
| 1. Use case pivot to cross-org | **Met**. Design premise is cross-org. |
| 2. Untrusted host requirement | Partially met. Customer is "not fully trusted" from vendor's perspective; vendor is "not fully trusted" from customer's perspective. TEE protects vendor-side keys even under customer infra access. |
| 3. Regulatory driver (offline verifiable) | Addressable, not met. The design supports offline verification (COSE signatures + Tariff + delegation chain are all verifiable years later). No specific regulation has been cited as driver. |
| 4. Breach evidence against 80% composition | Not met. No disclosed attack against IRSA+Vault+OPA+DPoP. |
| 5. Consortium commitment | Not met. No LLM provider or target-API operator has committed. |

**Conditions 1 is fully met and is the hinge. Condition 2 is mostly met (asymmetric trust). Others are not met, but conditions 1 and 2 together are sufficient — the original "one or more" criterion is met.**

---

## 8. What I still don't love

1. **The novel parts have no production track record.** Proportional Authority Protocol, Tariff, Classifier-as-WASM with stateful context — these are inventions. They look sound, and Round 6 Red Team didn't break them, but two LLM-driven rounds are not a safety certificate. The Architect says this repeatedly; I'm reinforcing it.

2. **Operational complexity at the customer side is underweighted.** Even at MV-1, the customer is signing Tariffs, rotating keys, running attestors or verifying attestor evidence, maintaining revocation channels. The "customer is competent" assumption is real but large. Documentation must be exceptionally good.

3. **The sub-threshold aggregation residual (V3-2) is real and marketing will want to gloss over it.** If the reference implementation's docs undersell this, customers will assume it's prevented and be surprised. The design team must be unusually honest about this in customer-facing documentation.

4. **Reference implementation quality matters more than usual.** A reference implementation with a subtle bug in delegation scope verification (V3-1) could escalate to CVE across all adopters. This is not an environment where "move fast, fix bugs" is acceptable. Treating reference implementation engineering cost as comparable to the spec effort is honest — plan for it.

5. **DeployCo operator insider threat (A6) is under-mitigated.** The design assumes DeployCo operators are not actively hostile. Audit countersignature by customer helps, but a DeployCo operator who can influence what intent gets submitted (e.g., via support-request channels) can still direct actions within the mandate. Not a cryptographic attack but a real operational concern. This should be documented as an assumption.

6. **The PCR-attestor transparency log scheme (V3-3 mitigation) requires a working transparency log ecosystem.** Sigstore is maturing but is not yet the institutional Certificate-Transparency-like infrastructure this depends on. Early adopters will carry infrastructure risk here.

---

## 9. Verdict — and what it conditions on

**I flip my verdict from NO to YES, conditionally.**

The conditions are:

**C1 — Use case confined to genuine cross-org asymmetric trust.** Do not deploy EPHEMERAL for in-org agents — the 80% alt remains superior for that case.

**C2 — Action mix justifies the tier.** If the agent's workload is 95% Tier 0-1, deploy MV-0 and don't pretend you need more. The Tariff-as-documentation value is real but doesn't by itself justify the cognitive overhead vs. a well-documented OPA bundle.

**C3 — External audit before production.** Proportional Authority Protocol, DelegationDocument, and the classifier-WASM-with-context are novel compositions. External audit by a firm with offensive capability against COSE, enclave attestation flows, and WASM sandbox escape is non-negotiable before Tier 3+ actions are authorized for any customer.

**C4 — Reference implementation includes conformance suite.** `design-final.md` §15 specifies the conformance test suite. The reference implementation MUST ship with these vectors implemented and exercised. Implementations without demonstrated passage should not be deployed.

**C5 — Customer operational maturity.** Customer must have HSM access (or credible KMS proxy), M-of-N officer policy capacity, and willingness to author or adopt a target-level invariant bundle for Tier 3+. Customers who can't commit this should stop at MV-1.

**C6 — Honest aggregation-residual disclosure.** Customer-facing documentation must name sub-threshold aggregation (V3-2) and describe its mitigation as operational, not cryptographic. Customers who expect cryptographic prevention of aggregation will be surprised; surprised customers drive CVEs.

**C7 — Plan for MV-0 as terminal state.** Most adopters will stop at MV-0 and that's acceptable. If the business case requires >50% of customers at MV-2+, the business case is wrong.

---

## 10. What changed my mind

I want to be explicit about this, because I am conscious that rounds of iteration can look like moving goalposts.

- **The Proportional Authority pivot** resolved my fundamental objection. In Round 0 I said "this architecture is theatre for most actions." The pivot concedes that and reserves the expensive machinery for actions that actually need it. This is correct engineering.
- **MV-0 as literal 80% alt** concedes the original use case to me. The Architect isn't claiming EPHEMERAL beats IRSA+Vault+OPA for in-cloud agents — they're claiming it beats it for cross-org agents, and for high-tier actions specifically.
- **Three red-team rounds without a surviving showstopper**. The attack surface migrated from "crypto protocol bugs" (Round 2) to "spec precision and operational honesty" (Round 6). This trajectory is what a converging design looks like. Not proof of correctness, but the right shape.
- **The Round 6 tightenings close real gaps**. Automated attestation (V3-3) replaces human rubber-stamping; baseline fuzz corpus (V3-8) prevents "customer forgot this pattern"; HA revocation (V3-6) prevents DoS → bypass-culture; scope-match table (V3-1) hardens delegation verification. These are the right improvements.

---

## 11. What I'm not saying

- I am not saying EPHEMERAL is correct. A competent external audit could still find something I missed. Round 6 produced no showstoppers under LLM-driven review; that is not the same as "no showstoppers exist."
- I am not saying adoption is likely. The cost and coordination required are real. Most vendors will not adopt this. Those that do will be in specific verticals.
- I am not saying the 80% alt is inferior generally. For its intended use case (in-cloud agent, single trust boundary) it remains the right answer.
- I am not retracting my Round 0 no-go. That verdict was correct for its premise. The premise changed.

---

## 12. Recommendation

Proceed to production implementation subject to C1–C7 above. Update `decision.md` to reflect the conditional YES.

The burden is now on the implementation to prove the design: conformance suite, external audit, first production deployment with post-hoc review by a different offensive-security firm. If any of those fail to produce confidence, re-open this review.

The design has earned a conditional YES. It has not earned a blank check.
