# decision.md — EPHEMERAL

**Date**: 2026-04-18
**Status**: Final, after six rounds of adversarial review (Round 0 Skeptic → Round 1 Architect → Round 2 Red Team → Round 3 Architect → Round 4 Red Team → Round 5 Architect → Round 6 Red Team → Round 5 Skeptic Final).

---

## Verdict: **CONDITIONAL YES** (for cross-org asymmetric-trust use case only)

The preemptive NO issued at Round 0 was correct **for the original premise** (in-cloud single-trust-boundary deployment agent) and stands for that premise. The design team explicitly pivoted the premise to cross-organization asymmetric-trust (SaaS vendor running autonomous agent on customer infrastructure). Under the pivoted premise, against the final design (`design-final.md`), the Skeptic's final review concludes that the architecture clears the bar — conditionally.

---

## The short argument (final)

Three things reconciled the original objection:

1. **Proportional Authority Protocol** (introduced in `design-v2.md`, consolidated in `design-final.md`). Not all actions receive the same ceremony. Tier 0-1 actions use OIDC+DPoP+OPA — literally the Round 0 Skeptic's 80% alternative, renamed MV-0. Tier 2+ actions invoke cryptographic mandates and capabilities. Tier 4+ requires user step-up. Tier 5 requires M-of-N ceremony. Expensive machinery is reserved for actions where blast radius justifies it.

2. **Cross-organization premise**. The original no-go was premised on single-trust-boundary agents where cryptographic capabilities provide no trust benefit beyond rearranging existing trust. The pivoted premise — vendor acting on customer infrastructure under customer authority — genuinely benefits from authority decoupled from the vendor's runtime.

3. **Three red-team rounds surfaced no surviving showstoppers**. Round 2 crypto protocol bugs (OPCE, BOOT-KEY-SUB, PARAM-CANON) resolved in v2. Round 4 composition bugs (CROSS-TIER-AGGREGATION, TARIFF-SIGNING-KEY-COMPROMISE) resolved in v3 via the aggregation defense-in-depth stack and three-level key hierarchy. Round 6 found only spec-precision concerns; all resolved in design-final.

---

## Conditions (normative; C1–C7 from skeptic-review.md §9)

| # | Condition | Purpose |
|---|---|---|
| C1 | Use case confined to **genuine cross-org asymmetric trust** | Prevents deployment to the Round 0 case where 80% alt wins |
| C2 | **Action mix justifies the tier** (skip MV-2+ if workload is 95% Tier 0-1) | Prevents machinery-theater for mostly-read agents |
| C3 | **External audit by offensive-security firm** before Tier 3+ actions in production | Validates novel compositions (PAP, DelegationDocument, classifier-WASM) |
| C4 | **Conformance test suite** (`design-final.md` §15) implemented and exercised | Catches subtle implementation bugs that would CVE-propagate |
| C5 | **Customer operational maturity** (HSM access, M-of-N policy capacity, target-invariant bundles) | Prevents gap between spec and deployed reality |
| C6 | **Honest aggregation-residual disclosure** in customer-facing docs | Prevents surprise-CVE from customers expecting cryptographic prevention |
| C7 | **Plan for MV-0 as terminal state** for most adopters | Business case must not require >50% adoption at MV-2+ |

Failure to meet any condition → do not deploy at the corresponding tier level.

---

## What EPHEMERAL provides that the 80% alternative does not (cross-org case only)

- **Vendor-runtime-independent authority**. A vendor RCE in MV-1+ cannot forge Tier 2+ actions without the customer's mandate-signer key. The 80% alt's cross-org form (shared IAM role) does not close this gap.
- **Cryptographic audit chain**. COSE-signed mandates, capabilities, and audit events verify offline with only public keys, years later. The 80% alt's CloudTrail logs are authoritative but custodial.
- **Proportional ceremony**. Tier 4 step-up and Tier 5 multi-party ceremony are structurally integrated, not grafted on per-action by customer's change-control.
- **Classifier-driven escalation**. Aggregation patterns, canary windows, and missing target invariants automatically increase ceremony. The 80% alt would require each customer to build this themselves.

## What EPHEMERAL does not provide beyond the 80% alternative

- **For in-cloud single-trust-boundary agents**: nothing meaningful. Do not deploy here.
- **For agents that only read**: nothing beyond documentation. Use MV-0 (which is the 80% alt + Tariff-as-docs).
- **For LLM provider compromise (A1)**: same mitigation both architectures — credentials off the LLM I/O path.
- **For target API compromise (A5)**: same mitigation both architectures — audit-based detection.

---

## Supporting evidence trail

| Artifact | Role |
|---|---|
| `no-go-preemptive.md` | Round 0 Skeptic, original no-go for single-trust-boundary premise |
| `design-v1.md` | Round 1 Architect, cross-org pivot, first full design |
| `redteam-round1.md` | Round 2 Red Team, 3 showstoppers + 5 serious |
| `design-v2.md` | Round 3 Architect, Proportional Authority Protocol introduced |
| `redteam-round2.md` | Round 4 Red Team, 2 showstoppers + 6 serious |
| `design-v3.md` | Round 5 Architect, aggregation stack + key hierarchy |
| `redteam-round3.md` | Round 6 Red Team, no new showstoppers, 5 serious |
| `design-final.md` | Consolidated spec with Round 6 tightenings (V3-1, V3-3, V3-6, V3-8) |
| `skeptic-review.md` | Round 5 Skeptic final, flip to conditional YES |

---

## External validation required (restated)

1. **External security audit** by a firm with offensive capability against Nitro Enclaves, SPIRE attestation flows, COSE implementations, and WASM sandbox escape. Required before any Tier 3+ production deployment.
2. **Formal verification** — not required but recommended — of the PAP composition and the delegation verification chain.
3. **First production deployment under red-team engagement** by a different firm than the audit firm.
4. **Public conformance report** for the reference implementation against all test vectors in `design-final.md` §15.
5. **Cryptographic review** of the DelegationDocument format and the Tariff signing scheme. Public disclosure to IETF (OAuth/GNAP WG) for comment.

---

## Cost comparison (revised for cross-org premise)

|  | Cross-org 80% alt | EPHEMERAL MV-0 | EPHEMERAL MV-1 | EPHEMERAL MV-3 |
|---|---|---|---|---|
| Customer setup | 3–5 dev-days | 3–5 dev-days | 15–25 dev-days | 40–80 dev-days |
| Vendor setup | 20–40 dev-days | 20–40 dev-days | 100–180 dev-days | 250–400 dev-days |
| Per-integration onboarding | 1 day | 1 day | 3–5 days | 5–10 days |
| Monthly compute surcharge | 0% | 0% | ~20% (Signer enclave) | ~40% (full stack) |
| Key custody ops | Existing IAM | Existing IAM + Tariff signing | Add customer HSM | Add spare root, audit key, ceremony signers |

**Economic conclusion**: EPHEMERAL defensible for the cross-org premise IF action mix includes significant Tier 2-3+ AND the customer cares about vendor-compromise blast radius. For Tier 0-1-only workloads, MV-0 adds marginal value (documentation) over the 80% alt, which is fine but doesn't justify the effort to adopt MV-1+.

---

## Conditions under which this verdict should be revisited

**Reverting toward NO** would require:
- Disclosed attack against the v3/final design under external audit. Specifically: anything that compromises mandate integrity, delegation chain, or Signer isolation.
- Adoption data showing customers stop at MV-0 at higher than ~95% rate — suggesting the MV-1+ tiers are genuinely unnecessary rather than deferred.
- A simpler architecture emerging (e.g., GNAP-based or confidential-inference-based) that achieves the same proportional-authority property at lower cost.

**Strengthening toward unconditional YES** would require:
- Multiple production deployments with independent red-team validation.
- Published CVE-free operational track record of at least 12 months.
- Reference implementation adopted by at least one major cloud provider or standards body.

---

## Mandatory caveat

This is still a self-adversarial review by a single language model across a compressed timeframe. Six rounds produced a stable design and a defensible pivot, but:

- No external audit has been performed.
- No formal verification has been performed.
- No real-world deployment has stress-tested the design.
- The novel components (Proportional Authority Protocol, Tariff, Classifier-with-context, DelegationDocument) have no production track record.

The conditional YES is a recommendation to proceed with design-driven engineering under the stated conditions, **not** a certification of correctness. C3 (external audit) is the minimum bar before any production deployment at Tier 3+.

---

## History preserved

The preemptive NO from Round 0 stands for the single-trust-boundary use case. The conditional YES from Round 5 Skeptic Final applies to the pivoted cross-organization premise. These are not contradictory — they apply to different problems.

The architectural lesson is that **authorization ceremony should match blast radius**, not average it. The Round 0 no-go forced this insight by refusing to allow one-size-fits-all expensive machinery. The resulting design (Proportional Authority) is stronger than either the original EPHEMERAL proposal or a flat application of the 80% alternative would have been.
