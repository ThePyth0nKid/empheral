# no-go-preemptive.md — EPHEMERAL Round 0 Skeptic Review

**Role**: The Skeptic. Principal engineer who has watched twenty security standards fail to achieve adoption. I am tasked with constructing the strongest possible version of the 80% alternative to EPHEMERAL and honestly assessing the gap.

**Verdict**: EPHEMERAL does not clear the bar over existing alternatives for the stated use case and threat model. The hard no-go trigger is met. I recommend stopping the design process.

---

## 1. The 80% alternative, steelmanned

The stated first use case is an autonomous deployment agent: read secrets from Vault, patch Kubernetes Deployments and ingress rules, rotate a database credential, confirm-or-rollback. The entire action surface lives inside one organization's cloud boundary. I construct the 80% alternative for exactly this.

### 1.1 Workload identity and short-lived credentials

- Agent runs in a Kubernetes pod with IRSA (IAM Roles for Service Accounts) or equivalent (GKE Workload Identity, AKS Workload Identity). The pod gets a projected service-account token, rotated by kubelet on a fixed interval (typically 3600s or shorter).
- That projected token is the OIDC JWT used for federation.
- Target credential domains are reached by trading the JWT:
  - **Vault** — `auth/jwt` role constrained by `bound_audiences`, `bound_subject`, `bound_claims`. Tokens issued with TTL ≤ 15 min and narrow policy.
  - **AWS** — `sts:AssumeRoleWithWebIdentity` with inline `SessionPolicy` narrowing the session to exactly the action's required permissions. Role trust policy pins the OIDC issuer and subject.
  - **Kubernetes** — pod's own service account, RBAC scoped to the target namespaces and verbs.
  - **Third-party SaaS APIs (Stripe, Slack, GitHub)** — fine-grained App tokens / Restricted Keys / installation tokens, stored in Vault, fetched per-action via the scoped Vault token. Where supported (GitHub Apps, newer Slack), mTLS or JWT-assertion-bound.

### 1.2 LLM interface

- LLM is consulted via structured function calling / tool-use.
- Prompts contain state, intent, recent history — **never credentials**. This is a design invariant identical to EPHEMERAL's.
- Completions are structured tool calls. Orchestrator validates every field.
- Orchestrator runs in our pod, not the LLM provider. The LLM provider executes only inference. It has no code-execution foothold in our environment.

### 1.3 Policy and authorization

- OPA (Open Policy Agent) evaluated before every tool call. Rego policy sees: `{action, resource, params, mandate_id, budget_consumed, time_window, llm_reasoning}`. Deny by default.
- Policy bundle distributed and signed; rotation via OPA bundle API.
- Per-mandate cost/rate budget tracked in a small state store (Redis, DynamoDB) and consulted on every decision.

### 1.4 Token-binding and anti-replay

- DPoP (RFC 9449) on APIs that support it. A stolen bearer token is useless without the corresponding private key — and the private key lives only in the pod that minted it.
- mTLS to backend APIs where available (Vault, internal services).
- For APIs that accept neither, tokens are minted with the smallest possible TTL and scoped at mint-time to the specific resource (e.g., Vault one-shot response-wrapped secrets).

### 1.5 Egress controls

- NetworkPolicy + Cilium / service-mesh egress: pod can only reach named external hosts.
- Cloud-level egress firewall (AWS VPC endpoints + security groups) as defence-in-depth.

### 1.6 Audit and kill-switch

- Every tool call, OPA decision, token mint, API response written to a structured log stream (Fluent Bit → CloudWatch + S3 Object Lock, or equivalent).
- CloudTrail / target-API audit feeds correlated into SIEM.
- Kill-switch: one button disables the OIDC trust relationship in Vault's JWT auth config, AWS IAM OIDC provider, and any third-party OAuth grant. All outstanding tokens expire within ≤15 min. No new tokens can be minted.

### 1.7 Supply chain

- SBOM per build (CycloneDX / SPDX), dep pinning, image signing (Sigstore / cosign).
- Runtime image scanning (Trivy / Snyk).
- Admission controller verifies image signatures before deploy.

This is not speculative. It is standard modern SRE with small adaptations for agent workloads. It is deployable today by any competent platform team.

---

## 2. Claim-by-claim comparison

EPHEMERAL's four claims:
1. Agents never hold long-lived, transferable credentials.
2. Compromise of the LLM provider's infrastructure does not grant executable authority.
3. Compromise of a dependency in the agent's software supply chain does not grant persistent authority.
4. Every action is individually authorized, scope-bound, time-bound, and audited.

### Claim 1 — No long-lived, transferable credentials

- **EPHEMERAL**: Ed25519 key generated and kept in enclave (Nitro); attestation-bound SVIDs from SPIRE; per-action capabilities.
- **80% alt**: OIDC JWT rotated every ~hour by kubelet; Vault tokens ≤15 min; AWS STS sessions ≤15 min; DPoP bindings where supported.
- **Gap analysis**: The 80% alt's tokens are "short-lived, memory-resident for minutes, bound to the issuing pod." EPHEMERAL's signing key is "hardware-custody, never memory-resident in plaintext outside the enclave." The difference is only meaningful if the agent host itself is adversarial — which is explicitly not the case for an in-cloud deployment agent.
- **Claim achievement by 80% alt**: ~95%.

### Claim 2 — LLM provider compromise does not grant authority

- **EPHEMERAL**: LLM sees only intents; orchestrator is in the user's enclave.
- **80% alt**: LLM sees only tool calls; orchestrator is in the user's pod. Credentials are never on the LLM I/O path.
- **Gap analysis**: NONE. Both architectures solve this by putting the orchestrator and credentials outside the LLM provider's infrastructure. The enclave does not add value on this threat because the LLM provider has no foothold either way. EPHEMERAL's enclave is a defence against a *different* threat (A4, compromised orchestrator host), not against A1.
- **Claim achievement by 80% alt**: 100%.

### Claim 3 — Dependency compromise does not grant persistent authority

- **EPHEMERAL**: Code execution in the orchestrator can steal a capability for the current action. No persistence; one action's worth of blast radius.
- **80% alt**: Code execution in the agent can use currently-minted short-lived tokens for ≤15 min, constrained by policy. Refresh requires being in the pod (already compromised); kill-switch removes the ability to refresh. No persistence across the kill-switch.
- **Gap analysis**: "Persistent" is the operative word. Neither architecture grants persistence. EPHEMERAL's blast-radius window is "one action" vs. "≤15 min of authorized actions." In real-world exploitation, attackers operate in seconds to milliseconds — neither "15 minutes" nor "one action at a time" is a meaningful constraint on an attacker who has already achieved code execution inside the orchestrator. Both reduce to "exfiltrate as much as possible within the mandate before detection."
- **Claim achievement by 80% alt**: ~90%.

### Claim 4 — Per-action authorization, scope-bound, time-bound, audited

- **EPHEMERAL**: Mandate → PDP → per-action capability → proxy → bearer call → audit.
- **80% alt**: OPA policy → per-action check → mint scoped short-lived credential → API call → audit log.
- **Gap analysis**: Structurally identical. EPHEMERAL's cryptographic capabilities add offline verifiability (an auditor years later with only public keys can verify the mandate was respected) and attenuable delegation (a capability holder can narrow and re-issue). Neither property is exercised by a deployment agent acting on its own org's resources.
- **Claim achievement by 80% alt**: 100% for the stated use case.

### Weighted average

Approximately 96% claim achievement by the 80% alternative on the stated use case.

---

## 3. Complexity comparison

### 80% alt incremental effort, assuming a platform team that already runs EKS/GKE + Vault + OPA

| Component | Effort |
|---|---|
| OIDC federation config (Vault JWT auth + AWS IAM IdP) | 1–3 days |
| OPA policy bundle for tool calls | 3–5 days |
| Tool-call wrapper integrated with OPA | 2–4 days |
| DPoP binding layer where supported | 1–2 days |
| Audit logging integration | 2–3 days |
| Kill-switch runbook + chaos test | 1–2 days |
| **Total** | **~2 weeks** |

If the org lacks the prerequisites, add ~4–6 weeks for those foundations.

### EPHEMERAL effort from zero

| Component | Effort |
|---|---|
| Nitro Enclave build + deploy pipeline | 4–8 weeks |
| SPIRE deployment + Nitro attestor integration | 3–6 weeks |
| Mandate format + signing library + operator signing UX | 4–6 weeks |
| Policy Decision Point (custom or OPA-extended with capability semantics) | 3–5 weeks |
| Capability Exchange Proxy (credential storage, translation, HA, rate limiting, audit) | 6–10 weeks |
| In-enclave orchestrator (vsock I/O, attestation-gated boot, key custody, restart semantics) | 6–10 weeks |
| Append-only tamper-evident audit log | 2–4 weeks |
| Revocation infrastructure (mandate revocation propagation, short-lived capability pre-revocation) | 2–3 weeks |
| Integration, failure-mode handling, chaos testing | 4–8 weeks |
| **Total** | **~8–12 months** |

Even for an org starting from zero on both, the ratio is ~6–8× in favour of the 80% alternative.

For an org with modern SRE already in place, the ratio is **~15–25×**.

---

## 4. Threat-model delta (A1–A5)

| Threat | 80% alt | EPHEMERAL delta | Delta worth 15–25×? |
|---|---|---|---|
| **A1** Malicious LLM provider insider | Full mitigation — no credentials on LLM path | Zero | No |
| **A2** Supply-chain dep compromise | Bounded to ≤15 min; DPoP-bound; no persistence | Narrows window to per-action | Marginal; attackers operate in seconds |
| **A3** Network attacker | TLS + mTLS | Same primitives | No |
| **A4** Compromised agent runtime (RCE) | Bounded to mandate scope; kill-switch in 15 min | Same bound if RCE is in-orchestrator; protects key custody if RCE is on host OS | Marginal unless host OS is untrusted — it isn't for an in-cloud deployment agent |
| **A5** Compromised target API | Audit-based detection only | Same | No |

**No threat in the stated model is structurally under-handled by the 80% alternative.**

---

## 5. Where EPHEMERAL *would* earn its complexity (not this use case)

To avoid false negatives, here are scenarios where EPHEMERAL's choices make architectural sense. None are the autonomous deployment agent:

1. **Cross-organization agent workflows.** A SaaS vendor runs agents on customer resources. The customer wants cryptographic mandate issuance with no vendor-side authority. EPHEMERAL's attestation + capability is genuinely stronger than "install our agent and give it an API key."
2. **Multi-party capability delegation / agent swarms.** Agents that delegate subtasks to other agents with attenuation of authority. Macaroons and Biscuits shine here; there is no comparable standard 80% alternative.
3. **Untrusted host environments.** Agent runs on edge, community-run, or co-located compute where the host OS is adversarial. Only TEE provides confidentiality + integrity for the agent process itself.
4. **Regulated workflows requiring offline audit verifiability.** A mandate that a regulator can verify years later using only public keys and archived capability chains, with no live PDP call. Cryptographic capabilities beat stored policy decisions here.
5. **Capability markets / machine-to-machine commerce.** Capabilities that are transferable, assignable, or tradable as first-class artifacts.

**The autonomous deployment agent is none of these.** It runs in your cloud, on your nodes, against your resources, directed by your LLM provider, logged to your SIEM. Every component is already inside a single trust boundary. Cryptographic capabilities and TEE attestation here are ceremony without trust benefit.

---

## 6. Hard no-go trigger

Per procedure: "Round 0 Skeptic finds the 80% alternative achieves ≥90% of claims with ≤20% complexity."

- **Claim achievement**: ~96% weighted.
- **Complexity ratio**: 80% alt is 4–7% (from zero) to 5–7% (with prereqs) of EPHEMERAL's effort. Well under 20%.
- **Trigger MET.**

---

## 7. What would change my mind

I am not a dogmatist. Specific premise changes that would move my verdict:

1. **Use case pivot.** If the real first use case is cross-org agent delegation (vendor acting on customer infra with customer-issued mandates), re-evaluate. EPHEMERAL has a genuine story there.
2. **Untrusted host requirement.** If the agent must run on compute where the host OS is adversarial — colocation, edge, community-hosted — TEE earns its keep.
3. **Regulatory driver.** If a specific regulation requires cryptographic offline verifiability of agent authority (not just logging), capabilities beat policy decisions.
4. **Breach evidence against the 80% composition.** Disclosed attacks that break short-lived OIDC + DPoP + OPA in a way the industry cannot patch incrementally would shift the calculus. I am not aware of any as of 2026-04.
5. **Consortium commitment.** If two or more major LLM providers and two or more major target-API operators (e.g., GitHub, AWS, Stripe) publicly commit to a capability-accepting interface, the proxy becomes less critical and the architecture is less theatre.

Absent one of these, the no-go stands.

---

## 8. Recommended action

1. **Stop the EPHEMERAL design process.** Do not proceed to Round 1.
2. **Build the 80% alternative** if not already deployed. It is tractable in ~2 weeks with existing tooling.
3. **Invest narrowly.** If a specific requirement from §5 applies (cross-org, untrusted host, offline audit), scope EPHEMERAL to that requirement only. Do not build a general-purpose architecture for a niche problem.
4. **Watch the environment.** DPoP adoption, GNAP standardization, confidential LLM inference, and cross-vendor agent interop specs are incrementally raising the 80% bar. If they coalesce, EPHEMERAL's marginal value shrinks further.

---

## 9. Honest caveat

This is a self-adversarial review by a single language model on 2026-04-18. It is not a substitute for:
- External security audit by a firm with offensive capability against the relevant primitives.
- Formal verification of any cryptographic protocol.
- Real-world red-team engagement under production threat.

The analysis rests on current (early 2026) maturity of IRSA, Vault, OPA, DPoP (RFC 9449), OIDC federation, SPIRE, and AWS Nitro Enclaves. A materially different use case (cross-org, untrusted host, regulated offline audit) could flip the verdict. The no-go applies specifically to the question as posed.
