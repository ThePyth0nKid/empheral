# decision.md — EPHEMERAL

## Verdict: **NO** (preemptive, Round 0)

EPHEMERAL should not be built as specified. For the autonomous deployment agent use case — an agent acting within a single organization's cloud trust boundary — the 80% alternative meets ~96% of EPHEMERAL's security claims at roughly 5–7% of the implementation cost. The hard no-go trigger defined in the procedure ("80% alt achieves ≥90% of claims with ≤20% complexity") is met.

## The short argument

EPHEMERAL's distinctive machinery — TEE-hardened orchestrator, SPIRE-issued SVIDs, cryptographic capabilities, in-enclave PDP, capability exchange proxy — defends against threats that do not arise in the stated use case: untrusted hosts, cross-organization delegation, offline-verifiable authority chains, and capability attenuation at scale. For an agent acting on its own organization's infrastructure, directed by its own LLM provider, logged to its own SIEM, every defended component is already inside a single trust boundary. The cryptographic ceremony does not buy additional trust; it rearranges it.

On each in-scope threat:

- **A1 (malicious LLM-provider insider)** is handled identically by both architectures, because neither places credentials on the LLM I/O path. The enclave adds nothing here.
- **A2, A4 (dep compromise, RCE)** — EPHEMERAL narrows the exploitation window from "≤15 min of authorized actions" to "per action," but realistic attackers operate in seconds to milliseconds inside a compromised process. The granularity delta is operationally meaningless.
- **A3 (network attacker)** — TLS/mTLS in both. No structural difference.
- **A5 (compromised target API)** — audit-based detection only in both. No structural difference.

EPHEMERAL's unique value props are real, but they apply to scenarios not covered by the stated use case: cross-org delegation, untrusted-host execution, regulated offline-verifiable authority, capability markets. Build for those when and if they arise. Do not build general infrastructure for a specific niche.

## Minimum viable implementation (of the 80% alt, not EPHEMERAL)

For an org deploying an autonomous deployment agent today:

1. Workload identity via IRSA or equivalent (projected SA tokens from kubelet).
2. Vault `auth/jwt` with `bound_audiences` + `bound_claims`; tokens TTL ≤ 15 min; narrow policy per action class.
3. AWS `AssumeRoleWithWebIdentity` with inline `SessionPolicy` per call, narrowing to the specific action's permissions.
4. OPA policy bundle evaluated before every tool call; decisions logged with `{mandate_id, action, params, verdict, reason}`.
5. DPoP (RFC 9449) on APIs that support it; mTLS elsewhere; one-shot response-wrapped secrets from Vault for the rest.
6. Structured audit logs (CloudTrail + S3 Object Lock or equivalent append-only store).
7. Kill-switch runbook: revoke OIDC trust in Vault JWT auth + IAM IdP → all outstanding tokens expire in ≤15 min.
8. Egress NetworkPolicy + VPC-level allowlist for target API endpoints only.
9. Supply-chain hardening: SBOM + image signing + admission-controller verification.

**Engineering effort**: ~2 weeks with existing Vault/OPA/IRSA prereqs; ~6–8 weeks from zero.

## External validation required *if* this had been a "yes"

Not applicable for the no verdict. For future use cases that re-open the question:

- External security audit by a firm with offensive capability against Nitro Enclaves, SPIRE attestation flows, and Biscuit/Macaroon implementations.
- Formal verification of the mandate → capability → proxy protocol and its composition with target-API bearer semantics.
- Deployment gated on mutual consent and operational coordination with the LLM provider, the mandate issuer, and the target-API operator.
- Independent cryptographic review of any capability-attenuation scheme, and disclosure of all primitives to the IETF (OAuth/GNAP WG).

## Cost comparison

|  | 80% alt | EPHEMERAL |
|---|---|---|
| Engineering, org with prereqs | ~10 dev-days | ~160 dev-days (lower bound) |
| Engineering, org from zero | ~40 dev-days | ~240 dev-days (lower bound) |
| Monthly compute surcharge | 0% | ~2–3× on orchestrator + proxy infra |
| Ops complexity | Existing SRE primitives | New: enclave tooling, SPIRE ops, proxy HA, bespoke audit pipeline |
| Vendor coupling | Cloud-standard | Nitro-specific in practice (portability is claimed, not cheap) |

## Conditions under which this verdict should be revisited

1. The real first use case is cross-organization agent delegation, not in-org deployment.
2. The agent must run on hosts where the host OS is untrusted (edge, colo, community compute).
3. A regulatory requirement emerges for offline-verifiable cryptographic authority chains (not satisfiable by retained audit logs).
4. A disclosed attack breaks the 80% composition in a way that cannot be patched incrementally with DPoP, OPA extensions, or short-TTL policy.
5. Two or more major LLM providers and two or more major target-API operators publicly commit to accepting capability-based authorization (not bearer tokens). This would halve the proxy's architectural necessity and re-cast EPHEMERAL as a genuine standards play.

## Caveat (mandatory)

This is a self-adversarial review by a single language model (2026-04-18). It finds known attack classes, design ambiguities, and composition issues. It is **not** a substitute for external security audit by a firm with offensive capability against the relevant primitives, formal verification of cryptographic protocols, or real-world red-team engagement under production threat. A surviving design from this process would be a candidate for external review, not a finished artifact. This no-go verdict carries the same caveat in reverse: it is a strong recommendation, not an infallible one. If the stated premises change, re-run the review.

## Supporting evidence

- `no-go-preemptive.md` — full Round 0 Skeptic analysis with per-claim and per-threat breakdown, steelmanned 80% alternative, and conditions for reconsidering.
