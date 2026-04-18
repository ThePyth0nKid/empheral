# redteam-round1.md — EPHEMERAL, Round 2 Red Team

**Role**: The Red Team. Offensive security researcher with CVEs against major OAuth implementations and production breaches at FAANG. I do not accept assurances; I look for the gap between what a design claims and what it proves.

**Target**: `design-v1.md` (Round 1). Cross-org premise (DeployCo managed agent on Customer infra).

**Ground rules**: Severity is frozen — the Architect in Round 3 may accept, reject, or mark-as-residual each attack but **may not downgrade severity to avoid engaging**. Confidence is my estimate of whether a competent external reviewer would find the same attack.

---

## Attack 1 — OPCE: Orchestrator Prompt-Context Key Exfiltration

**Preconditions**
- A2 (supply-chain compromise): any third-party library loaded into the enclave's orchestrator process has a hostile version at least once. Realistic vectors: compromised `openai` npm/Pip package, compromised logging library (Sentry, Datadog), compromised OpenTelemetry collector, compromised JSON parser used for intent normalization.
- OR A1 (malicious LLM provider insider) with ability to cause orchestrator to echo prompt contents back under conditions the LLM provider controls.

**Steps**
1. The enclave image measures **the files on disk**. It does not prevent those files from reading arbitrary memory within the enclave's process space once loaded.
2. The orchestrator, PDP, and LLM client all run in the same enclave. `K_enc_priv` (Ed25519 private half used to sign capabilities) is in the orchestrator's address space.
3. A compromised LLM-client dependency — or a compromised telemetry dependency linked into the orchestrator — reads `K_enc_priv` from process memory.
4. Exfiltrates it via one of:
   - Embedding bytes in a prompt "as a debug annotation" to the LLM provider
   - Encoding it in a tool-result trace to the LLM provider's logging service
   - Writing it to a Datadog/Sentry endpoint
   - Tunneling it via DNS lookups out of the enclave (if any DNS egress is allowed)
5. Recipient uses `K_enc_priv` to forge capabilities. Any attestation doc already issued for this enclave's `K_enc_pub` will validate forged capabilities at the proxy until the enclave restarts and produces a new key.
6. Window: minutes to hours, depending on enclave restart cadence.

**What is violated**
- A7 ("orchestrator code correctly avoids mixing secrets into LLM context") — but in a more general form than A7 anticipates. A7 is written as a discipline for the orchestrator author. This attack does not require the author to err — it requires only one dependency in the transitive closure to err, which is operationally indistinguishable from inevitable.
- The claim "compromise of a dependency does not grant persistent authority" — the forged capabilities are not "persistent authority" in the strict sense (they die at enclave restart), but they allow an attacker to execute **any action within the mandate**, not just "one action's worth" — which was the design's implicit bound for dep compromise.

**Severity: SHOWSTOPPER**

**Confidence: HIGH**. This is the classic mistake in every TEE-assisted design: putting sensitive key material in the same address space as complex, dep-heavy code. Any security reviewer with TEE background finds this in <1 hour.

**Proposed mitigation**
Signer-isolation pattern:
- Split the enclave into two roles: **Signer Enclave** (holds `K_enc_priv`, exposes a single function `sign(capability_bytes) -> signature`, no other functionality, no third-party deps beyond a vetted crypto library and a tiny IPC server) and **Orchestrator Enclave** (all LLM client, PDP, business logic).
- IPC via vsock with strict message schema: Orchestrator sends a CBOR-encoded capability, receives a signature. Signer never returns the private key or derived material.
- Attestation: proxy must verify the attestation doc of the **Signer Enclave**, not the Orchestrator. The Signer's measurements are stable across Orchestrator dep updates.
- This reduces the trusted computing base for `K_enc_priv` from "all of the orchestrator's deps" to "libsodium + ~200 LOC of IPC code."

Alternative: use AWS KMS with attestation-gated condition keys (the KMS grant requires an attestation doc matching specific PCRs). Private key never materializes in enclave memory; signing is a KMS API call gated on attestation. Adds latency; removes key-exfiltration risk entirely.

---

## Attack 2 — BOOT-KEY-SUB: Unmeasured vsock bootstrap substitution of `K_cust_pub`

**Preconditions**
- A6 (malicious DeployCo operator or vendor-side supply chain compromise of the parent-EC2 image / user-data / cloud-init scripts).
- The enclave receives `K_cust_pub` — or any other bootstrap config — over vsock from the parent at boot, which is standard Nitro practice.

**Steps**
1. Nitro enclave measurements (PCR0, PCR1, PCR2) cover the enclave image: kernel, initrd, application. They do NOT cover runtime data received over vsock after boot.
2. The enclave's application code reads `K_cust_pub` (and `mandate.revocation_pubkey`, `policy_bundle_hash` allowlist, customer account identifier) via a vsock channel from a "config service" on the parent.
3. A compromised parent — or a compromised cloud-init hook in the DeployCo account — substitutes `K_cust_pub_attacker` for `K_cust_pub_customer`.
4. Enclave boot completes with the attacker's key pinned as the trust root.
5. Attacker now issues mandates signed with their own key. Enclave validates. Policy decisions proceed. Capabilities are minted.
6. The proxy is in the customer's VPC and would reject capabilities whose PCR measurements don't match — but PCR measurements don't capture `K_cust_pub`. The attestation doc's `user_data` is `SHA-384(K_enc_pub)`, not `SHA-384(K_cust_pub_loaded_at_boot)`. The proxy has no way to verify which customer key the enclave believes is the root.
7. Customer's proxy verifies: mandate signature valid (against proxy-pinned `K_cust_pub_customer`). FAILS at proxy — good.

Wait. Let me re-read the design. The proxy DOES re-verify mandate signatures against its own pinned `K_cust_pub`. So substitution at boot causes the enclave to accept bogus mandates and mint capabilities — but the proxy rejects those capabilities because the mandate inside them is signed with the wrong key.

**HOWEVER**: the attacker doesn't need the mandate-signature to pass at the proxy. They need the **enclave** to mint a capability under `K_enc_priv` — and the enclave only mints capabilities after mandate-validation-passes. So the enclave will mint a capability that has the attacker's mandate bytes embedded. The proxy decodes the capability, extracts the mandate, verifies the mandate signature against proxy-pinned `K_cust_pub_customer` — FAILS. Attack blocked.

So BOOT-KEY-SUB does not directly allow action execution. But it does allow:
- DoS: enclave processes attacker mandates, wastes resources, never executes real mandates because the attacker's key has been substituted for the real customer's, so real customer mandates fail at the enclave.
- **If** the proxy's pinned `K_cust_pub` is itself loaded via the same vsock-bootstrap mechanism from a config service on the same compromised chain → catastrophe. The design does not explicitly say how the proxy obtains `K_cust_pub`. This is a gap.

**What is violated**
- A2 (K_cust integrity from the enclave's perspective) — directly.
- Availability / liveness.
- And potentially the entire trust chain, depending on ambiguity in proxy bootstrap.

**Severity: SHOWSTOPPER** (for the DoS and for the ambiguity; the direct action-execution path is blocked by proxy double-check, which is defense-in-depth working as intended — but the design must EXPLICITLY claim and justify this layered check, not leave it implicit).

**Confidence: HIGH** for the ambiguity and DoS; MEDIUM for whether a competent reviewer would call this a showstopper vs. a serious. I'm calling it showstopper because the spec leaves proxy-side `K_cust_pub` provisioning unspecified, which is exactly the kind of gap implementers resolve wrongly.

**Proposed mitigation**
1. **Measure customer identity into PCRs**. `K_cust_pub` (or its hash) should be part of the enclave image OR part of `user_data` in the attestation doc — something the proxy can cross-check. Suggested: enclave includes `SHA-256(K_cust_pub_expected)` in its attestation doc's `user_data` alongside `K_enc_pub`. Proxy verifies the hash matches its own pinned `K_cust_pub`.
2. **Spec the proxy bootstrap explicitly**. `K_cust_pub_customer` is loaded into the proxy from a customer-controlled source only (signed git repo, customer HSM export, customer KMS key policy). NEVER from a vendor-supplied config.
3. **Dual-sign bootstrap config**: if the enclave must load config via vsock, the config payload itself is COSE-signed by the customer (not just TLS-transported). Enclave verifies with a pubkey embedded in the measured image.

---

## Attack 3 — PARAM-CANON: Params canonicalization collision / field exclusion

**Preconditions**
- A2 or A4 (attacker controls intent params before they reach the PDP) OR A6 at the vendor (malicious orchestrator code path).
- The params hashing logic has any of: non-canonical encoding, partial field coverage, or field-name case sensitivity.

**Steps**
1. The design says `params_hash = sha256(canonical(params))`. "Canonical" is not further specified. There are known pitfalls:
   - JCS (RFC 8785) has edge cases with number precision and Unicode normalization.
   - CBOR deterministic encoding (RFC 8949 §4.2) is tighter but requires careful implementation.
   - Hand-rolled canonical JSON is a common source of hash-mismatches-on-read and hash-collisions on clever input.
2. Further: the design does not specify WHICH fields go into the hash. An implementer might reasonably hash only "user-facing" params and exclude "metadata" like annotations, labels, or nested configmaps. Attacker crafts two intents that differ only in excluded fields but have the same `params_hash`.
3. Alternative: if hashing includes `params` but normalization strips comments / annotations / unknown fields, attacker smuggles hostile content in stripped-but-not-stripped-consistently fields.
4. Concrete K8s example: `kubectl patch` accepts patches with `metadata.annotations`, `spec`, and many other fields. A policy that examines `spec.template.spec.containers[].image` but a `params_hash` that covers only the `patch` JSON — and not a separate "resource reference" field — can be tricked.

**What is violated**
- Step 6.11 (params binding).
- Claim 4 ("every action is individually authorized, scope-bound").

**Severity: SHOWSTOPPER** — because the entire capability model depends on the binding between "what the PDP approved" and "what the proxy executes." If those can be made to differ, the architecture's core guarantee collapses.

**Confidence: HIGH**. Canonicalization bugs have burned every major signed-JSON spec. JWT's original signature-stripping, JSON Web Signatures algorithm confusion, XML canonicalization attacks — this is a known endemic class.

**Proposed mitigation**
1. Specify canonicalization: **COSE_Sign1 over the full CBOR-encoded params object, not a hash-of-JSON**. The params themselves go through COSE, not through a separate hash field.
2. If a hash is used as a compact binding, specify: CBOR deterministic encoding (RFC 8949 §4.2) of the full params tree — no field exclusions, no transformations.
3. The policy evaluator and the proxy executor must consume the **exact same bytes**. No intermediate re-serialization.
4. Test vectors: publish a battery of inputs where two superficially-similar params yield different hashes, and verify that implementation matches the spec-reference hash.

---

## Attack 4 — AUDIT-GAP: Log-after-execute race

**Preconditions**
- Action execution and audit-log write are separate operations at the proxy.
- Proxy crash, network partition to audit store, or latency on the audit-store write.

**Steps**
1. Design §2 step 8 has the proxy write the audit event after the action returns: "Response captured" → "Proxy constructs audit event" → "Written to S3 Object Lock."
2. Between steps 7.3 (target API returns) and 8.2 (audit written to S3), the proxy holds a committed-at-target action with no durable audit record.
3. If the proxy process crashes or is killed between these steps:
   - Target API has executed the action.
   - S3 has no record.
   - On proxy restart, proxy has no way to know this action happened.
4. Under adversarial pressure: A6 insider at DeployCo with ability to trigger proxy restarts (not directly — proxy is customer-side — but indirectly via crafted inputs causing proxy-side panic).
5. Or under natural pressure: AZ failure, network partition to S3 right as action commits.

More adversarial: attacker with ability to delay the audit-write (network MITM to S3 — unlikely inside a VPC but possible for proxies with public egress) can accumulate a window of executed-but-unlogged actions.

**What is violated**
- A10 (audit log integrity).
- The claim "every action is individually ... audited."

**Severity: SERIOUS** — not showstopper because most incidents are recoverable (target API logs still record the action from its side; customer can reconcile). But the audit trail's completeness is a first-order claim of the architecture.

**Confidence: HIGH**. Log-after-act is a common bug class; it shows up in payments, in database replication, and in every first-draft audit subsystem.

**Proposed mitigation**
- **Two-phase audit**: proxy writes `intent_to_execute` to S3 BEFORE calling target API. Writes `action_executed` (with target response) AFTER. Both events signed, linked by nonce.
- On recovery, any `intent_to_execute` without a matching `action_executed` is treated as "status unknown" — must be reconciled against target API state.
- S3 writes are synchronous before the target API call — proxy blocks on write confirmation before executing. Adds latency (~50–200ms) but is the correct semantic.

---

## Attack 5 — REVOKE-RACE: Revocation propagation window

**Preconditions**
- Customer revokes a mandate.
- Proxy cache TTL on revocation list is up to 60s (per design).

**Steps**
1. Customer discovers a compromise (e.g., LLM loop producing clearly malicious intents). Revokes mandate at T=0.
2. Proxy's revocation cache was last refreshed at T=-55s. Next refresh at T=+5s.
3. Between T=0 and T=+5s, any capability (valid within its 30s `exp`) for this mandate is accepted by the proxy.
4. If the compromised enclave/LLM is producing capabilities at the rate of ~1/s, 5 malicious actions commit before revocation takes effect.
5. Worst case: if revocation-list fetch itself is blocked or slow, and the proxy has a "fail-open-on-fetch-error" posture, the window can extend further.

**What is violated**
- A11 (design-acknowledged as residual).
- Claim "revocation is immediate" — which the design doesn't quite claim, but "one-click mandate revocation" in the original sketch implies.

**Severity: SERIOUS**. Design acknowledges this; red team confirms it and pins it.

**Confidence: HIGH**.

**Proposed mitigation**
- Push-based revocation: proxy subscribes to a revocation topic (WebSocket, SSE) from customer's principal signing service. Revocation event arrives within ~1s, not 60s.
- Fallback to cache only on subscription failure, with ALERT.
- Fail-closed on revocation-list-fetch-error: if the proxy cannot verify a mandate is non-revoked within ≤5s, refuse the action.
- Reduce default cache TTL to ≤10s; stronger guarantee at the cost of more frequent fetches.
- Add a "panic button" that the customer can press — it both revokes the mandate and actively signals the proxy to drop all in-flight connections.

---

## Attack 6 — TOCTOU-TARGET: Target-state drift between policy decision and execution

**Preconditions**
- Capability binds `params_hash` (what to do) but not `resource_state_hash` (what the resource looks like right now).
- There's latency between PDP approval (in enclave) and proxy execution (on target).

**Steps**
1. At T=0, LLM observes state: `Deployment foo` has `image: acme/foo:v1.2.2` and `replicas: 10`.
2. LLM emits intent: "patch foo to image v1.2.3" — correctly, given state at T=0.
3. PDP approves. Capability minted (T=1s).
4. Between T=1s and T=20s (before proxy executes), another actor legitimately rolls `foo` to `v1.2.4` (hotfix) with `replicas: 12`.
5. Proxy executes the patch at T=21s. The K8s PATCH is a strategic-merge or JSON-patch on the Deployment. Depending on patch shape, the proxy now:
   - Overwrites the hotfix (`image: v1.2.3` replaces `v1.2.4`) → security regression.
   - Or: leaves replicas at 10 if the patch includes a replicas field → scaling down from 12.
6. The agent's mandate did allow this action — but the action's *effect* differs from what the LLM or PDP reasoned about.

**What is violated**
- Not a cryptographic property. But: the claim that EPHEMERAL bounds what an agent can do. A policy that thinks it has decided about "upgrading foo to v1.2.3" has in fact authorized "overwrite-whatever-foo-currently-is with patch P." The authorization was granted with false premises.
- Operator expectations: auditor looking at the log sees "patch applied, result 200 OK" — but cannot determine from the log alone whether the patch made sense at execution time.

**Severity: SERIOUS**. Not showstopper — the attack does not break the cryptographic architecture — but it breaks the *operational claim* that per-action authorization is meaningful. An authorized action that produces an unintended semantic is still a vulnerability, and the architecture's strongest selling point ("every action individually authorized") is weakened.

**Confidence: MEDIUM**. A competent external reviewer would raise this, but might also argue it's a target-API-semantics issue and not EPHEMERAL's problem to solve. I'm including it because "not my problem" is how this class of bug enters production.

**Proposed mitigation**
- Optimistic concurrency: include target-resource version (K8s `resourceVersion`, etcd mod_revision, DB row version) in the capability's params. Proxy sends `If-Match: <resourceVersion>` header. Target API rejects on mismatch.
- Canonical two-step: LLM must issue `read` first, then `act-bound-to-read-version`. The PDP sees both and enforces the binding.
- Document explicitly: "EPHEMERAL authorizes *intents*, not outcomes. Target-state drift between decision and execution is not cryptographically prevented. Operators must use target-level concurrency controls."

---

## Supplementary attacks (less-detailed, for completeness)

### Attack 7 — HA-REPLAY: Multi-instance proxy replay-cache inconsistency

**Severity: SERIOUS**. **Confidence: HIGH**.

If the proxy is deployed HA (N>1 instances for availability), nonce replay protection requires a shared, strongly consistent cache. Design spec is silent on this. An attacker obtaining a capability can present it to multiple proxy instances if the caches are not shared. **Mitigation**: shared Redis with fenced writes, or sticky-by-mandate-jti routing, or single-active-instance deployment with hot standby.

### Attack 8 — PDP-PCR-GAP: PDP code provenance in attestation

**Severity: SERIOUS**. **Confidence: MEDIUM**.

Design says "PDP code is measured into enclave PCRs" (assumption A5). PCR0–PCR2 measure kernel / initrd / application; PCR4–PCR8 measure user-land. If the PDP is a separately-loaded OPA binary fetched at runtime from unmeasured storage, the attestation proves the *loader* is the expected code, not the PDP. **Mitigation**: bundle the PDP binary + policy bundle hash into the enclave image so they're part of PCR0–PCR2. Or: have the loader measure the PDP and extend PCR8 with the measurement, reflected in attestation doc. Make this explicit in the spec.

### Attack 9 — MANDATE-JTI-ENTROPY: Predictable mandate identifiers

**Severity: MINOR**. **Confidence: HIGH**.

ULIDs have 80 bits of randomness and are time-sortable. For a security-sensitive identifier that an attacker might want to pre-compute or guess, 80 bits is low. Recommend ≥128 random bits (UUIDv4 or a random 16-byte identifier).

### Attack 10 — LLM-INGESTED PROMPT INJECTION shaping intents

**Severity: SERIOUS** (but design-acknowledged; confirming the bound).

A prompt-injection payload inside content the agent reads from target APIs (e.g., a Slack message, a Git commit message, a K8s annotation) can steer the LLM to emit intents within-mandate but operator-unintended. EPHEMERAL is explicit that prompt injection is bounded-not-prevented. **Confirming**: the bound is only as tight as the mandate. Narrow mandates are essential. This must become a documented operator rule, not a footnote.

---

## Composition: two threats combined

**Composition A** — A2 (supply-chain) + A1 (LLM-provider insider):
OPCE (Attack 1) requires both. Realistic because LLM provider insiders are exactly the ones who can push a version of their SDK that the orchestrator will auto-update to (if auto-updates are enabled, which is common). **Showstopper.**

**Composition B** — A6 (vendor insider) + A2 (supply-chain):
BOOT-KEY-SUB (Attack 2) realistic via compromised cloud-init or parent AMI. **Showstopper.**

**Composition C** — A4 (compromised enclave) + prompt-injection on ingested data:
Even a non-compromised enclave can emit in-scope-but-hostile actions. Doesn't require enclave compromise at all. Reinforces that mandate tightness is the primary defence.

---

## Summary

| # | Attack | Severity | Confidence |
|---|--------|---------|-----------|
| 1 | OPCE — key exfil via co-located LLM client | SHOWSTOPPER | HIGH |
| 2 | BOOT-KEY-SUB — unmeasured vsock bootstrap | SHOWSTOPPER | HIGH |
| 3 | PARAM-CANON — params binding via ambiguous canonicalization | SHOWSTOPPER | HIGH |
| 4 | AUDIT-GAP — log-after-execute race | SERIOUS | HIGH |
| 5 | REVOKE-RACE — revocation cache window | SERIOUS | HIGH |
| 6 | TOCTOU-TARGET — state drift between decision and execution | SERIOUS | MEDIUM |
| 7 | HA-REPLAY — multi-instance replay cache inconsistency | SERIOUS | HIGH |
| 8 | PDP-PCR-GAP — PDP code measurement ambiguity | SERIOUS | MEDIUM |
| 9 | MANDATE-JTI-ENTROPY — 80-bit identifier | MINOR | HIGH |
| 10 | PROMPT-INJECTION-VIA-INGESTED-CONTENT | SERIOUS | HIGH (acknowledged) |

**Three showstoppers.** Design v1 does not survive this round as specified.

Hard-trigger check: Do the three showstoppers require out-of-scope mitigations (confidential LLM inference, formal verification, novel crypto)?
- OPCE: mitigated by signer-isolation pattern (established design, no new crypto).
- BOOT-KEY-SUB: mitigated by measurement-in-attestation and explicit proxy-bootstrap spec (established).
- PARAM-CANON: mitigated by COSE-over-full-params + test vectors (established).

**None require out-of-scope mitigations.** Round 3 (Architect revision) is warranted. The showstoppers are all fixable within-scope; the question for Round 3 is whether the resulting design v2 is still a coherent architecture or has become a patchwork.
