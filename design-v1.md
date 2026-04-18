# design-v1.md — EPHEMERAL, Round 1 Architect

**Role**: The Architect. Senior distributed-systems + security engineer with background in confidential computing, SPIFFE/SPIRE, capability systems, and IETF RATS/OAuth work.

**Scope of this document**: A concrete protocol-level design intended to survive adversarial review in Round 2. Every claim of the form "X cannot happen" names the mechanism and the assumption it rests on. No hand-waving; no new cryptographic primitives.

---

## 0. Premise pivot (acknowledged)

The Skeptic's Round 0 no-go stands for the original in-org deployment-agent use case. This Round 1 proceeds under an explicitly pivoted premise:

**First use case (revised)**: A SaaS vendor, "DeployCo," operates an autonomous deployment agent as a managed service. Enterprise customers want DeployCo's agent to operate on *their* Kubernetes clusters, Vault instances, and databases, subject to cryptographically enforceable customer-issued authority — with the explicit property that **DeployCo never holds durable executable authority over customer resources**, and the customer can prove, years later, exactly what was authorized and what was executed, using only public keys and archived logs.

Under this premise, the six threats from the original threat model compose differently:

- **A1 (malicious LLM-provider insider)** remains in scope as before.
- **A2 (supply-chain compromise)** now has two flavours — compromise of DeployCo's deps, and compromise of customer-side proxy deps. Both must be bounded.
- **A3 (network attacker)** unchanged.
- **A4 (compromised agent runtime)** is now split into: compromise of the enclave-internal code, compromise of the enclave host (DeployCo's EC2 parent), compromise of the customer-side proxy.
- **A5 (compromised target API)** unchanged.
- **New: A6 (malicious DeployCo operator)**. A competent insider at the vendor — operator access to the parent instance, SPIRE server, PDP configuration, audit-log vendor-side mirror. This threat did not apply to the in-org case and is now central.

The pivot also makes EPHEMERAL's distinctive mechanisms load-bearing:
- **Attestation** becomes the cross-org trust primitive — the customer has no other way to know what code is running in DeployCo's enclave.
- **Cryptographic mandate** replaces "IAM role trust policy" because the customer is not the cloud-account owner of the agent runtime.
- **Customer-owned capability exchange proxy** becomes the authority concentration point, inside the customer's trust boundary rather than the vendor's.

---

## 1. Trust boundaries

### 1.1 Participants

| Participant | Location | Owner | Role |
|---|---|---|---|
| Principal (Customer) | Customer HQ / HSM | Customer | Mandate issuer. Holds root signing key `K_cust` (Ed25519), ideally in HSM / YubiKey / cloud KMS with HSM backing. |
| Principal Signing Service | Customer infra | Customer | Software front-end to `K_cust`. Enforces customer-side policy on mandate issuance (who can request what mandate, approval workflows). |
| Agent Runtime Enclave | DeployCo AWS account, Nitro-enabled parent EC2 | DeployCo (hosts it), but attested to Customer | Runs orchestrator + PDP + LLM client. Holds ephemeral enclave keypair `K_enc` generated inside the enclave at boot. |
| SPIRE Server | DeployCo account | DeployCo | Issues SVIDs to enclave workloads based on Nitro attestation. Separate from mandate-trust chain — SPIRE is used for TLS identity between vendor-side services, NOT for customer authority. |
| Policy Decision Point (PDP) | Same enclave as orchestrator | DeployCo (code), Customer (policy bundle signed by customer) | Evaluates per-action decisions against the customer-signed policy bundle referenced by `mandate.policy_bundle_hash`. |
| Capability Exchange Proxy | Customer VPC / on-prem | Customer | Verifies capabilities, holds real API credentials, issues API calls. **This is the sole authority concentration in the customer trust boundary.** |
| Target APIs | Customer-controlled (K8s, Vault, RDS) | Customer | Standard bearer-token / mTLS consumers. EPHEMERAL-unaware. |
| Audit Log | S3 Object Lock in Customer account (primary); vendor-side mirror (read-only for debugging) | Customer (primary) | Append-only sequence of signed audit events. |

### 1.2 Trust relationships, verified how

| Relying party | Trusts | Verification mechanism | Key material / reference |
|---|---|---|---|
| Customer Proxy | Enclave `K_enc` pubkey | Nitro attestation doc signed by AWS Nitro Root CA, PCR measurements match expected enclave image | AWS Nitro Root CA (published cert), expected PCR values (customer-attested out of band during onboarding) |
| Enclave | Customer mandate | Ed25519 signature over COSE_Sign1, key `K_cust_pub` pinned in enclave config at boot | `K_cust_pub` delivered via attested bootstrap (see §2 step 0) |
| Enclave | Policy bundle | SHA-256 hash matches `mandate.policy_bundle_hash`; bundle itself COSE-signed by customer | Customer-signed bundle, pinned by hash in every mandate |
| Customer Proxy | Mandate | Ed25519 signature against `K_cust_pub`, plus all temporal/scope checks | Customer's own pubkey |
| Customer Proxy | Capability (per action) | Ed25519 signature against `K_enc_pub`, attestation doc chain validates to AWS Nitro Root | AWS Nitro Root CA + PCR expectations |
| Vendor-internal services (SPIRE, PDP, orchestrator) | Each other | mTLS, SVIDs from SPIRE | SPIRE trust bundle |
| Auditor (years later) | Archived log | Ed25519 verify against archived `K_cust_pub`, `K_enc_pub` per sequence, attestation chain to archived AWS Root CA snapshot | Public keys only — no live services required |

### 1.3 Trust boundaries as a diagram (ASCII)

```
+-------------------- CUSTOMER BOUNDARY --------------------+
|                                                             |
|  [Principal]---signs--->[Mandate]                          |
|  [HSM: K_cust]                                              |
|                                                             |
|  [Proxy]<---mTLS----+                                       |
|  [API Creds in KMS] |                                       |
|  [Audit Log S3-OL]  |                                       |
|                     |                                       |
+---------------------|-------------------------------------+
                      | (mTLS over public internet)
                      |
+---------------------|------- VENDOR BOUNDARY -------------+
|                     |                                       |
|             [Nitro Enclave]                                 |
|             - Orchestrator                                  |
|             - PDP                                           |
|             - LLM Client                                    |
|             - K_enc (ephemeral)                             |
|                     ^                                       |
|                     | vsock (attested)                      |
|             [Parent EC2]                                    |
|                     ^                                       |
|                     | mTLS via SVID                         |
|             [SPIRE Server]                                  |
|                                                             |
|             [LLM Provider]<---API--- [Orchestrator]         |
|             (third-party, treated as adversary)             |
+-------------------------------------------------------------+
```

---

## 2. End-to-end walkthrough: "patch Deployment `foo` in namespace `prod`"

Step-by-step, with every cryptographic operation named.

### Step 0: Bootstrap (one-time per customer onboarding)

0.1 Customer generates `K_cust` (Ed25519) in HSM. Never exported.

0.2 Customer publishes `K_cust_pub` to DeployCo via authenticated channel (e.g., signed config in a git repo both parties control). Stored in DeployCo's enclave image config section.

0.3 Customer approves expected enclave PCR values. DeployCo publishes the enclave image hash and measured PCRs; customer reviews and records the expected PCR0/PCR1/PCR2 values in their onboarding doc. These are pinned into the customer's proxy config.

0.4 Customer deploys proxy in its VPC. Proxy generates its own keypair `K_proxy` for signing audit events.

0.5 Customer loads target API credentials into proxy's KMS-sealed store (`K_enc_proxy_sealed = KMS.encrypt(customer_KMS_key, bearer_token)`), keyed to a KMS key that the proxy service role can decrypt but no other principal can.

### Step 1: Enclave boot

1.1 DeployCo launches parent EC2; enclave boots from a pre-measured image.

1.2 Enclave generates ephemeral Ed25519 keypair `K_enc` inside enclave memory. Private half never leaves enclave.

1.3 Enclave fetches Nitro attestation document (via `NSM_GetAttestationDoc` syscall) with `user_data = SHA-384(K_enc_pub)`. This binds `K_enc_pub` to this specific enclave instance's measurements.

1.4 Enclave registers with SPIRE (vendor-side) via vsock → parent → SPIRE attestor; receives SVID for intra-vendor mTLS. This SVID is **not** used in customer trust chain.

1.5 Orchestrator is ready. Customer's proxy is notified out-of-band (or polls) of a new attestation doc available.

### Step 2: Mandate issuance

2.1 Customer principal (human or automation) requests a mandate: "allow agent to perform production deploys, 4-hour window, policy bundle `v3.1`, budget 100 actions / 500 API calls".

2.2 Customer Principal Signing Service constructs mandate:

```
mandate = {
  "iss":       "urn:customer:acme-corp",
  "sub":       "spiffe://deployco.vendor/agent/deploy/customer-acme",
  "aud":       ["k8s://prod.acme.internal", "vault://vault.acme.internal"],
  "iat":       1713456000,
  "nbf":       1713456000,
  "exp":       1713470400,           // +4h
  "jti":       "01HVXXXXXXXX",        // ULID
  "cap":       ["k8s:patch:deployment:prod/*",
                "k8s:rollout:status:prod/*",
                "vault:read:secret/prod/*"],
  "budget":    {"actions": 100, "api_calls": 500},
  "attester_required": {
      "tee":    "aws-nitro-v1",
      "pcr0":   "sha384:4f7e...",
      "pcr1":   "sha384:bc11...",
      "pcr2":   "sha384:aa33...",
      "image_sha384": "4f7e...aa33"
  },
  "policy_bundle_hash":  "sha256:0c8a...",
  "revocation_endpoint": "https://revoke.acme.internal/mandates/",
  "revocation_pubkey":   "ed25519:..."   // separate key for revocation signatures
}
```

2.3 Signed via COSE_Sign1 with `K_cust`. Encoding: deterministic CBOR (RFC 8949 §4.2).

2.4 Mandate delivered to enclave via authenticated-but-not-secret channel (it's a capability-grant, not a secret). Mandate also recorded in customer's audit log as `event.type = mandate_issued`.

### Step 3: LLM produces intent

3.1 Orchestrator asks LLM (function-calling mode): "Given deploy request for `foo:v1.2.3`, produce the next action."

3.2 LLM returns structured tool call:

```
intent = {
  "tool":  "k8s.patch",
  "args":  {"namespace": "prod", "kind": "Deployment",
            "name": "foo", "patch": {"spec":{"template":{"spec":
            {"containers":[{"name":"app","image":"acme/foo:v1.2.3"}]}}}}}
}
```

3.3 LLM output is treated as adversarial. Orchestrator does **not** execute; it submits `intent` to the PDP.

### Step 4: Policy decision

4.1 PDP (in-enclave, same attestation measurement as orchestrator) loads policy bundle. Verifies:
  - `bundle.hash == mandate.policy_bundle_hash`
  - `bundle` is COSE_Sign1-signed by `K_cust` (same key as mandate; or by a dedicated policy-signing subkey the customer publishes)

4.2 PDP evaluates Rego policy against input `{mandate, intent, budget_consumed, current_time, llm_reasoning_excerpt}`. Returns `{decision: allow/deny, reason: ..., consumed_budget: 1}`.

4.3 Decision logged to audit stream (event.type = `policy_decision`).

### Step 5: Capability minting

5.1 On `allow`, orchestrator constructs capability:

```
capability = {
  "parent_jti":   <mandate.jti>,
  "action":       "k8s.patch",
  "resource":     "deployment/prod/foo",
  "params_hash":  "sha256:<hash of normalized params>",   // binds to exact params
  "nonce":        <random 128-bit>,
  "iat":          1713459600,
  "exp":          1713459630,                              // +30s
  "attester_quote_hash": "sha384:<hash of current nitro doc>"
}
```

5.2 COSE_Sign1 with `K_enc`. Encoding: deterministic CBOR.

5.3 Bundle sent to proxy: `{capability, attestation_doc, mandate, params}`. Attestation doc is the raw Nitro doc (not re-signed); proxy will validate its chain to AWS Nitro Root CA.

5.4 Transport: mTLS 1.3 (ECDHE-X25519, AES-256-GCM, Ed25519 cert), cert chain via SPIRE SVID for vendor-side identity + pinned customer-to-vendor CA for cross-org mTLS.

### Step 6: Proxy verification

Proxy runs the following chain. **Any failure causes a hard deny and an audit event; partial failures do not fall through.**

6.1 Mandate signature: `Ed25519.Verify(K_cust_pub, mandate_bytes, mandate.sig) == true`.

6.2 Mandate temporal: `nbf ≤ now ≤ exp` (with ±5s grace for NTP skew — documented, not implicit).

6.3 Mandate not revoked: check revocation list (fetched from `mandate.revocation_endpoint` with ≤60s TTL, signed by `mandate.revocation_pubkey`).

6.4 Attestation doc chain: validate certificate path from attestation doc's signer cert to AWS Nitro Root CA, verify AWS-signature over doc, verify `doc.user_data == SHA-384(capability_parent_key)`.

6.5 Attestation PCRs: `doc.pcrs[0] == mandate.attester_required.pcr0` (and PCR1, PCR2, image_sha384).

6.6 Attestation freshness: `doc.timestamp ≥ now - max_quote_age` (suggested 5 min; quotes older than this rejected).

6.7 Capability signature: `Ed25519.Verify(K_enc_pub, cap_bytes, cap.sig) == true`. `K_enc_pub` is from the attestation doc's `public_key` field.

6.8 Capability temporal: `iat ≤ now ≤ exp`, grace ±5s.

6.9 Capability-mandate binding: `cap.parent_jti == mandate.jti`.

6.10 Action allowed: `cap.action + cap.resource` matches some element of `mandate.cap[]` by structured match.

6.11 Params binding: recompute `sha256(canonical(params))` and compare to `cap.params_hash`.

6.12 Nonce freshness: proxy's replay cache does not contain `cap.nonce` within a sliding window ≥ `cap.exp - cap.iat`.

6.13 Budget: proxy's mandate-budget counter for `mandate.jti` has remaining capacity; decrement atomically.

6.14 Egress allowlist: `cap.resource` target host is in proxy's allowlist for this mandate.

### Step 7: Proxy executes

7.1 Proxy decrypts sealed credential: `bearer = KMS.Decrypt(sealed_token)`. This is the real K8s service account token with RBAC scoped to whatever actions this mandate's `cap` list implies. (Credentials may themselves be short-lived Vault-issued; mandate-bound subset of actions is enforced at both proxy layer AND target RBAC for defense in depth.)

7.2 Proxy issues HTTPS PATCH to K8s API, TLS-pins to customer's K8s CA.

7.3 Response captured. Sanitized (no headers that could leak proxy state).

### Step 8: Audit and response

8.1 Proxy constructs audit event:

```
audit = {
  "type":         "action_executed",
  "mandate_jti":  ...,
  "cap_nonce":    ...,
  "action":       "k8s.patch",
  "resource":     "deployment/prod/foo",
  "params_hash":  ...,
  "attester_quote_hash": ...,
  "target_code":  200,
  "target_body_hash": "sha256:...",   // hash only, no body, for log-size bounds
  "timestamp":    ...,
  "seq":          <monotonic, per-proxy>
}
```

8.2 COSE_Sign1 with `K_proxy`. Written to S3 Object Lock bucket in customer account; also mirrored (read-only, not source-of-truth) to vendor audit stream.

8.3 Redacted response returned to enclave. Enclave does NOT see `bearer` — only the sanitized response.

### Step 9: Next action or terminate

9.1 Orchestrator resumes LLM loop with redacted response.

9.2 If mandate budget or time exhausted, orchestrator halts with `event.type = mandate_complete`.

---

## 3. Data schemas

All signed objects use COSE_Sign1 (RFC 9052) with Ed25519 (RFC 8032, COSE `alg: -8` / EdDSA).

Rationale for CBOR over JSON:
- **Mandate and Capability**: CBOR via COSE_Sign1 gives deterministic encoding (RFC 8949 §4.2), smaller wire size, and standardization via IETF RATS for attestation-related payloads. Signatures are canonical without hand-rolling JCS.
- **Attestation Document**: mandated CBOR by AWS Nitro.
- **Audit Events**: COSE_Sign1 CBOR on-wire (for deterministic signing); may be decoded to JSON for SIEM ingestion at read-time. Canonical form for signature is CBOR.
- **Policy bundle**: Rego source + metadata, COSE_Sign1 wrapped.

Schema summaries already shown inline in §2. Full CDDL (Concise Data Definition Language) is deferred to an appendix — for Round 1 the structural contract is sufficient to enable Round 2 attack.

Explicit non-secret fields (important for later rounds): `K_cust_pub`, `K_enc_pub`, all attestation docs, all capabilities and mandates. Nothing in this protocol is a "shared secret"; everything is public-key or bearer-sealed-by-KMS.

---

## 4. Failure modes

| Scenario | Behaviour | Mechanism | Known residual risk |
|---|---|---|---|
| SPIRE down | Vendor-internal mTLS cannot refresh; existing SVIDs valid until TTL (typ. 1h) | SPIRE CA keeps serving cached trust bundle | After TTL, orchestrator cannot authenticate to PDP → hard-stop |
| PDP down | No new decisions minted; pending capability requests fail closed | Orchestrator returns "policy unavailable" to LLM loop; no fallback | Agent halts until PDP returns |
| Proxy down | No action executes; orchestrator cannot drain LLM intents | mTLS connection refused → explicit error → halt | Customer-side monitoring must alert |
| Enclave restart mid-action | In-flight action aborts; `K_enc` changes on restart; new attestation doc required | Proxy replay-cache rejects the now-orphaned capability; mandate budget state is held in proxy, not enclave | Idempotency keys on actions prevent double-execution on retry; if action already committed, retry is a no-op via `If-Match` / idempotency-key at target API |
| Clock skew between enclave / customer HSM / proxy | ±5s grace at each check; NTP sync (AWS Time Sync) is required | Explicit grace; no automatic widening | If skew exceeds grace, valid actions fail and must re-request with fresh timestamp |
| `K_cust` rotation | Customer publishes new pubkey; old mandates continue until their `exp`; new mandates use new key | Proxy and enclave maintain key history (key-id in mandate header), validate against matching epoch | Overlap window requires simultaneous trust of old + new key for `exp_max` window |
| `K_enc` rotation | On enclave restart, `K_enc` is fresh; old capabilities expire in ≤30s (per capability `exp`); proxy re-fetches fresh attestation doc | `attester_quote_hash` changes → capabilities signed under old `K_enc` fail at proxy | Capabilities in flight during restart fail; user-observable as transient errors |
| LLM returns malformed intent | Orchestrator's schema validator rejects before PDP | JSON Schema / CDDL validation | Malformed intents never reach PDP; logged at debug level |
| LLM returns well-formed but out-of-scope intent | PDP denies; audit event; retry with different LLM output or halt | Policy evaluation | Adversarial LLM can only cause bounded harm within mandate; DoS possible if LLM loops |
| Customer revokes mandate mid-flight | In-flight capability may still commit at target if already past proxy; new capabilities fail at proxy | Revocation cache TTL ≤60s; proxy rechecks before every action | Window ≤60s + action-execution-latency where post-revocation actions may commit. **Flag for Round 2.** |
| Network attacker between enclave and proxy | mTLS 1.3 + attestation-pinned cert | Standard TLS guarantees + attestation in the data | None |
| AWS Nitro Root CA compromise | Entire attestation chain compromised; all capabilities forgeable | Out-of-band: customer rotates trust bundle; proxy hard-stops | Platform-level assumption, same as trusting any CA |

---

## 5. Assumptions (exhaustive)

Every item here is a condition on which security depends. If any fails, a specific property is lost.

| # | Assumption | If broken, what's lost |
|---|---|---|
| A1 | AWS Nitro attestation is trustworthy (no hardware backdoor, no broken signing, no side-channel that extracts enclave memory) | All capability authenticity; all enclave-integrity claims |
| A2 | Customer's `K_cust` private key is uncompromised (HSM integrity, no insider key extraction) | All mandate authenticity; attacker with `K_cust` can issue arbitrary mandates |
| A3 | Customer's proxy is uncompromised (no RCE; network-isolated; hardened; small Rust codebase) | All customer credentials, all in-flight authority |
| A4 | SPIRE server integrity (only affects intra-vendor identity; does NOT affect customer trust chain) | Internal mTLS between vendor services; but mandate/capability path is independent |
| A5 | PDP correctly enforces policy; PDP code is measured into enclave PCRs | Policy-level authorization; but temporal+scope checks at proxy are a second layer |
| A6 | LLM-provider is treated as adversarial and nothing in enclave memory is ever exfiltrated via LLM prompt/completion channels | No direct property lost if LLM is compromised; but see A7 |
| A7 | Orchestrator code correctly avoids mixing secrets into LLM context (e.g., never putting `K_enc` or capability internals into a prompt-visible variable) | Catastrophic: if orchestrator leaks `K_enc` into a prompt, LLM provider can forge capabilities until next restart |
| A8 | Target APIs honour the scoping of the bearer credentials held by proxy (RBAC, IAM, etc. are enforced) | Defense-in-depth layer; attacker with proxy compromise can still only do what target RBAC allows |
| A9 | TLS 1.3, Ed25519 (RFC 8032), SHA-256, SHA-384, AES-256-GCM remain unbroken | Everything |
| A10 | S3 Object Lock honours append-only semantics (compliance or governance mode, configured by customer) | Audit log integrity over time; otherwise auditor cannot trust log |
| A11 | Mandate revocation propagates from customer principal signing service to proxy faster than `cap.exp - cap.iat` | Revocation efficacy. **If not true, there's a race window. Flag to Round 2.** |
| A12 | Enclave boot produces reproducible measurements; `image_sha384` matches `PCR0` deterministically across parent-instance boots | Customer's ability to pin `attester_required.pcr*` in mandate |
| A13 | Nitro NSM (Nitro Security Module) syscall for attestation is trustworthy | `K_enc_pub` binding to measurements |
| A14 | Policy bundle (Rego) is authored correctly by the customer and cannot be tricked into allowing out-of-scope actions via crafted LLM reasoning or params | **Operator concern.** Policy-authoring is where most real-world vulnerabilities will live. |
| A15 | The attestation doc freshness window (5 min default) is appropriate — long enough to allow retries, short enough to bound replay | Capability replay window is bounded |

The concentration of authority at the Proxy (A3) is the single largest trust target. Mitigations in the design:
- Minimal code (target: <3000 LOC Rust)
- No general-purpose runtime (not a container with a shell)
- No secrets outside KMS-sealed envelope; `K_enc_pub` and policy bundle are derivable, not stored
- Dedicated AZ, dedicated VM, NetworkPolicy egress-lock, NACL
- Principle that Proxy logic is trivially audit-able; any behaviour not in spec is a red flag

---

## 6. Residual design concerns deliberately left for Round 2

I call these out to be honest about what I expect the Red Team to find:

1. **Revocation race** (A11). The ≤60s window where revoked mandates still grant actions is not zero.
2. **Attestation freshness vs. capability freshness** mismatch: attestation valid 5 min, capabilities valid 30s; I haven't fully justified the 5-min attestation window.
3. **Orchestrator-prompt-leak of secrets** (A7). The class of "LLM client code accidentally logs K_enc" is real and silent.
4. **Proxy-as-SPOF**. I am knowingly concentrating authority here. Round 0 Skeptic already noted this.
5. **Policy-bundle authoring complexity** (A14). Customers will write bad policies and not know it.
6. **Time-of-check / time-of-use** between PDP decision in enclave and proxy-side execution. Params can be "locked" by `params_hash` but the resource's *state* can change (e.g., "patch deployment/foo" when foo's image is not what it was at decision time).
7. **Cross-enclave reuse**: if DeployCo's parent EC2 hosts multiple enclaves per tenant, one enclave's compromise does not affect another (Nitro guarantees isolation) — but PCR measurements may be reused, and an attacker could boot an enclave with the "correct" image but feed it malicious runtime data via unmeasured vsock traffic. Worth hardening.
8. **Nonce replay cache sizing**: must be proxy-persistent, not in-memory, or a restart accepts replays.
9. **`jti` collision or brute-force**: ULIDs are 80 bits of randomness. Not ideal for security-sensitive identifiers. Should be ≥128 bits.
10. **Policy bundle signing key**: I casually said "same as K_cust or a subkey." In practice this needs its own small key-hierarchy story.

---

## 7. What is explicitly out of scope of this design

- Confidentiality of data passing through the LLM (per threat model).
- Nation-state hardware attacks against Nitro (per threat model).
- Model-poisoning of the LLM (per threat model).
- Formal verification of the composition. (Flagged in the caveat — would be required for production.)

---

## 8. Caveat

This is Round 1 output from a single LLM acting as The Architect. It names mechanisms, protocols, and assumptions. It is not a finished specification; it is a target for adversarial review. §6 is a partial list of the weaknesses I already see; I expect Round 2 to find more.
