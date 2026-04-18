# design-v2.md — EPHEMERAL, Round 3 Architect Revision

**Role**: The Architect. Revising after Round 2 Red Team.

**Scope**: Replace v1 with a design that (a) resolves every Round 2 showstopper and serious attack, (b) reconciles the Round 0 Skeptic's verdict with the Round 1 ambition, (c) introduces no new cryptographic primitives, (d) is simpler overall than v1, not more complex.

The central move is a **premise reframing**. v1 asked "how do we build one machinery that handles every agent action securely?" v2 asks "which machinery is *proportional* to each action's impact?" The former forces universal ceremony; the latter uses heavy machinery only where it earns its keep.

---

## 0. Why v1 was wrong even with the Round 2 patches applied

If I accept every Round 2 mitigation literally — signer-isolation enclave, attestation-bound `K_cust_pub`, deterministic CBOR params, write-ahead audit, push revocation, TOCTOU version-bind, shared replay cache, PDP-in-PCR — I arrive at a version of v1 that **works** but fails the Round 0 economic test. It is still massively over-built for the 80% of agent actions that are reads or idempotent writes. The skeptic's no-go was right *as to the use case*. v1 was right *as to cross-org properties*. Neither was the whole truth.

The right truth is: **agent actions are not uniform in impact, and authorization machinery should not be uniform either**. Treat that as a first-class design principle and the architecture changes shape.

---

## 1. The Tariff: proportional authority as first-class primitive

### 1.1 Impact Tiers (the new cardinal concept)

A **Tier** is a one-dimensional classification of an action's consequence-space. Six levels, defined operationally:

| Tier | Name | Examples | Authorization required |
|------|------|----------|--------|
| 0 | **Read** | `GET /repos`, `kubectl get`, `vault read` (non-secret metadata) | OIDC-federated token + rate limit |
| 1 | **Idempotent write** | `kubectl apply` (declarative), `PUT /configmap` (same content), `ensure-exists` patterns | OIDC-federated token + DPoP + OPA policy + rate limit |
| 2 | **Stateful write (reversible)** | `kubectl patch deployment` with image change, `vault write secret/path`, `POST /issues/comment` | **Mandate** + **Capability (short-lived, params-bound, attested signer)** + OPA + audit-ahead |
| 3 | **Destructive but recoverable** | `kubectl delete deployment` (spec is in git), `drop column` (backup exists), `disable user` (reversible) | Mandate + Capability + **push-based revocation check** + resource-version binding + explicit confirmation in mandate scope |
| 4 | **Irreversible / high-impact** | `kubectl delete namespace`, `rotate KMS root key`, `publish npm package`, `transfer domain`, spend > user-set threshold | **WebAuthn step-up on user device** + everything above |
| 5 | **Authority-granting / existential** | `RBAC: add cluster-admin`, `delete cluster`, `change organization billing`, `acquire/dispose of cryptographic root material` | **Multi-party signature** (user + compliance + second authenticator) + formal-ceremony approval record |

The tiers are **monotonic in friction**: higher tier = more ceremony, more latency, more humans. They are also **monotonic in blast radius**: higher tier = worse outcome if misauthorized.

The core claim: **80% of agent actions are Tier 0-1; 15% are Tier 2-3; 5% are Tier 4-5**. The distribution matters because it means the "expensive" authorization paths are rare and their friction is tolerable.

### 1.2 Tariff document

Customer signs *one* Tariff per integration (per "target-API surface + credential domain" combination), updated rarely, versioned explicitly.

```cbor
Tariff = {
  "customer_id":      "urn:customer:acme",
  "integration_id":   "k8s-prod",
  "version":          3,
  "iat":              1713700000,
  "classifier_hash":  "sha256:<32B hash of classifier-wasm>",
  "tiers": {
    0: { "authz": "oidc-dpop",
         "rate_limit":  {"per_minute": 1000} },
    1: { "authz": "oidc-dpop + opa",
         "opa_bundle":  "sha256:<...>",
         "rate_limit":  {"per_minute": 100} },
    2: { "authz": "capability",
         "mandate_required":   true,
         "resource_version_binding": true,
         "rate_limit":         {"per_minute": 50},
         "capability_ttl_seconds": 30 },
    3: { "authz": "capability + revocation-push",
         "mandate_required":   true,
         "revocation_push_url": "https://revoke.acme.internal/push",
         "resource_version_binding": true,
         "rate_limit":         {"per_minute": 10} },
    4: { "authz": "capability + webauthn",
         "user_device_pubkey": "cose:<...>",
         "challenge_ttl_seconds": 120,
         "rate_limit":         {"per_hour": 20} },
    5: { "authz": "multi-party",
         "signers_required":   3,
         "signers_allowlist":  [...],
         "ceremony_record":    "append-only"}
  },
  "minimum_tiers": {
    "verb:delete":              3,
    "resource:secret":          4,
    "resource:rbac":            5,
    "action:publish-package":   4,
    "action:spend":             "fn:spend_tier"   // see classifier
  },
  "ambiguity_resolution":       "up",   // ambiguous → higher tier
  "grace_skew_seconds":          5,
  "signature":                   <Ed25519 by K_cust>
}
```

Encoding: COSE_Sign1 (RFC 9052) over CBOR deterministic encoding (RFC 8949 §4.2). Signed by customer HSM-held `K_cust`.

### 1.3 Classifier

Deterministic pure function — `(action, resource, params, agent_context) -> tier`. Delivered as a WebAssembly module (portable, sandboxable, measurable). Hash pinned in Tariff.

Minimal interface:

```
classify(intent: Intent) -> {tier: 0..5, reason: string}
```

The classifier can be customer-written (Rust / AssemblyScript compiled to WASM) or generated from OpenAPI annotations. Customer signs the WASM blob; router verifies hash matches `tariff.classifier_hash` before use.

The router always enforces the `minimum_tiers` floor **after** classifier runs — a classifier bug cannot downgrade below the floor.

### 1.4 Authorization Router

The dispatch hub. Lives in customer VPC. Small Rust codebase (target < 5k LOC). Holds no long-lived secrets; Tier 2+ credentials are fetched per-use from KMS-sealed store.

Flow:

```
INPUT: intent = {action, resource, params, agent_id, mandate_ref?}
1. Fetch current Tariff (cached with short TTL, hash-verified each time).
2. Run classifier(intent) -> raw_tier
3. Apply minimum_tiers floor -> tier
4. Dispatch by tier.authz:
   - "oidc-dpop": fetch agent's OIDC-fed token, mint DPoP proof, return as authorization header set.
   - "oidc-dpop + opa": as above, evaluate OPA bundle on intent; if allow, proceed; else deny.
   - "capability": verify agent's presented mandate (Ed25519 against K_cust_pub);
                   run PDP on intent; if allow, mint capability (Ed25519 by router's K_router or attested signer service);
                   write intent_to_execute audit event; return capability.
   - "capability + revocation-push": as above, additionally block until subscription to revocation-push confirms mandate is live.
   - "capability + webauthn": as above, then issue WebAuthn challenge to user_device_pubkey;
                              block until signed assertion returns (within challenge_ttl);
                              append assertion to audit.
   - "multi-party": initiate ceremony: send signing requests to signers_allowlist;
                    await N-of-M signatures; append signatures to audit; release.
5. Agent executes the action. Router captures result.
6. Write action_executed audit event. Result returned to agent.

Every step is fail-closed. Every step is audit-logged.
```

### 1.5 Where EPHEMERAL v1's cryptographic machinery lives now

- **Nitro Enclave / attestation** lives in a **Signer Service** — a dedicated minimal enclave that does one thing: verify mandates, evaluate PDP, sign capabilities. It is used **only** for Tier 2+ authorization. Tier 0-1 never touches it.
- **SPIRE** is optional — only used where intra-router-fleet identity is needed; not on the customer trust chain.
- **Capabilities, mandates, PDP** are Tier 2+ primitives. Unchanged in spirit from v1, improved per Round 2 mitigations.
- **Proxy** (which in v1 held all credentials) is collapsed into the Router. The Router holds some credentials directly (Tier 0-1 tokens) and fetches others from KMS per-action (Tier 2+).

The v1 architecture is not abandoned — it is **scoped** to where it earns its keep. Everything below Tier 2 is standard modern SRE.

---

## 2. Architecture

### 2.1 Participants

```
+------------------ CUSTOMER CONTROL PLANE ------------------+
|                                                              |
|  [Principal Signing Service]  — holds K_cust in HSM         |
|  [Policy / Tariff Repo (git)] — signed Tariffs, OPA bundles |
|  [WebAuthn Device]            — user's phone / YubiKey      |
|  [Multi-Party Signers]        — compliance, second admin    |
|                                                              |
+--------------------------------------------------------------+
                              |
                              |  (signed artifacts: Tariff, Mandate, Policy)
                              v
+------------------ CUSTOMER EXECUTION PLANE ------------------+
|                                                               |
|     [Authorization Router]                                    |
|       - Fetches Tariff, classifier WASM, policies             |
|       - Dispatches by tier                                    |
|       - Holds KMS-sealed credentials for Tier 2+              |
|       - Writes audit to S3 Object Lock                        |
|                                                               |
|     [Signer Service (Nitro Enclave)]    (for Tier 2+ only)   |
|       - Verifies mandates                                     |
|       - Runs PDP                                              |
|       - Signs capabilities with K_signer (ephemeral, in-TEE)  |
|                                                               |
|     [Audit Log: S3 Object Lock, COSE-signed sequence]         |
|                                                               |
+---------------------------------------------------------------+
                              ^
                              |  mTLS
                              |
+----------------- VENDOR / AGENT RUNTIME ----------------------+
|                                                                |
|     [LLM Orchestrator]      — treats LLM output adversarially |
|     [LLM Client]            — calls LLM provider              |
|     [Tool Execution Layer]  — calls Router for authz          |
|                                                                |
|     Target API invocations go through Router.                 |
|     Agent holds NO long-lived credentials for anything ≥ T2.  |
|     For Tier 0-1, agent holds short-lived OIDC-fed tokens     |
|     (refreshed from projected SA token / Workload Identity).  |
|                                                                |
+----------------------------------------------------------------+
```

The agent runtime is NOT in a TEE in the general case. TEE is reserved for the Signer Service (small attack surface, small codebase). This is a major simplification over v1.

### 2.2 Trust boundaries (short version — §2.3 has the table)

- Agent runtime is **semi-trusted** — trusted to faithfully represent the user's intent TO the Router, but NOT trusted with Tier 2+ credentials.
- Router is trusted **as much as** the customer's other infra (same trust level as Vault or a K8s controller).
- Signer Service is trusted **only up to its measured code + attestation**. Its trust is *narrower* than the Router's, because it does only one thing.
- Customer Principal Signing Service (HSM) is trusted absolutely (root of trust).
- LLM provider, LLM output, Agent's deps — **adversarial**. No authority-related data ever flows to them.

### 2.3 Trust verification mechanisms (each step explicit)

| Relying party | Trusts | Verification | Key ref |
|---|---|---|---|
| Router | Tariff | Ed25519 signature against pinned `K_cust_pub` | `K_cust_pub` loaded from signed config (measured path — see §2.4) |
| Router | Classifier WASM | SHA-256 matches `tariff.classifier_hash` | Hash in Tariff |
| Router | Mandate (Tier 2+) | Ed25519 signature against `K_cust_pub`; nbf/exp/revocation check | Same `K_cust_pub` |
| Router | Capability (Tier 2+) | Ed25519 signature against `K_signer_pub` from Signer Service's attestation doc | `K_signer_pub` from current attestation; AWS Nitro Root CA pinned |
| Router | Signer Service | Nitro attestation chain to AWS Nitro Root CA + matching PCRs + `user_data == SHA-384(K_signer_pub || Tariff_hash)` | Pinned PCRs, AWS CA, Tariff hash |
| Router | WebAuthn assertion (Tier 4) | Standard WebAuthn verification against `tariff.tiers[4].user_device_pubkey` | Pubkey in Tariff |
| Router | Multi-party signature (Tier 5) | K-of-N Ed25519 signatures against `tariff.tiers[5].signers_allowlist` pubkeys | Allowlist in Tariff |
| Target API | Router's action | Bearer token / mTLS with resource-version (`If-Match`) | Standard target API auth |
| Auditor (offline, years later) | Archived log | Ed25519 verify against archived `K_cust_pub`, attestation roots, signer assertions | Public keys only |

### 2.4 Router bootstrap (where the Round 2 `BOOT-KEY-SUB` concern is answered)

1. Customer publishes `K_cust_pub` and trust-root bundle (AWS Nitro Root CA, signed) to a **customer-controlled** git repo.
2. Router image embeds a build-time pubkey `K_bootstrap_pub` that signs `K_cust_pub`. Build-time pubkey is set by customer at image build (customer-signed build).
3. Router on startup loads `K_cust_pub` from a config object; verifies the config object's signature against `K_bootstrap_pub` embedded in the image.
4. Router refuses to start if signature does not verify or if image's `K_bootstrap_pub` is not the customer's. Fail-closed.
5. Signer Service's attestation doc includes `user_data = SHA-384(K_signer_pub || SHA-256(Tariff))`. Router verifies this binding when accepting Signer Service.

Net effect: the root of trust chain flows `K_cust` → signed-Tariff → pinned in Router image → attestation doc's user_data → Signer Service trusted. No unmeasured vsock path for trust material.

---

## 3. End-to-end walkthroughs (one per representative tier)

### 3.1 Tier 0 — `kubectl get pods -n prod`

Latency budget: < 100 ms.

1. LLM emits intent `{action: "get", resource: "pods", ns: "prod"}`.
2. Orchestrator calls Router.
3. Router runs classifier → Tier 0.
4. Router dispatches to OIDC-DPoP path:
   - Fetches agent's OIDC-fed token from projected SA token path (in-pod).
   - Mints DPoP proof (Ed25519 over {method=GET, url=<target>, iat=now, nonce=<...>}).
   - Returns `{Authorization: Bearer <token>, DPoP: <proof>}`.
5. Agent runtime executes the HTTPS GET to K8s API.
6. Response returned to orchestrator, which returns it to LLM.
7. Audit event: `{tier:0, action:"get", resource:"pods/prod", status:200, actor:agent_id, ts}`.

No enclave. No capability. Rate-limited. Audit logged. Takes < 100ms.

### 3.2 Tier 1 — "Ensure configmap `release-notes` exists in `prod` with contents X"

Latency budget: < 200 ms.

1. LLM emits intent.
2. Router classifies → Tier 1.
3. Router evaluates OPA bundle on intent: allowed namespace, allowed kind, allowed content shape.
4. If allow: fetch OIDC-fed token + DPoP proof.
5. Agent executes `kubectl apply` via target API.
6. Audit event.

Still no enclave. No mandate. OPA gates.

### 3.3 Tier 2 — Patch `Deployment foo` in `prod` to image `v1.2.3`

Latency budget: < 400 ms.

1. LLM emits intent with params.
2. Router classifies → Tier 2.
3. Router checks: mandate exists and is valid (Ed25519 verify, nbf/exp, budget remaining, capability scope includes `k8s:patch:deployment:prod/*`).
4. Router requests capability from Signer Service (mTLS to enclave):
   ```
   CapabilityRequest = {
     mandate:   <full mandate COSE_Sign1>,
     intent:    <full intent>,
     target_resource_version: <fetched just now, e.g., "12345">
   }
   ```
5. Signer Service:
   - Verifies mandate signature against `K_cust_pub` pinned at boot.
   - Verifies intent is within mandate scope.
   - Evaluates PDP (OPA or custom Rego) on intent.
   - If allow, mints Capability:
     ```
     Capability = COSE_Sign1_Ed25519 (K_signer_priv) over {
       parent_mandate_jti, action, full-params-cbor, resource_version,
       nonce (16 bytes random), iat, exp (=iat+30s),
       attester_quote_hash
     }
     ```
   - Returns Capability + fresh attestation doc.
6. Router writes `intent_to_execute` audit event (write-ahead).
7. Router executes against target API. Uses bearer token fetched from KMS just now; adds `If-Match: 12345` header.
8. Target API checks resource version; executes or rejects.
9. Router writes `action_executed` audit event with result.
10. Capability nonce added to replay cache (shared Redis).

Full COSE_Sign1 over CBOR of the *entire params object* — no separate hash, no field exclusion. This resolves Round 2 `PARAM-CANON`.

Write-ahead resolves Round 2 `AUDIT-GAP`.

`If-Match` resolves Round 2 `TOCTOU-TARGET`.

Shared replay cache resolves Round 2 `HA-REPLAY`.

### 3.4 Tier 3 — Delete `Deployment foo` in `prod`

As Tier 2, plus:

- Router subscribes to customer's push-revocation stream (WebSocket or SSE) at startup. Each mandate has a `revocation_channel_ref`. Router blocks Tier 3 actions for mandates it has not confirmed-live in the last 5 seconds.
- If push stream drops: Router fails-closed on all Tier 3+ actions until stream re-established.

Resolves Round 2 `REVOKE-RACE`.

### 3.5 Tier 4 — Delete `Namespace prod` (irreversible)

Latency budget: tens of seconds (user interaction).

1. LLM emits intent. Router classifies → Tier 4 (via `minimum_tiers: "verb:delete-namespace": 4`).
2. Router requires mandate + capability + **user WebAuthn step-up**.
3. Router constructs challenge:
   ```
   WebAuthnChallenge = {
     rp_id:      customer.com,
     challenge:  sha256(intent || capability || random_nonce),
     user:       intended_user_handle,
     allowed_credentials: [tariff.tiers[4].user_device_pubkey]
   }
   ```
4. Challenge pushed to user's device (registered at Tariff signing time) via push notification / WebSocket.
5. User sees in device UI:
   > Agent `acme-deploy-42` requests DELETE NAMESPACE `prod`.
   > At 14:32 on 2026-04-18.
   > Tap to approve, reject, or hold.
6. User taps approve → WebAuthn signing → signed assertion returned to Router.
7. Router verifies assertion (standard WebAuthn verification).
8. Router executes deletion.
9. Audit event includes the signed WebAuthn assertion.

If challenge times out (default 120s) → fail-closed.

### 3.6 Tier 5 — Add `cluster-admin` RoleBinding

Latency budget: minutes.

1. Router classifies → Tier 5.
2. Multi-party signing ceremony: Router contacts each signer in `tariff.tiers[5].signers_allowlist`.
3. Each signer (typically: user's device, compliance officer's device, on-call lead's device) receives a ceremony invitation with the full intent context and a ceremony_id.
4. Each signer independently signs the ceremony record (Ed25519 or WebAuthn).
5. When `signers_required` signatures accumulate, Router releases action.
6. Ceremony record (with all signatures, timestamps, devices, geolocation-if-provided) appended to audit log. Immutable.

If quorum not reached within ceremony TTL (default 1 hour) → fail-closed.

---

## 4. Data schemas (CDDL-style fragments)

```cddl
Tariff = {
  customer_id: tstr,
  integration_id: tstr,
  version: uint,
  iat: uint,
  classifier_hash: bstr .size 32,
  tiers: { 0 => TierSpec, 1 => TierSpec, 2 => TierSpec, 3 => TierSpec, 4 => TierSpec, 5 => TierSpec },
  minimum_tiers: { tstr => uint },
  ambiguity_resolution: tstr,
  grace_skew_seconds: uint,
  ? revocation_channel_ref: tstr
}

Mandate = {
  iss: tstr,
  sub: tstr,
  aud: [tstr],
  iat: uint,
  nbf: uint,
  exp: uint,
  jti: bstr .size 16,
  cap: [tstr],               ; glob-style action descriptors
  budget: { actions: uint, api_calls: uint, spend_cents: uint },
  policy_bundle_hash: bstr .size 32,
  revocation_channel_ref: tstr,
  min_tier: uint,             ; mandate applies only to tier >= this
  attester_required: AttesterPins
}

Capability = {
  parent_mandate_jti: bstr,
  action: tstr,
  full_params: any,           ; full CBOR-encoded params, not a hash
  resource_version: tstr,
  nonce: bstr .size 16,
  iat: uint,
  exp: uint,
  attester_quote_hash: bstr .size 48
}

AuditEvent = {
  type: "intent_to_execute" / "action_executed" / "policy_decision" / "mandate_issued" / "mandate_revoked" / "webauthn_step_up" / "multi_party_ceremony",
  tier: uint,
  mandate_jti: ? bstr,
  capability_nonce: ? bstr,
  intent: Intent,
  resource_version: ? tstr,
  target_status: ? uint,
  target_body_hash: ? bstr,
  webauthn_assertion: ? bstr,
  ceremony_signatures: ? [Signature],
  seq: uint,                  ; monotonic per-router
  ts: uint
}
```

All signed objects: COSE_Sign1 (RFC 9052), EdDSA (Ed25519), deterministic CBOR (RFC 8949 §4.2).

---

## 5. How v2 resolves the Round 2 attacks

| # | Attack (severity) | Resolution in v2 |
|---|---|---|
| 1 | OPCE (SHOWSTOPPER) | `K_signer_priv` lives in the **Signer Service enclave ONLY**. LLM client, orchestrator, any dep-heavy code are in the Agent Runtime, a separate process (even separate compute), with **no access to `K_signer_priv`**. The attack path "compromised npm package reads key" is gone — the key is in a different address space than any package. |
| 2 | BOOT-KEY-SUB (SHOWSTOPPER) | `K_cust_pub` flows via **customer-built, customer-signed Router image**, not vendor-supplied vsock config. Router refuses to start if config-signature fails. Signer Service's attestation `user_data` includes `SHA-256(Tariff)`, so Router validates which-Tariff-the-enclave-trusts. No unmeasured trust path. |
| 3 | PARAM-CANON (SHOWSTOPPER) | Capability signs the **full CBOR-encoded params object**, not a hash. Canonicalization is RFC 8949 §4.2 deterministic CBOR, specified to the byte level. Test vectors published in implementation reference. |
| 4 | AUDIT-GAP (SERIOUS) | Two-phase audit mandatory: `intent_to_execute` written + synced to S3 BEFORE target API call; `action_executed` after. On recovery, orphan `intent_to_execute` events flag for reconciliation. |
| 5 | REVOKE-RACE (SERIOUS) | **Push-based revocation** for Tier 3+. Router holds a confirmed-live timestamp per mandate; rejects any Tier 3+ action if last confirmation > 5s ago. Tier 2 retains short-TTL cache (10s). Fail-closed if push stream down. |
| 6 | TOCTOU-TARGET (SERIOUS) | Capability for Tier 2+ carries `resource_version`. Router sends `If-Match` to target API. Target rejects on mismatch. Agent must re-read + re-submit. Tier 0-1 doesn't need this (reads are read; idempotent writes are idempotent). |
| 7 | HA-REPLAY (SERIOUS) | Router nonce cache is Redis with fenced writes (single-writer-per-nonce via Redis SETNX-style). Per-mandate session affinity via hash-routing. Replay across instances becomes impossible up to Redis consistency guarantees. |
| 8 | PDP-PCR-GAP (SERIOUS) | PDP code is statically linked into the Signer Service binary. That binary is measured in PCR0/1/2. Policy bundle hash is in Tariff; Signer Service fetches bundle, verifies hash, evaluates. No separate runtime PDP binary. |
| 9 | MANDATE-JTI-ENTROPY (MINOR) | `jti` specified as 128-bit random (16 bytes) in CDDL. Not ULID. |
| 10 | PROMPT-INJECTION-VIA-INGESTED-CONTENT (SERIOUS, acknowledged) | Still bounded by Tariff tightness. **New in v2**: the Tariff's `minimum_tiers` provides a hard floor that no mandate writer or policy author can accidentally undermine. Additionally: destructive ops always hit Tier 4+ → WebAuthn puts a human in the loop for the irreversible subset. |

All eight Round 2 issues addressable. None require novel crypto. None require formal verification of the full system. None require confidential LLM inference.

---

## 6. Assumptions (v2, revised)

Stripped down. Every item is a conditional; if broken, the stated property is lost.

| # | Assumption | If broken, what's lost |
|---|---|---|
| B1 | `K_cust` (customer HSM key) is uncompromised | All mandate / Tariff authenticity |
| B2 | Customer's Tariff correctly assigns Tiers; `minimum_tiers` covers obvious destructive cases | Proportionality guarantee |
| B3 | Classifier WASM is deterministic and correct | Correct tier assignment per action |
| B4 | Router codebase is auditable and free of RCE | Tier 0-1 authorization; Tier 2+ degrades to enclave-only trust |
| B5 | Signer Service enclave measurements are trustworthy (AWS Nitro) | Tier 2+ capability authenticity |
| B6 | WebAuthn device is in user's possession and uncompromised | Tier 4 step-up integrity |
| B7 | Multi-party signers are independent and adversarial-to-each-other-if-compromised | Tier 5 ceremony integrity |
| B8 | OIDC issuer + DPoP endpoint uncompromised | Tier 0-1 runtime identity |
| B9 | Target API honors RBAC/IAM from presented tokens | Defense-in-depth at target |
| B10 | S3 Object Lock in compliance mode is honored | Audit immutability |
| B11 | TLS 1.3, Ed25519, SHA-256/384, AES-256-GCM remain unbroken | Everything |
| B12 | Push-revocation channel is live with < 5s latency | Tier 3+ revocation promptness |
| B13 | Agent runtime is not Tier-2+-credentialed (held only Tier 0-1 credentials, obtained short-lived) | Agent compromise blast radius bounded to Tier 0-1 |

Trimmed from v1's 15 to 13. The two deleted assumptions (A7 "orchestrator avoids mixing secrets into LLM context" and A12 "enclave boot reproducibility") are no longer load-bearing — because the orchestrator never holds Tier 2+ secrets, and the Signer Service enclave has a small, stable measurement surface not shared with the LLM-handling code.

---

## 7. What v2 is NOT

- Not a confidential-LLM solution. Data passed to LLM remains visible to LLM provider. Threat model unchanged on this axis.
- Not a formal-verification-required system. Recommended to formally verify the Signer Service protocol, but the system is usable before that verification lands.
- Not dependent on any specific TEE vendor. Nitro is the default; TDX / SEV-SNP viable with different attestation chains; the attestation format is abstracted in the Tariff's `attester_required` field.
- Not a replacement for target-API permissions. RBAC/IAM at target is independent defense-in-depth.

---

## 8. Residual concerns (for Round 4)

Things I expect the Red Team to press on:

1. **Tariff mis-author risk** — a customer could write a bad Tariff (mis-assign tiers). This is now the central operator concern. Mitigated by: `minimum_tiers` floor, review tooling, test harness, but not eliminated.
2. **Classifier bypass** — an intent crafted to confuse the classifier into downgrading. `ambiguity_resolution: up` + `minimum_tiers` cap the downside but the surface exists.
3. **Cross-tier aggregation attacks** — N Tier-1 actions accomplishing what one Tier-4 would. E.g., many small DB updates that effectively delete a table. Operator-level concern; classifier cannot see histories without becoming stateful.
4. **WebAuthn phishing** — user confirms a challenge that displays misleading information. Mitigation is UI-level: show the intent's action + resource verbatim; rp_id binding prevents cross-origin.
5. **Multi-party signer collusion** — 3-of-3 signers colluding. Not a cryptographic attack; operational risk to signers_allowlist composition.
6. **Router-as-authority-concentration** — Router does a lot. Does it become a new SPOF? Partially mitigated by: Router holds only Tier 0-1 credentials persistently; Tier 2+ authority is minted fresh per action by the Signer. A router RCE can grant Tier 0-1 actions but not Tier 2+ actions.
7. **Push-revocation channel DoS** — attacker DoSes the push channel → Router fails-closed on Tier 3+ → denial of service. Intended fail-mode but must be monitored.
8. **Clock skew across signers** in Tier 5 ceremony — each signer's timestamp differs; how is ceremony timing anchored?

---

## 9. Minimum Viable variant (MV-EPHEMERAL)

Not every customer adopts all tiers at once. The architecture **degrades gracefully**:

- **MV-0**: Tier 0-1 only. Just OIDC-DPoP + OPA + audit. Identical to the Round 0 Skeptic's 80%-alt. Deployable in **~2 weeks**.
- **MV-1**: MV-0 + Tier 2. Adds Signer Service enclave, mandate, capability for the 15% of stateful writes. Deployable incrementally on top of MV-0 in **~2 months**.
- **MV-2**: MV-1 + Tier 3-4. Adds push-revocation + WebAuthn step-up. **+1-2 months**.
- **MV-3**: MV-2 + Tier 5. Multi-party ceremony. **+1-2 months**.

Most orgs will live at MV-1 for years. MV-2/3 is for high-stakes production surfaces.

**This resolves the Round 0 Skeptic's objection directly.** The vast majority of agent actions in an in-cloud deployment agent are Tier 0-1, handled identically to the 80%-alt. The architectural complexity of EPHEMERAL is **additive** and **optional** for the 5% of high-stakes actions where it earns its cost.

---

## 10. Caveat

This is Round 3 Architect output from a single LLM. The design is internally coherent and resolves the Round 2 findings, but is not audited or formally verified. External review required before production use — specifically, for the Signer Service enclave protocol and the Tariff / classifier boundary.
