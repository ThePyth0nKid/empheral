# conformance-plan.md — EPHEMERAL Conformance Suite Roadmap

**Purpose**: This document sets scope for the conformance test vector work and draws the line between **design-phase artifacts** (what we build now) and **development-phase artifacts** (what requires committed engineering resources).

**Status**: Phase A planning complete. Phase A execution in progress.

---

## Why conformance vectors now

Three reasons, ordered by weight:

1. **Spec-ambiguity detection**. Test vectors force the spec to be executable. Ambiguities that survive prose review (e.g., "what exactly constitutes scope-match?" from Round 6 V3-1) surface when you try to encode allow/deny pairs. This is the highest-leverage activity between "final design" and "reference implementation."

2. **Reference for first implementer**. The first team to implement EPHEMERAL will produce a CVE-generating bug in the first three months. If their implementation passes a published conformance suite, the bug is more likely in implementation detail than in protocol understanding. Without conformance vectors, we don't know which category the bug is in.

3. **Audit scaffolding**. External audit firms (condition C3 in `decision.md`) want to know what "correct" looks like. Conformance vectors are that definition.

---

## Phase A — Conformance vectors (design-phase, this session)

**Deliverables:**

| File | Spec ref | Target vectors |
|---|---|---|
| `conformance/schema.json` | §15 | JSON Schema for vector files themselves |
| `conformance/README.md` | §15 | Suite overview, execution contract |
| `conformance/delegation-scope.json` | §7.3, V3-1 | 50+ (allow/deny) pairs for delegation chain verification |
| `conformance/canonicalization.json` | §4.2, V2-2 | 80+ normalization equivalence pairs |
| `conformance/fuzz-baseline.json` | §4.4, V3-8 | 200+ intent patterns with expected tier floors |
| `conformance/tariff-reject.json` | §2.2, §3-§7, various | 60+ malformed Tariff rejection cases |
| `conformance/pcr-attestation-reject.json` | §9.3, §9.4, V3-3 | 40+ invalid attestation bundles |
| `conformance/audit-replay.json` | §3.5, §11 | 30+ attack audit streams anomaly detector must flag |

**Format decision**: JSON (UTF-8) as primary. CBOR serialization is lossless from this subset — CBOR encoders ship with every language. JSON is human-inspectable in a text editor and diffable in git. We serve CBOR at consumer-time, not source-time.

**Depth decision**: each vector has `id`, `category`, `description`, `input`, `expected`, `rationale`. Categories group vectors by attack class or spec-ambiguity. Each vector traces to a spec reference AND to the redteam finding that motivated it (if any).

**Out of scope for Phase A**:
- Executable validator harness (skeleton only, no real crypto verification).
- CBOR tooling.
- Test runner for any specific language.
- Real Ed25519 signatures (we use placeholder payloads; implementers generate real signatures against test keys).

---

## Phase B — Reference validator harness (design→development boundary)

**Trigger for starting Phase B**: conformance vectors passed an independent review (external or second-LLM) with zero ambiguity findings. If Phase A surfaces ambiguities in `design-final-v2.md`, fix those first.

**Deliverables:**

- `reference/validator/` — CLI that reads `schema.json` + all vector files, validates schema correctness.
- `reference/cbor/` — JSON↔CBOR round-trip library (can use `ciborium` for Rust or `cbor2` for Python).
- `reference/crypto/` — stubs for Ed25519 signature verification. Uses test keys.
- `reference/scope-matcher/` — executable implementation of §7.3 delegation scope-match table. Passes all `delegation-scope.json` allow vectors, rejects all deny vectors.
- `reference/classifier-harness/` — loads a classifier WASM, feeds `fuzz-baseline.json` intents, checks tier results match `minimum_tiers`.

**Estimated effort**: 15-25 dev-days if the implementer knows Rust + CBOR + Ed25519 + WASM runtime choice. Longer from zero.

**Language choice for reference**: Rust. Memory-safe (required by `design-final.md` §3.5 for Router), WASM support is mature (wasmtime), CBOR is mature (ciborium), COSE has a crate (cose-rust). Secondary: Go reference would have value for operability but isn't required.

**Phase B is still not production code.** It is engineering artifact used to validate the spec against itself. No HSM integration, no real enclave, no network stack.

---

## Phase C — Production reference implementation (development-phase)

**Trigger for starting Phase C**: Phase B's validator is clean, external audit of spec + Phase B artifacts is complete with no CRITICAL findings.

**Deliverables (at minimum)**:

- Router process (Rust, memory-safe, reproducibly built).
- Signer Service enclave (Nitro Enclave image + build pipeline).
- CLI tools for customer onboarding: `ephemeral-genkey`, `ephemeral-tariff-sign`, `ephemeral-mandate-sign`.
- Attestor service (automated PCR verification pipeline per V3-3).
- Classifier WASM reference library (K8s, Vault, generic DB).
- Target-invariant bundle reference library (Kyverno packs, Postgres constraints).
- Operational runbooks: key rotation, root compromise recovery, admin-bypass protocol.
- SBOM + provenance for all artifacts.
- CI: conformance suite gates every merge.

**Estimated effort** (from `skeptic-review.md` §3.2): 250-400 vendor dev-days for MV-3 feature set.

**Phase C is where production dollars matter.** The preceding phases are protection against committing those dollars to an unsound design.

---

## Phase D — External audit coordination

**Trigger**: Phase C MV-1 feature-complete.

Not a deliverable we build — a process we run. Items:
- Scope document (candidate firms receive this): `audit-scope.md` (can be produced in a later session).
- Threat model summary: already in `design-final.md` §1 + round artifacts.
- Test target deployment: Phase C artifact in a staging enclave.
- Source access: Phase B + Phase C source trees, reproducible builds verified.
- Findings integration: audit findings cause direct spec changes if fundamental; Phase C changes if implementation-only.

---

## Transition criteria summary

| Phase | Entry criterion | Exit criterion | Artifact readiness |
|---|---|---|---|
| A | Design stable (✓ reached) | All 6 vector files + schema + README land + self-consistent | Design-phase complete for spec |
| B | Phase A reviewed, zero ambiguity findings | Validator harness passes all vectors; documents implementation ambiguities for spec fixes | Spec proven executable |
| C | Phase B clean + external spec audit clean | MV-1 feature-complete + conformance suite gates CI | Product exists |
| D | MV-1 feature-complete | External audit report with no CRITICAL | Production-audit clean |

**Current position**: **Phase A + R7 + R8 delivery complete** (2026-04-18). 515 vectors across 6 files, schema-valid, all agent-produced output reviewed by a code-reviewer sub-agent, 4 critical findings fixed, 38 open spec questions fully resolved (R7: 15 bounded, R8: 23 operational). **Phase B entry satisfied via Path 1.**

### Phase A delivery summary

| File | Vectors | Spec ref | Defense focus |
|---|---:|---|---|
| `delegation-scope.json` | 68 | §7.3 + §3.1 | V3-1 scope-drift, §3.1 narrowness-rule |
| `canonicalization.json` | 93 | §4.2 | V2-2 classifier-signer normalization asymmetry |
| `fuzz-baseline.json` | 205 | §4.4, §4.5, §2.2 | V3-8 classifier weakness |
| `tariff-reject.json` | 68 | §2.2, §3-§7, §8.4 | R1 crypto integrity, V3-6 revocation HA |
| `pcr-attestation-reject.json` | 49 | §9.3, §9.4 | V3-3 attestation gaps |
| `audit-replay.json` | 32 | §3.5, §11 | R2 cross-tier-aggregation |

### Phase A → Phase B gate (review findings)

The code-reviewer pass identified 4 CRITICAL (fixed), 6 HIGH (2 fixed inline, 4 deferred to Phase B), 5 MEDIUM (documented, deferred). The suite is released as **v1.0.0 design-phase draft** — sufficient for Phase B intake but not for external audit (requires second independent human review first).

**Fixed before Phase A commit:**
- CRIT-1: duplicate JSON key in canonicalization.json `coverage_summary`.
- CRIT-2: `spec_version` unified to `round8-delta-applied` across all files (historical note: originally unified at `round6-final` during Phase A, bumped to `round7-applied` for R7 tightenings, and finally to `round8-delta-applied` when R8 operational tightenings merged into `design-final-v2.md`).
- CRIT-3: 4 new vectors (trej-065..068) cover V3-6 `revocation_channel_ha` enforcement.
- CRIT-4: `version-skew` renamed to `tariff-self-inconsistent-version` in tariff-reject to avoid cross-file code collision.
- HIGH-1: 4 new vectors (ds-065..068) cover §3.1 Layer 1 narrowness-rule.
- HIGH-3: ds-021 flipped to REJECT (strict interpretation of three-level role hierarchy).

**Deferred to Phase B (documented, non-blocking for design-phase):**
- HIGH-2: `pcr-attestor-not-trusted` used across tariff-reject and pcr-attestation-reject — taxonomy consolidation.
- HIGH-4: `audit-replay` arep-025 references `Tariff.operating_hours` field not in current §2.2 schema — either extend spec or rework vector.
- HIGH-5: no vectors for §5.3 resource-version binding on capability formation.
- HIGH-6: no vectors for §2.1 automatic escalation triggers (target_invariants_documented=false, classifier aggregation risk, canary-window Tier 3+).
- MED-1..5: reject code documentation polish, severity tagging review.

### Consolidated open spec questions (38 total)

Enumerated across files in their `notes` fields, grouped by theme:

- **Canonicalization semantics** (10): case-folding scope, NFC enforcement vs reject, null-vs-missing, length/depth caps, array ordering, zero-width/bidi char handling, identifier-separator escaping, locale neutrality.
- **PCR attestation** (6): normative PCR indices, STH max age, trusted log set pinning, nonce binding semantics, bundle size cap, split-view detection via witness cosignatures.
- **Anomaly detection** (4): pattern-library threshold values, auto-revoke vs alert-only, first-match vs N-consecutive firing, `Tariff.operating_hours` requirement.
- **Tariff structural limits** (5): max byte size, iat→not_before gap, max validity period, strict-vs-lenient on unknown fields, integration-unknown handling.
- **Delegation chain structure** (5): role hierarchy enforcement (ds-021), valid_until inclusivity, max chain depth, wildcard in integrations, empty-cap mandates.
- **Fuzz corpus tier assignments** (8): fieldSelector/sensitive-path/aggregation-window/drain-node/canary-bump/git-default-branch/DNS-apex/ACME-wildcard.

These 38 questions are the highest-value Phase A output. Each one is a spec-precision issue that a next-round architect pass should resolve before Phase B's reference validator harness is built.

---

## Phase B entry criteria (revised, post-Phase-A)

Entry to Phase B requires one of:
1. Independent second-LLM or human review of the 38 open spec questions — each resolved with a spec tightening or documented as "intentionally lenient". Raise spec to `design-final-v2.md` (R7 + R8 integrated) or equivalent.
2. Decision to proceed with Phase B using the current suite as-is, with Phase B validator harness tracking ambiguities as work items rather than resolving them upfront.

Path 1 is cheaper in total effort; Path 2 is faster to validator-reality-check.

**Original recommendation**: Path 1 for all 10 canonicalization questions and 5 delegation questions (bounded, architect can decide in one pass); Path 2 for the other 23 (more operationally dependent, better resolved against a real implementation).

**Actual resolution (2026-04-18)**: Path 1 adopted for **all 38 questions** — bounded 15 via R7 (`design-round7-tightenings.md`), operational 23 via R8 (`design-round8-operational-tightenings.md`). R8 was produced by a 4-architect agent swarm (one per cluster: PCR, Anomaly, Tariff, Fuzz) plus a two-pass review swarm (security-reviewer + code-reviewer + architect + Explore/redundancy). Pass 1: 6 findings (Sec-N1-N3, Code-N4/N5/N8) fixed in-place. Pass 2: 5 CRIT + 9 HIGH + 7 MED + 3 LOW findings across security/architect/code-reviewer reports; resolution strategy split into three categories — (A) mechanical count/rationale fixes applied directly to R8 delta + vectors; (B) four Pre-Integration Blockers (B-1 through B-4) documented in R8 as design-final.md/R7 amendment dependencies for the integration pass; (C) four operational residual flags (key_epoch self-declared, canary git-ref dead-zone, revocation cascade undefined, HWM bootstrap) added to R8 residual flags for Phase B instrumentation. Final strength direction: **23 STRENGTHEN / 0 NEUTRAL / 0 WEAKEN**, 32 new reject codes, 3 vector reject-code flips, 3 schema migrations, 0 outcome flips.

**Phase B entry is satisfied via Path 1 — CONDITIONAL** on Pre-Integration Blockers B-1 through B-4 resolution during the integration pass. The reference validator harness SHOULD be scaffolded against `design-final-v2.md` (the integrated R7 + R8 product, superseding the three-document stack `design-final.md` + `design-round7-tightenings.md` + `design-round8-operational-tightenings.md`). **[HISTORICAL NOTE — pre-integration guidance]**: during the integration pass itself, the harness was permitted to scaffold against the pre-integration three-document stack provided R8-dependent behaviors that collided with R6/R7 baselines were conservatively rejected. That guidance is superseded now that `design-final-v2.md` exists.

---

## Session plan for Phase A (this work order)

**Step 1 (solo, ~30 min)**: Plan doc + schema + README + `delegation-scope.json` (canonical).
**Step 2 (parallel subagents, ~20 min wall-clock)**: Spawn 5 agents in parallel, one per remaining vector file. Each agent gets:
- The schema.
- The canonical example file.
- Their assigned file's spec references and coverage requirements.
- Output contract.

**Step 3 (solo, ~15 min)**: Consistency review across all six files. Check categories are non-overlapping; ids are unique across suite; rationales trace to spec.

**Step 4 (code-reviewer agent)**: Independent validation pass. Specifically asked: does any file have coverage gaps relative to its spec section? Does any vector's expected behavior contradict another vector?

**Step 5 (solo)**: Commit + push.

**Honest session scope**: Phase A only. Phase B, C, D are next sessions, with external input between sessions.

---

## Non-goals for this session

- Do NOT write executable validator code.
- Do NOT generate real Ed25519 signatures for vectors (test keys and placeholder signatures are acceptable; implementers will re-sign with their own test keys before running).
- Do NOT write a Rust crate skeleton (Phase B).
- Do NOT speculate about firms for external audit (Phase D).
- Do NOT write CONTRIBUTING.md, LICENSE, or governance docs (separate session).

This session stays focused on: **make the spec executable by producing test vectors that unambiguously define correct behavior**. Anything else is scope creep.
