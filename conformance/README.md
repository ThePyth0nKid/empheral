# EPHEMERAL Conformance Test Vector Suite

**Version**: 1.0.0
**Spec reference**: `design-final.md` §15
**Status**: Phase A artifact (design-phase, not yet validated by any implementation)

---

## What this is

Six test vector files that unambiguously define correct EPHEMERAL behavior for the most security-critical decision points in the spec. Any implementation claiming v3-conformance MUST pass 100% of these vectors.

The suite is **source-form JSON**. Implementers serialize to deterministic CBOR (RFC 8949 §4.2) at consumer time. JSON is used as source because it is inspectable in any text editor, diffable in git, and the subset we use round-trips losslessly through CBOR.

---

## Files

| File | Spec ref | Purpose | Vector count target |
|---|---|---|---|
| `delegation-scope.json` | §7.3 | Delegation chain verification (V3-1 defense) | ≥ 50 |
| `canonicalization.json` | §4.2 | Intent normalization equivalence (V2-2 defense) | ≥ 80 |
| `fuzz-baseline.json` | §4.4 | Classifier baseline fuzz corpus (V3-8 defense) | ≥ 200 |
| `tariff-reject.json` | §2.2, §3-§7 | Malformed Tariff rejection | ≥ 60 |
| `pcr-attestation-reject.json` | §9.3, §9.4 | Invalid attestation bundles (V3-3 defense) | ≥ 40 |
| `audit-replay.json` | §3.5, §11 | Attack audit streams anomaly detector must flag | ≥ 30 |

---

## How to consume

1. Parse the file as JSON.
2. Validate against `schema.json` (any JSON Schema 2020-12 validator).
3. For each vector:
   a. Feed `input` to your implementation at the appropriate decision point.
   b. Compare your implementation's outcome to `expected.outcome`.
   c. If `expected.outcome == "reject"`, also compare `reject_code`.
   d. If `expected.outcome == "accept"` and `expected.output` is present, compare the implementation's output to it.
4. For any mismatch, log the vector `id` and your implementation's actual output. A v3-conformant implementation has zero mismatches.

---

## Conventions

### Vector IDs

Every vector has a stable ID. Format: `<prefix>-<sequence>`.

| Suite | Prefix | Example |
|---|---|---|
| delegation-scope | `ds` | `ds-042` |
| canonicalization | `canon` | `canon-113` |
| fuzz-baseline | `fuzz` | `fuzz-017` |
| tariff-reject | `trej` | `trej-025` |
| pcr-attestation-reject | `pcrrej` | `pcrrej-011` |
| audit-replay | `arep` | `arep-008` |

IDs are never reused even if a vector is removed. Add `deprecated: true` to a vector's object and leave it in place; use a fresh ID for its replacement.

### Categories

Each file uses its own set of category tags, documented in the file's `coverage_summary` field. Categories group vectors by the attack class or spec-ambiguity area they cover.

### Cryptographic material

Vectors use placeholder / test-vector public keys and signatures. **No real private keys.** Implementers running the suite locally generate ephemeral signing keys and replace placeholders at test-build time. Placeholder format is documented per-suite where relevant.

Where a vector's correctness depends on signature validity (e.g., `delegation-scope.json` tests a correctly-signed mandate), the vector specifies which signature-verification result the implementation should assume. A separate test vector category verifies signature-verification itself (live crypto, not in Phase A scope).

---

## Expected reject codes (cross-suite reference)

The following reject codes appear across multiple suites. Implementations should emit one of these codes (or a suite-specific extension) when rejecting.

| Code | Suite(s) | Meaning |
|---|---|---|
| `signature-invalid` | delegation-scope, tariff-reject, pcr-attestation-reject | Signature does not verify against the claimed key. |
| `signature-chain-broken` | delegation-scope | Chain has an unsigned or wrongly-signed link. |
| `scope-integration-mismatch` | delegation-scope | Mandate's `integration_ref` not in delegation's allowed integrations. |
| `scope-tier-exceeded` | delegation-scope | Mandate requests tier above delegation's `max_tier_signable`. |
| `scope-verb-forbidden` | delegation-scope | Canonical verb not in delegation's `allowed_verbs`. |
| `scope-resource-kind-forbidden` | delegation-scope | Canonical resource kind not in delegation's `allowed_resource_kinds`. |
| `scope-budget-exceeded` | delegation-scope | Mandate's budget exceeds delegation's `max_budget`. |
| `scope-expiry-too-long` | delegation-scope | Mandate's `exp - issued_at` exceeds delegation's `max_exp_seconds`. |
| `expired` | delegation-scope, tariff-reject | Validity window elapsed. |
| `revoked` | delegation-scope | On revocation list. |
| `version-too-old` | tariff-reject | Tariff version below previously-seen. |
| `version-skew` | delegation-scope | Mandate's `min_tariff_version` exceeds current pinned Tariff version (fires at mandate acceptance). |
| `tariff-self-inconsistent-version` | tariff-reject | Tariff's own internal `minimum_tiers` references a `min_tariff_version` higher than its own version (fires at Tariff load). Distinct from `version-skew` — different lifecycle stage. |
| `narrowness-rule-violation` | delegation-scope | §3.1 Layer 1: mandate cap contains wildcard but budget.actions exceeds `narrowness_threshold` (default 20). |
| `normalization-not-applied` | canonicalization | Intent presented to classifier was not canonical. |
| `tier-below-minimum` | fuzz-baseline | Classifier returned tier below Tariff's `minimum_tiers` floor for the action. |
| `pcr-attestation-quorum-short` | pcr-attestation-reject | Fewer than quorum attestors signed. |
| `pcr-attestation-mismatch` | pcr-attestation-reject | Attestors computed different PCR values. |
| `pcr-attestation-transparency-missing` | pcr-attestation-reject | No transparency-log inclusion proof. |
| `aggregation-pattern-detected` | audit-replay | Pattern matched; revocation should be pushed. |

Implementations MAY extend this list with vendor-specific codes but MUST support these when applicable.

---

## How to contribute vectors

For now: edit files in place, preserve existing vector IDs, add new vectors with new IDs. Every new vector MUST include:
- `rationale` traceable to a spec section or a redteam finding.
- `severity_if_failed` classification.
- Review by someone other than the author (Phase B will formalize this with CI).

Open questions raised while authoring vectors (spec ambiguities) are tracked in a file-level `notes` field. These are the most valuable output of this phase — they drive spec precision in future iterations.

---

## Relationship to spec revisions

Every time `design-final.md` changes materially, the `spec_version` field in each vector file must be updated. If the change invalidates vectors, bump `schema_version` and annotate the migration in this README.

The suite is an artifact of a specific spec commit. Vectors authored against one commit may not pass against a later commit without review.

---

## What this suite does NOT test

- **Real cryptographic primitive correctness**. Assumes Ed25519, COSE, CBOR libraries are correct. Those are tested by the libraries' own conformance suites.
- **Timing side channels, constant-time behavior**. Out of Phase A scope.
- **Network-level properties** (TLS, mTLS correctness). Out of scope.
- **Enclave attestation chain correctness**. Requires live Nitro; out of Phase A scope.
- **Target-API state invariants**. Out of EPHEMERAL scope (target-level, per §3.4).
- **Performance / resource limits**. Phase B+ concern.

---

## Known limitations

- Vectors were authored by a single language-model-driven process. Independent review (Phase B trigger) is required before declaring the suite "audit-ready."
- Some categories (notably `audit-replay.json`) encode attack patterns known at spec authoring time; novel patterns require suite updates.
- The `fuzz-baseline.json` target count (200) is a floor, not a ceiling. Reference implementations should augment with target-integration-specific patterns.
