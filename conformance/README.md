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
| `role-hierarchy-violation` | delegation-scope | R7.D1: direct `root`→`mandate_signer` delegation — must traverse `ops` role (three-level hierarchy). |
| `scope-integrations-wildcard-forbidden` | delegation-scope | R7.D4: `integrations: ["*"]` forbidden at every delegation level. Explicit enumeration required. |
| `mandate-empty-cap` | delegation-scope | R7.D5: mandates with `cap: []` forbidden. Every mandate MUST authorize ≥1 concrete action. |
| `chain-depth-exceeded` | delegation-scope | R7.D3: delegation chain exceeds max depth (default 4 keys / 3 links). |
| `normalization-not-applied` | canonicalization | Intent presented to classifier was not canonical. |
| `tier-below-minimum` | fuzz-baseline | Classifier returned tier below Tariff's `minimum_tiers` floor for the action. |
| `pcr-attestation-quorum-short` | pcr-attestation-reject | Fewer than quorum attestors signed. |
| `pcr-attestation-mismatch` | pcr-attestation-reject | Attestors computed different PCR values. |
| `pcr-attestation-transparency-missing` | pcr-attestation-reject | No transparency-log inclusion proof. |
| `aggregation-pattern-detected` | audit-replay | Pattern matched; revocation should be pushed. Payload extended by R8.A2 with `{pattern_id, library_version, severity, firing_rule}`. |
| `tariff-pcr-expected-empty` | pcr-attestation-reject | R8.P1: `Tariff.pcr_requirement.expected_pcrs` is empty. |
| `pcr-expected-missing-in-bundle` | pcr-attestation-reject | R8.P1: bundle omits a PCR index pinned by Tariff. |
| `pcr-bundle-malformed` | pcr-attestation-reject | R8.P1: bundle reports PCR indices outside TPM 2.0 [0,23] / Nitro [0,15] range. |
| `tariff-pcr-sth-age-unset` | pcr-attestation-reject | R8.P2: `transparency_log_max_root_age_seconds` absent. |
| `tariff-pcr-sth-age-too-lax` | pcr-attestation-reject | R8.P2: STH age ceiling > 604800s (7d). |
| `tariff-pcr-sth-age-invalid` | pcr-attestation-reject | R8.P2: STH age ceiling ≤ 0. |
| `pcr-attestation-transparency-stale` | pcr-attestation-reject | R8.P2: `root_age_seconds` exceeds Tariff ceiling. |
| `pcr-attestation-transparency-invalid` | pcr-attestation-reject | R8.P2: STH signature or proof fails; residual code. |
| `tariff-pcr-trusted-logs-empty` | pcr-attestation-reject | R8.P3: `trusted_transparency_logs` empty. |
| `tariff-pcr-trusted-logs-duplicate` | pcr-attestation-reject | R8.P3: duplicate `log_id` under R7.C6 SET semantics. |
| `tariff-pcr-trusted-log-alg-unsupported` | pcr-attestation-reject | R8.P3: `key_alg` outside allowlist. |
| `pcr-attestation-transparency-log-unknown` | pcr-attestation-reject | R8.P3: proof references `log_id` not in Tariff set. |
| `pcr-attestation-nonce-missing` | pcr-attestation-reject | R8.P4: attestation lacks nonce. |
| `pcr-attestation-nonce-mismatch` | pcr-attestation-reject | R8.P4: nonce ≠ Router challenge (also serves TTL-elapsed). |
| `pcr-attestation-nonce-reuse` | pcr-attestation-reject | R8.P4: nonce appears in Router consumed-ledger. |
| `pcr-attestation-nonce-inconsistent` | pcr-attestation-reject | R8.P4: attestors signed distinct nonces within one bundle (split-attestor forgery). |
| `tariff-pcr-bundle-max-size-too-strict` | pcr-attestation-reject | R8.P5: `bundle_max_size_bytes` < 4096. |
| `tariff-pcr-bundle-max-size-too-lax` | pcr-attestation-reject | R8.P5: `bundle_max_size_bytes` > 1048576. |
| `pcr-bundle-too-large` | pcr-attestation-reject | R8.P5: bundle byte-size exceeds Tariff cap (measured before CBOR decode). |
| `pcr-attestation-witness-cosignature-missing` | pcr-attestation-reject | R8.P6: bundle lacks required witness cosignatures. |
| `pcr-attestation-witness-cosignature-invalid` | pcr-attestation-reject | R8.P6: witness cosignature fails verification. |
| `tariff-pcr-witnessing-insufficient-for-tier` | pcr-attestation-reject | R8.P6: Tier 4+ Tariff has `required < 2` or `trusted_witnesses.length < 3`. |
| `tariff-pcr-witnessing-single-provider` | pcr-attestation-reject | R8.P6: Tier 4+ Tariff's witnesses span fewer than 2 distinct `provider` labels. |
| `pattern-library-version-too-old` | audit-replay | R8.A1: `AnomalyPatternLibrary.library_version` ≤ current pinned (distinct from Tariff `version-too-old`). |
| `pattern-library-signer-role-violation` | audit-replay | R8.A1: library signed by key other than `K_cust_anomaly_library_signer`. |
| `pattern-library-relaxation-without-exception` | audit-replay | R8.A1: new library relaxes threshold below high-water-mark without ceremony_quorum `PatternRelaxationException`. |
| `tariff-invalid-timezone` | tariff-reject, audit-replay | R8.A4: `operating_hours.timezone` not a valid IANA zone name. |
| `operating-hours-overlap` | tariff-reject | R8.A4: two `windows` entries with same `day_of_week` overlap on `(start_minute, end_minute)`. |
| `operating-hours-window-inverted` | tariff-reject | R8.A4: window's `end_minute` ≤ `start_minute`. |
| `operating-hours-day-invalid` | tariff-reject | R8.A4: `day_of_week` > 6. |
| `tariff-oversize` | tariff-reject | R8.T1: Tariff COSE envelope > 262144 bytes (256 KiB); checked before signature verify. |
| `tariff-iat-nbf-gap-excessive` | tariff-reject | R8.T2: `not_before - iat` > 2592000s (30d). |
| `tariff-iat-after-nbf` | tariff-reject | R8.T2: `iat > not_before`. |
| `clock-skew-exceeded` | tariff-reject | R8.T2: `iat > current_time + tolerance`. |
| `tariff-key-epoch-cap-exceeded` | tariff-reject | R8.T2: more than 2 Tariffs share one `K_tariff_signer` epoch. |
| `tariff-future-dated-requires-ceremony-quorum` | tariff-reject | R8.T2: Tariff with `not_before > current_time + 604800s` lacks ceremony_quorum co-signature. |
| `tariff-validity-period-excessive` | tariff-reject | R8.T3: `exp - not_before` > 2592000s (30d). |
| `tariff-validity-window-empty` | tariff-reject | R8.T3: `exp ≤ not_before`. |
| `tariff-unknown-field` | tariff-reject | R8.T4: payload contains top-level or nested key outside §2.2 schema (strict, no extensions map). |
| `tariff-version-unsupported` | tariff-reject | R8.T4: `version` integer outside supported range. |
| `tariff-integration-unknown` | tariff-reject | R8.T5: `integration_ref` (top-level, in `minimum_tiers`, or in `rate_matrix`) not in integration catalog. |

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
