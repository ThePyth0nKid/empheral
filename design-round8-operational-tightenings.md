# design-round8-operational-tightenings.md

**Version**: round8-delta
**Date**: 2026-04-18
**Spec reference**: `design-final.md` §2.2, §3.5, §4.4, §9.3–§9.4, §11
**Status**: Delta document resolving 23 operational spec ambiguities consolidated during Phase A conformance authoring.
**Relationship to R7**: R7 (`design-round7-tightenings.md`) resolved 15 bounded spec questions (§4.2 canonicalization + §7 delegation). R8 resolves the 23 operational questions deferred from R7 — they depend on execution-surface decisions that R7's bounded pass intentionally did not touch.

---

## Governing principles (inherited from R7, applied across all four clusters)

1. **Stricter-is-safer** — prefer MUST over SHOULD when operational cost is bounded.
2. **Preserve the V3-series defenses** — V3-1, V3-3, V3-6, V3-8 must not weaken.
3. **Determinism over permissiveness** — every verifier decision is a total function of `(input, pinned_tariff, current_time, router_state)` → `{accept, reject(code)}`.
4. **Explicit operator-visible fields over implicit assumptions** — operators MUST see what they are pinning.
5. **Cite prior authority** — RFC 6962/9162 (CT), RFC 8949 (CBOR), RFC 9052 (COSE), RFC 7519 (JWT), RFC 8555 (ACME), NIST SP 800-53, AWS Nitro Attestation v1.0, TCG PC Client Platform Firmware Profile, MITRE D3FEND D3-AE, Sigma rules, CNCF Argo Rollouts, CA/Browser Forum Baseline Requirements.
6. **Minimize taxonomy growth** — extend existing reject codes with structured detail where possible; new codes only when specificity buys detection precision.
7. **Composition rules must be explicit** — where multiple bumps / caps / windows interact, state the arithmetic.

**Summary of R8 strength direction**: 23 tightenings — **23 STRENGTHEN, 0 NEUTRAL, 0 WEAKEN**.

---

## Cluster 1 — PCR Attestation (§9.3–§9.4, V3-3 defense)

Six tightenings resolve all six ambiguity flags in `conformance/pcr-attestation-reject.json` notes.

### R8.P1: Normative PCR indices for Signer image hash

**Question**: Which PCR indices are authoritative for boot firmware, kernel, and enclave application?

**Answer (normative)**: Tariff MUST pin the PCR index set explicitly via `Tariff.pcr_requirement.expected_pcrs` (map PCR-index-label → SHA-256 hex). Recommended default for AWS Nitro profile: `PCR0` (image measurement), `PCR4` (kernel/boot-chain), `PCR8` (application payload). TPM 2.0 deployments SHOULD follow TCG PFP §3.3.4. Empty map REJECTS at Tariff validation with `tariff-pcr-expected-empty`. A bundle omitting any pinned index REJECTS with `pcr-expected-missing-in-bundle`.

**Rationale**: TCG PC Client Platform Firmware Profile assigns PCR0–PCR7 to platform firmware and boot chain, PCR8–PCR15 to OS/app extensions. AWS Nitro Attestation v1.0 aligns. Hardcoding the triple would break under Nitro profile revision or TPM 2.0 deployments. Tariff-pinning matches R7.D4 ("explicit enumeration beats wildcards").

**Spec patch (§9.4, new §9.4.1)**: Tariff MUST declare `pcr_requirement.expected_pcrs` as non-empty CBOR map (tstr → 64-char lowercase hex). Router MUST treat every pinned index as mandatory; a bundle omitting any rejects with `pcr-expected-missing-in-bundle`. A bundle reporting PCR indices outside TPM 2.0 `[0,23]` (or Nitro `[0,15]`) rejects with `pcr-bundle-malformed`.

**Vector impact**: `pcrrej-033` ratified. Phase B additions: `pcrrej-049` (Tariff pins only PCR8, matching bundle → accept), `pcrrej-050` (empty `expected_pcrs` → `tariff-pcr-expected-empty`).

**Strength impact**: STRENGTHEN — closes "silently accept subset of attested PCRs" evasion.

### R8.P2: Transparency-log Signed Tree Head maximum age

**Question**: Maximum STH age before Router rejects as stale?

**Answer (normative)**: `Tariff.pcr_requirement.transparency_log_max_root_age_seconds` MUST be present, range `[1, 604800]` (1s – 7d). Absence REJECTS with `tariff-pcr-sth-age-unset`. Value > 604800 REJECTS with `tariff-pcr-sth-age-too-lax`. Value ≤ 0 REJECTS with `tariff-pcr-sth-age-invalid`. Recommended default: 86400 (24h). At verification, `root_age_seconds > max` REJECTS with `pcr-attestation-transparency-stale`; `root_age_seconds < 0` REJECTS with `pcr-attestation-transparency-invalid`.

**Rationale**: RFC 6962 §3.5 specifies CT logs produce STH at least every 24h; Rekor/sigstore prod matches. 7-day ceiling prevents disabling freshness checks via permissive config (same pattern as R7 precedent on `grace_period_seconds` caps). Freeze attacks are the V3-3 surface this closes.

**Spec patch (§9.4, §9.4.2)**: As stated above; `root_age_seconds = current_time - sth_timestamp`.

**Vector impact**: `pcrrej-022` ratified. Phase B: `pcrrej-051` (future-dated STH), `pcrrej-052` (Tariff declares 30d max → `tariff-pcr-sth-age-too-lax`).

**Strength impact**: STRENGTHEN.

### R8.P3: Trusted transparency-log set pinning

**Question**: How are trusted transparency logs pinned against adversary-run logs?

**Answer (normative)**: `Tariff.pcr_requirement.trusted_transparency_logs` MUST be a non-empty CBOR array of log-identity objects:

```cbor
{
  "log_id":       tstr,   // stable identifier, byte-compared post-NFC (R7.C3)
  "public_key":   bstr,   // SubjectPublicKeyInfo DER per RFC 5280 §4.1
  "key_alg":      tstr,   // allowlist: "ed25519" | "ecdsa-p256-sha256" | "ecdsa-p384-sha384"
  "origin_url":   tstr,   // optional informational
  "valid_from":   uint,   // optional, half-open per R7.D2
  "valid_until":  uint
}
```

`log_id`s form a set (R7.C6); duplicates REJECT with `tariff-pcr-trusted-logs-duplicate`. Empty array REJECTS with `tariff-pcr-trusted-logs-empty`. Unsupported `key_alg` REJECTS with `tariff-pcr-trusted-log-alg-unsupported`. At verification, `log_id` not in set → `pcr-attestation-transparency-log-unknown`; STH signature failure → `pcr-attestation-transparency-invalid`.

**Rationale**: RFC 6962 §3.1 pins CT logs by public-key identity. Pinning by log_id alone is insufficient (DNS-spoofable). Matches sigstore `trusted-root.json` format. Key-alg allowlist prevents downgrade. `valid_from/valid_until` aligns with R7.D2 for consistency.

**Spec patch (§9.4, §9.4.3)**: As stated. Integration pass MUST extend the R7.C6 §4.2.1 SET-field enumeration to include `trusted_transparency_logs` — set-membership determined by `log_id` byte-compare post-NFC normalization; duplicate detection (`tariff-pcr-trusted-logs-duplicate`) runs over the `log_id` projection only.

**Vector impact**: `pcrrej-023` schema-migrate from string-array to object-array (reject_code unchanged). Phase B: `pcrrej-053` (expired log key).

**Strength impact**: STRENGTHEN.

### R8.P4: Router-issued nonce binding

**Question**: Is nonce freshness mandatory, optional, or profile-dependent?

**Answer (normative)**: **MANDATORY.** Every `attestations[i]` MUST include `nonce` byte-equal to the Router's cycle nonce. Router maintains a consumed-nonce ledger. Nonce MUST be ≥128 bits CSPRNG entropy. `Tariff.pcr_requirement.nonce_ttl_seconds` default 300, range `[30, 3600]`. Reject conditions:

- Missing nonce in any attestation → `pcr-attestation-nonce-missing`
- Nonce mismatch → `pcr-attestation-nonce-mismatch`
- Nonce reuse (ledger hit) → `pcr-attestation-nonce-reuse`
- Distinct nonces across `attestations[*]` in same bundle → `pcr-attestation-nonce-inconsistent`

**Rationale**: NIST SP 800-63B §5.1.1 mandates challenge-response for replay resistance, 128-bit minimum. `nonce-inconsistent` code closes split-attestor forgery where a compromised attestor signs own nonce while honest attestors sign Router's — quorum appears to pass unless consistency is checked.

**Spec patch (§9.4, §9.4.4)**: As stated; bundle presented after TTL rejects indistinguishably with `pcr-attestation-nonce-mismatch` (cannot reveal whether nonce existed).

**Vector impact**: `pcrrej-040`, `pcrrej-042` ratified. Phase B: `pcrrej-054` (nonce-inconsistent), `pcrrej-055` (nonce-missing in one entry), `pcrrej-056` (TTL-expired).

**Strength impact**: STRENGTHEN — closes replay + split-attestor forgery paths.

### R8.P5: PCR bundle size cap

**Question**: Upper bound on attestation bundle size?

**Answer (normative)**: `Tariff.pcr_requirement.bundle_max_size_bytes` MUST be present, range `[4096, 1048576]` (4 KiB – 1 MiB). Recommended default: 262144 (256 KiB). Value < 4096 → `tariff-pcr-bundle-max-size-too-strict`. Value > 1048576 → `tariff-pcr-bundle-max-size-too-lax`. Router MUST measure length **before CBOR decoding**; oversized bundles → `pcr-bundle-too-large`.

**Rationale**: Reference calibration: single Nitro attestation ~4–8 KiB; 5-attestor bundle with CT inclusion path ~50 KiB. 256 KiB = 5× headroom. 1 MiB is absolute ceiling beyond which DoS risk is unjustifiable. 4 KiB minimum prevents operator-configured DoS-via-tight-config. Measure-before-decode is determinism principle.

**Spec patch (§9.4, §9.4.5)**: As stated.

**Vector impact**: `pcrrej-047` ratified. Phase B: `pcrrej-057` (2 MiB policy → too-lax), `pcrrej-058` (1 KiB → too-strict).

**Strength impact**: STRENGTHEN.

### R8.P6: Split-view defense via witness cosignatures

**Question**: Witness cosignatures — binding, optional, or future work?

**Answer (normative)**: **Binding at Tariff option, required for Tier 4+.** New fields `Tariff.pcr_requirement.required_witness_cosignatures` (uint, default 0) and `trusted_witnesses` (array, same object shape as `trusted_transparency_logs` plus optional `provider: tstr` default `"unspecified"`).

Rules:
- `required == 0`: no witness check.
- `required > 0`: bundle MUST include `witness_cosignatures` array; at least N distinct cosignatures verify under distinct `trusted_witnesses` entries signing same `(sth_tree_hash, sth_tree_size)`.
- Missing/undersized → `pcr-attestation-witness-cosignature-missing`.
- Verification failure → `pcr-attestation-witness-cosignature-invalid`.
- **Tier 4+ Tariffs**: MUST have `required ≥ 2` AND `trusted_witnesses.length ≥ 3` spanning ≥ 2 distinct `provider` labels. Violation → `tariff-pcr-witnessing-insufficient-for-tier` or `tariff-pcr-witnessing-single-provider`.

**Rationale**: RFC 9162 §5.3 (CT 2.0) documents witness cosignatures as primary split-view defense. sigstore/sigsum ecosystem standardizes 2-of-N with 3+ diverse witnesses. Multi-provider mirrors §8.4 revocation_channel_ha Tier-4 gate. Lower tiers MAY opt out in exchange for operational simplicity — bounded blast radius at Tier 1-3 acceptable.

**Spec patch (§9.4, §9.4.6)**: As stated. Integration pass MUST extend the R7.C6 §4.2.1 SET-field enumeration to include `trusted_witnesses` — set-membership by `log_id` byte-compare post-NFC; `provider` label is informational for diversity check but not part of the membership key.

**Vector impact**: `pcrrej-045` reject_code FLIP from `pcr-attestation-transparency-invalid` → `pcr-attestation-witness-cosignature-missing` for specificity. Phase B: `pcrrej-059..062` (Tier 4 boundary cases).

**Strength impact**: STRENGTHEN.

**Residual operator-feedback flag** (cluster coordinator): R8.P6's Tier 4 minimum of 2-of-3 multi-provider witnesses is defensible on RFC 9162 + sigstore prior-art, but the witness supply side (armored-witness, sigsum) is still consolidating in 2026. Recommend one round of operator feedback from Nitro-enclave production customers before design-final freeze, or a phased rollout (1-of-1 in 2026, 2-of-3 in 2027).

---

## Cluster 2 — Anomaly Detection (§3.5, §11)

Four tightenings resolve `conformance/audit-replay.json` notes.

### R8.A1: Pattern-library default thresholds — versioned signed artifact

**Question**: Are the ten thresholds NORMATIVE, ADVISORY, or MINIMUM?

**Answer (normative)**: **MINIMUM** with versioned signed artifact AND distinct signing key role. Introduce `AnomalyPatternLibrary` — COSE_Sign1 CBOR document parallel to Tariff:

```cbor
AnomalyPatternLibrary = COSE_Sign1({
  "library_version":    uint,            // monotonic, distinct from Tariff version field
  "issued_at":          uint,
  "valid_until":        uint,
  "patterns":           [PatternEntry],  // SET-typed; extends R7.C6 §4.2.1 enumeration
  "issuer_constraints": {...}
}, signed_by: K_cust_anomaly_library_signer)
```

**Distinct signing key role (MANDATORY)**: `K_cust_anomaly_library_signer` is a distinct role in the R7.D1 hierarchy, rotated independently from `K_cust_ops`. Libraries signed by `K_cust_ops` (or any other delegation key) REJECT with `reject_code = pattern-library-signer-role-violation` (new code). The delegation path is `K_cust_root → K_cust_ops → K_cust_anomaly_library_signer` (three-level per R7.D1), but mandate/Tariff signing and pattern-library signing MUST NOT share signing keys — this prevents a single `K_cust_ops` compromise from both expanding mandate scope AND raising detection thresholds simultaneously.

**Integration-pass note (required)**: The R7.D1 §7.2 `child_role` enumeration in design-final.md currently lists {`ops`, `tariff_signer`, `audit_signer`, `mandate_signer`}. Integration MUST extend this enum to include `anomaly_library_signer` as a valid child role delegable under `ops`. Validator harnesses scaffolded from R7.D1 alone (without R8) MUST treat `anomaly_library_signer` as an unrecognized role and reject — the extension is additive, not a relaxation, and absence of the extension is a pre-integration blocker (see §"Pre-Integration Blockers" below).

**Threshold high-water-mark enforcement**: Router MUST track per-pattern_id high-water-mark of threshold strictness (smaller threshold = stricter; shorter window = stricter). A new library version that relaxes any pattern's threshold below its high-water-mark REJECTS with `reject_code = pattern-library-relaxation-without-exception` UNLESS accompanied by a `PatternRelaxationException` co-signed by ceremony_quorum per §2.2. Tightening (lowering threshold, shortening window) is always accepted; loosening requires ceremony_quorum regardless of whether the new value meets the spec's MINIMUM floor.

A v3-conformant deployment MUST enforce a library covering at least these ten MINIMUM patterns:

| pattern_id | window | threshold | scope | action |
|---|---:|---:|---|---|
| `delete-storm` | 60s | 5 | `(verb=delete, resource_kind, mandate_id)` | auto-revoke |
| `iam-attach-policy-storm` | 30s | 3 | IAM Attach* verbs, same mandate | auto-revoke |
| `vault-rotate-storm` | 300s | 5 | `(verb=rotate, resource_kind=secret, mandate_id)` | auto-revoke |
| `git-force-push-storm` | 60s | 3 | protected branches, same mandate | auto-revoke |
| `fanout-distinct-resources` | 60s | 10 distinct refs | same `(verb, mandate_id)` | auto-revoke |
| `cross-tier-escalation` | 300s | 1 sequence | T0→T2+→T3+ overlapping scope, same mandate OR operator | auto-revoke |
| `canary-window-second-tier3` | Tariff-declared, default 600s | 2 (second observation) | any mandate under same Signer PCR set | auto-revoke |
| `unusual-delegation-depth` | — | chain_depth > 3 | any mandate | auto-revoke (fires at depth 4, hard cap is 4 per R7.D3) |
| `machine-pace` | 1s | 10 | `tier ≥ 1 AND verb ∉ read_only_verbs`, same mandate | auto-revoke |
| `long-silence-before-burst` | 300s burst | 20 | silent ≥ 604800s then burst | auto-revoke |

Operators MAY tighten (lower N, shorter window); loosening requires `PatternRelaxationException` co-signed by ceremony_quorum, itself audit-logged.

**Rationale**: Sigma rules (versioned YAML with signed provenance) — industry-standard detection-content model. fail2ban ships authoritative defaults with overrides. AWS GuardDuty built-in finding types cannot be disabled without audited suppression. MITRE D3FEND D3-AE treats detection content as attacker-TTP-derived, evolving. ADVISORY rejected — defeats §3.5. NORMATIVE-fixed rejected — legitimate load profiles vary.

**Spec patch (§3.5.1)**: As stated; Router rejects library revision with `library_version ≤ current_pinned` with `reject_code = pattern-library-version-too-old` (new code, distinct from Tariff's `version-too-old` to discriminate artifact types in audit logs).

**Vector impact**: All 32 arep-xxx vectors use thresholds within MINIMUM table; no flips. `machine-pace` refinement "`verb ∉ read_only_verbs`" explicitly preserves arep-029/arep-031 (false-positive avoidance vectors).

**Strength impact**: STRENGTHEN.

### R8.A2: Detector output semantics — severity-gated auto-revoke with deadman escalation

**Question**: Auto-revoke (strict) vs alert-with-SLA (lenient)?

**Answer (normative)**: **Hybrid — severity-gated.** Each PatternEntry declares `action ∈ {alert, auto-revoke}` and `severity ∈ {low, medium, high, critical}`:
- `severity ∈ {high, critical}` MUST have `action = auto-revoke`. Revocation push SLA: 5s default, max 30s. Emit `AnomalyDetected` audit event.
- `severity ∈ {low, medium}` MAY have `action = alert`. Operator response SLA: **300s**; on SLA elapse without acknowledgment or `AnomalyFalsePositiveDeclaration`, auto-escalate to revocation and emit `AnomalyAlertEscalatedToRevoke`.

False-positive governance:
1. Auto-revoked mandates restored via `AnomalyFalsePositiveDeclaration` co-signed by ceremony_quorum (§2.2), logged to audit.
2. ≥ 3 FP declarations per `(pattern_id, match_scope)` in 30-day rolling window emits `PatternTuningRecommended` high-severity event.
3. Single detector firing revokes at most one `mandate_id` or one `operator_id`'s mandates; cross-customer revocation requires ceremony_quorum.
4. During revocation-channel grace period (§8.4), detector continues to emit events for queued delivery.

**Rationale**: AWS GuardDuty severity-tiered auto-remediation is industry norm. fail2ban enforces ban first, review after. SRE alert-fatigue postmortems (Google SRE Workbook Ch. 5) show alert-only detectors fail without deadman switches. Pure alert-only rejected — disarms §3.5. Pure auto-revoke rejected — false-positive availability risk with no operator review.

**Spec patch (§3.5.2–§3.5.4)**: As stated. Existing reject code `aggregation-pattern-detected` extended with structured detail `{pattern_id, library_version, severity, firing_rule}` in audit event payload.

**Vector impact**: No outcome flips. All 28 positive arep-xxx vectors are `severity ∈ {high, critical}`, auto-revoke. `arep-019` is annotated `medium` — Phase B adds alert-path variant.

**Strength impact**: STRENGTHEN.

### R8.A3: Firing rule — per-class with companion pairing

**Question**: First-match vs N-consecutive? Attackers can walk under N-consecutive.

**Answer (normative)**: Each PatternEntry declares `firing_rule ∈ {first-match, sequence-match, cumulative-over-baseline}`. **"N-consecutive" is NEVER a valid firing rule.** Three modes:

| firing_rule | Semantics | Applicable pattern classes |
|---|---|---|
| `first-match` | Fire on first event whose addition crosses threshold in sliding window. | delete-storm, iam-attach-policy-storm, vault-rotate-storm, git-force-push-storm, fanout, machine-pace |
| `sequence-match` | Fire on completion of declared ordered event-class sequence within window. | cross-tier-escalation, dwell-then-strike, canary-window-second-tier3, long-silence-before-burst |
| `cumulative-over-baseline` | Fire when rolling-window count ≥ threshold at ANY evaluation (every 60s + on event arrival). | slow-burn-*, spread-across-mandates |

**Anti-walk-under property (normative)**: Every `first-match` pattern with `window ≤ 3600s` MUST declare `firing_rule_companions: [pattern_id]` naming ≥ 1 `cumulative-over-baseline` pattern with window ≥ 10× this window. Libraries with orphaned short-window patterns emit `PatternLibraryIncomplete` startup warning and refuse production load.

**Rationale**: fail2ban `findtime`/`maxretry` = precisely first-match on sliding count window — industry precedent. Sigma correlation types (`event_count`, `temporal`, `temporal_ordered`) map to the three modes. "N-consecutive" is the attack-window the question flags; making it impossible in the schema closes the concern structurally.

**Spec patch (§3.5.1.2 – §3.5.1.3)**: As stated.

**Vector impact**: All 28 positive vectors implicitly map to one of three modes; R8.A3 ratifies. No flips. Phase B: 3–5 walk-under test vectors.

**Strength impact**: STRENGTHEN.

### R8.A4: `Tariff.operating_hours` schema extension

**Question**: Extend schema, fold into pattern, or delete vector?

**Answer (normative)**: **Extend §2.2 schema.** Add optional `operating_hours`:

```cbor
operating_hours = {
  "timezone":           tstr,              // IANA zone name REQUIRED (not numeric offset)
  "windows":            [OpHoursWindow],   // SET-typed per R7.C6
  "default_action":     "allow" | "escalate-one-tier" | "require-step-up" | "reject",
  "applies_to_tiers":   [uint],
  "exempt_mandate_ids": [tstr]
}
OpHoursWindow = {
  "day_of_week": uint,   // 0=Mon..6=Sun (ISO 8601)
  "start_minute": uint,  // 0..1439
  "end_minute": uint,    // 0..1440 (1440 = end of day)
  "label": tstr          // optional
}
```

Invalid configs REJECT at Tariff publication:
- `timezone` not IANA name → `tariff-invalid-timezone`
- Windows same day_of_week overlap → `operating-hours-overlap`
- `end_minute ≤ start_minute` → `operating-hours-window-inverted`
- `day_of_week > 6` → `operating-hours-day-invalid`

Companion pattern `operating-hours-violation` in library: `firing_rule = first-match`, `threshold = 1`, `severity = high` (unless `default_action` relaxes), `action = auto-revoke`. Windows do NOT cross midnight — customer expresses "Mon 22:00 → Tue 06:00" as two windows. Router MUST bundle IANA tzdata release ID in startup attestation; tzdata > 180 days stale emits `TzdataStale` warning.

**Rationale**: NIST SP 800-53 reproducibility requires named zones. IANA names carry DST rules; numeric offsets silently shift. Option (b) rejected — pattern library = rules, Tariff = config; separation mirrors Sigma/OPA best practice. Option (c) rejected — out-of-hours destructive action is top-10 MITRE ATT&CK "unusual time of activity" indicator.

**Spec patch (§2.2.1)**: As stated. Integration pass MUST extend the R7.C6 §4.2.1 SET-field enumeration to include `operating_hours.windows` — set-membership by tuple `(day_of_week, start_minute, end_minute)` byte-compare; `label` is informational and not part of the membership key. Overlap detection (`operating-hours-overlap`) operates over the structural tuple independent of labels.

**Vector impact**: `arep-025` schema-migrate to structured form (no semantic flip). `arep-032` re-express via `exempt_mandate_ids`. Phase B: 3 new tariff-reject vectors for new codes.

**Strength impact**: STRENGTHEN.

---

## Cluster 3 — Tariff Structural Limits (§2.2)

Five tightenings resolve `conformance/tariff-reject.json` notes.

### R8.T1: Maximum Tariff byte size

**Question**: §2.2 silent; suite uses 1 MiB default.

**Answer (normative)**: **MUST cap 262144 bytes (256 KiB)** on COSE_Sign1 outer envelope including signature. Exceeding REJECTS with `tariff-oversize` BEFORE signature verification. Not operator-configurable.

**Rationale**: Prior-art anchors:
- AWS IAM managed policy: 6 KiB hard cap.
- JWT practical: 8–16 KiB (nginx `large_client_header_buffers 4 8k`).
- X.509 typical: 1–4 KiB; EV with SCTs ~16 KiB.
- TLS handshake message (RFC 8446): 16 KiB max.
- CBOR + COSE is 20–40% denser than equivalent JSON.

256 KiB provides 4–8× growth headroom over realistic Tariff content (~32–64 KiB). Remains in L2 cache. 256 KiB × 1000 RPS parse throughput achievable on commodity. Customers needing larger policy sets MUST split into per-integration Tariffs (§10.2 supports).

**Spec patch (§2.2)**: Router MUST check size before COSE signature verification to prevent verification-DoS on oversized payloads.

**Vector impact**: `trej-059` update `policy_max_tariff_bytes: 1048576` → `262144` (outcome unchanged). Phase B: boundary at 262144 exact (accept) and 262145 (reject).

**Strength impact**: STRENGTHEN.

### R8.T2: Maximum `iat` → `not_before` gap

**Question**: Pre-issued dormant Tariff window?

**Answer (normative)**: **MUST cap 2592000s (30 days).** `(not_before - iat) > 30d` → `tariff-iat-nbf-gap-excessive`. `iat > not_before` → `tariff-iat-after-nbf`. `iat > current_time + clock_skew_tolerance` → `clock-skew-exceeded`.

**Rationale**: Closes R2-TARIFF-SIGNING-KEY-COMPROMISE dormant-replay: a compromised `K_tariff_signer` could pre-sign a distant-future Tariff, stash it, play it after key rotation. 30d = 4× the 7-day rotation cadence of `K_tariff_signer` (§7.5). RFC 7519 leaves `iat`→`nbf` unbounded; production JWT deployments (Auth0, Okta) typically flag > 24h. CA/Browser Forum BR §6.3.2 requires issuance-to-activation = 0 for standard end-entity certs.

**Spec patch (§2.2)**: Customers requiring > 30d scheduled rollout sign fresh Tariff within 30d of intended `not_before`.

**Companion key-epoch cap (addresses R8 review finding Sec-N2)**: Each Tariff MUST embed `key_epoch: uint` identifying the `K_tariff_signer` rotation epoch under which it was signed. Router MUST track the consumed-epoch ledger per `(customer_id, key_epoch)`: at most 2 Tariffs share any single epoch. Third Tariff → `tariff-key-epoch-cap-exceeded`. Any Tariff with `not_before > current_time + 604800s` (7d) MUST carry a `ceremony_quorum` co-signature block per §2.2; absence → `tariff-future-dated-requires-ceremony-quorum`. This closes the chained-pre-signed-Tariffs primitive: a single `K_tariff_signer` compromise during a rotation window could otherwise emit a sequence of dormant Tariffs that activate post-rotation. Pairing epoch-cap (2) with ceremony-quorum-for-future-dating (>7d) bounds attack exposure per compromise event at 2 Tariffs × 7d future-window = 14d worst case.

**Vector impact**: `trej-023` reject_code FLIP `tariff-malformed` → `tariff-iat-nbf-gap-excessive`. Phase B: boundary vectors; 2 key-epoch-cap vectors (accept on 2nd, reject on 3rd share); 2 future-dated vectors (accept with ceremony-quorum co-sig, reject without).

**Strength impact**: STRENGTHEN.

### R8.T3: Maximum Tariff validity period

**Question**: Max `(exp - not_before)`?

**Answer (normative)**: **MUST cap 2592000s (30 days).** `(exp - not_before) > 30d` → `tariff-validity-period-excessive`. `exp ≤ not_before` → `tariff-validity-window-empty`. Not operator-configurable. Customers requiring uninterrupted coverage MUST overlap Tariffs.

**Rationale**: Bounds silent-signer-compromise blast radius at 30d of authoritative wrong-policy emission. Aligns CA/Browser Forum trajectory (TLS certs 398d; Apple proposed 47d by 2028). SPIFFE JWT-SVID TTL 1h; X.509-SVID 1d. OCSP `nextUpdate` 4–10d. Matches `K_tariff_signer` 7d rotation × 4. Combined with R8.T2, total iat→exp ≤ 60d.

**Spec patch (§2.2)**: As stated.

**Vector impact**: `trej-062` ratified.

**Strength impact**: STRENGTHEN.

### R8.T4: Unknown top-level fields

**Question**: Strict, lenient-warn, or `extensions` allowlist?

**Answer (normative)**: **STRICT.** Top-level Tariff field set is closed enumeration per §2.2. Unknown keys → `tariff-unknown-field`. Applies recursively (unknown key in nested structure same code). No `extensions` map. Schema evolution via `version` integer only; unsupported version → `tariff-version-unsupported` (distinct code).

**Rationale**: Three converging authorities:
1. RFC 8949 §4.2 Core Deterministic Encoding: duplicate keys forbidden. Strict-unknown extends the posture to schema layer.
2. RFC 9052 COSE §3: unrecognized critical headers MUST cause rejection. Tariff has no critical/non-critical distinction, so safe default is treat-all-as-critical.
3. RFC 5280 §4.2 critical-extension semantics: policy-bearing extensions always critical specifically because attacker could hide authorization semantics in unrecognized fields.

"Lenient-warn" creates split-brain vulnerability (Router accepts with partial enforcement, auditor may have different rules — V2-2 asymmetry extended to Tariff layer). "Extensions map" creates same problem at narrower surface.

**Spec patch (§2.2)**: As stated.

**Vector impact**: `trej-030` reject_code FLIP `tariff-malformed` → `tariff-unknown-field`. Phase B: 2 coverage vectors (top-level unknown, nested unknown).

**Strength impact**: STRENGTHEN.

### R8.T5: Unknown integration_ref

**Question**: Reject or ignore-and-accept?

**Answer (normative)**: **MUST REJECT** with `tariff-integration-unknown`. Applies to `integration_ref` top-level, `minimum_tiers` keys, `rate_matrix` keys, any nested integration-scoped position. Router MUST NOT log-and-accept.

**Rationale**: "Resilient during rollout" is preamble to exploitation, not defense. Rollout is mechanically solvable by ordering (catalog update before Tariff update). Ambiguity (typo `k8s-prod-typ` vs `k8s-prod`) is only closeable. Prior art: RFC 5280 §4.2.1.4 (unrecognized cert policy OID fails validation); OAuth 2.0 RFC 6749 (unknown scopes MUST NOT be silently granted); SPIFFE Federation (unknown trust domain fails federation). "Ignore-and-accept" hides Routers-needing-update from health checks — silent-failure mode.

**Spec patch (§2.2)**: Catalog rollout ordering: integration-catalog → Tariff. Failed ordering manifests as `tariff-integration-unknown` on un-updated Routers, surfacing via fleet health check.

**Vector impact**: `trej-041` ratified. `trej-042` (empty string) Phase B refinement: distinct `tariff-integration-ref-malformed`.

**Strength impact**: STRENGTHEN.

---

## Cluster 4 — Fuzz-Baseline Tier Assignments (§4.4)

Eight tightenings resolve OQ-1..OQ-8 in `conformance/fuzz-baseline.json` notes.

### R8.F1: fieldSelector on nodeName

**Question**: Tier 0 metadata read or Tier 1 reconnaissance?

**Answer (normative)**: **Tier 0 baseline + rate-triggered escalation.** Single read Tier 0 (K8s RBAC treats `list pods` uniformly, no sub-selector discrimination). When ≥ 5 `list` operations on same `resource_kind` with varying selector field values in 120s, classifier emits `justification_tag = reconnaissance-pattern-detected` and returns Tier 1. Applies to K8s `spec.nodeName`/`metadata.ownerReferences.uid`/`spec.serviceAccountName`, Vault variable-prefix paths, cloud-provider resource-lister filters. Router-side rate-limit 100 list-ops/mandate/hour.

**Rationale**: K8s RBAC authorizes `list pods` without selector discrimination — classifier must not invent authorization distinctions the target doesn't enforce (V2-2 asymmetry risk). But enumerating `spec.nodeName` is MITRE ATT&CK T1526 / k8s threat matrix "node discovery." Rate-limit aggregation matches Falco/Tetragon audit-analysis semantics (per-rate, not per-request).

**Spec patch (§4.4 sensitive-path/aggregation)**: As stated.

**Vector impact**: `fuzz-010` stays Tier 0. Phase B: new vector 5× `list pods --field-selector spec.nodeName=<varying>` → Tier 1.

**Strength impact**: STRENGTHEN.

### R8.F2: `prod/*` secret read and bump composition

**Question**: Tier 2 or Tier 3? Do bumps compose or absorb?

**Answer (normative)**: **Tier 2** on single read (suite default ratified). **Bumps compose additively, capped at Tier 5**: `final_tier = min(5, floor + Σ bumps)`. Bumps are mutually independent:

- `sensitive-path` (+1): `sensitive_path_patterns` default `{prod/*, root/*, admin/*, ceremony/*}`
- `aggregation` (+1): §3.3 threshold met (R8.F3)
- `canary-window` (+1): applies iff pre-bump tier ≥ 3 (R8.F5)
- `target-invariants-missing` (+1): `target_invariants_documented = false` on Tier 3+
- `resource-state` (+1): snapshot contains escalation trigger

`justification_tag` lists every bump applied, space-separated.

**Rationale**: Vault ACL semantics treat path prefixes as access-control primitive; `secret/prod/*` is HashiCorp Reference Architecture §4 convention. Tier 3 default would force step-up on every routine prod read (thousands/day in typical prod fleet). Composition additivity: compromised mandate reading `prod/*` during canary with recent aggregation is substantively more dangerous than any single factor; absorbing flattens the signal. NIST SP 800-53 CM-3 change-magnitude supports cumulative over max-take. Cap at Tier 5 = spec ceiling.

**Spec patch (§4.4)**: As stated.

**Vector impact**: `fuzz-079`/`fuzz-080` Tier 2 stays. Phase B composition vector: sensitive-path + aggregation → Tier 3 (1 + 2 bumps).

**Strength impact**: STRENGTHEN.

**Residual operator-friction flag**: Composition on routine prod reads during canary windows is the largest friction surface. Canary-bump precondition (pre-bump tier ≥ 3 from R8.F5) partly contains this. Recommend Phase B instrumentation surfacing composition-above-Tier-3 rates with 30-day review.

### R8.F3: Aggregation window default

**Question**: 60s / 300s / 900s?

**Answer (normative)**: **300s** default, Tariff-configurable in `[60, 900]`. Window measured `[now - window_seconds, now]`; actions at exactly `t_offset = -window_seconds` INCLUDED (closed-below). Classifier MUST drop actions older than window to bound memory.

**Rationale**: 300s aligns K8s SIG-Architecture `--pod-eviction-timeout` default (5 min) and SRE Workbook §14 runbook-action latency band (2–10 min). 60s misses slow-drip attacker at 1-delete/70s. 900s catches legitimate shift-change cleanups → false positives. Falco `k8s_audit_rules.yaml` uses 300s for `K8s Delete Pod` aggregations.

Distinct from R8.A1 (which governs revocation-fire threshold); R8.F3 governs mid-stream tier bump.

**Spec patch (§4.4 / §3.3)**: As stated.

**Vector impact**: `fuzz-048` stays Tier 4. Phase B: boundary at exactly t=-300 (include/Tier 4) vs t=-301 (exclude/Tier 3).

**Strength impact**: STRENGTHEN.

### R8.F4: `kubectl drain <node>`

**Question**: Uniform Tier 3/4 or workload-aware?

**Answer (normative)**: **Tier 3 floor uniformly.** Workload-awareness via `resource_state_snapshot` bumps:
- `has_stateful_pods = true` → +1 (Tier 4)
- `pdb_violation_imminent = true` → +1
- `is_control_plane_node = true` → +2 (Tier 5)

Missing snapshot on Tier 3+ drain triggers `target-invariants-missing` bump. Classifier MUST NOT query K8s API (hermetic principle); Router populates snapshot at intent-creation.

**Rationale**: Stateless drain is routine (kured-pattern), dozens/week in prod — Tier 4 default creates step-up fatigue (V3-2 concern). Stateful drain is genuinely higher-impact (PV reattach, quorum loss). Classifier-hermeticity: live K8s API query breaks (a) enclave-verifiability, (b) TOCTOU, (c) latency coupling. Router-populates-snapshot matches §4.3 contract.

**Spec patch (§4.4)**: As stated.

**Vector impact**: `fuzz-029` Tier 3 stays. `fuzz-199` Tier 4 stays. Phase B: control-plane drain → Tier 5.

**Strength impact**: STRENGTHEN.

### R8.F5: Canary-window bump shape

**Question**: Uniform / per-tier curve / per-integration?

**Answer (normative)**: **+1 uniform, with sensitive-path carve-out:**
- Pre-bump tier ≥ 3: canary-bump +1 applied (default canary posture).
- Pre-bump tier = 2 AND any `sensitive-path` bump already applied: canary-bump +1 applied (closes canary-dead-zone for Tier 2 `prod/*` secret reads and sensitive-repo `git:push:default_branch`).
- Pre-bump tier = 2 without sensitive-path bump: no canary bump (routine reads/writes remain frictionless).
- Pre-bump tier ≤ 1: no canary bump.
- Cap at Tier 5. Per-integration variance non-conformant.

Companion pattern in R8.A1 library: `canary-window-sensitive-path-repeat` (firing_rule=first-match, severity=high, action=auto-revoke) fires on ≥ 3 distinct sensitive-path Tier 2 actions in a canary window.

**Rationale**: CNCF Argo Rollouts and Flagger apply uniform-step confidence degradation. Pure pre-bump ≥ 3 threshold creates a Tier 2 dead-zone: `prod/*` secret reads during canary receive zero canary friction — exactly the combination R8.F2 flags as substantively more dangerous. Sensitive-path carve-out preserves routine-read frictionlessness while closing exfiltration path. (Addresses R8 review finding Sec-N1.)

**Spec patch (§4.4)**: As stated; `justification_tag += " canary-window-escalation"` whenever the canary bump fires.

**Vector impact**: `fuzz-191..195` all stay. Phase B: sensitive-path + canary at pre-bump Tier 2 → Tier 3 (validates carve-out).

**Strength impact**: STRENGTHEN (flipped from NEUTRAL post-review).

### R8.F6: git push to default branch when default ≠ main

**Question**: Tier 2? Rename-during-session handling?

**Answer (normative)**: **Tier 2 bound to `integration_config.default_branch` frozen at Tariff-issuance.** Classifier consults the pinned value regardless of literal branch name (`main`, `master`, `trunk`, `develop`, `release/current` all apply). Rename on hosting provider MUST NOT take effect until next Tariff refresh (prevents mid-session rename-escape).

**Rationale**: GitHub/GitLab/Bitbucket/Gitea all expose `default_branch` via API as the authoritative semantic. Hardcoding `main` misses ~15–20% of production repos. Mid-session rename: pinning prevents TOCTOU (attacker proposes rename, proposes push; classifier sees post-state, Router sees pre-state — V2-2 asymmetry). SLSA framework level 3 requires protected default-branch; cannot collapse default-branch-push to generic Tier 1.

**Spec patch (§4.4 / §2.2 minimum_tiers)**: `git:push:default_branch` Tier 2 (frozen default). `git:push:protected_branch` Tier 2 (from `integration_config.protected_branches`). `git:push:branch` Tier 1.

**Vector impact**: `fuzz-141` Tier 2 stays. Phase B: decoupling vector (push to `main` when default=develop → Tier 1), rename-race vector.

**Strength impact**: STRENGTHEN.

### R8.F7: DNS apex A-record rewrite

**Question**: TTL-conditional or uniform Tier 4?

**Answer (normative)**: **Uniform Tier 4.** TTL-conditional tiering REJECTED. Applies to apex records of types A, AAAA, CNAME, MX, NS, or TXT containing SPF/DKIM/DMARC. TTL value in intent informational, MUST NOT alter tier. `dns:update:ns` at any level Tier 4. Subdomain A/AAAA remain Tier 3.

**Rationale**: RFC 1912 §2.2 warns TTL is advisory, not enforceable — resolvers commonly ignore low TTLs during reload storms, exceed them during outages (RFC 8767 explicitly permits serving-stale). TTL is attacker-controllable (mandate issuing the rewrite controls the TTL field) — classifier MUST NOT depend on unverifiable external state (principle 3). NIST SP 800-81-2 classifies apex modification as CAT-1 high-impact. Unlike wildcard certs (R8.F8) there is no universal passive-DNS public log — no post-hoc detection path analogous to CT.

**Spec patch (§4.4)**: As stated.

**Vector impact**: `fuzz-151`, `fuzz-152` Tier 4 stay. Phase B: attempted apex update with `ttl=30` → still Tier 4.

**Strength impact**: STRENGTHEN.

### R8.F8: ACME wildcard cert issuance

**Question**: Tier 3 (CT-mitigated) or Tier 4 (mass-MitM)?

**Answer (normative)**: **Tier 3 floor conditional on CT-compliant CA.** `acme:issue_wildcard:certificate` floor is Tier 3 iff CA appears in `integration_config.acme.ct_compliant_cas` (Tariff-frozen allowlist, default: Let's Encrypt, ZeroSSL, Buypass, Google Trust Services, DigiCert, Sectigo). Non-CT-compliant CA → Tier 4. `acme:revoke:certificate` Tier 3 (fast revocation mitigates).

Classifier MUST NOT perform live CT log checks; relies on frozen allowlist.

**Rationale**: ACME RFC 8555 §7.1.3 + DNS-01 validation acknowledges blast radius. But RFC 9162 CT + Chrome/Apple/Mozilla CT policies + `crt.sh`/`censys.io`/CT-monitor APIs provide minutes-to-hours post-hoc detection. Standard SRE/SecOps CT-monitoring practice (CIS Benchmark, NIST SP 800-52) catches issuance. Composite exposure = issuance detection + OCSP/CRL revocation minutes-to-hours, vs DNS rewrites with hour-to-day TTL cache lifetime (no analogous log). Tier 3 + bumps still escalates to Tier 4 in risky contexts (canary, sensitive-path).

**Spec patch (§4.4 / §2.2 minimum_tiers acme)**: As stated.

**Vector impact**: `fuzz-154` Tier 3 stays. Phase B: non-CT-CA wildcard → Tier 4. Wildcard during canary → Tier 4 (composition per R8.F5).

**Strength impact**: STRENGTHEN.

---

## Consolidated summary matrix

| ID | Cluster | Decision | Strength |
|---|---|---|---|
| R8.P1 | PCR | Tariff-pinned `expected_pcrs` map; default `{PCR0, PCR4, PCR8}` | STRENGTHEN |
| R8.P2 | PCR | STH age: required Tariff field, default 86400s, ceiling 604800s | STRENGTHEN |
| R8.P3 | PCR | `trusted_transparency_logs` object array with pubkey+alg+optional validity window | STRENGTHEN |
| R8.P4 | PCR | Mandatory 128-bit nonce with consistency check across attestors, TTL 300s | STRENGTHEN |
| R8.P5 | PCR | Bundle size `[4KiB, 1MiB]`, default 256 KiB, measure-before-decode | STRENGTHEN |
| R8.P6 | PCR | Witness cosignatures Tier 4+ MUST ≥2-of-3 multi-provider | STRENGTHEN |
| R8.A1 | Anomaly | `AnomalyPatternLibrary` COSE_Sign1 artifact, 10 MINIMUM patterns, tightening-only semantics | STRENGTHEN |
| R8.A2 | Anomaly | Severity-gated: high/critical auto-revoke 5s SLA; low/medium alert 300s deadman | STRENGTHEN |
| R8.A3 | Anomaly | `firing_rule ∈ {first-match, sequence-match, cumulative-over-baseline}`; short+long companion pairing mandatory | STRENGTHEN |
| R8.A4 | Anomaly | `Tariff.operating_hours` schema extension, IANA zones, non-wrap windows, exempt list | STRENGTHEN |
| R8.T1 | Tariff | Tariff size ≤ 262144 bytes (256 KiB), check before signature verify | STRENGTHEN |
| R8.T2 | Tariff | `iat`→`not_before` gap ≤ 30d | STRENGTHEN |
| R8.T3 | Tariff | Validity `(exp - not_before)` ≤ 30d | STRENGTHEN |
| R8.T4 | Tariff | Strict-reject unknown top-level fields `tariff-unknown-field`; no extensions map | STRENGTHEN |
| R8.T5 | Tariff | Reject unknown `integration_ref` with `tariff-integration-unknown` | STRENGTHEN |
| R8.F1 | Fuzz | fieldSelector: Tier 0 + rate-triggered reconnaissance to Tier 1 | STRENGTHEN |
| R8.F2 | Fuzz | `prod/*` Tier 2; bumps add, cap 5, explicit composition | STRENGTHEN |
| R8.F3 | Fuzz | Aggregation window 300s default, closed-below | STRENGTHEN |
| R8.F4 | Fuzz | Drain Tier 3 floor, state-snapshot bumps to Tier 4/5 | STRENGTHEN |
| R8.F5 | Fuzz | Canary +1 on pre-bump tier ≥ 3, plus sensitive-path carve-out at pre-bump Tier 2 | STRENGTHEN |
| R8.F6 | Fuzz | Default branch Tier 2 frozen-at-issuance | STRENGTHEN |
| R8.F7 | Fuzz | DNS apex uniform Tier 4, TTL ignored | STRENGTHEN |
| R8.F8 | Fuzz | Wildcard Tier 3 iff CT-compliant CA, Tier 4 otherwise | STRENGTHEN |

**Total**: 23 STRENGTHEN, 0 NEUTRAL, 0 WEAKEN.

---

## New reject codes introduced

**PCR cluster (18)**: `tariff-pcr-expected-empty`, `pcr-expected-missing-in-bundle`, `pcr-bundle-malformed`, `tariff-pcr-sth-age-unset`, `tariff-pcr-sth-age-too-lax`, `tariff-pcr-sth-age-invalid`, `tariff-pcr-trusted-logs-empty`, `tariff-pcr-trusted-logs-duplicate`, `tariff-pcr-trusted-log-alg-unsupported`, `pcr-attestation-nonce-missing`, `pcr-attestation-nonce-inconsistent`, `pcr-attestation-nonce-reuse`, `tariff-pcr-bundle-max-size-too-strict`, `tariff-pcr-bundle-max-size-too-lax`, `pcr-attestation-witness-cosignature-missing`, `pcr-attestation-witness-cosignature-invalid`, `tariff-pcr-witnessing-insufficient-for-tier`, `tariff-pcr-witnessing-single-provider`.

**Anomaly cluster (7)**: `tariff-invalid-timezone`, `operating-hours-overlap`, `operating-hours-window-inverted`, `operating-hours-day-invalid`, `pattern-library-version-too-old`, `pattern-library-signer-role-violation`, `pattern-library-relaxation-without-exception`. (Reuses `aggregation-pattern-detected` with structured detail.)

**Tariff cluster (7)**: `tariff-iat-nbf-gap-excessive`, `tariff-iat-after-nbf`, `tariff-validity-window-empty`, `tariff-validity-period-excessive`, `tariff-unknown-field`, `tariff-key-epoch-cap-exceeded`, `tariff-future-dated-requires-ceremony-quorum`. (Reuses `tariff-oversize`, `tariff-integration-unknown`, `clock-skew-exceeded`, `tariff-version-unsupported`.)

**Fuzz cluster (0)**: No new reject codes; tier decisions via `justification_tag` strings and existing escalation paths.

**Total: 32 new reject codes.**

---

## Vector impact summary

**Outcome flips**: **0** across all four clusters.
**Reject-code flips** (outcome correct, code flipped for specificity): **3** total.
- `pcrrej-045`: `pcr-attestation-transparency-invalid` → `pcr-attestation-witness-cosignature-missing` (R8.P6).
- `trej-023`: `tariff-malformed` → `tariff-iat-nbf-gap-excessive` (R8.T2).
- `trej-030`: `tariff-malformed` → `tariff-unknown-field` (R8.T4).

**Schema migrations** (mechanical, Phase B): 3.
- `pcrrej-023`: `trusted_transparency_logs` from string-array to object-array (R8.P3).
- `arep-025`: `operating_hours` from ad-hoc to normative schema (R8.A4).
- `arep-032`: re-express via `exempt_mandate_ids` (R8.A4).

**Coverage-summary count updates**: triggered by 3 reject-code flips + policy cap update in `trej-059`.

**New Phase B boundary vectors flagged**: ~34 across all clusters (adds 4 for R8.T2 key-epoch-cap + future-dated ceremony-quorum coverage; see per-section details).

---

## Phase B entry status (revised after R8)

Before R8, the Phase A → Phase B gate listed 38 open spec questions deferred. R7 resolved 15 bounded ones. R8 resolves the 23 operationally-dependent remainder.

**Current state**: All 38 original Phase A spec-ambiguity questions have normative resolutions in R7 or R8. The conformance suite's 515 vectors plus ~65 Phase B boundary additions define the full spec-executable behavior.

**Phase B entry criteria satisfied via Path 1 (architect-resolution) — CONDITIONAL** per the conformance-plan.md decision tree. The reference validator harness can be scaffolded against `design-final.md` + R7 delta + R8 delta as the authoritative three-document spec set, PROVIDED the Pre-Integration Blockers B-1 through B-4 (below) are tracked and resolved before harness scaffolding treats R8-dependent behaviors as authoritative. Until integration, R8-dependent behaviors that collide with R6/R7 baselines (e.g., `K_tariff_signer` vs. `K_cust_ops` Tariff signer) MUST be conservatively rejected.

**Integration path for design-final.md**: R7 + R8 deltas together propose ~50 spec patches across §2.2, §3.3, §3.5, §4.2, §4.4, §7.1–§7.4, §9.3–§9.4, §11. Integration is a separate session (produces `design-final-round8.md` or `design-final-v2.md`). This delta document + the R7 delta + `design-final.md` form the authoritative three-document spec set until integration.

**Residual operator-feedback flags** (before external audit):
1. **R8.P6 Tier 4 witness-cosignature minimum (2-of-3 multi-provider)** — witness supply-side still consolidating in 2026; recommend Nitro-operator feedback round or phased rollout (1-of-1 → 2-of-3 between 2026 and 2027).
2. **R8.F2 sensitive-path + canary composition on routine prod reads** — largest operator-friction surface. Recommend Phase B instrumentation + 30-day review window.
3. **R8.T2 `key_epoch` is an operator-declared Tariff payload field** (Sec-N4): `key_epoch: uint` is written by the Tariff signer into the signed payload. An attacker with K_tariff_signer can choose arbitrary values, making the 2-Tariff-per-epoch ledger a soft-defense only. Integration pass SHOULD derive `key_epoch` from the signed delegation document (R7.D1 issuance time) or from the COSE `kid` structure rather than from the Tariff payload itself. Until derived, the cap is pseudo-protection against drift, not against key compromise.
4. **R8.F2/F6 canary dead-zone for Git branch operations** (Sec-N5): the default `sensitive_path_patterns` (`prod/*, root/*, admin/*, ceremony/*`) do not cover Git refs like `refs/heads/main` or `refs/heads/master`. An attacker targeting `git:push:default_branch` at pre-bump Tier 2 slips under the sensitive-path carve-out. Operators MUST extend `sensitive_path_patterns` with Git protected-branch globs (e.g., `refs/heads/main`, `refs/heads/master`, `refs/heads/release/*`). Phase B SHOULD ship a minimum recommended `sensitive_path_patterns` set with Git coverage.
5. **R8.A1 role-hierarchy revocation propagation undefined** (Sec-N6): when K_cust_root revokes a K_cust_ops delegation, propagation to all K_cust_anomaly_library_signer children is undefined. §7.2 revocation semantics (R7.D1 chain walk) do not specify cascade depth for the anomaly library signer. Integration pass MUST clarify whether K_cust_ops revocation implicitly revokes all downstream signers or requires explicit per-child revocation. Operational default during this window: explicit per-child revocation (conservative).
6. **R8.A1 HWM bootstrap attack surface** (Sec-N7): a fresh Router node has no pinned high-water-mark. The first AnomalyPatternLibrary it accepts becomes the HWM, so an attacker able to race a relaxed library into initial sync establishes a loose baseline. Router nodes MUST bootstrap with a fixed spec-embedded HWM (the MINIMUM table at §3.5.1) before accepting any library revision. Phase B vectors MUST cover bootstrap-HWM-enforcement against attacker-first-library scenarios.

---

## Pre-Integration Blockers

R8 extends R7 and design-final.md with normative tightenings that assume structural changes to the v3 specification. These changes are NOT self-applying from R8 alone; the forthcoming integration pass (producing `design-final-round8.md` or `design-final-v2.md`) MUST resolve the following blockers BEFORE R8 can be considered merged. Validator harnesses scaffolded from `design-final.md` + R7 alone (without R8) MUST either: (a) block integration until these are resolved, or (b) reject R8-dependent behaviors conservatively.

**Blocker B-1 — K_tariff_signer role and key_epoch concept absent from §7.1** (Arch-1):
- design-final.md §2.2 (line 50) states: "The Tariff is a COSE_Sign1 CBOR document signed by `K_cust_ops` (§7)." This is a direct `K_cust_ops → Tariff` signing path.
- design-final.md §7.1 enumerates key hierarchy as {`K_cust_root` (root), `K_cust_ops` (90-day), `K_cust_mandate_*` (7-day)}. No `K_tariff_signer` appears.
- R7.D1 §7.2 added `tariff_signer` to `child_role` enum but did NOT patch §7.1 key hierarchy nor §2.2 signing assignment.
- R8.T2 introduces `key_epoch: uint` with "2-Tariff-per-epoch" ledger and assumes Tariff signed by short-lived `K_tariff_signer` (7d rotation analogous to mandate keys). This grounding does not exist in R6/R7.
- **Required integration action**: design-final.md §2.2 MUST be amended to state Tariff is signed by `K_tariff_signer` (child of `K_cust_ops`, 7-day rotation), and §7.1 MUST be amended to add `K_tariff_signer` to the enumerated hierarchy with its rotation cadence. Alternative: redesign R8.T2 to derive `key_epoch` from `K_cust_ops` rotation boundaries (90-day) rather than 7-day `K_tariff_signer` rotations.
- Inherited from R7 (already implicit); surfaced explicitly by R8.T2's key_epoch mathematics.

**Blocker B-2 — `anomaly_library_signer` role absent from R7.D1 §7.2 child_role enum** (Arch-3, Rev-C4):
- R7.D1 §7.2 enumerates `child_role ∈ {"ops", "mandate_signer", "tariff_signer", "audit_signer"}`.
- R8.A1 introduces `K_cust_anomaly_library_signer` as a child role under `K_cust_ops`. Libraries signed by any other delegation key reject with `pattern-library-signer-role-violation`.
- A validator implementing R7.D1 strictly (without R8) will REJECT all AnomalyPatternLibrary signatures because the child role is unrecognized.
- **Required integration action**: Amend R7.D1 §7.2 `child_role` enum to add `"anomaly_library_signer"` with the chain constraints: valid parent = `ops`; terminal (no sub-delegation). Document in integration notes that this is an additive, non-breaking extension.

**Blocker B-3 — §3.3 spec-patch target ambiguity for aggregation-window semantics** (Arch-2):
- R8.F3 states: `**Spec patch (§4.4 / §3.3)**`. design-final.md §3.3 is titled "Layer 3 — Stateful classifier with history" and describes pattern-based escalation using `recent_actions` and `resource_state_snapshot`, with example "5× replica→0 in 60s".
- R8.F3 adds normative `aggregation_window_seconds` default 300s, Tariff-configurable range [60, 900], closed-below semantics. These extend §3.3's implicit window concept.
- §3.3 does not currently define window semantics normatively, so R8.F3 is not in conflict — but the patch should land in a new explicit sub-section (e.g., §3.3.1 "Aggregation window") rather than the free-form §3.3 prose to avoid silent conflict with other classifier-window assumptions.
- **Required integration action**: Integration pass MUST create §3.3.1 (or §4.4.1) as a dedicated sub-section carrying R8.F3's normative aggregation-window semantics, and cross-reference from §3.3 and §4.4. R8.F3's `§4.4 / §3.3` patch target is replaced with a specific new sub-section address.

**Blocker B-4 — R7.C6 SET-field enumeration closure conflict with R8 extensions** (Arch-4):
- R7.C6 §4.2.1 declares a closed enumeration of SET-typed fields. R8.A4 introduces `operating_hours.windows` as a SET. R8.P3/P6 introduce `trusted_transparency_logs` and `trusted_witnesses` as SETs.
- R8.A1, R8.P3, R8.P6 already contain integration notes stating "Integration pass MUST extend the R7.C6 §4.2.1 SET-field enumeration to include [field]". A Phase B validator harness that scaffolds from R7.C6 alone (without R8) will apply byte-compare post-NFC SET semantics only to R7-enumerated fields, silently not applying them to R8-introduced fields.
- **Required integration action**: R7.C6 §4.2.1 MUST be amended to add the four new SET fields: `operating_hours.windows`, `trusted_transparency_logs`, `trusted_witnesses`, `patterns` (from AnomalyPatternLibrary). Amendment is additive; no existing vectors change semantics.

**Resolution posture**: Blockers B-1 through B-4 are out of scope for R8 architectural-pass work. They are documented here as pre-commit-integration dependencies. R8's "Phase B entry via Path 1" claim is contingent on these blockers being tracked and resolved before reference validator harness scaffolding treats R8-dependent behaviors as authoritative. If the integration pass does NOT resolve a blocker, the corresponding R8 tightening reverts to its R6/R7 state (conservative degrade).

---

## What this document does NOT do

- Does not modify `design-final.md`. Integration = separate session.
- Does not execute conformance-vector changes. Flips/migrations flagged, not applied.
- Does not extend red-team attack inventory (Round 3 procedure cap).
- Does not commit to git.
- Does not resolve out-of-scope concerns: performance/resource limits, enclave attestation chain live-verification, target-API state invariants (§3.4 out-of-scope), timing side channels.

---

**End of Round 8 architect pass — 23 operational tightenings.**

Governing strength direction: **23 STRENGTHEN, 0 NEUTRAL, 0 WEAKEN.**
New reject codes: **32.**
Outcome flips: **0.**
Reject-code flips: **3.**
Schema migrations: **3.**
Phase B entry: **SATISFIED via Path 1 — CONDITIONAL on B-1 through B-4 resolution.**
