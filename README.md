# EPHEMERAL

Cross-organization agent-authority protocol and reference validator.

[![CI](https://github.com/ThePyth0nKid/empheral/actions/workflows/ci.yml/badge.svg)](https://github.com/ThePyth0nKid/empheral/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

---

## What this is

EPHEMERAL is a specification and reference implementation for authorising an
autonomous LLM-driven agent that a SaaS vendor runs on a customer's
infrastructure. The customer is the authority over what the agent is allowed to
do; the vendor operates the agent's software; neither side blindly trusts the
other. The spec is captured in [`design-final-v2.md`](design-final-v2.md)
(R7 + R8 integrated, 1112 lines); this repository additionally contains the
conformance test-vector corpus under [`conformance/`](conformance/) and the
reference Rust validator under [`reference/validator/`](reference/validator/).

The protocol is described in adversarial terms. It was developed across three
red-team rounds, two operational tightening rounds, and a skeptic pass — the
audit trail is part of the repository (see [Spec provenance](#spec-provenance)).
Content without a red-team marker was inherited from the consolidation in
`design-final.md`; everything normative from the later rounds is labelled
`(R7.Cn)`, `(R7.Dn)`, `(R8.Pn)`, `(R8.An)`, `(R8.Tn)`, or `(R8.Fn)` inline.

## Thesis

An autonomous agent's actions have asymmetric blast radii. Reading pod status
is safe; patching production is not; deleting data is catastrophic. EPHEMERAL's
claim is that the **authorisation ceremony should match the action's blast
radius, not average it**. Low-impact calls use simple short-lived tokens;
high-impact calls require cryptographic capabilities; irreversible calls
require a human-in-the-loop; existential calls require multi-party ceremony.
Tiers are not performance policy — they are security policy.

## Threat model

Carried forward from Round 0, tightened across Rounds 1–3, R7 and R8:

| Actor | Capability                                                                           |
|:-----:|:-------------------------------------------------------------------------------------|
|  A1   | Malicious LLM insider — corrupted inference or in-flight prompt injection.           |
|  A2   | Supply-chain compromise of the vendor ("DeployCo") build pipeline.                   |
|  A3   | Network attacker on data in transit.                                                 |
|  A4   | Compromised agent runtime (container/host RCE at vendor side).                       |
|  A5   | Compromised target API — explicitly out of scope; audit-only mitigation (§14).       |
|  A6   | Compromised vendor operator (insider at DeployCo, introduced in Round 1).            |

A5 is acknowledged as outside what a cross-org authorisation layer can prevent.
The other five are the design targets.

## Impact tiers and escalation

Every intent (action + resource + parameters) maps to exactly one tier via a
customer-authored WebAssembly classifier (§4).

| Tier | Name                   | Examples                                         | Authority mechanism                                                    |
|:----:|:-----------------------|:-------------------------------------------------|:-----------------------------------------------------------------------|
|  0   | Read                   | `GET /deployments`, `kubectl get pods`           | OIDC + DPoP bearer                                                     |
|  1   | Idempotent write       | `kubectl apply` of unchanged manifest            | OIDC + DPoP + OPA                                                      |
|  2   | Stateful reversible    | scale +1 replica, add non-privileged firewall    | Mandate → capability                                                   |
|  3   | Destructive recoverable| delete pod (controller recreates), rotate secret | Mandate + push-revocation + resource-version binding                   |
|  4   | Irreversible           | `DELETE Deployment`, `DROP TABLE`, `rm -rf pv-*` | Tier 3 + WebAuthn step-up                                              |
|  5   | Authority-granting     | add signer to customer root, modify Tariff       | Tier 4 + M-of-N ceremony across multiple customer officers             |

Tier assignment is additive, capped at 5:
`final_tier = min(5, floor + Σ bumps)` (R8.F2). Independent bumps: `sensitive-path`
(e.g. `prod/*`, `root/*`, `admin/*`, `ceremony/*` — reference glob set in
[`conformance/reference-sensitive-paths.json`](conformance/reference-sensitive-paths.json)),
`aggregation` (pattern-match within window), `canary-window`,
`target-invariants-missing`, `resource-state`. A Tier 5 intent triggers a
`CeremonyInitiated` audit event and waits for quorum co-signatures declared in
the Tariff's `ceremony_quorum` field before the action is issued.

## Architecture

Six pillars, each specified in its own section of `design-final-v2.md`:

**Tariff (§2.2).** Customer-signed COSE_Sign1 CBOR policy. Pins classifier
WASM hash, tier defaults, rate matrix, narrowness rules, PCR requirement,
anomaly-library endpoint, operating-hours policy. Signed by a 7-day-rotated
child of `K_cust_ops`. Size-capped at 256 KiB, validity-capped at 30 days,
monotonic version enforcement. Rejected at Router startup and on every push
update if signature, size, or structural invariants fail.

**Classifier (§4).** Customer-authored WebAssembly module receiving canonical
intents (per §4.2 normalisation), recent-actions history, a resource-state
snapshot, and the mandate budget. Outputs a tier recommendation with
aggregation-pattern escalation. Hermetic — no network, no target-API queries.
Pinned to the Tariff by SHA-256 (`classifier_wasm_hash`, §2.2); the reference
implementation additionally wraps the binary in an Ed25519 COSE_Sign1 signature
envelope (Phase C.3-C implementation — not in the normative spec). Only the
exact WASM byte-for-byte executes.

**Mandates (Tier 2+, §5).** Customer-issued cryptographic capabilities
authorising specific intents. Delegation chain verified at the Router side
(§7.3). Half-open validity `[issued_at, exp)`, narrowness rules, max chain
depth 4 keys / 3 links (R7.D3), no wildcard integrations at any level
(R7.D4), no empty-capability mandates (R7.D5).

**Router (§10).** Vendor-side enforcement point. Per-integration isolated.
Orchestrates canonical normalisation → classification → delegation verification
→ signer capability mint → step-up (Tier 4+) → ceremony (Tier 5) → action
issuance → audit. Fails closed on Tier 3+ if the revocation channel is
unreachable. Tracks the PCR nonce consumed-ledger (R8.P4) and the Tariff
`key_epoch` ledger (R8.T2).

**PCR / Nitro attestation (§9.3–§9.4, R8.P1–P6).** Runtime integrity proof
from reproducible-build PCR attestation. The signer service mints capabilities
only after the Router verifies a quorum of independent attestor signatures,
transparency-log inclusion proofs bounded by STH age, a Router-issued nonce
bound to the bundle, a bundle size cap, and (Tier 4+) witness cosignatures
spanning at least two distinct providers.

**Anomaly detection (§3.5, §11.2).** A customer-operated service that
consumes the Router's signed audit stream and matches patterns from a versioned,
signed `AnomalyPatternLibrary` (R8.A1). Fires auto-revoke on high-severity
matches (5 s default SLA, 30 s maximum per R8.A2) and alerts on medium
(300 s SLA). Threshold relaxation
requires a ceremony-quorum `PatternRelaxationException` — the library enforces a
high-water-mark ratchet so a compromised library signer cannot loosen
detection silently.

## Repository layout

```
empheral/
├── conformance/                        # Test-vector corpus (JSON source-form)
│   ├── schema.json                     # JSON Schema 2020-12 for every suite file
│   ├── reference-sensitive-paths.json  # Operator reference set (~190 globs, 7 categories)
│   └── *.json                          # 11 vector files, 576 vectors total
├── reference/validator/                # Rust workspace — reference validator
│   ├── crates/
│   │   ├── ephemeral-anomaly           # Pattern-library envelope, state machine, firing rules
│   │   ├── ephemeral-attestation       # Nitro attestation + Rekor inclusion proofs
│   │   ├── ephemeral-attestation-test-support  # Deterministic Nitro fixture generation
│   │   ├── ephemeral-classifier        # wasmi 0.47.2 interpreter, ABI v1, signature envelope
│   │   ├── ephemeral-cli               # ephemeral-validator binary
│   │   ├── ephemeral-core              # Suite loader, schema validation, executors
│   │   └── ephemeral-crypto            # COSE_Sign1 + Ed25519 chain walk, capability types
│   └── tools/
│       ├── print-root-fingerprint      # AWS Nitro root G1 SHA-256 fingerprint
│       ├── prod-symbol-probe           # Feature-leak guard (test-fixtures must not ship)
│       └── vector-signer               # Deterministic COSE_Sign1 signer for vector regeneration
├── design-final-v2.md                  # Current normative specification
├── design-final.md                     # Pre-R7/R8 consolidation
├── design-v1.md .. design-v3.md        # Architectural evolution
├── redteam-round1.md .. round3.md      # Adversarial review rounds
├── design-round7-tightenings.md        # R7 canonicalisation + delegation (15 items: 10 + 5)
├── design-round8-operational-tightenings.md  # R8 operational tightenings (23 items)
├── no-go-preemptive.md                 # Pre-architecture decision gate
├── skeptic-review.md                   # Skeptic pass (what if the whole idea is wrong?)
├── decision.md                         # Consolidated decisions
└── conformance-plan.md                 # Conformance suite plan
```

## Implementation status

The reference validator is developed in three phases. The spec (Phase A) is
finalised; the structural validator (Phase B) covers six core suites; Phase C
replaces each mocked cryptographic boundary with live primitives against a
conformance corpus.

| Phase | Scope                                                                      | Status                                       |
|:-----:|:---------------------------------------------------------------------------|:---------------------------------------------|
|   A   | Design specification                                                       | Done — `design-final-v2.md`                  |
|   B   | Structural validator, six core suites (520 vectors after C.1 extensions)   | Done                                         |
|   C.1 | Live Ed25519 + COSE_Sign1 for Tariff and Delegation                        | Done                                         |
|   C.2 | Live AWS Nitro enclave attestation verification                            | Done                                         |
|  C.2.5| Rekor RFC 9162 inclusion-proof verification                                | Done                                         |
|  C.3-A| `ephemeral-classifier` crate, hermetic `wasmi` 0.47.2 interpreter          | Done                                         |
|  C.3-B| Strict ABI v1 hardening, 12 review findings                                | Done                                         |
|  C.3-C| Classifier signature envelope, live fuzz dispatch                          | Done                                         |
|  C.4-1| Anomaly-library envelope + six-stage verifier                              | Done                                         |
|  C.4-2| Pattern body + Stage-7 invariants                                          | Done                                         |
|  C.4-3| Replay-protection ledger + Stage 8                                         | Done                                         |
|  C.4-4| `anomaly-library-reject` conformance suite                                 | Done                                         |
| C.4-5A| Event-stream normaliser + state-machine core                               | Done                                         |
| C.4-5B/A | Firing-rule evaluators (FirstMatch, SequenceMatch, CumulativeOverBaseline) | Done                                         |
| C.4-5B/B | `anomaly-detect` conformance suite (15 vectors)                          | **Current `origin/main`**                    |
| C.4-5B/C | `audit.rs` production integration, `AnomalyDetected` emission            | Pending                                      |
| C.4-5B/D | Persistent dedup ledger (crash-recovery for `last_fired_at`)             | Optional, not committed                      |

Five of the six mock-crypto boundaries in the original Phase-C plan are now
live; the last (real `audit.rs` dispatch against the shipped firing-rule
evaluator) is the immediate next step.

## Conformance corpus

Vectors are JSON source-form. Implementations serialise to deterministic CBOR
(RFC 8949 §4.2) at consumer time. JSON is used because it is inspectable in any
text editor and diffable in git; the subset used round-trips losslessly through
CBOR. Vector IDs are stable and never reused — a removed vector is marked
`deprecated: true` and its ID is retired.

| Suite                                  | File                                          | Vectors | Prefix   | Scope                                                                 |
|:---------------------------------------|:----------------------------------------------|--------:|:---------|:----------------------------------------------------------------------|
| Canonicalisation                       | `canonicalization.json`                       |     93  | `canon`  | §4.2 — NFC, case-fold, null-reject, SET typing, homoglyph, locale     |
| Delegation scope                       | `delegation-scope.json`                       |     70  | `ds`     | §7.3 — signature chain, integration / tier / verb / budget / expiry   |
| Tariff reject                          | `tariff-reject.json`                          |     71  | `trej`   | §2.2, §3–§7 — sig, version, expiry, tier, PCR, classifier, rate matrix|
| Fuzz baseline                          | `fuzz-baseline.json`                          |    205  | `fuzz`   | §4.4 — classifier tier assignment across integrations                 |
| PCR attestation reject                 | `pcr-attestation-reject.json`                 |     49  | `pcrrej` | §9.3–§9.4 — quorum, attestor trust, PCR mismatch, transparency log    |
| Audit replay                           | `audit-replay.json`                           |     32  | `arep`   | §3.5 — delete/IAM/Vault/Git storm patterns, cross-tier escalation     |
| Tariff classifier-sig (C.3-C)          | `tariff-reject-c3-c-classifier.json`          |      8  | `trej`   | Live Ed25519 classifier envelope verification                         |
| Anomaly-library reject (C.4 S.4)       | `anomaly-library-reject.json`                 |     17  | `alrej`  | Envelope, ABI, payload, time, Stage-7 invariants, Stage-8 replay      |
| Anomaly detect (C.4 S.5-B B)           | `anomaly-detect.json`                         |     15  | `adet`   | Firing-rule dispatch: FirstMatch, SequenceMatch, CumulativeOverBaseline|
| PCR C.2 live                           | `pcr-attestation-reject-c2-live.json`         |      8  | `pcrrej` | Live Nitro ES384 with root-pinned trust                               |
| PCR C.2.5 Rekor                        | `pcr-attestation-reject-c2-5-rekor.json`      |      8  | `pcrrej` | RFC 9162 inclusion proofs, STH verification                           |
| **Total**                              |                                               | **576** |          |                                                                       |

Schema evolution bumps `schema_version`; the `vector_suite` enum in
`schema.json` is the authoritative list. See [`conformance/README.md`](conformance/README.md)
for per-suite contribution rules and the cross-suite reject-code reference.

## Reference validator

Rust 2021 edition, MSRV 1.75. Workspace-wide `#![forbid(unsafe_code)]` and
clippy pedantic with `-D warnings` in CI. Three-OS matrix in GitHub Actions
(Ubuntu, Windows, macOS) plus a daily scheduled run at 03:00 UTC to catch
silent AWS root-of-trust rotations.

### Building

```bash
cd reference/validator
cargo build --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test  --workspace --locked
```

### Running the conformance corpus

```bash
# Validate every suite file with defaults (schema + conformance dir at repo root).
cargo run --bin ephemeral-validator

# Point at explicit paths, or run a subset:
cargo run --bin ephemeral-validator -- \
    --schema          ../../conformance/schema.json \
    --conformance-dir ../../conformance \
    --suite           DelegationScope \
    --suite           Canonicalization

# Machine-readable summary:
cargo run --bin ephemeral-validator -- --json-report report.json
```

Consult `report.json` (or a fresh `--json-report` run) for the current per-suite
pass/fail/skipped totals. Suites whose crypto boundaries are still mocked remain
loaded and marked `skipped` until the corresponding Phase-C pillar lands; known
reject-code deviations (e.g. `pcrrej-024`) are tracked in the audit trail.

Exit codes:

|  Code | Meaning                                                                    |
|:-----:|:---------------------------------------------------------------------------|
|   0   | Every loaded file is structurally valid and every executed vector passes.  |
|   1   | At least one vector fails or a harness error occurs.                       |
|   2   | Invalid arguments or unreadable inputs (clap default).                     |

### Regenerating conformance vectors

```bash
cargo run -p vector-signer -- gen-phase-c4-detect   # one of the per-phase generators
cargo test -p vector-signer                         # includes determinism tripwires
```

Each generator is deterministic: two successive `--dry-run` invocations must
emit byte-identical stdout, and the SHA-256 of that stdout is pinned in the
corresponding `tests/determinism_*.rs`. The tripwires catch accidental
non-determinism in Ed25519 nonce derivation, CBOR map ordering, COSE header
serialisation, `BTreeMap` drift, and `serde_json`'s field-insertion behaviour.

## Security posture

- **No `unsafe`.** `unsafe_code = "forbid"` workspace-wide.
- **Clippy pedantic is a merge gate.** `RUSTFLAGS=-D warnings` is set in CI;
  `cargo clippy -- -D warnings` runs against every target on three operating
  systems per PR and daily.
- **Test fixtures cannot ship.** Fixture signers, RFC-6979 seeded keys, and
  WAT builders live behind a `test_fixtures` feature. A dedicated binary
  (`tools/prod-symbol-probe`) builds the core crates with that feature
  **disabled**, then greps the resulting rlib to assert that no fixture symbol
  is reachable from production code paths. Positive controls (the public
  verifier entry points) are also asserted to be present, so an accidental
  feature-unify does not silently pass.
- **Determinism is machinery-verified.** Every conformance generator's dry-run
  output has its SHA-256 pinned; changing it requires an intentional
  `DRY_RUN_SHA256` update, which surfaces in review.
- **Review-swarm before every commit.** `code-reviewer` and `security-reviewer`
  agents run in parallel while workspace tests execute; findings are applied
  inline before the commit lands. Commit messages reference the session
  identifier and no CRITICAL finding has landed unremediated.
- **Role-collapse as anti-enumeration.** Key-role mismatches fold to a single
  undifferentiated rejection at the trust-anchor lookup boundary; outer-envelope
  COSE-verification failures fold to a single undifferentiated rejection at the
  envelope boundary. Separate rejection codes appear only for inner-payload
  checks where the spec determines the disclosure is uncritical (§7.3, §8.2).
- **Attacker-controlled strings are sanitised at every log/error surface.**
  `sanitize_log_string` is mandatory on `event_id`, `mandate_id`, `library_id`,
  and any identifier that originates outside the Router's trust boundary.
- **Feature surface is narrow.** Workspace-level `time = { features = ["parsing"] }`;
  no consumer uses `formatting` or `macros`, so neither is enabled. Other
  crypto deps are pinned to explicit minor versions
  (`wasmi = "=0.47.2"`, `coset = "0.4"`, `ed25519-dalek = "2.2"`).

Responsible-disclosure contact and policy will land in a dedicated
`SECURITY.md`. Until then, please use GitHub's private vulnerability-reporting
feature via the repository's Security tab.

## Spec provenance

The specification is the product of three red-team rounds, a skeptic pass, and
two operational tightening rounds. The audit trail is versioned alongside the
code:

```
no-go-preemptive.md
        ↓
    design-v1.md
        ↓  redteam-round1.md
    design-v2.md
        ↓  redteam-round2.md
    design-v3.md
        ↓  redteam-round3.md  +  skeptic-review.md
    design-final.md
        ↓  design-round7-tightenings.md   (R7: 15 items — 10 canonicalisation + 5 delegation)
        ↓  design-round8-operational-tightenings.md   (R8: 23 operational items)
    design-final-v2.md   ← current normative spec
```

R7 and R8 items are integration-marked in place in `design-final-v2.md` (see
`§19` changelog). Every `conformance/*.json` file carries a `spec_version`
field; when the normative spec changes materially, that field is bumped and the
conformance README documents the migration.

## What this is NOT

- **Not a replacement for IAM.** Single-user interactive authentication remains
  OAuth/OIDC; EPHEMERAL sits above it, bounding what an already-authenticated
  agent is allowed to do with its bearer token.
- **Not a runtime.** The protocol authorises actions; it does not execute them.
  The agent, the target APIs, and the signer service are out of scope as
  implementations.
- **Not a defence against a compromised target API (A5).** If the destination
  system is itself controlled by the adversary, no cross-org authorisation
  layer can recover correctness. EPHEMERAL's mitigation is audit-only.
- **Not a cryptographic-primitive validator.** Ed25519, COSE, CBOR, wasmi
  correctness is assumed to be tested by those libraries' own conformance
  suites. The conformance corpus tests protocol-level behaviour.
- **Not protection against sub-threshold aggregation by a patient attacker
  (V3-2).** An attacker operating strictly within every rate limit and matching
  no known anomaly pattern can accumulate damage over time. This is a
  fundamental limit of any tier-based scheme. Narrow mandates, anomaly patterns
  for slow-burn behaviour, and target-level invariants bound blast radius and
  detection latency but do not eliminate the residual. Documented in §14.
- **Not a mitigation for side channels, hardware attacks, or model poisoning.**
  Explicitly out of scope.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

## Contributing

Vector contributions must include a `rationale` traceable to a spec section or
red-team finding, a `severity_if_failed` classification, and review by someone
other than the author. Preserve existing vector IDs; retired vectors stay in
place with `deprecated: true`. See [`conformance/README.md`](conformance/README.md)
for the full per-suite contribution protocol.

Unless you state otherwise, any contribution intentionally submitted for
inclusion in EPHEMERAL by you, as defined in the Apache-2.0 license, shall be
dual-licensed as above, without any additional terms or conditions.
