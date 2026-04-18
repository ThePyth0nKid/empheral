# design-round7-tightenings.md — Round 7 Architect Pass

**Date**: 2026-04-18 (same session as Phase A conformance delivery)
**Role**: Architect, Round 7. Resolves the 15 bounded spec ambiguities (10 canonicalization, 5 delegation) surfaced by Phase A conformance vector authoring.
**Status**: Delta document. To be integrated into `design-final.md` §4.2 and §7.1–§7.4 in a subsequent session.
**Purpose**: Make the Canonicalization and Delegation sections of `design-final.md` executable against a reference validator. The remaining 23 operational questions from Phase A are deferred to Phase B.

**Governing principles (in order of precedence when they conflict)**:
1. **Stricter is safer** — where the spec was silent or ambiguous, prefer the option with the smaller attack surface.
2. **Preserve V3-1 defense** — the §7.3 scope-match table is the primary anti-scope-drift defense. Nothing here may introduce a bypass.
3. **Preserve V2-2 defense** — the classifier and the mandate-signer MUST see identical canonical bytes. No silent conversion is permitted anywhere in the canonicalization pipeline.
4. **Determinism ≻ expressiveness** — canonical forms must be total functions from input to output (or to REJECT); no implementation-defined tail.
5. **Cite prior authority** — reuse RFC 3986 (URIs), RFC 8949 §4.2 (deterministic CBOR), Unicode Standard Annex #15 (normalization), Unicode Technical Standard #39 (security mechanisms), RFC 3454/7564 (stringprep/PRECIS) where they solve the problem.

---

## §4.2 Canonicalization — 10 tightenings

### R7.C1: Case-folding scope

**Question**: Does canonical form lowercase `resource_kind`, `namespace`, and `name` in addition to `verb`?

**Answer (normative)**: `verb` MUST be lowercased. `resource_kind` MUST be lowercased. `namespace` and `name` MUST be case-preserved (treated as opaque identifiers per RFC 3986 §6.2.2.1 — schemes and hosts are case-insensitive; path segments are not).

**Rationale**: Kubernetes API discovery treats `resource_kind` as case-insensitive (`Deployment` ≡ `deployment` ≡ `DEPLOYMENT`); silently accepting one form at the Router while the target API normalizes another produces the V2-2 asymmetry. `namespace` and `name`, by contrast, are case-sensitive at the target (K8s object names like `web-server` and `Web-Server` are distinct resources). Case-folding those would either lose uniqueness (silently merging two resources) or fail to match the target (creating a denial of service). The split follows the target-API contract.

**Spec patch (to append to §4.2)**:
> Canonicalization rules for identifier components:
> - `verb`: lowercased (ASCII `A-Z` → `a-z`) after `verb_aliases` mapping.
> - `resource_kind`: lowercased (ASCII `A-Z` → `a-z`) after schema resolution.
> - `namespace`, `name`: case-preserved. Case variance in these components produces distinct canonical intents.
> - Non-ASCII case mapping in any identifier component is handled per Unicode Default Case Folding (UTS #39 §5, `toCasefold`), locale-independent — see R7.C10.

**Vector impact**: `canon-020..025` (case-folding category) already assume this split; no flips required. Spec patch ratifies the existing vector semantics.

**Strength impact**: **STRENGTHEN** — closes the V2-2 asymmetry for `resource_kind` while preserving target-API semantics for `namespace`/`name`.

---

### R7.C2: Parameter keys case policy

**Question**: §4.2 says "Parameter keys: forbidden case variation." Does this mean REJECT or AUTO-LOWERCASE?

**Answer (normative)**: REJECT. If an intent object contains two parameter keys that differ only by Unicode case-folded equivalence (e.g., `{"Namespace": "a", "namespace": "b"}`), Router MUST reject with `reject_code = normalization-not-applied`. Router MUST NOT auto-lowercase parameter keys.

**Rationale**: Auto-lowercasing creates the exact V2-2 silent-conversion attack surface this spec exists to prevent — attacker submits `{"NameSpace": "safe-ns", "namespace": "target-ns"}`; classifier sees one (lowercased first-wins), signer sees the same merged view, but an intermediate proxy or target API de-duplicates differently. Rejection is deterministic; the caller either sends a single key or is explicit about multiple keys. This is the RFC 7396 "explicit over implicit" rule applied to JSON merge semantics.

**Spec patch (§4.2)**:
> Parameter key collision rule: Two parameter keys `k1, k2` in the same object scope that differ only by Unicode Default Case Folding (i.e., `casefold(k1) == casefold(k2)`) cause the enclosing intent to be REJECTED with `reject_code = normalization-not-applied`. Router MUST NOT implicitly merge, lowercase, or deduplicate parameter keys.

**Vector impact**: Canonicalization `case-folding` category vectors that submit colliding-case keys MUST expect `reject_code = normalization-not-applied`. Existing vectors already follow this convention (see notes field item 2).

**Strength impact**: **STRENGTHEN** — eliminates the silent-merge attack class entirely.

---

### R7.C3: Unicode normalization form

**Question**: NFC, NFD, NFKC, or NFKD? Do other forms silently convert or reject?

**Answer (normative)**: Canonical form is **NFC** (Unicode Standard Annex #15). Input that is already in NFC passes unchanged. Input that is not in NFC (i.e., `nfc(input) != input`) MUST be REJECTED with `reject_code = unicode-not-nfc`. Silent conversion is forbidden.

**Rationale**: NFC is the IETF default (RFC 5198) and the JSON best practice for identifier comparison. NFKC/NFKD perform *compatibility* decomposition which is lossy (e.g., `²` → `2`, full-width forms → ASCII, ligatures → component letters) — that is precisely the V2-2 attack surface (classifier sees `k8s`, signer sees `ｋ８ｓ`, target sees one form, auditor the other). Reject-not-convert ensures the classifier and the mandate-signer observe byte-identical canonical forms. Clients that want compatibility folding do it themselves before submission; the boundary is explicit.

**Spec patch (§4.2)**:
> Unicode normalization: All string-typed fields of an intent (verb, resource_kind, namespace, name, parameter keys, parameter string values) MUST be in Unicode Normalization Form C (NFC) per Unicode Standard Annex #15. Inputs failing `input == nfc(input)` byte-equality check are REJECTED with `reject_code = unicode-not-nfc`. Router MUST NOT apply NFC conversion implicitly.

**Vector impact**: `unicode-nfc-nfd-nfkc-nfkd` category (canon-026..035) already encodes reject-on-non-NFC. No flips; spec patch ratifies.

**Strength impact**: **STRENGTHEN** — closes a documented normalization-attack class with a deterministic rule.

---

### R7.C4: Null vs missing key semantics

**Question**: `{"x": null}` vs `{}` — same canonical form or distinct?

**Answer (normative)**: **DISTINCT**, and `{"x": null}` is REJECTED with `reject_code = null-value-forbidden`. The canonical form of an intent contains only present, non-null keys; any explicit null value in a canonical-input position is rejected.

**Rationale**: Two goals in tension — (a) canonical form must be minimal and deterministic; (b) `null` as an explicit assertion is semantically different from absence. We resolve by forbidding `null` entirely at the canonical boundary. A caller who means "no value" omits the key; a caller who means "zero" sends `0`; a caller who means "empty string" sends `""`. This removes one full dimension of ambiguity from V2-2's attack surface (where attacker sends `{"namespace": null}` and classifier vs signer disagree on whether to treat it as absence).

**Spec patch (§4.2)**:
> Null-value policy: A canonical intent MUST NOT contain JSON `null` or CBOR `null` (major type 7, simple value 22) as a value anywhere in its object tree. Intents containing any null value at any depth are REJECTED with `reject_code = null-value-forbidden`. Callers MUST omit absent keys rather than set them to null.

**Vector impact**: `null-vs-missing` category (canon-060..063) already encodes reject-on-null. Spec patch ratifies.

**Strength impact**: **STRENGTHEN** — removes an attack-relevant ambiguity with zero loss of expressiveness (all intents expressible without null still work).

---

### R7.C5: Max string length and nesting depth

**Question**: Numeric limits must be specified.

**Answer (normative)**:
- `max_string_bytes`: 4096 bytes (UTF-8 encoded) per string value.
- `max_key_bytes`: 256 bytes per object key.
- `max_object_depth`: 8 levels of nesting.
- `max_array_length`: 256 elements per array.
- `max_total_intent_bytes`: 65536 bytes for the entire canonical CBOR serialization of an intent.

Exceeding any limit causes REJECT with a specific reject code: `max-string-length-exceeded`, `max-key-length-exceeded`, `max-depth-exceeded`, `max-array-length-exceeded`, `max-intent-size-exceeded` respectively.

**Rationale**: Without hard caps, a malicious LLM (A1) or compromised Router (A4) can OOM the Signer enclave or the classifier WASM instance by submitting a pathologically nested or oversized intent. Round 3 V2-2 attack surface benefits from determinism over edge-case permissiveness. 4 KiB strings accommodate all K8s identifiers, Vault paths, and realistic resource references; 8 levels of nesting cover the deepest observed API shapes (K8s Deployment spec is 6 nested levels at maximum). Numbers sized to the baseline fuzz corpus expectations at §4.4.

**Spec patch (§4.2)**:
> Structural size limits (MUST; exceeding produces explicit reject codes):
> - `max_string_bytes = 4096` (per string value, UTF-8 encoded)
> - `max_key_bytes = 256` (per object key, UTF-8 encoded)
> - `max_object_depth = 8` (counting the intent root as depth 1)
> - `max_array_length = 256`
> - `max_total_intent_bytes = 65536` (canonical CBOR serialization)
>
> Router MUST enforce these before passing the intent to the classifier. Classifier WASM instances MUST additionally fail fast on inputs exceeding these limits (redundant check).

**Vector impact**: `empty-and-boundary` category (canon-090..094) already uses these thresholds. No vector flips.

**Strength impact**: **STRENGTHEN** — eliminates DoS/OOM primitives against classifier and Signer; improves determinism.

---

### R7.C6: Array ordering — SET or SEQUENCE?

**Question**: Are arrays in verb/cap lists SETS (sort-dedupe) or SEQUENCES (preserve)?

**Answer (normative)**: Field-typed. The following fields are **SETS** (canonicalized by sort-ascending on byte-lexicographic order of NFC UTF-8 encoding, then dedupe):
- `Mandate.cap[].verb` list (within a single cap entry)
- `DelegationScope.integrations`
- `DelegationScope.allowed_verbs`
- `DelegationScope.allowed_resource_kinds`
- `Tariff.step_up_allowlist`
- `Tariff.pcr_attestors`

The following fields are **SEQUENCES** (order preserved, duplicates significant):
- `ClassifierContext.recent_actions` (chronological order is semantic)
- Positional parameter arrays (e.g., CLI-style argv, shell command tokens)
- `revocation_channel_ha.secondary_endpoints` (order = failover priority)
- Audit event chains

**Rationale**: Sets where the spec's semantics are "the child may X for any one of these" (scope containment is a set-membership test). Sequences where order conveys meaning (chronology, priority, positional arguments). Mixing the two is the single largest source of V3-1 scope-drift bugs — if `allowed_verbs` were a sequence, `["patch", "PATCH"]` could parse two ways; as a set after NFC+lowercase they collapse to one and the scope-match table produces one answer.

**Spec patch (§4.2, extend with a new subsection §4.2.1)**:
> §4.2.1 Array-shape typing for canonicalization:
> The following fields are SETS. Canonical form sorts ascending on byte-lexicographic order of NFC UTF-8 encoding and deduplicates:
> `Mandate.cap[].verb`, `DelegationScope.integrations`, `DelegationScope.allowed_verbs`, `DelegationScope.allowed_resource_kinds`, `Tariff.step_up_allowlist`, `Tariff.pcr_attestors`, `Tariff.ceremony_quorum.signers`.
>
> The following fields are SEQUENCES (order significant, duplicates retained):
> `ClassifierContext.recent_actions`, `revocation_channel_ha.secondary_endpoints`, positional parameter arrays inside intent.params, audit-chain event arrays.
>
> An implementation that treats a SET field as a SEQUENCE (or vice versa) is non-conformant.

**Vector impact**: `array-handling` category (canon-055..058) and `delegation-scope` integration/verb fields already follow this typing. Spec patch ratifies and makes field-level typing enumerable for the validator.

**Strength impact**: **STRENGTHEN** — eliminates a V3-1 bypass pathway (scope-match through sequence-typed allowlist).

---

### R7.C7: Canonicalization ordering relative to CBOR

**Question**: Parse-JSON → canonicalize → CBOR, or canonicalize on CBOR?

**Answer (normative)**: The canonical pipeline is: **parse external format → canonicalize as an in-memory structure → serialize to deterministic CBOR per RFC 8949 §4.2**. Canonicalization happens on the in-memory object tree, not on the JSON or CBOR byte stream. Routers accepting JSON at the ingress MUST parse, canonicalize, and then emit deterministic CBOR for all internal use (classifier input, signer input, audit payload).

**Rationale**: Canonicalizing on bytes (e.g., sorting JSON keys in the input string) is fragile across whitespace and encoding variation. Canonicalizing on the parsed structure is total and deterministic. RFC 8949 §4.2 gives CBOR a single canonical byte form once the structure is fixed — we chain to it rather than re-inventing. This also gives the classifier and the mandate-signer byte-identical CBOR to hash — V2-2's core requirement.

**Spec patch (§4.2, new subsection §4.2.2)**:
> §4.2.2 Pipeline ordering (MUST be performed in this exact sequence):
> 1. Parse external representation (JSON per RFC 8259, or CBOR per RFC 8949) into an in-memory structure.
> 2. Apply canonicalization rules §4.2 / §4.2.1 / §4.2.3 (below) to the in-memory structure. Structure is either canonical or REJECTED.
> 3. Serialize the canonical structure to deterministic CBOR per RFC 8949 §4.2 (Core Deterministic Encoding Requirements: shortest-length integers, shortest-length float representation, definite-length items, map keys sorted by bytewise lexicographic order of their deterministic-encoded form).
> 4. The byte output of step 3 is the canonical bytes. Both the classifier input and the mandate-signer input MUST consume these exact bytes; any transformation between those two consumers is a protocol violation.

**Vector impact**: `roundtrip-jsoncbor` category (canon-079..082) already tests this pipeline. Spec patch ratifies.

**Strength impact**: **STRENGTHEN** — closes V2-2 by making the byte-form the contract, not the structure.

---

### R7.C8: Zero-width / bidi character handling

**Question**: Strip or reject characters U+200B, U+200C, U+200D, U+2060, U+FEFF, U+202A–202E, U+2066–2069?

**Answer (normative)**: **REJECT.** Any string-typed field containing any code point in the following set causes the intent to be rejected with `reject_code = invalid-control-char`:

- Zero-width: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+2060 (WJ), U+FEFF (ZWNBSP / BOM)
- Bidi overrides and embeddings: U+202A (LRE), U+202B (RLE), U+202C (PDF), U+202D (LRO), U+202E (RLO)
- Bidi isolates: U+2066 (LRI), U+2067 (RLI), U+2068 (FSI), U+2069 (PDI)
- Tag characters: U+E0000–U+E007F (entire Tags block)
- Additional control: U+00AD (soft hyphen), U+034F (combining grapheme joiner)

This aligns with Unicode Technical Standard #39 §5.4 "Restriction Level: ASCII-Only" *plus* the bidi-control subset relevant to homoglyph spoofing (CVE-2021-42574 "Trojan Source" class).

**Rationale**: These code points are the primary vehicle for invisible-identifier attacks against the classifier-signer pipeline. A `verb` of `patch\u200B` is byte-different from `patch` but visually identical in every renderer; without explicit rejection, one component lowercases away the zero-width and another doesn't, yielding V2-2. Strip-vs-reject: strip is a silent transformation (forbidden by principle 3), reject is deterministic and forces the client to clean the input.

**Spec patch (§4.2, new subsection §4.2.3)**:
> §4.2.3 Invisible / bidi / tag character policy: String-typed fields MUST NOT contain any code point in the following set. Presence causes REJECT with `reject_code = invalid-control-char`:
> U+00AD, U+034F, U+200B..U+200D, U+2060, U+FEFF, U+202A..U+202E, U+2066..U+2069, U+E0000..U+E007F.
> Router MUST enforce this check before NFC validation (R7.C3) and case folding (R7.C1).

**Vector impact**: `injected-control-chars` and `homoglyph-attacks` categories (canon-064..075) already reject on these code points. Spec patch ratifies.

**Strength impact**: **STRENGTHEN** — closes Trojan-Source / homoglyph attack class; removes silent-strip failure mode.

---

### R7.C9: Identifier separator escaping

**Question**: Canonical form is `<kind>/<namespace>/<name>`. What if `name` contains `/`?

**Answer (normative)**: **FORBID `/` in any identifier component.** Any raw intent whose `name`, `namespace`, or `resource_kind` string contains U+002F SOLIDUS is REJECTED with `reject_code = identifier-separator-forbidden`. Canonical identifier form is `<kind>/<namespace>/<name>` with the solidus exclusively acting as a structural separator — no escaping rule is defined, because no escaping is permitted.

**Rationale**: RFC 3986 §3.3 defines `/` as a structural delimiter in URI paths; overloading it as a literal identifier character requires percent-encoding, which reintroduces the V2-2 attack surface (does the classifier percent-decode, does the signer?). Existing K8s, Vault, and cloud-provider identifier conventions all forbid `/` in object names — no real-world workload is lost by enforcing this. An implementation wishing to support a target API that does allow `/` must wrap it in a dedicated field (e.g., `params.subpath`) outside the `<kind>/<namespace>/<name>` identifier.

**Spec patch (§4.2)**:
> Identifier canonical form is `<kind>/<namespace>/<name>`, where the two U+002F SOLIDUS characters are exclusively structural separators. No component may contain U+002F. An intent containing U+002F inside `resource_kind`, `namespace`, or `name` is REJECTED with `reject_code = identifier-separator-forbidden`. No escape sequence or percent-encoding for U+002F inside an identifier component is defined or permitted.

**Vector impact**: Current canonicalization vectors do not heavily exercise this case; canon-090..094 boundary category should be extended with 2–3 new vectors explicitly testing `/` in name and in namespace (flag for Phase B augmentation, not a flip of existing vectors).

**Strength impact**: **STRENGTHEN** — removes an entire parsing-ambiguity class; maintains interoperability with real-world target APIs.

---

### R7.C10: Locale neutrality

**Question**: Turkish dotless-i, German eszett, Lithuanian i-dots — must canonicalization be locale-independent?

**Answer (normative)**: **YES. Canonicalization MUST be locale-independent.** All case operations use Unicode Default Case Folding (the `CaseFolding.txt` rules, specifically the `C` + `F` mapping subset) per UTS #39 §5. Locale-specific case mappings (Turkish `tr`/`az` dotless-i, Lithuanian `lt` dotted-i, German `de-DE-1996` eszett expansion) MUST NOT be applied.

**Rationale**: A Router whose case-folding depends on `LC_CTYPE` produces different canonical forms on different hosts — a direct V2-2 vector (one node normalizes Turkish-style, another Default-style, classifier and signer disagree). Unicode Default Case Folding is total, deterministic, and host-independent. Clients that operate in locale-sensitive domains either (a) avoid the contentious code points or (b) pre-fold client-side before submission.

**Spec patch (§4.2)**:
> Locale independence: All string operations in canonicalization (case folding, case comparison, NFC validation, normalization equivalence) MUST use Unicode Default Case Folding (UTS #39 §5, `CaseFolding.txt` status `C` + `F`). Locale-tailored case mappings (e.g., `tr`, `az`, `lt`, `de-DE-1996`) MUST NOT be applied, regardless of host locale. Implementations on platforms where the default locale-tailored API is primary (e.g., Java `String.toLowerCase()` without explicit `Locale.ROOT`) MUST override to the locale-independent path.

**Vector impact**: `locale-sensitive` category (canon-085..088) already asserts Default-Case-Folding output regardless of locale. Spec patch ratifies.

**Strength impact**: **STRENGTHEN** — closes a V2-2 vector that would otherwise be implementation-platform-dependent.

---

## §7.1–§7.4 Delegation — 5 tightenings

### R7.D1: Role hierarchy enforcement (ds-021)

**Question**: §7.3 does not explicitly forbid direct `K_cust_root` → `mandate_signer` delegation. Must the chain enforce the three-level hierarchy?

**Answer (normative)**: **YES. Three-level hierarchy is normative.** A valid delegation chain terminating in a `mandate_signer` child_role MUST pass through exactly one intermediate `ops` or `tariff_signer` or `audit_signer` child_role. Direct `K_cust_root` → `mandate_signer` delegation is REJECTED with `reject_code = role-hierarchy-violation`.

Formally, let `R(k)` denote the `child_role` of the delegation link whose `child_key = k`. A chain `[d1, d2, ..., dN]` from `K_cust_root` to `K_cust_mandate_X` is valid only if:
- `R(d1.child_key) ∈ {"ops", "tariff_signer", "audit_signer"}` (first link descends into a role layer, not straight to mandate authority).
- `R(dN.child_key) = "mandate_signer"` (last link produces the mandate signing key).
- For every intermediate link `di` (1 < i < N), `R(di.child_key) = R(di-1.child_key)` (i.e., role is preserved across intermediate delegations within a single role layer — see R7.D3 for chain depth).
- A `mandate_signer` child_role may not be followed by a further delegation (mandate signing keys do not sub-delegate).

**Rationale**: The three-level hierarchy in §7.1 exists to bound the blast radius of a single key compromise. If `K_cust_root` can directly delegate to `mandate_signer`, then root compromise yields immediate mandate authority without any `K_cust_ops` mediation — defeating the entire 90-day/7-day rotation separation and the M-of-N policy at `K_cust_ops`. Round 3 V3-1 specifically names "scope drift via chain shape" as the primary defense target. Strict interpretation is mandatory per principle 1 (Stricter is safer) and principle 2 (preserve V3-1).

**Spec patch (insert into §7.3, before the scope-match table)**:
> §7.3.0 Chain-shape requirement (role hierarchy): A valid mandate delegation chain MUST have the shape `root → {ops|tariff_signer|audit_signer}* → mandate_signer`, where:
> - The first delegation link's `child_role` is one of `{ops, tariff_signer, audit_signer}` — never `mandate_signer` directly.
> - The final delegation link's `child_role` is `mandate_signer`.
> - Intermediate links (if any) preserve the role established by the first link.
> - `mandate_signer` child_role terminates the chain; no further delegation from a `mandate_signer` key is accepted.
>
> Chains violating this shape are REJECTED with `reject_code = role-hierarchy-violation` before scope-match evaluation.

**Vector impact**: `ds-021` currently encodes REJECT with `reject_code = signature-chain-broken`. Under R7.D1 the reject outcome is correct, but the reject code should be **flipped** to `role-hierarchy-violation` to distinguish chain-shape violations from signature-chain-integrity violations. Flag for vector update, do not modify here. `ds-059..064` (attack-scope-drift category) should be re-scanned for any chain that incidentally skips ops; those remain REJECT.

**Strength impact**: **STRENGTHEN** — closes a V3-1 bypass pathway and reinforces the §7.1 separation that the 90-day/7-day rotation math relies on.

---

### R7.D2: `valid_until` inclusivity (ds-014)

**Question**: Is the bound `time ≤ valid_until` (inclusive) or `time < valid_until` (exclusive)?

**Answer (normative)**: **EXCLUSIVE.** A delegation or mandate is valid when `valid_from ≤ current_time < valid_until`. At `current_time == valid_until`, the delegation/mandate is **expired** and MUST be rejected with `reject_code = expired`. The `valid_from` lower bound is inclusive; the `valid_until` upper bound is exclusive. This matches RFC 5280 §4.1.2.5 (X.509 `notAfter` is inclusive to the second, but the common interpretation in modern libraries including Go's `crypto/x509` is half-open) and aligns with the standard half-open interval convention in systems programming.

Additionally, `valid_until > valid_from` MUST hold (strict inequality); a delegation with `valid_until == valid_from` is rejected at issuance with `reject_code = validity-window-empty`.

**Rationale**: Half-open `[from, until)` intervals compose cleanly under union and intersection (the mathematical property that makes them the default in Rust `Range`, Python `range`, Go time arithmetic, CockroachDB intervals). Closed intervals `[from, until]` introduce off-by-one at every composition and require explicit edge handling. For revocation timing specifically, half-open makes "this key is valid until T" unambiguous: at T it is not valid. Matches Round 3 V3-6 grace-period math, which uses strict-less-than throughout.

**Spec patch (§7.2, append to the DelegationDocument definition)**:
> Validity window semantics: The half-open interval `[valid_from, valid_until)` defines when a DelegationDocument is usable. A verifier evaluating at `current_time`:
> - `current_time < valid_from` → reject with `not-yet-valid`.
> - `valid_from ≤ current_time < valid_until` → accept (subject to all other checks).
> - `current_time ≥ valid_until` → reject with `expired`.
>
> `valid_until > valid_from` is required at issuance; violation rejects with `validity-window-empty`.
>
> The same half-open rule applies to `Mandate.exp`: a mandate is valid while `issued_at ≤ current_time < exp`. Capability expiry (`Capability.exp`) follows the same rule.

**Vector impact**: `ds-014` currently encodes REJECT with `reject_code = expired` for `current_time == valid_until`. Under R7.D2 this is correct. No flip. Related boundary vectors (ds-013 exp boundary, ds-054..057 edge cases involving time) should be re-scanned for consistency; all current assertions match exclusive semantics.

**Strength impact**: **NEUTRAL** — the decision closes ambiguity in a direction that matches existing vectors and common convention; neither strengthens nor weakens defense. The *act of specifying* this removes a latent implementation-divergence risk, which is a mild strengthen.

---

### R7.D3: Max chain depth (ds-057)

**Question**: §7.3 does not specify a maximum chain length.

**Answer (normative)**: **Maximum delegation chain length = 4** (counting from root to mandate-signer, inclusive of both endpoints). That is, the `delegation_chain` array has at most 3 links (3 `DelegationDocument` entries, producing 4 keys: root, intermediate-1, intermediate-2, mandate-signer). Chains longer than 4 keys / 3 links are REJECTED with `reject_code = max-chain-depth-exceeded`.

Shape enumeration (all valid shapes):
- `root → mandate_signer` — **forbidden** (R7.D1, role-hierarchy-violation).
- `root → ops → mandate_signer` — valid (chain length 3, 2 links). Standard case.
- `root → ops → ops' → mandate_signer` — valid (chain length 4, 3 links). Ops sub-delegation.
- Longer chains — **forbidden** (this rule, max-chain-depth-exceeded).

The same cap applies to `tariff_signer` and `audit_signer` role branches (root → tariff_signer and root → audit_signer are directly permitted, max chain length 2 / 1 link; root → ops → tariff_signer is not allowed because tariff_signer is a root-direct role).

**Rationale**: Unbounded chain depth is an attack primitive: an attacker with a deep delegation chain can (a) exhaust Router verification compute, (b) evade human audit review (who reads a 20-layer chain carefully?), and (c) create scope-dilution paths where each layer shaves a tiny bit of restriction until the effective scope at the mandate is unrecognizable. A cap of 4 keys accommodates every real-world deployment pattern (root → ops → sub-ops → mandate for large orgs, root → ops → mandate for normal case) without enabling the deep-chain attack class. Round 3 V3-1 is strengthened: a 4-key cap plus the R7.D1 role-hierarchy rule plus the scope-match table gives three orthogonal constraints.

**Spec patch (§7.3, after the chain-shape requirement R7.D1)**:
> §7.3.1 Chain-depth limit: The `delegation_chain` that a Router processes to verify a mandate MUST contain no more than 3 `DelegationDocument` entries (yielding a chain of at most 4 keys: root + up to 2 intermediates + mandate-signer). Chains exceeding this depth are REJECTED with `reject_code = max-chain-depth-exceeded` before scope-match evaluation.

**Vector impact**: `ds-057` currently has a 5-link chain and expects `accept`. Under R7.D3 this MUST **flip to REJECT** with `reject_code = max-chain-depth-exceeded`. Flag for vector update. Additionally, a new vector should be added for the boundary case (chain of exactly 3 links → accept; chain of exactly 4 links → reject).

**Strength impact**: **STRENGTHEN** — closes the deep-chain scope-dilution and audit-evasion vectors.

---

### R7.D4: Wildcard in `allowed_integrations` (ds-054)

**Question**: Is `["*"]` permitted in `DelegationScope.integrations`? If yes, does it mean "any integration in Tariff scope" or "unrestricted"?

**Answer (normative)**: **FORBIDDEN** in `DelegationScope.integrations`. A delegation whose `scope.integrations` contains the literal string `"*"` (or any glob pattern) is REJECTED with `reject_code = wildcard-not-permitted-in-integrations`. `integrations` MUST be an explicit enumeration of integration_refs.

Wildcards `"*"` remain permitted in `allowed_verbs` and `allowed_resource_kinds` (where the combinatorial explosion of enumerating every verb/kind is impractical), but even there, they are bounded by the narrowness rule §3.1 (wildcard in cap requires `budget.actions ≤ narrowness_threshold`, default 20).

**Rationale**: The `integration_ref` is the coarsest scope dimension — a `k8s-prod` vs `vault-prod` vs `github-org-acme` distinction. Allowing `"*"` here means one compromised ops key can mint mandates for every target system the customer operates, which is exactly the V3-1 scope-drift attack at maximum amplitude. Unlike verbs/kinds (where the set is vast and known), integrations are a small, explicitly configured set at the customer — there is no operational burden in enumerating them. Stricter-is-safer applies with no usability cost.

**Spec patch (§7.3, extend the DelegationScope definition)**:
> `integrations`: Non-empty array of explicit integration_ref strings. The wildcard literal `"*"` is FORBIDDEN in this field. Delegations with `"*"` in `integrations` are REJECTED at issuance and at verification with `reject_code = wildcard-not-permitted-in-integrations`. Wildcards remain permitted in `allowed_verbs` and `allowed_resource_kinds` subject to the §3.1 narrowness rule.

**Vector impact**: `ds-054` currently encodes `accept` for a delegation with `integrations: ["*"]`. Under R7.D4 this MUST **flip to REJECT** with `reject_code = wildcard-not-permitted-in-integrations`. Flag for vector update.

**Strength impact**: **STRENGTHEN** — closes a V3-1 maximum-amplitude bypass with zero practical usability cost.

---

### R7.D5: Empty-cap mandates (ds-055)

**Question**: Is a mandate with `cap: []` valid? If yes, what does it authorize?

**Answer (normative)**: **FORBIDDEN.** A mandate whose `cap` field is an empty array is REJECTED with `reject_code = mandate-empty-cap`. Mandates MUST declare at least one capability (`len(cap) >= 1`).

Additionally: every capability entry in `cap` MUST have a non-empty `verb` and a non-empty `resource_kind` (per canonicalization rules). A mandate containing any `cap` entry with empty/null verb or resource_kind is rejected with `reject_code = mandate-cap-malformed`.

**Rationale**: An empty-cap mandate has no legitimate purpose. It cannot authorize any action (scope is empty). Allowing it creates two failure modes: (a) the narrowness rule §3.1 becomes ambiguous (does "wildcard in cap" apply when there is no cap?), (b) auditors see a signed mandate that appears active but produces no effect — the perfect cover for social-engineering ("that mandate wasn't doing anything") or for placeholder-swap attacks. Rejection at issuance and verification is deterministic and closes both failure modes.

**Spec patch (§5.1, append to Mandate definition)**:
> Mandate structural constraints (enforced at signing and at verification):
> - `cap` MUST be a non-empty array (`len(cap) ≥ 1`). Empty cap rejects with `reject_code = mandate-empty-cap`.
> - Each `cap[i]` MUST have non-empty `verb` and `resource_kind` after canonicalization. Malformed cap entries reject with `reject_code = mandate-cap-malformed`.
> - `cap` entries are a SET (per R7.C6): duplicates are eliminated and order is byte-lexicographic. After deduplication, the `len(cap) ≥ 1` check still applies (a cap list of all duplicates reducing to 1 remains valid).

**Vector impact**: `ds-055` currently encodes REJECT with `reject_code = scope-verb-forbidden`. Under R7.D5 the reject outcome is correct, but the reject code should be **flipped** to `mandate-empty-cap` for specificity. Flag for vector update.

**Strength impact**: **STRENGTHEN** — closes a placeholder-swap social-engineering attack and disambiguates the §3.1 narrowness rule.

---

## Summary matrix

| ID | Area | Decision | Impact | Vectors needing update |
|---|---|---|---|---|
| R7.C1 | Case-folding scope | verb+kind lowercase; ns+name preserve | STRENGTHEN | none (ratifies) |
| R7.C2 | Parameter key case | REJECT on case-colliding keys | STRENGTHEN | none (ratifies) |
| R7.C3 | Unicode normalization | NFC required, reject-not-convert | STRENGTHEN | none (ratifies) |
| R7.C4 | Null vs missing | REJECT on any null | STRENGTHEN | none (ratifies) |
| R7.C5 | Size limits | 4KB/256B/depth 8/256 elems/64KB | STRENGTHEN | none (ratifies) |
| R7.C6 | Array ordering | field-typed SET vs SEQUENCE | STRENGTHEN | none (ratifies) |
| R7.C7 | Pipeline ordering | parse → canon → det-CBOR | STRENGTHEN | none (ratifies) |
| R7.C8 | Zero-width / bidi | REJECT on listed code points | STRENGTHEN | none (ratifies) |
| R7.C9 | Identifier separator | FORBID `/` in components | STRENGTHEN | add 2–3 boundary vectors (Phase B) |
| R7.C10 | Locale neutrality | Default Case Folding only | STRENGTHEN | none (ratifies) |
| R7.D1 | Role hierarchy | 3-level strict | STRENGTHEN | ds-021 reject_code flip to `role-hierarchy-violation` |
| R7.D2 | valid_until | exclusive (half-open) | NEUTRAL | none |
| R7.D3 | Max chain depth | 4 keys / 3 links | STRENGTHEN | **ds-057 must flip from ACCEPT to REJECT** with `max-chain-depth-exceeded` |
| R7.D4 | Wildcard in integrations | FORBID | STRENGTHEN | **ds-054 must flip from ACCEPT to REJECT** with `wildcard-not-permitted-in-integrations` |
| R7.D5 | Empty cap | FORBID | STRENGTHEN | ds-055 reject_code flip to `mandate-empty-cap` |

**Vector flips required (2 total outcome-flips, 3 reject-code-flips)**:
- Outcome flips (ACCEPT → REJECT): ds-054, ds-057.
- Reject-code flips (outcome correct, code needs specificity): ds-021, ds-055, and an audit of any vector currently using generic `scope-verb-forbidden` or `signature-chain-broken` for what is now a specific class.

No vector contradicts these tightenings in the opposite direction; no existing ACCEPT vector needs to flip to REJECT beyond the two flagged.

---

## Phase B entry status

**Canonicalization section (§4.2 after R7.C1–C10 patches applied)**: **SUFFICIENTLY PRECISE.** Every edge case that Phase A conformance authoring surfaced has a normative decision with a reject code and a rationale. A reference validator written against the patched §4.2 can mechanically check all 93 vectors in `canonicalization.json` without additional spec interpretation. Prior-art citations (Unicode Standard Annex #15, UTS #39, RFC 8949 §4.2, RFC 3986) give implementers a shared reference library.

**Delegation section (§7.1–§7.4 after R7.D1–D5 patches applied)**: **SUFFICIENTLY PRECISE.** The three-level role hierarchy is now normative (R7.D1), chain depth is bounded (R7.D3), integration wildcards are forbidden (R7.D4), empty caps are forbidden (R7.D5), and validity-window semantics are half-open (R7.D2). Combined with the §7.3 scope-match table already in `design-final.md`, a reference validator can decide any `(delegation_chain, mandate)` pair mechanically. V3-1 defense is strengthened, not weakened: chain-shape, chain-depth, integration-enumeration, and scope-match now operate as four orthogonal constraints.

**Recommendation**: **Phase B MAY proceed** against `design-final.md` + this tightenings delta, in the Canonicalization and Delegation domains. A one-session integration pass should fold R7.C1–C10 into §4.2 and R7.D1–D5 into §7.1–§7.4, raising the document to `design-final-round7.md` or equivalent.

### Remaining operational ambiguities (23 questions, Phase B work items)

Phase B's reference validator harness must surface but not resolve the following themes from the Phase A open-questions list:

1. **PCR attestation operational parameters** (6 questions, `pcr-attestation-reject.json` notes). Normative PCR indices, STH max age, trusted log-set pinning, nonce binding semantics, bundle size cap, split-view detection via witness cosignatures. These require empirical calibration against real enclave deployment pipelines. Phase B validator encodes them as configuration, not as hardcoded spec.

2. **Anomaly detection tuning** (4 questions, `audit-replay.json` notes). Pattern-library threshold values, auto-revoke vs alert-only, first-match vs N-consecutive firing, `Tariff.operating_hours` schema extension decision. Operational tuning requires live audit-stream telemetry.

3. **Tariff structural limits** (5 questions, `tariff-reject.json` notes). Max byte size, `iat`→`not_before` gap, max validity period, strict-vs-lenient on unknown fields, integration-unknown handling. These interact with customer deployment cadence; reasonable defaults proposed in Phase B, ratified after first production pilot.

4. **Fuzz corpus tier assignments** (8 questions, `fuzz-baseline.json` notes). fieldSelector / sensitive-path / aggregation-window / drain-node / canary-bump / git-default-branch / DNS-apex / ACME-wildcard. Each requires a domain expert (K8s / Git / DNS / ACME) to rule on the tier floor. Phase B harness encodes the current guesses as warnings, not errors, until customer-domain input is available.

These 23 remaining questions are appropriately resolved against a running reference implementation rather than on paper. Phase B's validator should emit a structured report for each of them on every conformance run, so that operational resolutions accumulate observable evidence.

### What this document does NOT do

- Does not modify `design-final.md`. Integration is a separate session.
- Does not modify any conformance vector. Vector flips flagged, not executed.
- Does not commit to git.
- Does not resolve the 23 operational questions (out of scope for a spec-precision pass).
- Does not add new red-team attacks; the red-team procedure cap (3 rounds) is exhausted per `redteam-round3.md`.

---

**End of Round 7 architect pass.** 15 tightenings produced: 14 STRENGTHEN, 1 NEUTRAL, 0 WEAKEN.
