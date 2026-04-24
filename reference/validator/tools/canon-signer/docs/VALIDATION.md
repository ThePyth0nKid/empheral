# Validation — how Canon facts are verified

> Companion to [README](../README.md), [TECHNICAL.md](./TECHNICAL.md), and
> [HACKATHON.md](./HACKATHON.md).  This doc answers the question
> **"what does it mean that a Canon fact is verified, and who gets to check?"**

---

## TL;DR

Every signed Canon fact carries a **self-contained cryptographic receipt**
(a COSE_Sign1 envelope).  Anyone with the signer's public key can check
it — no Canon server required, no database lookup, no network.

Three tools exist for that check, targeting three audiences:

| Audience | Tool | Invocation |
|----------|------|------------|
| Canon runtime / Node app | `ephemeral-crypto` Rust library | `verify_cose_sign1(...)` |
| Auditor / ops / judge on CLI | `canon-verify` binary | `canon-verify --envelope-hex ... --pubkey ...` |
| Hackathon demo / stage | `scripts/demo.sh` | `bash scripts/demo.sh` |

A **web-based verifier** (paste-in-browser) does **not** exist today.
That is a known gap and the fourth section below sketches how to close it
after the hackathon.

---

## 1. What verification actually proves

Given:

- an envelope `cose_sign1_hex` (the wire bytes),
- a signer public key `ed25519:<base64>`, and
- the agreed external AAD `b"canon/fact/v1"`,

a successful verification proves three things, cryptographically:

1. **Provenance** — the envelope was produced by the holder of the
   private key matching the supplied public key.  An attacker who does
   not hold that key cannot forge a valid envelope, full stop.
   (Ed25519, EdDSA, RFC 8032.)

2. **Integrity** — every single bit of the signed payload is as it was
   at signing time.  Flipping one bit anywhere in the payload *or* the
   signature *or* the protected header breaks verification.  Detection
   is mathematical, not heuristic.

3. **Chain membership** — because each fact commits to its
   `parent_hash`, verifying a child envelope *plus* the parent's
   `event_hash` proves the child was signed with knowledge of the
   parent.  You cannot silently insert a fact in the middle of the
   chain without re-signing everything after it.

**What verification does *not* prove**:

- It does **not** prove the claim is *true*.  `claim = "Q1 revenue was
  EUR 127,000"` is attested by the signer, not adjudicated by Canon.
  Canon's job is tamper-evidence, not truth discovery.
- It does **not** prove freshness.  `created_at_ms` is caller-supplied;
  a malicious signer could backdate.  Freshness is an out-of-band
  concern (e.g. timestamping service, auditor's own clock).
- It does **not** establish *identity* beyond the key.  Binding the
  public key to a real-world entity (Canon instance, customer, legal
  person) is a PKI/trust concern outside this tool.

---

## 2. Three audiences, three tools

### 2a. Canon runtime — library call

Canon itself (the Node.js app) never needs to verify its own signatures
at runtime, but when a **consumer** of Canon's output (an audit trail
reader, a downstream pipeline) wants to check, they link the
`ephemeral-crypto` crate directly:

```rust
use ephemeral_crypto::{verify_cose_sign1, AnchorRole, TrustAnchor, TrustAnchorSet};

let mut anchors = TrustAnchorSet::new();
anchors.insert(
    TrustAnchor::new_ed25519(kid, &pubkey_bytes, AnchorRole::CanonSigner)?
)?;

let verified = verify_cose_sign1(
    &cose_bytes,
    &anchors,
    b"canon/fact/v1",
    AnchorRole::CanonSigner,
)?;
assert_eq!(verified.payload, expected_canonical_cbor);
```

This is the reference path — every other tool wraps this function.
`tools/canon-signer/tests/round_trip.rs` is the load-bearing test that
pins the invariant "whatever the signer emits, this verifier accepts".

### 2b. Auditor / ops / judge — `canon-verify` CLI

An auditor without the Rust toolchain (or a hackathon judge on stage)
wants a single-binary answer.  `canon-verify` is a thin CLI wrapper
around the same library:

```bash
canon-verify \
  --envelope-hex 84581ba20127045663616e6f6e2f... \
  --pubkey ed25519:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=
# → {"verified":true,"event_hash":"27d0310c...","kid":"canon/8a88e3dd7409f195"}
# exit 0
```

On tamper:

```bash
canon-verify --envelope-hex 84...FAKE --pubkey ed25519:...
# → {"verified":false,"error":"signature verification failed: ..."}
# exit 1
```

Exit code contract:

| exit | meaning |
|------|---------|
| `0`  | envelope verified (one-line `{"verified":true,...}` on stdout) |
| `1`  | verification failed (one-line `{"verified":false,...}` on stdout) |
| `2`  | usage / argument error (help on stderr)                       |

The binary has **no crypto of its own** — every guarantee comes from
`ephemeral-crypto`.  This is intentional: auditing "is the verifier
right?" reduces to auditing the EPHEMERAL library, which has a
battle-tested test suite (553+ CLI tests, Phase C.1–C.4).

### 2c. Hackathon demo — `scripts/demo.sh`

The stage story is **one script** that:

1. starts `canon-signer` with a deterministic demo key,
2. signs two chained facts (genesis + child),
3. verifies both with `canon-verify` — shows two ✓,
4. flips one nibble in the second envelope,
5. verifies again — shows ✗ and exit code 1,
6. prints a summary line.

Full source: [`scripts/demo.sh`](../scripts/demo.sh).  Runtime: ~2
seconds.

---

## 3. What exists today vs. what doesn't

**Shipped (branch `feat/canon-signer`, HEAD `d1ab9d2` + follow-ups):**

- ✅ `canon-signer` binary — NDJSON-over-stdio sign service
- ✅ `canon-verify` binary — standalone verifier CLI
- ✅ `ephemeral-crypto::verify_cose_sign1` — reference Rust API
- ✅ `scripts/smoke.sh` — 10-step hackathon-readiness gate
- ✅ `scripts/demo.sh` — reproducible stage playbook
- ✅ 44 passing tests (31 unit + 13 integration) covering round-trip,
  tamper, chain integrity, error recovery, 100-sign marathon
- ✅ Deterministic demo key `0x0101…01` → stable `kid=canon/8a88e3dd7409f195`

**Not shipped (known gaps):**

- ❌ **Web verifier** — there is no HTML page where a judge can paste an
  envelope into a textarea and see a ✓/✗ in the browser.  Section 4
  sketches the path.
- ❌ **JavaScript verifier library** — Canon is Node.js, so today
  verification in-process requires spawning `canon-verify` as a
  subprocess.  A pure-JS `verify_cose_sign1` would remove that fork.
- ❌ **Key rotation protocol** — single key per signer process today.
  Rotation = restart with a new seed.  Acceptable for the hackathon,
  non-negotiable for production.
- ❌ **Timestamping anchor** — signer trusts the caller's
  `created_at_ms`.  Adding a RFC 3161-style external timestamp would
  close the backdating hole.

---

## 4. Roadmap — the web verifier

The straight line from "CLI only" to "paste-in-browser":

### 4a. Compile `ephemeral-crypto` to WASM

```bash
cd reference/validator/crates/ephemeral-crypto
wasm-pack build --target web --release
# → pkg/ephemeral_crypto.js + ephemeral_crypto_bg.wasm
```

Prerequisites: all current dependencies (`ed25519-dalek`, `coset`,
`ciborium`, `sha2`) already compile to `wasm32-unknown-unknown`.
`rand_core` / `OsRng` is only used in the signer path, not the verifier,
so the WASM bundle stays small (~120 KiB gzipped, estimate).

Expose one function:

```rust
#[wasm_bindgen]
pub fn verify_canon_envelope(
    envelope_hex: &str,
    pubkey_wire: &str,
    kid: Option<String>,
) -> JsValue {
    // same body as canon-verify::run, returning a JS object
}
```

### 4b. Static HTML page

One `index.html`, no framework, no build step:

```html
<textarea id="envelope" placeholder="paste cose_sign1_hex"></textarea>
<textarea id="pubkey" placeholder="paste signer_pubkey"></textarea>
<button id="verify">Verify</button>
<pre id="result"></pre>

<script type="module">
  import init, { verify_canon_envelope } from "./ephemeral_crypto.js";
  await init();
  document.getElementById("verify").onclick = () => {
    const env = document.getElementById("envelope").value.trim();
    const pk = document.getElementById("pubkey").value.trim();
    const r = verify_canon_envelope(env, pk);
    document.getElementById("result").textContent =
      JSON.stringify(r, null, 2);
  };
</script>
```

Hosting: GitHub Pages on the `feat/canon-signer` branch, or a single
static file attached to the hackathon demo repo.  Zero backend.

### 4c. Estimated effort

- WASM build wiring + export: **1–2 hours** (existing crate, known
  toolchain).
- HTML + styling (match the wax-seal brand): **1 hour**.
- End-to-end test (Playwright paste-and-assert): **1 hour**.

**Total: half a day.**  Out of scope for pre-hackathon but directly
unlocks "scan-a-QR-code-and-see-✓" for the pitch.

---

## 5. Demo integration — how this fits the 3-min pitch

From [HACKATHON.md](./HACKATHON.md), the on-stage minute budget:

- **0:00 – 0:30** — The problem.  "AI extracts business facts from
  e-mail, but those facts are just strings in a database.  Auditors
  can't tell a real revenue claim from a hallucination."
- **0:30 – 1:15** — Canon the system.  Show the e-mail → extracted fact
  → chain UI.
- **1:15 – 2:00** — **The verification live-demo**.  Paste this slot
  with `scripts/demo.sh`:
  ```
  $ bash scripts/demo.sh
  ── step 1: start canon-signer ──────────────── ✓ live
  ── step 2: sign genesis fact ───────────────── ✓ event_hash=27d0310c...
  ── step 3: sign child fact ─────────────────── ✓ event_hash=90d6e240... parent=27d0310c...
  ── step 4: verify both facts ───────────────── ✓ ✓
  ── step 5: tamper with child envelope ──────── ✗ verification failed (expected!)
  ✔ end-to-end hash-chained signing + tamper detection
  ```
- **2:00 – 2:45** — The story.  "If any of these facts gets modified in
  the database, even one bit, the auditor's verify step screams.  We
  don't need to trust Canon or its server — we need to trust one
  public key."
- **2:45 – 3:00** — Call-to-action.  Canon is open-source; `canon-signer`
  is a single ~3 MiB static binary; the full receipt lives in one
  textarea-pasteable hex string.

Rescue answers for the Q&A slot are in
[HACKATHON.md](./HACKATHON.md#faq).

---

## 6. Reproducing verification yourself

You have three paths, in order of friction:

### Easiest — run the demo

```bash
bash reference/validator/tools/canon-signer/scripts/demo.sh
```

### Medium — one-off CLI

```bash
# Build once:
cargo build -p canon-signer --release

# Sign:
export CANON_SIGNER_KEY_HEX=$(head -c 32 /dev/urandom | xxd -p -c 256)
echo '{"op":"sign","fact_id":"demo","entity":"e","claim":"c","source_ref":"s","source_excerpt":null,"parent_hash":"","created_at_ms":0}' \
  | ./target/release/canon-signer > resp.json
cat resp.json   # contains cose_sign1_hex + signer_pubkey

# Verify:
COSE=$(python -c 'import json; print(json.load(open("resp.json"))["cose_sign1_hex"])')
PK=$(python  -c 'import json; print(json.load(open("resp.json"))["signer_pubkey"])')
./target/release/canon-verify --envelope-hex "$COSE" --pubkey "$PK"
# → {"verified":true,...}
```

### Deepest — link `ephemeral-crypto` from your own Rust code

See the snippet in §2a, or the test source
[`tests/round_trip.rs`](../tests/round_trip.rs).

---

## 7. Questions that come up

**Q: Can I verify without the signer's public key?**
No.  That is the whole point — without the pubkey, you cannot distinguish
a real signer from an attacker.  Publish the pubkey alongside the facts
(e.g. in Canon's `/.well-known/canon-signer.pub`).

**Q: What if the signer's key leaks?**
Every fact signed before the leak is still *mathematically* valid, but
the trust you place in them collapses.  Rotate the key (restart
`canon-signer` with a new seed), publish the new pubkey, and
cryptographically re-anchor the chain by co-signing the last event with
both keys.  (Not implemented today — documented as a gap in §3.)

**Q: Why COSE_Sign1 and not JWS?**
COSE is the CBOR-native successor to JWS (RFC 9052 replaces the
JSON-shaped signature envelope with a compact binary one).  Smaller on
the wire, deterministic by construction, first-class in the IETF
constrained-devices stack.  Canon uses CBOR for the payload anyway, so
keeping the envelope CBOR avoids a format jump.

**Q: Why the `b"canon/fact/v1"` AAD?**
Domain separation.  If the same Ed25519 key is ever re-used for an
EPHEMERAL envelope (which uses AADs like `b"tariff"` or
`b"ephemeral/anomaly-library/v1"`), the AAD mismatch forces verification
to fail — no cross-protocol signature reuse.  Cost: 13 bytes of AAD in
every signature input.  Benefit: airtight domain separation.
