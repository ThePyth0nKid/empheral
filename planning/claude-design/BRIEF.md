# BRIEF.md — The Story, three audiences

**For Claude Design.** Use these copy blocks verbatim, or as the source of truth Claude can rephrase to fit a layout. Do not invent claims beyond what's here — every sentence has been technically validated against the codebase.

---

## 0. The North Star (one sentence)

> **A wax seal for the digital age: any business claim, sealed once, verifiable forever, by anyone with a browser.**

Sub-line: _Production cryptography, no blockchain, no vendor trust._

---

## 1. The two-layer story (Canon × EPHEMERAL)

This project is **two things, intentionally separable.**

### Layer A — Canon-Signer (the hackathon artifact)

Canon is a Node.js system that reads business e-mail and extracts structured **facts** ("Customer X reported EUR 127,000 Q1 revenue"). **Canon-Signer** is the Rust sidecar that seals each fact cryptographically, like a notary pressing wax onto a letter. **The Web Verifier** lets _anyone_ — auditor, customer, journalist — open a URL and check the seal in their own browser. No login. No Canon account. No blockchain.

### Layer B — EPHEMERAL (the protocol behind it)

EPHEMERAL is the broader **Agent-Authority Protocol** — a cryptographic system for letting autonomous agents act on customer infrastructure without blind trust. Six tiers of authority, customer-signed Tariffs, deterministic WASM classifiers, Nitro-Enclave attestation, transparency-log-anchored audit. Canon-Signer is the **first public artifact** built on EPHEMERAL's primitives.

> _Canon-Signer ships today. EPHEMERAL is what makes it credible._

---

## 2. Audience A — Hackathon judges & builder crowd (Big Berlin Hack 2026-04-25/26)

### A.1 Hook (20 seconds, spoken)

> "Your business runs on e-mails. A customer writes 'we did 127k in Q1', you store it, you book against it. Six months later, when the auditor walks in, how do you prove that exact sentence was in that exact mail? A screenshot? Laughable."

### A.2 Promise (one sentence)

> Canon reads the mail, extracts the claim, and — this is the new part — **wax-seals it cryptographically**. Anyone, anywhere, can verify the seal in a browser in four seconds. No server trust. Tamper a single byte and the seal visibly breaks.

### A.3 Three killer points (memorize these — they're the deck spine)

**(1) Zero-trust by role separation.**
The code that **seals** runs on Canon's servers. The code that **verifies** runs in your browser. The verifier WASM contains _no_ signing primitive — even if Canon is compromised, no one can forge seals that browsers won't immediately reject. Trust isn't promised. It's architecturally enforced.

**(2) Portable without infrastructure.**
A signed fact is two strings: a hex envelope and a public key. They fit in a QR code. You can mail them, print them on an invoice, embed them in a PDF. No blockchain node, no central timestamp server, no GitHub-Pages dependency. The page can be hosted anywhere — S3, your own VPN, a USB stick.

**(3) Radical transparency, demonstrated.**
Most crypto products say "trust us, it's secure." We show **every step**, named, with byte-level detail, in an order the judge can replay. The customer doesn't take our word — the customer verifies. That is the differentiation against every "Blockchain for Enterprise" pitch on the market.

### A.4 Numbers that earn credibility (use as factoids)

- **964** workspace tests pass (canon-signer 44 + parent EPHEMERAL 920).
- **528** conformance vectors pass against live Ed25519 / COSE_Sign1.
- **20 µs** average sign time. **400 ms** browser verify time.
- **250 KB** WASM bundle. Loads cold in under a second.
- **0** unsafe code. `cargo clippy -D warnings` clean.
- **2** independent AI reviewer passes (security + correctness) before merge.
- **Apache-2.0 / MIT** dual-licensed. Reproducible from `github.com/ThePyth0nKid/empheral`.

### A.5 What to never say

❌ "Unhackable." → ✓ "Tamper-evident."
❌ "We invented this." → ✓ "We composed standards correctly."
❌ "Blockchain-grade." → ✓ "Cryptographic hash chain."
❌ "AI-generated code." → ✓ "AI-assisted, human-validated, 528 vectors green."

---

## 3. Audience B — Auditors, finance, enterprise risk

### B.1 Hook (one paragraph)

> Today, every audit of business communications is paper-thin. E-mail screenshots are editable in seconds. Database entries can be backdated by anyone with write access. CRM histories trust the CRM operator. The **chain of custody is a verbal claim**.

### B.2 Promise

> Canon turns each business claim from an e-mail into a **notarial record**: a signed, hash-chained, byte-frozen artifact, verifiable independently by any party — without trusting Canon, without trusting the customer, without specialized tooling. _Your auditor brings their own browser. The math is the receipt._

### B.3 What it gives you

- **Provenance.** Every claim points back to the source mail (`gmail:msg_abc123`), with a verbatim excerpt that cannot be silently edited later.
- **Integrity.** Signed with the exact CBOR layout. Flip a single bit anywhere → seal breaks. No "interpretation" of whether the data changed.
- **Chain.** Every fact's `parent_hash` references the previous fact about the same entity. Re-ordering or removing a record breaks the chain visibly. _A notarial book, page by page._
- **Independence.** Verification uses a 250 KB WASM library, source-available, that contains no signing capability. _Even if Canon is breached, the auditor's verification is unaffected._

### B.4 What it does NOT give you (we are honest about this)

- **Truth.** We can prove the claim was signed at time T by Canon. We cannot prove the claim is factually true. (Truth lives upstream, in the source email and the human who wrote it.)
- **Freshness.** A seal does not expire. If you need "this claim is current as of today", you sign a new fact today. Old facts remain valid forever.
- **Identity.** A `kid` (key id) is not a real-world identity. Identity binding (which company, which person, which CA) is a Canon-side concern, not a signer-side one.

### B.5 Compliance posture (handle with care, do not overclaim)

- Cryptography stack: **RFC 9052 COSE_Sign1**, **Ed25519 (RFC 8032)**, **SHA-256**, **CBOR (RFC 8949 §4.2 deterministic encoding)**. Same primitives as **WebAuthn / FIDO2 / Apple Pay**.
- Library origin: `ed25519-dalek` (audited), `coset`, `sha2`. No DIY crypto.
- For SOX / GDPR / GoBD-relevant evidence chains, this is a **technical foundation**, not a turnkey compliance product. Talk to counsel before declaring it "GoBD-konform."

---

## 4. Audience C — The non-technical layperson (1-pager / social card)

### C.1 The metaphor

> In the 16th century, important letters carried a **wax seal** with the sender's coat of arms.
>
> Three properties made the system robust:
> 1. **Hard to forge** — the crest couldn't be casually copied.
> 2. **Visibly broken** — any tampered letter showed it instantly.
> 3. **Publicly verifiable** — anyone who recognized the crest could confirm it themselves.
>
> Canon builds **exactly the same system** — for digital business claims instead of letters. Wax becomes an Ed25519 signature. The crest becomes a public key. The messenger becomes a hex string that fits in a QR code.

### C.2 What it does, in one sentence

> Canon reads your business e-mails, extracts the important claims, and **seals each one cryptographically**, so that years later anyone — your customer, your auditor, your own future self — can verify in a browser that nothing was changed.

### C.3 Why it matters

> Business runs on words. Words live in e-mails. E-mails are editable. _Until now, your business was as trustworthy as the most editable thing in your stack._

---

## 5. The journey of one fact (the canonical demo narrative)

Use this as the storyboard backbone for any prototype, video, or hero animation.

```
1. Friday 09:03 — Mrs. Meyer at customer Acme writes:
   "Our Q1 came in at 127k EUR, looking good."

2. Canon reads the mail. Its AI extracts:
       entity   customer:acme
       claim    Q1 revenue was EUR 127,000
       source   gmail:msg_abc123
       excerpt  "Our Q1 came in at 127k EUR…"

3. Canon hands the fact to Canon-Signer (the notary).
   Signer pours wax: builds a 7-field CBOR payload,
   wraps it in a COSE_Sign1 envelope, signs with Ed25519,
   returns hex envelope + public key. Total time: <1 ms.

4. Canon stores the envelope. The fact's event_hash
   becomes the parent_hash for the next fact about Acme.
   The chain extends.

5. Six months later, the auditor needs proof.
   Canon generates a Share URL:
   thepyth0nkid.github.io/empheral/?e=…&pk=…
   The URL fits in a QR code. Print it on the invoice.

6. The auditor opens the URL on their phone.
   No login. No account.
   The page shows: green wax seal, signed by canon/8a88…,
   the 9 fact fields, the 10 verify steps, all green.

7. The skeptical auditor changes one character in the URL.
   The page flips: red, broken seal. Step 7 lights red.
   No discussion needed. The seal is the answer.
```

**Total verification time, end to end: 4 seconds.**

---

## 6. Reusable phrases (for headlines, captions, slogans)

Pick from this menu. They have all been tested for tone.

### Hero candidates
- **"A wax seal for the digital age."**
- **"The math is the receipt."**
- **"Verifiable by anyone. Forgeable by no one."**
- **"Trust, but verify — and now you actually can."**
- **"Sealed once. Provable forever."**

### Sub-line candidates
- "Production cryptography. No blockchain. No vendor trust."
- "Open the URL. Watch the math. The seal is the answer."
- "RFC 9052, Ed25519, SHA-256 — the same standards your bank uses."
- "A signed fact is two strings. They fit in a QR code."

### Section openers
- **"Three actors. Three roles. One promise."** _(for the architecture section)_
- **"Ten steps. All visible. None skippable."** _(for the verification section)_
- **"What it proves. What it does not."** _(for the honesty section)_
- **"From e-mail to evidence."** _(for the journey section)_

---

## 7. The honesty paragraph (mandatory in any longer piece)

When the format allows >100 words, include this verbatim:

> **What this is not.**
> Canon-Signer does not prove a claim is true. It proves the claim was signed at a specific moment by a specific Canon installation, and that nothing has changed since. Truth lives upstream — in the source e-mail, in the human who wrote it. Identity binding (which company, which person owns a key) is a separate problem, deliberately kept out of this scope. We are tamper-evident, not tamper-proof, not omniscient. _The point is honesty about what cryptography can and cannot do._

---

## 8. Glossary (drop into a sidebar where useful)

- **Fact** — a structured business claim with 9 fields. The atomic unit.
- **Seal** — a COSE_Sign1 envelope wrapping a CBOR payload, signed Ed25519.
- **kid** — key id. Identifies which Canon key signed this fact.
- **event_hash** — SHA-256 over the canonical CBOR. The fact's fingerprint.
- **parent_hash** — the previous fact's event_hash. Links the chain.
- **Tariff** _(EPHEMERAL only)_ — customer-signed authorization document defining what an agent may do.
- **Tier** _(EPHEMERAL only)_ — 0–5 risk level for an agent action, classified deterministically.
- **Witness** — anyone running the verifier. The role architecturally separated from Author and Notary.

---

## 9. Don't-write-it list (lifted from VALIDATION.md)

Never let a designed surface claim:
- ❌ "Truth verification" / "fact-checking"
- ❌ "Decentralized" (we're not — Canon's key is centralized; we're _independent verification of a central signer_)
- ❌ "Blockchain" / "distributed ledger" / "Web3"
- ❌ "Quantum-safe" (Ed25519 is not post-quantum; that's a future migration question)
- ❌ "Audited" (not yet by an external firm — say "AI-reviewer-passed, externally auditable")
- ❌ "Compliant with [regulation]" (we provide a foundation; compliance is the customer's call with their counsel)

---

**Source-of-truth files in repo this BRIEF was distilled from:**
- `reference/validator/tools/canon-signer/docs/STORY.de.md` / `STORY.en.md`
- `reference/validator/tools/canon-signer/docs/HACKATHON.md`
- `reference/validator/tools/canon-signer/docs/EXPLAINER.md`
- `reference/validator/tools/canon-signer/docs/TECHNICAL.md`
- `reference/validator/tools/canon-signer/docs/VALIDATION.md`
- `Documents/obsidian-vault/Projekte/Aktiv/EPHEMERAL.md`
- `Documents/obsidian-vault/Projekte/Aktiv/EPHEMERAL/spec-overview.md`
