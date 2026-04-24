# SLIDE_OUTLINE.md — The Canon × EPHEMERAL Deck

**Target format:** 12 slides, 1920×1080, paced for a 3-minute live talk + leave-behind reading.
**Use in Claude Design:** open the **Slide deck** tab, paste this as the source-of-truth outline. Each slide block below contains: layout intent, copy, visual elements, motion notes.
**Style binding:** every slide MUST inherit from `DESIGN.md` — Cormorant Garamond display, Inter body, parchment palette, single wax seal per slide.

---

## Deck arc (the spine)

```
1  Cover         — the wax seal lands
2  The problem   — words live in e-mails, e-mails are editable
3  The promise   — wax seal for the digital age
4  Three actors  — author, notary, witness
5  One fact      — the 9 fields of a sealed claim
6  The journey   — 7 steps from e-mail to verified seal
7  Live demo     — verify a real fact in 4 seconds
8  Tamper test   — change one byte, watch the seal break
9  Architecture  — process-isolated, role-separated, key-rotatable
10 EPHEMERAL    — the protocol underneath
11 Numbers       — what we shipped, in receipts
12 Close         — QR code + CTA
```

Three section densities (per DESIGN.md §4.3): **Open / Read / Proof**, alternated.

| Slide | Density | Function |
|---|---|---|
| 1 | Open | hook, single object |
| 2 | Read | problem framing |
| 3 | Open | metaphor reveal |
| 4 | Read | mental model |
| 5 | Proof | data-dense card |
| 6 | Read | narrative timeline |
| 7 | Proof | live demo embed |
| 8 | Proof | failure demo |
| 9 | Read | architecture diagram |
| 10 | Read | broader context |
| 11 | Proof | metrics card |
| 12 | Open | call to action |

---

## SLIDE 1 — Cover

**Layout:** centered, single object. 80% whitespace.

**Visual:**
- Centered: 320px-diameter wax seal (Canon × EPHEMERAL monogram), `--seal-crimson`, soft `--verify-green-glow` ring pulsing once on slide-enter.
- Below seal, typeset block:

```
        A wax seal for the digital age.

   Canon × Canon-Signer × EPHEMERAL
      ───────────────────────────
        Big Berlin Hack · 04 · 26
              Nelson Mehlis
```

**Type:**
- Headline: Cormorant Garamond 600, 72px, `--ink-deep`.
- Sub: Cormorant Italic, 28px, `--ink-mid`.
- Footer: Inter Small Caps, 14px, tracking 0.15em, `--ink-soft`.

**Background:** `--paper`, subtle parchment texture (4% noise overlay).

**Motion:** seal enters with the wax-stamp scale animation (DESIGN.md §7), then green-glow pulse fires once.

---

## SLIDE 2 — The problem

**Layout:** asymmetric two-column (40 / 60). Left: pull quote. Right: failure visualization.

**Headline (top, full-width):**
> **What's the actual receipt for a sentence in an e-mail?**

**Left column copy:**
> A customer writes: _"We did 127k in Q1, looking good."_
>
> You store it. You book against it.
>
> Six months later, your auditor asks: prove that exact sentence was in that exact mail.

**Right column visual:**
A staged "screenshot of a screenshot" — a deliberately editable e-mail screenshot mock-up, with a faint "EDITABLE IN 5 SECONDS" stamp diagonally in `--tamper-red`, 30% opacity.

**Footer:**
> _A screenshot is not evidence. It is a claim about a claim._

**Type:** Cormorant 56px headline; Inter 18px body; Cormorant italic 22px footer.

---

## SLIDE 3 — The promise (metaphor reveal)

**Layout:** centered, single dominant object.

**Visual:**
- Macro photo or illustration of an actual 16th-century pressed red wax seal (the only photographic asset in the deck — DESIGN.md §8).
- 720px wide, dropped into the page like a museum plate.

**Headline (above, centered):**
> **Sixteenth century had this figured out.**

**Body (below, centered, narrow column):**
> Three properties made wax seals robust:
> **hard to forge · visibly broken · publicly verifiable.**
>
> Canon builds **exactly the same system** —
> for digital business claims instead of letters.
>
> Wax becomes _Ed25519_. The crest becomes a _public key_.
> The messenger becomes a _hex string that fits in a QR code_.

**Type:** Cormorant 56px headline; Cormorant italic 22px body with mono inline emphasis in `--code-hex`.

---

## SLIDE 4 — Three actors

**Layout:** horizontal three-column diagram, full-width, with the key insight as headline.

**Headline:**
> **Three roles. Architecturally separated. By design.**

**Visual (centered, 1500px wide):**
```
┌───────────────┐    JSON    ┌───────────────┐    hex+QR   ┌───────────────┐
│   AUTHOR      │ ─────────▶ │   NOTARY      │ ──────────▶ │   WITNESS     │
│   "Canon"     │            │  "Signer"     │             │  "Browser"    │
│               │            │               │             │               │
│   Node.js     │            │     Rust      │             │     WASM      │
│   reads mail  │            │  presses wax  │             │ verifies seal │
└───────────────┘            └───────────────┘             └───────────────┘
   what's being said           how it's sealed              how it's checked
```

Boxes: 1.5px stroke `--ink-deep`, sharp corners, parchment fill. Italic captions in Cormorant 14px below each box (`--ink-soft`).

**Pull-out callout (bottom-right):**
> _Even if Canon is breached tomorrow, the witness's WASM has no signing capability. Forgeries are architecturally impossible — not promised._

---

## SLIDE 5 — One fact (the atomic unit)

**Layout:** centered single fact-card, magnified. Shows the 9 fields.

**Headline:**
> **A fact is nine fields. Together: an unforgeable record.**

**Visual:** the fact-card from DESIGN.md §5.2, scaled to 1100px wide. Pre-filled with the canonical demo fact:

```
FACT  f_q1_acme_0001                                      [✓ SEALED]
─────────────────────────────────────────────────────────────────────
ENTITY        customer:acme
CLAIM         Q1 revenue was EUR 127,000
SOURCE        gmail:msg_abc123
EXCERPT       "Our Q1 came in at 127k EUR, looking good."
PARENT        — genesis —
SIGNED AT     2026-04-24 09:03:12 UTC
SIGNER (KID)  canon/8a88e3dd7409f195
EVENT HASH    b0f3 7530 95a4 c2e1 88ff … d7a1 9b40 0e3c
SIGNATURE     d28443a10126a10444…edaf  (568 hex chars)
```

**Annotation lines (Cormorant italic, dotted callouts):**
- "9 fields → 7-field CBOR payload + COSE envelope. RFC 9052 standard."
- "EVENT HASH = SHA-256 of the canonical CBOR. The fact's fingerprint."
- "PARENT links to the previous fact. The chain is unbreakable from this point on."

**Wax seal**: small (48px), top-right corner of card, `--seal-crimson` solid.

---

## SLIDE 6 — The journey (e-mail → seal → verify)

**Layout:** vertical 7-step timeline, parchment background.

**Headline:**
> **From e-mail to evidence, in 4 seconds.**

**Visual:** vertical numbered timeline, each step a row:

```
[1]  09:03 — Mrs. Meyer at Acme writes "Our Q1 came in at 127k EUR…"
[2]  Canon's AI extracts the structured claim.
[3]  Canon hands the fact to Canon-Signer over stdin.
[4]  Signer pours wax: CBOR + COSE_Sign1 + Ed25519.            ← <1 ms
[5]  Canon stores the envelope. event_hash → next parent_hash.
[6]  Six months later: auditor opens a QR-code URL on their phone.
[7]  Browser shows a green seal. The math is the receipt.       ← 400 ms
```

**Type:** step numbers in JetBrains Mono `--code-hex` gold, body in Inter 18px, timings in Cormorant italic `--ink-soft`.

**Subtle accent:** thin vertical wax-trail line on the left, `--seal-crimson`, connecting all 7 steps.

---

## SLIDE 7 — Live demo (the embedded verifier)

**Layout:** **this is the live moment.** Browser-frame embed of the actual web verifier, full-bleed.

**Headline (top strip, small):**
> **Live: thepyth0nkid.github.io/empheral**

**Visual:**
- Full-screen mockup of the web verifier, with the green wax seal stamped, all 10 verify steps showing ✓ in `--verify-green`.
- A QR code in the lower-right corner with the share URL.
- Caption strip below: "_Anyone in this room. Any browser. No login._"

**Voiceover cue (speaker notes):**
> "I'll just open this URL on my phone right now. Hit Verify. There — green seal. Acme, Q1, 127k EUR, signed at 9:03. The ten steps next to it are everything the browser just did. You don't have to trust me — you can read the math."

**Speaker notes (below slide, for the slide deck export):**
- Open: `thepyth0nkid.github.io/empheral/?e=<hex>&pk=<key>` (preloaded in pinned tab)
- Click "Verify"
- Point at green seal
- Point at 10 steps panel
- 35 seconds total

---

## SLIDE 8 — The tamper test (failure mode is the proof)

**Layout:** before/after diptych — left half "valid", right half "tampered". Vertical split.

**Headline:**
> **Change one byte. Watch the seal break.**

**Left panel:** the green-seal verifier (smaller version of slide 7). All steps green.

**Right panel:** same UI, but the wax seal is **cracked diagonally, displaced 6px**, in `--tamper-red`. Step 7 (Ed25519 verify) is glowing red. All subsequent steps are em-dashed grey "skipped".

**Caption strip below:**
> _A single hex character flipped on the URL. Verification time to detect: **400 milliseconds**. There is no "almost-valid". There is valid, or there is not._

**Speaker notes:**
- Live: change last hex char in URL
- Click Verify
- "There. Step 7 red. The seal cracked. The whole chain after this point is invalid. Cryptographically, not editorially."

---

## SLIDE 9 — Architecture (the why-this-is-trustworthy)

**Layout:** central diagram + four flanking proof-points.

**Headline:**
> **Why this isn't another "trust us" pitch.**

**Center diagram (600px):** the same three-actor diagram from slide 4, but expanded with crypto annotations:
```
   AUTHOR ─JSON─▶ NOTARY ─hex+QR─▶ WITNESS
   (Canon)        (Signer)        (Browser-WASM)
                   ↓
                Ed25519
                COSE_Sign1
                CBOR §4.2
                AAD: canon/fact/v1
```

**Four flanking cards (2x2 grid around the diagram):**

| Card | Heading | Body |
|---|---|---|
| ⊤L | **No shared signing primitives** | The verifier has no private-key code path. Forgery from a compromised Canon is architecturally impossible. |
| ⊤R | **Process isolation** | Signer is a separate Rust process. A bug in Canon's Node code cannot reach the key. |
| ⊥L | **Key rotation built-in** | Each fact carries its own `kid`. Old facts remain verifiable forever, even after key rotation. |
| ⊥R | **No infrastructure dependency** | The verifier is a static page + 250 KB WASM. Host it anywhere. The fact itself is two strings. |

---

## SLIDE 10 — EPHEMERAL (the protocol underneath)

**Layout:** wider context, shows Canon-Signer as one artifact in a larger system.

**Headline:**
> **Canon-Signer is the first public artifact of EPHEMERAL — the agent-authority protocol.**

**Visual:** a layered stack diagram, Canon-Signer highlighted in the middle band:

```
┌──────────────────────────────────────────────────────────────┐
│  EXTERNAL VERIFIERS  (browsers, auditors, customer CIOs)     │
└──────────────────────────────────────────────────────────────┘
            ▲
┌──────────────────────────────────────────────────────────────┐
│  CANON-SIGNER  ←── you are here                              │
│  Ed25519 / COSE_Sign1 / CBOR  ·  44 tests · 0 unsafe         │
└──────────────────────────────────────────────────────────────┘
            ▲
┌──────────────────────────────────────────────────────────────┐
│  EPHEMERAL CRYPTO PRIMITIVES                                 │
│  signing · verify · key-derivation · canonical-CBOR          │
│  (shared with the agent-authority protocol)                  │
└──────────────────────────────────────────────────────────────┘
            ▲
┌──────────────────────────────────────────────────────────────┐
│  EPHEMERAL FULL PROTOCOL                                     │
│  Tariffs · Tier 0–5 · WASM Classifier · Nitro Enclaves       │
│  · Rekor transparency log · Anomaly Pattern Library          │
│  528 conformance vectors · 920 workspace tests               │
└──────────────────────────────────────────────────────────────┘
```

**Body (right column, 350px):**
> **EPHEMERAL** is a cryptographic authorization protocol for letting autonomous agents act across organizations without blind trust. Six tiers of authority, customer-signed Tariffs, deterministic WASM classifiers, Nitro-Enclave attestation.
>
> Canon-Signer reuses EPHEMERAL's audited primitives. _You're not seeing a hackathon prototype. You're seeing a clean public face on a deeper system._

---

## SLIDE 11 — The receipts (numbers, no spin)

**Layout:** three-column metrics card, each column a "receipt" stack.

**Headline:**
> **What we shipped, in receipts.**

**Three columns:**

```
TESTS                    PERFORMANCE              CRYPTO
─────                    ───────────              ──────
   964                       <1 ms                Ed25519
   tests                     sign                 RFC 8032
                             time
                                                  COSE_Sign1
   528                       400 ms               RFC 9052
   conformance               browser
   vectors                   verify               SHA-256
                                                  FIPS 180-4
     0                       250 KB
   unsafe                    WASM                 CBOR §4.2
   blocks                    bundle               RFC 8949
```

**Type:** big numbers in JetBrains Mono `--code-hex` gold, 56px tabular nums; labels in Cormorant italic 16px below.

**Footer strip:** "_Reproducible: `github.com/ThePyth0nKid/empheral` · branch `feat/canon-signer` · Apache-2.0 / MIT_"

---

## SLIDE 12 — Close (the QR code that walks home with the judge)

**Layout:** centered, single dominant object — the QR code itself.

**Headline (above QR):**
> **Verify it yourself. Right now.**

**Visual:**
- Centered QR code, 480px square, parchment-framed, `--seal-crimson` accent on the framing corners.
- Below the QR, the URL spelled out in JetBrains Mono `--ink-deep`:
  `thepyth0nkid.github.io/empheral/?e=…&pk=…`

**Sub-line (Cormorant italic, below URL):**
> _Open. Verify. Tamper one character. Verify again._
>
> _The seal is the answer._

**Footer:**
> Nelson Mehlis · nelson@ultranova.io · `github.com/ThePyth0nKid/empheral`

**Motion:** wax-seal silhouette behind the QR fades in at 60% opacity; pulse once on slide-enter.

---

## Speaker-notes export (for PPTX)

For each slide, include the matching segment of the **3-minute stage script** from `docs/STORY.de.md §7`. Anglicize for international audience if Claude Design exports both DE and EN versions.

```
Slide 1: 5s pause, let the seal land. Don't speak.
Slide 2: 20s — the problem hook.
Slide 3: 20s — the metaphor.
Slide 4: 25s — three roles, point at each box.
Slide 5: 15s — quick fact-card glance, don't dwell.
Slide 6: 20s — narrate the journey.
Slide 7: 35s — LIVE demo, click Verify.
Slide 8: 30s — LIVE tamper, click Verify, point at red.
Slide 9: 15s — architecture, two beats.
Slide 10: 20s — EPHEMERAL context.
Slide 11: 15s — receipts.
Slide 12: 15s — CTA, leave QR up.
                ─────
Total:    ~3:40 (target 3:00 — cut slide 9 or 10 if behind)
```

---

## Backup slides (only if time / stage allows)

**S13 — Domain separation deep-dive** _(for technical Q&A)_
> The AAD (Additional Authenticated Data) is a fixed string `canon/fact/v1`. Even an attacker who lifts a signature cannot replay it under a different domain. The COSE_Sign1 spec mandates this. We did not invent it. We composed it correctly.

**S14 — What this is NOT** _(for skeptical auditors)_
> We do not prove truth. We do not prove freshness. We do not prove identity. Three honesty bullets. Then: _"What we do prove: a specific Canon installation signed this exact byte sequence at this exact moment, and nothing has changed since. That is the contract."_

**S15 — Roadmap** _(for investor-style audience)_
> Today: hackathon-state, dual-licensed, audit-ready.
> Q3 2026: external audit (Trail of Bits / NCC).
> Q4 2026: Canon production rollout, transparency log integration.
> 2027: EPHEMERAL OSS release, RFC submission.

---

## Export targets

| Format | Use |
|---|---|
| **PPTX** | Hackathon backup (USB stick, in case of internet failure) |
| **Hosted URL** | Primary stage delivery — Claude Design hosts, you click through |
| **PDF** | Leave-behind for judges, mailable to investors |
| **Canva** | If a non-technical co-founder needs to edit later |

**Recommended:** export all four. PPTX as offline failsafe; URL as primary; PDF for follow-up emails.
