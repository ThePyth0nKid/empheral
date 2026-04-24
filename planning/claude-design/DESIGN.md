# DESIGN.md — Notarial Modern

**Drop-in design system for Claude Design (claude.ai/design).**
Project: EPHEMERAL Agent-Authority Protocol + Canon-Signer.
Single source of brand truth. Paste this into Claude Design's "Set up design system" or upload as a file during onboarding.

---

## 1. Brand essence

> **"A wax seal for the digital age."**
> Sixteenth-century notarial gravitas, twenty-first-century cryptography.
> The aesthetic must convince both a hackathon judge and a Big-Four auditor in the same room.

**Three brand virtues, fixed in priority order:**
1. **Provability** — every claim shows its math. Visible mechanism > smooth UX.
2. **Permanence** — designs feel like documents that will still be readable in 2050.
3. **Precision** — Canon-grade optical-instrument craft. Nothing approximate.

**Three things to never do:**
- ❌ Cyberpunk neon, Web3 glitch, "AI gradient mesh."
- ❌ Sans-serif everything. Hierarchy collapses.
- ❌ Stock photography of people in suits. Use diagrams, seals, parchment textures.

---

## 2. Color tokens

### 2.1 Foundation (use these first)

| Token | Hex | Use |
|---|---|---|
| `--ink-deep` | `#0E0E0F` | Body copy, primary text |
| `--ink-mid` | `#3A3A3C` | Secondary text, captions |
| `--ink-soft` | `#6B6863` | Tertiary text, footnotes |
| `--paper` | `#F4EBD9` | Primary background ("parchment cream") |
| `--paper-bright` | `#FBF6E9` | Card backgrounds, callouts |
| `--paper-deep` | `#E8DCC2` | Hover states, subtle wells |

### 2.2 Brand accents (use sparingly — they should feel rare)

| Token | Hex | Use |
|---|---|---|
| `--seal-crimson` | `#8B1A1A` | The wax-seal red. Headlines accents, signatures, the seal itself. |
| `--seal-shadow` | `#5C0F0F` | Seal depth, hover state on crimson |
| `--seal-wax-rim` | `#B23E3E` | Highlight on seal for 3D effect |

### 2.3 Verification signal palette (semantic — DO NOT use elsewhere)

| Token | Hex | Use |
|---|---|---|
| `--verify-green` | `#00785A` | "Signature valid" — solid badge, success states |
| `--verify-green-glow` | `#00B86B` | Subtle glow / animation on verified seal |
| `--tamper-red` | `#A8281C` | "Signature broken" — contrast against `--paper` |
| `--tamper-red-bg` | `#FBE5E2` | Tampered alert background |
| `--neutral-amber` | `#B07A1F` | "Pending / unsigned / informational" |

### 2.4 Code & data palette

| Token | Hex | Use |
|---|---|---|
| `--code-bg` | `#1A1815` | Code-block background ("ink on parchment") |
| `--code-fg` | `#E8DCC2` | Code text |
| `--code-comment` | `#8A8576` | Code comments |
| `--code-hex` | `#C9A35A` | Hex strings, keys, hashes — gold ink |
| `--code-string` | `#7DA47D` | String literals |
| `--code-keyword` | `#C77B7B` | Reserved words |

**Contrast rule:** Body text MUST be `--ink-deep` on `--paper` or `--paper-bright`. Crimson is for accents only — never for paragraph copy.

---

## 3. Typography

### 3.1 Font stack

| Role | Font | Weight | Fallback |
|---|---|---|---|
| **Display headlines** | `Cormorant Garamond` | 600 | `EB Garamond, Garamond, 'Times New Roman', serif` |
| **Subheads / pull quotes** | `Cormorant Garamond` | 500 italic | same |
| **Body** | `Inter` | 400 / 500 | `'IBM Plex Sans', system-ui, sans-serif` |
| **Caption / metadata** | `Inter` | 400 small caps tracking-wide | same |
| **Code / hex / hashes** | `JetBrains Mono` | 400 | `'IBM Plex Mono', 'Courier New', monospace` |
| **Numerals (signatures, hashes shown big)** | `JetBrains Mono` tabular nums | 500 | same |

### 3.2 Type scale (modular, ratio 1.25 — Major Third)

```
display-xl   72 / 76    Cormorant 600     hero, slide-1 title
display-lg   56 / 60    Cormorant 600     section openers
display-md   40 / 48    Cormorant 600     slide titles
display-sm   28 / 36    Cormorant 600     card titles
heading-lg   22 / 30    Inter 600         component headings
heading-md   18 / 26    Inter 600         label headings
body-lg      18 / 30    Inter 400         lead paragraphs
body         16 / 26    Inter 400         default body
body-sm      14 / 22    Inter 400         supporting copy
caption      12 / 18    Inter 500 SC      metadata, footnotes
code         15 / 24    JetBrains 400     monospaced
code-hex     14 / 22    JetBrains 500     hex strings
```

### 3.3 Typography rules

- **Headlines:** Cormorant Garamond, never tracking-tight; let the serif breathe.
- **Body sans:** Inter at `letter-spacing: -0.01em` for body, `0` for captions.
- **Small caps:** for metadata, axis labels, fact-card field names (`SIGNED AT`, `EVENT HASH`, `PARENT`).
- **Numerals in data displays:** use `font-variant-numeric: tabular-nums` so hex columns align.
- **Hex strings:** always in `--code-hex` gold, JetBrains Mono, never line-broken inside a token; use `word-break: break-all` only where unavoidable.

---

## 4. Layout & spacing

### 4.1 Spacing scale (8-point base, with one half-step)

```
space-0    0
space-1    4
space-2    8
space-3    12
space-4    16
space-5    24
space-6    32
space-8    48
space-10   64
space-12   96
space-16   128
space-20   192
```

### 4.2 Grid

- **12-column**, gutter `space-5` (24px), max content width `1200px`.
- **Slide canvas:** 1920×1080, safe area 80px inset.
- **Margin discipline:** outer page margin `space-10` desktop / `space-6` mobile.
- **Vertical rhythm:** baseline grid 8px; headlines snap to 24px increments.

### 4.3 Section pacing rule

For long-form layouts (one-pager, deck), alternate three section densities:
1. **Open** (heavy whitespace, single object) — slide opener / hero.
2. **Read** (balanced text + diagram) — body sections.
3. **Proof** (data-dense, code blocks, verification steps) — credibility moments.

Never put two **Proof** sections back-to-back without a **Read** between them.

---

## 5. Components

### 5.1 The Wax Seal (signature component — most important)

**Three states, never break the visual contract:**

| State | Color | Texture | Animation |
|---|---|---|---|
| Unsigned | `--paper-deep` outline only | engraved line-art, no fill | none |
| **Signed (valid)** | `--seal-crimson` solid + `--seal-wax-rim` highlight | wax pour with subtle organic edge, slight gloss | 600ms gentle pulse on `--verify-green-glow` ring once on load |
| Tampered (broken) | `--tamper-red` desaturated | seal cracked diagonally, two halves displaced ~6px | 200ms shake, then settle |

**Geometry:** circular, default 96px diameter. Center sigil = stylized "C/E" monogram (Canon × EPHEMERAL). On the perimeter: small caps ring text `· VERIFIED · CANON · ED25519 ·` (Cormorant small caps, 11px, tracking 0.15em).

**Use:** anchor for verification cards, hero centerpiece on Slide 1, favicon, social card.

### 5.2 Fact Card

The atomic content unit. Renders one signed fact.

```
┌────────────────────────────────────────────────┐
│  FACT  f_q1_acme_0001              [SEAL ✓]   │
│  ────────────────────────────────────────────  │
│  ENTITY        customer:acme                   │
│  CLAIM         Q1 revenue was EUR 127,000      │
│  SOURCE        gmail:msg_abc123                │
│  SIGNED AT     2026-04-24 09:03:12 UTC         │
│  SIGNER (kid)  canon/8a88e3dd7409f195          │
│  EVENT HASH    b0f3 7530 95… ·tap to expand·   │
│  PARENT        — genesis —                     │
└────────────────────────────────────────────────┘
```

- Background `--paper-bright`, 1px border `--paper-deep`, corner radius `4px` (sharp, document-like — NOT iOS-rounded).
- Field labels in small caps `--ink-soft`, 11px tracking 0.1em.
- Field values in JetBrains Mono `--ink-deep`, 14px.
- Hex collapses with middle ellipsis; click reveals full string in modal with copy button.
- Top-right corner hosts the wax seal (32px in this density).

### 5.3 Verification Step List

Ten numbered rows, each represents one of the verifier's 10 steps. State per row:

```
[1] [✓]  Decode COSE_Sign1 envelope         48 ms · ok
[2] [✓]  Validate protected header           2 ms · ok
[3] [✓]  Decode CBOR payload                12 ms · ok
[4] [✓]  Verify field count = 7              0 ms · ok
[5] [✓]  Compute SHA-256 event_hash          3 ms · ok
[6] [✓]  Reconstruct signing input          11 ms · ok
[7] [✗]  Ed25519 verify signature           14 ms · TAMPERED
[8] [—]  Validate kid format                skipped
[9] [—]  Match parent hash                  skipped
[10][—]  Confirm signer pubkey              skipped
```

- Step number in small caps, JetBrains Mono.
- ✓ glyph: `--verify-green` filled circle. ✗: `--tamper-red` X-cross. — : `--ink-soft` em-dash.
- Each row click reveals the byte-level detail.
- After a failure (✗), all subsequent steps render as `--ink-soft` "skipped" — never green.

### 5.4 Diagram blocks (the three-actor mental model)

Always label boxes with the metaphor + the technical name in caption:

```
┌──────────┐     JSON     ┌──────────┐     hex+QR     ┌──────────┐
│  AUTHOR  │ ───────────▶ │  NOTARY  │ ─────────────▶ │  WITNESS │
│  Canon   │              │  Signer  │                │ Browser  │
│ (Node.js)│              │  (Rust)  │                │  (WASM)  │
└──────────┘              └──────────┘                └──────────┘
   reads mail              seals fact                  verifies seal
```

- Box stroke: 1.5px `--ink-deep`.
- Arrows: 1.5px, with small-caps inline labels above.
- Captions in italic Cormorant 14px below each box.
- NEVER use rounded boxes. Sharp corners only — these are notarial documents, not app UI.

### 5.5 Buttons (sparingly)

| Variant | Background | Text | Border | Use |
|---|---|---|---|---|
| Primary | `--seal-crimson` | `--paper-bright` | none | one per screen max |
| Secondary | `--paper-bright` | `--ink-deep` | 1.5px `--ink-deep` | default action |
| Ghost | transparent | `--ink-deep` | none, underline | inline / link-style |
| Danger | `--tamper-red` | white | none | only for "Tamper this fact" demo button |

- **Padding:** 12px vertical / 24px horizontal.
- **Corner radius:** 2px (almost square — notarial seal aesthetic).
- **Hover:** -8% lightness on background, no scale transforms. We don't bounce.

### 5.6 Code block

```
┌─ stdin ──────────────────────────────────────┐
│ {"op":"sign","fact_id":"demo_1",            │
│  "entity":"customer:acme",                  │
│  "claim":"Q1 revenue was EUR 127,000",      │
│  "parent_hash":"",                          │
│  "created_at_ms":1713974400000}             │
└──────────────────────────────────────────────┘
```

- Background `--code-bg`, text `--code-fg`, monospaced, 14px / 22px.
- Top label strip `stdin` / `stdout` / `stderr` in small caps `--code-comment`, 10px.
- 4px left border in `--seal-crimson` for "look here" emphasis blocks.

---

## 6. Iconography

**Style: engraved line-art, not flat-design.**

- Stroke 1.5px, terminals slightly tapered.
- Reference vocabulary: feather quill, wax stick, signet ring, scroll, magnifying glass, compass, lighthouse, lock-and-key, scales-of-justice.
- Avoid: rounded "Material" icons, gradient icons, emoji.
- Color: `--ink-deep` default; `--seal-crimson` only for the "seal" / "sign" verb icons.

**Provided assets in repo:** `reference/validator/tools/canon-signer/docs/diagrams/*.svg` and the wax-seal logo. **Re-use these as the iconographic anchor** — Claude Design should treat them as canonical.

---

## 7. Motion

**Rule of thumb: motion is a credibility signal, not a delight pattern.**

| Element | Motion | Duration | Easing |
|---|---|---|---|
| Page enter | Subtle fade + 4px upward translate | 320ms | `cubic-bezier(0.2, 0, 0, 1)` |
| Wax seal stamp | Scale 0.85 → 1.0 + opacity, single bounce | 600ms | `cubic-bezier(0.25, 1.6, 0.4, 1)` |
| Verify pulse (green ring) | 0 → 1 → 0 opacity, scale 1 → 1.15 | 700ms | linear |
| Tamper shake | translateX(±4px), 3 cycles | 240ms | linear |
| Step list reveal | sequential, 80ms stagger per row | varies | `ease-out` |

**Never:** parallax-on-scroll, infinite loops, anything that reads as "marketing site." We are a document.

---

## 8. Imagery & texture

- **Parchment texture:** subtle (4–8% opacity) noise overlay on `--paper` backgrounds. Hand-made watercolor-paper feel.
- **Engraving plates:** 16th-century botanical / cartographic illustrations as section dividers (always desaturated to `--ink-mid` ink wash, never colored).
- **Wax-seal photography (only one):** real macro photo of pressed red wax seal, used exactly **once** in the deck — the cover. Everywhere else: vector seal.
- **No people photography. No stock.**

---

## 9. Voice & tone

| Trait | Yes | No |
|---|---|---|
| Register | precise, slightly formal, dry humor | casual, hyped, exclamation-heavy |
| Verbs | "seal", "verify", "witness", "attest", "stamp" | "unlock", "supercharge", "leverage" |
| Numbers | exact ("64 hex chars", "20 µs", "528 vectors") | hand-wavy ("super fast", "really secure") |
| Metaphor density | one anchor (wax seal) used consistently | mixed metaphors |
| Sentence length | mostly short. Two long ones per paragraph max. | long, qualified, hedge-heavy |

**One-line voice test:** would this sentence belong in a 1923 Bank of England auditor's letter, or in a 2020 SaaS landing page? We aim closer to the first.

**Banned words:** _unhackable_, _revolutionary_, _disruptive_, _AI-powered_ (we say "AI-assisted, human-validated"), _blockchain-grade_, _Web3_.

**Preferred phrases:**
- "tamper-evident, not tamper-proof"
- "production crypto, not hackathon crypto"
- "verifiable by anyone with a browser"
- "no server trust required"
- "the math is the receipt"

---

## 10. Accessibility & contrast

- **WCAG AA minimum** for all text.
- Body `--ink-deep` on `--paper` = 14.8:1 ✓.
- `--seal-crimson` on `--paper-bright` = 8.1:1 ✓ for headlines.
- `--verify-green` on `--paper-bright` = 5.4:1 ✓.
- **Never** rely on color alone to encode verify/tamper — always pair with the seal-broken icon and a text label.
- Focus rings: 2px `--seal-crimson` outline at 2px offset.
- Reduced-motion respected: replace pulse/shake with static state.

---

## 11. Asset re-use from the repo

When Claude Design reads the codebase, point it at:

| Path | What to reuse |
|---|---|
| `reference/validator/tools/canon-signer/docs/diagrams/` | All inline SVG diagrams — these define the existing visual language |
| `reference/validator/tools/canon-signer/web/index.html` + `style.css` | Existing verifier page — color & typography reference |
| `reference/validator/tools/canon-signer/docs/STORY.de.md` & `STORY.en.md` | Canonical brand voice samples |
| `reference/validator/tools/canon-signer/docs/HACKATHON.md` §5 | The 3-minute stage script — canonical pacing |
| `reference/validator/tools/canon-signer/docs/PRESENT-KIT.md` | QR-code + present-kit assets |

**Web Capture target:** `https://thepyth0nkid.github.io/empheral/` — capture this page so Claude Design has the live visual anchor.

---

## 12. The 30-second taste test

If a designed artifact passes this, it's on-brand:

1. ☐ Could a 19th-century notary recognize the metaphor?
2. ☐ Could a 21st-century cryptographer verify the technical accuracy of every label?
3. ☐ Is there exactly one wax seal visible per screen (not zero, not three)?
4. ☐ Are all hex strings in JetBrains Mono `--code-hex` gold?
5. ☐ Does the page work without color (print-friendly)?
6. ☐ Is the headline a Cormorant Garamond serif, not a sans?
7. ☐ Did we avoid every banned word from §9?

If 7/7 → ship. If ≤5/7 → revise.
