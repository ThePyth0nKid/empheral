# PROTOTYPE_BRIEF.md — Interactive High-Fidelity Prototype

**Target:** an interactive web prototype, hosted by Claude Design, that anyone can click through in 60 seconds and feel the entire Canon × Canon-Signer × EPHEMERAL story.

**Use in Claude Design:** open the **Prototype → High Fidelity** tab, paste this as the prompt source. Web Capture target: `https://thepyth0nkid.github.io/empheral/`.

---

## 0. Why a prototype (separate from the live verifier)

The **live verifier** at `thepyth0nkid.github.io/empheral` is real WASM crypto — but it expects you to come with a URL containing real hex data. That's right for an auditor. It's wrong for a 30-second showcase.

The **prototype** is a **scripted, opinionated walk-through** of the same story, with pre-loaded examples, narrative captions, motion that explains _why_ each step matters, and a "Tamper this!" red button that breaks the seal in front of you. It is the demo a non-technical visitor remembers six months later.

| | Live verifier | Prototype (this brief) |
|---|---|---|
| Crypto | real WASM, real Ed25519 | simulated, with real cryptographic vocabulary |
| Audience | auditor with a URL | journalist, judge, investor, on a first visit |
| Goal | _verify a fact_ | _understand the system_ |
| Time | <4 sec | 60–90 sec narrated walk |

Both are correct. The prototype links to the live verifier as the credibility punctuation.

---

## 1. The 6 prototype screens

The prototype is a single-page experience with horizontal scroll-snap or a 6-step "next →" navigation. Each step is one screen.

```
[1] Hero            "A wax seal for the digital age."
[2] The Problem     "What's the receipt for a sentence in an e-mail?"
[3] The Metaphor    "16th-century mail was already a notarial system."
[4] The Demo        Click "Sign this fact" → wax seal stamps live
[5] The Tamper      Click "Change one byte" → seal cracks, step 7 lights red
[6] The Bridge      Link to live verifier + QR + GitHub + share
```

Each step inherits the DESIGN.md system. Cormorant headlines, parchment background, single wax seal per screen.

---

## 2. Screen-by-screen spec

### SCREEN 1 — Hero ("Land the seal")

**Hero element:**
A 480px wax seal, centered, animating in from invisible.
- 0–200ms: seal grows from 0% to 100% scale with cubic-bezier(0.25, 1.6, 0.4, 1) (the wax-stamp easing).
- 200–400ms: subtle 1° rotation as if pressed slightly off-axis.
- 600ms: green-glow ring (`--verify-green-glow`) pulses outward once and fades.
- 800ms: caption fades in below.

**Headline (below seal):**
```
A wax seal for the digital age.

Sealed once. Verifiable forever.
```

**Sub-caption:**
```
Canon × Canon-Signer × EPHEMERAL · Big Berlin Hack 2026
```

**Bottom CTA:**
A single button (Secondary variant per DESIGN.md §5.5):
> **`See how it works  →`**

On hover: 1px down-translate, no scale, no color shift beyond -8% lightness.

---

### SCREEN 2 — The Problem ("Show what's broken")

**Layout:** split 50/50.

**Left half:** an animated "screenshot of an e-mail" mock — a 480px window-chrome card showing:

```
From:    meyer@acme.de
To:      finance@example.com
Subject: Q1 numbers

  Hi team —

  Our Q1 came in at 127k EUR, looking good.
  Will share the deck tomorrow.

  Best, M.
```

A faint diagonal stamp `EDITABLE IN 5 SECONDS` overlays it in `--tamper-red` at 25% opacity.

After 1.5 seconds, the number `127k EUR` slowly auto-types over to `427k EUR` in `--tamper-red`, with no other visual change. Subtle. Disturbing.

**Right half:** the question.

```
Headline:
What's the actual receipt
for a sentence in an e-mail?

Body:
Today, every claim from a customer
lives in a mail no one can verify.
Screenshots are editable in seconds.
Database entries trust the operator.

For six months we've all just…
agreed not to ask too hard.
```

**Bottom CTA:**
> **`Show me the alternative  →`**

---

### SCREEN 3 — The Metaphor ("Land the analogy")

**Hero element:** a single illustration — line-art engraving of a 16th-century scribe pressing wax onto a folded letter. ~560px tall, centered.

**Headline (above):**
```
Sixteenth century had this figured out.
```

**Three properties block (below illustration, three columns):**

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  HARD TO FORGE   │  │ VISIBLY BROKEN   │  │ PUBLICLY VERIFIED│
│                  │  │                  │  │                  │
│  The crest       │  │  Any tampered    │  │  Anyone who knew │
│  could not be    │  │  letter showed   │  │  the crest could │
│  copied easily.  │  │  it instantly.   │  │  confirm it.     │
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

Below the three columns, a single sentence pull-quote in Cormorant italic 28px:
```
We rebuilt this.
For digital business claims.
```

Then a subtle bridge sentence in Inter 18px:
```
Wax becomes Ed25519. The crest becomes a public key.
The messenger becomes a hex string that fits in a QR code.
```
(`Ed25519`, `public key`, `hex string` rendered inline in JetBrains Mono `--code-hex`.)

**Bottom CTA:**
> **`Watch a fact get sealed  →`**

---

### SCREEN 4 — The Demo ("Stamp it in front of you")

**Layout:** vertical, three states.

**State A — Unsigned (initial):**
- Top: a fact-card per DESIGN.md §5.2, but the seal slot in top-right shows the **outline-only** unsigned variant.
- The card shows the 9 fields of the canonical demo fact (`f_q1_acme_0001`, customer:acme, etc., from BRIEF.md §5).
- Below the card, a Primary button:
  > **`Press the seal  ▮`**

**State B — Signing animation (200–800ms after click):**
- The seal-slot transitions: outline → wax-fill expanding outward.
- Simultaneously, three small captions float briefly to the right of the card, then fade:
  ```
  CBOR encode 7 fields
  COSE_Sign1 envelope
  Ed25519 sign · 0.3 ms
  ```
- The EVENT HASH field, previously empty, fills in character-by-character as a streaming hex output: `b0f3 7530 95a4 c2e1…`

**State C — Sealed (after 1 second):**
- The seal is fully red, with the green-glow pulse fired once.
- The fact-card now has a `[✓ SEALED]` indicator.
- A new section appears below the card, titled **"What just happened, in 10 steps"**, showing all 10 verification steps as ✓ in `--verify-green` with their per-step timings.

**Below the card:**
A subtle reveal-on-hover: hovering "EVENT HASH" or "SIGNATURE" expands them to full hex with a copy button.

**Bottom CTA:**
> **`Now break it  →`**

---

### SCREEN 5 — The Tamper ("Make the failure mode unforgettable")

**Layout:** the same fact-card as screen 4, **already sealed**, plus a danger button below.

**Initial state:** card looks identical to screen 4 state C — green seal, all 10 steps ✓.

**Below the card:**
A row with two buttons:
- Primary danger (per DESIGN.md §5.5): `[ Change one byte ⚠ ]`
- Ghost: `[ Reset ]`

**On click of "Change one byte":**

1. **0–100ms:** in the SIGNATURE field, the last hex character flips visibly (`…edaf` → `…edae`) with a brief `--tamper-red` flash.
2. **100–200ms:** the wax seal **shakes** (translateX ±4px three times, per DESIGN.md §7).
3. **200–500ms:** the seal **cracks diagonally** — split into two halves displaced 6px, color shifts from `--seal-crimson` to `--tamper-red`.
4. **300–700ms:** in the 10-step list, step 7 (`Ed25519 verify`) flashes red ✗.
5. **700–1000ms:** steps 8–10 fade to `--ink-soft` em-dash "skipped" state.
6. **1000ms:** a banner appears below the card:
   ```
   ┌─────────────────────────────────────────────────────────────┐
   │  ✗ TAMPERED                                                 │
   │  Signature verify failed at step 7.                         │
   │  Verification time to detect: 412 milliseconds.             │
   │                                                             │
   │  There is no "almost-valid". There is valid, or there is    │
   │  not. The seal is the answer.                               │
   └─────────────────────────────────────────────────────────────┘
   ```
   Banner background: `--tamper-red-bg`. Border: 1.5px `--tamper-red`. Text: `--ink-deep`.

**Reset button:** restores screen 4 state C.

**Bottom CTA:**
> **`See it on the live verifier  →`**

---

### SCREEN 6 — The Bridge ("Send them home with proof")

**Layout:** centered, single moment, three actions.

**Hero element:**
A 320px QR code, parchment-framed with `--seal-crimson` accent corners (per DESIGN.md §5 + slide 12). The QR encodes a real share URL pointing at the live verifier with a pre-loaded valid demo fact.

**Headline (above QR):**
```
Verify it yourself, right now.
```

**Sub-caption (below QR):**
The full URL in JetBrains Mono `--ink-deep`:
```
thepyth0nkid.github.io/empheral/?e=84581b…a2d1c0d&pk=ed25519:iojj…
```

**Three action cards below (horizontal):**

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  OPEN THE        │  │  READ THE        │  │  CLONE THE       │
│  VERIFIER        │  │  SOURCE          │  │  REPO            │
│                  │  │                  │  │                  │
│  Live page,      │  │  STORY.md +      │  │  Apache-2.0/MIT  │
│  real WASM,      │  │  TECHNICAL.md    │  │  feat/canon-     │
│  4-second walk.  │  │  on GitHub.      │  │  signer branch.  │
│                  │  │                  │  │                  │
│  [Open  →]       │  │  [Read  →]       │  │  [git clone  →]  │
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

**Footer:**
```
Nelson Mehlis · nelson@ultranova.io
github.com/ThePyth0nKid/empheral · Big Berlin Hack 2026-04-26
```

**Closing motion:** a final wax-seal silhouette fades in at 30% opacity behind the QR, single pulse.

---

## 3. Interactivity contract (the must-work behaviors)

Even at hi-fi prototype level, these interactions MUST be wired:

| Interaction | Effect | Why |
|---|---|---|
| Hover EVENT HASH on fact card | Expand middle ellipsis to full hex | Auditors check hashes |
| Hover SIGNATURE on fact card | Expand to full hex with copy button | Same |
| Click "Press the seal" on screen 4 | Run the signing animation, fill EVENT HASH live | The whole demo hinges on this |
| Click "Change one byte" on screen 5 | Run the tamper sequence end-to-end | The whole demo hinges on this |
| Click "Reset" on screen 5 | Restore green-seal state | Let visitors re-experience |
| Click QR / Open verifier | Open live verifier in new tab | The credibility bridge |

**Non-interactivity:** the 10-step list rows are decorative on the prototype (they expand on the real verifier, not here — keeps the prototype focused).

---

## 4. Motion budget (don't overdo it)

**Total prototype motion budget: <8 seconds across the entire walk.**

- Screen 1 hero seal: 800ms.
- Screen 2 number-edit reveal: 1500ms.
- Screen 4 sign animation: 1000ms.
- Screen 5 tamper animation: 1200ms.
- All transitions: 320ms cross-fade.

**Banned motion:** parallax, scroll-snap "wow" effects, anything that says "marketing site." We are a notary's office — not a SaaS landing page.

---

## 5. Empty-state & error handling (quality signal)

Even for a prototype, these tell Claude Design to render the un-glamorous states:

- **Loading:** thin parchment-rule progress bar, `--seal-crimson`. Never a spinner.
- **Failure to load:** the broken-seal icon at 96px with caption "_The page didn't load. Try refreshing._" — same visual vocabulary as a tamper-failure.
- **Reduced-motion:** disable all animations; show end-states directly.

---

## 6. Mobile / responsive

- **Breakpoints:** 1440 / 1024 / 768 / 420.
- **Mobile (≤768px):** stack columns vertically; reduce hero seal to 240px; QR code shrinks to 280px but parchment frame remains.
- **Touch:** all hover-interactions become tap-to-toggle.
- **The wax seal scales down to 64px in mobile fact-cards** but never below.

---

## 7. Performance & weight (we mention this on stage)

Targets:
- **<200 KB total** for the prototype (HTML + CSS + inline SVG + minimal JS).
- **No JS framework** (matches DESIGN.md zero-framework brand virtue).
- **One web font load** — Cormorant Garamond + Inter + JetBrains Mono via system + woff2 fallback.
- **Loads cold in <800 ms** on 4G.
- **All SVGs inline** — no external requests.

These are also brand statements: _we don't carry weight we don't need_.

---

## 8. Hand-off package (when prototype is ready)

When Claude Design says "prototype done," request the **Handoff bundle** export. It should contain:

- `index.html` (single-file or 6-screen split — both work)
- `style.css`
- inline SVGs (seal, fact-card, diagram, QR frame)
- screenshots at 1920×1080 of all 6 screens (PNG)
- a `prompt.md` containing the exact prompt history (for re-generation)

Drop this into `planning/claude-design/handoff/` and ping me — I can integrate it into `reference/validator/tools/canon-signer/web/showcase/` as a sibling to the live verifier.

---

## 9. The taste test (per DESIGN.md §12)

Before declaring "ship":

1. ☐ Does each screen pass all 7 brand-test bullets from DESIGN.md §12?
2. ☐ Is there exactly **one** wax seal visible per screen?
3. ☐ Does the prototype work without sound? Without color (print-test)?
4. ☐ Does the tamper animation make a non-technical viewer say _"oh, that's clever"_?
5. ☐ Does the QR on screen 6 actually scan and open the live verifier?
6. ☐ Total time to walk all 6 screens, narrated: ≤ 90 seconds?

7/7 → ship. Anything less → revise.

---

## 10. The prompt to drop into Claude Design

When you start the High-Fidelity prototype in Claude Design, paste this as the kickoff prompt (after attaching DESIGN.md + BRIEF.md + this file):

> Build a high-fidelity, six-screen interactive prototype for **Canon × Canon-Signer × EPHEMERAL**, using the design system in `DESIGN.md` and the story in `BRIEF.md`. Follow the screen-by-screen spec in `PROTOTYPE_BRIEF.md` exactly.
>
> Brand virtues, in order: **provability > permanence > precision**. Aesthetic: notarial modern — parchment cream background, wax-seal crimson, Cormorant Garamond display, Inter body, JetBrains Mono code/hex.
>
> The wax seal is the brand spine. Exactly one seal per screen. Animate the sign and tamper sequences exactly per `PROTOTYPE_BRIEF.md` §2 screens 4 and 5.
>
> No JS framework. Single-file or split, your call. <200 KB total. Mobile-responsive at 768px and 420px.
>
> Capture the live verifier at `https://thepyth0nkid.github.io/empheral/` for the visual anchor on screen 6's QR target.
>
> Output a deployable hi-fi prototype + a handoff bundle ready to drop into `reference/validator/tools/canon-signer/web/showcase/`.
