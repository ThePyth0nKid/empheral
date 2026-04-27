# Present Kit — Canon @ Berlin Hack 2026-04-25/26

Everything you need for the stage, in one index.

---

## The narrative docs

| File | When you read it |
|---|---|
| [`STORY.de.md`](STORY.de.md) | **Deutsche Gesamterzählung** — ~1.600 Wörter, 7 Sektionen.  Zum Verstehen, Recherchieren, Zitieren. |
| [`STORY.en.md`](STORY.en.md) | **English master narrative** — ~1,800 words, 7 sections.  For translation practice and reference. |

Both have identical section numbering so you can line them up side-by-
side while rehearsing.

---

## Stage scripts (what you actually say)

| File | When you read it |
|---|---|
| [`STAGE-SCRIPT.de.md`](STAGE-SCRIPT.de.md) | **Deutsches Bühnen-Skript** — 3-Min Demo + 2-Min Q&A.  Zeit-annotiert, mit Cue-Markern und Backup-Antworten. |
| [`STAGE-SCRIPT.en.md`](STAGE-SCRIPT.en.md) | **English stage script** — same structure. |

These are **verbatim** — designed so you can read them aloud under
rehearsal conditions and time yourself with a stopwatch.

---

## Physical artefacts

### QR codes — `docs/assets/`

| File | Content | Use |
|---|---|---|
| `canon-verifier-qr-basic.png` | bare verifier URL | Slide / handout — scanner lands on page, must click "Load demo fact" manually |
| `canon-verifier-qr-basic.svg` | same, vector | Large prints, fliers |
| `canon-verifier-qr-demo.png`  | URL **with demo fact pre-loaded** | **Recommended for stage** — one scan, auto-verifies, instant green seal |
| `canon-verifier-qr-demo.svg`  | same, vector | Large prints |

Regenerate any time via:

```bash
cd reference/validator/tools/canon-signer
python scripts/make-qr.py
```

The script is idempotent and reads the pinned demo envelope from
`crates/canon-verify-wasm/tests/fixtures/mod.rs`, so the QR stays in
lockstep with the test fixtures — no drift.

### Print guidance

- **Minimum printed size:** 6 cm × 6 cm (jury in the back row can scan
  from ~3 m).
- **Paper:** matte is better than glossy — camera glare on a laminated
  card kills scanning reliability on stage lights.
- **Margin:** keep at least 1 cm of white space around the QR (the
  generator already adds a 4-module quiet zone, but don't crop it).

---

## Live URL

**https://thepyth0nkid.github.io/empheral/**

(Hosted on GitHub Pages from `main`.)

---

## Rehearsal checklist (run through the evening before)

- [ ] Read `STORY.{de,en}.md` aloud once each, ignoring the time.
      Make sure you **understand** every sentence — don't recite what
      you don't believe.
- [ ] Read `STAGE-SCRIPT.de.md` with a stopwatch.  Target: exactly
      3:00.  If you run long, cut from 02:10 (architecture) — everything
      else is load-bearing.
- [ ] Repeat with `STAGE-SCRIPT.en.md`.
- [ ] Do the **tamper move** three times on a live browser so your
      hand knows which hex digit to flip without looking.
- [ ] Test the projector resolution — on some projectors the yellow
      preview banner can cut off the top nav.  If so, zoom the browser
      to 110 % to give the main panel more room.
- [ ] Scan the QR code with your own phone.  If it auto-verifies and
      stamps green — ship.

---

## Day-of checklist (30 min before stage)

- [ ] Laptop charged + charger in bag
- [ ] Browser fullscreen, tab pinned, fields cleared
- [ ] Backup: local copy of the page served via `python -m http.server`
      on a separate tab, in case GitHub Pages has an outage
- [ ] QR printout in hand — **demo** variant, not basic
- [ ] Water bottle
- [ ] Phone on silent but camera ready (you may want to scan your own
      QR as part of the show)
- [ ] Deep breath.

---

## If something goes wrong mid-demo

Three scenarios, three simple fallbacks:

| What breaks | What you say | What you do |
|---|---|---|
| Wi-Fi dies | *"Watch — we just lost Wi-Fi.  It still runs."* | Keep clicking.  The WASM is cached. |
| Page won't load fresh | *"Let me switch to the local copy."* | Open the `python -m http.server 8080` tab. |
| Verify button doesn't respond | *"Small load hiccup, one moment."* | Refresh once.  It'll come back.  If not, fall back to explaining the 10 steps from a screenshot. |

The **emotional key** is: never panic-look at the laptop.  Keep your
eyes on the jury, talk through the hiccup, and the audience will
forgive anything.
