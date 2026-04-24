# HANDOFF.md — Was du jetzt in Claude Design machen musst

**Stand:** 2026-04-24, 23:xx Uhr. Hackathon ist morgen (25./26.04.).
**Du bist bereits auf claude.ai/design eingeloggt** und im Setup-Bildschirm.
**Vibe ist entschieden:** _Notarial Modern_ — siehe `DESIGN.md`.

> **Ziel der nächsten 60–90 Minuten:** Design-System gesetzt, eine erste Slide-Deck-Iteration und ein erster Prototyp-Walkthrough vorhanden. Morgen früh Polish.
> **Token-Tipp:** Setup zuerst. Wenn du das Design-System sauber lädst, hörst du danach auf, jeden Prompt mit "make it look like our brand" zu beginnen — das spart spürbar Tokens (Quasa-Studie, 30–40% Reduktion).

---

## 0. Du brauchst diese 4 Dateien (alle liegen in `planning/claude-design/`)

| Datei | Wozu | Wann verwenden |
|---|---|---|
| **`DESIGN.md`** | Brand-Tokens, Typo, Komponenten | **Setup-Phase** (jetzt) |
| **`BRIEF.md`** | Story-Copy, drei Audiences, Slogans | Beim Erstellen jedes Artefakts |
| **`SLIDE_OUTLINE.md`** | 12-Slide-Pitchdeck-Struktur | Tab "Slide deck" |
| **`PROTOTYPE_BRIEF.md`** | 6-Screen Hi-Fi-Prototyp | Tab "Prototype → High Fidelity" |

Alle vier sind **drop-in** geschrieben — du sollst sie kopieren oder hochladen, nicht selbst paraphrasieren.

---

## SCHRITT 1 — Design-System aufsetzen (15 Minuten)

Du bist gerade auf claude.ai/design im Setup. Linke Sidebar zeigt dir den Knopf **"Set up design system"** (orange).

### 1.1 Klick "Set up design system"

Claude Design fragt dich nacheinander nach:
- **Codebase / repo connection** _(optional, aber sehr empfehlenswert)_
- **Brand assets** (Logo, Farben, Fonts)
- **Design files** (Figma / Sketch / Bildmaterial)
- **Eine kurze Brand-Beschreibung**

### 1.2 Wenn nach Codebase / Repo gefragt wird

**Option A — GitHub-Connect (bevorzugt, wenn Claude Design das anbietet):**
- Repo: `github.com/ThePyth0nKid/empheral`
- Branch: `feat/canon-signer`
- Wichtigste Pfade, die Claude Design lesen soll:
  ```
  reference/validator/tools/canon-signer/docs/diagrams/
  reference/validator/tools/canon-signer/web/
  reference/validator/tools/canon-signer/docs/STORY.de.md
  reference/validator/tools/canon-signer/docs/STORY.en.md
  reference/validator/tools/canon-signer/docs/HACKATHON.md
  planning/claude-design/DESIGN.md       ← der Token-Anker
  planning/claude-design/BRIEF.md        ← der Story-Anker
  ```

**Option B — Manuell hochladen, falls kein GitHub-Connect:**
Lade diese Files einzeln hoch:
1. `planning/claude-design/DESIGN.md`
2. `planning/claude-design/BRIEF.md`
3. Alle SVGs aus `reference/validator/tools/canon-signer/docs/diagrams/`
4. `reference/validator/tools/canon-signer/web/index.html` + `style.css` (als ZIP wenn nötig)

### 1.3 Wenn nach "Brand description" gefragt wird

Paste **wörtlich** das hier rein:

> **Notarial Modern.** A wax seal for the digital age — sixteenth-century notarial gravitas meets twenty-first-century cryptography. Parchment-cream background (`#F4EBD9`), wax-seal crimson (`#8B1A1A`) as primary accent, phosphor verify-green (`#00785A`) only for confirmation signals. Display in Cormorant Garamond serif; body in Inter; code and hashes in JetBrains Mono. Sharp corners, not rounded — this is a notarial document, not an iOS app. Engraved line-art icons, not flat-design glyphs. **Three brand virtues in priority order: provability > permanence > precision.** Project: Canon × Canon-Signer × EPHEMERAL — cryptographic notarization of business facts, hackathon-ready for Big Berlin Hack 2026-04-26. Full token system in DESIGN.md.

### 1.4 Wenn nach "Web Capture" / "Capture from URL" gefragt wird

URL: `https://thepyth0nkid.github.io/empheral/`

Das ist deine Live-Verifier-Page — Claude Design soll sie als visuellen Anker erfassen.

### 1.5 Done-Kriterium für Schritt 1

Die linke Sidebar wechselt von "Set up design system" zu **"Design system: Notarial Modern"** (oder ähnlich). Eine "Recent designs"-Sektion erscheint, in der dein erstes Sample-Design mit deinen Farben/Fonts auftaucht.

> **Wenn das Sample falsch aussieht:** klick auf **"Edit design system"** und paste einzeln die Color- und Typography-Sections aus `DESIGN.md` §2 und §3.

---

## SCHRITT 2 — Slide Deck bauen (20 Minuten)

### 2.1 Klick auf den Tab **"Slide deck"** (oben in der Sidebar)

Project name: `Canon × EPHEMERAL — Big Berlin Hack`

### 2.2 Beim ersten Prompt paste:

> Build a 12-slide pitch deck for **Canon × Canon-Signer × EPHEMERAL** at Big Berlin Hack 2026-04-26.
>
> Use the **Notarial Modern** design system already loaded. Follow `planning/claude-design/SLIDE_OUTLINE.md` slide-by-slide — every layout, every headline, every visual element is specified there. Do not deviate from the wax-seal brand spine.
>
> Story source: `planning/claude-design/BRIEF.md`. Voice: precise, slightly formal, dry. Banned words list in BRIEF.md §9 Audience-A.5 must be respected.
>
> Format: 1920×1080. Speaker notes per slide as specified in SLIDE_OUTLINE.md.
>
> One wax seal per slide, never zero, never two. Cormorant Garamond display, never sans for headlines.

### 2.3 Auf das erste Render warten (~30–60 Sekunden)

Du bekommst einen 12-Slide-Deck-Vorschau. **Erwartet:**
- Cover (Slide 1) zeigt das große rote Wachssiegel zentriert auf Pergament-Cream.
- Cormorant Garamond auf den Headlines.
- Kein "modern flat" Vibe, sondern Druckwerk-Anmutung.

### 2.4 Inline-Editing-Pass (10 Minuten — nicht per Prompt!)

**Wichtig:** wenn etwas nicht passt, **klick auf das Element** und paste einen kurzen Inline-Comment statt einen langen Prompt zu schreiben. Beispiele:
- Auf Slide 1 Seal klicken → "make this 20% bigger and add the green-glow ring per DESIGN.md §5.1"
- Auf Slide 11 Zahlen klicken → "use JetBrains Mono tabular-nums in code-hex gold per DESIGN.md §3.2"
- Auf eine Headline klicken die zu klein ist → "should be display-md (40/48) per DESIGN.md §3.2"

Token-effizienter und präziser als ein neuer Prompt.

### 2.5 Variations anfragen für Slide 1 + 12

Diese zwei Slides sind die Ankerslides — bitte um 3 Varianten:
> Show me 2 alternative layouts for slide 1 (cover) and slide 12 (close), all on-brand, all using the wax-seal as the central element.

Nimm das beste pro Slide.

### 2.6 Done-Kriterium Slide Deck

Walke einmal durch alle 12 Slides. Frag dich pro Slide den **DESIGN.md §12 Taste-Test**:
1. ☐ Cormorant Garamond auf der Headline?
2. ☐ Genau ein Wachssiegel sichtbar?
3. ☐ Hex-Strings in JetBrains Mono Gold?
4. ☐ Keiner der gebannten Wörter aus BRIEF.md §9?
5. ☐ Pergament-Hintergrund, nicht weiß?

Wenn 5/5: **export PPTX** (für USB-Stick) **+ hosted URL** (für Live-Pitch). Beides.

---

## SCHRITT 3 — Hi-Fi Prototyp bauen (25 Minuten)

### 3.1 Zurück zur "Designs"-Übersicht, klick **"Prototype"** Tab → **"High fidelity"**

Project name: `Canon — 90-Second Walk-Through`

### 3.2 Beim ersten Prompt paste:

> Build a high-fidelity, six-screen interactive prototype for **Canon × Canon-Signer × EPHEMERAL**, using the **Notarial Modern** design system already loaded.
>
> Follow `planning/claude-design/PROTOTYPE_BRIEF.md` screen-by-screen exactly. Story source: `planning/claude-design/BRIEF.md`.
>
> Brand virtues, in order: provability > permanence > precision. Single wax seal per screen. Cormorant Garamond display, Inter body, JetBrains Mono code/hex.
>
> The wax-stamp animation on screen 4 and the seal-cracking animation on screen 5 are **the two motion moments that must work**. Specs in PROTOTYPE_BRIEF.md §2.
>
> Capture the live verifier at `https://thepyth0nkid.github.io/empheral/` for the visual anchor on screen 6's QR target.
>
> Output: zero JS-framework, single HTML, mobile-responsive at 768px and 420px. Total bundle <200 KB.

### 3.3 Erstes Render abwarten

### 3.4 Tamper-Animation testen (das ist der Kern-Moment)

- Navigiere zu Screen 5
- Klick die rote `[Change one byte ⚠]` Button
- **Erwartet:** Hex-Char flippt, Siegel shaket, Siegel cracked (rot, displaced), Step 7 wird rot, Banner erscheint mit "412 ms verification time"

Wenn das nicht passiert → Inline-Comment auf den Button:
> follow PROTOTYPE_BRIEF.md §2 SCREEN 5 sequence exactly: 0–100ms hex flip, 100–200ms shake, 200–500ms crack with 6px displacement, 300–700ms step-7 red flash, 700–1000ms steps 8–10 fade to skipped, 1000ms tamper banner appears

### 3.5 Mobile-Check

Prototype-View auf 420px Breite stellen (Claude Design hat einen Device-Toggle):
- Hero seal nicht mehr 480px sondern 240px
- Spalten stacken vertikal
- QR auf Screen 6 noch lesbar

### 3.6 Done-Kriterium Prototyp

PROTOTYPE_BRIEF.md §9 Taste-Test:
1. ☐ Jeder Screen passt alle 7 DESIGN.md §12-Tests?
2. ☐ Genau ein Wachssiegel pro Screen?
3. ☐ Funktioniert ohne Sound, ohne Farbe (Print-Test)?
4. ☐ Tamper-Animation fühlt sich "clever" an (nicht plump)?
5. ☐ QR auf Screen 6 scannt zur Live-Verifier-Page?
6. ☐ Walk durch alle 6 Screens dauert ≤ 90 Sekunden?

7/7 → **export Handoff-Bundle**.

---

## SCHRITT 4 — Hand zurück an mich (im Terminal)

### 4.1 Handoff-Bundle in Claude Design exportieren

Im Prototype-View: **"Export → Handoff bundle"** (oder "Export to Claude Code").

Das gibt dir entweder:
- (a) einen Download-ZIP, oder
- (b) einen Claude-Code-Befehl zum Pasten in dein Terminal.

### 4.2 Bei Option (a) — ZIP herunterladen

Speichere das ZIP nach:
```
C:\Users\nelso\Desktop\empheral\planning\claude-design\handoff\
```

(Ich erstelle den Ordner gleich vor — siehe unten.)

### 4.3 Bei Option (b) — Claude-Code-Befehl

Paste den Befehl **in deinem Terminal hier**, in der laufenden Session bei mir. Ich integriere das Bundle dann in:
```
reference/validator/tools/canon-signer/web/showcase/
```
als Schwester-Verzeichnis zur Live-Verifier-Page.

### 4.4 Slide Deck — PPTX exportieren

Speichere die PPTX nach:
```
C:\Users\nelso\Desktop\empheral\planning\claude-design\deck\canon-ephemeral-pitch.pptx
```

Plus die hosted URL — paste die hier in den Chat, ich pinne sie in `HACKATHON.md`.

### 4.5 Sag mir kurz Bescheid

Wenn alles exportiert ist, schick mir hier:
1. Pfad zum Handoff-Bundle (oder Befehl gepasted)
2. Pfad zur PPTX
3. Hosted URL des Decks
4. Hosted URL des Prototypen

Dann mache ich:
- Bundle integrieren in `web/showcase/`
- Hosted-URLs in `HACKATHON.md` und `PRESENT-KIT.md` referenzieren
- README-Update mit "Try the 90-second walk-through"-Sektion
- Optional: Commit auf `feat/canon-signer` mit allem

---

## SCHRITT 5 — Falls etwas schiefgeht

### "Claude Design ignoriert mein Design System"

→ Re-import: gehe zu Settings → Design System → "Re-sync from codebase". Wenn das nicht hilft, **lösche das Design System komplett** und mache Schritt 1 nochmal mit `DESIGN.md` als ersten Upload.

### "Es sieht aus wie eine Standard-SaaS-Landing-Page"

→ Inline-Comment auf das offending Element:
> remove all rounded corners (radius 2px max per DESIGN.md §5), replace gradients with flat parchment, replace any sans-serif headline with Cormorant Garamond 600

### "Token-Limit erreicht / langsam"

→ Pause, mache lieber inline-edits statt neue Prompts. Wenn wirklich am Limit: warte auf Reset oder upgrade Plan kurz auf Max ($100). Du brauchst die Tokens für morgen früh den Polish-Pass.

### "Wachssiegel sieht aus wie ein Tomatendip"

→ Inline-Comment auf das Siegel:
> use the SVG seal asset from `reference/validator/tools/canon-signer/docs/diagrams/wax-seal.svg` directly. Color: `--seal-crimson` (#8B1A1A), highlight rim `--seal-wax-rim` (#B23E3E). Subtle gloss, organic edge, NOT a flat circle.

---

## SCHRITT 6 — Zeitplan (heute Abend / morgen früh)

| Zeit | Block |
|---|---|
| **heute, jetzt – +90 Min** | Schritte 1–4 durchziehen (Setup + Deck + Prototype + Export) |
| **heute, danach** | 30 Min Schlaf-Reserve. Nicht weiter polishen. Der Pitch ist morgen, du brauchst die Energie. |
| **morgen früh, +30 Min** | Polish-Pass: 1 Variation pro Slide checken, Tamper-Animation 3× üben |
| **morgen mittag** | `bash scripts/demo.sh` einmal lokal durchlaufen lassen (Failsafe) |
| **morgen, vor Pitch** | HACKATHON.md §10 Vor-dem-Pitch-Checkliste durchgehen |

---

## Was ICH parallel mache, während du in Claude Design bist

Nichts ungefragt, aber **ich kann gerade**:

- (a) `planning/claude-design/handoff/` Ordner anlegen (1 Sek)
- (b) Bundle integrieren sobald du exportiert hast
- (c) Die 5 Files committen auf `feat/canon-signer` (sag mir wenn ja)
- (d) `HACKATHON.md` Schritt-Update mit Claude-Design-Kontext schreiben (wenn du willst)
- (e) Hier ruhig bleiben und warten bis du Hilfe brauchst

Sag einfach **"a"**, **"b"**, **"c"**, **"d"** oder **"warte"**. Ich mache nichts ungefragt.

---

## Ein letzter Hinweis

**Du bist Solo-Dev mit dem Pitch in <24h.** Der Plan oben ist optimistisch. Wenn du nur **Schritt 1 (Setup) + Schritt 2 (Deck)** schaffst und der Prototyp morgen früh entsteht — auch geil. Das Slide-Deck allein ist genug für den Pitch. Der Prototyp ist Bonus / leave-behind.

**Priorität, falls Zeit knapp wird:**
1. Slide-Deck PPTX (für Bühne) ← **must**
2. Hosted-URL des Decks (für Backup) ← **must**
3. Prototyp ← **nice-to-have**

Du hast eine real funktionierende Live-Verifier-Page (`thepyth0nkid.github.io/empheral`). Die ist dein eigentlicher Demo-Anker. Slides + Prototyp sind die Bühne dafür.

**Geh da rein und zeig's.**
