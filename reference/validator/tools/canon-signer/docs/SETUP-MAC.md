# Mac-Setup — Canon Verifier in 5 Minuten

Der minimale Pfad vom frisch aufgeklappten MacBook zur bühnentauglichen
Demo.  Keine Dev-Toolchain, kein Rust, kein Node — nur das, was für
den Auftritt zählt.

---

## Schritt 1 · Repo holen

Terminal öffnen (Cmd+Space → „Terminal").

```bash
cd ~/Desktop
git clone https://github.com/ThePyth0nKid/empheral.git
cd empheral
```

Bei macOS ist Git bereits vorinstalliert.  Falls Git nach einer
Xcode-Installation fragt: **Ja, installieren** (ein paar Minuten).

---

## Schritt 2 · Live-URL testen

```bash
open https://thepyth0nkid.github.io/empheral/
```

Safari öffnet die Seite.  Du solltest sehen:
- Canon-Wax-Seal-Logo + „Canon Verifier"
- Textfelder + drei Buttons

**Klick „Load demo fact" → klick „Verify" → grüner Wachssiegel.**

Wenn das funktioniert: **du bist bühnenfähig.**

---

## Schritt 3 · Lokalen Backup-Server starten

Für den Fall, dass die Venue-Wi-Fi stirbt.  Zweites Terminal-Fenster
(Cmd+N):

```bash
cd ~/Desktop/empheral/reference/validator/tools/canon-signer/web
python3 -m http.server 8080
```

Das läuft, bis du Ctrl+C drückst.  Dann im Browser einen zweiten Tab:

```bash
open http://localhost:8080/
```

Wenn dieser Tab genauso aussieht wie die Live-URL — **du hast ein
voll funktionsfähiges Backup, offline-tauglich**.  Lass das Terminal-
Fenster vor der Bühne offen.

---

## Schritt 4 · QR-Code aufs Handy (oder aufs Papier)

QR-Datei liegt im Repo:

```
~/Desktop/empheral/reference/validator/tools/canon-signer/docs/assets/canon-verifier-qr-demo.png
```

Option A — **aufs Handy senden**: AirDrop-Button in Finder, an dein
iPhone schicken, in Fotos speichern.  Auf der Bühne dann: Bild öffnen,
Handy zur Jury drehen.

Option B — **ausdrucken**: Doppelklick → Cmd+P → min. A5-Größe, matt.
Jury in der hintersten Reihe soll ihn aus ~3 m scannen können.

Scan-Test mit deinem eigenen Handy:
- Kamera öffnen
- Auf den QR zielen
- Link tippen
- Sollte in Safari landen und **automatisch grüner Wachssiegel in ~2 s**

---

## Schritt 5 · Skript zum Üben

Datei öffnen:

```bash
open ~/Desktop/empheral/reference/validator/tools/canon-signer/docs/STAGE-SCRIPT.de.md
```

Das ist das **wortwörtliche** Bühnen-Skript, 3 Minuten, mit Zeit-
Markierungen und Cue-Punkten („jetzt Verify klicken", „jetzt Hex-Zeichen
ändern").

**Einmal mit Stoppuhr durchlesen.**  Ziel: genau 3:00.

Wenn du länger brauchst: der Architektur-Block (02:10) ist der einzige,
den du gefahrlos kürzen kannst.  Alles andere ist tragend.

Zum Üben auf Englisch: gleiches Skript auf Englisch unter
`STAGE-SCRIPT.en.md`.

---

## Am Veranstaltungstag — 30-Minuten-Checkliste

- [ ] MacBook voll geladen, Kabel in der Tasche
- [ ] Safari/Chrome im **Fullscreen** (Cmd+Ctrl+F), Tab gepinned
- [ ] Live-URL geladen, WASM im Cache, Felder leer (Clear-Button)
- [ ] Zweites Tab: `localhost:8080` läuft als Backup
- [ ] QR auf dem Handy **oder** gedruckt in der Tasche
- [ ] Wasserflasche
- [ ] Handy auf lautlos
- [ ] Tief durchatmen

---

## Wenn was schiefgeht

| Symptom | Fix in 3 Sekunden |
|---|---|
| Live-URL lädt nicht | Zum `localhost:8080`-Tab wechseln, weiterreden |
| `localhost:8080` auch tot | Terminal: `python3 -m http.server 8080` neu starten (aus `web/`-Ordner) |
| Verify-Button tot | Einmal Cmd+R.  WASM lädt neu. |
| Alles tot | QR in die Kamera halten und sagen: *„Hier ist die URL — scannt selbst"*.  Das ist eine **Feature-Demo**, kein Patzer. |

---

**Das war's.** Alles andere (Rust, Cargo, wasm-pack, Node) ist für die
Bühne **nicht** nötig.  Schlaf gut.
