# Mac-Setup (Full Dev) — Canon Signer end-to-end

Der **komplette** Weg: Rust-Toolchain, wasm-pack, Node, alles.  Du kannst
damit das Repo bauen, Tests fahren, die WASM neu kompilieren, und bei
Bedarf Änderungen am Signer/Verifier machen.

**Dauer:** ~30–45 Minuten inkl. aller Downloads.
Für den reinen Bühnen-Pfad (ohne Toolchain) siehe `SETUP-MAC.md`.

---

## 0 · Voraussetzungen prüfen

Terminal öffnen (Cmd+Space → „Terminal").

```bash
sw_vers                 # macOS-Version
uname -m                # arm64 = Apple Silicon, x86_64 = Intel
git --version           # falls nein: wird über Xcode CLI nachgeholt
```

Wenn `git` nicht gefunden wird:

```bash
xcode-select --install
```

Dialog bestätigen, warten (~5 min).

---

## 1 · Homebrew installieren

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Nach Installation zeigt brew zwei Zeilen an, die du in **deine Shell
laden** sollst (irgendwas mit `eval "$(...)"`).  Genau die ausführen, und
dann:

```bash
brew --version          # verifiziert dass brew im PATH ist
```

---

## 2 · Rust-Toolchain via rustup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Default-Installation (Option 1, Enter drücken).  Danach **neues
Terminal** öffnen oder:

```bash
source "$HOME/.cargo/env"
rustc --version         # sollte 1.82+ zeigen
cargo --version
```

Pinne die Toolchain im Repo-Root:

```bash
# wird später nach dem Clone gemacht — hier nur merken
```

---

## 3 · wasm-pack + wasm32-Target

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
rustup target add wasm32-unknown-unknown
wasm-pack --version
```

---

## 4 · Node.js (für headless WASM-Tests)

```bash
brew install node
node --version          # 20+
npm --version
```

(Falls du `nvm` bevorzugst: `brew install nvm`, dann `nvm install 20`.)

---

## 5 · Python 3 (für QR-Generator)

Auf neueren Macs vorinstalliert:

```bash
python3 --version       # 3.9+
```

Falls nicht, `brew install python@3.12`.

QR-Library:

```bash
python3 -m pip install --user qrcode[pil]
```

---

## 6 · Repo klonen

```bash
cd ~/Desktop
git clone https://github.com/ThePyth0nKid/empheral.git
cd empheral
git status              # sollte sauber sein, auf main
```

---

## 7 · Erster Workspace-Build (Warmlauf)

Aus Repo-Root:

```bash
cd reference
cargo build --workspace --release
```

Dauer: ~4–8 Minuten auf Apple Silicon, ~10–15 auf Intel.  Wenn fertig:

```bash
cargo test --workspace --release
```

Erwarte **964/964 PASS** (Stand 2026-04-24).  Wenn eine Zahl abweicht —
stehen geblieben — nicht pushen, in die Logs schauen.

---

## 8 · Canon-Signer isoliert prüfen

```bash
cd reference/validator/tools/canon-signer
cargo test -p canon-signer --release
```

Erwartet: **44/44 PASS**.  Dann die Live-Smoke:

```bash
bash scripts/smoke.sh --skip-musl
```

Erwartet: **10 PASS / 1 SKIP / 0 FAIL**.  Dann die Bühnen-Demo:

```bash
bash scripts/demo.sh
```

Erwartet: signiert 2 verkettete Facts, verifiziert beide, tampert den
zweiten und zeigt Verifikations-Fehler.  ~2 Sekunden Gesamtlaufzeit.

---

## 9 · WASM-Bindings bauen (optional — ist schon fertig im Repo)

Das WASM-Paket liegt bereits gebaut in `tools/canon-signer/web/pkg/`.
Falls du es **neu kompilieren** willst (z. B. nach Code-Änderung):

```bash
cd reference
wasm-pack build crates/canon-verify-wasm \
  --target web \
  --out-dir ../tools/canon-signer/web/pkg \
  --release
```

Dauer: ~1–2 Minuten.  Danach enthält `web/pkg/`:
- `canon_verify_wasm.js`
- `canon_verify_wasm_bg.wasm`
- `canon_verify_wasm.d.ts`

---

## 10 · Verifier lokal servieren

```bash
cd reference/validator/tools/canon-signer/web
python3 -m http.server 8080
```

In separatem Tab:

```bash
open http://localhost:8080/
```

Sollte identisch zur Live-URL aussehen (gelbe Preview-Leiste oben,
Wax-Seal-Logo, „Canon Verifier").  „Load demo fact" → „Verify" → grüner
Wachssiegel.

---

## 11 · QR-Codes neu generieren (optional)

```bash
cd reference/validator/tools/canon-signer
python3 scripts/make-qr.py
```

Schreibt 4 Dateien in `docs/assets/`:
- `canon-verifier-qr-basic.{png,svg}` — nur URL
- `canon-verifier-qr-demo.{png,svg}` — URL + preloaded demo

Das Skript liest den Demo-Envelope aus den Fixtures — kein Drift möglich.

---

## 12 · Dev-Loop cheatsheet

Ab hier bist du voll einsatzfähig.  Die Standard-Schleifen:

| Was du tust | Kommando |
|---|---|
| Nach Code-Änderung im Signer | `cargo test -p canon-signer --release` |
| Nach Code-Änderung im WASM-Crate | `wasm-pack build ...` (siehe Schritt 9) + Browser Cmd+R |
| Vor Push | `cargo test --workspace --release` + `bash scripts/smoke.sh --skip-musl` |
| Vor PR/Merge | zusätzlich `cargo clippy -p canon-signer --all-targets -- -D warnings` |

---

## 13 · Environment-Variablen für den Signer (wenn du live mit Canon testest)

```bash
export CANON_SIGNER_KEY_HEX="<64 hex chars of ed25519 seed>"
# oder
echo '<hex>' > ~/canon-signer.key && chmod 600 ~/canon-signer.key
export CANON_SIGNER_KEYFILE=~/canon-signer.key
```

Ohne beides: der Signer generiert beim Start einen Ephemeral-Key und
persistiert ihn nach `$TMPDIR/canon-signer.key` (chmod 0600).  Der Public
Key wird auf stderr geloggt.

---

## 14 · Troubleshooting Kurzliste

| Symptom | Ursache / Fix |
|---|---|
| `cargo: command not found` | Neues Terminal öffnen, oder `source $HOME/.cargo/env` |
| `error: linker 'cc' not found` | Xcode CLI-Tools fehlen → `xcode-select --install` |
| `wasm-pack: command not found` | PATH neu laden; Install-Pfad ist `~/.cargo/bin/wasm-pack` |
| `cargo test` failt mit „Address already in use" | Port 8080 belegt — andere Prozesse killen oder Port ändern |
| WASM im Browser: `SyntaxError: Unexpected token '<'` | `pkg/`-Ordner fehlt oder falscher MIME-Type — neu bauen (Schritt 9) |
| `python3: No module named 'qrcode'` | Schritt 5 nachholen: `pip install --user qrcode[pil]` |

---

## 15 · Am Veranstaltungstag

1. Öffne **zwei** Terminal-Fenster:
   - Fenster A: `cd empheral/reference/validator/tools/canon-signer/web && python3 -m http.server 8080` (Backup-Server läuft)
   - Fenster B: frei, für ad-hoc Kommandos
2. Browser: `https://thepyth0nkid.github.io/empheral/` geladen, WASM im Cache, Felder leer.
3. Zweiter Browser-Tab: `http://localhost:8080/` als sofortiger Fallback.
4. QR-Code-Ausdruck in der Tasche (siehe `SETUP-MAC.md` Schritt 4).
5. `STAGE-SCRIPT.de.md` / `.en.md` für letzten Durchlauf — Ziel 3:00.

---

**Das war's.** Mit diesem Setup kannst du **jede** Änderung am Signer,
Verifier oder Web-Frontend live nachvollziehen, testen und deployen.
Minimaler Bühnen-Pfad: `SETUP-MAC.md`.  Präsentations-Material-Index:
`PRESENT-KIT.md`.
