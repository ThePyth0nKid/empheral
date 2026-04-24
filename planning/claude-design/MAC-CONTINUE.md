# MAC-CONTINUE.md — Morgen am Mac weitermachen

**Geschrieben:** 2026-04-24 nachts. Hackathon ist heute (25./26.04).

---

## 1. Repo holen (Mac)

Du hast zwei Remotes — beide haben den gleichen Stand auf `main`. Nimm einfach einen.

### Option A — SSH via Gitea (bevorzugt, da privat)

Voraussetzung: Tailscale läuft auf dem Mac, eingeloggt als `nelson@ultranova.io`. SSH-Key `MacBook Air - nelsonmehlis` ist bereits in Gitea registriert (siehe `obsidian-vault/Credentials/gitea.md`).

```bash
# Falls noch nicht in ~/.ssh/config:
cat >> ~/.ssh/config <<'EOF'
Host pve-worker2-1
    HostName pve-worker2-1
    Port 30222
    User git
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
EOF

# Clone:
cd ~/Code   # oder wo du Projekte hast
git clone ssh://git@pve-worker2-1:30222/nelson/empheral.git
cd empheral
```

### Option B — HTTPS via GitHub (öffentlich, geht immer)

```bash
cd ~/Code
git clone https://github.com/ThePyth0nKid/empheral.git
cd empheral
```

Beide Wege geben dir den exakten Stand von heute Abend.

---

## 2. Beide Remotes konfigurieren (empfohlen)

Damit du auf dem Mac später zu beiden pushen kannst:

```bash
# Wenn du via GitHub geclont hast: gitea hinzufügen
git remote add gitea ssh://git@pve-worker2-1:30222/nelson/empheral.git

# Wenn du via Gitea geclont hast: github hinzufügen
git remote add github https://github.com/ThePyth0nKid/empheral.git
# (oder origin umbenennen — Geschmackssache)

git remote -v
```

---

## 3. Was im Repo dazugekommen ist (heute Abend)

`planning/claude-design/` — fünf Files plus zwei leere Output-Ordner:

```
planning/claude-design/
├── DESIGN.md            ← Brand-Token-System "Notarial Modern"
├── BRIEF.md             ← Story-Copy für 3 Audiences
├── SLIDE_OUTLINE.md     ← 12-Slide-Pitchdeck-Struktur
├── PROTOTYPE_BRIEF.md   ← 6-Screen Hi-Fi-Prototyp-Brief
├── HANDOFF.md           ← Schritt-für-Schritt Anleitung für Claude Design
├── MAC-CONTINUE.md      ← (diese Datei)
├── deck/                ← leer, hier landet die PPTX
└── handoff/             ← leer, hier landet das Claude-Design-Bundle
```

---

## 4. So machst du morgen früh weiter

### 4.1 Claude Design am Mac öffnen

`https://claude.ai/design` — selbe Anmeldung wie auf Windows. Dein Design-System "Notarial Modern" ist account-weit verfügbar (du hast es heute Abend auf Windows gesetzt — Claude Design speichert pro Account, nicht pro Device).

### 4.2 Erste Handlung am Mac

1. `HANDOFF.md` öffnen — das ist deine Schritt-für-Schritt-Anleitung
2. Wenn du heute Abend bei **Schritt 1 (Setup)** stehengeblieben bist → mach mit Schritt 2 weiter
3. Wenn du heute Abend bei **Schritt 2 (Slide Deck)** stehengeblieben bist → exportiere PPTX, dann Schritt 3
4. Wenn alles fertig ist → exportier Handoff-Bundle, drop nach `planning/claude-design/handoff/`, commit + push

### 4.3 Hackathon-Vorbereitung parallel

Vergiss nicht den `docs/HACKATHON.md` §10 Vor-dem-Pitch-Check:

- [ ] Laptop-Battery > 60% oder am Kabel
- [ ] Terminal-Font groß
- [ ] `cargo build -p canon-signer --release` grün
- [ ] `bash scripts/smoke.sh --skip-musl` 10 PASS / 1 SKIP / 0 FAIL
- [ ] Browser-Tab `thepyth0nkid.github.io/empheral/` offen
- [ ] QR-Code aus PRESENT-KIT.md griffbereit

### 4.4 Sicherheits-Todo (aus Credentials/gitea.md)

⚠️ Das iPhone-SSH-Key (id=4) muss heute rotiert werden — siehe `obsidian-vault/Credentials/gitea.md` "ROTATE TONIGHT". Das ist NICHT dieses Repo, aber du wirst es heute irgendwann sehen wollen.

---

## 5. Wenn Tailscale am Mac nicht läuft

Symptome: `git push gitea` hängt oder `Connection refused`.

```bash
# Tailscale-Status prüfen
tailscale status
# Wenn down: tailscale up und im Browser anmelden
```

GitHub-Push (`origin`) funktioniert auch ohne Tailscale — der ist die Failover-Route.

---

## 6. Stand der Dinge

| Was | Status |
|---|---|
| Heutige Claude-Design-Files committet | ✅ heute Abend |
| Push zu GitHub `origin/main` | ✅ heute Abend |
| Push zu Gitea `gitea/main` | ✅ heute Abend |
| Slide-Deck in Claude Design | ⏳ du, morgen früh |
| Hi-Fi-Prototyp in Claude Design | ⏳ du, morgen früh (optional) |
| Pitch | 🎤 Big Berlin Hack 2026-04-26 |

---

## 7. Wenn was schiefgeht und du mich brauchst

Schreib im Mac-Claude-Code einfach:

> "Ich bin am Mac in `~/Code/empheral`, will an Claude Design Slide Deck weitermachen, schau in `planning/claude-design/HANDOFF.md` und sag mir wo ich stehe."

Dann liest die neue Session automatisch dieses File und macht weiter wo du aufgehört hast.

---

**Schlaf gut. Du bist gut vorbereitet.**
