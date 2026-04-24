# canon-signer — Nelson's Hackathon Playbook

> **Dein persönlicher Demo- und Validation-Guide für Big Berlin Hack 2026-04-25/26.**
> **Sibling docs:** [TECHNICAL.md](./TECHNICAL.md) (tiefer Tech-Blick), [EXPLAINER.md](./EXPLAINER.md) (Laien-Story).

---

## 0. 30-Sekunden-Status-Check

Bevor du irgendetwas machst, einmal durchschauen:

```bash
cd ~/Desktop/empheral
git status
git log --oneline -3 feat/canon-signer
```

Erwartung:
- `On branch feat/canon-signer` (oder `main` falls schon gemerged)
- HEAD = `d1ab9d2` (review-swarm fixes) oder neuer
- Working tree clean (ignoriere `.claude/`, `LICENSE-*`, `report.json`)

Wenn was nicht stimmt: **nicht weitermachen**, erst klären.

---

## 1. Binary bauen (60 Sekunden)

### Lokal (Windows, für Demo-Laptop)

```bash
cd reference/validator
cargo build -p canon-signer --release
# → target/release/canon-signer.exe
```

### Für Canon's Docker / Railway (musl-static Linux)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build -p canon-signer --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/canon-signer
```

Wenn der Build scheitert: **nicht weitermachen**. `cargo build` soll grün sein, sonst ist alles andere irrelevant.

---

## 2. Smoke-Test auf dem Demo-Laptop (2 Minuten)

Öffne zwei Terminals.

**Terminal 1 — starte den Signer:**

```bash
export CANON_SIGNER_KEY_HEX=0101010101010101010101010101010101010101010101010101010101010101
./target/release/canon-signer.exe
```

Du solltest auf stderr sehen:
```
canon-signer: using key from CANON_SIGNER_KEY_HEX; pubkey=ed25519:<44 chars>
```

Das Terminal bleibt offen und wartet auf Input. **Das ist korrekt.**

**Terminal 2 — schick ihm einen Test-Fakt:**

```bash
echo '{"op":"sign","fact_id":"demo_1","entity":"customer:acme","claim":"Q1 revenue was EUR 127,000","source_ref":"gmail:msg_abc","source_excerpt":null,"parent_hash":"","created_at_ms":1713974400000}' | ./target/release/canon-signer.exe
```

Erwartete Antwort (eine Zeile JSON):

```json
{"fact_id":"demo_1","event_hash":"<64 hex chars>","cose_sign1_hex":"<lange hex Zeichen>","signer_pubkey":"ed25519:<44 chars>","signed_at_ms":<unix ms>}
```

Wenn **alle 5 Felder vorhanden sind** und `event_hash` genau 64 hex-chars hat — **du bist ready.**

Terminal 1 mit Ctrl+C beenden.

---

## 3. Canon-Integration prüfen (wenn du's vorführst)

Canon spawnt den Signer aus Node so:

```js
const { spawn } = require('child_process');
const signer = spawn('canon-signer', [], {
  env: { ...process.env, CANON_SIGNER_KEY_HEX: process.env.CANON_KEY },
  stdio: ['pipe', 'pipe', 'inherit'],  // stderr → Canon logs
});

signer.stdout.on('data', (chunk) => {
  // NDJSON: kann mehrere Zeilen enthalten, splitte an '\n'
  for (const line of chunk.toString().split('\n').filter(Boolean)) {
    const resp = JSON.parse(line);
    // resp.event_hash, resp.cose_sign1_hex, resp.signer_pubkey, …
  }
});

signer.stdin.write(JSON.stringify(request) + '\n');
```

**Dinge, die du auf Canon-Seite checken willst:**
- `stdio: ['pipe', 'pipe', 'inherit']` — stderr **muss inherit** sein, sonst siehst du den pubkey beim Start nicht.
- Die Request muss mit `\n` enden, sonst liest der Signer nie.
- Die Response wird **zeilenweise** gelesen — nicht als ein JSON blob.

Wenn Canon nach einer Request **hängt**: der Signer hat wahrscheinlich einen Fehler auf stdout geschrieben und Canon ignoriert ihn. Parse `resp.error` immer.

---

## 4. Was dir das stderr-Log sagt

Eine einzige Zeile beim Startup. Form:

```
canon-signer: using key from <source>; pubkey=ed25519:<44 chars>
```

| `<source>`                                              | Bedeutung                                         | Produktions-OK? |
|---------------------------------------------------------|---------------------------------------------------|-----------------|
| `CANON_SIGNER_KEY_HEX`                                  | Env-Variable gesetzt, validiert                   | ✅ ja           |
| `<keyfile-path>`                                        | `--keyfile` verwendet                             | ✅ ja           |
| `ephemeral key (auto-generated, persisted to <path>)`   | Kein env, kein flag, auto-gen, auf Disk persisted | ⚠️ Demo only     |
| `ephemeral key (auto-generated, NOT persisted — …)`     | Auto-gen, aber $TMPDIR ist read-only              | 🚨 Nie Production |

**Auf dem Hackathon-Demo-Laptop:** Env-Variable setzen. Wenn der Signer sagt "ephemeral key auto-generated", ist das für die Demo akzeptabel — aber Canon auf Railway soll immer `CANON_SIGNER_KEY_HEX` haben.

---

## 5. Demo-Skript (3 Minuten, sitzend an der Bühne)

```mermaid
timeline
    title 3-Minuten-Demo
    00:00 - 00:30 : Problem Setup ("Wie trust man einem DB-Eintrag?")
    00:30 - 01:15 : Live Sign ("Hier ist eine E-Mail, hier ist der Fakt, hier ist die Signatur")
    01:15 - 02:00 : Tamper-Demo ("Ich ändere ein Byte — verify schlägt fehl")
    02:00 - 02:45 : Chain-Demo ("Fakt B verweist auf Fakt A, A ändern = B kaputt")
    02:45 - 03:00 : Close ("Production-Crypto, 38 Tests, reused von EPHEMERAL")
```

### 5.1 Setup-Command (kopieren, vor der Demo testen)

```bash
# Pre-demo: Terminal groß + readable
export CANON_SIGNER_KEY_HEX=0101010101010101010101010101010101010101010101010101010101010101
./target/release/canon-signer.exe
```

### 5.2 Live-Sign-Command (in zweitem Terminal)

Formatiere hübsch mit `jq`:

```bash
echo '{"op":"sign","fact_id":"demo_A","entity":"customer:acme","claim":"Q1 revenue EUR 127k","source_ref":"gmail:msg_abc","source_excerpt":"Our Q1 came in at 127k EUR","parent_hash":"","created_at_ms":1713974400000}' \
  | ./target/release/canon-signer.exe | jq .
```

Zeigt:
```json
{
  "fact_id": "demo_A",
  "event_hash": "b4e1c2a0…",
  "cose_sign1_hex": "d28443a10126a10…",
  "signer_pubkey": "ed25519:oBE6…",
  "signed_at_ms": 1713974400017
}
```

**Sage dabei:**
> "Das `event_hash` ist der SHA-256 von dem genauen CBOR-Layout dieses Fakts. Das `cose_sign1_hex` ist die Ed25519-Signatur, eingepackt in ein RFC-9052-Envelope — das gleiche Format, das WebAuthn und FIDO-Keys verwenden."

### 5.3 Tamper-Demo

Nimm das `cose_sign1_hex` aus 5.2, ändere den letzten Character (z.B. `…5b` → `…5c`), übergib es an den Verifier:

```bash
# (Vorbereitet als Shell-Snippet oder kleinem Rust-Testprogramm)
# Verify auf tampered bytes → error
```

Oder zeig den passenden Integration-Test:

```bash
cargo test -p canon-signer --test round_trip tampered_envelope_fails_verification -- --nocapture
```

Der läuft in ~50ms und gibt `ok` aus. **Sage dabei:**
> "Ein Byte gekippt — der Verifier lehnt ab. Keine zweite Chance."

### 5.4 Chain-Demo

```bash
cargo test -p canon-signer --test chain -- --nocapture
```

Das ist der Test, der Fakt A → Fakt B → Re-Sign A macht. **Sage dabei:**
> "Fakt B zeigt auf Fakt A via `parent_hash`. Wenn ich Fakt A nachträglich ändere, ändert sich sein hash, und B's `parent_hash` stimmt nicht mehr. Die ganze Kette ab A bricht sichtbar."

### 5.5 Closing line

> "Production-Crypto von unserer EPHEMERAL-Codebase, 38 Tests, 0 unsafe, COSE_Sign1 Standard. Nicht mein Prototyp — das Binary, das morgen auf Railway läuft."

---

## 6. Audience FAQ (die 8 wahrscheinlichsten Fragen)

### Q1 — "Warum nicht einfach JWT?"

> JWT signiert ein Objekt, aber kettelt nicht. Wenn du 10 JWTs hast und jemand löscht #5, merkst du's nicht. Unser hash chain macht Löschen/Umstellen sichtbar — weil jeder Fakt den hash des vorherigen enthält.

### Q2 — "Warum nicht auf der Blockchain?"

> Für Business-Facts aus E-Mails? Overkill. Wir wollen Tamper-Evidence, nicht Byzantine Consensus. Unsere Lösung: 2 MB Binary, 20 µs pro Signatur, keine Gas-Fees. Blockchain wäre für den Use-Case teuer und langsam.

### Q3 — "Was passiert, wenn der Signer abstürzt?"

> Canon sieht das Pipe-EOF und spawnt neu. Wenn du die Env-Variable gesetzt hast, hat der neue Prozess den gleichen Key — also die gleiche Chain-Identität. Null Datenverlust.

### Q4 — "Was wenn jemand den privaten Key klaut?"

> Dann können sie zukünftige Fakten fälschen — aber nicht vergangene (die sind schon mit dem alten Key signiert und in der Chain verankert). Key-Rotation ist eine Canon-Aufgabe: Signer mit neuem Seed restarten, alte Pubkey bleibt als Trust-Anchor für historische Fakten gültig.

### Q5 — "Habt ihr das selbst geschrieben?"

> Die Binary-Orchestrierung und das Wire-Protokoll ja. Die Crypto selbst — Ed25519, COSE_Sign1, SHA-256 — kommt aus audited Libraries (`ed25519-dalek`, `coset`, `sha2`). Wir rolled nichts selbst.

### Q6 — "Warum Rust?"

> Process-Isolation (crash bringt Canon nicht runter), speed (~20 µs pro sign), `#![forbid(unsafe_code)]` — sichere Sprache ohne Tradeoff. Alternativen wären FFI (ABI-drift) oder pure-JS (fehlende standards-compliant libraries).

### Q7 — "Wie habt ihr das validiert?"

> Drei Layer: 38 automated tests (unit + integration), zwei unabhängige AI-Reviewer haben die Codebase parallel geprüft (security + correctness) — jede Finding gefoldet. `cargo clippy -D warnings` clean. Und der Round-Trip-Test prüft, dass `ephemeral_crypto::verify_cose_sign1` — der Production-Verifier aus unserem EPHEMERAL-Repo — unsere Output akzeptiert.

### Q8 — "Kann ich das nachbauen?"

> Ja. Repo ist `github.com/ThePyth0nKid/empheral`, Branch `feat/canon-signer`, Crate unter `reference/validator/tools/canon-signer/`. README hat Docker-Snippet und Node-Integration. Apache-2.0 / MIT dual-licensed.

---

## 7. Rescue-Antworten wenn was bricht

### Szenario A — Demo-Binary startet nicht

Symptom: `./canon-signer.exe: not found` oder ähnliches

**Sag:**
> "Moment, ich fall zurück auf die Test-Suite — die macht das gleiche vom Code-Pfad her."

**Mach:**
```bash
cargo test -p canon-signer --test smoke -- --nocapture
```

Das spawnt das Binary intern und zeigt einen Signing-Roundtrip. Gleicher Point, andere UI.

### Szenario B — Binary startet, aber kommt kein Output

Symptom: Du schickst JSON rein, Terminal hängt.

**Check:**
- Hat deine Input-Zeile am Ende `\n`? Wenn du `echo` benutzt: yes. Wenn du pasted in Terminal: maybe no.
- Ist der Signer-Prozess noch am Leben? `ps | grep canon-signer`
- Schau auf stderr des Signers — vielleicht gab's einen Startup-Fehler.

**Fallback sag:**
> "Lass mich die integration-test-Variante zeigen, da haben wir deterministische Pipes."

### Szenario C — Verifier rejected einen Fakt, obwohl er nicht tampered ist

Symptom: Du zeigst "verify ok", läuft kurz, kommt `error`.

**Check:**
- AAD-String richtig? Muss exact `b"canon/fact/v1"` sein.
- `AnchorRole::CanonSigner` benutzt, nicht `TariffSigner` oder `CoreValidator`?
- Pubkey-bytes aus `signer_pubkey` korrekt base64-decoded?
- Kid passend konstruiert (`canon/<first-16-hex-of-pubkey>`)?

**Fallback:** Zeig den passing round-trip-test — `cargo test -p canon-signer --test round_trip`.

### Szenario D — Jemand fragt was du nicht weißt

**Sag:**
> "Gute Frage, das würde ich gern nachschauen. Hier ist mein Kontakt — [email] — ich komme in den nächsten 24h darauf zurück."

**Nie erfinden.** Hackathon-Judges merken das sofort und es kostet mehr Credibility als ein ehrliches "weiß ich nicht."

---

## 8. Was du unbedingt sagen sollst

1. **"Production crypto, not hackathon crypto."** Das ist dein Hauptargument gegen alle DIY-Konkurrenz.
2. **"RFC 9052 COSE_Sign1 — same format as WebAuthn."** Standards-compliance = future-verifiability.
3. **"Process-isolated sidecar."** Null blast-radius bei Bug in Signer.
4. **"38 tests including an AI review-swarm pass."** Signalisiert Qualitätsbewusstsein.
5. **"Deterministic, re-verifiable by anyone."** Das ist das Kern-Property.

---

## 9. Was du unbedingt nicht sagen sollst

1. ❌ **"Unhackable."** — Nichts ist unhackable. Sag "tamper-evident." Der Unterschied ist wichtig.
2. ❌ **"We invented this."** — Sag "we correctly composed this." Der COSE-Standard existiert seit 2017; unser Beitrag ist die saubere Anwendung.
3. ❌ **"Blockchain-grade."** — Wir sind nicht Blockchain. Das verwirrt und lädt zu falschen Vergleichen ein. Sag "cryptographic hash chain" oder "tamper-evident log."
4. ❌ **"AI-generated code."** — Auch wenn Claude mitgeschrieben hat: der Code ist reviewed von dir UND zwei AI-Reviewern UND 38 Tests. Sag lieber "engineered with AI assistance, human-validated."
5. ❌ **"Zero vulnerabilities."** — Sag "no known vulnerabilities, audited library stack." Humility + accuracy.

---

## 10. Vor-dem-Pitch-Checkliste (15 Min vor Go)

- [ ] Laptop-Battery > 60% oder am Kabel
- [ ] Terminal-Font groß (mind. 16pt, für letzte Reihe lesbar)
- [ ] `jq` installiert auf Demo-Machine
- [ ] `cargo build -p canon-signer --release` grün gelaufen
- [ ] Smoke-Test aus §2 einmal ausgeführt
- [ ] `git status` clean
- [ ] Env `CANON_SIGNER_KEY_HEX` exportiert (nicht die Production-Key! — der Demo-Key aus §2)
- [ ] Browser-Tab mit TECHNICAL.md offen (für Tiefer-Fragen)
- [ ] Browser-Tab mit Repo-URL offen (wenn jemand den Code sehen will)
- [ ] Wasser in Reichweite
- [ ] Tief durchgeatmet

---

## 11. After-the-pitch-Notizen

Wenn du gepitched hast, mach dir sofort Notizen:

- Welche Frage kam, die du nicht kanntest? → Nachher beantworten, Kontakt pflegen.
- Welcher Punkt kam besonders gut an? → Das ist dein Elevator-Pitch für die nächste Runde.
- Gab's Judge-Feedback zur Präsentation? → Für nächstes Hackathon notieren.

---

## 12. Hilfreiche Referenzen (falls du tiefer reinmusst)

| Was du suchst                              | Wo es steht                                      |
|--------------------------------------------|--------------------------------------------------|
| Canonical CBOR Layout, 7-Feld-Array        | [TECHNICAL.md §3](./TECHNICAL.md#3-canonical-payload-the-load-bearing-format) |
| Threat-Model (was schützt canon-signer)    | [TECHNICAL.md §7](./TECHNICAL.md#7-threat-model) |
| Wire-Protocol (Request/Response-Schema)    | [TECHNICAL.md §2](./TECHNICAL.md#2-wire-protocol) |
| Non-technical explainer (für Journalisten) | [EXPLAINER.md](./EXPLAINER.md)                   |
| Docker-Deploy-Snippet                      | [README.md §Dockerfile](../README.md)            |
| RFC 9052 COSE_Sign1 spec                   | https://datatracker.ietf.org/doc/html/rfc9052    |
| Ed25519-dalek docs                         | https://docs.rs/ed25519-dalek                    |
| Canon Repo (falls öffentlich)              | github.com/ultranova/canon                       |

---

## 13. Final note

Du hast in ~3 Tagen einen production-grade Crypto-Sidecar gebaut, mit Reused-Components aus einer laufenden audit-grade Codebase, mit AI-Reviewer-pass, mit 38 Tests. Das ist solide. Geh da rein und zeig's.

**Viel Erfolg in Berlin. 🔏**
