# Canon — Wachssiegel fürs digitale Geschäft

> Eine Geschichte in sieben Teilen. Für Jury, Kunden und alle, die es
> verstehen wollen, ohne eine Zeile Code zu lesen.
> Für Technikdetails siehe [`TECHNICAL.md`](TECHNICAL.md) und
> [`VALIDATION.md`](VALIDATION.md).

---

## 1. TL;DR

**Canon** liest Business-E-Mails und extrahiert daraus strukturierte
**Facts** — kleine, präzise Behauptungen: *„Kunde X hat im Q1 EUR 127.000
Umsatz gemacht."* **canon-signer** siegelt jeden Fact kryptografisch, wie
ein Notar ein Dokument mit Wachs siegelt. **Der Web-Verifier** —
[thepyth0nkid.github.io/empheral](https://thepyth0nkid.github.io/empheral/)
— lässt **jeden Menschen** auf der Welt mit einem Browser **selbst**
nachprüfen, ob das Siegel echt ist. Kein Server-Vertrauen, keine
Blockchain, kein Vendor-Lock.

---

## 2. Die Metapher: Wachssiegel fürs Digitale

Im 16. Jahrhundert hatten wichtige Briefe ein **Wachssiegel** mit dem
Wappen des Absenders. Drei Eigenschaften machten das System robust:

1. **Fälschungsschwer** — das Wappen ließ sich nicht einfach nachmachen.
2. **Sichtbar gebrochen** — jeder manipulierte Brief fiel sofort auf.
3. **Öffentlich prüfbar** — jeder, der das Wappen kannte, konnte es
   selbst bestätigen. Kein Königshof nötig.

Canon baut **genau dasselbe System**, nur für digitale Facts statt
Briefe. Statt Wachs benutzen wir eine **Ed25519-Signatur**. Statt Wappen
benutzen wir einen **Public Key**. Statt Boten, die den Brief tragen,
benutzen wir einen **hex-String, der in einen QR-Code passt**.

Die Benutzer-Erfahrung ist bewusst an das alte System angelehnt: auf der
Verifier-Seite siehst du einen **gestempelten Wachssiegel** — grün, wenn
echt; gebrochen und rot, wenn manipuliert. Keine Konsole, keine
Log-Dateien. Das Siegel *ist* die Antwort.

---

## 3. Was ist ein „Fact"?

Ein Fact ist eine einzelne **strukturierte Behauptung**. Er hat neun
Felder — zusammen machen sie einen unveränderbaren Datensatz:

| Feld | Bedeutung | Beispiel |
|---|---|---|
| **Fact ID** | Eindeutige Kennung | `f_q1_acme_0001` |
| **Entity** | Über wen geht's | `customer:acme` |
| **Claim** | Die eigentliche Aussage | `Q1 revenue was EUR 127,000` |
| **Source** | Wo kommt das her | `gmail:msg_abc123` |
| **Excerpt** | Wörtliches Zitat | `"Our Q1 came in at 127k EUR…"` |
| **Parent** | Hash des vorigen Facts | `b0f3…` oder leer (Genesis) |
| **Signed at** | Zeitstempel | `2026-04-24T09:03:12Z` |
| **Signer (kid)** | Welcher Schlüssel hat gesiegelt | `canon/8a88e3dd7409f195` |
| **Event hash** | SHA-256 über den Payload | `b0f3753095…` |

Der kritische Punkt ist **Parent**. Jeder neue Fact zeigt auf den Hash
des vorigen — wie eine **Notariatsbuch-Seite**, die die vorige referenziert.
Wenn jemand einen alten Fact nachträglich ändert, passt die Kette nicht
mehr. Der Verifier merkt das sofort.

So entsteht aus einzelnen E-Mail-Aussagen eine **lückenlose Historie**,
die weder Canon noch der Kunde nachträglich umschreiben kann.

---

## 4. Wie die zwei Systeme zusammenspielen

```
   ┌────────────────────┐           ┌──────────────────────┐
   │  Canon (Node.js)   │           │  canon-signer (Rust) │
   │                    │  JSON     │                      │
   │  KI-Extraktor:     │  stdin    │  COSE_Sign1 +        │
   │  Mail → Claim      ├──────────▶│  Ed25519-Siegel      │
   │                    │           │                      │
   │                    │  JSON     │                      │
   │  Speichern/Ketten  │◀──────────┤  hex-Envelope +      │
   │                    │  stdout   │  Public Key          │
   └─────────┬──────────┘           └──────────────────────┘
             │
             │ Share-URL mit ?e=<hex>&pk=<key>
             │ (passt in QR-Code)
             ▼
   ┌────────────────────────────────────────────────────┐
   │  Web-Verifier (WASM im Browser)                    │
   │  thepyth0nkid.github.io/empheral                   │
   │                                                    │
   │   10 Schritte sichtbar, grüner Siegel, fertig.     │
   └────────────────────────────────────────────────────┘
```

Drei klare Rollen, jede mit einem Zweck:

- **Canon** ist der **Autor**. Er weiß, was Business-Claims sind, wie
  man sie aus einer E-Mail herausliest, wie man sie speichert. Er kann
  aber nicht selbst sicher siegeln — das wäre wie wenn der Autor selbst
  den Stempel schnitzt.
- **canon-signer** ist der **Notar**. Er hat genau *eine* Aufgabe: einen
  Fact bekommen, siegeln, zurückgeben. Er weiß nichts von E-Mails oder
  KI. Er ist in Rust geschrieben, ~700 Zeilen, und nutzt eine seit Jahren
  in Produktion abgehärtete Krypto-Bibliothek.
- **Der Web-Verifier** ist der **unabhängige Zeuge**. Er hat *nur* die
  Verify-Seite des Codes — er kann *nicht* signieren. Das heißt: selbst
  wenn jemand die Verifier-URL übernimmt, kann er keine gefälschten
  Siegel ausstellen. Er kann nur ehrlich prüfen oder die Seite lahmlegen.

Diese **Trennung zwischen Autor, Notar und Zeuge** ist das Herzstück.

---

## 5. Die Reise eines Facts

Nehmen wir ein konkretes Beispiel. Freitag, 9:03 Uhr:

**Schritt 1 — Die Mail kommt rein.**
Frau Meyer vom Kunden **Acme** schickt eine Mail an ihren Finanzberater:
*„Hallo, unser Q1 kam bei 127k EUR raus, sind gut dabei."*

**Schritt 2 — Canon liest mit.**
Die Canon-KI erkennt den Business-Claim, normalisiert ihn:
```
entity = "customer:acme"
claim  = "Q1 revenue was EUR 127,000"
source = "gmail:msg_abc123"
excerpt = "Our Q1 came in at 127k EUR…"
```

**Schritt 3 — Canon fragt den Notar.**
Canon ruft `canon-signer` als Subprozess auf, schickt eine JSON-Zeile
über stdin. Der Signer baut:

- einen **7-Feld-CBOR-Payload** (der Fact in kompakter Binärform),
- eine **COSE_Sign1-Hülle** mit Protected Header `{alg: Ed25519}`,
- eine **Ed25519-Signatur** über den Payload plus einen festen Domain-
  Separator `canon/fact/v1` (damit niemand den Fact in einem anderen
  Kontext wiederverwenden kann),
- antwortet mit dem **hex-Envelope** + dem **Public Key**.

Gesamtdauer: unter einer Millisekunde.

**Schritt 4 — Canon legt den Fact ab.**
Der Envelope wird in Canons Datenbank gespeichert. Der `event_hash`
des Facts wird zum `parent_hash` für den nächsten Fact über denselben
Kunden. So baut sich die Kette auf.

**Schritt 5 — Der Finanzberater will das belegen.**
Der Berater muss dem Wirtschaftsprüfer nachweisen, dass Acme *tatsächlich*
127.000 EUR gemeldet hat. Früher: „Hier ist ein Screenshot der Mail."
— Beweiskraft null, editierbar in Sekunden.

**Jetzt:** Canon generiert eine **Share-URL**:
```
https://thepyth0nkid.github.io/empheral/?e=84581b…a2d1c0d&pk=ed25519:iojj…
```

Diese URL passt in einen QR-Code. Man kann sie mailen, printen, auf ein
Angebot drucken, als Link in einen Rechnungs-PDF legen.

**Schritt 6 — Der Prüfer öffnet die URL.**
Auf seinem Handy. In einem beliebigen Browser. Ohne Login. Ohne
Canon-Account.
Die Seite zeigt:
- **Grüner gestempelter Wachssiegel** mit kleiner Animation.
- „Signature valid. Signed by `canon/8a88…` and has not been altered."
- Die 9 Fact-Felder, lesbar formatiert.
- Die 10 Verify-Schritte alle grün.
- Auf Wunsch: die rohen Bytes, die in die Signatur geflossen sind — für
  den Prüfer, der Python aufmacht und selbst rechnen will.

**Schritt 7 — Der Gegentest.**
Der Prüfer ändert spaßeshalber einen Buchstaben in der URL. Die Seite
kippt sofort: **roter, gebrochener Wachssiegel**. Schritt 7 („Ed25519
verify") leuchtet rot. Kein Reden nötig, es ist ganz offensichtlich.

Dauer der ganzen Prüfung: **vier Sekunden**, ohne Kontoerstellung, ohne
Vertrauen in Canon, ohne Blockchain-Wallet.

---

## 6. Warum das gewinnt — drei Killer-Punkte

**(a) Zero-Trust durch Rollen-Trennung.**
Der Code, der siegelt, läuft auf Canon-Infrastruktur. Der Code, der
prüft, läuft im Browser von jedem, der die URL aufmacht. Das WASM-Bundle
enthält **keine** Signing-Primitive — selbst wenn jemand den Verifier
kompromittiert, kann er keine gefälschten Siegel ausstellen. Die
Vertrauensbasis ist nicht „wir versprechen, fair zu sein" — sie ist
**architektonisch erzwungen**.

**(b) Portabel ohne Infrastruktur.**
Kein Blockchain-Node, kein zentraler Timestamp-Server, keine
Abhängigkeit von GitHub Pages (die Seite kann überall stehen — S3,
Self-Hosted, Kunden-VPN). Ein Fact ist **zwei Strings**: ein hex-Envelope
und ein Public Key. Beide zusammen passen in einen QR-Code. Du kannst
sie auf Papier drucken, per SMS schicken, in eine PDF-Rechnung einbetten.

**(c) Radikale Transparenz, vorgelebt.**
Die meisten Krypto-Produkte sagen „Trust us, it's cryptographically
secure." Wir zeigen **jeden einzelnen Schritt** — mit Namen, mit
Byte-Dump, in einer Reihenfolge, die die Jury selbst nachvollziehen
kann. Ein Kunde kann **sich selbst** vergewissern, nicht nur uns
glauben. Das ist die Differenzierung gegenüber jedem proprietären
„Blockchain für Enterprise"-Produkt am Markt.

---

## 7. Drei-Minuten-Bühnen-Skript

**[00:00 — 00:20] Hook.**
*„Heute läuft euer Geschäft auf E-Mails. Ein Kunde schreibt 'Wir haben
127k Umsatz', ihr speichert das, ihr bucht danach. Aber in sechs Monaten,
wenn der Wirtschaftsprüfer kommt: wie beweist ihr, dass genau dieser Satz
drinstand? Ein Screenshot? Lachhaft."*

**[00:20 — 00:50] Was Canon macht.**
*„Canon liest jede eingehende Mail, findet automatisch Business-Claims,
und extrahiert sie in strukturierte 'Facts'. Wer, was, wann, woher.
Das ist die erste Hälfte. Die zweite Hälfte ist das hier:"*
→ Browser öffnet [thepyth0nkid.github.io/empheral](https://thepyth0nkid.github.io/empheral/)

**[00:50 — 01:20] Demo live.**
*„Das ist der Canon Verifier. Läuft komplett im Browser — keine
Anmeldung, kein Account."*
→ **Load demo fact** klicken, dann **Verify**.
*„Grüner Wachssiegel. Das ist Acme, Q1-Umsatz 127.000 EUR, signiert um
9:03. Und hier — das ist das Entscheidende — sind die zehn Schritte, die
der Browser gerade gegangen ist. Jeder einzelne gezeigt. Ihr müsst mir
nichts glauben."*

**[01:20 — 02:00] Das Tamper-Moment.**
*„Ich ändere jetzt einen Buchstaben in der URL."*
→ Ein Hex-Zeichen am Ende der Envelope-Hex ändern, **Verify** klicken.
*„Siegel gebrochen. Schritt 7 rot. In 400 Millisekunden weiß die ganze
Welt: manipuliert. Das ist nicht 'wir loggen es' — das ist kryptografisch
nicht mehr reparierbar."*

**[02:00 — 02:30] Die Architektur in einem Atemzug.**
*„Der Code, der die Siegel **macht**, läuft bei uns. Der Code, der sie
**prüft**, ist in einer Rust-WASM-Binary — 250 Kilobyte, liegt in eurem
Browser-Cache. Die zwei Codebases teilen **keine** Signing-Primitive.
Das heißt: selbst wenn jemand uns hackt, kann er keine Fälschungen
ausstellen, ohne dass eure Browser sie sofort erkennen."*

**[02:30 — 03:00] Close.**
*„Kein Blockchain. Kein Vendor-Lock. Ein Fact ist zwei Strings, passt in
einen QR-Code. Hier ist die URL — jeder von euch kann das gerade live
selbst nachbauen. Dauert vier Sekunden. Danke."*
→ QR-Code auf dem Screen stehenlassen.

---

## Anhang: Wiederkehrende Fragen

**„Wenn Canon kompromittiert wird, ist doch alles hin?"**
Nur die *neuen* Siegel ab dem Zeitpunkt der Kompromittierung sind
verdächtig. Alle alten Facts bleiben verifizierbar, weil jeder seinen
eigenen Public Key im Header trägt. Ein Rotations-Event ist sichtbar —
der `kid` ändert sich. Der Verifier stempelt trotzdem grün, solange der
Public Key stimmt.

**„Warum COSE_Sign1 und nicht JWT/JWS?"**
JSON macht Payloads größer und nicht deterministisch (Feldreihenfolge).
CBOR ist kompakt und bytegleich. Für QR-Codes + Long-Term-Archiving
zählt jeder Byte.

**„Warum Ed25519, nicht ECDSA-P256?"**
Kleinere Signaturen (64 Byte vs. 72), deterministisch (keine
RNG-Schwächen), schneller zu verifizieren. Passt besser ins
Mobile-/QR-Szenario.

**„Ist das Open Source?"**
Der Verifier liegt als WASM öffentlich; die Signer-Crate ist
hackathon-state, LICENSE-Entscheidung nach dem Event. Siehe
[`VALIDATION.md`](VALIDATION.md).
