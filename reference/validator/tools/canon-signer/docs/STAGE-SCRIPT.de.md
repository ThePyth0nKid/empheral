# Bühnen-Skript (Deutsch) — Canon @ Berlin Hack

> **Dauer:** 3 Minuten Demo + 2 Minuten Q&A-Buffer.
> **Setup:** Laptop + Projektor, Browser-Tab auf `thepyth0nkid.github.io/empheral`
> offen und bereit.  QR-Code (`canon-verifier-qr-demo.png`) entweder
> als Ausdruck hochhalten oder als zweite Slide.

---

## Vorbereitung (2 Minuten vor Auftritt)

- [ ] Browser-Tab auf Live-URL, **im Voll-/Präsentations-Modus** (Strg+Umschalt+F)
- [ ] Felder **leer** (falls schon benutzt: Clear-Button)
- [ ] WLAN getestet — einmal kurz Verify durchlaufen lassen, dann Clear
- [ ] QR-Code sichtbar (Print in A5, oder Slide bereit)
- [ ] Zweiter Tab mit DevTools Console offen (falls jemand fragt: du zeigst „null Requests nach Load")
- [ ] Stimme warm, Wasser griffbereit

---

## 00:00 – 00:20 · Hook

> *„Heute läuft euer Geschäft auf E-Mails.  Ein Kunde schreibt 'Wir haben
> hundertsiebenundzwanzigtausend Umsatz im Q1', ihr speichert das, ihr
> bucht danach.  Aber in sechs Monaten, wenn der Prüfer kommt — wie
> beweist ihr, dass **genau dieser Satz** drinstand?"*

**Pause.  Publikum anschauen.**

> *„Ein Screenshot?  Lachhaft.  Screenshot-Fälschung ist ein
> Zweisekunden-Job mit Photoshop."*

**Tempo:** ruhig, ernst.  Du rahmst das Problem, noch keine Lösung.

---

## 00:20 – 00:50 · Was Canon macht

> *„Wir bauen Canon.  Canon liest jede eingehende Business-Mail und
> extrahiert mit KI die eigentlichen Aussagen daraus — strukturiert.
> Wer hat was gesagt, über wen, wann, woher.  Wir nennen das einen
> 'Fact'.  Das ist die erste Hälfte des Produkts."*

**[Auf Projektor zeigen.]**

> *„Die zweite Hälfte ist das hier."*

**Browser-Tab in den Vordergrund.**

---

## 00:50 – 01:30 · Demo live

> *„Das ist der Canon Verifier.  Läuft zu hundert Prozent im Browser.
> Kein Login, kein Account, keine Canon-Infrastruktur nötig.  Ein
> reines HTML-Dokument plus zweihundertfünfzig Kilobyte WebAssembly."*

**[Load demo fact]** klicken.  Beide Textfelder füllen sich.

> *„Ich lade einen Beispiel-Fact.  Acme GmbH, Q1-Umsatz hundertsiebenundzwanzigtausend
> Euro, signiert am 24. April.  Und jetzt der Schlüsselmoment."*

**[Verify]** klicken.

**Kurze Pause — den Wachssiegel einstempeln lassen.**

> *„Grüner Wachssiegel.  Das ist unsere Metapher — ein digitales
> Wachssiegel, genauso wie im 16. Jahrhundert: fälschungssicher,
> sichtbar gebrochen, öffentlich prüfbar."*

**Scrollen zum Steps-Panel.**

> *„Und hier ist das, was Canon **anders** macht als jedes andere
> Produkt: Die zehn Schritte, die der Browser gerade gemacht hat.
> Jeder einzelne gezeigt.  Byte-Dump inklusive.  Ihr müsst mir
> **nichts** glauben — ihr seht selbst."*

---

## 01:30 – 02:10 · Das Tamper-Moment (Highlight)

> *„Ich kippe jetzt einen einzigen Buchstaben in der Signatur."*

**Im Envelope-Feld: ganz am Ende ein Hex-Zeichen ändern.**
Zum Beispiel `…a2d1c0d` → `…a2d1c0e`.

**[Verify]** klicken.

**Das Siegel bricht rot.  Schritt 7 leuchtet rot.**

> *„Siegel gebrochen.  Schritt sieben — Ed25519-Verifikation — rot.
> In vierhundert Millisekunden.  Das ist nicht 'wir loggen das und
> hoffen, dass es jemand merkt' — das ist **kryptografisch** nicht
> mehr reparierbar."*

**Pause.  Das wirkt.**

---

## 02:10 – 02:40 · Die Architektur in einem Atemzug

> *„Der Code, der die Siegel **macht**, läuft bei uns auf
> Canon-Servern.  Der Code, der sie **prüft**, ist diese
> Rust-WASM-Binary im Browser.  Die beiden Codebases teilen **null**
> Signing-Primitive."*

**Mit den Händen zwei getrennte Blöcke zeigen.**

> *„Heißt im Klartext: Selbst wenn jemand uns hackt, kann er keine
> gefälschten Facts ausstellen — sie würden im Browser des Empfängers
> **sofort** als rot erkannt."*

---

## 02:40 – 03:00 · Close

> *„Kein Blockchain.  Kein zentraler Timestamp-Server.  Kein
> Vendor-Lock.  Ein Canon-Fact ist genau zwei Strings: ein Hex-Envelope
> und ein Public Key.  Beide passen in einen QR-Code."*

**[QR-Code hochhalten oder Slide einblenden.]**

> *„Hier ist er.  Jeder im Saal kann das **jetzt gerade, live**,
> selbst nachprüfen.  Vier Sekunden.  Keine App, kein Account.
> Danke."*

**QR-Code stehen lassen.  Lächeln.**

---

## Q&A-Buffer (2 Minuten, falls gefragt)

### „Und wenn Canon kompromittiert wird?"

> *„Nur die **neuen** Siegel ab Kompromittierungs-Zeitpunkt sind
> verdächtig.  Alle vorher ausgestellten Facts bleiben verifizierbar,
> weil jeder seinen eigenen Public Key im Header trägt.  Wir rotieren
> Schlüssel regulär; der `kid` im Siegel ändert sich — das macht es
> sofort sichtbar."*

### „Warum nicht einfach Blockchain?"

> *„Weil Blockchain hier kein Problem löst, das wir haben.  Wir müssen
> nicht beweisen, dass **wir** was signiert haben — ein Public Key
> reicht.  Blockchain wäre ein Timestamp-Server mit globalem Konsens —
> brauchen wir nicht.  Was wir brauchen ist: das Siegel muss
> unverändert sein.  Das liefert Ed25519 in vierundsechzig Bytes, für
> null laufende Kosten."*

### „Warum COSE_Sign1?"

> *„Weil's ein IETF-Standard ist — RFC 9052.  JSON-Web-Tokens sind
> nicht deterministisch, also kann man nicht garantieren, dass zwei
> Verifier auf genau denselben Bytes arbeiten.  CBOR ist byte-exakt,
> kompakt, und passt in einen QR-Code.  Plus: in zehn Jahren ist COSE
> immer noch der Standard, auf den die IoT-Welt setzt — wir schreiben
> nichts selbst."*

### „Wie groß kann das werden?"

> *„Der Envelope ist typischerweise zweihundert Bytes, plus dem
> Public-Key-Bekanntmachung.  Ein Unternehmen mit zehntausend Mails
> pro Tag erzeugt weniger als zwei Megabyte signierte Facts pro Tag.
> Das passt in jede Datenbank, in jedes Backup, in jede Mail-Signatur.
> Skalierung ist kein Thema."*

### „Kann ich das heute testen?"

> *„Ja.  Scan den QR-Code, die Demo läuft im Browser.  Für die
> Signer-Integration: wir haben ein Rust-Sidecar, Docker-ready, eine
> JSON-Zeile rein, eine JSON-Zeile raus.  Zehn Minuten bis zum ersten
> signierten Fact aus eurem Stack."*

---

## Notfall-Plan — wenn das WLAN aussetzt

1. **Browser ist fertig geladen** vor Beginn.  WASM ist im Cache.
2. Wenn WLAN tot: der Verifier **läuft trotzdem** — er macht nach dem
   initialen Load **null Netzwerk-Calls**.  Jury darauf hinweisen:
   > *„Sehen Sie — wir haben das WLAN abgeschaltet.  Es läuft trotzdem.
   > Null Server, null Abhängigkeit."*
   Das wird zum **zusätzlichen Proof-Point**, nicht zum Problem.
3. QR-Code als Ausdruck ist unabhängig von allem.

---

## Stimme + Körpersprache

- **Tempo:** Ruhig, fast langsam.  Die Kryptographie braucht keine
  Eile, und Ruhe wirkt souveräner als Fachbegriffs-Feuerwerk.
- **Hände:** Wenn du die Architektur erklärst (02:10), zeig mit zwei
  Händen zwei getrennte Blöcke.  Das verankert „Trennung" visuell.
- **Blick:** Beim Hook und beim Close ins Publikum.  Beim Demo auf
  den Screen.
- **Den Tamper-Moment nicht erklären** — zeig ihn und lass ihn wirken.
  Die Stille nach dem roten Siegel ist dein bestes Argument.
