# canon-signer Documentation

Drei Einstiegspunkte — wähle nach deinem Zweck:

| Du willst …                                                         | Lies                               |
|---------------------------------------------------------------------|------------------------------------|
| Verstehen, **wie das Ding technisch funktioniert**                  | [TECHNICAL.md](./TECHNICAL.md)     |
| Jemandem erklären, **warum das wichtig ist**, ohne Jargon           | [EXPLAINER.md](./EXPLAINER.md)     |
| Es auf dem **Hackathon vorführen** oder für ein Demo prüfen         | [HACKATHON.md](./HACKATHON.md)     |
| Nur **bauen + wire-protocol nachschlagen**                          | [../README.md](../README.md)       |

## Diagramme

Alle fünf Diagramme liegen als fertige `.excalidraw`-Dateien in `diagrams/`. Drag & drop auf [excalidraw.ultranova.io](https://excalidraw.ultranova.io) oder über den Obsidian Excalidraw-Plugin importieren (File → Import → `.excalidraw`).

| Datei | Was es zeigt | Verwendet in |
|-------|--------------|--------------|
| [`architecture.excalidraw`](./diagrams/architecture.excalidraw) | 3-Swim-Lane: Canon / canon-signer / Verifier + 6-Schritt-Pipeline | TECHNICAL §1 |
| [`cbor-layout.excalidraw`](./diagrams/cbor-layout.excalidraw) | 7 positionale CBOR-Boxen + `bstr` vs `tstr` / `array` vs `map` Rationale | TECHNICAL §4 |
| [`notary.excalidraw`](./diagrams/notary.excalidraw) | Notar-Analogie (email → Canon → signer → Buch) + drei Prinzipien | EXPLAINER §"Notary" |
| [`chain.excalidraw`](./diagrams/chain.excalidraw) | Saubere 4-Fakt-Kette + getamperte Variante mit Parent-Mismatch | EXPLAINER §"Chain" |
| [`review-swarm.excalidraw`](./diagrams/review-swarm.excalidraw) | Parallele Security+Code-Reviewer + reale Bugs, die sie gefangen haben | EXPLAINER §"Review-Swarm" |

Die Markdown-Dokumente enthalten zusätzlich Mermaid-Inline-Fallbacks, damit GitHub direkt ohne Excalidraw-Import rendert.

### Diagramme regenerieren

Die `.excalidraw`-Dateien werden deterministisch aus `diagrams/generate.py` erzeugt. Nach Änderungen am Skript:

```bash
cd docs/diagrams
python generate.py
```

Fonts, Farben und Layout werden aus dem Skript-Header gesteuert — Palette nah an Nelsons homelab-Diagrammen.

## Quick links zurück in den Code

- Crate-Root: [../src/lib.rs](../src/lib.rs)
- Wire types + stdin loop: [../src/io.rs](../src/io.rs)
- COSE envelope builder: [../src/cose.rs](../src/cose.rs)
- Canonical CBOR encoder: [../src/event.rs](../src/event.rs)
- Key loading + zeroize: [../src/key.rs](../src/key.rs)
- Load-bearing round-trip test: [../tests/round_trip.rs](../tests/round_trip.rs)
