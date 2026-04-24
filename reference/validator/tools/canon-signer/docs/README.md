# canon-signer Documentation

Drei Einstiegspunkte — wähle nach deinem Zweck:

| Du willst …                                                         | Lies                               |
|---------------------------------------------------------------------|------------------------------------|
| Verstehen, **wie das Ding technisch funktioniert**                  | [TECHNICAL.md](./TECHNICAL.md)     |
| Jemandem erklären, **warum das wichtig ist**, ohne Jargon           | [EXPLAINER.md](./EXPLAINER.md)     |
| Es auf dem **Hackathon vorführen** oder für ein Demo prüfen         | [HACKATHON.md](./HACKATHON.md)     |
| Nur **bauen + wire-protocol nachschlagen**                          | [../README.md](../README.md)       |

## Diagramme

Jedes Diagramm liegt in zwei Formaten in `diagrams/` nebeneinander:

- **`.svg`** — wird direkt in den Markdown-Docs inline gerendert (GitHub, Obsidian-Preview).
- **`.excalidraw`** — bearbeitbar: drop auf [excalidraw.ultranova.io](https://excalidraw.ultranova.io) oder via Obsidian Excalidraw-Plugin importieren.

| Thema | SVG (inline) | Excalidraw (editable) | Verwendet in |
|-------|--------------|------------------------|--------------|
| Architecture | [`architecture.svg`](./diagrams/architecture.svg) | [`architecture.excalidraw`](./diagrams/architecture.excalidraw) | TECHNICAL §1 |
| CBOR Layout | [`cbor-layout.svg`](./diagrams/cbor-layout.svg) | [`cbor-layout.excalidraw`](./diagrams/cbor-layout.excalidraw) | TECHNICAL §3 |
| Notary analogy | [`notary.svg`](./diagrams/notary.svg) | [`notary.excalidraw`](./diagrams/notary.excalidraw) | EXPLAINER §"Notary" |
| Hash chain | [`chain.svg`](./diagrams/chain.svg) | [`chain.excalidraw`](./diagrams/chain.excalidraw) | EXPLAINER §"Chain" |
| Review-Swarm | [`review-swarm.svg`](./diagrams/review-swarm.svg) | [`review-swarm.excalidraw`](./diagrams/review-swarm.excalidraw) | EXPLAINER §"Review-Swarm" |

Die `.md`s enthalten zusätzlich Mermaid-Fallbacks in `<details>`-Blöcken — für den Fall, dass ein Reader SVGs nicht rendern kann.

### Diagramme regenerieren

Beide Formate werden aus **einem** Skript deterministisch erzeugt (gleiche RNG-Seeds → gleiche Bytes):

```bash
cd docs/diagrams
python generate.py
# → architecture.svg + architecture.excalidraw (5×)
```

Farben, Fonts und Layout stehen im Skript-Header. Wenn du das Layout änderst, **committe beide** — `.svg` fürs README-Rendering, `.excalidraw` zum Weiterbearbeiten.

## Quick links zurück in den Code

- Crate-Root: [../src/lib.rs](../src/lib.rs)
- Wire types + stdin loop: [../src/io.rs](../src/io.rs)
- COSE envelope builder: [../src/cose.rs](../src/cose.rs)
- Canonical CBOR encoder: [../src/event.rs](../src/event.rs)
- Key loading + zeroize: [../src/key.rs](../src/key.rs)
- Load-bearing round-trip test: [../tests/round_trip.rs](../tests/round_trip.rs)
