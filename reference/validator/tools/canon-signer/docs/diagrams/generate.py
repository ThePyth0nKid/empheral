"""Generate the 5 canon-signer .excalidraw diagrams deterministically.

Run:  python generate.py
Output: architecture.excalidraw, cbor-layout.excalidraw, notary.excalidraw,
        chain.excalidraw, review-swarm.excalidraw — drop any of them into
        excalidraw.ultranova.io or open with the Obsidian Excalidraw plugin
        (File -> Import -> .excalidraw).

Style matches Nelson's existing homelab diagrams: dark-on-cream, hand-drawn
roughness, sections labelled as a top-down story.
"""
from __future__ import annotations

import json
import random
import time
import zlib
from pathlib import Path

# Deterministic across runs — same file, same bytes.
_rng = random.Random(0xCA10C)


def _seed() -> int:
    return _rng.randint(1, 2**31 - 1)


def _id(prefix: str) -> str:
    return f"{prefix}-{_rng.randint(0, 2**32):08x}"


NOW_MS = 1_713_974_400_000

# Palette — close to Nelson's home-cluster diagram hues.
INK = "#1e1e1e"
CREAM = "#fef9e7"
BLUE = "#a5d8ff"
GREEN = "#b2f2bb"
AMBER = "#ffe066"
RED = "#ffa8a8"
PURPLE = "#d0bfff"
GREY = "#dee2e6"
NONE = "transparent"


def _base_element(etype: str, x: int, y: int, w: int, h: int) -> dict:
    return {
        "id": _id(etype),
        "type": etype,
        "x": x,
        "y": y,
        "width": w,
        "height": h,
        "angle": 0,
        "strokeColor": INK,
        "backgroundColor": NONE,
        "fillStyle": "solid",
        "strokeWidth": 2,
        "strokeStyle": "solid",
        "roughness": 1,
        "opacity": 100,
        "groupIds": [],
        "frameId": None,
        "roundness": {"type": 3},
        "seed": _seed(),
        "version": 1,
        "versionNonce": _seed(),
        "isDeleted": False,
        "boundElements": None,
        "updated": NOW_MS,
        "link": None,
        "locked": False,
    }


def rect(x, y, w, h, fill=NONE, stroke=INK):
    el = _base_element("rectangle", x, y, w, h)
    el["backgroundColor"] = fill
    el["strokeColor"] = stroke
    return el


def diamond(x, y, w, h, fill=NONE):
    el = _base_element("diamond", x, y, w, h)
    el["backgroundColor"] = fill
    return el


def ellipse(x, y, w, h, fill=NONE):
    el = _base_element("ellipse", x, y, w, h)
    el["backgroundColor"] = fill
    return el


def text(x, y, s, size=20, w=None, align="center", color=INK):
    # Rough width guess; Excalidraw fixes on open.
    font_w = int(size * 0.6)
    if w is None:
        lines = s.split("\n")
        w = max(len(line) for line in lines) * font_w + 10
    h = size * (s.count("\n") + 1) + 4
    el = _base_element("text", x, y, w, h)
    el["strokeColor"] = color
    el["text"] = s
    el["fontSize"] = size
    el["fontFamily"] = 1  # Virgil (hand-drawn)
    el["textAlign"] = align
    el["verticalAlign"] = "middle"
    el["baseline"] = int(size * 0.85)
    el["containerId"] = None
    el["originalText"] = s
    el["lineHeight"] = 1.25
    return el


def arrow(x1, y1, x2, y2, dashed=False):
    x = min(x1, x2)
    y = min(y1, y2)
    w = abs(x2 - x1)
    h = abs(y2 - y1)
    el = _base_element("arrow", x, y, w, h)
    el["points"] = [[x1 - x, y1 - y], [x2 - x, y2 - y]]
    el["lastCommittedPoint"] = None
    el["startBinding"] = None
    el["endBinding"] = None
    el["startArrowhead"] = None
    el["endArrowhead"] = "arrow"
    el["elbowed"] = False
    if dashed:
        el["strokeStyle"] = "dashed"
    return el


def line(x1, y1, x2, y2, color=INK):
    x = min(x1, x2)
    y = min(y1, y2)
    w = abs(x2 - x1)
    h = abs(y2 - y1)
    el = _base_element("line", x, y, w, h)
    el["strokeColor"] = color
    el["points"] = [[x1 - x, y1 - y], [x2 - x, y2 - y]]
    el["lastCommittedPoint"] = None
    el["startBinding"] = None
    el["endBinding"] = None
    return el


def _xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


_FONT_STACK = (
    "'Segoe Print', 'Bradley Hand', 'Comic Sans MS', "
    "'Caveat', 'Patrick Hand', cursive, sans-serif"
)


def _svg_element(el: dict) -> str:
    t = el["type"]
    sc = el["strokeColor"]
    sw = el.get("strokeWidth", 2)
    bg = el.get("backgroundColor", NONE)
    fill = bg if bg and bg != NONE else "none"

    if t == "rectangle":
        return (
            f'<rect x="{el["x"]}" y="{el["y"]}" width="{el["width"]}" height="{el["height"]}"'
            f' rx="10" ry="10" fill="{fill}" stroke="{sc}" stroke-width="{sw}"/>'
        )
    if t == "ellipse":
        cx = el["x"] + el["width"] / 2
        cy = el["y"] + el["height"] / 2
        return (
            f'<ellipse cx="{cx}" cy="{cy}" rx="{el["width"] / 2}" ry="{el["height"] / 2}"'
            f' fill="{fill}" stroke="{sc}" stroke-width="{sw}"/>'
        )
    if t == "diamond":
        x, y, w, h = el["x"], el["y"], el["width"], el["height"]
        pts = f"{x + w / 2},{y} {x + w},{y + h / 2} {x + w / 2},{y + h} {x},{y + h / 2}"
        return f'<polygon points="{pts}" fill="{fill}" stroke="{sc}" stroke-width="{sw}"/>'
    if t in ("arrow", "line"):
        ox, oy = el["x"], el["y"]
        pts = el.get("points") or [[0, 0], [el["width"], el["height"]]]
        x1, y1 = ox + pts[0][0], oy + pts[0][1]
        x2, y2 = ox + pts[-1][0], oy + pts[-1][1]
        dash = ' stroke-dasharray="10,6"' if el.get("strokeStyle") == "dashed" else ""
        marker = ' marker-end="url(#arrow-ink)"' if t == "arrow" else ""
        return (
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"'
            f' stroke="{sc}" stroke-width="{sw}" stroke-linecap="round"{dash}{marker}/>'
        )
    if t == "text":
        size = el["fontSize"]
        align = el.get("textAlign", "center")
        anchor = {"left": "start", "center": "middle", "right": "end"}.get(align, "middle")
        if align == "left":
            tx = el["x"]
        elif align == "right":
            tx = el["x"] + el["width"]
        else:
            tx = el["x"] + el["width"] / 2
        cy = el["y"] + el["height"] / 2
        lines = el["text"].split("\n")
        line_h = size * 1.25
        first_y = cy - (len(lines) - 1) * line_h / 2
        tspans = []
        for i, ln in enumerate(lines):
            dy = 0 if i == 0 else line_h
            tspans.append(f'<tspan x="{tx}" dy="{dy}">{_xml_escape(ln)}</tspan>')
        return (
            f'<text x="{tx}" y="{first_y}" font-size="{size}" fill="{sc}"'
            f' font-family="{_FONT_STACK}"'
            f' text-anchor="{anchor}" dominant-baseline="middle">{"".join(tspans)}</text>'
        )
    return ""


def _render_svg(elements: list, bg: str) -> str:
    # Bounding box across all elements (includes text for safety).
    min_x = min_y = float("inf")
    max_x = max_y = float("-inf")
    for el in elements:
        x, y = el["x"], el["y"]
        w, h = el["width"], el["height"]
        if el["type"] in ("arrow", "line"):
            ox, oy = x, y
            pts = el.get("points") or [[0, 0], [w, h]]
            for px, py in pts:
                ax, ay = ox + px, oy + py
                min_x = min(min_x, ax); min_y = min(min_y, ay)
                max_x = max(max_x, ax); max_y = max(max_y, ay)
            continue
        min_x = min(min_x, x); min_y = min(min_y, y)
        max_x = max(max_x, x + w); max_y = max(max_y, y + h)

    pad = 30
    min_x -= pad; min_y -= pad
    max_x += pad; max_y += pad
    vw = max_x - min_x
    vh = max_y - min_y

    head = (
        f'<svg xmlns="http://www.w3.org/2000/svg"'
        f' viewBox="{min_x:.0f} {min_y:.0f} {vw:.0f} {vh:.0f}"'
        f' width="{vw:.0f}" height="{vh:.0f}"'
        f' font-family="{_FONT_STACK}">'
    )
    defs = (
        '<defs>'
        '<marker id="arrow-ink" viewBox="0 0 10 10" refX="9" refY="5"'
        ' markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{INK}"/>'
        '</marker>'
        '</defs>'
    )
    bg_rect = (
        f'<rect x="{min_x:.0f}" y="{min_y:.0f}" width="{vw:.0f}" height="{vh:.0f}"'
        f' fill="{bg}"/>'
    )
    body = "\n  ".join(_svg_element(el) for el in elements if _svg_element(el))
    return f"{head}\n{defs}\n  {bg_rect}\n  {body}\n</svg>\n"


def save(elements: list, name: str, bg: str = "#fef9e7"):
    doc = {
        "type": "excalidraw",
        "version": 2,
        "source": "https://excalidraw.ultranova.io",
        "elements": elements,
        "appState": {
            "gridSize": None,
            "gridStep": 5,
            "viewBackgroundColor": bg,
        },
        "files": {},
    }
    out_dir = Path(__file__).parent
    exc_path = out_dir / f"{name}.excalidraw"
    exc_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")

    svg_path = out_dir / f"{name}.svg"
    svg_path.write_text(_render_svg(elements, bg), encoding="utf-8")

    print(f"wrote {exc_path.name} + {svg_path.name} ({len(elements)} elements)")


# ============================================================
# 1. architecture.excalidraw
# ============================================================
def architecture() -> list:
    els: list = []

    # Title
    els.append(text(60, 20, "canon-signer — Architecture", size=28, align="left"))
    els.append(text(60, 56, "Canon (Node.js)  ↔  canon-signer (Rust sidecar)  ↔  Any Verifier", size=16, align="left", color="#666"))

    # ------- Canon swim lane (left) -------
    els.append(rect(40, 100, 260, 500, fill="#eaf4ff"))
    els.append(text(170, 120, "Canon (Node.js)", size=22))
    els.append(rect(70, 170, 200, 70, fill=BLUE))
    els.append(text(170, 195, "Fact Extractor\n(email → JSON)", size=14))
    els.append(rect(70, 280, 200, 70, fill=BLUE))
    els.append(text(170, 305, "spawn + pipe\n(stdio)", size=14))
    els.append(rect(70, 480, 200, 70, fill=BLUE))
    els.append(text(170, 505, "Store signed fact", size=14))

    # ------- canon-signer swim lane (center) -------
    els.append(rect(360, 100, 360, 500, fill="#fff4cc"))
    els.append(text(540, 120, "canon-signer (Rust)", size=22))

    # Pipeline boxes
    step_xs = [390, 390, 390, 390, 390, 390]
    step_ys = [170, 235, 300, 365, 430, 495]
    step_labels = [
        "1. stdin read_line",
        "2. JSON parse + size caps",
        "3. CBOR encode (7-field array)",
        "4. SHA-256 = event_hash",
        "5. COSE_Sign1 build (Ed25519)",
        "6. hex + JSON stdout flush",
    ]
    for i, (sx, sy, sl) in enumerate(zip(step_xs, step_ys, step_labels)):
        fill = AMBER if i < 4 else GREEN
        els.append(rect(sx, sy, 300, 55, fill=fill))
        els.append(text(sx + 150, sy + 27, sl, size=14))

    # ------- Verifier swim lane (right) -------
    els.append(rect(780, 100, 260, 500, fill="#efe7ff"))
    els.append(text(910, 120, "Any Verifier", size=22))
    els.append(rect(810, 280, 200, 100, fill=PURPLE))
    els.append(text(910, 320, "ephemeral_crypto::\nverify_cose_sign1", size=14))

    # Connectors: Canon → signer → Canon (loop), signer → Verifier (audit)
    els.append(arrow(270, 315, 395, 195))   # Canon spawn -> stdin
    els.append(arrow(395, 522, 270, 515))   # signer stdout -> Canon store
    els.append(arrow(720, 522, 815, 330, dashed=True))  # store -> verifier (later)
    els.append(text(740, 540, "later: audit", size=12, color="#777"))

    # Footnote
    els.append(text(60, 620, "One Node process + one Rust process. Sub-ms sign latency. 38 tests. Zero unsafe. Zero network.",
                   size=14, align="left", color="#555"))

    return els


# ============================================================
# 2. cbor-layout.excalidraw
# ============================================================
def cbor_layout() -> list:
    els: list = []
    els.append(text(40, 20, "Canonical CBOR Payload — the exact bytes that get signed", size=24, align="left"))
    els.append(text(40, 56, "Positional array of 7.  No map, no keys, no ordering ambiguity.  RFC 8949 §4.2 deterministic.",
                   size=14, align="left", color="#666"))

    els.append(text(40, 110, "CBOR header byte:  0x87   (= major type 4 = array, short count = 7)",
                   size=14, align="left", color="#555"))

    # 7 boxes horizontally
    fields = [
        ("[0]  parent_hash", "bstr", "hex-decoded bytes\nbstr<0> for genesis", BLUE),
        ("[1]  fact_id", "tstr", "ULID / UUID", GREEN),
        ("[2]  entity", "tstr", "customer:acme", GREEN),
        ("[3]  claim", "tstr", '"Q1 revenue …"', AMBER),
        ("[4]  source_ref", "tstr", "gmail:msg_abc", GREEN),
        ("[5]  source_excerpt", "tstr | null", "null = 0xf6", GREY),
        ("[6]  created_at_ms", "uint", "positive integer", BLUE),
    ]
    x = 40
    y = 160
    w = 180
    for name, ct, desc, fill in fields:
        els.append(rect(x, y, w, 170, fill=fill))
        els.append(text(x + w // 2, y + 20, name, size=14))
        els.append(line(x + 10, y + 42, x + w - 10, y + 42))
        els.append(text(x + w // 2, y + 62, ct, size=16))
        els.append(text(x + w // 2, y + 105, desc, size=12, color="#333"))
        x += w + 12

    # Brace below
    els.append(line(40, 360, 40 + 7 * (w + 12) - 12, 360))
    els.append(text((40 + 40 + 7 * (w + 12) - 12) // 2, 390,
                   "SHA-256 over the whole array bytes  →  event_hash (64 hex chars)", size=16))

    # "Why bstr not tstr?" callout
    els.append(rect(40, 450, 680, 110, fill="#fff0f0", stroke="#c92a2a"))
    els.append(text(380, 470, "Why bstr for parent_hash (not tstr)?", size=15, color="#c92a2a"))
    els.append(text(380, 510,
                   "• Hex case ambiguity would make 'AB' and 'ab' distinct text but identical bytes.\n"
                   "• Genesis = empty bstr (0x40), byte-distinct from empty tstr (0x60). No ambiguity.",
                   size=13))

    # "Why array not map?" callout
    els.append(rect(740, 450, 580, 110, fill="#f0fff4", stroke="#2b8a3e"))
    els.append(text(1030, 470, "Why array, not map?", size=15, color="#2b8a3e"))
    els.append(text(1030, 510,
                   "A map has key-ordering rules that libraries can drift on.\n"
                   "A positional array is canonical by construction — no keys exist to sort.",
                   size=13))

    return els


# ============================================================
# 3. notary.excalidraw (explainer — notary analogy)
# ============================================================
def notary() -> list:
    els: list = []
    els.append(text(40, 20, "The Notary Analogy", size=28, align="left"))
    els.append(text(40, 56, "canon-signer = a notary for business facts extracted from your inbox",
                   size=16, align="left", color="#666"))

    # Flow: email -> Canon -> signer -> book (db)
    els.append(ellipse(50, 150, 180, 120, fill=BLUE))
    els.append(text(140, 185, "📧\nEmail arrives", size=16))

    els.append(arrow(235, 210, 315, 210))

    els.append(rect(320, 150, 180, 120, fill=GREEN))
    els.append(text(410, 185, "🤖 Canon\n(extracts fact)", size=16))

    els.append(arrow(505, 210, 585, 210))

    els.append(rect(590, 150, 220, 120, fill=AMBER, stroke="#c92a2a"))
    els.append(text(700, 175, "🔏 canon-signer", size=18))
    els.append(text(700, 205, "stamps it", size=14))
    els.append(text(700, 232, "(Ed25519 + COSE_Sign1)", size=11, color="#555"))

    els.append(arrow(815, 210, 895, 210))

    els.append(rect(900, 150, 200, 120, fill=PURPLE))
    els.append(text(1000, 185, "📚 Canon DB\n(the leather book)", size=16))

    # Three principles box
    els.append(text(40, 340, "Three things make a notary trustworthy — and canon-signer replicates each:",
                   size=16, align="left"))

    principles = [
        ("1. The stamp is unique", "Only the notary has the wax seal.",
         "canon-signer holds a 32-byte Ed25519 private key. Forging a matching signature is cryptographically infeasible.", BLUE),
        ("2. The book is sequential", "Entry #1038 sits between #1037 and #1039.",
         "Every fact embeds parent_hash of the previous one. Insert attempts break the chain.", GREEN),
        ("3. Tampering is loud", "Rip out a page — the numbering breaks.",
         "Change any byte → hash changes → every later fact's parent_hash is wrong.", AMBER),
    ]
    y = 400
    for title, old_world, new_world, fill in principles:
        els.append(rect(40, y, 1060, 110, fill=fill))
        els.append(text(60, y + 22, title, size=17, align="left"))
        els.append(text(60, y + 52, "Old world:  " + old_world, size=13, align="left", color="#555"))
        els.append(text(60, y + 80, "canon-signer:  " + new_world, size=13, align="left"))
        y += 125

    return els


# ============================================================
# 4. chain.excalidraw (hash chain visualisation)
# ============================================================
def chain() -> list:
    els: list = []
    els.append(text(40, 20, "The Hash Chain — why tampering breaks everything", size=28, align="left"))
    els.append(text(40, 56, "Every fact points backward at the one before via parent_hash. Editing any fact poisons the chain from that point.",
                   size=14, align="left", color="#666"))

    # 4 facts in a chain
    facts = [
        ("🌱 Genesis", "parent_hash: \"\"", "hash: a3f2…", "#d0f0ff"),
        ("Fact A", "parent: a3f2…", "hash: b4e1…", GREEN),
        ("Fact B", "parent: b4e1…", "hash: c5d0…", GREEN),
        ("Fact C", "parent: c5d0…", "hash: d6e9…", GREEN),
    ]
    x = 60
    y = 150
    w = 200
    h = 160
    centers: list[tuple[int, int]] = []
    for i, (title, parent, h_hash, fill) in enumerate(facts):
        els.append(rect(x, y, w, h, fill=fill))
        els.append(text(x + w // 2, y + 22, title, size=18))
        els.append(line(x + 10, y + 48, x + w - 10, y + 48))
        els.append(text(x + w // 2, y + 72, parent, size=12))
        els.append(text(x + w // 2, y + 102, h_hash, size=12))
        els.append(text(x + w // 2, y + 132, "signed ✔", size=12, color="#2b8a3e"))
        centers.append((x + w // 2, y + h // 2))
        if i < len(facts) - 1:
            els.append(arrow(x + w, y + h // 2, x + w + 60, y + h // 2))
        x += w + 60

    # Tampered scenario — copy the chain below, break Fact B
    els.append(text(40, 370, "⚠  Attacker edits Fact B.  Watch the chain react:",
                   size=18, align="left", color="#c92a2a"))

    y2 = 420
    x2 = 60
    tamper_facts = [
        ("🌱 Genesis", "parent: \"\"", "hash: a3f2…", GREEN, "valid"),
        ("Fact A", "parent: a3f2…", "hash: b4e1…", GREEN, "valid"),
        ("Fact B 🖋️", "parent: b4e1…", "hash: XXXX…", "#ffc9c9", "edited → new hash"),
        ("Fact C", "parent: c5d0… ❌", "hash: d6e9…", "#ffc9c9", "parent mismatch!"),
    ]
    for i, (title, parent, h_hash, fill, status) in enumerate(tamper_facts):
        els.append(rect(x2, y2, w, h, fill=fill))
        els.append(text(x2 + w // 2, y2 + 22, title, size=18))
        els.append(line(x2 + 10, y2 + 48, x2 + w - 10, y2 + 48))
        els.append(text(x2 + w // 2, y2 + 72, parent, size=12))
        els.append(text(x2 + w // 2, y2 + 102, h_hash, size=12))
        status_color = "#2b8a3e" if status == "valid" else "#c92a2a"
        els.append(text(x2 + w // 2, y2 + 132, status, size=12, color=status_color))
        if i < len(tamper_facts) - 1:
            els.append(arrow(x2 + w, y2 + h // 2, x2 + w + 60, y2 + h // 2))
        x2 += w + 60

    # Footnote
    els.append(text(40, 610,
                   "To cover the forgery, the attacker would need to re-sign every subsequent fact — but that requires the private key, which they don't have.",
                   size=14, align="left", color="#555"))

    return els


# ============================================================
# 5. review-swarm.excalidraw
# ============================================================
def review_swarm() -> list:
    els: list = []
    els.append(text(40, 20, "The Review Swarm — two independent AI reviewers in parallel", size=26, align="left"))
    els.append(text(40, 52, "Every commit to canon-signer went through this before it shipped.",
                   size=14, align="left", color="#666"))

    # Code (top)
    els.append(rect(460, 120, 280, 110, fill=BLUE))
    els.append(text(600, 160, "📝 Fresh code", size=20))
    els.append(text(600, 195, "src/*.rs, tests/*.rs", size=13, color="#333"))

    # Two reviewers in parallel
    els.append(arrow(550, 232, 250, 330))
    els.append(arrow(650, 232, 950, 330))

    els.append(rect(100, 340, 300, 140, fill=AMBER, stroke="#c92a2a"))
    els.append(text(250, 370, "🔒 Security reviewer", size=18))
    els.append(text(250, 405, "Crypto mistakes, memory safety,\nattack surfaces, zeroize discipline", size=13, color="#333"))

    els.append(rect(800, 340, 300, 140, fill=AMBER, stroke="#1864ab"))
    els.append(text(950, 370, "🔍 Code reviewer", size=18))
    els.append(text(950, 405, "Bugs, sloppy patterns,\nhidden assumptions, test quality", size=13, color="#333"))

    # Findings box
    els.append(arrow(250, 485, 520, 570))
    els.append(arrow(950, 485, 680, 570))

    els.append(rect(420, 580, 360, 130, fill=PURPLE))
    els.append(text(600, 610, "📋  Findings", size=20))
    els.append(text(600, 645, "0 critical · 4 high · 5 medium\n4 low · 3 nitpick", size=14))
    els.append(text(600, 690, "Every single one folded into commit.", size=12, color="#555"))

    # Downstream: fix + re-run + ship
    els.append(arrow(600, 715, 600, 760))

    els.append(rect(400, 770, 400, 80, fill=GREEN))
    els.append(text(600, 810, "🔧 Inline fixes  ✓  cargo clippy -D warnings  ✓  38 tests", size=14))

    els.append(arrow(600, 855, 600, 900))

    els.append(rect(460, 910, 280, 70, fill="#d0f0ff"))
    els.append(text(600, 945, "🚀 Ship to feat/canon-signer", size=16))

    # Examples sidebar — real bugs caught
    els.append(rect(40, 580, 350, 370, fill="#fff0f0", stroke="#c92a2a"))
    els.append(text(215, 610, "Real bugs they caught:", size=15, color="#c92a2a"))
    bugs = [
        "• Stack [u8;32] seed buffer not zeroized",
        "  (only the heap Vec was) → both scrubbed now",
        "",
        "• hex_seed String lived in memory after",
        "  fs::write → now zeroed explicitly",
        "",
        "• Error slug ambiguous: parse_error used",
        "  for both bad JSON and unknown op",
        "  → split into parse_error + unsupported_op",
        "",
        "• Test used matches!(…) silently — passed",
        "  even when pattern didn't match",
        "  → wrapped in assert!(matches!(…))",
    ]
    ly = 640
    for bug in bugs:
        els.append(text(55, ly, bug, size=12, align="left"))
        ly += 22

    return els


def main() -> None:
    for name, builder in [
        ("architecture", architecture),
        ("cbor-layout", cbor_layout),
        ("notary", notary),
        ("chain", chain),
        ("review-swarm", review_swarm),
    ]:
        _rng.seed(zlib.crc32(name.encode("utf-8")))  # stable across runs
        save(builder(), name)


if __name__ == "__main__":
    main()
