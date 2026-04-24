#!/usr/bin/env python3
"""
make-qr.py — generate the Canon Verifier QR codes.

Produces two QR variants, each in both PNG (for slides / print) and SVG
(for vector scaling):

    canon-verifier-qr-basic.{png,svg}
        → points at the bare verifier URL.  Scanning lands on the page;
        the auditor then clicks "Load demo fact" themselves.

    canon-verifier-qr-demo.{png,svg}
        → pre-loaded with the pinned demo envelope + pubkey so the page
        auto-verifies the moment it opens.  Ideal for a stage demo: one
        scan, green seal, done.

Usage
-----
    pip install qrcode
    python scripts/make-qr.py

Regenerates all four files into docs/assets/.  Idempotent — safe to run
on every doc update.
"""

from __future__ import annotations

import sys
from pathlib import Path

import qrcode
from qrcode.image.svg import SvgPathImage

# ───────── constants ─────────
HERE        = Path(__file__).resolve().parent
CRATE_ROOT  = HERE.parent                         # tools/canon-signer/
ASSETS_DIR  = CRATE_ROOT / "docs" / "assets"

LIVE_URL    = "https://thepyth0nkid.github.io/empheral/"

# Byte-identical to the fixture pinned in
# crates/canon-verify-wasm/tests/fixtures/mod.rs — kid canon/8a88e3dd7409f195.
DEMO_ENVELOPE = (
    "84581ba20127045663616e6f6e2f38613838653364643734303966313935a0587187"
    "406b665f64656d6f5f303030316d637573746f6d65723a61636d65781a5133312072"
    "6576656e75652077617320455552203132372c30303070676d61696c3a6d73675f61"
    "6263313233781d4f75722051312063616d6520696e206174203132376b204555522e"
    "2e2e1b0000018f10d5d4005840f1da68f2c73f1f53ead697488daa1fb18cbedf9f00"
    "3c7cb3a68c4df80893f3cb96559c5abd192a89d4fb05245f7190da6bd4036e3c7c41"
    "bb1d778d085a2d1c0d"
)
DEMO_PUBKEY = "ed25519:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="


def demo_url() -> str:
    # Matches app.js's URLSearchParams read: ?e=<hex>&pk=<wire>.
    # Quote nothing — both values are already URL-safe (hex + base64 with
    # `+ / =` — `=` is fine in a query value, `+` becomes space on the
    # receiving side unless pre-encoded, but all our base64 values in the
    # fixtures use the standard alphabet and we test for it round-tripping
    # correctly through the browser).  Keep it readable for the screenshot.
    return f"{LIVE_URL}?e={DEMO_ENVELOPE}&pk={DEMO_PUBKEY}"


def write_png(data: str, out: Path) -> None:
    # ERROR_CORRECT_M gives ~15% redundancy — enough for a printed page
    # with a coffee ring on it, without making the code uselessly dense.
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#2a241b", back_color="#f6efd8")
    img.save(out)
    print(f"  wrote {out.relative_to(CRATE_ROOT)}  ({img.size[0]}×{img.size[1]})")


def write_svg(data: str, out: Path) -> None:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
        image_factory=SvgPathImage,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(str(out))
    print(f"  wrote {out.relative_to(CRATE_ROOT)}")


def main() -> int:
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    targets = [
        ("basic", LIVE_URL),
        ("demo",  demo_url()),
    ]

    print(f"Canon Verifier QR generator")
    print(f"  live URL       : {LIVE_URL}")
    print(f"  demo URL length: {len(demo_url())} chars")
    print(f"  output dir     : {ASSETS_DIR.relative_to(CRATE_ROOT)}")
    print()

    for tag, data in targets:
        print(f"• {tag}")
        write_png(data, ASSETS_DIR / f"canon-verifier-qr-{tag}.png")
        write_svg(data, ASSETS_DIR / f"canon-verifier-qr-{tag}.svg")

    print()
    print("Done.  Both variants render in any camera app.")
    print("For stage: print the demo QR at >= 6 cm across so the jury in")
    print("the back row can scan from ~3 m away.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
