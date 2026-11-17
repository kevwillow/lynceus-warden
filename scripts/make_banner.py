#!/usr/bin/env python3
"""
README banner and logo mark for Lynceus Warden.

The mark is a shield holding an arriving signal. It is a deliberate structural
sibling to the Argus mark and shares none of its shapes: Argus is one container
(an eye) holding a motif (concentric rings, a thing already catalogued), and
this is one container (a shield, because Warden is in the name) holding a motif
(arcs sweeping in toward a point).

The arcs arrive from ABOVE and terminate at the dot, symmetric about the
vertical centre. Shield plus signal reads as wireless defence, which is the
product. The shield carries "passive" and "defensive", so the arcs only have to
carry "wireless" and do not have to fight to say "receiving" on their own.

Three earlier attempts are worth not repeating. An eye was too close to Argus.
A lighthouse emits, which is the opposite of the product. A transmission mast
is the universal icon for broadcasting, and reads as exactly the wrong thing.
A tower plus separate arcs is two objects competing in a square and turned to
mush below 64px; the mark was redesigned square-first after measuring that.

It is now drawn low-poly, as flat shaded facets, to match the other project
marks on gurutechnology.services: a gold shield, three navy arcs and the red
dot. The filled facets carry three arcs at 32px where the old outline could
only carry two.

PNG rather than SVG on purpose. GitHub sanitises SVG in markdown, and text in an
SVG depends on fonts the reader may not have. A PNG renders identically
everywhere. Everything is drawn at SS x supersample and downsampled with LANCZOS,
because GitHub serves the file at the reader's column width and a 1x render looks
soft on a HiDPI screen.

Usage:
    python3 scripts/make_banner.py
"""
import os
import xml.etree.ElementTree as ET

from PIL import Image, ImageDraw, ImageFont

SS = 4                                   # supersample factor
GROUND = (13, 13, 15)                    # near-black page ground
TEXT = (242, 240, 238)
MUTED = (139, 134, 128)
ACCENT = (200, 16, 46)                   # the same red Argus uses; these are siblings

FONT_DIRS = ["/usr/share/fonts", "/usr/local/share/fonts", os.path.expanduser("~/.fonts")]
FONT_PREFS = {
    "bold": ["DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf", "NotoSans-Bold.ttf"],
    "regular": ["DejaVuSans.ttf", "LiberationSans-Regular.ttf", "NotoSans-Regular.ttf"],
    "mono": ["DejaVuSansMono.ttf", "LiberationMono-Regular.ttf"],
}


def font(kind, size):
    for name in FONT_PREFS[kind]:
        for root in FONT_DIRS:
            for dirpath, _, files in os.walk(root):
                if name in files:
                    return ImageFont.truetype(os.path.join(dirpath, name), size)
    return ImageFont.load_default()


# ---- the low-poly mark ------------------------------------------------------
# The mark is docs/assets/lynceus-mark.svg, the same file gurutechnology.services
# shows: flat shaded polygons in a 64-unit box. draw_mark reads those polygons
# and scales them to pixels, so these PNGs cannot drift from the site's mark.
MARK_SVG = os.path.join(os.path.dirname(__file__), "..", "docs", "assets", "lynceus-mark.svg")


def _mark_polygons():
    """[(rgb, [(x, y), ...]), ...] from MARK_SVG, in drawing order."""
    polys = []
    for el in ET.parse(MARK_SVG).iter("{http://www.w3.org/2000/svg}polygon"):
        nums = [float(v) for v in el.get("points").replace(",", " ").split()]
        fill = el.get("fill").lstrip("#")
        rgb = tuple(int(fill[i:i + 2], 16) for i in (0, 2, 4))
        polys.append((rgb, list(zip(nums[::2], nums[1::2], strict=True))))
    if not polys:
        raise SystemExit(f"no polygons found in {MARK_SVG}")
    return polys


def draw_mark(d, cx, cy, size):
    """Draw the mark centred on (cx, cy), its longer side `size` pixels.

    Each polygon is outlined in its own colour, so no seam shows between
    neighbours after the LANCZOS downsample.
    """
    polys = _mark_polygons()
    xs = [x for _, pts in polys for x, _ in pts]
    ys = [y for _, pts in polys for _, y in pts]
    s = size / max(max(xs) - min(xs), max(ys) - min(ys))
    mx, my = (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2
    for rgb, pts in polys:
        d.polygon([(cx + (x - mx) * s, cy + (y - my) * s) for x, y in pts], fill=rgb, outline=rgb)


def make_logo(path, size=512):
    """Square mark on a transparent ground, for a favicon, avatar or docs header.

    The faceted mark is filled, so one drawing reads on light and dark pages.
    The -dark file is kept under its old name for anything that links to it.
    """
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    draw_mark(d, s / 2, s / 2, s * 0.90)
    img.resize((size, size), Image.LANCZOS).save(path)
    return path


def fit(d, text, kind, size, maxw):
    """Largest font <= size whose rendered width fits maxw."""
    while size > 8:
        f = font(kind, size)
        if d.textlength(text, font=f) <= maxw:
            return f
        size = int(size * 0.94)
    return font(kind, 8)


def make_banner(path, w=1280, h=320):
    ww, hh = w * SS, h * SS
    img = Image.new("RGB", (ww, hh), GROUND)
    d = ImageDraw.Draw(img)

    d.rectangle([0, hh - 4 * SS, ww, hh], fill=ACCENT)

    pad = ww * 0.055
    r = hh * 0.180
    cx, cy = pad + r * 1.05, hh * 0.47
    draw_mark(d, cx, cy, r * 2.04)

    x = cx + r * 1.65
    avail = ww - x - pad                  # hard right bound; nothing may exceed it

    # ⭐ Kev's line, kept: "Passive RF counter-surveillance" is the strapline
    # and does not change. The second sentence used to be "It listens, and
    # never transmits", which describes what the product REFRAINS from doing.
    # It now says what the product does, and it is checkable: observed devices
    # are matched against a curated database of surveillance hardware and named.
    tagline = "Passive RF counter-surveillance. It names the surveillance hardware near you."
    # ⚠️ THESE NUMBERS ROT, and this one has rotted three times already. Both
    # are snapshots, so RE-DERIVE them when you regenerate rather than trusting
    # what is written here:
    #
    #     tests:     pytest --collect-only -q | tail -1
    #     watchlist: sqlite3 <db> "SELECT COUNT(*) FROM watchlist"
    #
    # Measured 2026-11-10 at `3457de9` in a clean checkout: 5,433 tests
    # selected (64 deselected), and 41,518 records in the shipped
    # src/lynceus/data/default_watchlist.csv (its record_count line agrees).
    # The image had sat at 41,508 and 4,566 since before #220.
    facts = (
        "41,518 watchlist records   ·   5,433 tests   "
        "·   receive only   ·   runs on a Pi"
    )

    f_word = fit(d, "LYNCEUS", "bold", int(hh * 0.255), avail)
    f_sub = fit(d, tagline, "regular", int(hh * 0.085), avail)
    f_mono = fit(d, facts, "mono", int(hh * 0.062), avail)

    d.text((x, hh * 0.335), "LYNCEUS", font=f_word, fill=TEXT, anchor="lm")
    d.text((x, hh * 0.625), tagline, font=f_sub, fill=MUTED, anchor="lm")
    d.text((x, hh * 0.795), facts, font=f_mono, fill=(102, 98, 94), anchor="lm")

    img.resize((w, h), Image.LANCZOS).save(path)
    return path


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "..", "docs", "assets")
    os.makedirs(out, exist_ok=True)
    make_banner(os.path.join(out, "lynceus-banner.png"))
    make_logo(os.path.join(out, "lynceus-logo.png"))
    make_logo(os.path.join(out, "lynceus-logo-dark.png"))
    for px in (128, 64, 32):
        make_logo(os.path.join(out, f"lynceus-logo-{px}.png"), size=px)
    import glob
    for f in sorted(glob.glob(os.path.join(out, "lynceus-*.png"))):
        print(f"  {os.path.relpath(f)}  {os.path.getsize(f):,} bytes")
