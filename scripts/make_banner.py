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
import colorsys
import math
import os

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
# Every shape is split into flat triangles, and each triangle is shaded by how
# much it faces one light from the top left, so the mark reads as a faceted
# solid. Geometry is in a 64-unit box; draw_mark scales it to pixels. The same
# geometry is the SVG mark on gurutechnology.services.
LIGHT = (-0.45, -0.65, 0.62)
_ln = math.sqrt(sum(c * c for c in LIGHT))
LIGHT = tuple(c / _ln for c in LIGHT)


def _shade(rgb, p, q, r, spread):
    (x1, y1, z1), (x2, y2, z2), (x3, y3, z3) = p, q, r
    ux, uy, uz = x2 - x1, y2 - y1, z2 - z1
    vx, vy, vz = x3 - x1, y3 - y1, z3 - z1
    nx, ny, nz = uy * vz - uz * vy, uz * vx - ux * vz, ux * vy - uy * vx
    if nz < 0:
        nx, ny, nz = -nx, -ny, -nz
    m = math.sqrt(nx * nx + ny * ny + nz * nz) or 1
    d = (nx * LIGHT[0] + ny * LIGHT[1] + nz * LIGHT[2]) / m
    hue, lum, sat = colorsys.rgb_to_hls(*(c / 255 for c in rgb))
    delta = spread * (d - 0.62) * 1.6
    if delta < 0:
        delta *= 0.55                     # the shaded side darkens gently, so colours stay even
    lum = min(0.93, max(0.08, lum + delta))
    return tuple(round(c * 255) for c in colorsys.hls_to_rgb(hue, lum, sat))


def _ngon(cx, cy, r, n, rot=0):
    return [(cx + r * math.cos(math.radians(rot + 360 * k / n)),
             cy + r * math.sin(math.radians(rot + 360 * k / n))) for k in range(n)]


class _Facets:
    """Collects shaded triangles as (colour, [(x, y), (x, y), (x, y)])."""

    def __init__(self):
        self.tris = []

    def tri(self, a, b, c, rgb, spread):
        self.tris.append((_shade(rgb, a, b, c, spread), [a[:2], b[:2], c[:2]]))

    def fan(self, poly, apex, h, rgb, spread):
        """A pyramid: every edge of poly joined to a raised apex."""
        top = (apex[0], apex[1], h)
        for i in range(len(poly)):
            p, q = poly[i], poly[(i + 1) % len(poly)]
            self.tri((p[0], p[1], 0), (q[0], q[1], 0), top, rgb, spread)

    def dome(self, poly, apex, h, rgb, spread, k=0.5, kz=0.72):
        """Two rings of facets: an outer band rising to an inner ring, then a pyramid."""
        inner = [(x + (apex[0] - x) * k, y + (apex[1] - y) * k) for x, y in poly]
        top = (apex[0], apex[1], h)
        n = len(poly)
        for i in range(n):
            p, q = poly[i], poly[(i + 1) % n]
            a, b = inner[i], inner[(i + 1) % n]
            P, Q = (p[0], p[1], 0), (q[0], q[1], 0)
            A, B = (a[0], a[1], h * kz), (b[0], b[1], h * kz)
            self.tri(P, Q, B, rgb, spread)
            self.tri(P, B, A, rgb, spread)
            self.tri(A, B, top, rgb, spread)

    def ridge_arc(self, cx, cy, r, t, a0, a1, segs, h, rgb, spread=0.30):
        """A band along an arc with a raised ridge down its middle."""
        for i in range(segs):
            b0 = math.radians(a0 + (a1 - a0) * i / segs)
            b1 = math.radians(a0 + (a1 - a0) * (i + 1) / segs)

            def P(rad, ang, z=0):
                return (cx + rad * math.cos(ang), cy + rad * math.sin(ang), z)
            i0, i1 = P(r - t / 2, b0), P(r - t / 2, b1)
            o0, o1 = P(r + t / 2, b0), P(r + t / 2, b1)
            m0, m1 = P(r, b0, h), P(r, b1, h)
            self.tri(i0, i1, m1, rgb, spread)
            self.tri(i0, m1, m0, rgb, spread)
            self.tri(m0, m1, o1, rgb, spread)
            self.tri(m0, o1, o0, rgb, spread)


def _mark_facets():
    """Gold shield, three navy arcs arriving from above, one red dot."""
    f = _Facets()
    shield = [(11, 7), (32, 7), (53, 7), (53, 21), (52, 32), (46, 44),
              (32, 58), (18, 44), (12, 32), (11, 21)]
    f.dome(shield, (32, 28), 12, (0xe6, 0xae, 0x34), 0.18)
    for r in (8, 14.5, 21):
        f.ridge_arc(32, 44, r, 3.6, 222, 318, 3 if r < 10 else 4, 1.6, (0x26, 0x2a, 0x48))
    f.fan(_ngon(32, 44, 3.6, 6, -90), (32, 44), 2.5, (0xf4, 0x24, 0x46), 0.18)
    return f.tris


MARK_BOX = (11, 7, 53, 58)               # the shield's extent in the 64-unit box


def draw_mark(d, cx, cy, size):
    """Draw the mark centred on (cx, cy), its longer side `size` pixels.

    Each facet is filled and outlined in its own colour, so no seam shows
    between neighbours after the LANCZOS downsample.
    """
    x0, y0, x1, y1 = MARK_BOX
    s = size / max(x1 - x0, y1 - y0)
    mx, my = (x0 + x1) / 2, (y0 + y1) / 2
    for rgb, pts in _mark_facets():
        xy = [(cx + (x - mx) * s, cy + (y - my) * s) for x, y in pts]
        d.polygon(xy, fill=rgb, outline=rgb)


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
