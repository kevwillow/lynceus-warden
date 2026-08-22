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

PNG rather than SVG on purpose. GitHub sanitises SVG in markdown, and text in an
SVG depends on fonts the reader may not have. A PNG renders identically
everywhere. Everything is drawn at SS x supersample and downsampled with LANCZOS,
because GitHub serves the file at the reader's column width and a 1x render looks
soft on a HiDPI screen.

Usage:
    python3 scripts/make_banner.py
"""
import os

from PIL import Image, ImageDraw, ImageFont

SS = 4                                   # supersample factor
GROUND = (13, 13, 15)                    # near-black page ground
TEXT = (242, 240, 238)
MUTED = (139, 134, 128)
ACCENT = (200, 16, 46)                   # the same red Argus uses; these are siblings
RING = (58, 58, 64)                      # cool grey for the outer arcs

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


def _shield(cx, cy, w, h, n=90):
    """Heater shield: flat top, straight upper flanks, a curve sweeping to a tip."""
    pts = [(cx - w, cy - h), (cx + w, cy - h)]
    for i in range(n + 1):
        t = i / n
        pts.append((cx + w * (1 - t * t), cy - h + (2 * h) * (0.42 + 0.58 * t)))
    for i in range(n + 1):
        t = 1 - i / n
        pts.append((cx - w * (1 - t * t), cy - h + (2 * h) * (0.42 + 0.58 * t)))
    return pts


def draw_mark(d, cx, cy, r, hole=GROUND, outline=TEXT):
    """The shield mark, centred on (cx, cy) with radius r.

    The shield is two FILLED polygons, outer in `outline` and inner in the
    background, rather than a stroked outline. Stroking a dense polyline leaves
    visible lumps at this scale; filling does not.

    Two arcs, not three. A third was measured turning to mush at 32px, which is
    the size that decides whether a mark works.
    """
    lw = max(2.0, r * 0.155)
    w, h = r * 0.96, r * 1.02
    d.polygon(_shield(cx, cy, w, h), fill=outline)
    d.polygon(_shield(cx, cy - lw * 0.10, w - lw * 1.25, h - lw * 0.95), fill=hole)

    # ⭐ Symmetric about the vertical centre, and the arcs arrive from ABOVE.
    # The first version swept in from the left, which was asymmetric and read
    # as lopsided at every size.
    #
    # Two arcs, not three. Three measured to a smear at 32px, and 32px is the
    # size that decides whether a mark works.
    #
    # ⚠️ The innermost arc used to be ACCENT and sat close to the dot, which
    # merged the two into a red blob at small sizes. Grey arcs, one red dot,
    # with a real gap between them.
    by = cy + r * 0.26
    for frac in (0.80, 0.50):
        q = r * frac
        d.arc([cx - q, by - q, cx + q, by + q], start=204, end=336,
              fill=RING, width=max(3, int(r * 0.145)))

    pr = r * 0.135
    d.ellipse([cx - pr, by - pr, cx + pr, by + pr], fill=ACCENT)


def make_logo(path, size=512, outline=(42, 42, 48)):
    """Square mark on a transparent ground, for a favicon, avatar or docs header.

    Two variants ship. The default dark outline reads on light backgrounds;
    lynceus-logo-dark.png uses the light outline for dark ones. A single mark
    cannot do both, because the lens outline has to contrast with the page.
    """
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    draw_mark(d, s / 2, s / 2, s * 0.26, hole=(0, 0, 0, 0), outline=outline)
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
    draw_mark(d, cx, cy, r)

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
    # Measured 2026-08-22 at `bf20903`: 4,573 collected, 47 deselected.
    # The count was left at 4,566 through #200, which added seven.
    facts = (
        "41,508 watchlist records   ·   4,573 tests   "
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
    make_logo(os.path.join(out, "lynceus-logo-dark.png"), outline=TEXT)
    for px in (128, 64, 32):
        make_logo(os.path.join(out, f"lynceus-logo-{px}.png"), size=px)
    import glob
    for f in sorted(glob.glob(os.path.join(out, "lynceus-*.png"))):
        print(f"  {os.path.relpath(f)}  {os.path.getsize(f):,} bytes")
