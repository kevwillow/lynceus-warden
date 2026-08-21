#!/usr/bin/env python3
"""
README banner and logo mark for Lynceus Warden.

The mark is a sibling to the Argus one and deliberately not a copy. Argus is a
database, so its eye holds closed concentric rings: a thing that has been
catalogued. Lynceus is a live receiver, so its iris is three arcs opening to the
right, the glyph for a transmission arriving. The eye is narrower than the Argus
vesica because Lynceus was the Argonaut with the sharpest sight, and because a
narrower lens reads as looking rather than merely open.

The arcs point INTO the eye, never out of it. That is the whole product in one
mark: it receives, it never transmits.

PNG rather than SVG on purpose. GitHub sanitises SVG in markdown, and text in an
SVG depends on fonts the reader may not have. A PNG renders identically
everywhere. Everything is drawn at SS x supersample and downsampled with LANCZOS,
because GitHub serves the file at the reader's column width and a 1x render looks
soft on a HiDPI screen.

Usage:
    python3 scripts/make_banner.py
"""
import math
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


def _vesica(cx, cy, w, hgt, n=160):
    """Points of a true vesica: two circular arcs meeting at (+-w, 0).

    The upper arc passes through (-w, 0), (0, -hgt), (w, 0). A circle through
    those three points has centre (0, k) with k = (w^2 - hgt^2) / (2 * hgt).
    """
    k = (w * w - hgt * hgt) / (2.0 * hgt)
    r = k + hgt
    a0 = math.atan2(0 - k, -w)
    a1 = math.atan2(0 - k, w)
    top, bot = [], []
    for i in range(n + 1):
        t = a0 + (a1 - a0) * i / n
        x, y = cx + r * math.cos(t), cy + k + r * math.sin(t)
        top.append((x, y))
        bot.append((x, 2 * cy - y))
    return top + bot[::-1]


def draw_mark(d, cx, cy, r, hole=GROUND, outline=TEXT):
    """The receiving-eye mark, centred on (cx, cy) with iris radius r.

    The lens is two FILLED vesicas, outer in `outline` and inner in the
    background, rather than a stroked polyline. Stroking a dense polyline leaves
    visible lumps at this scale; filling does not. That trick is inherited from
    the Argus mark and is the reason both read cleanly at 32px.
    """
    lw = max(2.0, r * 0.150)
    w, hh = r * 1.86, r * 1.04            # narrower than Argus: a sharper eye
    d.polygon(_vesica(cx, cy, w, hh), fill=outline)
    d.polygon(_vesica(cx, cy, w - lw * 1.30, hh - lw), fill=hole)

    # Three arcs opening RIGHT: an incoming transmission, not an emitted one.
    # Drawn as arc segments rather than full ellipses so the eye reads as
    # receiving a direction, which is what separates this mark from the Argus
    # one at a glance.
    # The pupil sits LEFT of centre and the arcs sweep in toward it, so the
    # composition reads as a signal arriving rather than three shapes parked
    # side by side. Centring the pupil made the arcs look like decoration.
    px = cx - r * 0.30
    for frac, col in [(0.96, RING), (0.72, RING), (0.47, ACCENT)]:
        rr = r * frac
        d.arc(
            [px - rr, cy - rr, px + rr, cy + rr],
            start=-58, end=58,
            fill=col, width=max(2, int(r * 0.10)),
        )

    pr = r * 0.20
    d.ellipse([px - pr, cy - pr, px + pr, cy + pr], fill=ACCENT)


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
    cx, cy = pad + r * 1.86, hh * 0.47
    draw_mark(d, cx, cy, r)

    x = cx + r * 2.55
    avail = ww - x - pad                  # hard right bound; nothing may exceed it

    tagline = "Passive RF counter-surveillance. It listens, and never transmits."
    facts = (
        "41,508 watchlist records   ·   4,566 tests   "
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
