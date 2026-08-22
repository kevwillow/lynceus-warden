"""Guard the two claims the token layer makes that nothing else can check.

⛔ Both defects these catch are silent. A font left out of the wheel renders
in a fallback mono that looks deliberate, and a colour that fails contrast
looks fine to whoever picked it. Neither shows up as a failing page, a
traceback or a red CI job, so a test is the only thing that can report them.

Every value here is READ OUT of the shipped files. Nothing is transcribed:
a token renamed, a colour edited or an asset moved changes what these
assertions compute, rather than leaving them agreeing with a stale copy of
what used to be true.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

REPO = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO / "src" / "lynceus" / "webui" / "static"
TOKENS = STATIC_DIR / "tokens.css"

# WCAG 2.1 AA for normal-size text. The dashboard's data columns are small
# text, so the large-text 3:1 allowance does not apply to them.
AA_NORMAL = 4.5


def _relative_luminance(hex_colour: str) -> float:
    """WCAG relative luminance, per the definition the ratio is built on."""
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    srgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in srgb]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(a: str, b: str) -> float:
    la, lb = _relative_luminance(a), _relative_luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _tokens_in_block(block: str) -> dict[str, str]:
    """Every `--lyn-*: #rrggbb` pair declared in one CSS block."""
    return {
        name: value
        for name, value in re.findall(
            r"(--lyn-[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;", block
        )
    }


def _theme_blocks() -> dict[str, dict[str, str]]:
    """The colour tokens each theme actually ships, read from tokens.css.

    ⛔ The selectors are found by searching for the three tiers the file
    documents, not by slicing at fixed offsets: a block that moves must still
    be found, and a tier that is DELETED must make this raise rather than
    silently reduce the number of themes under test.
    """
    css = TOKENS.read_text()
    # Strip comments first, so a hex value quoted inside a comment (the file
    # explains its own colour choices) can never be mistaken for a declaration.
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)

    blocks: dict[str, dict[str, str]] = {}
    for label, pattern in (
        ("light", r"(?<![-\w]):root\s*\{(.*?)\}"),
        ("dark-auto", r":root:not\(\[data-theme=\"light\"\]\)\s*\{(.*?)\}"),
        ("dark-explicit", r"\[data-theme=\"dark\"\]\s*\{(.*?)\}"),
    ):
        for match in re.finditer(pattern, css, flags=re.S):
            found = _tokens_in_block(match.group(1))
            if "--lyn-ground" in found:
                blocks[label] = found
                break
    missing = {"light", "dark-auto", "dark-explicit"} - blocks.keys()
    assert not missing, (
        f"tokens.css no longer declares a palette for {sorted(missing)}. Each "
        "theme needs its own, because the `app` cascade layer outranks Pico "
        "unconditionally: a colour set only on :root also applies in dark mode, "
        "where Pico would otherwise have replaced it."
    )
    return blocks


@pytest.mark.webui
@pytest.mark.parametrize("theme", ["light", "dark-auto", "dark-explicit"])
def test_foreground_tokens_pass_aa_on_their_own_ground(theme):
    """Every text-bearing token is legible on the ground it is shipped with.

    🪤 This is why the dark accent is not #c8102e. Argus red scores 3.30:1 on
    the #0d0d0f ground, which fails AA — so dark mode ships a tint of the same
    hue instead. Deciding that by eye is exactly the mistake this prevents.
    """
    tokens = _theme_blocks()[theme]
    ground = tokens["--lyn-ground"]
    surface = tokens.get("--lyn-surface", ground)

    # Derived, not listed: every token whose job is to be READ, paired with
    # the background it is actually read against. A new foreground token is
    # covered the moment it is added.
    #
    # ⚠️ `--lyn-on-accent` is the one that is NOT read on the page ground --
    # it is the label inside a filled accent button. Grading it against the
    # ground asks the wrong question and fails a correct colour.
    checks: list[tuple[str, str, str]] = []
    for name in tokens:
        suffix = name.split("-")[-1]
        if name.startswith("--lyn-on-"):
            checks.append((name, "the accent it sits on", tokens["--lyn-accent"]))
        elif suffix in {"text", "muted", "dim"} or name in {
            "--lyn-accent", "--lyn-accent-hover"
        }:
            checks.append((name, "ground", ground))
            checks.append((name, "surface", surface))
    assert checks, "no foreground tokens found; this test would prove nothing"

    for name, bg_name, bg in sorted(checks):
        ratio = _contrast(tokens[name], bg)
        assert ratio >= AA_NORMAL, (
            f"{theme}: {name} ({tokens[name]}) on {bg_name} ({bg}) is "
            f"{ratio:.2f}:1, below the {AA_NORMAL}:1 WCAG AA floor for "
            f"normal text. Lighten or darken the token; do not lower this "
            f"threshold."
        )


@pytest.mark.webui
def test_the_accent_stays_argus_red():
    """The mark's argument is that lynceus and Argus are siblings.

    `scripts/make_banner.py` sets the mark in "the same red Argus uses". The
    dark tier ships a lighter tint for contrast, so this pins the HUE rather
    than the hex — which is the thing the sibling claim actually rests on.
    """
    banner = (REPO / "scripts" / "make_banner.py").read_text()
    # The banner works in PIL, so its colours are RGB tuples, not hex.
    argus_reds = [
        "".join(f"{int(c):02x}" for c in match)
        for match in re.findall(
            r"\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)", banner
        )
    ]
    argus_reds += re.findall(r"#([0-9a-fA-F]{6})", banner)
    # Only the reddish ones: the mark is mostly greys, and a grey has no
    # meaningful hue to compare an accent against.
    argus_reds = [
        c for c in argus_reds
        if int(c[0:2], 16) > int(c[2:4], 16) + 40 and int(c[0:2], 16) > int(c[4:6], 16) + 40
    ]
    assert argus_reds, "no red found in make_banner.py; nothing to compare against"

    def hue(hex_colour: str) -> float:
        h = hex_colour.lstrip("#")
        r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
        mx, mn = max(r, g, b), min(r, g, b)
        if mx == mn:
            return 0.0
        if mx == r:
            return (60 * ((g - b) / (mx - mn))) % 360
        if mx == g:
            return 60 * ((b - r) / (mx - mn)) + 120
        return 60 * ((r - g) / (mx - mn)) + 240

    light_accent = _theme_blocks()["light"]["--lyn-accent"]
    banner_hues = [hue(c) for c in argus_reds]
    accent_hue = hue(light_accent)
    closest = min(abs(((accent_hue - h + 180) % 360) - 180) for h in banner_hues)
    assert closest <= 12, (
        f"the UI accent {light_accent} sits {closest:.1f}deg from the nearest "
        f"colour in make_banner.py. The banner says the mark uses 'the same red "
        f"Argus uses; these are siblings' — if the accent drifts, that claim "
        f"stops being true."
    )

    for theme in ("dark-auto", "dark-explicit"):
        dark_hue = hue(_theme_blocks()[theme]["--lyn-accent"])
        drift = abs(((dark_hue - accent_hue + 180) % 360) - 180)
        assert drift <= 12, (
            f"{theme}'s accent is {drift:.1f}deg from the light accent. The "
            f"dark tier may be a lighter TINT for contrast, but it must stay "
            f"the same hue."
        )


def _assets_referenced_by_css() -> set[Path]:
    """Every local file the shipped CSS asks the browser to fetch."""
    found: set[Path] = set()
    for sheet in STATIC_DIR.rglob("*.css"):
        for url in re.findall(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", sheet.read_text()):
            if url.startswith(("http://", "https://", "data:", "//")):
                continue
            found.add((sheet.parent / url).resolve())
    return found


@pytest.mark.webui
def test_every_asset_the_css_references_exists():
    assets = _assets_referenced_by_css()
    assert assets, "no local url() references found; this test would prove nothing"
    for path in sorted(assets):
        assert path.is_file(), (
            f"CSS references {path}, which is not on disk. The browser would "
            f"fall back silently rather than report anything."
        )


@pytest.mark.webui
def test_every_referenced_asset_is_packaged_into_the_wheel():
    """The failure this catches happens only in the installed product.

    🪤 `webui/static/*` is a SINGLE-level glob. It does not reach
    `webui/static/fonts/`, so a self-hosted font can be present in every dev
    checkout, referenced correctly by the CSS, and still be absent from the
    wheel — where it degrades to a fallback font instead of erroring.
    """
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())
    patterns = pyproject["tool"]["setuptools"]["package-data"]["lynceus"]
    package_root = REPO / "src" / "lynceus"

    covered: set[Path] = set()
    for pattern in patterns:
        covered.update(p.resolve() for p in package_root.glob(pattern))

    for asset in sorted(_assets_referenced_by_css()):
        assert asset in covered, (
            f"{asset.relative_to(package_root)} is referenced by the CSS but is "
            f"not matched by any [tool.setuptools.package-data] pattern, so it "
            f"will be missing from the built wheel. Patterns are single-level: "
            f"a file in a new subdirectory needs its own entry."
        )


@pytest.mark.webui
def test_the_app_actually_serves_every_referenced_asset(tmp_path):
    """Packaged and on disk is still not the same as reachable over HTTP."""
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    try:
        client = TestClient(create_app(config, db))
        for asset in sorted(_assets_referenced_by_css()):
            url = "/static/" + asset.relative_to(STATIC_DIR).as_posix()
            response = client.get(url)
            assert response.status_code == 200, (
                f"{url} returned {response.status_code}; the StaticFiles mount "
                f"does not reach it."
            )
            assert response.content, f"{url} served an empty body"
    finally:
        db.close()
