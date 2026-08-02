"""Diagnostic dump for the wizard prev/next button sizing residual (#A).

v0.7.3 commit 22adbc6 ("feat(wizard): normalize Prev/Next sizing on both
axes") added the rule::

    .wizard-footer a[role="button"],
    .wizard-footer button {
        box-sizing: border-box;
        min-width: 9em;
        padding: 0.6em 1.5em;
        line-height: 1.25;
        text-align: center;
    }

to ``_base.html``'s inline ``<style>`` block. Unit tests (Arc A T2)
confirmed the rule lands on all 14 wizard pages. Real-hardware Firefox
and Chromium nonetheless render Previous and Next at visibly different
sizes.

Gap is in the cascade: either Pico's bundled ``button`` rules carry
higher specificity than the inline ``.wizard-footer button`` selector
for some property, or the ``<a role="button">`` vs ``<button>`` element
divergence resolves to different effective values for a property the
inline rule doesn't pin (height, font-size, font-family, border-width,
the per-axis padding shorthand).

This diagnostic walks every wizard page, extracts each prev/next button
element, computes which inline-and-pico CSS rules match it, resolves
the cascade for the sizing-critical properties, and diffs across the
prev/next pair. The output names the property where the two elements
resolve to different effective values + the winning rule for each --
that's the fix surface.

No headless browser; everything answerable from stylesheets alone is
captured here. If the divergence is a UA-default that no rule overrides
(unlikely given Pico's classless build resets most form controls), that
shows up as "no matching rule" on both elements for the property.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import lynceus.setup.web.steps_kismet as steps_kismet
from lynceus.setup.web.app import create_wizard_app

pytestmark = pytest.mark.diagnostic

TOKEN = "diag-button-cascade-token-1234567890"
TARGET = Path("/tmp/diag-button-cascade-lynceus.yaml")


# Properties that determine the rendered box for a button element. If
# prev and next resolve to different values for any of these, the
# rendered boxes will look different. font-family is in here because
# Pico's <button> rule explicitly sets font-family:inherit but an
# anchor inherits the body's default text font directly -- the path
# is different even though the resolved value is usually the same.
_SIZING_PROPERTIES: tuple[str, ...] = (
    "box-sizing",
    "display",
    "width",
    "min-width",
    "max-width",
    "height",
    "min-height",
    "max-height",
    "padding",
    "padding-top",
    "padding-bottom",
    "padding-left",
    "padding-right",
    "margin",
    "margin-top",
    "margin-bottom",
    "margin-left",
    "margin-right",
    "border",
    "border-width",
    "border-top-width",
    "border-bottom-width",
    "border-left-width",
    "border-right-width",
    "line-height",
    "font-size",
    "font-family",
    "font-weight",
    "text-align",
    "vertical-align",
    "-webkit-appearance",
    "appearance",
)


_PAGES: list[tuple[str, str]] = [
    ("landing", "/"),
    ("step01_kismet_url", "/step/1"),
    ("step02_kismet_key", "/step/2"),
    ("step03_kismet_probe", "/step/3"),
    ("step04_kismet_sources", "/step/4"),
    ("step05_probe_ssids", "/step/5"),
    ("step06_ble_friendly_names", "/step/6"),
    ("step07_ntfy_url", "/step/7"),
    ("step08_ntfy_topic", "/step/8"),
    ("step09_ntfy_probe", "/step/9"),
    ("step10_rssi", "/step/10"),
    ("step11_severity", "/step/11"),
    ("step12_rules", "/step/12"),
    ("review", "/review"),
]


def _seed_session(app) -> None:
    """Pre-populate session.answers so every deep-link renders its own
    page rather than redirecting back to step 1 / step 7."""
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(
        {
            "kismet_url": "http://localhost:2501",
            "kismet_api_key": "diag-key-stub",
            "kismet_probe_ok": True,
            "kismet_probe_version": "diag-fake-version",
            "kismet_probe_error": None,
            "kismet_probe_sources": [],
            "kismet_sources": ["wlan1"],
            "probe_ssids": False,
            "ble_friendly_names": False,
            "ntfy_url": "https://ntfy.sh",
            "ntfy_topic": "diag-topic",
            "ntfy_probe_ok": True,
            "ntfy_probe_error": None,
            "min_rssi": -75,
            "severity_overrides": {},
            "rules": [],
        }
    )


# ---------------------------------------------------------------------------
# Minimal CSS parser + selector matcher
# ---------------------------------------------------------------------------
#
# Goal: enumerate every CSS rule (selector + declarations) in a
# stylesheet text, then for a given element decide whether the selector
# matches and what the (a,b,c) specificity is. We don't need the full
# CSS grammar -- the wizard's footer buttons are styled by a small set
# of selector shapes (type, class, attribute, combinator, pseudo-class).
# We support enough of the grammar to evaluate those.
#
# We treat at-rules (@media, @supports) by extracting their inner rules
# and tagging the outer condition into the source-location string so a
# reviewer can spot when a media-query-gated rule is the cascade winner.
# Specificity calculation ignores the at-rule wrapper (per the CSS spec,
# media queries don't add specificity).


_AT_RULE_NESTED_RE = re.compile(r"@(media|supports)[^{]*\{(?P<body>.*?)\n\}", flags=re.DOTALL)


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _iter_rules(css_text: str, *, source: str) -> list[dict]:
    """Yield ``{"selector", "declarations", "source"}`` per rule.

    ``source`` carries the stylesheet name + (optionally) the at-rule
    condition so a reviewer can spot media-query / supports-gated rules
    that might or might not apply at run time. Declarations are parsed
    into a property-keyed dict (last write wins for repeated properties
    within the same rule, per CSS).
    """
    css_text = _strip_comments(css_text)
    rules: list[dict] = []

    # Pull at-rule blocks first; they nest a rule list whose specificity
    # is identical to a top-level rule's (the @media just gates whether
    # the rule applies at run time).
    cursor = 0
    while True:
        m = _AT_RULE_NESTED_RE.search(css_text, cursor)
        if m is None:
            break
        # Everything between cursor and the at-rule start: top-level.
        rules.extend(_parse_flat(css_text[cursor : m.start()], source=source))
        # Inside the at-rule: same flat parser, tag the source.
        cond = m.group(0).split("{", 1)[0].strip()
        rules.extend(_parse_flat(m.group("body"), source=f"{source} [{cond}]"))
        cursor = m.end()
    rules.extend(_parse_flat(css_text[cursor:], source=source))
    return rules


_SELECTOR_BLOCK_RE = re.compile(r"([^{}]+)\{([^{}]*)\}", flags=re.DOTALL)


def _parse_flat(css_chunk: str, *, source: str) -> list[dict]:
    out: list[dict] = []
    for m in _SELECTOR_BLOCK_RE.finditer(css_chunk):
        sel_text, body_text = m.group(1).strip(), m.group(2).strip()
        if not sel_text or sel_text.startswith("@"):
            # nested at-rule we didn't expand, or stray @keyframes etc.
            continue
        # Comma-split into individual selectors (cascade evaluates each
        # selector separately, with its own specificity).
        for sel in (s.strip() for s in sel_text.split(",")):
            if not sel:
                continue
            decls = _parse_declarations(body_text)
            if not decls:
                continue
            out.append(
                {
                    "selector": sel,
                    "declarations": decls,
                    "source": source,
                }
            )
    return out


_DECL_RE = re.compile(r"([a-zA-Z-]+)\s*:\s*([^;]+?)(?:\s*!important)?\s*(?:;|$)")
_IMPORTANT_RE = re.compile(r"!important\s*(?:;|$)")


def _parse_declarations(body: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for m in _DECL_RE.finditer(body):
        prop = m.group(1).strip().lower()
        value = m.group(2).strip()
        important = bool(_IMPORTANT_RE.search(body[m.start() : m.end()]))
        out[prop] = {"value": value, "important": important}
    return out


# ---------------------------------------------------------------------------
# Selector matching (subset sufficient for the wizard's stylesheets)
# ---------------------------------------------------------------------------


def _selector_matches(selector: str, element: dict) -> bool:
    """Return True iff ``selector`` matches ``element``.

    ``element`` is a dict with keys ``tag`` (str), ``attrs`` (dict),
    ``ancestor_chain`` (list of ancestor elements, root-first; the
    target itself is NOT in this list).

    We support type selectors, ``*``, classes, ``[attr=value]`` and
    ``[attr]``, ``:not(...)``, descendant combinator (space), and
    pseudo-classes that are no-ops for static matching (``:hover``,
    ``:focus``, ``:active``, etc.) -- those are treated as "matches"
    so the resolved value reflects the styles the browser would apply
    in their state (the diff still surfaces a property that only
    changes under interaction, which is fine for our purposes).
    """
    # Descendant combinator split (CSS allows other combinators -- >,
    # +, ~ -- but they are absent from the wizard's stylesheets).
    parts = _split_descendant(selector)
    # Right-most compound must match the target element.
    if not _compound_matches(parts[-1], element):
        return False
    # Walk left through compounds, advancing through ancestor_chain.
    ancestors = list(element["ancestor_chain"])
    for compound in reversed(parts[:-1]):
        while ancestors:
            anc = ancestors.pop()
            if _compound_matches(
                compound,
                {"tag": anc["tag"], "attrs": anc["attrs"], "ancestor_chain": []},
            ):
                break
        else:
            return False
    return True


def _split_descendant(selector: str) -> list[str]:
    """Split a selector on descendant combinator (space), respecting
    bracket / paren nesting so ``a[role="button"] .x`` splits into two
    compounds not three.
    """
    parts: list[str] = []
    buf: list[str] = []
    depth_bracket = depth_paren = 0
    for ch in selector:
        if ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket -= 1
        elif ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
        if ch == " " and depth_bracket == 0 and depth_paren == 0 and buf:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


_COMPOUND_TOKEN_RE = re.compile(
    r"\[[^\]]+\]"  # [attr] / [attr=value]
    r"|::[A-Za-z-]+(?:\([^)]*\))?"  # ::pseudo-element
    r"|:[A-Za-z-]+(?:\([^)]*\))?"  # :pseudo-class (including :not(...))
    r"|\.[A-Za-z_][A-Za-z0-9_-]*"  # .class
    r"|#[A-Za-z_][A-Za-z0-9_-]*"  # #id
    r"|\*"  # universal
    r"|[A-Za-z][A-Za-z0-9-]*"  # type
)


def _compound_tokens(compound: str) -> list[str]:
    return _COMPOUND_TOKEN_RE.findall(compound)


def _compound_matches(compound: str, element: dict) -> bool:
    """Match a single compound selector (no combinators) against the
    target element."""
    for tok in _compound_tokens(compound):
        if not _token_matches(tok, element):
            return False
    return True


def _token_matches(tok: str, element: dict) -> bool:
    if tok == "*":
        return True
    if tok.startswith("["):
        return _attr_token_matches(tok, element)
    if tok.startswith("."):
        classes = element["attrs"].get("class", "").split()
        return tok[1:] in classes
    if tok.startswith("#"):
        return element["attrs"].get("id") == tok[1:]
    if tok.startswith(":not("):
        inner = tok[len(":not(") : -1]
        # :not(X) matches when X doesn't match. Inner can be any simple
        # selector; pass it through the token matcher recursively.
        for sub in _compound_tokens(inner):
            if _token_matches(sub, element):
                return False
        return True
    if tok.startswith("::"):
        # Pseudo-elements (::before, ::placeholder) don't apply to the
        # actual element box for sizing purposes; the buttons we're
        # examining have none. Treat as non-matching so pseudo-element
        # rules don't pollute the dump.
        return False
    if tok.startswith(":"):
        # Pseudo-classes: state-dependent (:hover, :focus, :active,
        # :disabled) are treated as matching so the dump captures the
        # styles the browser would apply when the user interacts with
        # the element. Structural pseudo-classes (:first-child etc.)
        # would need ancestor context we don't track for top-level
        # elements; rare for wizard buttons.
        return True
    # Type selector.
    return element["tag"].lower() == tok.lower()


_ATTR_RE = re.compile(r"\[([A-Za-z-]+)(?:([~|^$*]?=)\"?([^\"\]]*)\"?)?\]")


def _attr_token_matches(tok: str, element: dict) -> bool:
    m = _ATTR_RE.match(tok)
    if not m:
        return False
    attr, op, value = m.group(1), m.group(2), m.group(3)
    have = element["attrs"].get(attr.lower())
    if op is None:
        return have is not None
    if have is None:
        return False
    if op == "=":
        return have == value
    if op == "~=":
        return value in have.split()
    if op == "|=":
        return have == value or have.startswith(value + "-")
    if op == "^=":
        return have.startswith(value)
    if op == "$=":
        return have.endswith(value)
    if op == "*=":
        return value in have
    return False


def _specificity(selector: str) -> tuple[int, int, int]:
    """Compute (a,b,c) per CSS Selectors Level 3:
        a = # of id selectors
        b = # of classes, attributes, pseudo-classes
        c = # of type selectors, pseudo-elements
    Descendant combinator (space) contributes nothing on its own.
    ``*`` contributes nothing.
    """
    a = b = c = 0
    for compound in _split_descendant(selector):
        for tok in _compound_tokens(compound):
            if tok == "*":
                continue
            if tok.startswith("#"):
                a += 1
            elif (
                tok.startswith(".")
                or tok.startswith("[")
                or (
                    tok.startswith(":") and not tok.startswith("::") and not tok.startswith(":not(")
                )
            ):
                b += 1
            elif tok.startswith(":not("):
                # :not() doesn't count itself; its inner selector does.
                inner = tok[len(":not(") : -1]
                inner_a, inner_b, inner_c = _specificity(inner)
                a += inner_a
                b += inner_b
                c += inner_c
            elif tok.startswith("::"):
                c += 1
            else:
                c += 1
    return (a, b, c)


# ---------------------------------------------------------------------------
# Cascade resolution
# ---------------------------------------------------------------------------


def _resolve_cascade(
    rules: list[dict], element: dict, properties: tuple[str, ...]
) -> dict[str, dict]:
    """Return, for each property, the winning rule + value.

    Cascade order: !important > normal; within each origin, higher
    specificity wins; ties resolve by source order (later wins). We
    don't model author-vs-UA origins (no UA stylesheet here); inline
    style attributes don't appear on the wizard's buttons either.
    """
    matched_by_prop: dict[str, list[dict]] = {p: [] for p in properties}
    for idx, rule in enumerate(rules):
        if not _selector_matches(rule["selector"], element):
            continue
        spec = _specificity(rule["selector"])
        for prop, decl in rule["declarations"].items():
            if prop not in matched_by_prop:
                continue
            matched_by_prop[prop].append(
                {
                    "selector": rule["selector"],
                    "source": rule["source"],
                    "value": decl["value"],
                    "important": decl["important"],
                    "specificity": spec,
                    "order": idx,
                }
            )
    winners: dict[str, dict] = {}
    for prop, candidates in matched_by_prop.items():
        if not candidates:
            winners[prop] = {"value": "<unmatched>", "winner": None}
            continue
        # !important first, then specificity, then order.
        candidates.sort(key=lambda c: (c["important"], c["specificity"], c["order"]))
        winner = candidates[-1]
        winners[prop] = {
            "value": winner["value"],
            "winner": (
                f"{winner['selector']!r} from {winner['source']} "
                f"specificity={winner['specificity']} "
                f"{'!important ' if winner['important'] else ''}"
                f"(order={winner['order']})"
            ),
            "candidates": [
                f"  - {c['selector']!r} -> {c['value']!r} "
                f"spec={c['specificity']} "
                f"{'!important ' if c['important'] else ''}"
                f"src={c['source']} order={c['order']}"
                for c in candidates
            ],
        }
    return winners


# ---------------------------------------------------------------------------
# Element extraction from rendered HTML
# ---------------------------------------------------------------------------


_OPEN_TAG_RE = re.compile(r"<(?P<tag>a|button)\b(?P<attrs>[^>]*)>", flags=re.IGNORECASE)
_ATTR_PAIR_RE = re.compile(r'([a-zA-Z-]+)\s*=\s*"([^"]*)"')


def _parse_attrs(blob: str) -> dict[str, str]:
    return {k.lower(): v for k, v in _ATTR_PAIR_RE.findall(blob)}


def _extract_footer_buttons(body: str) -> list[dict]:
    """Pull every <a> or <button> inside any wizard-footer block.

    Returns one dict per element with ``tag``, ``attrs``, and
    ``ancestor_chain``. The ancestor chain is constructed from the
    enclosing main.container -> footer/div.wizard-footer envelope --
    enough for the selectors the wizard's stylesheets care about.
    """
    out: list[dict] = []
    for footer_m in re.finditer(
        r"<(?P<wrap>footer|div)\b(?P<wrap_attrs>[^>]*)>(?P<body>.*?)</(?P=wrap)>",
        body,
        flags=re.DOTALL | re.IGNORECASE,
    ):
        wrap_attrs = _parse_attrs(footer_m.group("wrap_attrs"))
        wrap_classes = wrap_attrs.get("class", "").split()
        if "wizard-footer" not in wrap_classes:
            continue
        ancestor_chain = [
            {"tag": "html", "attrs": {}},
            {"tag": "body", "attrs": {}},
            {"tag": "main", "attrs": {"class": "container"}},
            {"tag": footer_m.group("wrap").lower(), "attrs": wrap_attrs},
        ]
        for tag_m in _OPEN_TAG_RE.finditer(footer_m.group("body")):
            out.append(
                {
                    "tag": tag_m.group("tag").lower(),
                    "attrs": _parse_attrs(tag_m.group("attrs")),
                    "ancestor_chain": ancestor_chain,
                    "raw": tag_m.group(0),
                }
            )
    return out


# ---------------------------------------------------------------------------
# The diagnostic
# ---------------------------------------------------------------------------


def test_diag_wizard_button_cascade(diag, monkeypatch):
    monkeypatch.setattr(
        steps_kismet, "probe_kismet", lambda url, key: (False, None, "diag-no-kismet")
    )
    monkeypatch.setattr(steps_kismet, "probe_kismet_sources", lambda url, key: None)

    # -- Locate the two stylesheets reachable from the wizard pages.
    diag.section("stylesheet inventory")
    base_template = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "lynceus"
        / "setup"
        / "web"
        / "templates"
        / "_base.html"
    )
    pico_path = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "lynceus"
        / "webui"
        / "static"
        / "pico.min.css"
    )
    base_text = base_template.read_text(encoding="utf-8")
    pico_text = pico_path.read_text(encoding="utf-8")
    style_m = re.search(r"<style>(.*?)</style>", base_text, flags=re.DOTALL)
    inline_text = style_m.group(1) if style_m else ""
    diag.observed(f"inline <style> source: {base_template} ({len(inline_text)} chars)")
    diag.observed(f"pico.min.css source: {pico_path} ({len(pico_text)} chars)")

    # Inline rules come AFTER pico in the document (declaration order
    # in _base.html is <link rel=stylesheet href=pico>, then <style>),
    # so the inline rules appear later in source order and win ties.
    pico_rules = _iter_rules(pico_text, source="pico.min.css")
    inline_rules = _iter_rules(inline_text, source="_base.html inline <style>")
    all_rules = pico_rules + inline_rules
    diag.observed(f"pico rules parsed: {len(pico_rules)}")
    diag.observed(f"inline rules parsed: {len(inline_rules)}")
    diag.observed(f"total cascade-eligible rules: {len(all_rules)}")

    # Surface the inline rule of interest so the dump is self-contained.
    diag.section("inline wizard-footer button rule (the v0.7.3 normalization)")
    for r in inline_rules:
        if "wizard-footer" in r["selector"]:
            diag.observed(
                f"selector: {r['selector']!r} -> "
                f"declarations: { {k: v['value'] for k, v in r['declarations'].items()} }"
            )

    # Surface pico's rules that target type=button OR a[role=button] so a
    # reviewer can see the rules in flight without re-parsing pico.
    diag.section("pico rules that could target wizard prev/next")
    for r in pico_rules:
        sel = r["selector"]
        if (
            re.search(r"\bbutton\b", sel)
            or "[role" in sel
            or "[type" in sel
            or sel.strip() in {"a", "input"}
        ):
            # Limit to single-compound selectors so the dump stays
            # tractable (pico has hundreds of compound rules; the
            # selector match step below evaluates them all anyway).
            decls = {k: v["value"] for k, v in r["declarations"].items() if k in _SIZING_PROPERTIES}
            if not decls:
                continue
            diag.observed(f"  selector={sel!r} src={r['source']} sizing-declarations={decls}")

    # -- Walk pages, extract buttons, resolve cascade, diff prev/next.
    diag.section("per-page cascade resolution")
    app = create_wizard_app(setup_token=TOKEN, scope="user", target_path=TARGET)
    _seed_session(app)

    divergences_seen: list[str] = []

    with TestClient(app, follow_redirects=False) as client:
        for label, path in _PAGES:
            resp = client.get(f"{path}?token={TOKEN}")
            if resp.status_code != 200:
                diag.observed(
                    f"--- {label} ({path}) ---  status={resp.status_code} "
                    f"location={resp.headers.get('location')!r} (skip)"
                )
                continue
            buttons = _extract_footer_buttons(resp.text)
            diag.observed(f"--- {label} ({path}) ---  footer buttons={len(buttons)}")
            for b in buttons:
                diag.observed(f"  element: <{b['tag']} {b['attrs']}>  raw={b['raw']!r}")
            if len(buttons) < 2:
                diag.observed("  (need >= 2 buttons to diff -- skipping per-page diff)")
                continue

            resolved = [_resolve_cascade(all_rules, b, _SIZING_PROPERTIES) for b in buttons]

            # Diff every property across every pair (most pages have
            # exactly 2 buttons; step 3 may have 2 real <button>s).
            diag.observed("  per-property cascade outcomes:")
            for prop in _SIZING_PROPERTIES:
                values = [r[prop]["value"] for r in resolved]
                if len(set(values)) == 1:
                    continue
                divergences_seen.append(f"{label}: {prop} -> {values}")
                diag.observed(f"    DIVERGENT {prop}:")
                for i, (b, r) in enumerate(zip(buttons, resolved, strict=False)):
                    diag.observed(
                        f"      [{i}] <{b['tag']} role={b['attrs'].get('role')!r}> "
                        f"= {r[prop]['value']!r}"
                    )
                    diag.observed(f"          winner: {r[prop]['winner']}")
                    for line in r[prop].get("candidates", []):
                        diag.observed(f"        {line}")

            # Also report any property the inline rule "should" have
            # pinned but didn't win (cascade-lost cases).
            for prop in ("min-width", "padding", "line-height", "box-sizing", "text-align"):
                for i, (b, r) in enumerate(zip(buttons, resolved, strict=False)):
                    winner = r[prop].get("winner") or ""
                    if "_base.html inline" in winner:
                        continue
                    diag.observed(
                        f"    inline-rule LOST for {prop} on element[{i}] "
                        f"<{b['tag']} role={b['attrs'].get('role')!r}>: "
                        f"value={r[prop]['value']!r} winner={winner!r}"
                    )

    diag.section("summary: divergent properties across all pages")
    if not divergences_seen:
        diag.observed("no divergent sizing-properties detected across any page pair.")
        diag.observed(
            "Implication: the visible-rendering gap is NOT in any sizing property "
            "the stylesheets touch -- residual is most likely a UA-default that "
            "no rule resets (e.g. browser-specific button intrinsic min-content "
            "width, or a font-metric divergence between the anchor text node "
            "and the button text node)."
        )
    else:
        for d in divergences_seen:
            diag.observed(f"  - {d}")

    diag.notes(
        "Fix-direction guide for the follow-up prompt:\n"
        " * If DIVERGENT lines name a property: extend the .wizard-footer "
        "rule to pin it explicitly (specificity is already 0,1,2 which "
        "beats pico's bare-element rules at 0,0,1 -- pinning is enough).\n"
        " * If a property shows 'inline-rule LOST': pico has a "
        "higher-specificity rule (e.g. with [role] or a class) and the "
        "inline rule needs the same shape to win the cascade.\n"
        " * If no divergences AND no losses: the residual is UA-default "
        "(intrinsic widths, font metrics). Fix path is to set "
        "width:<value> or display:inline-flex with explicit gap, or to "
        "make both elements the same tag (e.g. render Previous as a "
        "<button> styled as link via form action= rather than as <a>)."
    )
