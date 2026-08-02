"""Tests for the severity overrides + rules engine section
(F6 Phase 2a, Touch 6).

Steps 11-12. Pins:
* Severity path defaults to ``<target_parent>/severity_overrides.yaml``
  and is validated through ``_looks_like_path``.
* The rules-engine form lists every rule_type from
  ``DELEGATION_RULES`` (8 in total) with the per-pattern-type count.
* Counts come from ``count_watchlist_by_pattern_type`` and are 0
  pre-apply (DB doesn't exist) — the form still lists each row so
  the operator can pre-stage opt-ins.
* enable_alerting + per-type checkboxes round-trip to
  ``answers["enable_alerting"]`` + ``answers["enabled_rule_types"]``.
* enable_alerting=off means no per-type opt-ins are recorded, even
  if the per-type boxes were checked (defensive against stale form
  state).
* Token enforcement on /step/11 and /step/12.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.core import DELEGATION_RULES
from lynceus.setup.web import steps_severity_rules as steps
from lynceus.setup.web.app import create_wizard_app

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"
TARGET = Path("/tmp/wizard-test-lynceus.yaml")


def _make_app(**overrides):
    kwargs = dict(setup_token=TOKEN, scope="user", target_path=TARGET)
    kwargs.update(overrides)
    return create_wizard_app(**kwargs)


def _client(app):
    return TestClient(app, follow_redirects=False)


def _csrf_get(client, path):
    client.get(f"{path}?token={TOKEN}")
    return client.cookies.get("lynceus_csrf")


# ---- Step 11: Severity overrides ------------------------------------------


@pytest.mark.webui
def test_severity_get_renders_default_path():
    app = _make_app(target_path=Path("/etc/lynceus/lynceus.yaml"))
    with _client(app) as c:
        resp = c.get(f"/step/11?token={TOKEN}")
    assert resp.status_code == 200
    # Default = target_path.parent / severity_overrides.yaml
    assert "severity_overrides.yaml" in resp.text
    # Hint at the right parent directory.
    assert "/etc/lynceus" in resp.text or "etc\\lynceus" in resp.text


@pytest.mark.webui
def test_severity_page_carries_two_layer_model():
    """Regression for fix commit 658fa94: the Step 11 page reaches
    parity with the CLI's SEVERITY_OVERRIDES_EXPLANATION block by
    surfacing the import-time vs runtime distinction. Without it,
    an operator editing severity_overrides.yaml has no way to know
    whether their edit needs a re-import or just a daemon restart
    to take effect."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/11?token={TOKEN}")
    body = resp.text
    lowered = body.lower()
    # Two-layer framing.
    assert "import-time" in lowered or "import time" in lowered
    assert "runtime" in lowered
    # When each layer's edits take effect — load-bearing for the
    # operator who edits the file post-install.
    assert "re-import" in lowered
    assert "daemon restart" in lowered or "restart" in lowered
    # At least one key from each layer is named so the operator can
    # locate which bucket their edit falls into.
    assert "vendor_overrides" in body  # import-time
    assert "device_category_severity" in body  # runtime


@pytest.mark.webui
def test_severity_post_valid_path_advances():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/11")
        resp = c.post(
            f"/step/11?token={TOKEN}",
            data={"severity_path": "/etc/lynceus/severity_overrides.yaml", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/12")
    assert (
        app.state.session_store.get(TOKEN).answers["severity_overrides_path"]
        == "/etc/lynceus/severity_overrides.yaml"
    )


@pytest.mark.webui
def test_severity_post_blank_uses_default():
    app = _make_app(target_path=Path("/etc/lynceus/lynceus.yaml"))
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/11")
        resp = c.post(
            f"/step/11?token={TOKEN}",
            data={"severity_path": "", "_csrf": csrf},
        )
    assert resp.status_code == 303
    stored = app.state.session_store.get(TOKEN).answers["severity_overrides_path"]
    assert stored.endswith("severity_overrides.yaml")


@pytest.mark.webui
def test_severity_post_garbage_re_renders():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/11")
        resp = c.post(
            f"/step/11?token={TOKEN}",
            data={"severity_path": "definitely not a path", "_csrf": csrf},
        )
    assert resp.status_code == 200
    # Jinja HTML-escapes the apostrophe ("doesn&#39;t") so we look
    # for the unambiguous tail of the message instead.
    assert "look like a file path" in resp.text
    # Operator's input is echoed back.
    assert "definitely not a path" in resp.text


# ---- Step 12: Rules engine -----------------------------------------------


@pytest.mark.webui
def test_rules_get_lists_all_rule_types():
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/12?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    # Every rule_type appears as a checkbox name.
    for _name, rule_type, _pt, _label, _desc in DELEGATION_RULES:
        assert f"enable_{rule_type}" in body, f"missing rule_type: {rule_type}"


@pytest.mark.webui
def test_rules_get_shows_zero_counts_when_db_absent(monkeypatch):
    """Pre-apply, the daemon DB doesn't exist; every count is 0 and
    the form still renders every row so the operator can pre-stage."""
    monkeypatch.setattr(
        steps,
        "count_watchlist_by_pattern_type",
        lambda db_path: {pt: 0 for (_n, _rt, pt, _l, _d) in DELEGATION_RULES},
    )
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/12?token={TOKEN}")
    body = resp.text
    # All zero counts present.
    assert "0 rows" in body or "(0" in body


@pytest.mark.webui
def test_rules_get_surfaces_nonzero_counts(monkeypatch):
    """When the daemon DB exists (e.g. --reconfigure over a live
    install), per-type counts are real numbers."""
    fake_counts = {pt: 0 for (_n, _rt, pt, _l, _d) in DELEGATION_RULES}
    fake_counts["mac"] = 1234
    fake_counts["oui"] = 56789
    monkeypatch.setattr(
        steps, "count_watchlist_by_pattern_type", lambda db_path: fake_counts
    )
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/12?token={TOKEN}")
    body = resp.text
    assert "1,234" in body
    assert "56,789" in body


@pytest.mark.webui
def test_rules_post_alerting_off_records_no_types():
    """When the top-level gate is off, no per-type opt-ins should be
    stored even if their boxes were checked (defensive against
    operator confusion or stale form state)."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={
                "enable_watchlist_mac": "on",
                "enable_watchlist_oui": "on",
                "argus_mode": "skip",
                "_csrf": csrf,
            },
        )
    assert resp.status_code == 303
    # v0.7.7 Touch 5: merged step advances directly to /review.
    assert resp.headers["location"].startswith("/review")
    answers = app.state.session_store.get(TOKEN).answers
    assert answers["enable_alerting"] is False
    assert answers["enabled_rule_types"] == []


@pytest.mark.webui
def test_rules_post_alerting_on_records_selected_types():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={
                "enable_alerting": "on",
                "enable_watchlist_mac": "on",
                "enable_watchlist_oui": "on",
                "argus_mode": "skip",
                "_csrf": csrf,
            },
        )
    assert resp.status_code == 303
    # v0.7.7 Touch 5: merged step advances directly to /review.
    assert resp.headers["location"].startswith("/review")
    answers = app.state.session_store.get(TOKEN).answers
    assert answers["enable_alerting"] is True
    assert answers["enabled_rule_types"] == ["watchlist_mac", "watchlist_oui"]


@pytest.mark.webui
def test_rules_post_ignores_unknown_rule_types():
    """A POST that names a rule_type not in DELEGATION_RULES must be
    dropped — the wizard captures intent, not arbitrary keys."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={
                "enable_alerting": "on",
                "enable_watchlist_mac": "on",
                "enable_made_up_rule": "on",
                "argus_mode": "skip",
                "_csrf": csrf,
            },
        )
    assert resp.status_code == 303
    answers = app.state.session_store.get(TOKEN).answers
    assert answers["enabled_rule_types"] == ["watchlist_mac"]


# ---- v0.7.7 Touch 5: merged step 12 (rules + argus) -----------------------


@pytest.mark.webui
def test_unified_step_12_get_renders_both_sections():
    """GET /step/12 surfaces both the rules-engine fieldset and the
    argus-load-mode radio block on the same page."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/12?token={TOKEN}")
    body = resp.text
    assert resp.status_code == 200
    # Rules-engine pieces.
    assert 'name="enable_alerting"' in body
    assert "Per-rule-type enables" in body
    # Argus-load-mode pieces.
    assert 'name="argus_mode"' in body
    assert 'value="skip"' in body
    assert 'value="bundled"' in body
    assert 'value="github"' in body
    assert 'value="file"' in body


@pytest.mark.webui
def test_unified_step_12_post_skip_advances_to_review():
    """POST /step/12 with mode=skip records the argus_choice and
    advances directly to /review (no /step/13 hop)."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={"argus_mode": "skip", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/review")
    answers = app.state.session_store.get(TOKEN).answers
    assert answers["argus_choice"]["mode"] == "skip"


@pytest.mark.webui
def test_unified_step_12_post_bundled_records_choice():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={"argus_mode": "bundled", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/review")
    assert (
        app.state.session_store.get(TOKEN).answers["argus_choice"]["mode"]
        == "bundled"
    )


@pytest.mark.webui
def test_unified_step_12_post_file_mode_missing_path_re_renders():
    """File mode without a file path blocks advance; both sections'
    state must be preserved on the bounce so the operator's rules
    selection doesn't vanish."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={
                "enable_alerting": "on",
                "enable_watchlist_mac": "on",
                "argus_mode": "file",
                "argus_file_path": "",
                "_csrf": csrf,
            },
        )
    assert resp.status_code == 200
    body = resp.text
    assert "File mode selected but no file path" in body
    # Rules state preserved (the enable_alerting checkbox is still checked).
    assert 'name="enable_alerting"' in body and 'checked' in body
    # Argus mode preserved (file radio still selected). The template
    # renders attributes across multiple lines, so check by stripping
    # whitespace between value= and checked.
    import re
    body_collapsed = re.sub(r"\s+", " ", body)
    assert 'value="file" checked' in body_collapsed
    # Operator's per-type opt-in preserved (per-rule-type checkbox).
    assert 'name="enable_watchlist_mac"' in body_collapsed and (
        'name="enable_watchlist_mac" checked' in body_collapsed
        or 'name="enable_watchlist_mac" class="rule-type-checkbox" checked' in body_collapsed
        or 'class="rule-type-checkbox" name="enable_watchlist_mac" checked' in body_collapsed
    )


@pytest.mark.webui
def test_unified_step_12_post_unknown_mode_re_renders():
    """An argus_mode value not in the accept list re-renders with an
    error rather than silently coercing to skip."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={"argus_mode": "exfiltrate", "_csrf": csrf},
        )
    assert resp.status_code == 200
    assert "Unknown argus load mode" in resp.text


@pytest.mark.webui
def test_legacy_step_13_redirects_to_step_12():
    """Bookmarks / browser-back to /step/13 land on /step/12 with the
    setup token carried forward."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/13?token={TOKEN}")
    assert resp.status_code == 303
    assert "/step/12" in resp.headers["location"]
    assert f"token={TOKEN}" in resp.headers["location"]


@pytest.mark.webui
def test_step_titles_no_longer_lists_argus_watchlist():
    """STEP_TITLES tuple has 12 entries after the merge — the
    "Argus watchlist" entry from v0.7.6 Tier 4 is gone."""
    from lynceus.setup.web.app import STEP_TITLES, TOTAL_STEPS
    assert TOTAL_STEPS == 12
    assert "Argus watchlist" not in STEP_TITLES
    assert "Argus configuration" in STEP_TITLES


# ---- Step 12 copy structure ----------------------------------------------


@pytest.mark.webui
def test_rules_page_excludes_phase_2b_reference():
    """Regression for fix commit a227f44: Step 12 copy named the
    internal phase ("Phase 2b") as the trigger for the bundled
    watchlist import, which is meaningless to an operator. The
    operator-facing language must reference clicking Apply, not the
    internal release phase plan."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/12?token={TOKEN}")
    body = resp.text
    lowered = body.lower()
    assert "phase 2b" not in lowered
    assert "phase 2a" not in lowered


@pytest.mark.webui
def test_rules_page_surfaces_zero_rows_explanation_before_gate():
    """Regression for fix commit a227f44: smoke testing showed the
    explanation that 0-row counts are EXPECTED on first install was
    buried inside the per-rule-type <small> caption, where the
    operator read the table of zero counts as "no data to import"
    and bounced. The explanation must precede the gate checkbox in
    document order, so the first-install operator sees "this is
    expected" before being asked to decide."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/12?token={TOKEN}")
    body = resp.text
    # Explanation copy carries the load-bearing pieces.
    assert "first-install" in body.lower() or "first install" in body.lower()
    assert "22,000" in body or "22000" in body
    assert "Apply" in body
    # Document order: the explanation appears before the gate
    # checkbox markup.
    explanation_idx = body.lower().find("first-install")
    if explanation_idx < 0:
        explanation_idx = body.lower().find("first install")
    gate_idx = body.find('name="enable_alerting"')
    assert explanation_idx >= 0, "missing first-install explanation"
    assert gate_idx >= 0, "missing enable_alerting checkbox"
    assert explanation_idx < gate_idx, (
        "first-install 0-rows explanation must precede the alerting gate "
        "checkbox in document order so the operator reads the "
        "expectation-setting copy before deciding on the gate"
    )


@pytest.mark.webui
def test_rules_page_carries_select_all_rule_types_checkbox():
    """v0.7.0 Linux smoke: the per-rule-type list shipped without a
    select-all affordance, so an operator who wanted to enable every
    rule type had to click each of the 8 checkboxes individually.
    Add a "select all" checkbox that toggles every per-type box at
    once via a tiny inline onchange handler (no JS file, no build
    step). Pin its presence + the class hook the JS uses to find
    the per-type boxes so a refactor can't silently drop one half
    of the pair."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/12?token={TOKEN}")
    body = resp.text
    # The select-all checkbox itself.
    assert 'id="select-all-rule-types"' in body
    assert "Select all rule types" in body
    # The per-type checkboxes must carry the class the inline JS
    # selector reaches for; missing class hooks would no-op the
    # toggle and silently regress the affordance.
    assert 'class="rule-type-checkbox"' in body
    # And the inline JS that wires the two together (presence test
    # only; behavior test of the toggle would need a JS runtime).
    assert "rule-type-checkbox" in body
    assert "querySelectorAll" in body


# ---- token enforcement ---------------------------------------------------


@pytest.mark.webui
@pytest.mark.parametrize("path", ["/step/11", "/step/12"])
def test_severity_rules_routes_require_token(path):
    app = _make_app()
    with _client(app) as c:
        assert c.get(path).status_code == 403
        assert c.post(path).status_code == 403


@pytest.mark.webui
def test_step_12_watchlist_loading_renders_above_rule_type_enables():
    """UX-polish arc Touch 3: the watchlist-loading block (argus_mode
    radios) must render ABOVE the per-rule-type enablement selection so
    the operator decides *whether/how* to load Argus before staging
    per-type opt-ins. Document-order assertion only; field names and POST
    handling are unchanged (covered by the post_* tests)."""
    app = _make_app()
    with _client(app) as c:
        body = c.get(f"/step/12?token={TOKEN}").text
    load_idx = body.find('name="argus_mode"')
    load_heading_idx = body.find("Argus watchlist loading")
    pertype_idx = body.find("Per-rule-type enables")
    gate_idx = body.find('name="enable_alerting"')
    assert load_idx >= 0 and pertype_idx >= 0 and gate_idx >= 0
    assert load_heading_idx >= 0
    # Watchlist-loading section (heading + first radio) precedes both the
    # per-rule-type list and the alerting gate.
    assert load_heading_idx < pertype_idx
    assert load_idx < pertype_idx
    assert load_idx < gate_idx


@pytest.mark.webui
def test_step_12_post_preserves_handling_after_reorder():
    """After the Touch 3 reorder, a POST with both sections filled still
    records the rules opt-ins and the argus choice correctly — proving
    the visual swap didn't disturb by-name field handling."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/12")
        # Pick a real rule_type so the opt-in is collected.
        rule_type = next(rt for (_n, rt, _pt, _l, _d) in DELEGATION_RULES)
        resp = c.post(
            f"/step/12?token={TOKEN}",
            data={
                "argus_mode": "bundled",
                "enable_alerting": "on",
                f"enable_{rule_type}": "on",
                "_csrf": csrf,
            },
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/review")
    answers = app.state.session_store.get(TOKEN).answers
    assert answers["argus_choice"]["mode"] == "bundled"
    assert answers["enable_alerting"] is True
    assert rule_type in answers["enabled_rule_types"]
