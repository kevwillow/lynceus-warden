"""Tests for the review page + noop apply (F6 Phase 2a, Touch 7).

Pins:
* The review page renders with secrets redacted (Kismet API key
  head/tail; ntfy topic head/bullets/tail).
* Validation errors surface per-field with "edit step X" links that
  point at the responsible step.
* ``GET /apply-preview.json`` returns the same validated Config in
  JSON form, with the same redactions, plus the Phase-2b apply
  extras (severity path, alerting flags, scope, target).
* ``POST /apply`` is a placeholder — no filesystem writes, returns
  the apply_placeholder.html template.
* The Apply button on the review page is disabled when validation
  errors exist; enabled when the Config is valid.
* Edit-step-X links on the review page carry the setup token.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.web.app import create_wizard_app

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"
TARGET = Path("/tmp/wizard-test-lynceus.yaml")


def _valid_answers():
    """A wizard-state dict that yields a Config without errors."""
    return {
        "kismet_url": "http://localhost:2501",
        "kismet_api_key": "ABCDEF0123456789XYZ",
        "kismet_sources": ["external_wifi"],
        "probe_ssids": False,
        "ble_friendly_names": True,
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "lynceus-prod-alerts",
        "min_rssi": -70,
        "severity_overrides_path": "/etc/lynceus/severity_overrides.yaml",
        "enable_alerting": True,
        "enabled_rule_types": ["watchlist_mac", "watchlist_oui"],
    }


def _make_app(**overrides):
    kwargs = dict(setup_token=TOKEN, scope="user", target_path=TARGET)
    kwargs.update(overrides)
    return create_wizard_app(**kwargs)


def _client(app):
    return TestClient(app, follow_redirects=False)


def _csrf_get(client, path):
    client.get(f"{path}?token={TOKEN}")
    return client.cookies.get("lynceus_csrf")


# ---- Review page (HTML) --------------------------------------------------


@pytest.mark.webui
def test_review_apply_form_disables_button_on_submit():
    """Finding 4.3: the Apply form must disable its submit button on
    click so an operator double-click cannot fire two POSTs before
    the server-side 409 guard lands. Defense in depth behind the
    apply_lock + apply_state check (Finding 1.1)."""
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # Form carries an onsubmit that disables the submit button.
    # Pin the substring rather than exact attribute formatting so
    # quoting changes don't break the test.
    assert "onsubmit=" in body
    assert "disabled = true" in body or "disabled=true" in body


@pytest.mark.webui
def test_review_warns_about_hand_edit_overwrite_on_reconfigure():
    """Finding 1.2 (PRESHIP): the Apply article on review.html must
    warn about lynceus.yaml / rules.yaml hand-edits being clobbered
    when the wizard is running under --reconfigure (operator already
    has an existing config that the wizard is about to overwrite).
    Matches the wording of the Re-run-section warning added to
    apply_complete.html in batch 1's ef73949."""
    app = _make_app(reconfigure=True)
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # Same wording as apply_complete.html's Re-run section warning.
    assert "Hand-edits will be overwritten" in body
    assert "lynceus.yaml" in body
    # The warning lives inside a wizard-error block (styled red, same
    # as the Re-run page).
    assert "wizard-error" in body


@pytest.mark.webui
def test_review_does_not_warn_about_overwrite_on_first_install():
    """First-install path (no --reconfigure) must NOT show the
    hand-edit warning — there is no pre-existing config to overwrite,
    and an unconditional warning would be noise on the happy path."""
    app = _make_app(reconfigure=False)
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    assert "Hand-edits will be overwritten" not in body


@pytest.mark.webui
def test_review_renders_all_sections():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    # Each section is named.
    assert "Kismet" in body
    assert "Capture privacy" in body or "probe SSIDs" in body
    assert "ntfy" in body
    assert "Severity overrides" in body
    # Apply button present.
    assert "Apply" in body


@pytest.mark.webui
def test_review_redacts_kismet_api_key():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # Full key never appears.
    assert "ABCDEF0123456789XYZ" not in body
    # Head/tail preview present.
    assert "ABCD...9XYZ" in body


@pytest.mark.webui
def test_review_redacts_ntfy_topic():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # Full topic never appears in plain form.
    assert "lynceus-prod-alerts" not in body
    # First-4 + bullets + last-2 preview present.
    assert "lync" in body  # head
    # Bullets are rendered as •••; check for the redacted format.
    assert "•••" in body


@pytest.mark.webui
def test_review_edit_links_carry_token():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # Edit links for each section.
    for n in (1, 5, 7, 10, 11, 12):
        assert f"/step/{n}?token={TOKEN}" in body, f"missing edit link for step {n}"


@pytest.mark.webui
def test_review_apply_button_enabled_when_valid():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # No 'disabled' attribute on the Apply submit.
    # We look for the button literal; its enabled form lacks the
    # disabled attribute.
    assert "<button type=\"submit\">Apply" in body


@pytest.mark.webui
def test_review_surfaces_validation_errors_with_edit_links():
    app = _make_app()
    bad = _valid_answers()
    bad["kismet_url"] = "not-a-url"  # fails Config URL validator
    app.state.session_store.get_or_create(TOKEN).answers.update(bad)
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    assert "validation errors" in body.lower() or "kismet_url" in body
    # The error gets an edit-step link pointing at step 1.
    assert f"/step/1?token={TOKEN}" in body


@pytest.mark.webui
def test_review_apply_button_disabled_on_validation_error():
    app = _make_app()
    bad = _valid_answers()
    bad["kismet_url"] = "not-a-url"
    app.state.session_store.get_or_create(TOKEN).answers.update(bad)
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # Disabled attribute present on the Apply button.
    assert "disabled" in body


@pytest.mark.webui
def test_review_apply_copy_reflects_phase_2b_writes_to_disk():
    """Finding 8.1: the Apply article must describe current behavior
    (Apply writes to disk), not the Phase 2a "noop" placeholder.

    Pins both directions: the obsolete copy is gone, and the current-
    state language ("writes ... to disk", idempotent re-run safety
    net) is present. Pre-smoke-blocker — operator-facing accuracy."""
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/review?token={TOKEN}")
    body = resp.text
    # Obsolete Phase 2a copy must be gone.
    assert "Phase 2a" not in body
    assert "does not write the config to disk yet" not in body
    assert "lands in Phase 2b" not in body
    # Current-state copy present: makes the write-on-Apply contract
    # explicit and points at the Re-run safety net.
    assert "lynceus.yaml" in body
    assert "Re-run" in body or "re-run" in body
    assert "idempotent" in body


# ---- Apply POST contract (Phase 2b: real apply pipeline) -----------------
# Detailed apply-pipeline behavior (state transitions, SSE streaming,
# 409 on double-Apply, CLI parity on filesystem state) lives in
# tests/test_setup_web_apply.py. The assertions here pin only the
# request-shape contract the review page depends on.


@pytest.mark.webui
def test_apply_post_valid_config_redirects_to_progress(monkeypatch):
    """Valid config → 303 → /apply-progress (where the SSE stream
    drives the live update). We mock apply_config to a noop so this
    test doesn't actually run the side-effect chain."""
    from lynceus.setup.web import review as review_mod
    from lynceus.setup.models import ApplyReport

    monkeypatch.setattr(
        review_mod, "apply_config",
        lambda *args, **kwargs: ApplyReport(steps=()),
    )
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        resp = c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/apply-progress")


@pytest.mark.webui
def test_apply_post_invalid_config_redirects_to_review():
    """Invalid config → 303 → /review (the review page rebuilds the
    Config and surfaces the same error rows inline; the redirect is
    idempotent)."""
    app = _make_app()
    bad = _valid_answers()
    bad["kismet_url"] = "not-a-url"
    app.state.session_store.get_or_create(TOKEN).answers.update(bad)
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        resp = c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/review")


# ---- /apply-preview.json -------------------------------------------------


@pytest.mark.webui
def test_apply_preview_json_valid_returns_redacted_config():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        resp = c.get(f"/apply-preview.json?token={TOKEN}")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["valid"] is True
    cfg = payload["config"]
    # Public fields round-tripped.
    assert cfg["kismet_url"] == "http://localhost:2501"
    assert cfg["kismet_sources"] == ["external_wifi"]
    # Secrets redacted.
    assert cfg["kismet_api_key"] != "ABCDEF0123456789XYZ"
    assert cfg["kismet_api_key"] == "ABCD...9XYZ"
    assert cfg["ntfy_topic"] != "lynceus-prod-alerts"
    assert "•••" in cfg["ntfy_topic"]
    # Phase 2b apply extras carried through.
    extras = payload["extras"]
    assert extras["severity_overrides_path"] == "/etc/lynceus/severity_overrides.yaml"
    assert extras["enable_alerting"] is True
    assert extras["enabled_rule_types"] == ["watchlist_mac", "watchlist_oui"]
    assert extras["scope"] == "user"
    assert extras["target_path"] == str(TARGET)


@pytest.mark.webui
def test_apply_preview_json_invalid_returns_400_with_errors():
    app = _make_app()
    bad = _valid_answers()
    bad["kismet_url"] = "not-a-url"
    app.state.session_store.get_or_create(TOKEN).answers.update(bad)
    with _client(app) as c:
        resp = c.get(f"/apply-preview.json?token={TOKEN}")
    assert resp.status_code == 400
    payload = resp.json()
    assert payload["valid"] is False
    fields = [e["field"] for e in payload["errors"]]
    assert "kismet_url" in fields


@pytest.mark.webui
def test_apply_preview_json_preserves_no_apply_invariant(tmp_path):
    """Hitting the preview endpoint must not touch the filesystem."""
    target = tmp_path / "lynceus.yaml"
    app = _make_app(target_path=target)
    app.state.session_store.get_or_create(TOKEN).answers.update(_valid_answers())
    with _client(app) as c:
        c.get(f"/apply-preview.json?token={TOKEN}")
    assert not target.exists()


# ---- token enforcement --------------------------------------------------


@pytest.mark.webui
def test_review_route_requires_token():
    app = _make_app()
    with _client(app) as c:
        assert c.get("/review").status_code == 403


@pytest.mark.webui
def test_apply_route_requires_token():
    app = _make_app()
    with _client(app) as c:
        assert c.post("/apply").status_code == 403


@pytest.mark.webui
def test_apply_preview_json_requires_token():
    app = _make_app()
    with _client(app) as c:
        assert c.get("/apply-preview.json").status_code == 403
