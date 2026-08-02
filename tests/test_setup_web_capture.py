"""Tests for the capture + ntfy + RSSI section (F6 Phase 2a, Touch 5).

Covers steps 5-10: probe_ssids, ble_friendly_names, ntfy URL/topic/
probe, RSSI threshold. Pins:
* Booleans round-trip to the session as ``True`` / ``False``.
* Empty ntfy URL skips topic + probe and jumps to /step/10.
* Defensive redirects: deep-linking into /step/8 or /step/9 with no
  URL in session bounces back to /step/7.
* ntfy topic validation rejects out-of-range / denylisted values
  via the existing ``_looks_like_ntfy_topic`` helper.
* RSSI parsing rejects non-int and out-of-range values.
* ntfy probe honors ``skip_probes`` and offers Continue Anyway on
  failure.
* Token enforcement on every capture route.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.web import steps_capture as steps
from lynceus.setup.web.app import create_wizard_app

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"
TARGET = Path("/tmp/wizard-test-lynceus.yaml")


@pytest.fixture(autouse=True)
def _no_real_ntfy_probe(monkeypatch):
    """Default ntfy probe to a failure so a stray real call doesn't
    POST to ntfy.sh from CI. Tests that exercise success path
    override per-test."""
    monkeypatch.setattr(steps, "probe_ntfy", lambda url, topic: (False, "test default"))


def _make_app(**overrides):
    kwargs = dict(setup_token=TOKEN, scope="user", target_path=TARGET)
    kwargs.update(overrides)
    return create_wizard_app(**kwargs)


def _client(app):
    return TestClient(app, follow_redirects=False)


def _csrf_get(client, path):
    client.get(f"{path}?token={TOKEN}")
    return client.cookies.get("lynceus_csrf")


# ---- Step 5: probe_ssids ---------------------------------------------------


@pytest.mark.webui
def test_probe_ssids_get_default_off():
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/5?token={TOKEN}")
    assert resp.status_code == 200
    assert "Step 5: Probe SSIDs" in resp.text


@pytest.mark.webui
@pytest.mark.parametrize("value,expected", [("yes", True), ("no", False)])
def test_probe_ssids_post_stores_boolean(value, expected):
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/5")
        resp = c.post(
            f"/step/5?token={TOKEN}",
            data={"probe_ssids": value, "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/6")
    assert app.state.session_store.get(TOKEN).answers["probe_ssids"] is expected


# ---- Step 6: ble_friendly_names ------------------------------------------


@pytest.mark.webui
@pytest.mark.parametrize("value,expected", [("yes", True), ("no", False)])
def test_ble_names_post_stores_boolean(value, expected):
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/6")
        resp = c.post(
            f"/step/6?token={TOKEN}",
            data={"ble_friendly_names": value, "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/7")
    assert app.state.session_store.get(TOKEN).answers["ble_friendly_names"] is expected


# ---- Step 7: ntfy URL ----------------------------------------------------


@pytest.mark.webui
def test_ntfy_url_page_carries_cli_parity_context():
    """Regression for fix commit 11a3947: the Step 7 page reaches
    parity with the CLI's _print_context block — the two-prompts
    sequence overview, the topic-is-a-password warning surfaced
    BEFORE committing to ntfy, and the public-vs-self-host
    distinction. The first two are load-bearing for the operator's
    opt-in decision; the third unblocks self-hosters who would
    otherwise wonder if the wizard even supports their URL."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/7?token={TOKEN}")
    body = resp.text
    # Two-prompts framing.
    assert "broker URL" in body
    assert "topic" in body.lower()
    # Shared-secret warning, surfaced on the URL step (not just on
    # the topic step) so it informs the opt-in decision itself.
    assert "password" in body.lower() or "shared secret" in body.lower()
    # Public-vs-self-host distinction.
    assert "self-host" in body.lower() or "self host" in body.lower()


@pytest.mark.webui
def test_ntfy_url_page_warns_against_topic_in_url():
    """0.9.1: the Step 7 page must steer the operator away from the field
    misconfiguration — appending the topic to the URL so the daemon POSTs to
    <url>/<topic>/<topic>, a dead topic nothing is subscribed to."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/7?token={TOKEN}")
    low = resp.text.lower()
    # URL field is the SERVER BASE only; the topic must not be appended.
    assert "server base" in low
    assert "do not append" in low
    # The concrete failure mode is named so the operator recognises it.
    # (Assert the contiguous consequence clause — "dead topic" can straddle
    # a template line-wrap, the same gotcha the subscribe-walkthrough test
    # calls out below.)
    assert "nothing is subscribed" in low


@pytest.mark.webui
def test_ntfy_url_post_valid_advances_to_topic():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/7")
        resp = c.post(
            f"/step/7?token={TOKEN}",
            data={"ntfy_url": "https://ntfy.sh", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/8")
    assert app.state.session_store.get(TOKEN).answers["ntfy_url"] == "https://ntfy.sh"


@pytest.mark.webui
def test_ntfy_url_post_empty_skips_to_rssi():
    """Empty URL is the operator's "skip ntfy entirely" signal in
    the CLI flow; the web flow must mirror that and jump straight to
    /step/10 (RSSI), bypassing topic + probe."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/7")
        resp = c.post(
            f"/step/7?token={TOKEN}",
            data={"ntfy_url": "", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/10")
    answers = app.state.session_store.get(TOKEN).answers
    assert answers["ntfy_url"] == ""
    assert answers["ntfy_topic"] == ""


@pytest.mark.webui
def test_ntfy_url_post_empty_clears_stale_topic():
    """If the operator initially set up ntfy and then re-walked the
    wizard clearing the URL, the prior topic must not survive."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(ntfy_url="https://old.example", ntfy_topic="old-topic")
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/7")
        c.post(
            f"/step/7?token={TOKEN}",
            data={"ntfy_url": "", "_csrf": csrf},
        )
    assert app.state.session_store.get(TOKEN).answers["ntfy_topic"] == ""


@pytest.mark.webui
def test_ntfy_url_post_invalid_re_renders():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/7")
        resp = c.post(
            f"/step/7?token={TOKEN}",
            data={"ntfy_url": "not-a-url", "_csrf": csrf},
        )
    assert resp.status_code == 200
    assert "not-a-url" in resp.text
    assert "error" in resp.text.lower()


# ---- Step 8: ntfy topic ---------------------------------------------------


@pytest.mark.webui
def test_ntfy_topic_get_redirects_if_no_url():
    """Defensive: deep-linking into /step/8 with empty ntfy_url
    bounces back to /step/7 instead of erroring."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/8?token={TOKEN}")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/7")


@pytest.mark.webui
def test_ntfy_topic_get_shows_suggested():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers["ntfy_url"] = "https://ntfy.sh"
    with _client(app) as c:
        resp = c.get(f"/step/8?token={TOKEN}")
    assert resp.status_code == 200
    # Suggested topic follows the lynceus-XXXXXXXX pattern.
    assert "lynceus-" in resp.text


@pytest.mark.webui
def test_ntfy_topic_page_carries_subscribe_walkthrough():
    """Regression for fix commit 0d8ae61: the Step 8 page reaches
    parity with the CLI's _print_context block by surfacing the
    phone-subscribe steps. Without these, an operator finishes the
    wizard configuring publication but has no idea how to subscribe
    to actually receive the alerts they just opted into."""
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers["ntfy_url"] = "https://ntfy.sh"
    with _client(app) as c:
        resp = c.get(f"/step/8?token={TOKEN}")
    body = resp.text
    # App-install pointer — the platform-specific store names are
    # load-bearing for an operator who has never used ntfy. Using
    # the store names instead of "ntfy app" because template line
    # wrapping puts whitespace between "ntfy" and "app".
    assert "Play Store" in body or "App Store" in body
    # Subscribe action: tap + button, enter topic.
    assert "subscribe" in body.lower() or "subscription" in body.lower()
    # Desktop browser fallback for operators without a phone handy.
    assert "browser" in body.lower()


@pytest.mark.webui
def test_ntfy_topic_post_accepts_valid():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers["ntfy_url"] = "https://ntfy.sh"
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/8")
        resp = c.post(
            f"/step/8?token={TOKEN}",
            data={"ntfy_topic": "lynceus-prod-alerts", "suggested": "ignored", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/9")
    assert app.state.session_store.get(TOKEN).answers["ntfy_topic"] == "lynceus-prod-alerts"


@pytest.mark.webui
def test_ntfy_topic_post_blank_uses_suggested():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers["ntfy_url"] = "https://ntfy.sh"
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/8")
        resp = c.post(
            f"/step/8?token={TOKEN}",
            data={"ntfy_topic": "", "suggested": "lynceus-abcd1234", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert app.state.session_store.get(TOKEN).answers["ntfy_topic"] == "lynceus-abcd1234"


@pytest.mark.webui
def test_ntfy_topic_post_invalid_re_renders():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers["ntfy_url"] = "https://ntfy.sh"
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/8")
        resp = c.post(
            f"/step/8?token={TOKEN}",
            data={"ntfy_topic": "xx", "suggested": "ignored-by-invalid", "_csrf": csrf},
        )
    assert resp.status_code == 200
    assert "error" in resp.text.lower()


@pytest.mark.webui
def test_ntfy_topic_post_denylisted_re_renders():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers["ntfy_url"] = "https://ntfy.sh"
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/8")
        resp = c.post(
            f"/step/8?token={TOKEN}",
            data={"ntfy_topic": "skip", "suggested": "ignored", "_csrf": csrf},
        )
    assert resp.status_code == 200


# ---- Step 9: ntfy probe --------------------------------------------------


@pytest.mark.webui
def test_ntfy_probe_get_redirects_if_no_url():
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/9?token={TOKEN}")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/7")


@pytest.mark.webui
def test_ntfy_probe_get_skip_probes_renders_skipped(monkeypatch):
    # Spy probe_ntfy to ensure skip-probes doesn't accidentally call it.
    calls = []
    monkeypatch.setattr(steps, "probe_ntfy", lambda u, t: calls.append((u, t)) or (True, None))
    app = _make_app(skip_probes=True)
    app.state.session_store.get_or_create(TOKEN).answers.update(
        ntfy_url="https://ntfy.sh", ntfy_topic="lynceus-prod-alerts"
    )
    with _client(app) as c:
        resp = c.get(f"/step/9?token={TOKEN}")
    assert resp.status_code == 200
    assert "skipped" in resp.text.lower()
    assert calls == []


@pytest.mark.webui
def test_ntfy_probe_get_dispatches_via_to_thread(monkeypatch):
    """Finding 3.6 (PRESHIP): probe_ntfy is synchronous (requests.post,
    5s timeout). Pin the route-handler dispatches it through
    asyncio.to_thread so the event loop stays responsive during the
    network call.

    Spy on asyncio.to_thread (still call-through) and assert the
    probe_ntfy function is the one being dispatched.
    """
    def fake_probe_ntfy(url, topic):
        return (True, None)

    monkeypatch.setattr(steps, "probe_ntfy", fake_probe_ntfy)
    dispatched: list = []
    real_to_thread = steps.asyncio.to_thread

    async def spy_to_thread(fn, *args, **kwargs):
        dispatched.append(fn)
        return await real_to_thread(fn, *args, **kwargs)

    monkeypatch.setattr(steps.asyncio, "to_thread", spy_to_thread)

    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(
        ntfy_url="https://ntfy.sh", ntfy_topic="lynceus-prod-alerts"
    )
    with _client(app) as c:
        resp = c.get(f"/step/9?token={TOKEN}")
    assert resp.status_code == 200
    # Identity-check the dispatch.
    assert fake_probe_ntfy in dispatched


@pytest.mark.webui
def test_ntfy_probe_get_success(monkeypatch):
    from lynceus.redact import redact_topic_in_url

    monkeypatch.setattr(steps, "probe_ntfy", lambda u, t: (True, None))
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(
        ntfy_url="https://ntfy.sh", ntfy_topic="lynceus-prod-alerts"
    )
    with _client(app) as c:
        resp = c.get(f"/step/9?token={TOKEN}")
    body = resp.text
    assert resp.status_code == 200
    assert app.state.session_store.get(TOKEN).answers["ntfy_probe_ok"] is True
    # The resolved POST target is shown, topic-redacted (never raw).
    assert redact_topic_in_url("https://ntfy.sh/lynceus-prod-alerts") in body
    assert "lynceus-prod-alerts" not in body
    # Reachability is stated honestly — a 2xx must NOT be sold as success,
    # and the operator is pointed at confirming receipt on their device.
    assert "configured successfully" not in body.lower()
    assert "subscrib" in body.lower()


@pytest.mark.webui
def test_ntfy_probe_get_failure_offers_continue(monkeypatch):
    monkeypatch.setattr(steps, "probe_ntfy", lambda u, t: (False, "HTTP 403"))
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(
        ntfy_url="https://ntfy.sh", ntfy_topic="lynceus-prod-alerts"
    )
    with _client(app) as c:
        resp = c.get(f"/step/9?token={TOKEN}")
    body = resp.text
    assert "failed" in body.lower()
    assert "HTTP 403" in body
    assert "Continue anyway" in body


@pytest.mark.webui
def test_ntfy_probe_post_continue_advances():
    app = _make_app()
    app.state.session_store.get_or_create(TOKEN).answers.update(
        ntfy_url="https://ntfy.sh", ntfy_topic="lynceus-prod-alerts"
    )
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/9")
        resp = c.post(
            f"/step/9?token={TOKEN}",
            data={"action": "continue", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/10")


# ---- Step 10: RSSI -------------------------------------------------------


@pytest.mark.webui
def test_rssi_get_renders_default():
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/10?token={TOKEN}")
    assert resp.status_code == 200
    assert "-70" in resp.text or "Step 10" in resp.text


@pytest.mark.webui
def test_rssi_get_renders_slider_with_semantic_labels():
    """v0.7.0 Linux smoke surfaced operator confusion about the
    number-arrow direction on the negative-dBm input. v0.7.1's inline
    sign-convention copy didn't land; v0.7.2 replaces the number input
    with a range slider whose extremes are labelled semantically
    ("more permissive" ↔ "stricter") so the operator drags toward
    the intent without ever resolving sign convention. Pin that both
    semantic labels render so a template cleanup that drops one
    re-surfaces the smoke confusion."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/10?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    assert 'type="range"' in body
    # The number input is gone — pinned absent so a regression to
    # type="number" (the prior input) fails this test.
    assert 'type="number"' not in body
    # Range bounds match the validator (Config.min_rssi range).
    assert 'min="-120"' in body
    assert 'max="0"' in body
    assert 'step="1"' in body
    # Semantic labels at the extremes.
    assert "stricter" in body.lower()
    assert "permissive" in body.lower()
    # Live readout span gets updated by inline JS on slider input.
    assert "min_rssi_readout" in body


@pytest.mark.webui
def test_rssi_slider_carries_concrete_trade_off_labels():
    """v0.7.2 follow-up: the "permissive / stricter" framing names the
    direction but assumes the operator knows what dBm means in practice.
    Each extreme label is extended with the concrete trade-off (catches
    more weak / distant devices ↔ only strong / nearby devices) and a
    one-line tip below names the -80 dBm default for the home-setup
    case. Pin each anchor phrase so a template cleanup that drops one
    re-surfaces the "I don't know what this slider does in practice"
    confusion."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/10?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    # Concrete trade-off labels at the slider extremes.
    assert "Catches more" in body
    assert "Catches fewer" in body
    # Default-value tip below the labels.
    assert "-80 dBm is the default" in body


@pytest.mark.webui
def test_rssi_post_valid_int_advances_and_stashes():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/10")
        resp = c.post(
            f"/step/10?token={TOKEN}",
            data={"min_rssi": "-65", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/11")
    assert app.state.session_store.get(TOKEN).answers["min_rssi"] == -65


@pytest.mark.webui
def test_rssi_post_non_int_re_renders():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/10")
        resp = c.post(
            f"/step/10?token={TOKEN}",
            data={"min_rssi": "nope", "_csrf": csrf},
        )
    assert resp.status_code == 200
    assert "integer" in resp.text.lower()
    assert "nope" in resp.text


@pytest.mark.webui
def test_rssi_post_out_of_range_re_renders():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/10")
        resp = c.post(
            f"/step/10?token={TOKEN}",
            data={"min_rssi": "42", "_csrf": csrf},  # positive — operator confusion
        )
    assert resp.status_code == 200
    assert "between" in resp.text.lower() or "-120" in resp.text


# ---- token enforcement ----------------------------------------------------


@pytest.mark.webui
@pytest.mark.parametrize("path", ["/step/5", "/step/6", "/step/7", "/step/8", "/step/9", "/step/10"])
def test_capture_routes_require_token(path):
    app = _make_app()
    with _client(app) as c:
        assert c.get(path).status_code == 403
        assert c.post(path).status_code == 403
