"""Web wizard: passive BLE bridge toggle on the BLE capture step.

tests/ is gitignored — these are NEVER committed (see project memory).

The load-bearing test here is the _build_config_from_session one. apply_config
renders lynceus.yaml from that Config, so a field the web wizard collects
but does not thread through is silently discarded — the operator ticks the
box, the wizard says it applied, and the file says enabled: false.
"""

from __future__ import annotations

from lynceus.config import BleBridgeConfig
from lynceus.setup.web import review as review_mod
from lynceus.setup.web.app import STEP_TITLES


def _answers(**overrides) -> dict:
    base = {
        "kismet_url": "http://localhost:2501",
        "kismet_sources": ["wlan0"],
        "probe_ssids": False,
        "ble_friendly_names": True,
        "min_rssi": -70,
    }
    base.update(overrides)
    return base


def test_config_from_answers_threads_the_bridge_through():
    """THE regression: the answer must survive into the rendered Config."""
    config = review_mod._build_config_from_session(
        _answers(ble_bridge_enabled=True, ble_bridge_adapter="hci0")
    )
    assert config.ble_bridge.enabled is True
    assert config.ble_bridge.adapter == "hci0"


def test_config_from_answers_defaults_to_off():
    config = review_mod._build_config_from_session(_answers())
    assert config.ble_bridge.enabled is False


def test_missing_adapter_answer_falls_back_to_the_model_default():
    config = review_mod._build_config_from_session(_answers(ble_bridge_enabled=True))
    assert config.ble_bridge.adapter == BleBridgeConfig().adapter


def test_review_summary_reports_the_bridge():
    summary = review_mod._summarize(
        _answers(ble_bridge_enabled=True, ble_bridge_adapter="hci0"), None
    )
    assert summary["ble_bridge_enabled"] is True
    assert summary["ble_bridge_adapter"] == "hci0"


def test_step_count_is_unchanged():
    """The toggle rides the existing BLE step — no renumbering, no new route."""
    assert len(STEP_TITLES) == 12
    assert STEP_TITLES[5] == "BLE capture"


# ---- HTTP flow (the context tests above bypass the route) -------------------


def _http():
    from lynceus.setup.web.app import create_wizard_app
    from tests.test_setup_web_capture import TARGET, TOKEN, _client, _csrf_get

    app = create_wizard_app(setup_token=TOKEN, scope="user", target_path=TARGET)
    # follow_redirects=False so the 303 is observable, not silently followed.
    return app, _client(app), TOKEN, _csrf_get


def test_step6_post_stores_the_bridge_answer():
    app, client, token, csrf_get = _http()
    with client as c:
        csrf = csrf_get(c, "/step/6")
        resp = c.post(
            f"/step/6?token={token}",
            data={"ble_friendly_names": "yes", "ble_bridge_enabled": "yes", "_csrf": csrf},
        )
    assert resp.status_code == 303
    answers = app.state.session_store.get(token).answers
    assert answers["ble_bridge_enabled"] is True
    assert answers["ble_bridge_adapter"] == BleBridgeConfig().adapter


def test_step6_post_defaults_to_off_when_unticked():
    app, client, token, csrf_get = _http()
    with client as c:
        csrf = csrf_get(c, "/step/6")
        c.post(
            f"/step/6?token={token}",
            data={"ble_friendly_names": "yes", "_csrf": csrf},
        )
    assert app.state.session_store.get(token).answers["ble_bridge_enabled"] is False


def test_step6_get_renders_the_toggle():
    _, client, token, _ = _http()
    with client as c:
        html = c.get(f"/step/6?token={token}").text
    assert "ble_bridge_enabled" in html
    assert "not a decoder over Kismet" in html
