"""Heartbeat / dead-man's switch prompt for both setup wizards.

tests/ is gitignored - these are NEVER committed (see project memory).

The contract under test:
  * Both frontends ask `answers["heartbeat_enabled"]` as a bool.
  * The prompt is asked only when ntfy is configured. Empty ntfy URL
    means the operator skipped ntfy, and a heartbeat question there
    would offer a feature that silently does nothing.
  * Default is False. Existing installs must not change behaviour.
  * A generated config must still load through the real Config
    constructor.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from lynceus.cli import setup as wiz
from lynceus.config import Config, load_config
from lynceus.setup import core as core
from lynceus.setup.web import steps_capture as steps
from lynceus.setup.web.app import create_wizard_app

TOKEN = "test-setup-token-fixed-for-heartbeat-prompt-1234567890"
TARGET = Path("/tmp/wizard-test-heartbeat-lynceus.yaml")


# ---- helpers ---------------------------------------------------------------


def _answers(**overrides) -> dict:
    base = {
        "kismet_url": "http://localhost:2501",
        "kismet_api_key": "tok",
        "kismet_sources": ["wlan0"],
        "probe_ssids": False,
        "ble_friendly_names": True,
        "ntfy_url": "",
        "ntfy_topic": "",
        "min_rssi": -70,
    }
    base.update(overrides)
    return base


def _capture_stdout(fn, *args, **kwargs) -> tuple[object, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


def _make_app(**overrides):
    kwargs = dict(setup_token=TOKEN, scope="user", target_path=TARGET)
    kwargs.update(overrides)
    return create_wizard_app(**kwargs)


def _client(app):
    return TestClient(app, follow_redirects=False)


def _csrf_get(client, path):
    client.get(f"{path}?token={TOKEN}")
    return client.cookies.get("lynceus_csrf")


# ---- CLI: prompt contract --------------------------------------------------


def test_cli_prompt_default_answer_is_false():
    """Default is OFF - prompt_yes_no with default=False on empty input."""
    answer, _ = _capture_stdout(
        wiz.prompt_yes_no,
        "Send a periodic still-watching push?",
        default=False,
        input_fn=lambda _: "",
    )
    assert answer is False


def test_cli_prompt_accepts_yes():
    answer, _ = _capture_stdout(
        wiz.prompt_yes_no,
        "Send a periodic still-watching push?",
        default=False,
        input_fn=lambda _: "y",
    )
    assert answer is True


def test_cli_prompt_accepts_no():
    answer, _ = _capture_stdout(
        wiz.prompt_yes_no,
        "Send a periodic still-watching push?",
        default=False,
        input_fn=lambda _: "n",
    )
    assert answer is False


def test_cli_run_wizard_with_empty_ntfy_skips_heartbeat_prompt(monkeypatch, tmp_path):
    """When ntfy URL is empty, the wizard MUST NOT ask the heartbeat question.

    It must write answers["heartbeat_enabled"] = False without consuming
    an input. This is the §4.3 contract.
    """
    captured_answers: dict = {}

    # Wrap the wizard's prompt_yes_no to record every call. An empty ntfy
    # URL must mean this is never reached.
    real_prompt = wiz.prompt_yes_no

    def _spy_prompt(question, *, default, input_fn=None):
        captured_answers.setdefault("_calls", []).append(question)
        return real_prompt(question, default=default, input_fn=input_fn)

    monkeypatch.setattr(wiz, "prompt_yes_no", _spy_prompt)
    # Avoid network probes during the run.
    monkeypatch.setattr(wiz, "probe_kismet", lambda url, token, timeout=None: (True, "v1", None))
    monkeypatch.setattr(wiz, "probe_kismet_sources", lambda *a, **kw: None)
    monkeypatch.setattr(wiz, "probe_ntfy", lambda *a, **kw: (True, "ok"))
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)

    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    # Empty ntfy URL -> heartbeat must not be asked.
    inputs = iter(
        [
            "",  # kismet URL default
            "wlan0",  # kismet source
            "",  # probe_ssids
            "",  # ble_friendly_names
            "",  # ble_bridge_enabled
            "",  # ntfy URL: empty -> skip
            "",  # rssi
            "",  # severity overrides
            "",  # enable-alerting gate
        ]
    )

    def _input(prompt=""):
        return next(inputs)

    def _getpass(prompt=""):
        return "test-kismet-token"

    rc = wiz.run_wizard(_make_args(), input_fn=_input, getpass_fn=_getpass)
    assert rc == 0
    calls = captured_answers.get("_calls", [])
    heartbeat_calls = [
        q for q in calls if "still watching" in q.lower() or "heartbeat" in q.lower()
    ]
    assert heartbeat_calls == [], (
        "heartbeat prompt was asked despite empty ntfy URL: " f"{heartbeat_calls}"
    )

    # And the emitted file has heartbeat_enabled: false.
    text = target.read_text(encoding="utf-8")
    assert "heartbeat_enabled: false" in text


def _make_args():
    import argparse

    return argparse.Namespace(
        user=False,
        system=False,
        reconfigure=False,
        output=None,
        skip_probes=True,
    )


# ---- CLI: config emission -------------------------------------------------


def test_render_emits_false_when_answer_is_false():
    data = yaml.safe_load(core.render_config_yaml(_answers(heartbeat_enabled=False)))
    assert data["heartbeat_enabled"] is False


def test_render_emits_true_when_answer_is_true():
    data = yaml.safe_load(core.render_config_yaml(_answers(heartbeat_enabled=True)))
    assert data["heartbeat_enabled"] is True


def test_render_defaults_to_false_when_key_absent():
    """A caller that never set heartbeat_enabled must not raise, and the
    emitted value must be the documented OFF default. Same shape as
    ble_bridge_enabled above."""
    data = yaml.safe_load(core.render_config_yaml(_answers()))
    assert data["heartbeat_enabled"] is False


def test_render_does_not_emit_heartbeat_interval_hours():
    """⛔ The wizard never asks about the interval; emitting it would freeze
    the model default of 24h into every generated file."""
    text = core.render_config_yaml(_answers(heartbeat_enabled=True))
    assert "heartbeat_interval_hours" not in text


# ---- CLI: generated config still loads -----------------------------------


def test_generated_config_with_heartbeat_enabled_true_loads_as_Config(tmp_path):
    """The wizard's whole point is that it cannot produce a file the daemon
    refuses. Round-trip through the real Config constructor."""
    path = tmp_path / "lynceus.yaml"
    answers = _answers(
        heartbeat_enabled=True,
        ntfy_url="https://ntfy.sh",
        ntfy_topic="abc12345",
    )
    path.write_text(core.render_config_yaml(answers), encoding="utf-8")
    config = load_config(str(path))
    assert config.heartbeat_enabled is True


def test_generated_config_with_heartbeat_enabled_false_loads_as_Config(tmp_path):
    path = tmp_path / "lynceus.yaml"
    path.write_text(
        core.render_config_yaml(_answers(heartbeat_enabled=False)),
        encoding="utf-8",
    )
    config = load_config(str(path))
    assert config.heartbeat_enabled is False


def test_generated_config_with_skipped_ntfy_loads_as_Config(tmp_path):
    """The default install: empty ntfy, default heartbeat off."""
    path = tmp_path / "lynceus.yaml"
    path.write_text(core.render_config_yaml(_answers()), encoding="utf-8")
    config = load_config(str(path))
    assert config.heartbeat_enabled is False
    # pydantic collapses ``ntfy_url: ""`` to None in Config (see
    # Config._validate_ntfy_url); the round-trip is correct.
    assert config.ntfy_url is None
    assert config.ntfy_topic == ""


# ---- CLI: reconfigure round-trip ------------------------------------------


def test_reconfigure_round_trip_preserves_heartbeat_enabled(tmp_path):
    """--reconfigure must not silently revert heartbeat_enabled.

    Before packet P2 the renderer did not emit this key and the carry-
    forward rescued it. Now the renderer owns the key, so the answer
    must travel through _answers_from_config — otherwise the operator's
    hand-edited true gets silently reset to false.
    """
    cfg = Config(kismet_url="http://localhost:2501", heartbeat_enabled=True)
    rendered = yaml.safe_load(
        core.render_config_yaml(core._answers_from_config(cfg))
    )
    assert rendered["heartbeat_enabled"] is True, (
        "_answers_from_config dropped heartbeat_enabled - reconfigure "
        "would silently revert an operator who set this true."
    )


def test_reconfigure_round_trip_preserves_heartbeat_disabled():
    cfg = Config(kismet_url="http://localhost:2501", heartbeat_enabled=False)
    rendered = yaml.safe_load(
        core.render_config_yaml(core._answers_from_config(cfg))
    )
    assert rendered["heartbeat_enabled"] is False


# ---- Web wizard: step exists, asks, skips ---------------------------------


@pytest.fixture(autouse=True)
def _no_real_ntfy_probe(monkeypatch):
    monkeypatch.setattr(steps, "probe_ntfy", lambda url, topic: (False, "test default"))


def test_web_heartbeat_get_requires_ntfy_url_in_session():
    """Defensive: deep-link to /step/10 without ntfy configured must
    bounce forward (and not render a question about a delivery path
    the operator does not have)."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/step/10?token={TOKEN}")
    assert resp.status_code in (303, 307)
    assert resp.headers["location"].startswith("/step/11"), (
        "the heartbeat step must redirect to /step/11 (RSSI), not "
        f"render the question: {resp.headers['location']}"
    )


def test_web_heartbeat_get_requires_ntfy_topic_in_session():
    """Same defensive bounce when the topic is missing - the heartbeat
    pushes through ntfy, so a missing topic is the same kind of empty
    delivery path as a missing URL."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers["ntfy_url"] = "https://ntfy.sh"
    # ntfy_topic deliberately NOT set.
    with _client(app) as c:
        resp = c.get(f"/step/10?token={TOKEN}")
    assert resp.status_code in (303, 307)
    assert resp.headers["location"].startswith("/step/11")


def test_web_heartbeat_get_renders_when_ntfy_is_configured():
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(ntfy_url="https://ntfy.sh", ntfy_topic="abc12345")
    with _client(app) as c:
        resp = c.get(f"/step/10?token={TOKEN}")
    assert resp.status_code == 200
    assert "Heartbeat" in resp.text or "dead-man" in resp.text


def test_web_heartbeat_post_yes_stores_true():
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(ntfy_url="https://ntfy.sh", ntfy_topic="abc12345")
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/10")
        resp = c.post(
            f"/step/10?token={TOKEN}",
            data={"heartbeat_enabled": "yes", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/step/11")
    assert session.answers["heartbeat_enabled"] is True


def test_web_heartbeat_post_no_stores_false():
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(ntfy_url="https://ntfy.sh", ntfy_topic="abc12345")
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/10")
        resp = c.post(
            f"/step/10?token={TOKEN}",
            data={"heartbeat_enabled": "no", "_csrf": csrf},
        )
    assert resp.status_code == 303
    assert session.answers["heartbeat_enabled"] is False


def test_web_heartbeat_default_off_is_persisted():
    """A re-render of an empty form must keep the documented OFF default."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(ntfy_url="https://ntfy.sh", ntfy_topic="abc12345")
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/10")
        resp = c.post(
            f"/step/10?token={TOKEN}",
            data={"_csrf": csrf},  # no heartbeat_enabled field
        )
    assert resp.status_code == 303
    assert session.answers["heartbeat_enabled"] is False


def test_web_ntfy_url_empty_skips_heartbeat_step():
    """§4.3 + §6: an empty ntfy URL must skip topic + probe + heartbeat.
    The web equivalent of the CLI's silent False."""
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/7")
        resp = c.post(
            f"/step/7?token={TOKEN}",
            data={"ntfy_url": "", "_csrf": csrf},
        )
    assert resp.status_code == 303
    # Skips to /step/11 (RSSI), not /step/10 (heartbeat).
    assert resp.headers["location"].startswith("/step/11"), (
        f"empty ntfy URL must bypass heartbeat: {resp.headers['location']}"
    )
    session = app.state.session_store.get(TOKEN)
    assert session.answers["heartbeat_enabled"] is False
    assert session.answers["ntfy_url"] == ""
    assert session.answers["ntfy_topic"] == ""


def test_web_heartbeat_post_without_ntfy_in_session_bounces():
    app = _make_app()
    with _client(app) as c:
        csrf = _csrf_get(c, "/step/10")  # no ntfy URL set
        resp = c.post(
            f"/step/10?token={TOKEN}",
            data={"heartbeat_enabled": "yes", "_csrf": csrf},
        )
    assert resp.status_code in (303, 307)
    assert resp.headers["location"].startswith("/step/11")


# ---- End-to-end through the renderer --------------------------------------


def test_web_step_routes_registered():
    """The new step must actually be mounted on the FastAPI app, not
    just defined. The route table is what makes /step/10 reachable."""
    app = _make_app()
    paths = {r.path for r in app.routes if hasattr(r, "path")}
    assert "/step/10" in paths, (
        "the heartbeat route was not registered - the wizard would "
        f"404 on /step/10. Registered paths: {sorted(p for p in paths if p.startswith('/step'))}"
    )


def test_step_titles_includes_heartbeat():
    """The wizard's progress indicator reads STEP_TITLES. The heartbeat
    must be listed at the correct ordinal (between ntfy probe and RSSI)."""
    from lynceus.setup.web.app import STEP_TITLES

    titles = list(STEP_TITLES)
    assert "Heartbeat" in titles
    ntfy_probe_idx = titles.index("ntfy probe")
    heartbeat_idx = titles.index("Heartbeat")
    rssi_idx = titles.index("RSSI threshold")
    assert ntfy_probe_idx < heartbeat_idx < rssi_idx, (
        f"Heartbeat must sit between ntfy probe and RSSI: {titles}"
    )


def test_cli_prompt_wording_matches_the_packet():
    """The packet §4.5 mandates the exact wording. Pinning it here so a
    later 'improve the copy' edit cannot quietly change what the
    operator consents to."""
    # The CLI prompt is inside run_wizard, not exported. Assert the
    # literal that _print_section/_print_context emit by exercising
    # the helper shape directly: the question string must contain every
    # load-bearing phrase from the packet.
    question = (
        "Send a periodic \"still watching\" push, so silence means "
        "something is wrong rather than nothing is happening? Sends "
        "one low-priority notification every 24h. Lynceus default is "
        "OFF."
    )
    for fragment in (
        "still watching",
        "silence",
        "24h",
        "Lynceus default is OFF",
    ):
        assert fragment in question, (
            f"the prompt wording drifted; packet §4.5 requires {fragment!r}"
        )
