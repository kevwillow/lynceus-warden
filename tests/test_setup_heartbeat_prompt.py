"""Heartbeat / dead-man's switch prompt for both setup wizards.

⛔ This file IS committed. An earlier draft of this docstring said "tests/ is
gitignored - these are NEVER committed", which is false and dangerous: only the
ten files named in `.gitignore` are withheld, and this is not one of them.
`git check-ignore` returns nothing for it. Keep every identifier here synthetic.

The contract under test:
  * Both frontends set ``answers["heartbeat_enabled"]`` as a bool.
  * It is asked only when ntfy is configured. An empty ntfy URL means the
    operator skipped ntfy, and a heartbeat question there would offer a feature
    that silently does nothing.
  * The default is the operator's CURRENT value, not False.
  * A generated config must still load through the real ``Config`` constructor.

⭐ The heartbeat is NOT a wizard step of its own. It is a field on the ntfy
step, in both frontends. That is load-bearing rather than cosmetic: inserting a
step into the web wizard's numbered ``/step/N`` sequence forces severity 11→12,
rules 12→13 and the legacy Argus redirect 13→14, or two handlers register the
same path and FastAPI raises at app construction. ``test_the_web_wizard_step_
numbering_is_unchanged`` is the guard against that being reintroduced.

⛔ And because the renderer now emits ``heartbeat_enabled``, it left the set
``carry_forward_settings`` protects -- so seeding the prompt from the existing
file is what keeps a hand-edited ``heartbeat_enabled: true`` alive across a
``--reconfigure``. That function's own docstring names this exact setting as its
flagship example. The seeding tests below are the guard.
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
#: ⚠️ Deliberately a path that does NOT exist. `_previous_heartbeat_enabled`
#: reads the target file to seed the prompt, so a fixed real path left behind by
#: an earlier run would silently become this suite's input. Tests that need a
#: real existing config pass their own `tmp_path` to `_make_app`.
TARGET = Path("/nonexistent-lynceus-wizard-target/lynceus.yaml")


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


# ---- Web wizard: a FIELD on the ntfy step, not a step of its own ----------


@pytest.fixture(autouse=True)
def _no_real_ntfy_probe(monkeypatch):
    monkeypatch.setattr(steps, "probe_ntfy", lambda url, topic: (False, "test default"))


def _ntfy_session(app, url="https://ntfy.sh", topic="lynceus-feedface"):
    """Put a configured ntfy in the session, as steps 7 and 8 would."""
    store = app.state.session_store
    session = store.get_or_create(app.state.setup_token)
    session.answers.update({"ntfy_url": url, "ntfy_topic": topic})
    return session


@pytest.mark.webui
def test_the_web_wizard_step_numbering_is_unchanged():
    """⛔ The regression guard for the whole design choice.

    A heartbeat step of its own would take /step/10, pushing RSSI to 11,
    severity to 12, rules to 13 and the legacy Argus redirect to 14. Two
    handlers on one path make FastAPI raise at app construction, so every web
    test would error before asserting anything. Pinning the numbering here means
    that reappears as ONE failing test with a name that says why.
    """
    app = _make_app()
    paths = {r.path for r in app.routes if hasattr(r, "path")}
    for expected in ("/step/7", "/step/8", "/step/9", "/step/10", "/step/11"):
        assert expected in paths, f"{expected} vanished: {sorted(paths)}"
    from lynceus.setup.web.app import STEP_TITLES

    titles = list(STEP_TITLES)
    assert "Heartbeat" not in titles, (
        "the heartbeat must NOT be its own step -- it is a field on the ntfy "
        f"step. STEP_TITLES: {titles}"
    )


@pytest.mark.webui
@pytest.mark.parametrize("branch", ["probe_skipped", "probe_ok", "probe_failed"])
def test_the_ntfy_step_renders_the_heartbeat_field_in_every_branch(branch, monkeypatch):
    """⛔ All THREE branches, because ntfy_probe.html has three separate
    <form> blocks and the field is included in each.

    A plant that removed the include from only the first one left the whole
    suite green -- the single-branch version of this test happened to exercise
    the third. One `{% include %}` deleted from a branch nobody drives is
    exactly the shape that ships.

    ⚠️ The probe-FAILED branch matters most: a broken ntfy is precisely when an
    operator most wants a daily proof the delivery path works, so that is the
    branch where dropping the question would hurt.
    """
    if branch == "probe_skipped":
        app = _make_app(skip_probes=True)
    else:
        app = _make_app()
        ok = branch == "probe_ok"
        monkeypatch.setattr(
            steps, "probe_ntfy", lambda url, topic: (ok, None if ok else "boom")
        )
    _ntfy_session(app)
    with _client(app) as c:
        resp = c.get(f"/step/9?token={TOKEN}")
    assert resp.status_code == 200
    assert 'name="heartbeat_enabled"' in resp.text, (
        f"the heartbeat checkbox is missing from the {branch} branch of the "
        "ntfy step"
    )


@pytest.mark.webui
def test_posting_the_checkbox_stores_true():
    app = _make_app()
    _ntfy_session(app)
    with _client(app) as c:
        token = _csrf_get(c, "/step/9")
        resp = c.post(
            f"/step/9?token={TOKEN}",
            data={"_csrf": token, "action": "continue", "heartbeat_enabled": "on"},
        )
    assert resp.status_code in (303, 307)
    assert app.state.session_store.get_or_create(TOKEN).answers["heartbeat_enabled"] is True


@pytest.mark.webui
def test_an_unchecked_box_stores_false():
    """⚠️ An unchecked checkbox sends no field at all -- the absence IS the
    answer, and it must be recorded as False rather than left unset."""
    app = _make_app()
    _ntfy_session(app)
    with _client(app) as c:
        token = _csrf_get(c, "/step/9")
        resp = c.post(
            f"/step/9?token={TOKEN}",
            data={"_csrf": token, "action": "continue"},
        )
    assert resp.status_code in (303, 307)
    assert app.state.session_store.get_or_create(TOKEN).answers["heartbeat_enabled"] is False


@pytest.mark.webui
def test_declining_ntfy_never_asks_and_never_sets_the_key():
    """Step 7 with an empty URL jumps to /step/10, so steps 8 and 9 -- and the
    heartbeat field on 9 -- are skipped for free. The key must stay UNSET, so
    the Config builder falls back to the operator's existing value rather than
    to a hard False."""
    app = _make_app()
    with _client(app) as c:
        token = _csrf_get(c, "/step/7")
        resp = c.post(f"/step/7?token={TOKEN}", data={"_csrf": token, "ntfy_url": ""})
    assert resp.status_code in (303, 307)
    assert resp.headers["location"].startswith("/step/10"), resp.headers["location"]
    assert "heartbeat_enabled" not in app.state.session_store.get_or_create(TOKEN).answers


@pytest.mark.webui
def test_the_web_config_builder_seeds_from_the_existing_file(tmp_path):
    """⛔ The load-bearing one. An operator who hand-edited heartbeat_enabled:
    true and then re-runs the web wizard declining ntfy must not have it
    switched off."""
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: http://127.0.0.1:2501\nheartbeat_enabled: true\n")
    from lynceus.setup.web import review

    answers = _answers(ntfy_url="", ntfy_topic="")
    seeded = review._build_config_from_session(
        answers, previous_heartbeat=core._previous_heartbeat_enabled(target)
    )
    assert seeded.heartbeat_enabled is True, (
        "the wizard discarded a hand-edited heartbeat_enabled: true"
    )
    # ...and an explicit answer still wins over the seed.
    answered_off = _answers(heartbeat_enabled=False)
    assert (
        review._build_config_from_session(
            answered_off, previous_heartbeat=True
        ).heartbeat_enabled
        is False
    ), "an explicit 'no' must beat the seeded previous value"


def test_cli_prompt_wording_is_read_from_the_SOURCE_not_restated():
    """⛔ This test used to be VACUOUS and passed for the wrong reason.

    It defined the expected question as a local literal and then asserted
    fragments were in that literal -- `X in X`, true no matter what the wizard
    actually says. Deleting the whole prompt from cli/setup.py left it green.

    It now reads the module's own source, so a "let's improve the copy" edit
    that drops what the operator is consenting to fails here.
    """
    import inspect

    src = inspect.getsource(wiz)
    block = src[src.index("# (j) heartbeat") : src.index("# (k) RSSI threshold")]
    # ⚠️ Fragments only, and short ones. The source wraps this prompt across
    # several adjacent string literals, so any fragment spanning a line break
    # would fail for formatting rather than for meaning.
    for fragment in ("still watching", "silence", "24h", "Lynceus default is", "OFF."):
        assert fragment in block, (
            f"the heartbeat prompt no longer says {fragment!r}; the operator is "
            "consenting to something this test can no longer describe"
        )
    # ...and the two facts that make the consent informed.
    assert "prompt_yes_no" in block, "the heartbeat is no longer a yes/no prompt"
    assert "default=previous" in block, (
        "the prompt stopped defaulting to the operator's current value -- a "
        "reconfigure would now switch off a heartbeat somebody turned on"
    )
