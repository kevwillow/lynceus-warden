"""Tests for the ``--web`` / ``--port`` / ``--bind`` flags on
``lynceus-setup`` (F6 Phase 2a, Touch 2).

Pins the dispatch contract: ``main(["--web", ...])`` must call
``run_wizard_server`` with the resolved scope and target path; the
default bind is loopback; the default port is one above the UI
default. The legacy CLI flow must be unaffected when ``--web`` is
absent.

These tests do not actually start a server — ``run_wizard_server``
is mocked at the import site in ``lynceus.cli.setup`` so the test
can inspect the kwargs it was handed.
"""

from __future__ import annotations

from lynceus.cli import setup as cli_setup
from lynceus.setup.web import server as wizard_server


def _patch_server(monkeypatch):
    """Replace ``run_wizard_server`` and return the kwargs captor."""
    captured: dict = {}

    def fake_run_wizard_server(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(
        "lynceus.setup.web.server.run_wizard_server",
        fake_run_wizard_server,
    )
    # Defang the sudo refusal so tests work regardless of the test
    # host's euid; the dispatch under test happens AFTER the euid check.
    monkeypatch.setattr(cli_setup, "_euid", lambda: 1000)
    return captured


def test_web_flag_dispatches_to_run_wizard_server(monkeypatch):
    captured = _patch_server(monkeypatch)
    rc = cli_setup.main(["--web"])
    assert rc == 0
    assert captured, "run_wizard_server was not invoked"
    # Default scope and bind for an unprivileged invocation.
    assert captured["scope"] == "user"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8766


def test_web_flag_port_override(monkeypatch):
    captured = _patch_server(monkeypatch)
    cli_setup.main(["--web", "--port", "9000"])
    assert captured["port"] == 9000


def test_web_flag_bind_override(monkeypatch):
    captured = _patch_server(monkeypatch)
    cli_setup.main(["--web", "--bind", "0.0.0.0"])
    assert captured["host"] == "0.0.0.0"


def test_web_flag_with_user_scope(monkeypatch):
    captured = _patch_server(monkeypatch)
    cli_setup.main(["--web", "--user"])
    assert captured["scope"] == "user"


def test_web_flag_with_system_scope(monkeypatch):
    # The CLI's sudo check refuses non-root --system on POSIX. We mock
    # _euid to 0 so the system-scope branch is exercised, and patch the
    # server to avoid binding.
    captured = _patch_server(monkeypatch)
    monkeypatch.setattr(cli_setup, "_euid", lambda: 0)
    cli_setup.main(["--web", "--system"])
    assert captured["scope"] == "system"


def test_web_flag_reconfigure_passes_through(monkeypatch):
    captured = _patch_server(monkeypatch)
    cli_setup.main(["--web", "--reconfigure"])
    assert captured["reconfigure"] is True


def test_web_flag_skip_probes_passes_through(monkeypatch):
    captured = _patch_server(monkeypatch)
    cli_setup.main(["--web", "--skip-probes"])
    assert captured["skip_probes"] is True


def test_web_flag_output_overrides_target_path(monkeypatch, tmp_path):
    captured = _patch_server(monkeypatch)
    explicit = tmp_path / "explicit-lynceus.yaml"
    cli_setup.main(["--web", "--output", str(explicit)])
    assert captured["target_path"] == explicit


def test_web_flag_target_path_defaults_from_scope(monkeypatch):
    """Without --output, target_path follows scope's standard location.
    Mirrors what ``resolve_config_path`` returns for the same args."""
    captured = _patch_server(monkeypatch)
    cli_setup.main(["--web"])
    expected = cli_setup.resolve_config_path("user", None)
    assert captured["target_path"] == expected


def test_web_default_constants_pin_loopback_and_port_above_ui():
    # If someone changes the wizard's default port to collide with the
    # lynceus-ui default (8765), this test breaks loudly.
    assert wizard_server.DEFAULT_WIZARD_BIND == "127.0.0.1"
    assert wizard_server.DEFAULT_WIZARD_PORT == 8766
    from lynceus.config import Config
    assert wizard_server.DEFAULT_WIZARD_PORT != Config().ui_bind_port


def test_no_web_flag_falls_through_to_run_wizard(monkeypatch):
    """The legacy CLI flow must be unaffected when ``--web`` is absent.
    We patch ``run_wizard`` and confirm it's the dispatch target."""
    monkeypatch.setattr(cli_setup, "_euid", lambda: 1000)
    called: list = []

    def fake_run_wizard(args):
        called.append(args)
        return 0

    monkeypatch.setattr(cli_setup, "run_wizard", fake_run_wizard)
    # Also patch the web server so a stray dispatch would be visible
    # (asserted absent below).
    web_called: list = []
    monkeypatch.setattr(
        "lynceus.setup.web.server.run_wizard_server",
        lambda **kwargs: web_called.append(kwargs) or 0,
    )
    rc = cli_setup.main([])
    assert rc == 0
    assert len(called) == 1
    assert called[0].web is False
    assert web_called == []


def test_port_and_bind_default_to_none_in_parser():
    """When --web is absent, --port / --bind are not enforced. argparse
    should leave them as None so the wizard's defaults are used only when
    --web is set, not silently overriding the CLI flow's environment."""
    parser = cli_setup._build_parser()
    args = parser.parse_args([])
    assert args.web is False
    assert args.port is None
    assert args.bind is None
