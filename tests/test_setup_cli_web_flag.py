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
    # Defang both preflights. These tests are about DISPATCH — which kwargs
    # reach run_wizard_server — and they invoke the default config path, so
    # without this they would fail on any machine that actually has a
    # ~/.config/lynceus/lynceus.yaml, and the scope check would additionally
    # diverge by platform. The preflights' real behaviour on the --web path is
    # pinned separately below, in the refuses/allows pair, which does NOT patch
    # them.
    monkeypatch.setattr(cli_setup, "preflight_existing", lambda *a, **k: None)
    monkeypatch.setattr(cli_setup, "preflight_scope", lambda *a, **k: None)
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


# ---------------------------------------------------------------------------
# The preflights on the --web path.
#
# main() dispatches --web before run_wizard(), and both preflight_existing and
# preflight_scope live inside _run_wizard_body, which --web never enters. So
# for one release the browser wizard would serve the whole flow and then
# overwrite an existing config unconditionally, while --reconfigure's help says
# "Without this flag the wizard refuses" and docs/DEPLOYMENT.md says every flag
# "works identically" under --web.
#
# These two do NOT use _patch_server's preflight defanging: they patch only the
# server, so the real preflight runs. The load-bearing assertion is that the
# server is never reached — refusing after binding a port and collecting the
# operator's answers would be no use.
# ---------------------------------------------------------------------------


def _patch_server_only(monkeypatch):
    """Like _patch_server but leaves both preflights real."""
    captured: dict = {}

    def fake_run_wizard_server(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(
        "lynceus.setup.web.server.run_wizard_server",
        fake_run_wizard_server,
    )
    monkeypatch.setattr(cli_setup, "_euid", lambda: 1000)
    return captured


def test_web_refuses_existing_config_without_reconfigure(monkeypatch, tmp_path, capsys):
    captured = _patch_server_only(monkeypatch)
    target = tmp_path / "lynceus.yaml"
    original = "kismet:\n  url: http://hand-edited-do-not-clobber\n"
    target.write_text(original, encoding="utf-8")

    rc = cli_setup.main(["--web", "--output", str(target)])

    assert rc == 2, "--web must refuse an existing config, as the CLI flow does"
    assert not captured, (
        "the wizard server must not start when the config exists: refusing only "
        "after the operator has filled in the whole flow is not refusing"
    )
    err = capsys.readouterr().err
    assert "already exists" in err
    assert "--reconfigure" in err
    assert target.read_text(encoding="utf-8") == original, "config was modified"


def test_web_allows_existing_config_with_reconfigure(monkeypatch, tmp_path):
    captured = _patch_server_only(monkeypatch)
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet:\n  url: http://replace-me\n", encoding="utf-8")

    rc = cli_setup.main(["--web", "--reconfigure", "--output", str(target)])

    assert rc == 0
    assert captured, "--reconfigure must let the wizard start"
    assert captured["reconfigure"] is True
    assert captured["target_path"] == target


def test_web_starts_when_no_config_exists_yet(monkeypatch, tmp_path):
    """The common first-run case must not be caught by the new gate."""
    captured = _patch_server_only(monkeypatch)
    target = tmp_path / "does-not-exist-yet" / "lynceus.yaml"

    rc = cli_setup.main(["--web", "--output", str(target)])

    assert rc == 0
    assert captured["target_path"] == target
