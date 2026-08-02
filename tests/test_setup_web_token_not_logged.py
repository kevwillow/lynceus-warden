"""The wizard's setup token must not reach uvicorn's access log.

The token rides in the query string, because that is how the operator gets it
from the terminal into a browser. uvicorn's access log writes the full request
line including the query string (``protocols/utils.py::get_path_with_query_string``
feeds ``logging.py``'s ``request_line``), so with ``access_log=True`` every
request would print ``GET /?token=<secret>`` to stdout. On a headless host that
lands in journald; under ``sudo ... | tee install.log`` it lands in a file that
outlives the run.

This mirrors the reasoning already applied to the ntfy topic in
``cli.setup``, which is redacted from the wizard summary for the same reason.

Regression test for the ``access_log=False`` change in
``setup/web/server.py::run_wizard_server``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import uvicorn

from lynceus.setup.web import server as server_mod


class _CapturedConfig:
    """Stands in for ``uvicorn.Config``, recording the kwargs it was built with."""

    last_kwargs: dict = {}

    def __init__(self, app, **kwargs):
        self.app = app
        type(self).last_kwargs = dict(kwargs)


class _NoopServer:
    """Stands in for ``uvicorn.Server``; ``run()`` returns without binding."""

    def __init__(self, config):
        self.config = config
        self.started = False
        self.should_exit = False
        self.ran = False

    def run(self):
        self.ran = True


@pytest.fixture
def wizard_run(monkeypatch, tmp_path):
    """Run ``run_wizard_server`` with uvicorn stubbed out, return (kwargs, stdout)."""
    monkeypatch.setattr(uvicorn, "Config", _CapturedConfig)
    monkeypatch.setattr(uvicorn, "Server", _NoopServer)

    def _run(capsys) -> tuple[dict, str]:
        rc = server_mod.run_wizard_server(
            host="127.0.0.1",
            port=8766,
            scope="user",
            target_path=Path(tmp_path) / "lynceus.yaml",
            no_browser=True,
        )
        assert rc == 0
        return _CapturedConfig.last_kwargs, capsys.readouterr().out

    return _run


def test_wizard_disables_uvicorn_access_log(wizard_run, capsys):
    """``access_log`` is False, so no request line carrying the token is emitted.

    Asserted on the uvicorn Config kwarg rather than on captured log output:
    the access logger is uvicorn's, configured at bind time, and this is the
    single switch that decides whether it ever writes a request line at all.
    """
    kwargs, _out = wizard_run(capsys)
    assert kwargs["access_log"] is False, (
        "the setup token is in the query string; enabling the access log "
        f"writes it to stdout on every request (kwargs={kwargs})"
    )


def test_wizard_still_prints_the_token_for_the_operator(wizard_run, capsys):
    """Guards the obvious wrong fix: suppressing the token everywhere.

    The operator cannot reach the wizard without it, so it must still appear
    on stdout exactly once as part of the browsable URL.
    """
    _kwargs, out = wizard_run(capsys)
    assert "?token=" in out
    token = out.split("?token=")[1].split()[0]
    assert len(token) > 20, f"token looks truncated: {token!r}"
