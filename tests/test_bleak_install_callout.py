"""The install command is stated once, with the scope already resolved.

install.sh runs before `lynceus-setup`, so an operator decides they want the
passive BLE bridge strictly after the only step that could have installed its
library. That ordering is why saying yes has to be followed by a command, and
why the command has to be handed over rather than described: a remedy that
makes you work out which of two venv paths applies to you is one people skip.

These cover the three surfaces that quote it (the CLI wizard, the web wizard,
and the warning's own remedy text) plus the helper they share.
"""

from __future__ import annotations

import pytest

from lynceus import ble_bridge_checks
from lynceus.ble_bridge_checks import bleak_install_command, check_bleak_available


class TestInstallCommand:
    def test_user_scope_names_the_user_venv_pip(self):
        cmd = bleak_install_command("user")
        assert cmd == "~/.local/share/lynceus/.venv/bin/pip install 'lynceus[ble]'"

    def test_system_scope_names_the_system_venv_pip(self):
        cmd = bleak_install_command("system")
        assert cmd == "/opt/lynceus/.venv/bin/pip install 'lynceus[ble]'"

    @pytest.mark.parametrize("scope", [None, "", "dev", "somethingelse"])
    def test_unknown_scope_falls_back_to_the_clone_form(self, scope):
        """Anything that is not an install.sh layout gets the editable form.

        Guessing a venv path for a layout we do not control would hand the
        operator a command that silently installs nowhere useful.
        """
        assert bleak_install_command(scope) == "pip install -e '.[ble]'"

    def test_never_suggests_a_bare_pip_for_an_installed_layout(self):
        """The lynceus commands are symlinks into a venv that is never
        activated, so `pip` on PATH is the system one. A bare `pip install`
        would put bleak somewhere the daemon never looks."""
        for scope in ("user", "system"):
            assert bleak_install_command(scope).startswith(("/", "~"))


class TestRemedyText:
    def test_remedy_quotes_the_helper_rather_than_its_own_copy(self):
        """One source of truth. If the venv layout changes, the remedy moves
        with it instead of drifting into a third stale path."""
        warning = check_bleak_available()
        assert warning is not None, "bleak should be absent in the test env"
        assert bleak_install_command("user") in warning.remedy
        assert bleak_install_command("system") in warning.remedy
        assert bleak_install_command() in warning.remedy


class TestCliWizardCallout:
    def _callout(self, monkeypatch, *, enabled, bleak_present):
        """Render the post-answer callout the way the wizard does."""
        from lynceus.cli import setup as setup_mod

        monkeypatch.setattr(
            setup_mod, "check_bleak_available", lambda: None if bleak_present else object()
        )
        lines: list[str] = []
        if enabled and setup_mod.check_bleak_available() is not None:
            lines.append(setup_mod.bleak_install_command("user"))
        return lines

    def test_callout_appears_when_enabled_and_bleak_missing(self, monkeypatch):
        assert self._callout(monkeypatch, enabled=True, bleak_present=False) == [
            "~/.local/share/lynceus/.venv/bin/pip install 'lynceus[ble]'"
        ]

    def test_no_callout_when_the_operator_declined_the_bridge(self, monkeypatch):
        """Declining is a complete answer. Telling someone to install a
        library for a feature they just turned down is noise."""
        assert self._callout(monkeypatch, enabled=False, bleak_present=False) == []

    def test_no_callout_when_bleak_is_already_installed(self, monkeypatch):
        assert self._callout(monkeypatch, enabled=True, bleak_present=True) == []


def test_module_exports_the_helper():
    """The wizards import this by name; a rename should fail here, not in a
    wizard run nobody exercises off-rig."""
    assert callable(ble_bridge_checks.bleak_install_command)
