"""``lynceus-ui-passwd``, and the startup refusal it exists to satisfy.

⭐ The pair that matters here is ``remote_bind_refusal`` + the CLI: the refusal
is what stops authentication shipping switched off exactly where the exposure
is, and the CLI is the only way to satisfy it. A test suite that covered the
middleware but not this pair would be measuring a feature nobody can turn on.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
import yaml

from lynceus.cli.ui_passwd import main as passwd_main
from lynceus.config import Config
from lynceus.webui.auth import verify_password
from lynceus.webui.credentials import load_credentials
from lynceus.webui.server import remote_bind_refusal

PASSWORD = "a-perfectly-fine-passphrase"


def _write_config(tmp_path: Path, **overrides) -> Path:
    payload = {
        "kismet_url": "http://127.0.0.1:2501",
        "db_path": str(tmp_path / "state" / "lynceus.db"),
        **overrides,
    }
    path = tmp_path / "lynceus.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


# --- The startup refusal ------------------------------------------------------


def test_a_loopback_bind_never_refuses(tmp_path):
    config = Config(db_path=str(tmp_path / "s.db"))
    assert remote_bind_refusal(config, credentials_configured=False) == []
    assert remote_bind_refusal(config, credentials_configured=True) == []


def test_the_flag_alone_does_not_refuse(tmp_path):
    """``ui_allow_remote`` is a permission; the bind is the fact. Same rule the
    exposure warning follows, and it must not diverge."""
    config = Config(db_path=str(tmp_path / "s.db"), ui_allow_remote=True)
    assert remote_bind_refusal(config, credentials_configured=False) == []


def test_an_off_loopback_bind_without_a_password_refuses_and_names_the_command(tmp_path):
    config = Config(
        db_path=str(tmp_path / "s.db"), ui_bind_host="0.0.0.0", ui_allow_remote=True
    )
    text = "\n".join(remote_bind_refusal(config, credentials_configured=False))
    assert text, "an off-loopback bind with no password did not refuse"
    assert "REFUSES" in text
    # ⛔ It must print the way forward. A refusal that does not name the next
    # command is how an operator ends up deleting things to make it start.
    assert "lynceus-ui-passwd" in text
    assert f"ssh -L {config.ui_bind_port}:127.0.0.1:{config.ui_bind_port}" in text
    assert "0.0.0.0" in text


def test_an_off_loopback_bind_with_a_password_starts(tmp_path):
    """The control. Without it the assertion above is satisfied by a function
    that refuses everything."""
    config = Config(
        db_path=str(tmp_path / "s.db"), ui_bind_host="0.0.0.0", ui_allow_remote=True
    )
    assert remote_bind_refusal(config, credentials_configured=True) == []


def test_the_refusal_and_the_warning_agree_about_loopback(tmp_path):
    """Derived from LOOPBACK_HOSTS, never transcribed.

    Three readers now decide what "loopback" means: the config validator, the
    exposure warning and this refusal. Two of them disagreeing would mean the
    server refuses a bind it elsewhere calls safe, or starts on one it calls
    dangerous.
    """
    from lynceus.config import LOOPBACK_HOSTS
    from lynceus.webui.server import remote_exposure_warning

    assert LOOPBACK_HOSTS, "empty set would make every assertion below vacuous"
    for host in LOOPBACK_HOSTS:
        config = Config(db_path=str(tmp_path / f"{host}.db"), ui_bind_host=host)
        assert remote_bind_refusal(config, credentials_configured=False) == [], host
        assert remote_exposure_warning(config) == [], host

    wide = Config(
        db_path=str(tmp_path / "wide.db"), ui_bind_host="192.168.1.10", ui_allow_remote=True
    )
    assert remote_bind_refusal(wide, credentials_configured=False) != []
    assert remote_exposure_warning(wide) != []


# --- The CLI ------------------------------------------------------------------


def test_setting_a_password_writes_a_verifiable_hash(tmp_path, monkeypatch, capsys):
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr(
        "lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD
    )

    assert passwd_main(["--config", str(config_path)]) == 0

    cfg = Config(**yaml.safe_load(config_path.read_text()))
    creds = load_credentials(cfg.resolved_ui_auth_path())
    assert creds is not None
    assert verify_password(PASSWORD, creds.password_hash)
    # ⛔ The operator must be told the server does not pick this up live.
    assert "Restart" in capsys.readouterr().out


def test_the_written_file_is_not_world_readable(tmp_path, monkeypatch):
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)
    passwd_main(["--config", str(config_path)])

    cfg = Config(**yaml.safe_load(config_path.read_text()))
    mode = stat.S_IMODE(cfg.resolved_ui_auth_path().stat().st_mode)
    assert mode == 0o600, f"credentials file is {mode:04o}"


def test_mismatched_confirmation_writes_nothing(tmp_path, monkeypatch, capsys):
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: None)

    assert passwd_main(["--config", str(config_path)]) == 1
    cfg = Config(**yaml.safe_load(config_path.read_text()))
    assert not cfg.resolved_ui_auth_path().exists()
    assert "did not match" in capsys.readouterr().err


def test_a_short_password_is_refused_and_writes_nothing(tmp_path, monkeypatch, capsys):
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: "short")

    assert passwd_main(["--config", str(config_path)]) == 1
    cfg = Config(**yaml.safe_load(config_path.read_text()))
    assert not cfg.resolved_ui_auth_path().exists()
    assert "at least" in capsys.readouterr().err


def test_stdin_mode_reads_the_first_line(tmp_path, monkeypatch):
    """⚠️ The trailing newline matters. ``echo secret | cmd``, a here-string and
    a file all append one, and a password that silently gained a ``\\n`` would
    lock the operator out by a character they cannot see."""
    import io

    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))

    assert passwd_main(["--config", str(config_path), "--stdin"]) == 0
    cfg = Config(**yaml.safe_load(config_path.read_text()))
    creds = load_credentials(cfg.resolved_ui_auth_path())
    assert creds is not None
    assert verify_password(PASSWORD, creds.password_hash), (
        "the stored hash does not verify against the password without its newline"
    )


def test_stdin_mode_with_nothing_on_stdin_refuses(tmp_path, monkeypatch, capsys):
    import io

    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert passwd_main(["--config", str(config_path), "--stdin"]) == 1
    assert "no password on stdin" in capsys.readouterr().err


def test_prompting_with_no_tty_refuses_rather_than_hanging(tmp_path, monkeypatch, capsys):
    """A provisioning script that forgot ``--stdin`` must get an error, not a
    process that blocks forever waiting on a terminal that is not there."""
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert passwd_main(["--config", str(config_path)]) == 1
    assert "--stdin" in capsys.readouterr().err


def test_check_reports_absent_then_present(tmp_path, monkeypatch, capsys):
    config_path = _write_config(tmp_path)

    assert passwd_main(["--config", str(config_path), "--check"]) == 1
    assert "No web UI password is set" in capsys.readouterr().out

    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)
    passwd_main(["--config", str(config_path)])
    capsys.readouterr()

    assert passwd_main(["--config", str(config_path), "--check"]) == 0
    assert "A web UI password is set" in capsys.readouterr().out


def test_remove_deletes_the_file(tmp_path, monkeypatch, capsys):
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)
    passwd_main(["--config", str(config_path)])
    cfg = Config(**yaml.safe_load(config_path.read_text()))
    assert cfg.resolved_ui_auth_path().exists()
    capsys.readouterr()

    assert passwd_main(["--config", str(config_path), "--remove"]) == 0
    assert not cfg.resolved_ui_auth_path().exists()


def test_removing_on_an_off_loopback_bind_warns_that_the_ui_will_not_start(
    tmp_path, monkeypatch, capsys
):
    """⛔ Name the consequence when it is created, not in a document.

    Removing the password on an off-loopback host does not reopen the UI to the
    network — it stops ``lynceus-ui`` starting at all. An operator who learns
    that from a failed restart has been served badly by this command.
    """
    config_path = _write_config(tmp_path, ui_bind_host="0.0.0.0", ui_allow_remote=True)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)
    passwd_main(["--config", str(config_path)])
    capsys.readouterr()

    assert passwd_main(["--config", str(config_path), "--remove"]) == 0
    err = capsys.readouterr().err
    assert "REFUSE" in err
    assert "0.0.0.0" in err


def test_removing_on_loopback_says_nothing_alarming(tmp_path, monkeypatch, capsys):
    """The control: the warning above must be keyed on the bind, not printed
    unconditionally, or operators learn to ignore it."""
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)
    passwd_main(["--config", str(config_path)])
    capsys.readouterr()

    passwd_main(["--config", str(config_path), "--remove"])
    assert "REFUSE" not in capsys.readouterr().err


def test_check_and_remove_together_are_refused(tmp_path, capsys):
    config_path = _write_config(tmp_path)
    assert passwd_main(["--config", str(config_path), "--check", "--remove"]) == 1
    assert "mutually exclusive" in capsys.readouterr().err


def test_a_missing_config_is_a_clean_error_not_a_traceback(tmp_path, capsys):
    assert passwd_main(["--config", str(tmp_path / "nope.yaml")]) == 1
    assert "no such config file" in capsys.readouterr().err


def test_config_is_required(capsys):
    assert passwd_main([]) == 1
    assert "--config is required" in capsys.readouterr().err


def test_setting_a_password_twice_replaces_it(tmp_path, monkeypatch):
    """A change-password flow, which is the same command run again."""
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)

    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)
    passwd_main(["--config", str(config_path)])
    cfg = Config(**yaml.safe_load(config_path.read_text()))
    first = load_credentials(cfg.resolved_ui_auth_path()).password_hash

    monkeypatch.setattr(
        "lynceus.cli.ui_passwd._prompt_for_password", lambda: "a-different-passphrase"
    )
    passwd_main(["--config", str(config_path)])
    second = load_credentials(cfg.resolved_ui_auth_path()).password_hash

    assert first != second
    assert verify_password("a-different-passphrase", second)
    assert not verify_password(PASSWORD, second), "the old password still works"


def test_the_credentials_file_lands_in_the_state_dir_creating_it(tmp_path, monkeypatch):
    """``db_path``'s parent may not exist yet on a fresh install."""
    config_path = _write_config(tmp_path)
    state_dir = tmp_path / "state"
    assert not state_dir.exists()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)

    assert passwd_main(["--config", str(config_path)]) == 0
    assert (state_dir / "ui_auth.json").exists()


def test_the_file_is_json_a_human_can_read(tmp_path, monkeypatch):
    """It is operator-visible state. A binary blob would be one more thing that
    can only be understood by running the code that wrote it."""
    config_path = _write_config(tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("lynceus.cli.ui_passwd._prompt_for_password", lambda: PASSWORD)
    passwd_main(["--config", str(config_path)])

    cfg = Config(**yaml.safe_load(config_path.read_text()))
    payload = json.loads(cfg.resolved_ui_auth_path().read_text(encoding="utf-8"))
    assert set(payload) == {"version", "password_hash", "updated_at"}
    # ⛔ And the plaintext is nowhere in it.
    assert PASSWORD not in json.dumps(payload)


@pytest.mark.parametrize("flag", ["--check", "--remove"])
def test_read_only_and_destructive_modes_both_handle_a_missing_file(
    tmp_path, flag, capsys
):
    config_path = _write_config(tmp_path)
    rc = passwd_main(["--config", str(config_path), flag])
    # --check reports "not set" (1); --remove is idempotent (0). Neither
    # tracebacks, which is the property under test.
    assert rc in (0, 1)
    assert "Traceback" not in capsys.readouterr().err


# --- The server refuses rather than degrading ---------------------------------


def test_a_corrupt_credentials_file_stops_the_server(tmp_path, capsys):
    """⛔ The fail-open this feature exists to close, at the outermost layer.

    A credentials file can be corrupt for ordinary reasons — a disk full, a
    power cut mid-write. Treating that as "no password configured" would bring
    the UI up unauthenticated with nothing said, which is precisely the state
    an operator set a password to avoid.
    """
    from lynceus.webui.server import main as ui_main

    config_path = _write_config(tmp_path)
    cfg = Config(**yaml.safe_load(config_path.read_text()))
    auth_path = cfg.resolved_ui_auth_path()
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.write_text("{ this is not json", encoding="utf-8")

    rc = ui_main(["--config", str(config_path)])
    assert rc == 2, f"lynceus-ui returned {rc}, not the refusal exit code 2"
    err = capsys.readouterr().err
    assert "refusing to start" in err
    # It must name the file, or the operator cannot act on it.
    assert str(auth_path) in err
    # ⛔ And no traceback: this is an operator-facing condition, not a crash.
    assert "Traceback" not in err


def test_an_off_loopback_bind_without_a_password_exits_two(tmp_path, capsys):
    """The refusal reaches the real entry point, not just its helper.

    ⚠️ A helper that returns the right lines proves nothing if ``main`` never
    calls it, or calls it after uvicorn has already taken the port.
    """
    from lynceus.webui.server import main as ui_main

    config_path = _write_config(tmp_path, ui_bind_host="0.0.0.0", ui_allow_remote=True)
    rc = ui_main(["--config", str(config_path)])
    assert rc == 2, f"lynceus-ui returned {rc}, not the refusal exit code 2"
    err = capsys.readouterr().err
    assert "REFUSES to start" in err
    assert "lynceus-ui-passwd" in err
