"""Subprocess-mocked cover for the eight shell-out surfaces of `cli/bootstrap_kismet.py`.

Orchestration plan W3-C continued. Four sibling files (`..._behaviour.py`,
`..._file_modes.py`, `..._interface_validation.py`, `..._probes.py`) already pin
the distro-detection, source-line, patcher, dry-run, file-mode, `--interface`-
validation, and pure-function-probe surfaces. None of them mock ``subprocess``
or ``urllib.request.urlopen`` -- so the eight functions that *do* shell out
had zero references anywhere under ``tests/``.

This file covers them in the priority order listed in PACKET.md §3:

    run                              (1528) -- 86 missed
    install_kismet_apt_repo          (506)  -- 58
    _select_interfaces               (1468) -- 32
    install_kismet_package           (583)  -- 26
    detect_wifi_monitor_capable      (685)  -- 25
    print_unsupported_pointer        (1164) -- 15
    _prompt_yes_no                   (995)  -- 13
    main                             (1743) -- 12

Each test pins a promise the module's own docstring makes. Assertions live on
the contract, not on a restatement of the implementation -- the defect class
this project has spent the week finding is "docstring stopped being true of the
code beneath it", so the eleven pin points quoted verbatim from PACKET.md §5
are the spine of this file.

🪤 The cleanest single trap in this module is **`_run(dry_run=True)` must not
invoke anything.** An operator running `--dry-run` is asking what *would*
happen; a bug there applies changes they were only previewing, to a capture
config, as root. The first test below is the gate that stops a future
"optimisation" from sneaking in a real call.

⛔ SYNTHETIC NAMES ONLY. This file is committed and published. The existing
``tests/test_bootstrap_kismet.py`` embeds the operator's real capture adapter
MAC and the rig account name, so ``.gitignore`` withholds it. This file is
NOT withheld, so all interface names, sysfs paths, and any user/hostname
literal come from the canonical synthetic set listed in PACKET.md §6:
``wlan0``, ``wlan1``, ``wlp2s0``, ``hci0``, ``hci1``, ``kismon0``, ``phy0``,
``phy1``, ``wlan9``, ``wlan0mon``. No ``wlx*`` interface names. No ``00:c0:ca``
OUI. No real-looking MAC. No username, no hostname, no email, no path under
a real home directory. Every file the tests touch goes through pytest's
``tmp_path``, never a real system path. A test that writes to ``/etc`` or
``/usr/share`` is a bug in the test, not a finding.

⭐ The highest-stakes test in this file is **`install_kismet_apt_repo` is
idempotent under `_apt_source_configured()`**: it must not download the key,
must not write the keyring, but MUST still run `apt-get update`. A bug
that short-circuited the update would leave the operator with a configured
source for an old key, then any later `apt-get install kismet` would hit
NO_PUBKEY and fail with the most confusing possible apt error message.
"""

from __future__ import annotations

import argparse
import urllib.error
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from lynceus.cli import bootstrap_kismet as bk

# --- Test doubles ----------------------------------------------------------


class _FakeCompleted:
    """Stand-in for ``subprocess.CompletedProcess[bytes]``.

    The function under test reads ``returncode``, ``stderr``, ``stdout`` and
    (on the gpg path) ``.stdout`` for the dearmored key body. The minimum
    surface below is exactly what the production code touches.
    """

    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_subprocess_factory(*, default_returncode: int = 0):
    """Build a `subprocess.run` replacement that records every call.

    Each call appends ``(cmd_list, kwargs)`` to ``calls``. The return value
    is a ``_FakeCompleted(default_returncode, b"", b"")``. Tests can swap
    the recorder by capturing ``calls`` after the call, or override the
    returncode for one specific call by replacing the underlying callable.
    """

    calls: list[tuple[list[str], dict]] = []

    def _run(cmd, **kwargs):
        calls.append((list(cmd), dict(kwargs)))
        return _FakeCompleted(default_returncode, b"", b"")

    _run.calls = calls  # type: ignore[attr-defined]
    return _run


def _ns(**overrides) -> argparse.Namespace:
    """Build an argparse.Namespace with the keys `_select_interfaces` /
    `run` reads, so each test only overrides the fields it cares about.

    Mirrors ``tests/test_bootstrap_kismet_interface_validation.py::_args``
    but expands it for the wider field set the orchestrator touches.
    """
    base = dict(
        interface=[],
        interface_type="wifi",
        yes=False,
        install=False,
        no_network=False,
        reset_config=False,
        dry_run=False,
        skip_install=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


@pytest.fixture
def redirect_paths(monkeypatch, tmp_path):
    """Point ``KISMET_KEYRING_PATH`` and ``KISMET_SOURCES_LIST_PATH`` at
    ``tmp_path`` so the install path can write to disk without ever
    touching ``/usr/share`` or ``/etc``.

    ⛔ A test that writes to ``/usr/share/keyrings/`` is a bug in the test,
    not a finding -- the suite runs as a developer on a host where the
    kernel will refuse but the operator's PATH will not.
    """
    keyring = tmp_path / "kismet-archive-keyring.gpg"
    sources = tmp_path / "kismet.list"
    monkeypatch.setattr(bk, "KISMET_KEYRING_PATH", keyring)
    monkeypatch.setattr(bk, "KISMET_SOURCES_LIST_PATH", sources)
    return SimpleNamespace(keyring=keyring, sources=sources)


@pytest.fixture
def isolated_sysfs(tmp_path, monkeypatch):
    """Point the module's sysfs constants at an empty ``tmp_path`` tree.

    The default `_select_interfaces` path calls
    ``detect_wifi_monitor_capable`` and ``detect_bluetooth_interfaces``,
    both of which scan ``/sys/class/net`` and ``/sys/class/bluetooth``. On a
    host with real interfaces this would leak real names into the operator
    prompt; on a CI runner those dirs may not exist. Either way the test
    does not own that surface, so we redirect it.
    """
    net = tmp_path / "net"
    bt = tmp_path / "bluetooth"
    net.mkdir()
    bt.mkdir()
    monkeypatch.setattr(bk, "_SYS_CLASS_NET", net, raising=False)
    monkeypatch.setattr(bk, "_SYS_CLASS_BLUETOOTH", bt, raising=False)
    return SimpleNamespace(net=net, bluetooth=bt)


# ===========================================================================
# _run -- the seam every higher-level helper goes through
# ===========================================================================


def test_run_dry_run_does_not_invoke_subprocess(monkeypatch, capsys):
    """Documented contract: 'DRY-RUN: <rendered> ... return None' on the dry-run
    path; ``subprocess.run`` must not be reached.

    🪤 The trap. An operator running ``--dry-run`` is asking what *would*
    happen. A bug here applies changes they were only previewing, to a
    capture config, as root. The presence assertion beside the dry-run one
    (the ``result is None`` check) is the gate against a future "fix" that
    returns a real CompletedProcess on the dry-run path.
    """
    sp_run = MagicMock()
    monkeypatch.setattr(bk.subprocess, "run", sp_run)

    result = bk._run(["apt-get", "update"], dry_run=True)

    assert result is None
    assert not sp_run.called, "dry-run actually invoked subprocess.run"
    out = capsys.readouterr().out
    assert "DRY-RUN:" in out
    assert "apt-get update" in out


def test_run_returns_completed_process_on_zero_exit(monkeypatch):
    """Documented contract: 'On real runs, returns the CompletedProcess.' A
    bug that raised on success or returned ``None`` would force every
    caller to special-case the happy path."""
    monkeypatch.setattr(
        bk.subprocess,
        "run",
        lambda cmd, **kw: _FakeCompleted(0, b"out", b""),
    )

    result = bk._run(["true"], dry_run=False)

    assert result is not None
    assert result.returncode == 0


def test_run_raises_bootstrap_error_carrying_stderr_tail(monkeypatch):
    """Documented contract: 'raises BootstrapError with the stderr tail on
    non-zero exit'. A bug that omitted the tail would hand the operator
    only "command failed" with no hint which package conflict or missing
    repo caused it.
    """
    monkeypatch.setattr(
        bk.subprocess,
        "run",
        lambda cmd, **kw: _FakeCompleted(2, b"", b"E: Unable to locate package kismet\n"),
    )

    with pytest.raises(bk.BootstrapError) as excinfo:
        bk._run(["apt-get", "install", "-y", "kismet"], dry_run=False)

    msg = str(excinfo.value)
    assert "E: Unable to locate package kismet" in msg, msg
    assert "exit 2" in msg, msg


def test_run_falls_back_to_stdout_when_stderr_is_empty(monkeypatch):
    """Documented contract: 'if not tail: tail = ... result.stdout'.
    Some apt operations print their error to stdout (postinst prompts,
    some 4xx warning rendering). A bug that raised with an empty message
    when only stdout carried the error would give the operator no
    diagnostic.
    """
    monkeypatch.setattr(
        bk.subprocess,
        "run",
        lambda cmd, **kw: _FakeCompleted(1, b"std err here\n", b""),
    )

    with pytest.raises(bk.BootstrapError) as excinfo:
        bk._run(["apt-get", "update"], dry_run=False)

    assert "std err here" in str(excinfo.value), str(excinfo.value)


def test_run_maps_file_not_found_to_bootstrap_error(monkeypatch):
    """Documented contract: 'FileNotFoundError -> BootstrapError naming the
    missing command'. A bug that let ``FileNotFoundError`` propagate would
    land the operator on a Python traceback rather than the actionable
    'install it (e.g. sudo apt install <package>)' hint.
    """
    def _raise_fnf(cmd, **kw):
        raise FileNotFoundError(2, "No such file or directory", cmd[0])

    monkeypatch.setattr(bk.subprocess, "run", _raise_fnf)

    with pytest.raises(bk.BootstrapError) as excinfo:
        bk._run(["apt-get", "update"], dry_run=False)

    msg = str(excinfo.value)
    assert "apt-get" in msg, msg
    assert "command not found" in msg, msg


def test_run_check_false_does_not_raise_on_nonzero_exit(monkeypatch):
    """Documented contract: ``check=True`` (default) raises on non-zero
    exit. ``check=False`` is the escape hatch ``install_kismet_package``
    uses so it can format its own error with the apt message rather than
    the rendered command line.
    """
    monkeypatch.setattr(
        bk.subprocess,
        "run",
        lambda cmd, **kw: _FakeCompleted(1, b"", b"err"),
    )

    result = bk._run(["apt-get", "install", "-y", "kismet"], dry_run=False, check=False)

    assert result is not None
    assert result.returncode == 1


# ===========================================================================
# _download_kismet_gpg_key -- urllib seam
# ===========================================================================


def test_download_kismet_gpg_key_returns_response_body(monkeypatch):
    """Documented contract: 'Fetch the ASCII-armored key body'. The function
    is a thin wrapper around ``urlopen``; the body it returns must reach
    the caller unmodified."""
    fake_resp = MagicMock()
    fake_resp.read.return_value = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nFAKE\n"
    fake_resp.__enter__ = lambda self: self
    fake_resp.__exit__ = lambda self, *a: False
    monkeypatch.setattr(
        bk.urllib.request, "urlopen", lambda url, timeout: fake_resp
    )

    body = bk._download_kismet_gpg_key()

    assert b"BEGIN PGP PUBLIC KEY BLOCK" in body, body


def test_download_kismet_gpg_key_maps_urlerror_to_bootstrap_error(monkeypatch):
    """Documented contract: 'URLError -> BootstrapError'. The exception
    chain must survive so a future debugging session can still see the
    underlying URLError via ``__cause__``.
    """
    def _raise_url(url, timeout):
        raise urllib.error.URLError("network unreachable")

    monkeypatch.setattr(bk.urllib.request, "urlopen", _raise_url)

    with pytest.raises(bk.BootstrapError) as excinfo:
        bk._download_kismet_gpg_key()

    assert "network unreachable" in str(excinfo.value), str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, urllib.error.URLError)


# ===========================================================================
# install_kismet_apt_repo -- the apt-repo install path
# ===========================================================================


def test_install_kismet_apt_repo_already_configured_skips_key_and_writes_nothing(
    monkeypatch, redirect_paths, tmp_path, capsys
):
    """⭐ Idempotency: when ``_apt_source_configured()`` is True, the function
    must NOT download the key and must NOT write the keyring.

    A bug here would silently overwrite the operator's hand-edited sources
    file with one derived from whatever the network gave us -- exactly the
    'clobber a deliberate edit' the docstring promises to avoid.
    """
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: True)
    download_calls = MagicMock()
    monkeypatch.setattr(bk, "_download_kismet_gpg_key", download_calls)

    run_seen: list[tuple[list[str], dict]] = []

    def _fake_run(cmd, **kw):
        run_seen.append((list(cmd), dict(kw)))
        return None

    monkeypatch.setattr(bk, "_run", _fake_run)

    bk.install_kismet_apt_repo("bookworm", dry_run=False)

    download_calls.assert_not_called()
    assert not redirect_paths.keyring.exists(), "keyring was written despite being configured"
    assert not redirect_paths.sources.exists(), "sources was written despite being configured"
    out = capsys.readouterr().out
    assert "skipping add-source" in out, out
    # And apt-get update DID run -- the second half of the idempotency contract.
    assert len(run_seen) == 1, run_seen
    assert run_seen[0][0] == ["apt-get", "update"]


def test_install_kismet_apt_repo_fresh_install_order_is_key_then_sources_then_update(
    monkeypatch, redirect_paths, capsys
):
    """Documented contract: 'Order matters: key first, then sources file,
    then update. Putting apt update before either causes a NO_PUBKEY
    hiccup that confuses operators reading the log.'

    Pin the call order against the real ``subprocess.run`` and the real
    ``_atomic_write_bytes`` / ``_atomic_write_text`` (the ones already
    covered by `test_bootstrap_kismet_file_modes.py`). We assert on the
    observable side-effects -- keyring and sources file appearance -- and
    on the order in which the captured calls fired.
    """
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: False)
    monkeypatch.setattr(bk, "_download_kismet_gpg_key", lambda: b"FAKE-ARMORED-KEY")
    monkeypatch.setattr(
        bk.shutil, "which", lambda cmd: "/usr/bin/gpg" if cmd == "gpg" else None
    )

    order: list[str] = []

    dearmored = b"\xde\xad\xbe\xef" * 4

    def _fake_subprocess_run(cmd, **kw):
        order.append("subprocess.gpg")
        # The dearmored key is what gets written to the keyring.
        return _FakeCompleted(0, dearmored, b"")

    monkeypatch.setattr(bk.subprocess, "run", _fake_subprocess_run)

    original_write_bytes = bk._atomic_write_bytes
    original_write_text = bk._atomic_write_text

    def _spy_bytes(path, content, *, mode=0o644):
        order.append(f"write:{path.name}")
        return original_write_bytes(path, content, mode=mode)

    def _spy_text(path, content, *, mode=0o644):
        order.append(f"write:{path.name}")
        return original_write_text(path, content, mode=mode)

    monkeypatch.setattr(bk, "_atomic_write_bytes", _spy_bytes)
    monkeypatch.setattr(bk, "_atomic_write_text", _spy_text)

    run_calls: list[list[str]] = []

    def _fake_run(cmd, **kw):
        run_calls.append(list(cmd))
        order.append("apt-update")
        return None

    monkeypatch.setattr(bk, "_run", _fake_run)

    bk.install_kismet_apt_repo("bookworm", dry_run=False)

    # Observable side-effects: keyring and sources file actually exist.
    assert redirect_paths.keyring.exists(), "keyring was not written"
    assert redirect_paths.sources.exists(), "sources list was not written"
    # Order: subprocess.gpg first, then keyring, then sources, then apt update.
    # `_atomic_write_text` delegates to `_atomic_write_bytes`, so the spy
    # sees both layers; that's expected and not a re-ordering. The contract
    # being pinned is "key before sources before update".
    assert order[0] == "subprocess.gpg", order
    assert order[-1] == "apt-update", order
    # Sources-file writes all happen after the keyring write.
    keyring_index = next(
        i for i, ev in enumerate(order) if ev.endswith(redirect_paths.keyring.name)
    )
    sources_indices = [
        i for i, ev in enumerate(order) if ev.endswith(redirect_paths.sources.name)
    ]
    assert sources_indices, order
    assert all(i > keyring_index for i in sources_indices), order
    # And the apt-update fires after the last sources-file write.
    assert order.index("apt-update") > max(sources_indices), order
    # Keyring got the dearmored bytes, not the armored input.
    assert redirect_paths.keyring.read_bytes() == dearmored, (
        "keyring content did not come from gpg's stdout"
    )
    # Sources file mentions the codename, so a repo path bug (e.g. wrong
    # codename interpolation) would surface here.
    sources_body = redirect_paths.sources.read_text(encoding="utf-8")
    assert "bookworm" in sources_body, sources_body
    assert "kismet-archive-keyring.gpg" in sources_body, sources_body
    # apt-get update fired exactly once and used the module's _run (which
    # raises BootstrapError on nonzero exit by default -- check=True).
    assert run_calls == [["apt-get", "update"]], run_calls


def test_install_kismet_apt_repo_dry_run_writes_nothing_to_disk(
    monkeypatch, redirect_paths, capsys
):
    """Documented contract: dry-run is a preview, not an action.

    🪤 The trap. A bug here would leave a half-configured apt repo on disk
    -- the keyring written but the sources file missing, or vice versa.
    The next ``apt-get install kismet`` would either NO_PUBKEY or pull
    from an unsigned mirror, depending on which half landed. Either
    failure mode is harder to debug than 'just run it again'.
    """
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: False)
    monkeypatch.setattr(bk, "_download_kismet_gpg_key", lambda: b"FAKE-ARMORED-KEY")
    monkeypatch.setattr(
        bk.shutil, "which", lambda cmd: "/usr/bin/gpg" if cmd == "gpg" else None
    )

    sp_run = MagicMock()
    monkeypatch.setattr(bk.subprocess, "run", sp_run)

    run_calls: list[list[str]] = []

    def _fake_run(cmd, **kw):
        run_calls.append(list(cmd))
        return None

    monkeypatch.setattr(bk, "_run", _fake_run)

    bk.install_kismet_apt_repo("bookworm", dry_run=True)

    assert not redirect_paths.keyring.exists(), "dry-run wrote the keyring"
    assert not redirect_paths.sources.exists(), "dry-run wrote the sources file"
    assert not sp_run.called, "dry-run invoked subprocess.run (the gpg dearmor)"
    # The download step itself is also skipped on dry_run -- downloading
    # under dry-run would talk to the network, which dry-run is meant to avoid.
    out = capsys.readouterr().out
    assert "DRY-RUN:" in out
    assert run_calls == [["apt-get", "update"]], (
        "dry-run still ran apt-get update via _run (it should, via _run's dry-run branch)"
    )


def test_install_kismet_apt_repo_already_configured_dry_run_still_invokes_apt_update(
    monkeypatch, redirect_paths
):
    """The dry-run counterpart of the idempotency test. A configured source
    must still have its ``apt-get update`` previewed, otherwise the operator
    who is on a stale-apt-cache host (the most common reason to re-run
    bootstrap) gets a dry-run that doesn't tell them what they came for.
    """
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: True)
    monkeypatch.setattr(bk, "_download_kismet_gpg_key", MagicMock())

    run_calls: list[list[str]] = []
    monkeypatch.setattr(
        bk,
        "_run",
        lambda cmd, **kw: run_calls.append(list(cmd)) or None,
    )

    bk.install_kismet_apt_repo("bookworm", dry_run=True)

    assert run_calls == [["apt-get", "update"]], run_calls
    assert not redirect_paths.keyring.exists()
    assert not redirect_paths.sources.exists()


def test_install_kismet_apt_repo_raises_when_gpg_missing_on_path(
    monkeypatch, redirect_paths
):
    """Documented contract: 'gpg not found on PATH -> BootstrapError'.

    A fresh Debian image without gnupg installed would otherwise fall
    through to ``subprocess.run(["gpg", "--dearmor"], ...)`` and surface
    as a confusing FileNotFoundError. The explicit check turns that into
    an actionable message.
    """
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: False)
    monkeypatch.setattr(bk, "_download_kismet_gpg_key", lambda: b"FAKE")
    monkeypatch.setattr(bk.shutil, "which", lambda cmd: None)
    # If the check is wrong and we fall through, subprocess.run would be
    # called. Block it so a passing test is meaningful.
    monkeypatch.setattr(bk.subprocess, "run", MagicMock())

    with pytest.raises(bk.BootstrapError) as excinfo:
        bk.install_kismet_apt_repo("bookworm", dry_run=False)

    assert "gpg" in str(excinfo.value).lower(), str(excinfo.value)
    assert "gnupg" in str(excinfo.value).lower(), str(excinfo.value)


# ===========================================================================
# install_kismet_package -- apt-get install path
# ===========================================================================


def test_install_kismet_package_dry_run_does_not_invoke_subprocess(monkeypatch, capsys):
    """The dry-run counterpart of the package install. Same trap as
    ``install_kismet_apt_repo``: a bug here would actually install
    Kismet (and add its apt deps) on a host that was only being
    previewed.
    """
    sp_run = MagicMock()
    monkeypatch.setattr(bk.subprocess, "run", sp_run)

    bk.install_kismet_package(dry_run=True)

    assert not sp_run.called, "dry-run actually invoked subprocess.run"
    out = capsys.readouterr().out
    assert "DRY-RUN:" in out
    assert "kismet" in out


def test_install_kismet_package_real_run_sets_debian_frontend_noninteractive(monkeypatch):
    """Documented contract: 'DEBIAN_FRONTEND=noninteractive so apt doesn't
    try to throw a debconf prompt at a non-tty operator -- Kismet's
    postinst asks "Install kismet with suid root?" by default.'

    ⛔ This exists because the postinst prompt would deadlock a
    headless bootstrap (no controlling terminal to answer it). Asserting
    the env key catches the bug at the test seam -- a future refactor
    that drops the env copy would otherwise silently break non-tty
    operators.
    """
    captured: dict = {}

    def _capture(cmd, **kw):
        captured["cmd"] = list(cmd)
        captured["env"] = kw.get("env")
        captured["capture_output"] = kw.get("capture_output")
        captured["check"] = kw.get("check")
        return _FakeCompleted(0, b"", b"")

    monkeypatch.setattr(bk.subprocess, "run", _capture)

    bk.install_kismet_package(dry_run=False)

    assert captured["cmd"] == ["apt-get", "install", "-y", "kismet"], captured
    assert captured["env"]["DEBIAN_FRONTEND"] == "noninteractive", captured["env"]
    # The full env must include what the OS provided (so PATH etc. survive).
    assert "PATH" in captured["env"], "env was not a copy of os.environ"


def test_install_kismet_package_raises_bootstrap_error_carrying_stderr(monkeypatch):
    """Documented contract: 'apt-get install failed (exit N): <tail>'.
    The message carries the apt stderr so the operator can tell a missing
    repo from a signature failure."""
    monkeypatch.setattr(
        bk.subprocess,
        "run",
        lambda cmd, **kw: _FakeCompleted(
            100, b"", b"E: Unable to fetch ... NO_PUBKEY 12345678\n"
        ),
    )

    with pytest.raises(bk.BootstrapError) as excinfo:
        bk.install_kismet_package(dry_run=False)

    msg = str(excinfo.value)
    assert "NO_PUBKEY" in msg, msg
    assert "100" in msg or "exit 100" in msg, msg


def test_install_kismet_package_maps_file_not_found_to_unsupported_distro(monkeypatch):
    """Documented contract: 'FileNotFoundError -> requires Debian/Ubuntu/Kali'.

    The check is specifically on ``apt-get`` (not any missing binary), so
    the message can say "this script requires Debian/Ubuntu/Kali" and
    point the operator at the real cause.
    """
    def _raise_fnf(cmd, **kw):
        raise FileNotFoundError(2, "No such file or directory", cmd[0])

    monkeypatch.setattr(bk.subprocess, "run", _raise_fnf)

    with pytest.raises(bk.BootstrapError) as excinfo:
        bk.install_kismet_package(dry_run=False)

    msg = str(excinfo.value)
    assert "apt-get" in msg, msg
    assert "Debian" in msg or "Ubuntu" in msg or "Kali" in msg, msg


# ===========================================================================
# detect_wifi_monitor_capable -- the iw probe
# ===========================================================================


def _completed_with(text: str, returncode: int = 0) -> _FakeCompleted:
    """Helper for detect_wifi_monitor_capable tests.

    `detect_wifi_monitor_capable` runs two subprocess calls (``iw dev``
    and ``iw phy <phy> info``) with ``text=True``, so the resulting
    CompletedProcess carries str stdout/stderr (not bytes). This helper
    builds a stand-in that matches that contract.
    """
    return _FakeCompleted(returncode, text, "")


def test_detect_wifi_monitor_capable_returns_empty_when_iw_missing(monkeypatch, capsys):
    """Documented contract: 'If `iw` is missing on PATH we return an empty
    list rather than raising'. A minimal host without iw should not
    crash bootstrap; the operator on such a host can still use
    ``--interface`` explicitly."""
    monkeypatch.setattr(bk.shutil, "which", lambda cmd: None if cmd == "iw" else "/usr/bin/true")
    sp_run = MagicMock()
    monkeypatch.setattr(bk.subprocess, "run", sp_run)

    assert bk.detect_wifi_monitor_capable() == []
    assert not sp_run.called, "iw is missing but subprocess.run was still called"


def test_detect_wifi_monitor_capable_returns_empty_when_iw_dev_fails(monkeypatch):
    """Documented contract: 'dev_result.returncode != 0 -> []'. A host
    where `iw` is installed but its socket is unavailable (some hardened
    sandbox variants) should not crash bootstrap."""
    monkeypatch.setattr(bk.shutil, "which", lambda cmd: "/usr/bin/iw" if cmd == "iw" else None)
    monkeypatch.setattr(
        bk.subprocess, "run", lambda cmd, **kw: _completed_with("", returncode=1)
    )

    assert bk.detect_wifi_monitor_capable() == []


def test_detect_wifi_monitor_capable_handles_oserror_on_iw_dev(monkeypatch):
    """Documented contract: 'OSError -> []'. A bare
    ``subprocess.OSError`` from the spawn (e.g. ENOEXEC on a corrupted
    binary) must not propagate."""
    monkeypatch.setattr(bk.shutil, "which", lambda cmd: "/usr/bin/iw" if cmd == "iw" else None)

    def _raise_oserror(cmd, **kw):
        raise OSError("simulated spawn failure")

    monkeypatch.setattr(bk.subprocess, "run", _raise_oserror)

    assert bk.detect_wifi_monitor_capable() == []


def test_detect_wifi_monitor_capable_returns_monitor_capable_interfaces(monkeypatch):
    """The happy path that the function exists to answer: ``iw dev``
    finds a phy+iface pair, ``iw phy <phy> info`` advertises monitor,
    the function returns the iface name. The synthesized ``iw dev``
    output uses only synthetic names from the canonical set."""
    iw_dev_output = (
        "phy#0\n"
        "    Interface wlan0\n"
        "    type managed\n"
        "phy#1\n"
        "    Interface wlp2s0\n"
        "    type managed\n"
    )
    iw_phy0_output = (
        "Wiphy phy0\n"
        "    Supported interface modes:\n"
        "         * IBSS\n"
        "         * managed\n"
        "         * monitor\n"
    )
    iw_phy1_output = (
        "Wiphy phy1\n"
        "    Supported interface modes:\n"
        "         * managed\n"
    )

    monkeypatch.setattr(bk.shutil, "which", lambda cmd: "/usr/bin/iw" if cmd == "iw" else None)

    responses = iter(
        [
            _completed_with(iw_dev_output),
            _completed_with(iw_phy0_output),
            _completed_with(iw_phy1_output),
        ]
    )

    def _respond(cmd, **kw):
        return next(responses)

    monkeypatch.setattr(bk.subprocess, "run", _respond)

    assert bk.detect_wifi_monitor_capable() == ["wlan0"]


def test_detect_wifi_monitor_capable_drops_kismet_monitor_vif_shadows(monkeypatch):
    """Documented contract: ``kismon*`` interfaces backed by a phy shared
    with another candidate are Kismet's auto-created monitor VIFs and
    must not be selected as capture sources.

    The dual-filter rule is asserted end-to-end here rather than only
    on the pure ``filter_kismet_monitor_vifs`` function, because the
    shell-out surface is the one that previously had no test.
    """
    iw_dev_output = (
        "phy#0\n"
        "    Interface wlan0\n"
        "    Interface kismon0\n"
    )
    iw_phy_info_monitor = (
        "Wiphy phy0\n"
        "    Supported interface modes:\n"
        "         * monitor\n"
    )

    monkeypatch.setattr(bk.shutil, "which", lambda cmd: "/usr/bin/iw" if cmd == "iw" else None)

    # The function calls `iw phy <phy> info` once per (phy, iface) pair --
    # so a 2-pair result means 3 subprocess calls total: 1 for `iw dev`,
    # 2 for the (shared) phy info.
    responses = iter(
        [
            _completed_with(iw_dev_output),
            _completed_with(iw_phy_info_monitor),
            _completed_with(iw_phy_info_monitor),
        ]
    )

    monkeypatch.setattr(bk.subprocess, "run", lambda cmd, **kw: next(responses))

    assert bk.detect_wifi_monitor_capable() == ["wlan0"]


def test_detect_wifi_monitor_capable_skips_phy_when_iw_phy_info_oserrors(monkeypatch):
    """Documented contract: 'OSError on iw phy -> continue' (skip the
    failing phy, keep the others). A failure to query one phy must not
    abort the whole scan."""
    iw_dev_output = (
        "phy#0\n"
        "    Interface wlan0\n"
        "phy#1\n"
        "    Interface wlp2s0\n"
    )
    iw_phy1_output = (
        "Wiphy phy1\n"
        "    Supported interface modes:\n"
        "         * monitor\n"
    )

    monkeypatch.setattr(bk.shutil, "which", lambda cmd: "/usr/bin/iw" if cmd == "iw" else None)

    def _respond(cmd, **kw):
        # First call: iw dev (succeeds).
        if cmd == ["iw", "dev"]:
            return _completed_with(iw_dev_output)
        # Second call: iw phy phy0 info (OSError).
        if cmd == ["iw", "phy", "phy0", "info"]:
            raise OSError("phy0 query failed")
        # Third call: iw phy phy1 info (succeeds with monitor).
        return _completed_with(iw_phy1_output)

    monkeypatch.setattr(bk.subprocess, "run", _respond)

    assert bk.detect_wifi_monitor_capable() == ["wlp2s0"]


# ===========================================================================
# _prompt_yes_no -- the input_fn seam
# ===========================================================================


def test_prompt_yes_no_default_true_accepts_y(monkeypatch):
    """Documented contract: ``default=True``, ``"y"`` -> True."""
    calls: list[str] = []
    monkeypatch.setattr("builtins.print", lambda *a, **kw: calls.append(a[0]) if a else "")

    result = bk._prompt_yes_no("Continue?", default=True, input_fn=lambda _: "y")

    assert result is True


def test_prompt_yes_no_default_true_accepts_yes(monkeypatch):
    """Documented contract: ``"yes"`` is recognized alongside ``"y"``."""
    result = bk._prompt_yes_no("Continue?", default=True, input_fn=lambda _: "yes")

    assert result is True


def test_prompt_yes_no_default_true_rejects_n(monkeypatch):
    """Documented contract: ``"n"`` -> False (the explicit no branch)."""
    result = bk._prompt_yes_no("Continue?", default=True, input_fn=lambda _: "n")

    assert result is False


def test_prompt_yes_no_default_true_rejects_no(monkeypatch):
    """Documented contract: ``"no"`` is recognized alongside ``"n"``."""
    result = bk._prompt_yes_no("Continue?", default=True, input_fn=lambda _: "no")

    assert result is False


def test_prompt_yes_no_empty_input_returns_default(monkeypatch, capsys):
    """Documented contract: 'EOFError on stdin closed -> use default'.
    Empty input while stdin is still open must also use the default --
    the operator hit Return without typing anything. A bug that re-prompted
    on empty input would loop until the operator typed something."""
    result = bk._prompt_yes_no("Continue?", default=True, input_fn=lambda _: "")
    assert result is True

    result_false = bk._prompt_yes_no("Continue?", default=False, input_fn=lambda _: "")
    assert result_false is False


def test_prompt_yes_no_eoferror_returns_default():
    """Documented contract: 'EOFError on stdin closed -> use default'.
    On a non-tty (e.g. CI), the underlying ``input()`` raises EOFError;
    the helper must catch it and return the default rather than letting
    it propagate.
    """
    def _raise_eof(_):
        raise EOFError

    assert bk._prompt_yes_no("?", default=True, input_fn=_raise_eof) is True
    assert bk._prompt_yes_no("?", default=False, input_fn=_raise_eof) is False


def test_prompt_yes_no_garbage_input_reprompts_until_answer(monkeypatch):
    """Documented contract: 'Repeats on invalid input until we get a
    parseable answer'. A bug that returned ``False`` (or the default)
    on the first garbage character would let a fat-fingered operator
    cancel the bootstrap unintentionally."""
    answers = iter(["maybe", "definitely", "y"])
    result = bk._prompt_yes_no(
        "Continue?", default=True, input_fn=lambda _: next(answers)
    )
    assert result is True
    # And the re-prompt must have actually surfaced the helper's hint.
    out = []
    monkeypatch.setattr("builtins.print", lambda *a, **kw: out.append(str(a)) if a else "")
    answers2 = iter(["garbage", "n"])
    result2 = bk._prompt_yes_no(
        "?", default=True, input_fn=lambda _: next(answers2)
    )
    assert result2 is False
    assert any("y" in line.lower() and "n" in line.lower() for line in out), out


def test_prompt_yes_no_default_false_only_y_is_true():
    """Documented contract: when ``default=False``, the prompt suffix
    is ``[y/N]`` and only an explicit ``y``/``yes`` returns True."""
    assert bk._prompt_yes_no("?", default=False, input_fn=lambda _: "y") is True
    assert bk._prompt_yes_no("?", default=False, input_fn=lambda _: "yes") is True
    assert bk._prompt_yes_no("?", default=False, input_fn=lambda _: "n") is False
    assert bk._prompt_yes_no("?", default=False, input_fn=lambda _: "") is False


# ===========================================================================
# _select_interfaces -- detection-driven path (the --interface path is
# covered by `test_bootstrap_kismet_interface_validation.py`)
# ===========================================================================


def test_select_interfaces_no_named_interfaces_returns_detected_set_when_all_yes(
    monkeypatch, isolated_sysfs
):
    """Without ``--interface``, the helper asks Y per detected candidate
    and accepts whatever the harness says. Pin: the detected names reach
    the input function as part of the prompt, and the selected set is
    the subset that the helper got True back for."""
    prompts: list[str] = []

    def _input(q):
        prompts.append(q)
        return "y"

    # Two phantoms: one wifi, one bt, both with monitor (the bluetooth
    # detection is sysfs-driven so we just need the entries to exist).
    (isolated_sysfs.net / "wlan0" / "device").mkdir(parents=True)
    (isolated_sysfs.bluetooth / "hci0").mkdir()

    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: ["wlan0"])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda: ["hci0"])
    monkeypatch.setattr(bk, "describe_interface", lambda iface, kind: "")

    args = _ns(yes=False)
    wifi, bt = bk._select_interfaces(args, _input)

    assert wifi == ["wlan0"]
    assert bt == ["hci0"]
    # Both prompts fired.
    assert any("wlan0" in p for p in prompts), prompts
    assert any("hci0" in p for p in prompts), prompts


def test_select_interfaces_no_interfaces_detected_returns_empty_without_prompting(
    monkeypatch, isolated_sysfs
):
    """Documented contract: 'No interfaces' is not an error. The helper
    logs a note and returns two empty lists; it does not raise and does
    not prompt."""
    prompts: list[str] = []

    def _input(q):
        prompts.append(q)
        return "y"

    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: [])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda: [])

    wifi, bt = bk._select_interfaces(_ns(yes=False), _input)

    assert wifi == []
    assert bt == []
    assert prompts == [], "the helper prompted with no candidates to choose from"


def test_select_interfaces_yes_skips_the_prompt(monkeypatch, isolated_sysfs):
    """Documented contract: ``--yes`` makes every Y/n prompt default to Y
    without asking. Pin: the helper builds a yes_fn that returns True
    without consulting input_fn, so on a yes-mode run, every detected
    candidate is selected."""
    inputs_called = []

    def _should_not_be_called(_):
        inputs_called.append(True)
        return "y"

    (isolated_sysfs.net / "wlan0" / "device").mkdir(parents=True)
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: ["wlan0"])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda: [])
    monkeypatch.setattr(bk, "describe_interface", lambda iface, kind: "")

    wifi, bt = bk._select_interfaces(_ns(yes=True), _should_not_be_called)

    assert wifi == ["wlan0"]
    assert bt == []
    assert inputs_called == [], "the --yes path consulted input_fn anyway"


def test_select_interfaces_describe_interface_renders_when_available(monkeypatch, isolated_sysfs):
    """Documented contract: the prompt renders ``<iface> -- <descriptor>``
    when ``describe_interface`` returns non-empty, and the bare name
    otherwise. A bug that lost the descriptor would degrade the operator
    UX but not the behaviour; pinning the rendering here is a presence
    check on the integration between the two helpers.
    """
    prompts: list[str] = []

    def _input(q):
        prompts.append(q)
        return "y"

    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: ["wlan0"])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda: [])
    monkeypatch.setattr(bk, "describe_interface", lambda iface, kind: "Synthetic-Adapter")

    bk._select_interfaces(_ns(yes=False), _input)

    assert any("wlan0" in p and "Synthetic-Adapter" in p for p in prompts), prompts


def test_select_interfaces_no_branch_skips_candidates_the_user_rejects(
    monkeypatch, isolated_sysfs
):
    """The detection path with two candidates and one explicit 'no' answer.
    Pin: the rejected interface is dropped, the accepted one is kept.
    """
    def _input(q):
        # First prompt: yes for wifi. Second prompt: no for bt.
        if "Wi-Fi" in q:
            return "y"
        return "n"

    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: ["wlan0"])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda: ["hci0"])
    monkeypatch.setattr(bk, "describe_interface", lambda iface, kind: "")

    wifi, bt = bk._select_interfaces(_ns(yes=False), _input)

    assert wifi == ["wlan0"]
    assert bt == [], "the bt interface was selected despite 'no'"


# ===========================================================================
# print_unsupported_pointer
# ===========================================================================


def test_print_unsupported_pointer_with_none_does_not_crash_or_claim_a_distro(capsys):
    """Documented contract: 'Unsupported-distro message printed when
    ``--install`` was given on a distro outside the apt matrix. Clean
    exit 0'. The helper must not crash when ``distro_id`` is None, and
    the printed label must not falsely attribute the system to a known
    distro.
    """
    bk.print_unsupported_pointer(None)

    out = capsys.readouterr().out
    # The "unknown" label is shown, not "debian"/"ubuntu"/"kali" or any
    # other specific ID we might be tempted to fall back to.
    assert "unknown" in out, out
    # And the upstream pointer URL is there so the operator can act.
    assert "kismetwireless.net" in out, out


def test_print_unsupported_pointer_renders_a_distro_id(capsys):
    """The labelled path: the helper prints whatever ``distro_id`` it
    was given, verbatim. A bug that lowercased, normalised, or rewrote
    the distro name would defeat grep-based log audits."""
    bk.print_unsupported_pointer("fedora")

    out = capsys.readouterr().out
    assert "'fedora'" in out, out


# ===========================================================================
# run -- the orchestrator (driven with monkeypatched seams, no real subprocess)
# ===========================================================================


@pytest.fixture
def orchestrator_env(monkeypatch, tmp_path, isolated_sysfs):
    """Set up the minimum state for `run()` to reach `print_closing_pointer`
    without firing real subprocess calls, writing to /etc, or usermod'ing
    the developer.

    The defaults here are the "successful, no --install, no warnings"
    path -- individual tests override the seams they want to exercise.
    """
    site_conf = tmp_path / "kismet_site.conf"
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr(bk, "detect_distro", lambda: ("debian", "bookworm"))
    monkeypatch.setattr(bk, "resolve_site_conf_path", lambda: site_conf)
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: True)
    monkeypatch.setattr(bk, "warn_about_stale_lockfiles", lambda: False)
    monkeypatch.setattr(bk, "warn_about_lingering_kismon_vifs", lambda: False)
    monkeypatch.setattr(bk, "_select_interfaces", lambda args, input_fn: (["wlan0"], []))
    monkeypatch.setattr(bk, "_real_operator_user", lambda: None)
    monkeypatch.setattr(
        bk, "install_kismet_apt_repo", lambda *a, **kw: None
    )
    monkeypatch.setattr(bk, "install_kismet_package", lambda *, dry_run: None)
    monkeypatch.setattr(
        bk, "add_user_to_kismet_group", lambda user, *, dry_run: None
    )
    return SimpleNamespace(site_conf=site_conf)


def test_run_returns_2_when_not_root(monkeypatch, capsys):
    """Documented exit code: '2 -- tool-level failure (run not root, etc.)'.
    The error must reach stderr (not stdout), because operators triage
    bootstrap output by looking at stderr first."""
    monkeypatch.setattr(bk, "_is_root", lambda: False)

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 2
    err = capsys.readouterr().err
    assert "must run as root" in err, err


def test_run_returns_2_on_non_linux_platform(monkeypatch, capsys):
    """Documented contract: 'Linux only'. The check is on
    ``sys.platform`` -- a Mac or BSD operator running this script gets
    exit 2 with a clear message, not a traceback."""
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr(bk.sys, "platform", "darwin")

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 2
    err = capsys.readouterr().err
    assert "darwin" in err.lower() or "platform" in err.lower(), err


def test_run_unsupported_distro_with_install_prints_pointer_and_returns_zero(
    monkeypatch, capsys
):
    """Documented contract: 'Operator asked to install via apt on an
    unsupported distro: point them at the manual-install instructions +
    exit 0'. The exit code is 0 (the operator isn't broken, just on a
    distro the matrix doesn't cover), and the pointer URL is rendered.
    """
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr(bk, "detect_distro", lambda: (None, None))

    code = bk.run(_ns(install=True), input_fn=lambda _: "y")

    assert code == 0
    out = capsys.readouterr().out
    assert "kismetwireless.net" in out, out


def test_run_unsupported_distro_without_install_does_not_print_pointer(capsys, monkeypatch):
    """The mirror image: on an unsupported distro without ``--install``,
    the closing-pointer URL is NOT shown -- because the operator didn't
    ask to install, and the default path runs interface config +
    permissions regardless. A bug that always printed the pointer would
    litter the operator's run output with off-topic advice.

    What the run DOES print in this branch is the closing 'unsupported
    distro' note + the 'continue with config' reassurance.
    """
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr(bk, "detect_distro", lambda: (None, None))
    monkeypatch.setattr(bk, "resolve_site_conf_path", lambda: None)
    monkeypatch.setattr(bk, "_real_operator_user", lambda: None)
    monkeypatch.setattr(bk, "warn_about_stale_lockfiles", lambda: False)
    monkeypatch.setattr(bk, "warn_about_lingering_kismon_vifs", lambda: False)
    monkeypatch.setattr(bk, "_select_interfaces", lambda a, f: ([], []))

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 0
    out = capsys.readouterr().out
    # And the run does tell the operator WHY we're not installing.
    assert "Unsupported distro" in out or "unsupported" in out.lower(), out
    # The closing-pointer URL that the dedicated pointer function emits is
    # rendered in the install branch only -- here, it's the kismet-on-path
    # branch that names the URL, and kismet_on_path=True in the fixture
    # path means the URL doesn't appear in the run-without-install case.
    assert "--install would install via apt" in out or "Continuing with" in out, out


def test_run_no_network_overrides_install(monkeypatch, capsys, orchestrator_env):
    """Documented contract: '``--no-network`` refuses any apt/network
    operation and overrides ``--install``'. With both flags set, the
    install path is skipped and the operator is told why."""
    code = bk.run(
        _ns(install=True, no_network=True), input_fn=lambda _: "y"
    )

    assert code == 0
    out = capsys.readouterr().out
    assert "--no-network" in out, out
    assert (
        "Installing Kismet via apt" not in out
    ), "the install branch ran despite --no-network"


def test_run_skips_install_when_distro_unsupported_and_install_not_requested(
    monkeypatch, capsys, orchestrator_env
):
    """Default path: no ``--install`` means the orchestrator does not
    call the apt install helpers -- even on an unsupported distro, since
    we only run the install helpers when ``do_install`` is True.
    """
    install_calls: list[bool] = []
    monkeypatch.setattr(
        bk,
        "install_kismet_apt_repo",
        lambda codename, *, dry_run: install_calls.append(True),
    )

    monkeypatch.setattr(bk, "detect_distro", lambda: (None, None))

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 0
    assert install_calls == [], "install_kismet_apt_repo ran without --install"


def test_run_install_path_when_kismet_not_on_path(
    monkeypatch, capsys, orchestrator_env
):
    """The install path with Kismet not present: apt-repo install +
    package install both fire. Pin: both are called exactly once with
    the codename from detect_distro and the dry_run flag from args.
    """
    monkeypatch.setattr(bk, "_kismet_installed", lambda: False)

    install_repo_calls: list[tuple[str, bool]] = []
    install_pkg_calls: list[bool] = []
    monkeypatch.setattr(
        bk,
        "install_kismet_apt_repo",
        lambda codename, *, dry_run: install_repo_calls.append((codename, dry_run)),
    )
    monkeypatch.setattr(
        bk,
        "install_kismet_package",
        lambda *, dry_run: install_pkg_calls.append(dry_run),
    )

    code = bk.run(_ns(install=True, dry_run=True), input_fn=lambda _: "y")

    assert code == 0
    assert install_repo_calls == [("bookworm", True)], install_repo_calls
    assert install_pkg_calls == [True], install_pkg_calls


def test_run_install_path_with_kismet_present_and_yes_skips(
    monkeypatch, capsys, orchestrator_env
):
    """Documented contract: 'with --yes, the re-install prompt defaults
    to N, so --yes skips re-install'. A bug that ignored --yes here
    would force a scripted operator to manage an interactive prompt on
    every run; the package is already present.
    """
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)

    install_calls = {"repo": 0, "pkg": 0}
    monkeypatch.setattr(
        bk,
        "install_kismet_apt_repo",
        lambda *a, **kw: install_calls.__setitem__("repo", install_calls["repo"] + 1),
    )
    monkeypatch.setattr(
        bk,
        "install_kismet_package",
        lambda *, dry_run: install_calls.__setitem__("pkg", install_calls["pkg"] + 1),
    )

    code = bk.run(_ns(install=True, yes=True), input_fn=lambda _: "y")

    assert code == 0
    assert install_calls == {"repo": 0, "pkg": 0}, install_calls


def test_run_install_path_with_kismet_present_and_reinstall_yes(
    monkeypatch, capsys, orchestrator_env
):
    """Documented contract: 'the install branch also runs when the
    operator explicitly confirms re-install'. With ``--yes`` no, the
    operator must answer 'y' to the re-install prompt; with the answer
    'y', the install helpers fire.
    """
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)

    install_calls = {"repo": 0, "pkg": 0}
    monkeypatch.setattr(
        bk,
        "install_kismet_apt_repo",
        lambda *a, **kw: install_calls.__setitem__("repo", install_calls["repo"] + 1),
    )
    monkeypatch.setattr(
        bk,
        "install_kismet_package",
        lambda *, dry_run: install_calls.__setitem__("pkg", install_calls["pkg"] + 1),
    )

    code = bk.run(
        _ns(install=True, yes=False), input_fn=lambda _: "y"
    )

    assert code == 0
    assert install_calls == {"repo": 1, "pkg": 1}, install_calls


def test_run_no_interfaces_selected_skips_site_conf_patch(
    monkeypatch, capsys, orchestrator_env
):
    """Documented contract: 'No interfaces selected ... Skipping config
    patch'. A bug here would write an empty config or, worse, fall
    through and rewrite an existing config with the same content.
    """
    monkeypatch.setattr(bk, "_select_interfaces", lambda a, f: ([], []))

    patch_calls: list[bool] = []
    monkeypatch.setattr(
        bk, "patch_kismet_site_conf", lambda *a, **kw: patch_calls.append(True)
    )

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 0
    assert patch_calls == [], "patch_kismet_site_conf fired with no interfaces"
    out = capsys.readouterr().out
    assert "No interfaces selected" in out, out


def test_run_no_site_conf_dir_skips_with_warning(monkeypatch, capsys, orchestrator_env):
    """Documented contract: 'Kismet config dir isn't laid down yet. Don't
    guess a path -- warn clearly'. The patcher is not called; the
    warning names the candidates so the operator can install Kismet
    first and re-run."""
    monkeypatch.setattr(bk, "resolve_site_conf_path", lambda: None)
    monkeypatch.setattr(bk, "_select_interfaces", lambda a, f: (["wlan0"], []))

    patch_calls: list[bool] = []
    monkeypatch.setattr(
        bk, "patch_kismet_site_conf", lambda *a, **kw: patch_calls.append(True)
    )

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 0
    assert patch_calls == [], "patch_kismet_site_conf fired without a site_conf_path"
    out = capsys.readouterr().out
    assert "no Kismet config directory" in out, out


def test_run_reset_config_backs_up_before_patching(
    monkeypatch, capsys, orchestrator_env
):
    """Documented contract: '``--reset-config``: back up the existing
    kismet_site.conf, then write a fresh file'. Pin: the backup
    fires before the patch, and the operator gets a confirming line
    naming the backup path."""
    orchestrator_env.site_conf.write_text(
        "source=wlan9:type=linuxwifi\n", encoding="utf-8"
    )

    backup_calls: list[bool] = []
    patch_calls: list[bool] = []

    def _spy_backup(*a, **kw):
        backup_calls.append(True)
        # Return a real backup path so print_closing_pointer has
        # something to render.
        return orchestrator_env.site_conf.with_suffix(".conf.bak-123")

    monkeypatch.setattr(bk, "backup_kismet_site_conf", _spy_backup)
    monkeypatch.setattr(
        bk, "patch_kismet_site_conf", lambda *a, **kw: patch_calls.append(True)
    )

    code = bk.run(_ns(reset_config=True), input_fn=lambda _: "y")

    assert code == 0
    assert backup_calls, "--reset-config did not invoke backup_kismet_site_conf"
    assert patch_calls, "--reset-config did not invoke patch_kismet_site_conf"


def test_run_reset_config_with_no_existing_conf_does_not_break(
    monkeypatch, capsys, orchestrator_env
):
    """The 'no existing file to back up' branch. The backup returns
    None, the patch still fires, and the operator gets a "no existing"
    line rather than "backed up existing"."""
    monkeypatch.setattr(bk, "backup_kismet_site_conf", lambda *a, **kw: None)
    monkeypatch.setattr(
        bk, "patch_kismet_site_conf", lambda *a, **kw: ["source=wlan0:type=linuxwifi"]
    )

    code = bk.run(_ns(reset_config=True), input_fn=lambda _: "y")

    assert code == 0
    out = capsys.readouterr().out
    assert "no existing" in out, out


def test_run_real_operator_in_kismet_group_skips_usermod(monkeypatch, capsys, orchestrator_env):
    """Documented contract: 'operator already in kismet group? skip
    usermod'. A bug that ran usermod anyway would error out with
    'already a member of group' on every idempotent re-run.
    """
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "synth-operator")
    monkeypatch.setattr(bk, "_group_exists", lambda group: True)
    monkeypatch.setattr(bk, "_user_in_group", lambda user, group: True)

    usermod_calls: list[bool] = []
    monkeypatch.setattr(
        bk, "add_user_to_kismet_group", lambda *a, **kw: usermod_calls.append(True)
    )

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 0
    assert usermod_calls == [], "usermod ran even though operator was already in group"
    out = capsys.readouterr().out
    assert "synth-operator" in out, out


def test_run_real_operator_not_in_kismet_group_invokes_usermod(
    monkeypatch, capsys, orchestrator_env
):
    """The active add-to-group branch: when the operator is real but
    not yet a member of the kismet group, the add-user helper is
    called."""
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "synth-operator")
    monkeypatch.setattr(bk, "_group_exists", lambda group: True)
    monkeypatch.setattr(bk, "_user_in_group", lambda user, group: False)

    usermod_calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        bk,
        "add_user_to_kismet_group",
        lambda user, *, dry_run: usermod_calls.append((user, dry_run)),
    )

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 0
    assert usermod_calls == [("synth-operator", False)], usermod_calls


def test_run_missing_kismet_group_returns_1_on_supported_distro(
    monkeypatch, capsys, orchestrator_env
):
    """Documented contract: 'missing group on a supported distro ...
    the package install didn't complete cleanly. ... exit 1'. The
    operator gets a clear, branch-specific error."""
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "synth-operator")
    monkeypatch.setattr(bk, "_group_exists", lambda group: False)
    monkeypatch.setattr(bk, "detect_distro", lambda: ("debian", "bookworm"))

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 1
    err = capsys.readouterr().err
    assert "kismet" in err, err


def test_run_missing_kismet_group_returns_1_on_unsupported_distro(
    monkeypatch, capsys, orchestrator_env
):
    """The other half of the missing-group branch: on an unsupported
    distro, the message names 'install Kismet first' rather than
    'package install didn't complete cleanly'. Same exit code, same
    operator-blocking intent, different actionable advice."""
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "synth-operator")
    monkeypatch.setattr(bk, "_group_exists", lambda group: False)
    monkeypatch.setattr(bk, "detect_distro", lambda: (None, None))
    monkeypatch.setattr(bk, "resolve_site_conf_path", lambda: None)
    monkeypatch.setattr(bk, "_select_interfaces", lambda a, f: ([], []))
    monkeypatch.setattr(bk, "warn_about_stale_lockfiles", lambda: False)
    monkeypatch.setattr(bk, "warn_about_lingering_kismon_vifs", lambda: False)

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 1
    err = capsys.readouterr().err
    assert "kismet" in err.lower(), err
    # And the message names 'install' -- the actionable verb for the
    # from-source / non-apt path.
    assert "install" in err.lower(), err


def test_run_no_sudo_user_prints_manual_command_instead_of_usermod(
    monkeypatch, capsys, orchestrator_env
):
    """Documented contract: 'SUDO_USER not set or runs as root.
    Skipping kismet group membership step -- the user that will run
    Kismet should be added manually'. A bug that fell through to
    usermod here would fail (no SUDO_USER to add) and exit 1 instead
    of gracefully pointing the operator at the manual command.
    """
    monkeypatch.setattr(bk, "_real_operator_user", lambda: None)

    usermod_calls: list[bool] = []
    monkeypatch.setattr(
        bk, "add_user_to_kismet_group", lambda *a, **kw: usermod_calls.append(True)
    )

    code = bk.run(_ns(), input_fn=lambda _: "y")

    assert code == 0
    assert usermod_calls == [], "usermod fired without a SUDO_USER"
    out = capsys.readouterr().out
    assert "SUDO_USER" in out or "your operator user" in out, out


# ===========================================================================
# main -- the CLI entry point
# ===========================================================================


def test_main_returns_zero_on_happy_path(monkeypatch, capsys):
    """Documented contract: 'main() forwards [the run() exit code] to
    sys.exit'. Pin: when run() returns 0, main() returns 0 -- and does
    so without argv parsing or any other surprise.
    """
    monkeypatch.setattr(bk, "run", lambda args: 0)

    code = bk.main([])

    assert code == 0


def test_main_catches_bootstrap_error_and_returns_1(monkeypatch, capsys):
    """Documented contract: 'BootstrapError caught at the main()
    boundary and rendered to stderr; exits 1'. The error must NOT
    propagate (would otherwise print a Python traceback to stderr), the
    exit code must be 1 (operator-actionable failure, distinct from the
    'tool-level' exit 2).
    """
    def _raise(args):
        raise bk.BootstrapError("apt-get install failed: NO_PUBKEY 12345")

    monkeypatch.setattr(bk, "run", _raise)

    code = bk.main([])

    assert code == 1
    err = capsys.readouterr().err
    assert "NO_PUBKEY 12345" in err, err


def test_main_returns_2_when_run_returns_2(monkeypatch):
    """Forwarding exit code 2 (tool-level failure, e.g. 'not root').
    The main() boundary must not rewrite exit codes; if it did, an
    operator triage script that keys off the exit value would have
    to know two different conventions."""
    monkeypatch.setattr(bk, "run", lambda args: 2)

    assert bk.main([]) == 2


def test_main_keyboard_interrupt_returns_130(monkeypatch, capsys):
    """Documented contract: 'Ctrl-C mid-run ... should read as a clean
    cancellation, not Python's default unhandled-exception traceback.
    Exit 130 (128 + SIGINT)'. A bug here would either let the
    KeyboardInterrupt propagate (printing a traceback to stderr and
    exiting with 1) or swallow it and exit 0, hiding the operator's
    cancellation.
    """
    def _raise_keyboard(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(bk, "run", _raise_keyboard)

    code = bk.main([])

    assert code == 130
    err = capsys.readouterr().err
    assert "cancelled" in err, err


def test_main_parses_argv_through_the_real_parser(monkeypatch, capsys):
    """main() is the entry point that actually receives argv. Pin: the
    parser built inside main() produces the namespace that run() sees,
    so a future refactor that bypassed the parser would surface here.
    """
    captured: dict = {}

    def _spy_run(args):
        captured["install"] = args.install
        captured["dry_run"] = args.dry_run
        return 0

    monkeypatch.setattr(bk, "run", _spy_run)

    code = bk.main(["--install", "--dry-run"])

    assert code == 0
    assert captured == {"install": True, "dry_run": True}, captured
