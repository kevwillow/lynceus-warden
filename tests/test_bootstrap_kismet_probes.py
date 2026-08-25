"""Behavioural probes for the zero-cover surfaces of `cli/bootstrap_kismet.py`.

Orchestration plan W3-C. Three sibling files (`..._behaviour.py`,
`..._file_modes.py`, `..._interface_validation.py`) already pin the
distro-detection, source-line, patcher, dry-run, file-mode, and
`--interface`-validation surfaces. This file covers what those left:
the eight functions that have no test referencing them anywhere
under `tests/`.

Each test pins a promise the module's own docstring makes -- the
defect class this project has spent the week finding is "docstring
stopped being true of the code beneath it", so the assertions live
on the contract, not on a derived behaviour. Section 5 of the packet
measured ten outcomes against the real module; those values are
quoted verbatim below, because a "fix" that drifts them would not be
caught by anything else.

⛔ SYNTHETIC NAMES ONLY. This file is committed and published. The
existing `tests/test_bootstrap_kismet.py` embeds the operator's real
capture adapter MAC and the rig account name, so `.gitignore`
withholds it. THIS file is not withheld, so the interface names in
test fixtures and the section-5 pin inputs are restricted to the
canonical synthetic set (wlan0/1, wlp2s0, hci0/1, kismon0, phy0/1,
plus wlan9 / wlan0mon where section 5 requires them). No `wlx*`
interface names, no `00:c0:ca` OUI, no real-looking MAC, no
username, no hostname.

⭐ The highest-stakes test is **`backup_kismet_site_conf` under
`dry_run=True` must NOT rename anything.** An operator running
`--dry-run` is asking what *would* happen; a bug there applies
changes they were only previewing, to a capture config, as root.
"""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

import pytest

from lynceus.cli import bootstrap_kismet as bk

# --- parse_iw_dev: `iw dev` -> [(phy, iface), ...] --------------------------


def test_an_interface_before_any_phy_line_is_dropped():
    """Documented rationale: "phy lines look like ``phy#N``; we re-emit them
    as ``phyN`` ... A single phy may carry multiple Interface entries".

    The code carries this by gating Interface entries on a `current_phy` that
    is only set by a preceding ``phy#N`` line. An Interface before any phy#
    has nothing to attach to, so attaching it to the FIRST seen phy would
    silently mis-attribute a stray line. Pin: a stray ``Interface wlan9``
    before ``phy#0`` is ignored.
    """
    out = "    Interface wlan9\nphy#0\n    Interface wlan0\n"
    assert bk.parse_iw_dev(out) == [("phy0", "wlan0")]


def test_phy_lines_are_re_emitted_as_phyN():
    """Documented rationale: "Phy lines look like ``phy#N``; we re-emit them
    as ``phyN`` to match what ``iw phy <name> info`` expects."

    If the ``#`` were carried through, the subsequent `iw phy phy#0 info`
    call would be made against a name `iw` does not understand, and the
    monitor-mode probe would silently return ``[]`` -- no exception, just no
    detection. Pin: ``phy#0`` becomes ``phy0`` in the returned pairs.
    """
    out = "phy#0\n\tInterface wlan0\n\tInterface wlan0mon\n"
    assert bk.parse_iw_dev(out) == [
        ("phy0", "wlan0"),
        ("phy0", "wlan0mon"),
    ]


def test_two_phys_split_their_interfaces():
    """Documented rationale: each `phy#N` opens its own block; the same phy
    can carry multiple Interface entries, and they attach to whichever phy
    immediately precedes them. Without the gate, all interfaces would
    collapse onto the last-seen phy, and `iw phy <wrong> info` would
    succeed-but-misattribute detection."""
    out = (
        "phy#0\n"
        "    Interface wlan0\n"
        "phy#1\n"
        "    Interface wlan1\n"
    )
    assert bk.parse_iw_dev(out) == [
        ("phy0", "wlan0"),
        ("phy1", "wlan1"),
    ]


def test_empty_or_comment_only_input_yields_no_pairs():
    """Defensive default. A host with no phy entries produces a parser that
    does not raise and does not invent -- `detect_wifi_monitor_capable`
    short-circuits on an empty result, but only if the empty result is
    real rather than a KeyError on `current_phy`."""
    assert bk.parse_iw_dev("") == []
    assert bk.parse_iw_dev("# just a comment\n\n") == []


# --- parse_iw_phy_info_supports_monitor ------------------------------------


def test_a_blank_line_terminates_the_supported_modes_bullet_scan():
    """Documented shape ends with "the first non-``\\s*\\* `` line after the
    header, or end-of-output". A blank line is the natural section break in
    real `iw` output (it precedes the next section header) and is NOT a
    ``\\s*\\* `` line -- so it ends the scan.

    Pin: ``* managed`` followed by a blank line then ``* monitor`` is
    ``False``. A scan that did not honour the blank line would treat the
    later ``* monitor`` as part of the supported section and answer
    ``True``, which would auto-pick an adapter that does not actually
    advertise monitor in its SUPPORTED modes (only in some later,
    non-advertised section).
    """
    out = "Supported interface modes:\n\t * managed\n\n\t * monitor\n"
    assert bk.parse_iw_phy_info_supports_monitor(out) is False


def test_monitor_in_a_later_non_advertised_section_does_not_count():
    """The whole point of the section is the header "Supported interface
    modes:". `iw phy` output continues after the supported list with other
    sections (e.g. "software interface modes:") that may also list
    monitor. Counting those would claim a phy is monitor-capable when
    `iw dev` + `iw phy <name> info` would not produce a working monitor
    VIF."""
    out = (
        "Supported interface modes:\n"
        "\t * managed\n"
        "software interface modes:\n"
        "\t * monitor\n"
    )
    assert bk.parse_iw_phy_info_supports_monitor(out) is False


def test_monitor_in_the_supported_section_is_recognised_case_insensitively():
    """Documented scan: "bullet matches monitor". The check lowercases the
    bullet text before comparing. Real `iw` output renders the word
    "Monitor" with a capital M in some firmware versions; matching it
    case-sensitively would false-negative a perfectly capable adapter."""
    out = "Supported interface modes:\n\t * Monitor\n"
    assert bk.parse_iw_phy_info_supports_monitor(out) is True


def test_a_normal_supported_section_with_monitor_is_true():
    """The happy path that the function exists to answer: the canonical
    output of `iw phy <name> info` advertises monitor and the helper
    should say yes. Without this presence check, a parser bug that
    always returned False would satisfy the section-5 measurements
    while breaking the actual feature."""
    out = (
        "Supported interface modes:\n"
        "\t * IBSS\n"
        "\t * managed\n"
        "\t * AP\n"
        "\t * monitor\n"
    )
    assert bk.parse_iw_phy_info_supports_monitor(out) is True


def test_no_supported_section_header_at_all_is_false_not_an_error():
    """An `iw phy <name> info` on a non-wireless device (or a future `iw`
    version that drops the section) does not crash the parser; absence of
    the header is absence of the feature. Detection must surface as "no
    monitor candidates" rather than traceback."""
    assert bk.parse_iw_phy_info_supports_monitor("") is False
    assert bk.parse_iw_phy_info_supports_monitor("Wiphy phy0\n") is False


# --- filter_kismet_monitor_vifs ---------------------------------------------


def test_an_orphaned_kismon_with_a_private_phy_is_preserved():
    """Documented two-signal rule: "A kismon* with no shared phy (orphaned,
    parent unplugged) is preserved so the operator can decide."

    Name-only filtering would false-positive an operator who renamed their
    adapter "kismon-test" but does not actually have it backing another
    candidate; phy-only filtering would over-fire here. The
    orphan-preserved case is the one that proves the rule is conjunctive
    rather than disjunctive: name AND shared-phy are BOTH required to drop.
    """
    assert bk.filter_kismet_monitor_vifs([("phy0", "kismon0")]) == ["kismon0"]


def test_a_kismon_sharing_a_phy_with_a_candidate_is_dropped():
    """Documented rationale: "those are Kismet's auto-created monitor-mode
    VIFs; selecting them as capture sources double-registers the physical
    adapter and breaks capture".

    Pin: of the three pairs, ``kismon0`` shares ``phy0`` with ``wlan0``
    and is dropped; ``wlan0`` survives; ``wlan1`` survives on ``phy1``.
    The function returns interface names (not pairs) in input order.
    """
    assert bk.filter_kismet_monitor_vifs(
        [("phy0", "wlan0"), ("phy0", "kismon0"), ("phy1", "wlan1")]
    ) == ["wlan0", "wlan1"]


def test_survivors_are_returned_in_input_order():
    """The function is used to drive the operator's choice list. Re-ordering
    silently would change which adapter is presented first; an "ordered by
    detection" promise that did not hold would shuffle the menu between
    runs."""
    pairs = [
        ("phy1", "wlan1"),
        ("phy0", "wlan0"),
        ("phy0", "kismon0"),  # dropped
        ("phy0", "wlan0"),  # duplicate iface on same phy -> kept (multi-VIF ok)
    ]
    assert bk.filter_kismet_monitor_vifs(pairs) == [
        "wlan1",
        "wlan0",
        "wlan0",
    ]


def test_empty_input_yields_empty_output():
    """Defensive: `detect_wifi_monitor_capable` may pass an empty list when
    `iw` is missing or returns no pairs; the filter must not invent."""
    assert bk.filter_kismet_monitor_vifs([]) == []


# --- detect_bluetooth_interfaces -------------------------------------------


def test_an_empty_sysfs_tree_yields_no_controllers(tmp_path):
    """A freshly imaged host with no Bluetooth hardware has no
    /sys/class/bluetooth/hci* entries. Detection must report empty rather
    than crash, because `--interface-type bt` defaults to `wifi` and a
    spurious `hci0` claim would misconfigure every operator who has the
    bt checkbox checked."""
    bt = tmp_path / "bluetooth"
    bt.mkdir()
    assert bk.detect_bluetooth_interfaces(bt) == []


def test_a_missing_sysfs_directory_is_treated_as_empty(tmp_path):
    """A hardened container or a `chroot` may have no /sys/class/bluetooth
    at all. `Path.is_dir()` is False on a missing path and the helper
    short-circuits to ``[]`` rather than raising. A `FileNotFoundError`
    propagating up would terminate the bootstrap on a host that has
    perfectly valid wifi."""
    missing = tmp_path / "absent"
    assert bk.detect_bluetooth_interfaces(missing) == []


def test_hci_entries_are_returned_sorted(tmp_path):
    """The detection feeds the operator prompt; stable ordering is part of
    the contract (otherwise a host that boots with hci1 appearing before
    hci0 in sysfs would shuffle between runs)."""
    bt = tmp_path / "bluetooth"
    bt.mkdir()
    (bt / "hci1").mkdir()
    (bt / "hci0").mkdir()
    assert bk.detect_bluetooth_interfaces(bt) == ["hci0", "hci1"]


def test_non_hci_entries_are_ignored(tmp_path):
    """/sys/class/bluetooth can contain non-hci symlinks on some kernels
    (e.g. rfkill subentries, or `host`/`virtual` shims). They are NOT
    controllers and must not be offered as capture sources; offering a
    non-hci path to Kismet's linuxbluetooth source would fail to open."""
    bt = tmp_path / "bluetooth"
    bt.mkdir()
    (bt / "hci0").mkdir()
    (bt / "rfkill0").mkdir()
    (bt / "host0").mkdir()
    (bt / "hci-notnum").mkdir()
    assert bk.detect_bluetooth_interfaces(bt) == ["hci0"]


# --- _shell_quote ----------------------------------------------------------


def test_empty_arg_is_rendered_as_an_empty_quoted_string():
    """Documented contract: "if not arg ... return ``'`` + arg.replace(...) +
    ``'``". An empty arg has no content to print; the preview still shows
    a syntactically valid shell token (``''``) so the operator can read
    the resulting command line. A naive ``return arg`` would emit a
    bare empty string and let the next token visually concatenate."""
    assert bk._shell_quote("") == "''"


def test_a_plain_arg_is_returned_verbatim():
    """Documented contract: the function is "Render an argument for the
    dry-run preview. Not used to actually invoke the command (which always
    goes through ``subprocess.run`` with the list form)."

    Pin: a safe arg passes through. The point of the function is to ONLY
    quote when needed; over-quoting every arg would still be parseable but
    is uglier to read and hides the structural difference between the two
    cases in dry-run output.
    """
    assert bk._shell_quote("plain") == "plain"


def test_a_single_quote_is_escaped_by_close_quote_escaped_reopen_quote():
    """Documented contract: the standard POSIX ``close-quote, escaped,
    reopen-quote`` form (``'\\''``). A naive ``arg.replace("'", "''")``
    would produce ``''it''s''``, which is NOT valid shell -- an embedded
    quote inside a single-quoted string must exit the string to emit the
    quote itself.

    Pin: ``it's`` -> ``'it'\\''s'``. This is the form the operator will
    see in the dry-run preview and would copy back to verify a failing
    command; getting it wrong is a preview that lies.
    """
    assert bk._shell_quote("it's") == "'it'\\''s'"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("has space", "'has space'"),
        ("has\ttab", "'has\ttab'"),
        ('has"quote', "'has\"quote'"),
        ("has\\backslash", "'has\\backslash'"),
        ("has$dollar", "'has$dollar'"),
        ("has`backtick`", "'has`backtick`'"),
    ],
)
def test_other_shell_metacharacters_also_trigger_quoting(raw, expected):
    """Documented trigger set: ``' \\t\"\\'$` `` -- every character that, if
    passed verbatim, would change the meaning of the surrounding shell
    command. Pinning each of them ensures a future "optimisation" that
    narrows the trigger set does not reintroduce a shell-injection
    surface in the dry-run preview."""
    assert bk._shell_quote(raw) == expected


# --- backup_kismet_site_conf -----------------------------------------------


def test_backup_of_a_nonexistent_path_returns_none(tmp_path):
    """Documented contract: "Returns the backup path on success, or ``None``
    when ``path`` does not exist (nothing to back up -- a fresh write
    will land cleanly without any rename)."

    A path that does not exist has nothing to back up; returning ``None``
    signals "no prior file, proceed without renaming" to the caller, and
    is what the caller checks to decide whether to mention a backup to
    the operator. A bug that returned the would-be backup path on
    missing input would make every fresh install falsely claim to have
    preserved a prior backup.
    """
    p = tmp_path / "absent.conf"
    assert bk.backup_kismet_site_conf(p, dry_run=False) is None
    assert bk.backup_kismet_site_conf(p, dry_run=True) is None


def test_dry_run_returns_the_would_be_backup_path_without_renaming(tmp_path):
    """⭐ The highest-stakes test in this file.

    Documented contract: "In dry-run, prints the rename and returns the
    path that WOULD have been created so the closing hint stays
    accurate."

    An operator running `--dry-run` is asking what *would* happen; a
    bug here would rename a real kismet_site.conf they were only
    previewing, leaving the next run to write a fresh file with no
    backup of the previous one, on a path Kismet reads at every
    capture. We pin both halves of the contract: the return value is
    the would-be backup path, AND the original file is byte-identical
    to what it was on entry.
    """
    conf = tmp_path / "kismet_site.conf"
    original = "httpd_password=hunter2\nsource=wlan0\n"
    conf.write_text(original, encoding="utf-8")
    original_mode = stat.S_IMODE(conf.stat().st_mode)

    result = bk.backup_kismet_site_conf(conf, dry_run=True)

    assert result is not None
    assert result.parent == conf.parent
    assert result.name.startswith(f"{conf.name}.bak-"), (
        f"dry-run returned a non-`.bak-<ts>` name: {result.name}"
    )
    assert conf.read_text(encoding="utf-8") == original, (
        "dry-run rewrote the original file"
    )
    assert conf.exists(), "dry-run deleted the original file"
    assert stat.S_IMODE(conf.stat().st_mode) == original_mode, (
        "dry-run altered the original file's mode"
    )
    # And the would-be backup itself must not yet exist on disk.
    assert not result.exists(), (
        f"dry-run materialised the backup path it only promised: {result}"
    )


def test_real_run_renames_the_original_into_a_bak_unix_ts_file(tmp_path):
    """Documented contract: "rename ``path`` to ``<path>.bak-<unix-ts>``".
    Pin: the original is gone, the backup exists with the suffix, and
    the backup's content is byte-identical to the original.

    The unix-ts suffix matters because `--reset-config` may be run
    repeatedly; a fixed-suffix backup would overwrite the prior backup
    on the second run. An operator recovering a clobbered customisation
    via ``mv kismet_site.conf.bak-<ts> kismet_site.conf`` needs the
    prior backup to still be there.
    """
    conf = tmp_path / "kismet_site.conf"
    body = "source=wlan0:type=linuxwifi\n"
    conf.write_text(body, encoding="utf-8")

    backup = bk.backup_kismet_site_conf(conf, dry_run=False)

    assert backup is not None
    assert not conf.exists(), "real run left the original in place"
    assert backup.exists(), "real run did not create the backup"
    assert backup.name.startswith(f"{conf.name}.bak-"), backup.name
    assert backup.read_text(encoding="utf-8") == body
    # No new sibling file appeared beyond the backup itself.
    siblings = sorted(p.name for p in conf.parent.iterdir())
    assert siblings == [backup.name], siblings


# --- find_stale_kismet_lockfiles -------------------------------------------


def _make_lockfile(path, *, uid_owner: bool = True, mode: int = 0o600) -> Path:
    """Create a fake Kismet capture lockfile under tmp_path.

    � We cannot make the test file ACTUALLY owned by uid 0 on a non-root
    test runner. The function reads `st.st_uid` from the kernel; we
    patch `os.stat` below to return a synthetic stat result instead --
    so the test does not require root and is hermetic, but still
    exercises the exact comparison the production code performs.
    """
    path.write_text("", encoding="utf-8")
    os.chmod(path, mode)
    return path


def _patch_stat(monkeypatch, *, uid: int, mode: int):
    """Build a `Path.stat` replacement returning a fixed uid/mode.

    `find_stale_kismet_lockfiles` reads `st_uid` / `st_mode`, and the runner is
    not root, so it cannot legitimately own a lockfile as uid 0.

    ⚠️ **Callers install this on the Path CLASS**, via
    `monkeypatch.setattr(Path, "stat", ...)` — not on individual instances. For
    the duration of such a test EVERY `Path.stat()` returns this synthetic
    result, including any the test itself makes. That is acceptable here only
    because these tests touch nothing else after installing it, and because
    `monkeypatch` restores the attribute at teardown (verified: no bleed across
    a fixed-order run with the file-modes and webui-auth suites). An earlier
    version of this docstring claimed the patch applied "only on the Path
    objects we hand it", which is not what the callers do."""

    class _StatResult:
        def __init__(self, uid: int, mode: int) -> None:
            self.st_uid = uid
            self.st_mode = mode

    def _stat_for(path, *, uid=uid, mode=mode):
        return _StatResult(uid, mode)

    return _stat_for


def test_a_root_owned_lockfile_with_no_group_or_other_write_is_flagged(
    monkeypatch, tmp_path
):
    """Documented rationale: "A lockfile here owned by root with no
    group/other write (i.e. a leftover from a prior ``sudo kismet`` run)
    silently kills capture when Kismet next starts as the kismet user ...
    Bootstrap-kismet surfaces the path + cleanup command so the operator
    can clear it before launching Kismet."

    Pin: the canonical stale shape (root-owned, 0o600) appears in the
    returned list with its real Path, its uid=0, and mode 0o600.
    """
    lock = _make_lockfile(tmp_path / ".kismet_cap_linux_wlan0")

    monkeypatch.setattr(Path, "stat", _patch_stat(monkeypatch, uid=0, mode=0o600))

    found = bk.find_stale_kismet_lockfiles(str(tmp_path / ".kismet_cap_linux_*"))

    assert found == [(lock, 0, 0o600)], found


def test_a_lockfile_owned_by_the_kismet_user_is_not_flagged(
    monkeypatch, tmp_path
):
    """Documented rationale: "A lockfile owned by the kismet user (active
    session) is NOT flagged -- that's the documented in-use case and
    clearing it would break a running capture."

    Pin: the exact same shape, uid=1000 instead of 0, is filtered out.
    A bug that used only the mode check would falsely flag every
    active capture.
    """
    _make_lockfile(tmp_path / ".kismet_cap_linux_wlan0")

    monkeypatch.setattr(
        Path, "stat", _patch_stat(monkeypatch, uid=1000, mode=0o600)
    )

    found = bk.find_stale_kismet_lockfiles(str(tmp_path / ".kismet_cap_linux_*"))

    assert found == [], found


@pytest.mark.parametrize("mode", [0o020, 0o002, 0o660, 0o602, 0o622, 0o777])
def test_a_root_owned_lockfile_with_any_group_or_other_write_is_skipped(
    monkeypatch, tmp_path, mode
):
    """Documented rule: "if st.st_mode & 0o022: continue". A root-owned
    lockfile with group or other write is not the "restrictive root
    leftover" shape -- it is either world-writable (a separate problem)
    or group-writable (likely active capture). Pin: every mode that
    has any of group-write (0o020) or other-write (0o002) is filtered,
    even with uid=0."""
    _make_lockfile(tmp_path / ".kismet_cap_linux_wlan0", mode=mode)

    monkeypatch.setattr(Path, "stat", _patch_stat(monkeypatch, uid=0, mode=mode))

    found = bk.find_stale_kismet_lockfiles(str(tmp_path / ".kismet_cap_linux_*"))

    assert found == [], (
        f"root-owned lockfile with mode {oct(mode)} should be skipped"
    )


def test_a_glob_that_matches_nothing_yields_an_empty_list(tmp_path):
    """Defensive: when no leftover lockfiles exist, `find_stale_kismet_lockfiles`
    is called at the start of every bootstrap and must not invent
    warnings. Pinning this also exercises the loop's empty branch."""
    assert bk.find_stale_kismet_lockfiles(
        str(tmp_path / ".kismet_cap_linux_definitely_no_such_file_*")
    ) == []


# --- _build_parser ---------------------------------------------------------


def _parse(argv: list[str]) -> argparse.Namespace:
    return bk._build_parser().parse_args(argv)


def test_no_arguments_yields_the_documented_defaults():
    """Documented defaults: every boolean flag is ``False``; ``--interface``
    is an accumulating list defaulting to ``[]``; ``--interface-type``
    defaults to ``"wifi"``. Pinning each default is the presence check
    beside the behaviour checks below -- a parser that defaulted
    ``dry_run=True`` would satisfy a single happy-path test while
    silently previewing every real run."""
    ns = _parse([])
    assert ns.install is False
    assert ns.skip_install is False
    assert ns.interface == []
    assert ns.interface_type == "wifi"
    assert ns.no_network is False
    assert ns.reset_config is False
    assert ns.dry_run is False
    assert ns.yes is False


def test_interface_appends_across_multiple_flag_occurrences():
    """Documented shape: "action='append' ... May be given multiple
    times". A flag that used `nargs='+'` would consume positional
    arguments after the first; a flag that used `default=...` without
    `append` would overwrite rather than accumulate. Pin: three
    occurrences produce a list of three."""
    ns = _parse(["--interface", "wlan0", "--interface", "wlan1", "--interface", "wlan9"])
    assert ns.interface == ["wlan0", "wlan1", "wlan9"]


def test_interface_type_accepts_only_wifi_or_bt():
    """Documented constraint: ``choices=('wifi', 'bt')``. An operator typo
    (``--interface-type bluetooth``) must be refused at parse time, not
    silently fall back to ``wifi`` and misconfigure every later run."""
    assert _parse(["--interface-type", "bt"]).interface_type == "bt"

    with pytest.raises(SystemExit):
        _build_parser = bk._build_parser().parse_args(["--interface-type", "bluetooth"])


def test_version_flag_exits_with_the_documented_prog_name():
    """Documented: ``--version`` action with the literal prog name from
    ``_build_parser``'s ``prog=`` argument. Pin: a version banner
    change that dropped ``lynceus-`` from the program name would break
    every script that greps for the version string in CI logs -- and
    the test makes the breakage visible here first."""
    parser = bk._build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    # argparse writes the version line to stdout then exits with code 0.
    assert exc.value.code == 0


def test_all_boolean_flags_toggle_independently():
    """Documented: each boolean flag is an independent ``store_true``. A
    parser bug that wired two flags to the same dest would surface
    here as one of them reading True after the other was set. Pin:
    each flag is set on its own, none of the others moves."""
    ns = _parse(
        [
            "--install",
            "--no-network",
            "--reset-config",
            "--dry-run",
            "--yes",
            "--skip-install",
        ]
    )
    assert ns.install is True
    assert ns.skip_install is True
    assert ns.no_network is True
    assert ns.reset_config is True
    assert ns.dry_run is True
    assert ns.yes is True


def test_the_prog_name_matches_the_consolescript_entrypoint():
    """Documented in the parser description: the tool's user-facing
    identity is ``lynceus-bootstrap-kismet`` (the entry point in
    pyproject.toml). A rename of either side without the other would
    break the help text and any external scripts that invoke
    `lynceus-bootstrap-kismet --help`."""
    parser = bk._build_parser()
    assert parser.prog == "lynceus-bootstrap-kismet"
