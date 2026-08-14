"""Behavioural cover for `cli/bootstrap_kismet.py`'s four remaining surfaces.

Orchestration plan W3-C. The module is ~1,650 lines and had no behavioural test
until #25 (file modes) and #36 (`--interface` validation). This covers what
those left: **distro detection, source-line generation, the patcher, and
dry-run.**

Each test pins a promise the module's own docstrings make. That is deliberate:
every defect this project found in the past week was a docstring that had
stopped being true of the code beneath it — `_atomic_write` promising "never
broader than requested", the handoffs misattributing a CodeQL bucket. So the
promises are what get asserted here, quoted where it matters.

⭐ The highest-stakes one is **dry-run must not write.** An operator running
`--dry-run` is asking what *would* happen; a bug there applies changes they were
only previewing, to a capture config, as root.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lynceus.cli import bootstrap_kismet as bk

WIFI = "wlan0"
BT = "hci0"


# --- source-line generation -------------------------------------------------


def test_source_lines_always_carry_an_explicit_type():
    """Documented rationale: "the auto-detect form works but is harder to debug
    when an interface gets misclassified". Silently dropping `type=` would be
    invisible until an operator was debugging a wrong-driver capture."""
    assert bk.build_source_line(WIFI, "wifi") == "source=wlan0:type=linuxwifi"
    assert bk.build_source_line(BT, "bt") == "source=hci0:type=linuxbluetooth"


def test_an_unknown_source_kind_raises_rather_than_guessing():
    """Emitting a source line for a kind we do not understand would hand Kismet
    a config it cannot act on, and the operator a sensor that captures nothing
    while reporting success."""
    with pytest.raises(ValueError, match="unknown source kind"):
        bk.build_source_line(WIFI, "zigbee")


@pytest.mark.parametrize(
    "line",
    [
        "source=wlan0:type=linuxwifi",
        "  source=wlan0:type=linuxwifi",  # indented
        "source = wlan0 : type=linuxwifi",  # spaced around =
        "source=wlan0",  # no suffix at all
        "source=wlan0:type=linuxwifi:name=front-door",  # operator suffix
    ],
)
def test_an_existing_source_is_recognised_in_every_form_the_file_allows(line):
    """Idempotency is only as good as this detection. A form that is valid to
    Kismet but invisible here produces a DUPLICATE source line on every re-run.
    """
    assert bk.existing_source_interfaces(line) == {"wlan0"}


@pytest.mark.parametrize(
    "line",
    [
        "# source=wlan0:type=linuxwifi",
        "   # source=wlan0",
        "httpd_source=wlan0",  # a different key that merely ends in 'source'
    ],
)
def test_things_that_only_look_like_a_source_line_are_not_counted(line):
    """The other direction, and the one that costs capture rather than tidiness:
    treating a commented-out or unrelated line as "already configured" means the
    interface is never added and the operator's sensor silently does not watch
    it."""
    assert bk.existing_source_interfaces(line) == set()


# --- the patcher ------------------------------------------------------------


def test_a_new_file_gets_the_header_and_the_sources(tmp_path):
    conf = tmp_path / "kismet_site.conf"
    added = bk.patch_kismet_site_conf(conf, [WIFI], [BT], dry_run=False)
    body = conf.read_text(encoding="utf-8")

    assert added == [
        "source=wlan0:type=linuxwifi",
        "source=hci0:type=linuxbluetooth",
    ]
    assert "Managed (append-only) by lynceus-bootstrap-kismet" in body
    assert "source=wlan0:type=linuxwifi" in body
    assert "source=hci0:type=linuxbluetooth" in body


def test_re_running_adds_nothing(tmp_path):
    """The idempotency invariant, end to end."""
    conf = tmp_path / "kismet_site.conf"
    bk.patch_kismet_site_conf(conf, [WIFI], [BT], dry_run=False)
    first = conf.read_text(encoding="utf-8")

    assert bk.patch_kismet_site_conf(conf, [WIFI], [BT], dry_run=False) == []
    assert conf.read_text(encoding="utf-8") == first, "a re-run rewrote the file"


def test_an_operator_suffix_is_preserved_and_not_duplicated(tmp_path):
    """Quoting the promise: "This preserves operator customisations
    (``:name=foo``, ``:channel_list=...``) instead of silently rewriting them."

    Appending our own bare `source=wlan0:type=linuxwifi` beside theirs would
    give Kismet two sources for one interface -- and the operator's tuning would
    be the one ignored.
    """
    conf = tmp_path / "kismet_site.conf"
    conf.write_text("source=wlan0:type=linuxwifi:channel_list=1,6,11\n", encoding="utf-8")

    added = bk.patch_kismet_site_conf(conf, [WIFI], [], dry_run=False)

    assert added == []
    assert "channel_list=1,6,11" in conf.read_text(encoding="utf-8")
    assert conf.read_text(encoding="utf-8").count("source=wlan0") == 1


def test_unrelated_operator_content_survives_verbatim(tmp_path):
    """"Pre-existing content is appended to, never replaced." That file can hold
    `httpd_password=` — #25 exists because of it — so a patcher that rewrote
    rather than appended would destroy a credential."""
    conf = tmp_path / "kismet_site.conf"
    original = (
        "# my notes\n"
        "httpd_password=hunter2\n"
        "source=wlan9:type=linuxwifi\n"
    )
    conf.write_text(original, encoding="utf-8")

    bk.patch_kismet_site_conf(conf, [WIFI], [], dry_run=False)
    body = conf.read_text(encoding="utf-8")

    assert original in body, "existing content was not preserved verbatim"
    assert "httpd_password=hunter2" in body
    assert "source=wlan9:type=linuxwifi" in body, "an untouched source was dropped"


def test_a_file_without_a_trailing_newline_is_still_parseable_afterwards(tmp_path):
    """The no-trailing-newline path, which an operator's hand-edit easily
    produces.

    🪤 **I first wrote this asserting that the `sep` branch is what stops the
    last existing line gluing to our first addition. That is FALSE**, and
    planting `sep = ""` proved it: nothing failed. The appended block already
    begins with its own `\\n`, so the two cases produce **byte-identical**
    output --

        no trailing newline:   '...linuxwifi\\n\\n# Added by...'
        with trailing newline: '...linuxwifi\\n\\n# Added by...'

    ⇒ `sep` is **cosmetic** (it keeps the blank separator line consistent), not
    a correctness guard. Recorded here so nobody later "fixes" a bug that does
    not exist, or assumes this test is guarding one -- and because writing a
    docstring that misdescribed the code beneath it is the exact defect class
    this repo has spent the week finding in its own source.

    What is asserted below is the invariant that IS real: the file still parses,
    and neither source is lost.
    """
    conf = tmp_path / "kismet_site.conf"
    conf.write_text("source=wlan9:type=linuxwifi", encoding="utf-8")  # no \n

    bk.patch_kismet_site_conf(conf, [WIFI], [], dry_run=False)
    body = conf.read_text(encoding="utf-8")

    assert bk.existing_source_interfaces(body) == {"wlan9", "wlan0"}
    assert body.endswith("\n"), "the written file must end with a newline"


# --- dry-run ----------------------------------------------------------------


def test_dry_run_does_not_create_the_file(tmp_path):
    """⭐ The operator asked what WOULD happen."""
    conf = tmp_path / "kismet_site.conf"
    added = bk.patch_kismet_site_conf(conf, [WIFI], [BT], dry_run=True)

    assert added, "dry-run must still report what it would add"
    assert not conf.exists(), "dry-run created the file"


def test_dry_run_does_not_modify_an_existing_file(tmp_path):
    conf = tmp_path / "kismet_site.conf"
    original = "source=wlan9:type=linuxwifi\n"
    conf.write_text(original, encoding="utf-8")

    added = bk.patch_kismet_site_conf(conf, [WIFI], [], dry_run=True)

    assert added == ["source=wlan0:type=linuxwifi"]
    assert conf.read_text(encoding="utf-8") == original, "dry-run wrote to the file"


def test_dry_run_reports_exactly_what_a_real_run_would_write(tmp_path):
    """⛔ A dry-run that reports something OTHER than what the real run does is
    worse than no dry-run: it is a preview the operator trusts and that lies.
    Same input, two runs, compared."""
    preview_conf = tmp_path / "preview.conf"
    real_conf = tmp_path / "real.conf"
    for c in (preview_conf, real_conf):
        c.write_text("source=wlan9:type=linuxwifi\n", encoding="utf-8")

    previewed = bk.patch_kismet_site_conf(preview_conf, [WIFI], [BT], dry_run=True)
    actually = bk.patch_kismet_site_conf(real_conf, [WIFI], [BT], dry_run=False)

    assert previewed == actually


# --- distro detection -------------------------------------------------------


def _os_release(tmp_path, **fields) -> Path:
    p = tmp_path / "os-release"
    p.write_text(
        "\n".join(f'{k}="{v}"' for k, v in fields.items()) + "\n", encoding="utf-8"
    )
    return p


def test_kali_reports_the_repo_codename_not_the_os_release_one(tmp_path):
    """Documented: "the Kismet repo uses the literal ``kali`` codename, not the
    ``kali-rolling`` value /etc/os-release reports". Passing `kali-rolling`
    through would point apt at a repo that does not exist."""
    p = _os_release(tmp_path, ID="kali", VERSION_CODENAME="kali-rolling")
    assert bk.detect_distro(p) == ("kali", "kali")


@pytest.mark.parametrize("codename", sorted(bk.SUPPORTED_DEBIAN_CODENAMES))
def test_supported_debian_codenames_are_accepted(tmp_path, codename):
    p = _os_release(tmp_path, ID="debian", VERSION_CODENAME=codename)
    assert bk.detect_distro(p) == ("debian", codename)


@pytest.mark.parametrize("codename", sorted(bk.SUPPORTED_UBUNTU_CODENAMES))
def test_supported_ubuntu_codenames_are_accepted(tmp_path, codename):
    p = _os_release(tmp_path, ID="ubuntu", VERSION_CODENAME=codename)
    assert bk.detect_distro(p) == ("ubuntu", codename)


def test_a_supported_distro_at_an_unsupported_version_is_declined(tmp_path):
    """"right distro, wrong version" must fall back to manual install rather
    than pointing apt at a repo that has no build for it."""
    p = _os_release(tmp_path, ID="debian", VERSION_CODENAME="buster")
    assert bk.detect_distro(p) == (None, None)


@pytest.mark.parametrize("distro", ["fedora", "arch", "alpine"])
def test_unsupported_distros_are_declined(tmp_path, distro):
    p = _os_release(tmp_path, ID=distro, VERSION_CODENAME="whatever")
    assert bk.detect_distro(p) == (None, None)


def test_a_missing_os_release_is_declined_rather_than_crashing(tmp_path):
    """A container or a minimal image may have no /etc/os-release. Bootstrap
    should offer the manual path, not traceback."""
    assert bk.detect_distro(tmp_path / "definitely-absent") == (None, None)


def test_the_id_is_matched_case_insensitively(tmp_path):
    """/etc/os-release quoting and case vary by distro; matching `ID` strictly
    would silently decline a supported system."""
    p = _os_release(tmp_path, ID="Debian", VERSION_CODENAME="Bookworm")
    assert bk.detect_distro(p) == ("debian", "bookworm")
