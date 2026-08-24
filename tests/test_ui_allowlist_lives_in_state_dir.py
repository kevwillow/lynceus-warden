"""Web-UI suppression must work on the install mode the docs recommend.

`_write_ui_allowlist` wrote `allowlist_ui.yaml` beside the operator's own
allowlist. Under `--system` that is `/etc/lynceus`, and the units grant

    ReadWritePaths=/var/lib/lynceus /var/log/lynceus

with `/etc/lynceus` excluded deliberately -- the daemon must not be able to
rewrite the operator's config or the secrets in it. The atomic write needs
DIRECTORY write permission for its lock file and its tmp file, not just write
permission on the target, so every suppression action failed:

    POST /devices/<mac>/allowlist  ->  500

measured end to end with a real route, a real CSRF token and the config
directory at mode 0500.

The file is daemon-written STATE, not operator config, so it now lives beside
the database -- which the units already grant, on every install scope, without
weakening anything.

⚠️ The dangerous half of this change is not the move, it is the MIGRATION. An
install that already has suppressions has them in the old place. Getting that
wrong does not fail loudly: it silently un-suppresses every device the operator
had told the product to ignore, and the symptom is alerts they thought they had
turned off. The read-fallback and the seed-on-first-write are what stop that,
and the tests below are mostly about them rather than about the move.
"""

from __future__ import annotations

import os
import stat

import pytest
from fastapi.testclient import TestClient

from lynceus.allowlist import AllowlistEntry, add_ui_entry, load_allowlist, remove_ui_entry
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

MAC = "aa:bb:cc:dd:ee:01"


@pytest.fixture
def install(tmp_path):
    """A --system-shaped install: config dir and state dir are DIFFERENT."""
    config_dir = tmp_path / "etc"
    state_dir = tmp_path / "var"
    config_dir.mkdir()
    state_dir.mkdir()
    allowlist = config_dir / "allowlist.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    config = Config(
        db_path=str(state_dir / "lynceus.db"),
        allowlist_path=str(allowlist),
    )
    db = Database(config.db_path)
    db.upsert_device(MAC, "wifi", "Acme", 0, 1_700_000_000)
    yield config, db, config_dir, state_dir
    db.close()


def test_the_ui_file_resolves_into_the_state_directory(install):
    config, _db, config_dir, state_dir = install
    active = config.resolved_ui_allowlist_path()
    assert active == state_dir / "allowlist_ui.yaml"
    assert active.parent != config_dir, (
        "the daemon-written file is still in the operator's config directory"
    )


def test_the_legacy_location_is_still_computed(install):
    """It has to be, or the migration has nothing to read."""
    config, _db, config_dir, _state = install
    assert config.legacy_ui_allowlist_path() == config_dir / "allowlist_ui.yaml"


def test_no_legacy_path_when_the_two_directories_coincide(tmp_path):
    """A user-scope install, and every test fixture in this repo, puts the DB
    and the allowlist in one place. Reporting a legacy path there would make
    the migration read and seed from the file it is already writing."""
    allowlist = tmp_path / "allowlist.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    config = Config(db_path=str(tmp_path / "x.db"), allowlist_path=str(allowlist))
    assert config.resolved_ui_allowlist_path() == tmp_path / "allowlist_ui.yaml"
    assert config.legacy_ui_allowlist_path() is None


# --- the actual 500 -------------------------------------------------------


def _csrf_client(config, db):
    app = create_app(config, db)
    return TestClient(app)


@pytest.mark.parametrize("route", ["allowlist", "snooze"])
def test_suppression_works_with_a_read_only_config_dir(install, route):
    """⭐ THE MEASUREMENT. Config dir 0500, exactly as a --system install has it."""
    config, db, config_dir, _state = install
    client = _csrf_client(config, db)
    # ⚠️ Both halves, or the POST is rejected at the CSRF layer and the test
    # measures a 403 instead of the write it exists to measure. That is not
    # hypothetical — the first version of this test passed on a 403 while the
    # route was never reached, because `status_code < 500` is satisfied by a
    # rejection just as happily as by a success.
    token = client.get(f"/devices/{MAC}").cookies[CSRF_COOKIE_NAME]
    client.cookies.set(CSRF_COOKIE_NAME, token)

    original_mode = stat.S_IMODE(config_dir.stat().st_mode)
    os.chmod(config_dir, 0o500)
    try:
        data = {CSRF_FORM_FIELD: token}
        if route == "snooze":
            data["duration"] = "1h"
        response = client.post(
            f"/devices/{MAC}/{route}", data=data, follow_redirects=False
        )
    finally:
        os.chmod(config_dir, original_mode)

    assert response.status_code < 500, (
        f"POST /devices/<mac>/{route} returned {response.status_code} with the "
        "config directory read-only — this is the documented --system install "
        "mode, and every suppression action failed on it"
    )
    # ⚠️ `< 500` alone is a weak assertion: a 403 from a mis-built CSRF token
    # would satisfy it while the suppression never happened, and the test would
    # report the defect fixed on a request that never reached the writer. Pin
    # the OUTCOME.
    assert response.status_code in (200, 303), response.status_code
    active = config.resolved_ui_allowlist_path()
    assert active.exists(), "the route returned success and wrote nothing"
    assert MAC in active.read_text(encoding="utf-8"), (
        "the suppression the operator asked for is not in the file"
    )
    assert not (config_dir / "allowlist_ui.yaml").exists(), (
        "the daemon wrote into the operator's config directory"
    )


# --- the migration --------------------------------------------------------


def test_existing_suppressions_are_read_from_the_legacy_location(install):
    """An install upgrading across the move must not lose its suppressions the
    moment it restarts."""
    config, _db, config_dir, _state = install
    legacy = config_dir / "allowlist_ui.yaml"
    add_ui_entry(legacy, AllowlistEntry(pattern=MAC, pattern_type="mac", note="old"))

    merged = load_allowlist(
        config.allowlist_path,
        ui_path=config.resolved_ui_allowlist_path(),
        legacy_path=config.legacy_ui_allowlist_path(),
    )
    assert [e.pattern for e in merged.entries] == [MAC]


def test_the_first_new_write_carries_the_old_entries_across(install):
    """⛔ The one that silently loses data if it is wrong.

    Without the seed, the first UI write creates the active file, the
    read-fallback stops applying, and every suppression the operator had
    disappears in the same instant — while the click that caused it reports
    success.
    """
    config, _db, config_dir, state_dir = install
    legacy = config_dir / "allowlist_ui.yaml"
    add_ui_entry(legacy, AllowlistEntry(pattern=MAC, pattern_type="mac", note="old"))

    add_ui_entry(
        config.resolved_ui_allowlist_path(),
        AllowlistEntry(pattern="11:22:33:44:55:66", pattern_type="mac", note="new"),
        config.legacy_ui_allowlist_path(),
    )

    merged = load_allowlist(
        config.allowlist_path,
        ui_path=config.resolved_ui_allowlist_path(),
        legacy_path=config.legacy_ui_allowlist_path(),
    )
    assert sorted(e.pattern for e in merged.entries) == [
        "11:22:33:44:55:66",
        MAC,
    ], "the pre-move suppressions were dropped by the first write to the new file"


def test_removing_a_legacy_entry_does_not_drop_the_others(install):
    """The same trap on the removal path, and it is easier to miss: the entries
    are visible in the UI via the fallback, so "remove" looks like it should
    just work."""
    config, _db, config_dir, _state = install
    legacy = config_dir / "allowlist_ui.yaml"
    for mac in (MAC, "11:22:33:44:55:66", "22:33:44:55:66:77"):
        add_ui_entry(legacy, AllowlistEntry(pattern=mac, pattern_type="mac"))

    removed = remove_ui_entry(
        config.resolved_ui_allowlist_path(),
        MAC,
        "mac",
        config.legacy_ui_allowlist_path(),
    )
    assert removed is True

    merged = load_allowlist(
        config.allowlist_path,
        ui_path=config.resolved_ui_allowlist_path(),
        legacy_path=config.legacy_ui_allowlist_path(),
    )
    assert sorted(e.pattern for e in merged.entries) == [
        "11:22:33:44:55:66",
        "22:33:44:55:66:77",
    ]


def test_the_legacy_file_is_not_deleted(install):
    """Copy, not move. The daemon has no write access to that directory on the
    install this is all about, and a migration that needs a privilege the
    hardening denies is a migration that fails."""
    config, _db, config_dir, _state = install
    legacy = config_dir / "allowlist_ui.yaml"
    add_ui_entry(legacy, AllowlistEntry(pattern=MAC, pattern_type="mac"))
    add_ui_entry(
        config.resolved_ui_allowlist_path(),
        AllowlistEntry(pattern="11:22:33:44:55:66", pattern_type="mac"),
        config.legacy_ui_allowlist_path(),
    )
    assert legacy.exists()


def test_the_legacy_file_stops_counting_once_the_new_one_exists(install):
    """⛔ Never a merge. Two files that both counted would mean an entry the
    operator deleted staying live in the other one."""
    config, _db, config_dir, _state = install
    legacy = config_dir / "allowlist_ui.yaml"
    add_ui_entry(legacy, AllowlistEntry(pattern=MAC, pattern_type="mac"))
    add_ui_entry(
        config.resolved_ui_allowlist_path(),
        AllowlistEntry(pattern="11:22:33:44:55:66", pattern_type="mac"),
        config.legacy_ui_allowlist_path(),
    )
    # A LATER write to the legacy file (an old daemon still running, say) must
    # not resurrect itself into the active merge.
    add_ui_entry(legacy, AllowlistEntry(pattern="99:99:99:99:99:99", pattern_type="mac"))

    merged = load_allowlist(
        config.allowlist_path,
        ui_path=config.resolved_ui_allowlist_path(),
        legacy_path=config.legacy_ui_allowlist_path(),
    )
    assert "99:99:99:99:99:99" not in {e.pattern for e in merged.entries}


def test_promoting_a_watchful_entry_carries_the_legacy_ones_forward(install):
    """⛔ The promote path is a MUTATING path, so it must seed too.

    `_seed_from_legacy` says every mutating path has to call it, and the two
    obvious ones -- the add and the remove above -- do. `Database.
    promote_watchful_to_allowlist` is the third, and it is the easiest to miss:
    it lives in `db.py` rather than in the web layer, it takes its paths as
    keyword arguments, and `legacy_path` defaults to `None`, so dropping it is
    silent at every level. No type error, no lint error, no failing test.

    The cost of missing it is the same as the cost of missing the add path, and
    it is the worst outcome this file exists to prevent: on an upgraded install
    the operator promotes one watched device, that first write creates the
    active file without seeding, the read-fallback stops applying, and every
    suppression they already had is gone in the same instant -- while the click
    reports success.

    ⚠️ Keyed on BEHAVIOUR (are the old entries in the merged view afterwards)
    and not on the call site, so a future path that writes the UI file some
    other way is covered by the same assertion.
    """
    config, db, config_dir, _state_dir = install
    legacy = config_dir / "allowlist_ui.yaml"
    add_ui_entry(legacy, AllowlistEntry(pattern=MAC, pattern_type="mac", note="old"))

    active = config.resolved_ui_allowlist_path()
    assert not active.exists(), "precondition: the move has not happened yet"

    promoted = "11:22:33:44:55:66"
    db.upsert_device(promoted, "wifi", "Acme", 0, 1_700_000_000)
    alert_id = db.add_alert(
        ts=1_700_000_000,
        rule_name="watchlist_mac",
        mac=promoted,
        message="seen",
        severity="high",
    )
    entry_id = db.create_watchful_from_alert(
        alert_id, snooze_duration_seconds=None, now_ts=1_700_000_000
    )

    assert db.promote_watchful_to_allowlist(
        entry_id,
        allowlist_path=active,
        legacy_allowlist_path=config.legacy_ui_allowlist_path(),
        pattern=promoted,
        pattern_type="mac",
        note="known device",
        expires_at=None,
        now_ts=1_700_000_100,
    )

    merged = load_allowlist(
        config.allowlist_path,
        ui_path=active,
        legacy_path=config.legacy_ui_allowlist_path(),
    )
    assert sorted(e.pattern for e in merged.entries) == [promoted, MAC], (
        "promoting one watchful entry dropped the operator's pre-move "
        "suppressions: the promote path did not seed from the legacy file"
    )
