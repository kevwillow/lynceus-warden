"""Diagnostic: A2 — a malformed (corrupt-but-present) primary allowlist
must fail SAFE, not fail OPEN.

VERIFY-ONLY in spirit, but now carries hard asserts so it doubles as a
local regression check for the A2 fix. No production code is touched.

Before the fix (root cause): a parse error in the primary allowlist was
swallowed inside ``_load_primary`` (returned an empty ``Allowlist()`` with
no exception), so the mid-run reload — whose only fail-safe was
``except FileNotFoundError`` — treated it as a successful load of zero
entries and swapped the empty allowlist into ``self.allowlist``. That is
fail-OPEN: suppression lost, every previously-allowlisted device now
flows into rule eval, watchlist matches fire alerts + ntfy → storm.

After the fix:
  - ``_load_primary(..., raise_on_parse_error=True)`` RAISES
    ``AllowlistParseError`` on a parse/validation failure (the default
    call still returns empty, for the lenient web-UI / validate callers).
  - A *valid-but-empty* file still parses to an empty ``Allowlist`` with
    NO exception under either setting (the key regression guard).
  - Mid-run reload (``Poller._maybe_reload_allowlist``) catches
    ``AllowlistParseError`` and RETAINS the last-good allowlist — the
    same fail-SAFE stance as the deleted-file path.
  - Startup (``Poller.__init__``) with a corrupt primary starts with an
    empty allowlist (detection keeps running) AND flags the degraded
    state (``_allowlist_startup_degraded``) so a CRITICAL log + operator
    ntfy fire; a *missing* primary still raises (config error, must crash).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lynceus.allowlist import (
    AllowlistParseError,
    _load_allowlist_with_counts,
    _load_primary,
    load_allowlist,
)
from lynceus.config import Config
from lynceus.kismet import DeviceObservation
from lynceus.poller import Poller

pytestmark = pytest.mark.diagnostic


VALID_PRIMARY = """\
entries:
  - pattern: "aa:bb:cc:11:22:33"
    pattern_type: mac
    note: diag-seeded known-good device
"""

# A legitimately empty (valid YAML, zero entries) allowlist. This MUST
# keep loading as empty after the fix — it is the main regression risk:
# the fix must treat ONLY a parse failure as failure, never a valid file
# that happens to carry no entries.
VALID_BUT_EMPTY_PRIMARY = """\
entries: []
"""

# Corrupt-but-present: schema-invalid (unknown pattern_type fails the
# AllowlistEntry Literal + extra="forbid" Pydantic validation). The file
# EXISTS and is valid YAML -- it is the in-content corruption an operator
# produces by fat-fingering a field, which is exactly the mid-run reload
# trigger (mtime moves).
CORRUPT_PRIMARY = """\
entries:
  - pattern: "aa:bb:cc:11:22:33"
    pattern_type: not_a_real_pattern_type
"""

# A matching observation: the VALID primary suppresses this MAC.
OBS = DeviceObservation(
    mac="aa:bb:cc:11:22:33",
    device_type="wifi",
    first_seen=1_700_000_000,
    last_seen=1_700_000_100,
    rssi=-40,
    ssid="diag-ssid",
    oui_vendor=None,
    is_randomized=False,
)


def _bump_mtime(p: Path) -> None:
    """Force an mtime change so _maybe_reload_allowlist trips, regardless
    of filesystem timestamp granularity within one test run."""
    st = p.stat()
    os.utime(p, (st.st_atime + 10, st.st_mtime + 10))


def test_diag_a2_allowlist_failsafe(diag, tmp_path):
    primary = tmp_path / "allowlist.yaml"

    # -----------------------------------------------------------------
    diag.section("loader: corrupt -> default lenient empty; opt-in raises")
    diag.fixture(
        "_load_primary: missing file RAISES FileNotFoundError (unchanged). "
        "A corrupt-but-present file returns empty under the default "
        "(raise_on_parse_error=False, for the web-UI / validate callers) "
        "but RAISES AllowlistParseError when raise_on_parse_error=True "
        "(the poller opts in)."
    )

    primary.write_text(VALID_PRIMARY, encoding="utf-8")
    al_valid = load_allowlist(str(primary))
    assert al_valid.is_allowed(OBS, now_ts=1_700_000_500) is not None
    diag.observed(
        f"valid primary: load_allowlist -> {len(al_valid.entries)} entry, "
        f"is_allowed(OBS)={al_valid.is_allowed(OBS, now_ts=1_700_000_500)!r}"
    )

    primary.write_text(CORRUPT_PRIMARY, encoding="utf-8")
    direct_default = _load_primary(primary)
    assert direct_default.entries == []
    diag.observed(
        f"corrupt primary, default lenient: _load_primary -> "
        f"Allowlist(entries={len(direct_default.entries)}) -- empty, no raise "
        f"(preserves web-UI / validate behavior)"
    )

    with pytest.raises(AllowlistParseError):
        _load_primary(primary, raise_on_parse_error=True)
    with pytest.raises(AllowlistParseError):
        _load_allowlist_with_counts(str(primary), raise_on_parse_error=True)
    diag.observed(
        "corrupt primary, opt-in: _load_primary / _load_allowlist_with_counts "
        "(raise_on_parse_error=True) RAISE AllowlistParseError -- the signal "
        "the poller fails safe on"
    )

    # The key regression guard: a VALID-BUT-EMPTY file must NOT be
    # mistaken for a parse failure under the opt-in path.
    primary.write_text(VALID_BUT_EMPTY_PRIMARY, encoding="utf-8")
    al_empty, pc, uc = _load_allowlist_with_counts(
        str(primary), raise_on_parse_error=True
    )
    assert al_empty.entries == []
    assert al_empty.is_allowed(OBS, now_ts=1_700_000_500) is None
    diag.observed(
        f"valid-but-empty primary, opt-in: _load_allowlist_with_counts -> "
        f"entries={len(al_empty.entries)} primary_count={pc} ui_count={uc} "
        f"(NO raise) -- legitimate zero-entry allowlist still works as empty"
    )

    # Contrast: a *missing* file still raises FileNotFoundError (the
    # reload's deleted-file fail-safe hook), regardless of the flag.
    primary.unlink()
    with pytest.raises(FileNotFoundError):
        _load_primary(primary, raise_on_parse_error=True)
    diag.observed(
        "missing primary: _load_primary STILL raises FileNotFoundError "
        "(deleted-file fail-safe hook unchanged)"
    )

    # -----------------------------------------------------------------
    diag.section("mid-run reload: corrupt RETAINS last-good (fail-SAFE)")
    diag.fixture(
        "Poller._maybe_reload_allowlist now catches AllowlistParseError "
        "(alongside FileNotFoundError) and RETAINS self.allowlist instead "
        "of swapping in the empty merge."
    )
    primary.write_text(VALID_PRIMARY, encoding="utf-8")
    config = Config(
        kismet_fixture_path="",  # FakeKismet not needed; no poll runs here
        db_path=str(tmp_path / "diag_a2.db"),
        kismet_health_check_on_startup=False,
        allowlist_path=str(primary),
    )
    poller = Poller(config)
    assert poller.allowlist.is_allowed(OBS, now_ts=1_700_000_500) is not None
    diag.observed(
        f"Poller init (valid primary): entries={len(poller.allowlist.entries)} "
        f"is_allowed(OBS)="
        f"{poller.allowlist.is_allowed(OBS, now_ts=1_700_000_500)!r}"
    )

    # Operator fat-fingers an edit -> corrupt content, mtime moves.
    primary.write_text(CORRUPT_PRIMARY, encoding="utf-8")
    _bump_mtime(primary)
    poller._maybe_reload_allowlist()
    assert poller.allowlist.is_allowed(OBS, now_ts=1_700_000_500) is not None
    diag.observed(
        f"after corrupt reload: entries={len(poller.allowlist.entries)} "
        f"is_allowed(OBS)="
        f"{poller.allowlist.is_allowed(OBS, now_ts=1_700_000_500)!r}  "
        f"-> RETAINED last-good (fail-SAFE) -- suppression preserved"
    )

    # Restore valid, reload, then DELETE -> last-known retained too.
    primary.write_text(VALID_PRIMARY, encoding="utf-8")
    _bump_mtime(primary)
    poller._maybe_reload_allowlist()
    diag.observed(
        f"after valid reload: entries={len(poller.allowlist.entries)} (restored)"
    )
    primary.unlink()
    poller._maybe_reload_allowlist()
    assert poller.allowlist.is_allowed(OBS, now_ts=1_700_000_500) is not None
    diag.observed(
        f"after DELETE reload: entries={len(poller.allowlist.entries)} "
        f"is_allowed(OBS)="
        f"{poller.allowlist.is_allowed(OBS, now_ts=1_700_000_500)!r}  "
        f"-> retained last-known (fail-SAFE) -- deleted AND corrupt now "
        f"symmetric: both safe"
    )
    poller.db.close()

    # -----------------------------------------------------------------
    diag.section("startup: corrupt primary -> empty + degraded flag")
    diag.fixture(
        "Poller.__init__ with a corrupt primary: no last-good exists, so it "
        "starts with an empty allowlist (detection keeps running) and sets "
        "_allowlist_startup_degraded so a CRITICAL log + operator ntfy fire. "
        "A *missing* primary still raises (config error)."
    )
    corrupt_primary = tmp_path / "startup_allowlist.yaml"
    corrupt_primary.write_text(CORRUPT_PRIMARY, encoding="utf-8")
    config2 = Config(
        kismet_fixture_path="",
        db_path=str(tmp_path / "diag_a2_startup.db"),
        kismet_health_check_on_startup=False,
        allowlist_path=str(corrupt_primary),
    )
    poller2 = Poller(config2)  # must NOT raise
    assert poller2.allowlist.entries == []
    assert poller2._allowlist_startup_degraded is not None
    assert poller2.allowlist.is_allowed(OBS, now_ts=1_700_000_500) is None
    diag.observed(
        f"startup (corrupt primary): construction succeeded, "
        f"entries={len(poller2.allowlist.entries)} (empty -> detection runs), "
        f"_allowlist_startup_degraded={poller2._allowlist_startup_degraded!r} "
        f"(CRITICAL log + deferred operator ntfy fire)"
    )
    poller2.db.close()

    # Missing primary at startup still crashes (config error, fail-fast).
    missing_primary = tmp_path / "does_not_exist.yaml"
    config3 = Config(
        kismet_fixture_path="",
        db_path=str(tmp_path / "diag_a2_missing.db"),
        kismet_health_check_on_startup=False,
        allowlist_path=str(missing_primary),
    )
    with pytest.raises(FileNotFoundError):
        Poller(config3)
    diag.observed(
        "startup (missing primary): Poller.__init__ RAISES FileNotFoundError "
        "(config error must surface, not silently disable suppression)"
    )

    diag.notes(
        "A2 FIXED. The asymmetry is gone: a corrupt-but-present primary now "
        "fails SAFE on mid-run reload (retain last-good + WARNING), matching "
        "the already-safe deleted-file path, and degrades loudly but keeps "
        "running at startup (empty + CRITICAL + operator ntfy). The "
        "valid-but-empty case is unaffected (still empty, no false failure). "
        "Root-cause closure: _load_primary now SIGNALS a parse failure "
        "(AllowlistParseError under raise_on_parse_error=True) instead of "
        "silently returning empty, so the reload's last-good retention can "
        "apply; the default lenient path is preserved for the web-UI / "
        "validate callers that depend on it."
    )
