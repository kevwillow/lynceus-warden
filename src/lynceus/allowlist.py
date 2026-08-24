"""Allowlist management: load known-good devices and suppress matching alerts.

Storage shape is two YAML files:

- The operator-curated primary file (``allowlist.yaml``, path set via
  ``Config.allowlist_path``) is read-only from the daemon's perspective.
  Lynceus never writes to it, so hand-formatting, comments, and key
  ordering are preserved indefinitely.
- A daemon-managed sibling file (``<primary>_ui.yaml``, derived from
  the primary path) carries entries written by the UI mutation routes.
  Absent until the first UI write; the loader treats missing as empty.

Entries from both files are concatenated into a single in-memory
``Allowlist`` at load time. File order does not affect what gets
suppressed: ``is_allowed`` returns the STRONGEST matching entry, not the
first one — see its docstring for why the distinction is load-bearing.
"""

from __future__ import annotations

import contextlib
import fcntl
import logging
import os
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Literal, NamedTuple

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from lynceus.kismet import DeviceObservation
from lynceus.patterns import (
    canonicalize_mac_range_pattern,
    mac_in_mac_range,
    normalize_pattern,
    parse_mac_range_pattern,
)
from lynceus.yaml_duplicates import warn_duplicate_keys

logger = logging.getLogger(__name__)


class AllowlistParseError(Exception):
    """The primary allowlist file exists but could not be parsed/validated.

    Distinct from ``FileNotFoundError`` (missing file) and from a
    valid-but-empty file (which parses cleanly to an empty ``Allowlist``
    with no error). Raised only when ``_load_primary`` is asked to signal
    parse failures (``raise_on_parse_error=True``) so a caller can fail
    SAFE — retain its last-good allowlist — instead of swapping in an
    empty one and dropping every suppression (the fail-open ntfy-storm
    path A2 closes). The original YAML/validation cause is chained via
    ``__cause__``.
    """


# Pattern types accepted by the allowlist: EIGHT, matching the eight
# DB-delegation rule_types in rules.evaluate one for one, so an
# operator can express suppression in the same shape they watched in.
#
# ⚠️ Two watchlist pattern_types have NO allowlist counterpart, and the
# gap is not symmetric with how live they are:
#
#   ssid_pattern  REJECTED here -- and it is one of only THREE watchlist
#                 types that fire on the shipped ruleset (see Finding 32).
#                 An operator watching a substring can suppress a specific
#                 SSID or MAC, but cannot express "suppress this class".
#   imei_tac      REJECTED here, and dead on the watchlist side too --
#                 DeviceObservation carries no field for it at all.
#
# ⛔ This comment used to claim the allowlist covered "any shape the
# watchlist alerts on", and said seven where there are eight. It was
# wrong about ssid_pattern in the direction that hides a real gap: the
# sentence below names the exact failure mode, and the codebase had it.
# Whether a substring allowlist SHOULD exist is a live decision (a
# substring silences everything containing the needle) and is recorded in
# docs/AUDIT_REGISTER.md under "Reserved for Kev" -- not settled here.
#
# Drift between the two surfaces silently allows an alert to fire that an
# operator believed they had allowlisted, which is why the counterparts
# that DO exist are pinned by tests rather than by this comment.
AllowlistPatternType = Literal[
    "mac",
    "oui",
    "ssid",
    "mac_range",
    "ble_uuid",
    "ble_manufacturer_id",
    "drone_id_prefix",
    "ble_local_name",
]


class AllowlistEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern: str
    pattern_type: AllowlistPatternType
    note: str | None = None
    # Unix epoch seconds; None means permanent. Entries whose
    # ``expires_at`` is at or before the evaluation clock are silently
    # skipped by ``is_allowed`` — that is the "snooze expired" path.
    expires_at: int | None = None
    # Unix epoch seconds at which the entry was created. None for
    # operator hand-edits that omit the field; UI writes always populate
    # it so the alert-detail page can render "added YYYY-MM-DD HH:MM".
    added_at: int | None = None

    @model_validator(mode="after")
    def _bound_timestamps(self) -> AllowlistEntry:
        """Reject epochs `datetime.fromtimestamp` cannot represent.

        ⛔ `expires_at` was an unrestricted `int`, and the poller formats it for
        the suppression audit line:

            _dt.datetime.fromtimestamp(entry.expires_at, tz=_dt.UTC)

        Measured with a hand-edit typo of `expires_at: 99999999999999` — the
        kind an extra keypress produces — `process_observation` raised
        `ValueError: year 3170843 is out of range`, AFTER the device and
        sighting were persisted and both counters advanced. That device is then
        unprocessable on every tick it appears, and the poll watermark is held
        and eventually advanced past it, losing capture data.

        ⭐ Validating here rather than guarding the format call is the point:
        this is the system boundary where operator-authored YAML enters, and a
        bad value should be rejected once at load with a legible message rather
        than raising from an unrelated line every poll. A rejected entry is now
        handled gracefully by the loaders — the primary logs/raises per its
        `raise_on_parse_error` contract, and the UI sibling drops just that
        entry and keeps the others.
        """
        # `datetime.fromtimestamp(..., tz=UTC)` tops out at year 9999 and
        # cannot take a negative epoch on every supported platform.
        MAX_EPOCH = 253_402_300_799  # 9999-12-31T23:59:59Z
        for field in ("expires_at", "added_at"):
            value = getattr(self, field)
            if value is None:
                continue
            if value < 0 or value > MAX_EPOCH:
                raise ValueError(
                    f"{field}={value} is not a representable Unix timestamp "
                    f"(expected 0..{MAX_EPOCH})"
                )
        return self

    @model_validator(mode="after")
    def _normalize_pattern(self) -> AllowlistEntry:
        # All known pattern_types route through lynceus.patterns so
        # the canonical form stored here matches the canonical form
        # stored in watchlist.pattern for the same type — the
        # poll-time matcher relies on that equivalence.
        if self.pattern_type == "mac_range":
            prefix_hex, length = parse_mac_range_pattern(self.pattern)
            normalized = canonicalize_mac_range_pattern(prefix_hex, length)
        else:
            normalized = normalize_pattern(self.pattern_type, self.pattern)
        if normalized != self.pattern:
            object.__setattr__(self, "pattern", normalized)
        return self


class Allowlist(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entries: list[AllowlistEntry] = []

    def is_allowed(
        self,
        obs: DeviceObservation,
        now_ts: int | None = None,
    ) -> AllowlistEntry | None:
        """Return the STRONGEST matching entry if the device is allowlisted,
        else None.

        ⛔ "Strongest", not "first", and the difference is a real defect this
        function used to have. Since the hard/soft split landed, the returned
        entry's ``pattern_type`` is what decides whether suppression happens at
        all — ``poller.process_observation`` asks ``is_soft_attribute`` about
        *this one entry*. Returning whichever entry happened to sit earliest in
        the file therefore let an unrelated SOFT entry answer for a device the
        operator had explicitly allowlisted by MAC.

        🪤 Measured on the shipped ruleset, one device, one watchlist row, the
        same two allowlist entries — only the FILE ORDER differs:

            hard `mac` entry only                 -> suppressed
            hard `mac` first, then soft `name`    -> suppressed
            soft `name` first, then hard `mac`    -> *** 2 ALERTS, 2 SENT ***

        The operator wrote "ignore this MAC" and, because an unrelated
        headphones-by-name entry sat above it, kept getting paged. Nothing in
        the UI, the logs, or the file hints at the ordering dependency, and the
        module docstring positively asserted that order does not matter.

        ⭐ So: a HARD match wins over a SOFT one regardless of position, and
        position still breaks ties WITHIN a class (so the ``expires_at`` an
        audit line reports is stable for soft-only allowlists, as before).

        ⚠️ Expiry is still applied FIRST. An expired hard entry is not a match
        at all and must not out-rank a live soft one — otherwise a lapsed
        snooze would start silencing watchlist hits, which is the same defect
        pointing the other way.

        Allowlist matches take precedence over watchlist matches: callers
        should not produce alerts for allowlisted devices, and should emit
        an audit log when an allowlisted device would have matched a
        watchlist rule (see ``poller.poll_once`` for the canonical pattern).
        Without that audit signal, anyone with allowlist write access can
        silently disable a watchlist rule by adding the matching device.

        Entries whose ``expires_at`` is non-None and at or before ``now_ts``
        are silently skipped — those are snooze entries whose window has
        passed. ``now_ts`` defaults to the current wall clock; tests inject
        a deterministic value to make expiry behavior reproducible.

        Return value is the matched ``AllowlistEntry`` (truthy) or ``None``
        (falsy). Callers that only need a boolean can use it as such; the
        poller uses the returned entry's ``expires_at`` to annotate the
        audit log line for snooze-based suppressions.

        Per-type matching pairs 1:1 with ``rules.evaluate`` watchlist
        branches so suppression and alerting see the same truth. See
        ``_entry_matches`` for the per-type predicate.
        """
        if now_ts is None:
            now_ts = int(time.time())
        first_soft: AllowlistEntry | None = None
        for entry in self.entries:
            if entry.expires_at is not None and entry.expires_at <= now_ts:
                continue
            if not _entry_matches(entry, obs):
                continue
            if not is_soft_attribute(entry.pattern_type):
                # A radio-level identifier is the operator's strongest
                # statement about this device; nothing later can outrank it,
                # so returning on the first one keeps this O(n) with no
                # second pass.
                return entry
            if first_soft is None:
                first_soft = entry
        return first_soft


#: Allowlist pattern types split by whether the ATTACKER controls the value.
#:
#: ⛔ HARD identifiers are properties of the radio itself. A device cannot
#: present someone else's MAC without actively spoofing the address it
#: transmits on, which is a different and more detectable act than choosing
#: what to call itself.
#:
#: ⛔ SOFT attributes are FREE TEXT the device puts in its own advertisement.
#: A BLE peripheral names itself; it advertises whatever service UUIDs and
#: manufacturer ID it likes. Suppressing on one of these means "ignore anything
#: that SAYS it is X", and anything can say it is X.
#:
#: 🪤 Measured before this split existed. Operator allowlists their own
#: headphones by name -- the obvious, documented use of `ble_local_name`:
#:
#:     the real headphones                mac=aa:bb:cc:dd:ee:01  suppressed=YES
#:     AN ATTACKER broadcasting that name mac=de:ad:be:ef:00:99  suppressed=YES
#:     the same attacker, not spoofing    mac=de:ad:be:ef:00:99  suppressed=no
#:
#: One freely-chosen advertisement field silenced everything for a completely
#: different MAC -- including the operator's own HIGH-severity watchlist entry
#: for that MAC. An attacker only has to name themselves after something the
#: operator allowlisted.
#:
#: ⛔ Tightening allowlisting to MAC-only is NOT the fix and would break the
#: feature: BLE devices use randomised, rotating addresses, which is precisely
#: why name/UUID/manufacturer matching exists at all.
HARD_ALLOWLIST_PATTERN_TYPES: frozenset[str] = frozenset(
    {"mac", "mac_range", "oui"}
)

#: Everything else. Kept as an explicit complement rather than "not hard" so a
#: NEW pattern_type cannot silently inherit full suppressing power -- see
#: `assert_allowlist_pattern_types_are_classified`.
SOFT_ALLOWLIST_PATTERN_TYPES: frozenset[str] = frozenset(
    {
        "ssid",
        "ssid_pattern",
        "ble_uuid",
        "ble_manufacturer_id",
        "ble_local_name",
        "drone_id_prefix",
        "imei_tac",
    }
)


def is_soft_attribute(pattern_type: str) -> bool:
    """True when the matched value is chosen by the device, not by the radio.

    A soft match may suppress ambient noise -- new-device notices and the like
    -- but must never silence an EXPLICIT watchlist hit, because the operator
    naming a MAC is a deliberate instruction and the advertisement field is
    attacker-controlled.
    """
    return pattern_type not in HARD_ALLOWLIST_PATTERN_TYPES


def _entry_matches(entry: AllowlistEntry, obs: DeviceObservation) -> bool:
    """Per-pattern_type predicate paired with ``rules.evaluate``.

    Each branch mirrors the in-memory match-shape the watchlist uses
    for the same pattern_type, so an operator who allowlists a device
    by any one of its identifiers blocks the corresponding watchlist
    alert. Types whose observation field is None (e.g. a non-BLE
    record evaluated against a ``ble_uuid`` entry) short-circuit to
    False — the existing watchlist branches do the same.
    """
    pt = entry.pattern_type
    if pt == "mac":
        return obs.mac == entry.pattern
    if pt == "oui":
        return obs.mac.startswith(entry.pattern + ":")
    if pt == "ssid":
        return obs.ssid is not None and obs.ssid == entry.pattern
    if pt == "mac_range":
        return mac_in_mac_range(obs.mac, entry.pattern)
    if pt == "ble_uuid":
        return entry.pattern in obs.ble_service_uuids
    if pt == "ble_manufacturer_id":
        return (
            obs.ble_manufacturer_id is not None
            and obs.ble_manufacturer_id == entry.pattern
        )
    if pt == "drone_id_prefix":
        # Leading-substring, mirroring the watchlist matcher (Argus
        # MAC-357). The stored entry is an LCP prefix; a captured wire
        # serial is longer, so equality would never suppress. An
        # operator suppressing one exact serial enters the full serial.
        return (
            obs.drone_id_prefix is not None
            and obs.drone_id_prefix.startswith(entry.pattern)
        )
    if pt == "ble_local_name":
        return (
            obs.ble_local_name is not None
            and obs.ble_local_name == entry.pattern
        )
    # AllowlistPatternType keeps this branch unreachable; the explicit
    # False keeps mypy / type-checkers happy without raising on data
    # that has already passed Pydantic validation.
    return False


def ui_filename(primary_path: Path) -> str:
    """Filename for the daemon-managed allowlist file.

    ``allowlist.yaml`` → ``allowlist_ui.yaml``. Uses ``Path.with_stem`` so
    an unusual extension (``.yml``) carries across cleanly rather than being
    silently rewritten.
    """
    return primary_path.with_stem(primary_path.stem + "_ui").name


def derive_ui_path(primary_path: Path) -> Path:
    """⛔ The LEGACY location: beside the operator's own allowlist.

    ``/etc/lynceus/allowlist.yaml`` → ``/etc/lynceus/allowlist_ui.yaml``.

    This is where the file lived until the state-directory move, and it is
    kept for exactly two jobs: the read-fallback that lets an existing
    install keep its suppressions, and the seed on first write. Nothing
    should WRITE here.

    Why it moved. The file is daemon-written STATE, not operator config, and
    it was being written into the operator's config directory. On a
    ``--system`` install that is ``/etc/lynceus``, and the units grant
    ``ReadWritePaths=/var/lib/lynceus /var/log/lynceus`` -- ``/etc/lynceus``
    is excluded deliberately, so the daemon must not be able to rewrite the
    operator's own config or the secrets in it.

    The atomic write needs DIRECTORY write permission for its lock file and
    its tmp file, not just write permission on the target, so the whole
    suppression surface failed. Measured end to end, real route, real CSRF
    token, config dir chmod 0500:

        POST /devices/<mac>/allowlist  ->  500

    ⇒ On the documented install mode, "allowlist this device" and "snooze"
    both returned a server error. Every one of them.
    """
    return primary_path.with_stem(primary_path.stem + "_ui")


def _validate_ui_entries(raw: object, ui_path: Path) -> list[AllowlistEntry]:
    """Validate UI entries ONE AT A TIME, keeping the ones that are good.

    ⛔ This used to be `Allowlist(**data).entries` — all-or-nothing. A single
    malformed entry therefore discarded every other suppression in the file,
    and combined with the read-modify-write path below that turned a partial
    corruption into a permanent one. Measured on a file truncated mid-write
    (a power cut, or SD-card rot on the Pi this runs on):

        5 UI suppressions -> truncated -> readable: 0
        operator adds one more via the UI          -> readable: 0
        ...and the malformed entry is now written back, forever

    ⭐ The root cause was that the read path and the write path used DIFFERENT
    validators: this function checked the schema, `_read_ui_yaml` did not. So a
    file the reader rejected, the writer faithfully preserved and extended.
    Every subsequent "Allowlist this device" click reported success and did
    nothing, because the file could never be read again.

    Dropping per entry fixes both directions at once: a truncated file keeps
    the suppressions that survived, and the next UI write rewrites the file
    without the bad entry, repairing it.
    """
    # ⚠️ Keep the "could not be parsed" phrasing on these two branches. It is
    # the string operators grep journalctl for, and `test_split_loader_
    # malformed_ui_logs_warning_treats_as_empty` pins it — the same
    # stable-prefix reasoning as "Allowlist suppressed watchlist hit:".
    if not isinstance(raw, dict):
        logger.warning(
            "allowlist UI file %s could not be parsed (not a mapping); "
            "treating as empty",
            ui_path,
        )
        return []
    items = raw.get("entries")
    if items is None:
        # ⚠️ An empty mapping is the ordinary "nothing written yet" state and
        # must stay silent. A NON-empty mapping with no `entries` key is a
        # malformed file — rubbish that happened to parse as YAML, e.g.
        # `:::not valid yaml:::` becomes `{':::not valid yaml::': None}`.
        #
        # The previous `Allowlist(**data)` rejected that via `extra="forbid"`
        # and logged. Returning [] silently here would be a REGRESSION: the
        # operator loses every UI suppression and nothing says so. Caught by
        # `test_split_loader_malformed_ui_logs_warning_treats_as_empty`.
        if raw:
            logger.warning(
                "allowlist UI file %s could not be parsed (no 'entries' key; "
                "found %s); treating as empty",
                ui_path,
                ", ".join(sorted(map(str, raw))[:5]),
            )
        return []
    if not isinstance(items, list):
        logger.warning(
            "allowlist UI file %s could not be parsed ('entries' is not a "
            "list); treating as empty",
            ui_path,
        )
        return []
    good: list[AllowlistEntry] = []
    dropped = 0
    for item in items:
        try:
            good.append(AllowlistEntry(**item))
        except Exception as exc:
            dropped += 1
            logger.warning(
                "dropping malformed allowlist UI entry %r in %s (%s)",
                item,
                ui_path,
                exc,
            )
    if dropped:
        # ⚠️ Loud on purpose. Every dropped entry is a suppression the operator
        # asked for and will now stop getting, so they need to know before the
        # alerts start rather than after.
        logger.error(
            "allowlist UI file %s: %d entr%s dropped as malformed, %d kept. "
            "Suppressions from the dropped entries are NO LONGER ACTIVE.",
            ui_path,
            dropped,
            "y" if dropped == 1 else "ies",
            len(good),
        )
    return good


def _load_ui_entries(
    ui_path: Path, legacy_path: Path | None = None
) -> list[AllowlistEntry]:
    """Read entries from the daemon-managed UI file.

    Absent file → empty list (the normal state before any UI write).
    Malformed entries → WARNING and skipped individually; the rest are kept.
    The daemon must not crash because the UI sibling got corrupted, and it must
    not throw away good suppressions because of one bad neighbour.

    ⛔ Duplicate keys are reported here too, and the reason this file was once
    exempted was an assumption rather than a measurement: *"daemon-managed, not
    operator-managed"*. It is plain YAML in the config directory beside a file
    this project has already proven operators hand-edit. Measured, a duplicate
    `pattern:` here does exactly what it does in the primary -- the device the
    operator meant keeps alerting, one they never named is silenced, and the
    note still reads what they wrote.

    ``legacy_path`` is the file's home before it moved to the state directory.
    It is read ONLY when the active file does not exist, which is exactly the
    state an install upgrading across the move is in. The first UI write seeds
    the new file from it (``add_ui_entry``), so the fallback stops being
    consulted the moment the operator touches a suppression.

    ⛔ Never a MERGE of the two. Two files that both counted would mean an
    entry the operator deleted through the UI staying live in the other one --
    a suppression they can neither see nor remove, on the surface whose whole
    job is to stop alerts.
    """
    if not ui_path.exists():
        if legacy_path is not None and legacy_path.exists():
            logger.info(
                "reading UI allowlist from its pre-move location %s; it will "
                "be copied to %s on the next suppression written from the UI",
                legacy_path,
                ui_path,
            )
            return _load_ui_entries(legacy_path)
        return []
    try:
        with open(ui_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        logger.warning(
            "allowlist UI file %s could not be parsed (%s); treating as empty",
            ui_path,
            exc,
        )
        return []
    warn_duplicate_keys(ui_path, logger=logger, subject="allowlist UI file")
    return _validate_ui_entries(data, ui_path)


def _warn_on_duplicate_keys(primary_path: Path) -> None:
    """WARN for each duplicate key in the operator-curated primary file.

    ``yaml.safe_load`` keeps the LAST duplicate, silently. Measured on a
    hand-edited file with a stray second ``pattern:`` line:

        entries:
          - pattern: "ac:de:48:00:11:22"   <- the device they meant
            pattern: "ac:de:48:99:99:99"   <- the stray line
            pattern_type: mac
            note: kev phone

        stored pattern                 ac:de:48:99:99:99  (note: 'kev phone')
        is_allowed(ac:de:48:00:11:22)  False  <- the device they MEANT alerts
        is_allowed(ac:de:48:99:99:99)  True   <- one they never named is silent

    So the entry count is right, the file is valid, every surface says fine,
    and the suppression covers a device the operator never wrote down. A
    duplicate top-level ``entries:`` key is the same mechanism one level up:
    the first block is discarded whole.

    ⚠️ WARN rather than reject, deliberately. A duplicate key is not grounds
    to drop every other suppression in the file -- that is the all-or-nothing
    failure `_validate_ui_entries` exists to undo. `lynceus-validate` reports
    the same finding as an ERROR with line numbers, which is the loud surface;
    this line is for the operator who never runs it.

    ⛔ Swallows its own failures, and that is load-bearing rather than tidy.
    This is a DIAGNOSTIC: it re-reads a file the caller has already parsed, and
    it runs inside `_load_primary`'s `except Exception` where any raise would
    be reported as "could not be parsed" and, under `raise_on_parse_error`,
    become an `AllowlistParseError` -- which at startup means the poller sets
    an empty allowlist and logs SUPPRESSION DISABLED. A helper whose only job
    is to add a warning must never be able to turn a loadable file into a
    disabled one. `yaml.compose` on a pathological file can still raise past
    the OSError/YAMLError that `find_duplicate_keys` handles (RecursionError
    on deep nesting, MemoryError), so the broad catch is the point.

    ⇒ **Delegates to `yaml_duplicates.warn_duplicate_keys`**, which owns that
    property for every loader. This function used to implement it here, and
    keeping a second copy was an overclaim in the PR that introduced the shared
    one ("implemented once so the property is tested once" -- while this copy
    stayed live). The copy also had the same hole the shared one did: it
    wrapped only the DETECTION call, leaving `logger.warning` outside the try,
    so a raising handler propagated into `_load_primary`'s parse-failure path
    and produced exactly the empty allowlist this docstring warns about.
    """
    warn_duplicate_keys(
        primary_path, logger=logger, subject="allowlist primary file"
    )


def _load_primary(
    primary_path: Path, *, raise_on_parse_error: bool = False
) -> Allowlist:
    """Read the operator-curated primary file.

    Missing primary always raises ``FileNotFoundError`` — that case is
    a configuration error (``allowlist_path`` pointing at nothing) and
    must surface, not silently empty the allowlist.

    A malformed-but-present primary (YAML syntax error or schema /
    validation failure) is handled per ``raise_on_parse_error``:

    - ``False`` (default): log ERROR and return an empty ``Allowlist``.
      The lenient web-UI read views and the validate CLI rely on this —
      a syntax slip must not 500 a page or crash the tool.
    - ``True``: log ERROR and raise ``AllowlistParseError``. The poller
      opts in so a parse failure fails SAFE (retain the last-good
      allowlist on mid-run reload; degrade loudly at startup) rather
      than fail-OPEN — an empty allowlist drops every suppression and
      storms ntfy (A2).

    A *valid-but-empty* file never reaches the except branch: it parses
    cleanly to an empty ``Allowlist`` and returns normally under either
    setting, so legitimate zero-entry allowlists keep working as empty.
    """
    if not primary_path.exists():
        raise FileNotFoundError(str(primary_path))
    try:
        with open(primary_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        _warn_on_duplicate_keys(primary_path)
        return Allowlist(**data)
    except Exception as exc:
        logger.error(
            "allowlist primary file %s could not be parsed (%s)%s",
            primary_path,
            exc,
            "" if raise_on_parse_error else "; treating as empty",
        )
        if raise_on_parse_error:
            raise AllowlistParseError(str(primary_path)) from exc
        return Allowlist()


def _load_allowlist_with_counts(
    path: str,
    *,
    raise_on_parse_error: bool = False,
    ui_path: Path | None = None,
    legacy_path: Path | None = None,
) -> tuple[Allowlist, int, int]:
    """Load the merged allowlist along with per-source entry counts.

    Returns ``(allowlist, primary_count, ui_count)``. The poller uses
    the counts for its reload INFO line; ``load_allowlist`` drops them.


    ``ui_path`` is where the daemon-written UI file actually lives, and
    ``legacy_path`` is its home before the state-directory move (read only when
    ``ui_path`` does not exist yet). Both default to None, which reproduces the
    pre-move behaviour of a plain sibling -- that keeps every caller that has no
    Config in scope working unchanged, and the callers that DO have one
    (`Config.resolved_ui_allowlist_path` / `legacy_ui_allowlist_path`) pass them.

    ``raise_on_parse_error`` is forwarded to ``_load_primary``: when
    True a malformed primary raises ``AllowlistParseError`` instead of
    loading empty, so the poller can fail safe. The UI sibling stays
    lenient regardless (a corrupt sibling only WARNINGs to empty) — it
    is daemon-managed and not the load-bearing suppression surface.
    """
    primary_path = Path(path)
    primary = _load_primary(primary_path, raise_on_parse_error=raise_on_parse_error)
    ui_entries = _load_ui_entries(
        ui_path if ui_path is not None else derive_ui_path(primary_path),
        legacy_path,
    )
    if not ui_entries:
        return primary, len(primary.entries), 0
    merged = Allowlist(entries=list(primary.entries) + ui_entries)
    return merged, len(primary.entries), len(ui_entries)


def load_allowlist(
    path: str, *, ui_path: Path | None = None, legacy_path: Path | None = None
) -> Allowlist:
    """Load the allowlist from the operator file plus its UI sibling.

    ``path`` is the operator-curated primary file; the UI file is merged in
    transparently if present.

    ``ui_path`` is where the daemon-written UI file actually lives, and
    ``legacy_path`` is its home before the state-directory move (read only when
    ``ui_path`` does not exist yet). Both default to None, which reproduces the
    pre-move behaviour of a plain sibling -- that keeps every caller that has no
    Config in scope working unchanged, and the callers that DO have one
    (`Config.resolved_ui_allowlist_path` / `legacy_ui_allowlist_path`) pass them.
    """
    merged, _primary_count, _ui_count = _load_allowlist_with_counts(
        path, ui_path=ui_path, legacy_path=legacy_path
    )
    return merged


# Entry source discriminator used by the management UI. The /allowlist
# table renders a badge per row and refuses bulk-remove on primary
# entries; both signals key off this string.
EntrySource = Literal["primary", "ui"]


def load_allowlist_with_source(
    path: str, *, ui_path: Path | None = None, legacy_path: Path | None = None
) -> list[tuple[AllowlistEntry, EntrySource]]:
    """Load all allowlist entries tagged by source file.

    Returns a list of ``(entry, "primary" | "ui")`` tuples preserving
    each file's internal order (primary entries first, then UI). The
    /allowlist management view uses the tags to render a source badge
    and to refuse UI-side mutations on primary-file entries — the
    daemon never writes to ``allowlist.yaml``, so operator-curated
    rows are read-only from the UI by construction.

    Missing primary still raises ``FileNotFoundError`` for parity
    with ``load_allowlist``; a missing UI file silently contributes
    zero entries (the normal pre-first-UI-write state).

    ``ui_path`` is where the daemon-written UI file actually lives, and
    ``legacy_path`` is its home before the state-directory move (read only when
    ``ui_path`` does not exist yet). Both default to None, which reproduces the
    pre-move behaviour of a plain sibling -- that keeps every caller that has no
    Config in scope working unchanged, and the callers that DO have one
    (`Config.resolved_ui_allowlist_path` / `legacy_ui_allowlist_path`) pass them.
    """
    primary_path = Path(path)
    primary = _load_primary(primary_path)
    ui_entries = _load_ui_entries(
        ui_path if ui_path is not None else derive_ui_path(primary_path),
        legacy_path,
    )
    tagged: list[tuple[AllowlistEntry, EntrySource]] = [
        (e, "primary") for e in primary.entries
    ]
    tagged.extend((e, "ui") for e in ui_entries)
    return tagged


def _atomic_write_yaml(path: Path, payload: dict) -> None:
    """Write ``payload`` to ``path`` atomically via tmpfile + ``os.replace``.

    The poller may stat / read the same file concurrently. ``os.replace``
    is atomic on both POSIX and Windows, so readers see either the old
    content or the new content, never a half-written file.

    ⛔ Atomic is not the same as DURABLE, and this helper had only the first
    half. Without an ``fsync`` before the replace, the rename can reach disk
    ahead of the data, so a power loss leaves the file present and empty or
    partially written — the corruption `_validate_ui_entries` exists to survive,
    arriving through the one path that was supposed to prevent it. On the
    SD-card-backed Pi this targets, that is not a theoretical crash.

    ⭐ The sibling helper ``cli.bootstrap_kismet._atomic_write_bytes`` already
    does ``flush()`` + ``fsync()`` before its ``os.replace``. Two atomic-write
    helpers in one codebase disagreeing about durability is the bug; this makes
    them agree.

    ⚠️ Residual, deliberately not fixed here: the parent DIRECTORY is not
    fsynced, so the rename itself is not guaranteed durable. That failure is
    benign in a way this one was not — losing the rename leaves the previous
    complete file, whereas losing the data left a corrupt one. Fixing it means
    an extra directory fsync per UI write, which is a cost the sibling helper
    also declined to pay.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(payload, f, sort_keys=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmpname, path)
    except Exception:
        try:
            os.unlink(tmpname)
        except OSError:
            pass
        raise


def ui_lock_path(ui_path: Path) -> Path:
    """Path of the advisory lock guarding read-modify-write on ``ui_path``.

    ⛔ A SEPARATE file, and that is the whole point — see ``_ui_write_lock``.
    """
    return ui_path.with_name(ui_path.name + ".lock")


@contextlib.contextmanager
def _ui_write_lock(ui_path: Path) -> Iterator[None]:
    """Serialise read-modify-write of the UI allowlist ACROSS PROCESSES.

    Every mutator here is read → modify → ``os.replace``. Two of them running
    at once both read the same starting state and the second write discards the
    first one's change. Measured on the real functions, with a sequential
    control that keeps both:

    - two concurrent ``add_ui_entry`` calls → one suppression **silently gone**,
      and both callers were told they succeeded;
    - the poller's ``repair_future_dated_ui_entries`` racing one UI click →
      the operator's click **discarded**, with no operator concurrency at all.

    ⛔ **A ``threading.Lock`` cannot fix this.** The repair runs in the POLLER
    and the clicks run in the web process — different processes, so an
    in-process lock serialises neither. Hence ``fcntl.flock``, which the kernel
    holds against the open file description rather than the process, so an
    ordinary crash or ``SIGKILL`` releases it when the descriptor is closed.

    ⚠️ Stated precisely because the obvious phrasing is wrong: that is release
    on *descriptor* close, not on *holder* death. A process that forks while
    holding this lock shares the open file description with its child, and the
    lock survives the original holder's death for as long as the child lives.
    Measured. Nothing here forks while holding it — the mutators are called
    from request handlers and the poll loop — but a future caller that did
    would not get the guarantee this sentence used to promise.

    ⛔ **The lock is NOT taken on ``ui_path`` itself, and that is load-bearing.**
    ``_atomic_write_yaml`` finishes with ``os.replace``, which swaps the INODE
    behind the path. A writer that locked the old inode still holds a lock on a
    file no longer reachable by name, so the next writer opens the NEW inode and
    acquires it immediately — two writers inside the critical section at once.
    Measured: locking the data file gives mutual exclusion that a single write
    silently dissolves. The lock file is never replaced, so it stays stable.

    ⚠️ Scope, stated rather than implied: this serialises the mutators in THIS
    module. It does not make ``load_allowlist`` take the lock — readers do not
    need it, because ``os.replace`` already guarantees a reader sees either the
    whole old file or the whole new one. It also does not protect the
    operator-curated primary file, which the daemon never writes.

    ⚠️ POSIX-only, matching the project's declared
    ``Operating System :: POSIX :: Linux``. There is deliberately no silent
    no-op fallback: a lock that quietly does nothing would report success while
    losing exactly the writes this exists to keep.
    """
    lock_path = ui_lock_path(ui_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        # Closing the descriptor releases the flock; doing it in `finally`
        # means a raising mutator cannot strand the lock and wedge the poller.
        os.close(fd)


def _read_ui_yaml(ui_path: Path) -> dict:
    """Read the current UI-file contents, returning a ``{"entries": [...]}`` dict.

    Absent file or missing/invalid ``entries`` key → empty list shape.
    The dict is round-tripped via ``yaml.safe_dump`` after mutation, so
    any extra top-level keys an operator wrote there get dropped on
    write — but the UI file is daemon-managed, not operator-managed,
    so that is acceptable.
    """
    if not ui_path.exists():
        return {"entries": []}
    try:
        with open(ui_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        logger.warning(
            "allowlist UI file %s could not be parsed during read-modify-write "
            "(%s); starting from empty entries list",
            ui_path,
            exc,
        )
        data = {}
    # ⛔ Reported BEFORE the round-trip below, because the round-trip destroys
    # the evidence. Measured: a UI file carrying a duplicate `pattern:` names
    # both addresses, so an operator reading it can still see the stray line.
    # One "Allowlist this device" click later, `yaml.safe_dump` has written
    # back only the winner -- the address they actually meant is GONE from the
    # file and it reads as though they had always chosen the other one. That
    # makes this path strictly worse than the primary's, where the duplicate
    # stays visible forever, and it is why "daemon-managed, so it does not
    # matter" was the wrong call: the laundering is done BY the daemon.
    warn_duplicate_keys(ui_path, logger=logger, subject="allowlist UI file")
    if not isinstance(data.get("entries"), list):
        data["entries"] = []
    # ⛔ Validate through the SAME path the reader uses, then re-serialise.
    #
    # This function used to hand back whatever YAML happened to contain. That
    # made the writer strictly more permissive than the reader, so an entry the
    # reader rejected got faithfully appended-to and written back on the next UI
    # click — persisting the corruption forever while every read returned
    # nothing. Measured: 5 suppressions, a truncation, one "Allowlist this
    # device" click, and the file was permanently unreadable with the operator
    # told nothing.
    #
    # ⭐ Round-tripping through validation makes any UI write REPAIR the file
    # instead of entrenching the damage: the surviving entries are rewritten
    # cleanly and the malformed one is gone.
    validated = _validate_ui_entries(data, ui_path)
    data["entries"] = [e.model_dump(mode="json", exclude_none=True) for e in validated]
    return data


def _seed_from_legacy(
    data: dict, ui_path: Path, legacy_path: Path | None
) -> dict:
    """Fold the pre-move file's entries into ``data``, once, before a write.

    ⛔ Every mutating path must call this, not just the ADD path, and the
    removals are the reason. While only the legacy file exists, the reader
    falls back to it — so an operator sees those suppressions in the UI. If
    "remove" wrote a fresh active file without carrying them, the removal
    would report success, the entry the operator deleted would come back the
    moment the fallback stopped applying... and every OTHER suppression they
    had would vanish in the same instant. Fixing a fail-open by hand is how a
    fail-closed gets shipped.

    Copy, not move. The legacy file lives in the operator's config directory,
    which the units deliberately keep the daemon out of — deleting it is not
    something this process can or should do. It simply stops being read once
    the active file exists.

    Must be called INSIDE ``_ui_write_lock`` so two processes cannot both
    decide the active file is absent and both seed it.
    """
    if legacy_path is None or ui_path.exists() or not legacy_path.exists():
        return data
    carried = _read_ui_yaml(legacy_path).get("entries") or []
    if not carried:
        return data
    logger.info(
        "carrying %d UI allowlist entr%s forward from %s to %s",
        len(carried),
        "y" if len(carried) == 1 else "ies",
        legacy_path,
        ui_path,
    )
    data["entries"] = list(carried) + list(data["entries"])
    return data


def add_ui_entry(
    ui_path: Path, entry: AllowlistEntry, legacy_path: Path | None = None
) -> None:
    """Append ``entry`` to the daemon-managed UI file.

    File is created on first call. Existing entries are preserved.
    Write is atomic (tmpfile + ``os.replace``) and the whole
    read-modify-write is serialised across processes by ``_ui_write_lock``.

    ⛔ This used to say concurrent writes were "last-write-wins by file mtime —
    acceptable given the UI cadence is operator-driven (manual button clicks)".
    Measured, that was not a trade-off, it was a lost suppression: two clicks
    close together kept ONE, and both requests reported success. No request
    rate is needed — a double-click, two browser tabs, or the poller's repair
    landing on the same file is enough.
    """
    with _ui_write_lock(ui_path):
        data = _read_ui_yaml(ui_path)
        data = _seed_from_legacy(data, ui_path, legacy_path)
        data["entries"].append(entry.model_dump(mode="json", exclude_none=True))
        _atomic_write_yaml(ui_path, data)


#: Matches ``webui.clock.CLOCK_BEHIND_TOLERANCE_SECONDS`` and, through it,
#: ``poller.CLOCK_JUMP_TOLERANCE_SECONDS``. Deliberately NOT imported: `webui`
#: imports `allowlist`, so importing back would invert the layering for one
#: integer. ``test_the_clock_tolerances_stay_equal`` asserts they stay equal
#: instead -- the same pattern, and the same reason, as `webui/clock.py`'s own
#: copy of the poller constant.
#:
#: ⚠️ Without it, an ordinary NTP slew of a second or two between two clicks
#: reads as a backward jump. What it buys the operator is a second of a snooze;
#: what it costs them is a warning that their clock is broken when it is not.
UI_ORDER_TOLERANCE_SECONDS = 300


class ImpossibleUiEntry(NamedTuple):
    """A UI suppression stamped EARLIER than one written before it.

    Named rather than a bare tuple for the reason ``db.ImpossibleSnooze``
    records: these fields are rendered into an operator-facing message, and a
    positional mistake there is invisible to tests that only check values.

    ``duration_seconds`` is ``expires_at - added_at`` -- what the operator
    actually asked for, which survives the wrong clock because both stamps moved
    together.
    """

    pattern: str
    pattern_type: str
    added_at: int
    duration_seconds: int
    #: The ``added_at`` of the earlier-written entry this one contradicts, and
    #: its pattern -- so the message can name the evidence rather than assert a
    #: verdict.
    preceded_by_pattern: str
    preceded_by_added_at: int
    #: How far the clock had moved backward by the time this row was written.
    behind_by_seconds: int


def find_impossible_ui_entries(
    ui_path: Path, now_ts: int
) -> list[ImpossibleUiEntry]:
    """Expired UI suppressions stamped before an entry written earlier.

    ⭐ **The third of the four deadline backends to get a BACKWARD reporter, and
    the one Finding 56 recorded as unreachable.** That record was right about the
    discriminator it had and wrong about the conclusion: it says this file *"has
    no ``schema_migrations`` row to compare against, so the ordering
    discriminator does not exist for it."* No ``schema_migrations`` row exists
    here -- but **a different ordering fact does**, and it does not need one.

    **The fact: this file's list order IS its write order.** ``add_ui_entry``
    appends; ``remove_ui_entry`` and ``bulk_remove_ui_entries`` filter;
    ``repair_future_dated_ui_entries`` rebuilds in place; ``_validate_ui_entries``
    keeps survivors in order. **Nothing in this module sorts.** So an entry
    sitting BELOW another while claiming an EARLIER ``added_at`` is a
    contradiction between two things the file records independently -- position
    and timestamp -- and the only way to produce it is a clock that moved
    backward between the two writes. No reference to the reading clock is made,
    which is why it works where clock reasoning does not.

    ⛔ **This is a DISAGREEMENT, not a proof about which clock was right**, and
    the caller must phrase it that way -- exactly as ``db.find_impossible_
    rule_type_snoozes`` must. Either the later row was stamped behind, or the
    earlier row was stamped ahead. Nothing local can say which.

    ⛔ **Scoped to ``expires_at <= now_ts``, and that conjunction is REQUIRED**,
    for the reason #139 had to add it to the DB sibling: a suppression written
    on a behind clock can still be IN FORCE if its duration outruns the gap.
    Measured on this backend -- clock 12h behind, 24h asked for, operator gets
    12h. Telling them it *"never took effect"* would be false about a
    suppression they can watch working.

    ⭐ **The scope also kills a false positive this backend has and the DB ones
    do not.** ``repair_future_dated_ui_entries`` rewrites ``added_at`` in place
    without moving the row, so a forward-dated entry repaired AFTER a later
    healthy write leaves the file genuinely out of order. Measured: a 10-second
    inversion, manufactured by the repair, on two perfectly good suppressions.
    Both were still live, so the scope excludes them.

    ⚠️ **The residual, measured, not eliminated:** if the poller is stopped long
    enough for the later healthy entry's own deadline to pass BEFORE the repair
    runs, the scope no longer excludes it and this reports a healthy row. It
    needs the daemon down for longer than the snooze while the web UI keeps
    serving clicks. The direction is the recoverable one -- the operator is told
    to check a clock that is fine, about a suppression that already worked --
    which is the same trade ``webui/clock.py`` documents for its own false
    positives. **It is a narrower claim than the DB siblings can make, and
    saying so is the point.**

    ⛔ **The precondition, and it is NOT "no assumptions".** This needs every
    ``added_at`` in the file to have been stamped AT WRITE TIME. All three UI
    write paths do exactly that (``webui/app.py`` stamps
    ``added_at=int(time.time())`` at each of them), so for a file only the UI has
    touched the append order and the timestamps are two records of one event.

    **A hand-edit breaks that, and a test fixture found it before any operator
    did.** ``added_at`` is operator-supplied data in a hand-written entry -- a
    *claim about the past*, not a record of the write -- so someone documenting
    when they originally added a device produces a genuine out-of-order file with
    a perfectly good clock. `tests/test_webui.py`'s allowlist-filter fixture does
    precisely this (an entry back-dated 7200s to make it expired) and this
    reported it. Pinned by
    ``test_a_backdated_hand_edit_is_a_known_false_positive``.

    ⇒ So the wording must offer BOTH readings -- "either the clock moved backward
    between the two saves, or these were added by hand with a past date" -- and
    must not say the clock is wrong. Hand-edits that OMIT ``added_at`` (the shape
    the field's own docstring describes) are skipped and cost nothing.

    ⚠️ **Blind, by construction, on an install where every UI write shares one
    behind clock** -- there is no earlier-stamped row to contradict. That is the
    same population ``schema_migrations`` cannot see either (Finding 41's
    RTC-less Pi), so this narrows the window without closing it.

    ⚠️ **``expires_at is None`` is a PERMANENT entry, not a snooze**, and unlike
    the SQLite sibling -- where ``NULL <= x`` is never true and the equivalent
    guard is redundant -- this one is load-bearing: in Python the comparison
    would raise. A permanent entry has no deadline to be wrong about.

    ⚠️ Entries with no ``added_at`` are operator hand-edits. They carry no
    provenance, so they are skipped entirely: they neither report nor advance
    the running maximum.

    ⛔ **Never raises.** A diagnostic that can change what its caller does is the
    defect this project has shipped twice -- once emptying an allowlist from
    inside this very module's loader, once taking the daemon down at startup. On
    any failure this reports nothing and the caller behaves exactly as before.
    """
    try:
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            return []
        # ⛔ The canonical loader, not a private parser. A second reader is how
        # this module produced a permanent corruption once already: the read path
        # and the write path validated differently, so a file the reader rejected
        # the writer preserved and extended. See `_validate_ui_entries`. It also
        # keeps this off `test_every_yaml_loader_is_wired_or_exempt_with_a_reason`
        # -- a new `safe_load` site here would need an exemption, and an
        # exemption is a claim.
        entries = _load_ui_entries(ui_path)
        out: list[ImpossibleUiEntry] = []
        # ⛔ Carried as ONE value, not two. An `assert high_pattern is not None`
        # here would be swallowed by this function's own `except Exception` and
        # silently return [] -- a reporter that goes dark is the failure mode
        # this whole family exists to prevent, and `python -O` strips the assert
        # anyway. A single tuple makes the pairing unrepresentable-if-wrong.
        high: tuple[int, str] | None = None
        for e in entries:
            if e.added_at is None:
                continue
            if high is None or e.added_at >= high[0] - UI_ORDER_TOLERANCE_SECONDS:
                # ⚠️ The running maximum advances only on a stamp that is NOT a
                # violation, so one backward jump followed by several writes on
                # the still-wrong clock reports every one of them -- they are all
                # short, and they are all the operator's.
                if high is None or e.added_at > high[0]:
                    high = (e.added_at, e.pattern)
                continue
            if e.expires_at is None or e.expires_at > now_ts:
                continue
            duration = e.expires_at - e.added_at
            if duration <= 0:
                # ⛔ A hand-edit whose deadline precedes its own stamp. The
                # model permits it (`_bound_timestamps` checks the range, not
                # the ordering) and it was reachable: the banner read *"asked
                # for -24.0h"*. Skipped rather than reported, because such an
                # entry expired at the moment it was written and its problem is
                # the edit, not the clock -- naming the clock would send the
                # operator to fix the wrong thing. Same `duration > 0` posture
                # `repair_future_dated_ui_entries` already takes.
                continue
            out.append(
                ImpossibleUiEntry(
                    pattern=e.pattern,
                    pattern_type=e.pattern_type,
                    added_at=e.added_at,
                    duration_seconds=duration,
                    preceded_by_pattern=high[1],
                    preceded_by_added_at=high[0],
                    behind_by_seconds=high[0] - e.added_at,
                )
            )
        return out
    except Exception:  # noqa: BLE001 -- see above; a report must never decide
        return []


def repair_future_dated_ui_entries(
    ui_path: Path, now_ts: int
) -> list[tuple[str, int]]:
    """Re-base UI suppressions written by a process whose clock was wrong.

    ⛔ Same defect as `Database.repair_future_dated_rule_type_snoozes`, in the
    other storage backend. `webui/app.py`'s `_write_ui_allowlist` computes
    `expires_at = now_ts + seconds` from `int(time.time())` — the web process
    has no `ClockAnchor` — so an operator clicking "snooze this device for 24h"
    while the host clock is wrong stores a deadline wrong by the same amount.

    Measured with the clock +91 days fast: a 24-hour snooze on ONE SUSPICIOUS
    DEVICE suppressed it for **92 days**. That is worse than the rule_type case,
    because the operator picked that MAC deliberately — it is the device they
    thought was worth watching.

    ⭐ Recoverable without a schema change for the same reason: the entry
    carries BOTH `added_at` and `expires_at`, so their difference is the
    duration that was actually chosen.

    ⚠️ Keyed on `added_at` in the future, never on `expires_at` — a live
    suppression always has a future `expires_at`, so keying on that would
    re-base every healthy entry on every poll tick and extend it forever.

    ⚠️ Entries with `expires_at is None` are PERMANENT allowlist entries, not
    snoozes. They have no duration to preserve and are left untouched.

    Returns ``[(pattern, intended_duration_seconds), ...]`` for rows re-based.
    """
    if not isinstance(now_ts, int) or isinstance(now_ts, bool):
        raise ValueError("now_ts must be an int (epoch seconds)")
    if not ui_path.exists():
        return []
    # ⛔ Held across the read AND the write. This runs in the POLLER while the
    # web process is serving clicks: measured, a click landing inside this
    # window was discarded by the repair's write, needing no operator
    # concurrency whatsoever.
    with _ui_write_lock(ui_path):
        entries = _load_ui_entries(ui_path)
        repaired: list[tuple[str, int]] = []
        rebuilt: list[AllowlistEntry] = []
        for e in entries:
            duration = None
            if (
                e.added_at is not None
                and e.expires_at is not None
                and e.added_at > now_ts
            ):
                duration = e.expires_at - e.added_at
            if duration is not None and duration > 0:
                rebuilt.append(
                    e.model_copy(
                        update={"added_at": now_ts, "expires_at": now_ts + duration}
                    )
                )
                repaired.append((e.pattern, duration))
            else:
                rebuilt.append(e)
        if not repaired:
            # ⚠️ Do not rewrite the file when nothing changed. This runs every
            # poll tick, and a needless write would churn the disk on a Pi and
            # defeat the "an intact file is untouched" guarantee the corruption
            # tests assert.
            return []
        _atomic_write_yaml(
            ui_path,
            {
                "entries": [
                    e.model_dump(mode="json", exclude_none=True) for e in rebuilt
                ]
            },
        )
    return repaired


def remove_ui_entry(
    ui_path: Path,
    pattern: str,
    pattern_type: str,
    legacy_path: Path | None = None,
) -> bool:
    """Remove a matching entry from the UI file.

    Returns ``True`` if a matching entry was removed, ``False`` if no
    matching entry was found (or the file does not exist).

    ``pattern`` is compared as-stored — i.e. post-normalization. The
    route layer that calls this is expected to construct an
    ``AllowlistEntry`` first (which normalizes MAC / OUI patterns) and
    pass ``entry.pattern`` here, so a raw "AA:BB:CC:..." from a user
    form does not silently miss a stored "aa:bb:cc:...". Pattern_type
    is an exact string match against the stored value.

    ``legacy_path`` is the pre-move location. It is folded in before the
    removal, because while only that file exists its entries are the ones the
    operator can see — removing one of them has to carry the rest across, or
    the click that deletes one suppression silently deletes them all.
    """
    if not ui_path.exists() and not (legacy_path is not None and legacy_path.exists()):
        return False
    with _ui_write_lock(ui_path):
        data = _seed_from_legacy(_read_ui_yaml(ui_path), ui_path, legacy_path)
        before = len(data["entries"])
        data["entries"] = [
            e
            for e in data["entries"]
            if not (
                e.get("pattern") == pattern and e.get("pattern_type") == pattern_type
            )
        ]
        if len(data["entries"]) == before:
            return False
        _atomic_write_yaml(ui_path, data)
    return True


def bulk_remove_ui_entries(
    ui_path: Path,
    keys: list[tuple[str, str]],
    legacy_path: Path | None = None,
) -> int:
    """Remove every UI entry whose ``(pattern, pattern_type)`` is in ``keys``.

    Returns the number of entries actually removed. The whole batch
    is one read + one atomic write — N sequential ``remove_ui_entry``
    calls would produce N mtime updates and N reload ticks on the
    daemon side, so this function is the only place batch removal
    should happen.

    ``keys`` is matched against the stored (post-normalization) form
    of each entry, so callers should construct ``AllowlistEntry`` (or
    canonicalize via ``patterns.normalize_pattern``) before deriving
    keys from raw form input — otherwise an uppercase MAC from a form
    would silently miss the lowercase-stored row.

    Absent UI file → returns 0 without writing. Empty ``keys`` is a
    no-op (also returns 0) — operators clicking "Remove selected"
    with nothing checked land here; the caller is responsible for
    surfacing the empty-selection case to the user before this call.
    """
    if not keys or not (
        ui_path.exists() or (legacy_path is not None and legacy_path.exists())
    ):
        return 0
    with _ui_write_lock(ui_path):
        data = _seed_from_legacy(_read_ui_yaml(ui_path), ui_path, legacy_path)
        before = len(data["entries"])
        key_set = set(keys)
        data["entries"] = [
            e
            for e in data["entries"]
            if (e.get("pattern"), e.get("pattern_type")) not in key_set
        ]
        removed = before - len(data["entries"])
        if removed > 0:
            _atomic_write_yaml(ui_path, data)
    return removed
