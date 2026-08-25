"""Configuration loading and validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from lynceus.yaml_duplicates import warn_duplicate_keys

logger = logging.getLogger(__name__)

# Loopback IP, not "localhost". Deterministic across /etc/hosts edits and
# IPv4/IPv6 ambiguity (some resolvers prefer ::1, which Kismet doesn't bind by
# default). Single source of truth for both config defaults and the wizard.
DEFAULT_KISMET_URL = "http://127.0.0.1:2501"

# The host values that mean "nothing off this machine can reach the UI".
# ⭐ Defined once because TWO things read it and they must not drift: the
# validator below, which refuses a non-loopback bind unless ui_allow_remote is
# set, and the startup exposure warning in webui/server.py. If those two ever
# disagreed, the daemon would either refuse a bind it then called safe, or bind
# wide open and say nothing.
LOOPBACK_HOSTS = ("127.0.0.1", "localhost")


def _validate_url_scheme_and_host(value: str, field_name: str) -> None:
    """Reject scheme-less or non-http(s) URLs at the config layer.

    The poller previously accepted anything that smelled like a URL and
    handed it to ``requests.get``, which raises ``MissingSchema`` for inputs
    like ``"127.0.0.1:2501"``. Operators were typing exactly that into the
    wizard at rc1, and the failure surfaced as a cryptic stack trace at
    poll time rather than a clear validation error at config load.
    """
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(
            f"{field_name} must include scheme (http:// or https://) and host. Got: {value!r}"
        )


class CaptureConfig(BaseModel):
    """Tier 1 passive metadata capture toggles.

    Probe SSIDs are off by default — lynceus is a tool to detect
    surveillance, not to become it. Operators opt in explicitly when the
    triage value (matching probes against a known-watchlist offline) is
    worth the privacy footprint.

    BLE friendly names are on by default — they are publicly broadcast
    with intent (the device name is part of the GAP advertisement).
    """

    model_config = ConfigDict(extra="forbid")

    probe_ssids: bool = False
    ble_friendly_names: bool = True


class CoObservationConfig(BaseModel):
    """Read-only co-observation explorer (additive; OFF by default).

    Shows the operator which other devices keep turning up at the same time as
    a given one. It makes no statistical claim: sensor uptime is not recorded
    anywhere in the schema, so absence of data cannot be distinguished from
    absence of a device, and no score would be defensible. An earlier scored
    design was withdrawn after it was measured returning maximum confidence for
    the always-present neighbour it existed to demote.

    ⭐ ``enabled`` is a capability toggle and a security control, not a
    preference. Iterating the route across every MAC reconstructs an
    association graph, and a stolen operator session can request thousands of
    endpoints even though each page shows 25. A capability that is not enabled
    cannot be enumerated at all, which is the only control here that changes
    the exposure rather than merely pacing it. It also means a panel whose
    output is "devices that keep appearing near a person" cannot be reached by
    accident.

    ``window_days`` bounds the scan because ``sightings`` retention is
    OPT-IN and defaults to off (``sightings_retention_days = None``), so on
    a default install the table does grow without bound. ⚠️ This used to
    read "has no retention policy and is never pruned", which was true
    when written and stopped being true when opt-in retention shipped --
    the bound is still needed, but for a weaker reason than the prose
    claimed, and an operator who HAS enabled retention was being told
    something false about their own install. ``proximity_seconds`` is W, the co-observation
    threshold: two sightings at one location within W of each other. The UI
    offers 1/5/15-minute presets and always displays the value in use, because
    a relationship that dissolves as W tightens is information the operator
    should have. ``gap_seconds`` is how long a device must be unseen before its
    next sighting starts a new observation run; the default tolerates a missed
    poll tick at the default 60s interval without splitting one stay in two.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    window_days: int = 30
    proximity_seconds: int = 300
    gap_seconds: int = 900
    max_candidates: int = 25

    @field_validator("window_days")
    @classmethod
    def _validate_window_days(cls, v: int) -> int:
        if not (1 <= v <= 3650):
            raise ValueError("window_days must be in [1, 3650]")
        return v

    @field_validator("proximity_seconds")
    @classmethod
    def _validate_proximity_seconds(cls, v: int) -> int:
        # 0 is legitimate: it means "logged at the same second", the tightest
        # possible reading. Database.list_co_observations accepts >= 0 too.
        if not (0 <= v <= 86400):
            raise ValueError("proximity_seconds must be in [0, 86400]")
        return v

    @field_validator("gap_seconds")
    @classmethod
    def _validate_gap_seconds(cls, v: int) -> int:
        if not (1 <= v <= 86400):
            raise ValueError("gap_seconds must be in [1, 86400]")
        return v

    @field_validator("max_candidates")
    @classmethod
    def _validate_max_candidates(cls, v: int) -> int:
        # Ceiling matches Database.list_co_observations' own limit bound, so a
        # value the config accepts cannot raise at query time.
        if not (1 <= v <= 200):
            raise ValueError("max_candidates must be in [1, 200]")
        return v


class BleBridgeConfig(BaseModel):
    """Passive BLE capture bridge (additive; OFF by default).

    When enabled, the poller runs a passive BLE scan in a background thread with
    its OWN Database connection (the WAL second-writer pattern), feeding
    observations through the same pipeline as Kismet polls. Disabled by default:
    enabling it is an explicit opt-in and changes no existing poll behavior.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    adapter: str = "hci1"
    # The bridge's own tick interval, separate from the Kismet poll loop. None
    # falls back to poll_interval_seconds when the bridge is wired up.
    flush_interval: int | None = None

    @field_validator("flush_interval")
    @classmethod
    def _validate_flush_interval(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("flush_interval must be >= 1 second")
        return v


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kismet_url: str = DEFAULT_KISMET_URL
    kismet_api_key: str | None = None
    kismet_fixture_path: str | None = None
    #: Shift the fixture's clocks so its newest record is one hour old at load.
    #: Off by default: the test suites assert against fixed fixture timestamps,
    #: and a demo is the only caller that wants a moving clock.
    kismet_fixture_shift_to_now: bool = False
    db_path: str = "lynceus.db"
    location_id: str = "default"
    location_label: str = "Default Location"
    poll_interval_seconds: int = 60
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    rules_path: str | None = None
    allowlist_path: str | None = None
    #: Where the daemon-written ``allowlist_ui.yaml`` lives. None means
    #: "derive it", which puts it in the STATE directory beside the database
    #: rather than beside ``allowlist_path``.
    #:
    #: ⛔ It used to be a sibling of ``allowlist_path``. On a ``--system``
    #: install that is ``/etc/lynceus``, which the units deliberately exclude
    #: from ``ReadWritePaths`` -- so every web-UI suppression returned HTTP
    #: 500. It is daemon-written state, not operator config, and it belongs
    #: with the database. See allowlist.derive_ui_path for the measurement.
    #:
    #: Operators who genuinely want it elsewhere can set this explicitly;
    #: an existing install needs nothing, because the read-fallback and the
    #: seed-on-first-write in allowlist.py carry the old file forward.
    ui_allowlist_path: str | None = None
    # Path to severity_overrides.yaml — the same file lynceus-import-argus
    # consumes via --override-file. The poller reads the runtime-relevant
    # subset (device_category_severity, suppress_categories) at startup
    # and applies overrides at alert time for DB-delegation matches.
    # When None, the runtime override layer is disabled and delegation
    # matches fire at their imported severities unchanged. The wizard
    # scaffolds this file at paths.default_overrides_path(scope) AND
    # persists the path into lynceus.yaml (setup/core.py's
    # "--- Severity overrides ---" block), so a wizard-installed operator
    # gets the override layer wired up without hand-editing anything.
    # ⚠️ This comment used to say the opposite — that the path was never
    # persisted and operators had to set the field themselves. True when
    # written, false since the wizard started emitting it, and it survived
    # long enough to send a reader hunting a defect that no longer existed.
    severity_overrides_path: str | None = None
    alert_dedup_window_seconds: int = 3600
    ntfy_url: str | None = None
    ntfy_topic: str | None = None
    ntfy_auth_token: str | None = None
    ui_bind_host: str = "127.0.0.1"
    ui_bind_port: int = 8765
    ui_allow_remote: bool = False
    #: Where the web UI's password hash lives. None means "derive it", which
    #: puts it in the STATE directory beside the database — same reasoning as
    #: ``ui_allowlist_path``, and see ``webui/credentials.py`` for why it is not
    #: a field in this file.
    #:
    #: ⚠️ The PATH is config; the SECRET is not. Setting this points lynceus at
    #: a different credentials file, it does not contain one. Write the file
    #: with ``lynceus-ui-passwd``.
    ui_auth_path: str | None = None
    kismet_sources: list[str] | None = None
    kismet_source_locations: dict[str, str] | None = None
    min_rssi: int | None = None
    kismet_timeout_seconds: float = 10.0
    kismet_health_check_on_startup: bool = True
    # --- Heartbeat / dead-man's switch -------------------------------------
    # Off by default: it is the only feature that pushes when nothing has
    # happened, so opting an existing operator into unsolicited notifications
    # on upgrade would be the wrong default.
    heartbeat_enabled: bool = False
    # 24h suits the field deployment (mobile, checked daily). The floor is 1h
    # rather than 0 because the point is a periodic proof of life, and an
    # interval shorter than the poll interval cannot mean anything.
    heartbeat_interval_hours: int = 24
    capture: CaptureConfig = CaptureConfig()
    ble_bridge: BleBridgeConfig = BleBridgeConfig()
    co_observation: CoObservationConfig = CoObservationConfig()
    evidence_capture_enabled: bool = True
    evidence_retention_days: int = 90
    # ⛔ None means NEVER prune, which is what every install has always done.
    # Deleting observation history is destructive and irreversible, so it is
    # opt-in: an upgrade must not silently discard an operator's evidence.
    # Setting it bounds a table that otherwise grows without limit, which is
    # the reason co_observation.window_days exists.
    sightings_retention_days: int | None = None
    # Watchlist staleness threshold for the startup log line + the
    # /settings freshness card. An imported Argus corpus older than
    # this many days flips the startup line from INFO to WARNING
    # with a `lynceus-import-argus --from-github` refresh hint, and
    # the settings card surfaces a stale-status indicator. 30 days
    # matches Argus's nominal release cadence; operators on a
    # different cadence (kiosk deployments, air-gapped refreshes)
    # tune via this field.
    watchlist_staleness_warn_days: int = 30
    # GPS coordinates in evidence rows are the OPERATOR's location at
    # alert time (Kismet sources the geopoint from the receiver's GPS
    # fix, not the observed device's). Opt-in by default so an operator
    # who enables evidence capture does not silently start a 90-day
    # high-resolution self-movement log.
    evidence_store_gps: bool = False

    def resolved_ui_allowlist_path(self) -> Path | None:
        """Where the daemon WRITES its allowlist entries, or None.

        ⛔ Everything that reads or writes the UI allowlist must resolve it
        through here. There is exactly one thing worse than the file being in
        the wrong place, and that is half the processes finding it in one
        place and half in another: the poller would go on suppressing a device
        the web UI had just un-suppressed, and nothing would say so.

        Defaults into the STATE directory -- the parent of ``db_path`` -- which
        is what the units already grant ``ReadWritePaths`` for. It follows the
        operator's actual database location, so a user-scope install, a
        system-scope install and a test's tmp_path all land somewhere writable
        without any of them special-casing.

        Returns None when no primary allowlist is configured, which is the
        state where there is no UI allowlist to speak of either.
        """
        if self.allowlist_path is None:
            return None
        if self.ui_allowlist_path:
            return Path(self.ui_allowlist_path)
        from .allowlist import ui_filename

        return Path(self.db_path).parent / ui_filename(Path(self.allowlist_path))

    def resolved_ui_auth_path(self) -> Path:
        """Where the web UI reads its password hash from.

        ⛔ Everything that reads or writes the credential must resolve it
        through here, for the reason written on
        ``resolved_ui_allowlist_path``: the failure mode of two callers
        disagreeing is not "it breaks", it is that ``lynceus-ui-passwd``
        cheerfully writes a password to one path while ``lynceus-ui`` reads
        another and reports that authentication is not configured.

        Unlike the allowlist this never returns None: a database path always
        exists, so the credentials path is always derivable, and "no
        credentials" is the file being absent rather than the path being
        unknown.
        """
        if self.ui_auth_path:
            return Path(self.ui_auth_path)
        from .webui.credentials import default_credentials_path

        return default_credentials_path(self.db_path)

    def legacy_ui_allowlist_path(self) -> Path | None:
        """The pre-move location: beside the operator's own allowlist.

        Read-only, and only for the migration -- the read-fallback and the
        seed-on-first-write. An install upgrading from a version that wrote
        here keeps its suppressions without the operator doing anything, and
        without the daemon needing write access to a directory the units
        deliberately keep it out of.
        """
        if self.allowlist_path is None:
            return None
        from .allowlist import derive_ui_path

        legacy = derive_ui_path(Path(self.allowlist_path))
        active = self.resolved_ui_allowlist_path()
        return None if active is not None and legacy == active else legacy

    @field_validator("kismet_url")
    @classmethod
    def _validate_kismet_url(cls, v: str) -> str:
        _validate_url_scheme_and_host(v, "kismet_url")
        return v

    @field_validator("ntfy_url", mode="before")
    @classmethod
    def _validate_ntfy_url(cls, v: str | None) -> str | None:
        # ntfy is optional. Empty / whitespace-only collapses to None so
        # operators (and the wizard) can disable notifications by writing
        # ``ntfy_url: ""`` without tripping scheme validation.
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError(f"ntfy_url must be a string, got {type(v).__name__}")
        if v.strip() == "":
            return None
        _validate_url_scheme_and_host(v, "ntfy_url")
        return v

    @field_validator("poll_interval_seconds")
    @classmethod
    def _validate_interval(cls, v: int) -> int:
        if v < 5:
            raise ValueError("poll_interval_seconds must be >= 5")
        return v

    @field_validator("alert_dedup_window_seconds")
    @classmethod
    def _validate_dedup_window(cls, v: int) -> int:
        if v < 0:
            raise ValueError("alert_dedup_window_seconds must be >= 0")
        return v

    @field_validator("heartbeat_interval_hours")
    @classmethod
    def _validate_heartbeat_interval(cls, v: int) -> int:
        # >= 1 rather than >= 0: a 0-hour interval would push on every poll
        # tick, which is not a heartbeat but a flood, and would train the
        # operator to mute the topic the alerts also arrive on.
        if v < 1:
            raise ValueError("heartbeat_interval_hours must be >= 1")
        return v

    @field_validator("sightings_retention_days")
    @classmethod
    def _validate_sightings_retention_days(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 3650):
            raise ValueError("sightings_retention_days must be in [1, 3650] or null")
        return v

    @model_validator(mode="after")
    def _validate_retention_covers_co_observation(self) -> Config:
        """Pruning must not silently undercut the co-observation window.

        The panel renders "the last N days" and every denominator with it. If
        sightings are pruned to fewer days than that, each count stays truthful
        about the rows it found and becomes wrong about the period it claims to
        cover, and nothing on screen would say so. Rejected at load rather than
        warned about, because the wrong number is indistinguishable from the
        right one once it is rendered.

        Only enforced while the panel is enabled: the constraint exists to
        protect that claim, and with no panel there is no claim.
        """
        if (
            self.sightings_retention_days is not None
            and self.co_observation.enabled
            and self.sightings_retention_days < self.co_observation.window_days
        ):
            raise ValueError(
                "sightings_retention_days "
                f"({self.sightings_retention_days}) must be >= "
                f"co_observation.window_days ({self.co_observation.window_days}); "
                "pruning below the window makes the panel claim a period the "
                "database no longer covers"
            )
        return self

    @model_validator(mode="after")
    def _validate_ntfy_pair(self) -> Config:
        if self.ntfy_url and not self.ntfy_topic:
            raise ValueError("ntfy_topic required when ntfy_url is set")
        if self.ntfy_topic and not self.ntfy_url:
            raise ValueError("ntfy_url required when ntfy_topic is set")
        return self

    @field_validator("kismet_sources")
    @classmethod
    def _validate_kismet_sources(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if len(v) == 0:
            raise ValueError(
                "kismet_sources must be omitted or a non-empty list "
                "(an empty list would filter out everything)"
            )
        cleaned: list[str] = []
        for entry in v:
            if not isinstance(entry, str):
                raise ValueError(f"kismet_sources entries must be strings: {entry!r}")
            stripped = entry.strip()
            if not stripped:
                raise ValueError("kismet_sources entries must be non-empty after strip")
            cleaned.append(stripped)
        return cleaned

    @field_validator("kismet_source_locations")
    @classmethod
    def _validate_kismet_source_locations(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is None:
            return None
        cleaned: dict[str, str] = {}
        for key, val in v.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(f"kismet_source_locations keys must be non-empty strings: {key!r}")
            if not isinstance(val, str) or not val.strip():
                raise ValueError(
                    f"kismet_source_locations values must be non-empty strings: {val!r}"
                )
            cleaned[key.strip()] = val.strip()
        return cleaned

    @field_validator("min_rssi")
    @classmethod
    def _validate_min_rssi(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v < -120 or v > 0:
            raise ValueError(
                "min_rssi must be in [-120, 0] (dBm); -120 is below thermal noise, "
                "0 is unphysically strong"
            )
        return v

    @field_validator("kismet_timeout_seconds")
    @classmethod
    def _validate_kismet_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("kismet_timeout_seconds must be > 0")
        if v > 120.0:
            raise ValueError("kismet_timeout_seconds must be <= 120.0")
        return v

    @field_validator("evidence_retention_days")
    @classmethod
    def _validate_evidence_retention_days(cls, v: int) -> int:
        if v < 1 or v > 3650:
            raise ValueError("evidence_retention_days must be in [1, 3650]")
        return v

    @field_validator("watchlist_staleness_warn_days")
    @classmethod
    def _validate_watchlist_staleness_warn_days(cls, v: int) -> int:
        if v < 1:
            raise ValueError(
                "watchlist_staleness_warn_days must be >= 1 (a 0-day "
                "threshold would WARN at every startup; the threshold is "
                "tunable per operator cadence)"
            )
        return v

    @model_validator(mode="after")
    def _validate_ui_bind(self) -> Config:
        if self.ui_bind_port < 1 or self.ui_bind_port > 65535:
            raise ValueError("ui_bind_port must be between 1 and 65535")
        if self.ui_bind_host not in LOOPBACK_HOSTS and not self.ui_allow_remote:
            raise ValueError(
                "ui_bind_host is non-loopback but ui_allow_remote is False. "
                "Set ui_allow_remote: true explicitly to bind to a non-loopback address. "
                "Anything that can reach the bound address can read the UI, and "
                "/probes is the probe-SSID history of every device in range — "
                "bystanders, not just you. lynceus-ui additionally REFUSES to "
                "start on a non-loopback host until a password is set with "
                "lynceus-ui-passwd."
            )
        return self


def load_config(path: str) -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    # ⚠️ The sharpest case here leaves no trace anywhere else. A duplicate
    # `heartbeat_enabled:` returns the dead-man's switch to its default
    # (False), and `poller.py:1252` then returns early on every tick without
    # logging -- so the one feature whose entire purpose is to speak when
    # nothing else can is disarmed in silence. Nothing counts it, so no
    # count-based startup line can show it.
    warn_duplicate_keys(p, logger=logger, subject="config file")
    if "db_path" not in data:
        # Backward compat for legacy lynceus.yaml files that predate
        # the wizard's explicit db_path: render. Without this, the
        # daemon falls through to the Config default "lynceus.db" —
        # a CWD-relative path — and opens a different SQLite file
        # than the wizard imported the watchlist into. Detect scope
        # from the config file's location so a system-scope yaml
        # (/etc/lynceus/lynceus.yaml) resolves to /var/lib/lynceus/
        # lynceus.db rather than the operator's XDG path; everything
        # else falls back to user-scope. Both probes (the system
        # config-path lookup and the resolved db-path lookup) are
        # wrapped together because NotImplementedError can fire from
        # either on macOS / Windows (no system scope) and the back-
        # fill must always degrade to the user-scope db_path rather
        # than propagating.
        from lynceus import paths
        try:
            system_config = paths.default_config_path("system").resolve()
            scope: Literal["user", "system"] = (
                "system" if p.resolve() == system_config else "user"
            )
            resolved_db = paths.default_db_path(scope)
        except NotImplementedError:
            resolved_db = paths.default_db_path("user")
        data["db_path"] = str(resolved_db)
    cfg = Config(**data)
    if cfg.kismet_fixture_path and cfg.kismet_url != DEFAULT_KISMET_URL:
        logger.warning(
            "Both kismet_fixture_path and a non-default kismet_url are set; fixture wins."
        )
    return cfg
