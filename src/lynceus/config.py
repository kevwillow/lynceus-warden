"""Configuration loading and validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

logger = logging.getLogger(__name__)

DEFAULT_KISMET_URL = "http://localhost:2501"


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


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kismet_url: str = DEFAULT_KISMET_URL
    kismet_api_key: str | None = None
    kismet_fixture_path: str | None = None
    db_path: str = "lynceus.db"
    location_id: str = "default"
    location_label: str = "Default Location"
    poll_interval_seconds: int = 60
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    rules_path: str | None = None
    allowlist_path: str | None = None
    alert_dedup_window_seconds: int = 3600
    ntfy_url: str | None = None
    ntfy_topic: str | None = None
    ntfy_auth_token: str | None = None
    ui_bind_host: str = "127.0.0.1"
    ui_bind_port: int = 8765
    ui_allow_remote: bool = False
    kismet_sources: list[str] | None = None
    kismet_source_locations: dict[str, str] | None = None
    min_rssi: int | None = None
    kismet_timeout_seconds: float = 10.0
    kismet_health_check_on_startup: bool = True
    capture: CaptureConfig = CaptureConfig()

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

    @model_validator(mode="after")
    def _validate_ui_bind(self) -> Config:
        if self.ui_bind_port < 1 or self.ui_bind_port > 65535:
            raise ValueError("ui_bind_port must be between 1 and 65535")
        if self.ui_bind_host not in ("127.0.0.1", "localhost") and not self.ui_allow_remote:
            raise ValueError(
                "ui_bind_host is non-loopback but ui_allow_remote is False. "
                "Set ui_allow_remote: true explicitly to bind to a non-loopback address. "
                "This is a footgun — lynceus has no auth layer in v0.2."
            )
        return self


def load_config(path: str) -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    cfg = Config(**data)
    if cfg.kismet_fixture_path and cfg.kismet_url != DEFAULT_KISMET_URL:
        logger.warning(
            "Both kismet_fixture_path and a non-default kismet_url are set; fixture wins."
        )
    return cfg
