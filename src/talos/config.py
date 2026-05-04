"""Configuration loading and validation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

logger = logging.getLogger(__name__)

DEFAULT_KISMET_URL = "http://localhost:2501"


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kismet_url: str = DEFAULT_KISMET_URL
    kismet_api_key: str | None = None
    kismet_fixture_path: str | None = None
    db_path: str = "talos.db"
    location_id: str = "default"
    location_label: str = "Default Location"
    poll_interval_seconds: int = 60
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    rules_path: str | None = None
    allowlist_path: str | None = None
    alert_dedup_window_seconds: int = 3600

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
