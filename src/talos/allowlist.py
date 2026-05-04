"""Allowlist management: load known-good devices and suppress matching alerts."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from talos.kismet import DeviceObservation, normalize_mac

logger = logging.getLogger(__name__)

_OUI_RE = re.compile(r"^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$")


class AllowlistEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern: str
    pattern_type: Literal["mac", "oui", "ssid"]
    note: str | None = None

    @model_validator(mode="after")
    def _normalize_pattern(self) -> AllowlistEntry:
        if self.pattern_type == "mac":
            normalized = normalize_mac(self.pattern)
        elif self.pattern_type == "oui":
            s = self.pattern.strip().lower().replace("-", ":")
            if not _OUI_RE.match(s):
                raise ValueError(f"invalid oui: {self.pattern!r}")
            normalized = s
        else:
            normalized = self.pattern
        if normalized != self.pattern:
            object.__setattr__(self, "pattern", normalized)
        return self


class Allowlist(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entries: list[AllowlistEntry] = []

    def is_allowed(self, obs: DeviceObservation) -> bool:
        for entry in self.entries:
            if entry.pattern_type == "mac":
                if obs.mac == entry.pattern:
                    return True
            elif entry.pattern_type == "oui":
                if obs.mac.startswith(entry.pattern + ":"):
                    return True
            elif entry.pattern_type == "ssid":
                if obs.ssid is not None and obs.ssid == entry.pattern:
                    return True
        return False


def load_allowlist(path: str) -> Allowlist:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Allowlist(**data)
