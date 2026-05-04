"""Detection rules: load rule definitions and evaluate them against observations."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from talos.kismet import DeviceObservation, normalize_mac, normalize_uuid

logger = logging.getLogger(__name__)

_OUI_RE = re.compile(r"^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$")

RuleType = Literal[
    "watchlist_mac",
    "watchlist_oui",
    "watchlist_ssid",
    "ble_uuid",
    "new_non_randomized_device",
]
Severity = Literal["low", "med", "high"]


class Rule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    rule_type: RuleType
    severity: Severity
    enabled: bool = True
    patterns: list[str] = []
    description: str | None = None

    @model_validator(mode="after")
    def _validate_rule(self) -> Rule:
        if not self.name:
            raise ValueError("rule name must be non-empty")

        if self.rule_type.startswith("watchlist_") or self.rule_type == "ble_uuid":
            if not self.patterns:
                raise ValueError(f"rule {self.name!r}: watchlist rules require non-empty patterns")
        elif self.rule_type == "new_non_randomized_device":
            if self.patterns:
                raise ValueError(
                    f"rule {self.name!r}: new_non_randomized_device must have empty patterns"
                )

        if self.rule_type == "watchlist_mac":
            normalized = [normalize_mac(p) for p in self.patterns]
            object.__setattr__(self, "patterns", normalized)
        elif self.rule_type == "watchlist_oui":
            normalized = []
            for p in self.patterns:
                s = p.strip().lower().replace("-", ":")
                if not _OUI_RE.match(s):
                    raise ValueError(f"rule {self.name!r}: invalid oui pattern: {p!r}")
                normalized.append(s)
            object.__setattr__(self, "patterns", normalized)
        elif self.rule_type == "ble_uuid":
            try:
                normalized = [normalize_uuid(p) for p in self.patterns]
            except ValueError as e:
                raise ValueError(f"rule {self.name!r}: {e}") from e
            object.__setattr__(self, "patterns", normalized)

        return self


class Ruleset(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: list[Rule] = []

    @model_validator(mode="after")
    def _check_unique_names(self) -> Ruleset:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.name in seen:
                raise ValueError(f"duplicate rule name: {rule.name!r}")
            seen.add(rule.name)
        return self


class RuleHit(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_name: str
    severity: Severity
    message: str
    mac: str


def load_ruleset(path: str) -> Ruleset:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Ruleset(**data)


def evaluate(
    ruleset: Ruleset,
    obs: DeviceObservation,
    is_new_device: bool,
) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for rule in ruleset.rules:
        if not rule.enabled:
            continue

        if rule.rule_type == "watchlist_mac":
            if obs.mac in rule.patterns:
                msg = f"MAC {obs.mac} on watchlist: {rule.description or rule.name}"
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "watchlist_oui":
            for p in rule.patterns:
                if obs.mac.startswith(p + ":"):
                    msg = (
                        f"OUI {obs.mac[:8]} on watchlist: "
                        f"{rule.description or rule.name} (mac {obs.mac})"
                    )
                    hits.append(
                        RuleHit(
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=msg,
                            mac=obs.mac,
                        )
                    )
                    break
        elif rule.rule_type == "watchlist_ssid":
            if obs.ssid is not None and obs.ssid in rule.patterns:
                msg = (
                    f"SSID {obs.ssid!r} on watchlist: "
                    f"{rule.description or rule.name} (mac {obs.mac})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "ble_uuid":
            for p in rule.patterns:
                if p in obs.ble_service_uuids:
                    msg = (
                        f"BLE service UUID {p} on watchlist: "
                        f"{rule.description or rule.name} (mac {obs.mac})"
                    )
                    hits.append(
                        RuleHit(
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=msg,
                            mac=obs.mac,
                        )
                    )
                    break
        elif rule.rule_type == "new_non_randomized_device":
            if is_new_device and not obs.is_randomized:
                msg = (
                    f"New non-randomized device: {obs.mac} (vendor: {obs.oui_vendor or 'unknown'})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
    return hits
