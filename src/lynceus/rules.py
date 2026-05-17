"""Detection rules: load rule definitions and evaluate them against observations."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from lynceus.kismet import DeviceObservation, normalize_mac, normalize_uuid
from lynceus.patterns import normalize_pattern

if TYPE_CHECKING:
    from lynceus.db import Database

logger = logging.getLogger(__name__)

_OUI_RE = re.compile(r"^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$")

RuleType = Literal[
    "watchlist_mac",
    "watchlist_oui",
    "watchlist_ssid",
    "watchlist_mac_range",
    "ble_uuid",
    "watchlist_ble_manufacturer_id",
    "watchlist_drone_id_prefix",
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

        # Per-rule_type empty/non-empty patterns admission. Each
        # rule_type's policy is spelled out explicitly rather than
        # falling through a generic startswith("watchlist_") branch:
        # the four delegation-capable types accept BOTH shapes (empty
        # patterns = delegate to DB, non-empty = in-memory match), and
        # the two carve-out types (watchlist_mac_range and
        # new_non_randomized_device) require empty patterns. Spelling
        # each out independently means a future hypothetical
        # watchlist_X type lands in an explicit branch instead of
        # silently inheriting whichever default is most recent.
        if self.rule_type == "watchlist_mac_range":
            # Part 2 carve-out: matching is exclusively delegated to
            # the watchlist DB (no in-memory semantic possible for
            # ranges — patterns are CIDR-shaped, not equality-shaped).
            if self.patterns:
                raise ValueError(
                    f"rule {self.name!r}: watchlist_mac_range delegates matching "
                    "to the watchlist DB; per-rule patterns are not supported "
                    "(patterns must be empty)"
                )
        elif self.rule_type == "new_non_randomized_device":
            # Categorical, not pattern-based — patterns have no
            # semantic for this rule_type.
            if self.patterns:
                raise ValueError(
                    f"rule {self.name!r}: new_non_randomized_device must have empty patterns"
                )
        elif self.rule_type in ("watchlist_mac", "watchlist_oui", "watchlist_ssid", "ble_uuid"):
            # Delegation-capable. Empty patterns = delegate matching
            # to the watchlist DB at evaluate-time (severity sourced
            # from the matched row); non-empty = legacy in-memory
            # match against the listed patterns (severity sourced
            # from the rule). Both shapes are valid; the
            # rules.evaluate branch picks the path based on
            # rule.patterns at call time. No assertion needed here.
            pass
        elif self.rule_type in (
            "watchlist_ble_manufacturer_id",
            "watchlist_drone_id_prefix",
        ):
            # Same delegation-capable shape as the four types above.
            # Empty patterns = delegate to the watchlist DB; non-empty
            # = in-memory equality match against rule.patterns (the
            # observation field carries the canonical string form
            # populated at parse_kismet_device time, so equality is
            # the right shape). No carve-out — both modes are valid.
            pass
        # No else: the RuleType Literal already constrains rule_type
        # to a known set; pydantic rejects unknown values upstream.

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
        elif self.rule_type == "watchlist_ble_manufacturer_id":
            try:
                normalized = [
                    normalize_pattern("ble_manufacturer_id", p) for p in self.patterns
                ]
            except ValueError as e:
                raise ValueError(f"rule {self.name!r}: {e}") from e
            object.__setattr__(self, "patterns", normalized)
        elif self.rule_type == "watchlist_drone_id_prefix":
            try:
                normalized = [
                    normalize_pattern("drone_id_prefix", p) for p in self.patterns
                ]
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
    rule_type: RuleType
    severity: Severity
    message: str
    mac: str


_VALID_SEVERITIES = ("low", "med", "high")


class RuntimeSeverityOverride(BaseModel):
    """Runtime-layer view of severity_overrides.yaml.

    Reads four keys from the same file the import-time
    ``OverrideConfig`` in ``import_argus.py`` consumes, but exposes
    only the runtime-relevant subset:

    - ``device_category_severity`` (BOTH layers). Import time bakes
      this into ``watchlist.severity`` at write time; the runtime
      layer re-applies it at alert time on top of whatever was
      baked. Operators editing the value after import → daemon
      restart picks it up → already-imported rows fire at the new
      severity without re-importing the 17,786-row Argus corpus.

    - ``suppress_categories`` (RUNTIME only). Delegation matches
      whose ``device_category`` is in this list emit no RuleHit
      (alert suppressed entirely). The import-time layer has no
      equivalent; this is the closest runtime cousin of
      vendor_overrides' ``"drop"`` sentinel, but at category
      granularity instead of vendor.

    - ``suppress_vendors`` (RUNTIME only). Delegation matches whose
      matched row's ``vendor`` (projected as ``manufacturer`` on
      Resolved*Match) is in this list emit no RuleHit.
      Case-insensitive exact match — entries are normalized at load
      time (lowercase + strip) and stored in that form; the
      eval-time check normalizes ``match.manufacturer`` the same
      way before comparison. The deliberate runtime counterpart to
      import-time ``vendor_overrides``, which keeps its
      skip-at-import ``"drop"`` semantic unchanged.

    - ``pattern_overrides`` (RUNTIME only — NEW key). Row-level
      severity remap keyed by ``argus_record_id`` — the stable
      16-hex SHA-256 prefix Argus emits as its consumer-facing
      identifier and Lynceus stores in
      ``watchlist_metadata.argus_record_id``. Matches whose
      ``argus_record_id`` appears as a key get their severity
      remapped to the value (``"low"`` / ``"med"`` / ``"high"``).
      Closes the runtime severity-tuning matrix at row × category ×
      vendor: operators can carve a specific row out of a
      category-level default (e.g. "alpr → high in general, but
      THIS specific Flock camera → high too — or some other tier").
      Keys normalized to lowercase at load time. Only rows with a
      metadata row carrying an ``argus_record_id`` can be targeted;
      operator-seeded rows via ``lynceus-seed-watchlist`` without
      metadata fall through to the category-level layer (use the
      allowlist for per-row suppression of non-Argus rows).

    Other ``OverrideConfig`` keys (``vendor_overrides``,
    ``geographic_filter``, ``confidence_downgrade_threshold``)
    remain consumed by the importer's existing code path and have
    NO runtime effect — they shape what gets imported, not what
    gets alerted on. ``vendor_overrides`` stays import-time-only by
    design: its ``"drop"`` sentinel means "skip-at-import" and a
    runtime interpretation would silently overload it.
    ``suppress_vendors`` is the cleanly-designed runtime cousin.

    The frozen+extra-ignore config lets the parser tolerate the
    full superset of keys the wizard's starter file documents —
    parsing an import-time-only file produces an empty runtime
    view, not a validation error.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    device_category_severity: dict[str, Severity] = {}
    suppress_categories: frozenset[str] = frozenset()
    suppress_vendors: frozenset[str] = frozenset()
    pattern_overrides: dict[str, Severity] = {}

    @model_validator(mode="after")
    def _validate(self) -> RuntimeSeverityOverride:
        for cat, sev in self.device_category_severity.items():
            if sev not in _VALID_SEVERITIES:
                raise ValueError(
                    f"device_category_severity[{cat!r}] = {sev!r}: "
                    f"expected one of {_VALID_SEVERITIES}"
                )
        for arid, sev in self.pattern_overrides.items():
            if sev not in _VALID_SEVERITIES:
                raise ValueError(
                    f"pattern_overrides[{arid!r}] = {sev!r}: "
                    f"expected one of {_VALID_SEVERITIES}"
                )
        return self

    def is_empty(self) -> bool:
        """No remap and no suppression → fast-path pass-through.

        ``rules.evaluate`` short-circuits the override block when the
        config is None OR empty by this definition; the per-match
        ``device_category is None`` / ``manufacturer is None`` /
        ``argus_record_id is None`` checks in
        ``_apply_runtime_overrides`` are the second tier of the
        pass-through fast-path (a match without that metadata has
        nothing to key on, regardless of config richness).
        """
        return (
            not self.device_category_severity
            and not self.suppress_categories
            and not self.suppress_vendors
            and not self.pattern_overrides
        )


def load_runtime_severity_overrides(
    path: str | Path | None,
) -> RuntimeSeverityOverride | None:
    """Load the runtime view of severity_overrides.yaml.

    Failure modes are all benign — the runtime override layer is
    additive; the poller must never crash because the operator
    edited their override file into a malformed state. Every
    outcome — success and every failure mode — emits a log line at
    the appropriate level so an operator running ``journalctl -u
    lynceus.service`` at daemon startup can confirm the layer's
    state without grepping the source.

    - ``path`` is None: INFO log (layer disabled because
      ``severity_overrides_path`` is unset in lynceus.yaml) and
      return None. Distinct from a missing file: the operator
      deliberately did not opt in to runtime overrides.
    - File missing: INFO log + return None. Absence is normal — the
      operator may not have run the wizard, or may have intentionally
      removed the file.
    - File present, runtime keys absent or empty: INFO log naming
      the path + return an empty RuntimeSeverityOverride (which
      fast-paths through at evaluate-time). Distinct from a file
      with active runtime keys.
    - File loaded with active runtime keys: INFO log naming the
      path, the count of remap entries, and the count of suppressed
      categories + return the populated RuntimeSeverityOverride.
    - File present but unreadable (PermissionError, OSError): WARNING
      log + return None.
    - YAML parse error: WARNING log + return None.
    - Pydantic validation error (e.g. invalid severity literal):
      WARNING log + return None.

    Every WARNING names the path and the underlying error. The
    poller continues running with pass-through semantics for the
    runtime layer; the import-time consumer in ``import_argus.py``
    is unaffected (separate code path, separate error handling).
    """
    if path is None:
        logger.info(
            "severity_overrides_path not set in lynceus.yaml; runtime override "
            "layer disabled. Set the field to your severity_overrides.yaml path "
            "(e.g. /etc/lynceus/severity_overrides.yaml under --system, or "
            "~/.config/lynceus/severity_overrides.yaml under --user) and restart "
            "the daemon to enable. The import-time consumer in lynceus-import-argus "
            "is unaffected by this field — it reads the file via --override-file."
        )
        return None
    p = Path(path)
    if not p.exists():
        logger.info(
            "severity overrides file %s not found; runtime override layer disabled "
            "(import-time overrides via lynceus-import-argus are unaffected)",
            path,
        )
        return None
    try:
        with open(p, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning(
            "could not read severity overrides file %s (%s); runtime override "
            "layer disabled. Fix the file and restart the daemon to re-enable.",
            path,
            exc,
        )
        return None
    if not isinstance(raw, dict):
        logger.warning(
            "severity overrides file %s did not parse to a YAML mapping "
            "(got %s); runtime override layer disabled.",
            path,
            type(raw).__name__,
        )
        return None
    runtime_kwargs: dict = {}
    if isinstance(raw.get("device_category_severity"), dict):
        runtime_kwargs["device_category_severity"] = raw["device_category_severity"]
    if isinstance(raw.get("suppress_categories"), list):
        runtime_kwargs["suppress_categories"] = frozenset(
            s for s in raw["suppress_categories"] if isinstance(s, str)
        )
    if isinstance(raw.get("suppress_vendors"), list):
        # Normalize at load time (lowercase + strip) so the eval-time
        # check is a single frozenset lookup. Comparison is
        # case-insensitive exact match; trimming makes the parser
        # tolerant of operator whitespace typos. Per-entry validation
        # drops non-string and empty-after-strip entries with a
        # WARNING — the rest of the file still parses; one malformed
        # entry must not disable the whole layer.
        normalized: set[str] = set()
        for entry in raw["suppress_vendors"]:
            if not isinstance(entry, str):
                logger.warning(
                    "severity overrides file %s: suppress_vendors entry "
                    "%r is not a string; dropping. Other entries still apply.",
                    path,
                    entry,
                )
                continue
            stripped = entry.strip().lower()
            if not stripped:
                logger.warning(
                    "severity overrides file %s: suppress_vendors entry "
                    "%r is empty after stripping whitespace; dropping. "
                    "Other entries still apply.",
                    path,
                    entry,
                )
                continue
            normalized.add(stripped)
        runtime_kwargs["suppress_vendors"] = frozenset(normalized)
    if isinstance(raw.get("pattern_overrides"), dict):
        # Operator-supplied row-level severity remap keyed by
        # argus_record_id (16-hex SHA-256 prefix per the Argus
        # contract). Per-entry validation: keys must be 16 hex chars
        # after lowercase-normalization, values must be a known
        # severity literal. One malformed entry never disables the
        # layer — a WARNING is logged and the rest of the dict
        # parses normally. Whether the argus_record_id corresponds
        # to a real row in the DB is NOT checked at load time: an
        # operator may legitimately carry a stale entry across a
        # re-import (the row will be re-added and the override will
        # start applying again), and the runtime check is a simple
        # dict membership test that pass-throughs on miss.
        normalized_overrides: dict[str, str] = {}
        for raw_key, raw_value in raw["pattern_overrides"].items():
            if not isinstance(raw_key, str):
                logger.warning(
                    "severity overrides file %s: pattern_overrides key "
                    "%r is not a string; dropping. Other entries still apply.",
                    path,
                    raw_key,
                )
                continue
            normalized_key = raw_key.strip().lower()
            if len(normalized_key) != 16 or not all(
                c in "0123456789abcdef" for c in normalized_key
            ):
                logger.warning(
                    "severity overrides file %s: pattern_overrides key "
                    "%r is not a 16-hex argus_record_id; dropping. "
                    "Other entries still apply.",
                    path,
                    raw_key,
                )
                continue
            if not isinstance(raw_value, str) or raw_value not in _VALID_SEVERITIES:
                logger.warning(
                    "severity overrides file %s: pattern_overrides[%r] = "
                    "%r is not a valid severity literal (expected one of "
                    "%s); dropping. Other entries still apply.",
                    path,
                    raw_key,
                    raw_value,
                    _VALID_SEVERITIES,
                )
                continue
            normalized_overrides[normalized_key] = raw_value
        runtime_kwargs["pattern_overrides"] = normalized_overrides
    try:
        overrides = RuntimeSeverityOverride(**runtime_kwargs)
    except Exception as exc:
        logger.warning(
            "severity overrides file %s failed validation (%s); runtime override "
            "layer disabled.",
            path,
            exc,
        )
        return None
    # Success path. Two log shapes so an operator grepping the
    # startup output can tell at a glance whether the file is
    # actually doing something (active runtime keys) or whether
    # it parsed cleanly but has no runtime effect (e.g. a file
    # containing only import-time keys — the wizard's default
    # starter state until the operator uncomments a runtime key).
    if overrides.is_empty():
        logger.info(
            "runtime severity overrides loaded from %s but contain no active "
            "runtime keys (device_category_severity / suppress_categories / "
            "suppress_vendors / pattern_overrides); runtime layer is "
            "effectively pass-through. Edit the file and restart the daemon "
            "to activate.",
            path,
        )
    else:
        logger.info(
            "runtime severity overrides loaded from %s: "
            "%d category remap(s), %d suppressed category(ies), "
            "%d suppressed vendor(s), %d pattern override(s). "
            "Edits take effect on daemon restart.",
            path,
            len(overrides.device_category_severity),
            len(overrides.suppress_categories),
            len(overrides.suppress_vendors),
            len(overrides.pattern_overrides),
        )
    return overrides


def load_ruleset(path: str) -> Ruleset:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Ruleset(**data)


def _apply_runtime_overrides(
    *,
    match_severity: str,
    match_device_category: str | None,
    match_manufacturer: str | None,
    match_argus_record_id: str | None,
    match_watchlist_id: int,
    rule_name: str,
    overrides: RuntimeSeverityOverride | None,
) -> str | None:
    """Apply runtime severity overrides to a DB-delegation match.

    Returns the (possibly remapped) severity to use for the RuleHit,
    or ``None`` to signal suppression (caller skips emitting the
    RuleHit entirely).

    Pass-through fast-path — byte-identical to pre-overrides
    behavior — when any of:
    - ``overrides`` is None (no file loaded, or file disabled the
      layer per ``load_runtime_severity_overrides`` failure modes).
    - ``overrides.is_empty()`` (file parsed but no runtime key
      populated — e.g. a file containing only import-time keys).

    The three per-match metadata fields gate which checks run
    independently:
    - ``match_manufacturer`` is None → the vendor check is skipped
      (the matched row has no metadata, or a metadata row with
      NULL vendor). Falls through to the next tier.
    - ``match_argus_record_id`` is None → the row-level
      pattern_overrides check is skipped (the matched row has no
      metadata, so there is no stable identifier to key on). Falls
      through to the category-driven checks.
    - ``match_device_category`` is None → category-driven checks
      are skipped (the matched row has no metadata to key on).
      Falls through to the default.

    Precedence is most-specific-wins:
    1. Vendor suppression: normalized ``match_manufacturer`` in
       ``suppress_vendors`` → return None. INFO-log the suppression
       with rule_name, the un-normalized manufacturer string from
       the row, and watchlist_id.
    2. Category suppression: category in ``suppress_categories``
       → return None. INFO-log with rule_name, category, and
       watchlist_id.
    3. Pattern override (NEW, row-level remap):
       ``match_argus_record_id`` in ``pattern_overrides`` → return
       the remapped severity. More specific than the category
       remap below; no INFO log (symmetric with
       device_category_severity — the alert itself surfaces the
       effective severity).
    4. Category remap: category in ``device_category_severity``
       → return the remapped severity.
    5. Default: no rule applies → return ``match_severity``
       unchanged.

    Vendor wins over category because manufacturer is the more
    specific axis; suppression always wins over remap because
    "no alert" is a stronger statement than "different severity"
    and the operator opted in to it deliberately. Per-row
    UNSUPPRESSION is explicitly NOT a feature — a vendor or
    category suppression cannot be overridden by listing a row's
    argus_record_id in ``pattern_overrides``.
    """
    if overrides is None or overrides.is_empty():
        return match_severity
    if match_manufacturer is not None:
        normalized_vendor = match_manufacturer.strip().lower()
        if normalized_vendor in overrides.suppress_vendors:
            logger.info(
                "runtime override: suppressing manufacturer=%r alert for "
                "watchlist_id=%d (rule=%s)",
                match_manufacturer,
                match_watchlist_id,
                rule_name,
            )
            return None
    if (
        match_device_category is not None
        and match_device_category in overrides.suppress_categories
    ):
        logger.info(
            "runtime override: suppressing category=%s alert for "
            "watchlist_id=%d (rule=%s)",
            match_device_category,
            match_watchlist_id,
            rule_name,
        )
        return None
    if (
        match_argus_record_id is not None
        and match_argus_record_id in overrides.pattern_overrides
    ):
        return overrides.pattern_overrides[match_argus_record_id]
    if (
        match_device_category is not None
        and match_device_category in overrides.device_category_severity
    ):
        return overrides.device_category_severity[match_device_category]
    return match_severity


def evaluate(
    ruleset: Ruleset,
    obs: DeviceObservation,
    is_new_device: bool,
    *,
    db: Database | None = None,
    severity_overrides: RuntimeSeverityOverride | None = None,
) -> list[RuleHit]:
    """Match an observation against the ruleset; emit one RuleHit per hit.

    ``db`` is consulted by the DB-delegated rule_types — currently
    ``watchlist_mac_range`` (always) and ``watchlist_mac``,
    ``watchlist_oui``, ``watchlist_ssid``, ``ble_uuid`` whenever
    ``rule.patterns`` is empty (the empty-patterns-delegates-to-DB
    semantic established by Part 2 and extended to the other four
    types here). Rules with non-empty patterns continue to match
    in-memory against ``rule.patterns`` and ignore ``db`` — backward
    compat for pre-existing rules.yaml deployments. Keyword-only on
    purpose so existing callers stay source-compatible.

    ``severity_overrides`` is the runtime view of
    severity_overrides.yaml (see ``RuntimeSeverityOverride``). Only
    the five DB-delegation branches consult it; in-memory pattern
    matches keep their rule-sourced severity unchanged. None or
    empty config short-circuits to pass-through — byte-identical
    RuleHits to the pre-overrides behavior. The three per-match
    metadata-driven checks each gate independently: vendor-suppress
    (``suppress_vendors``) applies when ``manufacturer`` is
    non-None; pattern_overrides applies when ``argus_record_id`` is
    non-None; category-driven checks (``suppress_categories``,
    ``device_category_severity``) apply when ``device_category`` is
    non-None. Rows with no metadata at all pass through unchanged.
    """
    hits: list[RuleHit] = []
    for rule in ruleset.rules:
        if not rule.enabled:
            continue

        if rule.rule_type == "watchlist_mac":
            if rule.patterns:
                # In-memory match path — preserved unchanged for
                # backward compat. Severity sourced from the rule.
                if obs.mac in rule.patterns:
                    msg = f"MAC {obs.mac} on watchlist: {rule.description or rule.name}"
                    hits.append(
                        RuleHit(
                            rule_name=rule.name,
                            rule_type=rule.rule_type,
                            severity=rule.severity,
                            message=msg,
                            mac=obs.mac,
                        )
                    )
            else:
                # Delegation path — empty patterns means "match every
                # watchlist mac row". Severity sourced from the
                # matched DB row, NOT from rule.severity (mirror of
                # the watchlist_mac_range divergence; see
                # ResolvedWatchlistMatch and the watchlist_mac_range
                # eval branch for the architectural rationale).
                if db is None:
                    logger.error(
                        "delegation rule %r (watchlist_mac, empty patterns) "
                        "evaluated without db; skipping. evaluate() must be "
                        "called with db= when any delegation rule is in the "
                        "ruleset.",
                        rule.name,
                    )
                    continue
                match = db.resolve_matched_mac_for_eval(obs.mac)
                if match is None:
                    continue
                effective_severity = _apply_runtime_overrides(
                    match_severity=match.severity,
                    match_device_category=match.device_category,
                    match_manufacturer=match.manufacturer,
                    match_argus_record_id=match.argus_record_id,
                    match_watchlist_id=match.watchlist_id,
                    rule_name=rule.name,
                    overrides=severity_overrides,
                )
                if effective_severity is None:
                    continue  # suppressed by runtime override
                msg = (
                    f"MAC {obs.mac} on watchlist "
                    f"(watchlist_id={match.watchlist_id}): "
                    f"{rule.description or rule.name}"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        rule_type=rule.rule_type,
                        severity=effective_severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "watchlist_oui":
            if rule.patterns:
                # In-memory match path — preserved unchanged.
                # Severity sourced from the rule.
                for p in rule.patterns:
                    if obs.mac.startswith(p + ":"):
                        msg = (
                            f"OUI {obs.mac[:8]} on watchlist: "
                            f"{rule.description or rule.name} (mac {obs.mac})"
                        )
                        hits.append(
                            RuleHit(
                                rule_name=rule.name,
                                rule_type=rule.rule_type,
                                severity=rule.severity,
                                message=msg,
                                mac=obs.mac,
                            )
                        )
                        break
            else:
                # Delegation path. Severity sourced from the matched
                # DB row — see the watchlist_mac branch above for the
                # architectural rationale.
                if db is None:
                    logger.error(
                        "delegation rule %r (watchlist_oui, empty patterns) "
                        "evaluated without db; skipping.",
                        rule.name,
                    )
                    continue
                match = db.resolve_matched_oui_for_eval(obs.mac)
                if match is None:
                    continue
                effective_severity = _apply_runtime_overrides(
                    match_severity=match.severity,
                    match_device_category=match.device_category,
                    match_manufacturer=match.manufacturer,
                    match_argus_record_id=match.argus_record_id,
                    match_watchlist_id=match.watchlist_id,
                    rule_name=rule.name,
                    overrides=severity_overrides,
                )
                if effective_severity is None:
                    continue
                msg = (
                    f"OUI {obs.mac[:8]} on watchlist "
                    f"(watchlist_id={match.watchlist_id}): "
                    f"{rule.description or rule.name} (mac {obs.mac})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        rule_type=rule.rule_type,
                        severity=effective_severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "watchlist_ssid":
            if rule.patterns:
                # In-memory match path — preserved unchanged.
                # Severity sourced from the rule.
                if obs.ssid is not None and obs.ssid in rule.patterns:
                    msg = (
                        f"SSID {obs.ssid!r} on watchlist: "
                        f"{rule.description or rule.name} (mac {obs.mac})"
                    )
                    hits.append(
                        RuleHit(
                            rule_name=rule.name,
                            rule_type=rule.rule_type,
                            severity=rule.severity,
                            message=msg,
                            mac=obs.mac,
                        )
                    )
            else:
                # Delegation path. Severity sourced from the matched
                # DB row — see the watchlist_mac branch above for the
                # architectural rationale.
                if db is None:
                    logger.error(
                        "delegation rule %r (watchlist_ssid, empty patterns) "
                        "evaluated without db; skipping.",
                        rule.name,
                    )
                    continue
                match = db.resolve_matched_ssid_for_eval(obs.ssid)
                if match is None:
                    continue
                effective_severity = _apply_runtime_overrides(
                    match_severity=match.severity,
                    match_device_category=match.device_category,
                    match_manufacturer=match.manufacturer,
                    match_argus_record_id=match.argus_record_id,
                    match_watchlist_id=match.watchlist_id,
                    rule_name=rule.name,
                    overrides=severity_overrides,
                )
                if effective_severity is None:
                    continue
                msg = (
                    f"SSID {obs.ssid!r} on watchlist "
                    f"(watchlist_id={match.watchlist_id}): "
                    f"{rule.description or rule.name} (mac {obs.mac})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        rule_type=rule.rule_type,
                        severity=effective_severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "watchlist_mac_range":
            # First DB-delegated rule_type in Lynceus. Two structural
            # divergences from the other watchlist_* branches above:
            #
            #   1. Matching consults the watchlist DB via
            #      db.resolve_matched_mac_range rather than
            #      rule.patterns (which is validator-required to be
            #      empty for this rule_type). A single rules.yaml
            #      entry enables alert-firing for every matching
            #      mac_range row imported by lynceus-import-argus.
            #
            #   2. Severity is sourced from the matched DB row, not
            #      from rule.severity. The importer wrote per-row
            #      severity from device_category for a reason; reading
            #      it back at alert time is the only path that
            #      respects that data. rule.severity is ignored for
            #      this rule_type (documented in the bundled
            #      config/rules.yaml template).
            if obs.mac is None:
                continue
            if db is None:
                # Defensive: should never happen in production —
                # poller.poll_once passes db=self.db. A test or
                # synthetic caller invoking evaluate() without db
                # silently dropping the hit would be worse than a
                # loud error, hence the WARNING and continue.
                logger.error(
                    "watchlist_mac_range rule %r evaluated without db; "
                    "skipping. This is a programming error — "
                    "evaluate() must be called with db= when any "
                    "watchlist_mac_range rule is in the ruleset.",
                    rule.name,
                )
                continue
            match = db.resolve_matched_mac_range(obs.mac)
            if match is None:
                continue
            effective_severity = _apply_runtime_overrides(
                match_severity=match.severity,
                match_device_category=match.device_category,
                match_manufacturer=match.manufacturer,
                match_argus_record_id=match.argus_record_id,
                match_watchlist_id=match.watchlist_id,
                rule_name=rule.name,
                overrides=severity_overrides,
            )
            if effective_severity is None:
                continue
            msg = (
                f"MAC {obs.mac} inside watchlisted mac_range "
                f"(/{match.prefix_length}, watchlist_id={match.watchlist_id}): "
                f"{rule.description or rule.name}"
            )
            hits.append(
                RuleHit(
                    rule_name=rule.name,
                    rule_type=rule.rule_type,
                    severity=effective_severity,
                    message=msg,
                    mac=obs.mac,
                )
            )
        elif rule.rule_type == "ble_uuid":
            if rule.patterns:
                # In-memory match path — preserved unchanged. Loops
                # the rule's patterns and breaks on the first that
                # appears in the observation. Severity sourced from
                # the rule.
                for p in rule.patterns:
                    if p in obs.ble_service_uuids:
                        msg = (
                            f"BLE service UUID {p} on watchlist: "
                            f"{rule.description or rule.name} (mac {obs.mac})"
                        )
                        hits.append(
                            RuleHit(
                                rule_name=rule.name,
                                rule_type=rule.rule_type,
                                severity=rule.severity,
                                message=msg,
                                mac=obs.mac,
                            )
                        )
                        break
            else:
                # Delegation path. The DB matcher iterates obs's UUIDs
                # in order and returns the first whose UUID is in the
                # ble_uuid watchlist — same first-match shape as the
                # in-memory branch above, just driven by DB rows
                # instead of rule.patterns. Severity sourced from the
                # matched DB row.
                if db is None:
                    logger.error(
                        "delegation rule %r (ble_uuid, empty patterns) "
                        "evaluated without db; skipping.",
                        rule.name,
                    )
                    continue
                match = db.resolve_matched_ble_uuid_for_eval(obs.ble_service_uuids)
                if match is None:
                    continue
                effective_severity = _apply_runtime_overrides(
                    match_severity=match.severity,
                    match_device_category=match.device_category,
                    match_manufacturer=match.manufacturer,
                    match_argus_record_id=match.argus_record_id,
                    match_watchlist_id=match.watchlist_id,
                    rule_name=rule.name,
                    overrides=severity_overrides,
                )
                if effective_severity is None:
                    continue
                msg = (
                    f"BLE service UUID on watchlist "
                    f"(watchlist_id={match.watchlist_id}): "
                    f"{rule.description or rule.name} (mac {obs.mac})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        rule_type=rule.rule_type,
                        severity=effective_severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "watchlist_ble_manufacturer_id":
            # Equality-shape delegation, mirroring watchlist_mac. The
            # observation's ble_manufacturer_id is None for non-BLE
            # records and for BLE records where the Kismet field paths
            # in kismet._BLE_MANUFACTURER_ID_PATHS did not resolve — both
            # short-circuit to no match. See the kismet.py docstring for
            # the field-path uncertainty caveat.
            if obs.ble_manufacturer_id is None:
                continue
            if rule.patterns:
                # In-memory match path. Severity sourced from the rule.
                if obs.ble_manufacturer_id in rule.patterns:
                    msg = (
                        f"BLE manufacturer 0x{obs.ble_manufacturer_id} on "
                        f"watchlist: {rule.description or rule.name} "
                        f"(mac {obs.mac})"
                    )
                    hits.append(
                        RuleHit(
                            rule_name=rule.name,
                            rule_type=rule.rule_type,
                            severity=rule.severity,
                            message=msg,
                            mac=obs.mac,
                        )
                    )
            else:
                # Delegation path. Severity sourced from the matched
                # DB row — see the watchlist_mac branch above for the
                # architectural rationale.
                if db is None:
                    logger.error(
                        "delegation rule %r (watchlist_ble_manufacturer_id, "
                        "empty patterns) evaluated without db; skipping.",
                        rule.name,
                    )
                    continue
                match = db.resolve_matched_ble_manufacturer_id_for_eval(
                    obs.ble_manufacturer_id
                )
                if match is None:
                    continue
                effective_severity = _apply_runtime_overrides(
                    match_severity=match.severity,
                    match_device_category=match.device_category,
                    match_manufacturer=match.manufacturer,
                    match_argus_record_id=match.argus_record_id,
                    match_watchlist_id=match.watchlist_id,
                    rule_name=rule.name,
                    overrides=severity_overrides,
                )
                if effective_severity is None:
                    continue
                msg = (
                    f"BLE manufacturer 0x{obs.ble_manufacturer_id} on "
                    f"watchlist (watchlist_id={match.watchlist_id}): "
                    f"{rule.description or rule.name} (mac {obs.mac})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        rule_type=rule.rule_type,
                        severity=effective_severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "watchlist_drone_id_prefix":
            # Equality-shape delegation, mirroring watchlist_mac. The
            # observation's drone_id_prefix is None until both
            # kismet._DRONE_ID_PATHS field-path verification AND
            # _TYPE_MAP extension to admit Remote-ID device records
            # land — see the kismet.py docstring for the dual caveat.
            if obs.drone_id_prefix is None:
                continue
            if rule.patterns:
                # In-memory match path. Severity sourced from the rule.
                if obs.drone_id_prefix in rule.patterns:
                    msg = (
                        f"Drone Remote-ID {obs.drone_id_prefix} on "
                        f"watchlist: {rule.description or rule.name} "
                        f"(mac {obs.mac})"
                    )
                    hits.append(
                        RuleHit(
                            rule_name=rule.name,
                            rule_type=rule.rule_type,
                            severity=rule.severity,
                            message=msg,
                            mac=obs.mac,
                        )
                    )
            else:
                # Delegation path. Severity sourced from the matched
                # DB row — see the watchlist_mac branch above for the
                # architectural rationale.
                if db is None:
                    logger.error(
                        "delegation rule %r (watchlist_drone_id_prefix, "
                        "empty patterns) evaluated without db; skipping.",
                        rule.name,
                    )
                    continue
                match = db.resolve_matched_drone_id_prefix_for_eval(
                    obs.drone_id_prefix
                )
                if match is None:
                    continue
                effective_severity = _apply_runtime_overrides(
                    match_severity=match.severity,
                    match_device_category=match.device_category,
                    match_manufacturer=match.manufacturer,
                    match_argus_record_id=match.argus_record_id,
                    match_watchlist_id=match.watchlist_id,
                    rule_name=rule.name,
                    overrides=severity_overrides,
                )
                if effective_severity is None:
                    continue
                msg = (
                    f"Drone Remote-ID {obs.drone_id_prefix} on watchlist "
                    f"(watchlist_id={match.watchlist_id}): "
                    f"{rule.description or rule.name} (mac {obs.mac})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        rule_type=rule.rule_type,
                        severity=effective_severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
        elif rule.rule_type == "new_non_randomized_device":
            if is_new_device and not obs.is_randomized:
                msg = (
                    f"New non-randomized device: {obs.mac} (vendor: {obs.oui_vendor or 'unknown'})"
                )
                hits.append(
                    RuleHit(
                        rule_name=rule.name,
                        rule_type=rule.rule_type,
                        severity=rule.severity,
                        message=msg,
                        mac=obs.mac,
                    )
                )
    return hits
