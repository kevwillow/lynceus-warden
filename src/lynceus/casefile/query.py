"""Database to CaseFile. The choke point.

Every disclosure decision in this feature is made in this module and
nowhere else: which co-observers are named, which evidence is withheld,
what is capped and what the document must admit it cannot show.

🪤 Why one function rather than a rule at each entry point. #216's S5
closed the remote_id extraction path, and the model layer then re-stripped
the same fields by a second route: two paths reached one mechanism, and
closing one closed only a surface. The CLI and the web UI are two paths
into this feature. They meet here, and ``render.py`` cannot reach the
database, so it cannot disclose anything this module excluded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..kismet import normalize_mac
from ..retention import STATE_KEY_LAST_SIGHTINGS_PRUNE

#: The DB layer clamps ``get_device_with_sightings`` to [1, 1000]. That
#: is the existing bound and it is the one used here rather than a new
#: number: the repo's habit is that an existing clamp is the right one.
MAX_SIGHTINGS = 1000

#: ``list_co_observations`` clamps to [1, 200] and ``list_alerts_with_match``
#: pagination to 1000. Both are existing bounds, quoted rather than invented.
MAX_CO_OBSERVERS = 200
MAX_ALERTS = 1000

#: ``list_co_observation_pairs`` clamps to [1, 500], but 500 is not the
#: right number here and 100 is: it matches ``webui/app.py``'s existing
#: ``_CO_PAIRS_LIMIT``, so the case file and the co-observation page show
#: the same depth of drill-down.
#:
#: ⭐ MEASURED, not chosen. At the caps (1000 sightings, 200 alerts, 200
#: evidence rows, 200 named co-observers) on 2026-08-24:
#:
#:     pairs cap   pairs    artifacts   peak alloc   wall
#:     500         100000   18.15 MB    108.7 MB     35.2s
#:     200          40000    8.12 MB     47.1 MB     29.7s
#:     100          20000    4.78 MB     26.3 MB     22.5s
#:      50          10000    3.11 MB     16.0 MB     18.9s
#:
#: ⚠️ Note what does NOT move: the query itself costs 17 to 21 seconds at
#: every cap, because it is 200 separate per-co-observer queries and that
#: count is fixed by MAX_CO_OBSERVERS. Lowering this further buys memory,
#: not time. See .claude/gates.md.
MAX_PAIRS_PER_CO_OBSERVER = 100

DEFAULT_PROXIMITY_SECONDS = 300
DEFAULT_GAP_SECONDS = 900

#: The ONLY fields of a stored Kismet record a case file publishes.
#:
#: ⛔ An allowlist, and it has to be. Kismet's
#: ``/devices/last-time/N/devices.json`` is not field-limited, so
#: ``DeviceObservation.raw_record`` is the whole device record, and
#: ``evidence.py``'s capture-time redactor strips probe SSIDs and BLE
#: friendly names and nothing else. For a Wi-Fi access point the rest of
#: that record includes ``dot11.device.associated_client_map``, which is
#: keyed by the MAC of every device associated to it: members of the
#: public, by the same argument that keeps unwatchlisted co-observers out
#: of this document.
#:
#: 🪤 A denylist of the nested fields known to carry other addresses would
#: be wrong the next time Kismet adds one, and the failure is silent and
#: unrecoverable, because the document has already been handed to
#: somebody. An allowlist fails the other way: a new field Kismet adds is
#: withheld until someone decides to publish it.
#:
#: Scalars only, for the same reason. Every structure that has turned out
#: to hold third-party addresses has been a dict or a list.
PUBLISHED_EVIDENCE_FIELDS = (
    "kismet.device.base.macaddr",
    "kismet.device.base.name",
    "kismet.device.base.manuf",
    "kismet.device.base.type",
    "kismet.device.base.first_time",
    "kismet.device.base.last_time",
    "kismet.device.base.channel",
    "kismet.device.base.frequency",
    "kismet.device.base.crypt",
)


@dataclass
class CaseFile:
    """The complete disclosable record for one device.

    ⛔ An unwatchlisted co-observer's MAC must never reach any field on
    this dataclass. ``co_observers_aggregate`` is a count and nothing
    else, so a leak cannot happen by a renderer later deciding to show
    "just one more field".
    """

    device: dict
    window: dict
    locations: list[dict] = field(default_factory=list)
    sightings: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    co_observers_named: list[dict] = field(default_factory=list)
    co_observers_aggregate: int = 0
    parameters: dict = field(default_factory=dict)
    limits: list[dict] = field(default_factory=list)
    excluded_counts: dict[str, int] = field(default_factory=dict)

    def approved_addresses(self) -> set[str]:
        """Every MAC this document is allowed to contain.

        ⛔ The disclosure rule expressed as a SET rather than as a list of
        fields somebody remembered to filter. `bundle.py` sweeps the
        finished artifacts against this, so a MAC reaching an output by a
        route nobody anticipated is redacted rather than published. Two
        such routes have already been found, one of them after the guards
        for the first were written.
        """
        approved = {str(self.device.get("mac", "")).lower()}
        approved |= {str(c["mac"]).lower() for c in self.co_observers_named}
        return {a for a in approved if a}


def build_case_file(
    db,
    mac: str,
    *,
    now_ts: int,
    since_ts: int | None = None,
    until_ts: int | None = None,
    sighting_limit: int = MAX_SIGHTINGS,
    config=None,
):
    """Build the complete record for one device.

    ``since_ts=None`` means all retained history, per spec section 11.1: a
    silent default window would add a second, undocumented truncation on
    top of retention, and limit 2 already has to explain the first one.

    ``config`` is optional and supplies only the retention settings, which
    live in the config file rather than the database. When it is absent
    the limits section says the setting was unavailable rather than
    implying retention was off. Everything a disclosure rule depends on
    is read from the database, so the two entry points cannot diverge by
    passing different configs.

    Raises ``LookupError`` for a device that is not in the database. A
    blank but official-looking document for a MAC that was never seen
    reads as "it was not there", which is a stronger claim than the
    record supports.
    """
    # Rule 0: normalise first. The MAC is the only user-controlled input
    # on both paths, and the output filename is derived from the
    # normalised value, so a MAC-shaped path traversal never reaches the
    # filesystem.
    norm = normalize_mac(mac)

    sighting_limit = max(1, min(int(sighting_limit), MAX_SIGHTINGS))
    record = db.get_device_with_sightings(norm, sighting_limit=sighting_limit)
    if record is None:
        raise LookupError(f"no device in this database for {norm}")

    device = dict(record["device"])
    excluded: dict[str, int] = {}

    # Rule 1: sightings, newest first, capped. The omitted count is
    # recorded rather than the cap being applied silently.
    summary = db.summarize_sightings_for_mac(norm, since_ts=since_ts, until_ts=until_ts)
    # ⛔ Windowed in SQL, NOT by filtering the newest rows afterwards.
    # `get_device_with_sightings` knows nothing about a window, so asking
    # it for the newest 1000 rows and then filtering by `until_ts` returns
    # zero sightings for an old window on a busy device, and then reports
    # the rows it never looked at as "over cap". A wrong document, not a
    # slow one.
    sightings = db.list_sightings_for_mac(
        norm, since_ts=since_ts, until_ts=until_ts, limit=sighting_limit
    )
    excluded["sightings_over_cap"] = max(0, summary["total"] - len(sightings))

    # Rule 2: alerts by EXACT mac. `q` is a substring match across
    # mac + message + vendor, and proximity messages quote other
    # devices' MACs by design, so a substring filter here would put
    # another device's alert in this device's case file.
    alerts = db.list_alerts_with_match(
        {
            "mac": norm,
            "since_ts": since_ts,
            "until_ts": until_ts,
            "limit": MAX_ALERTS,
        }
    )
    # ⛔ Counted separately, because evidence is reached by iterating the
    # alerts returned above. An alert past the cap takes its evidence with
    # it, INCLUDING a do_not_publish row, whose exclusion would then go
    # uncounted: the document would claim it withheld nothing while
    # withholding something. Disclosing the alert cap is what keeps the
    # do_not_publish count honest about its own scope.
    total_alerts = db.count_alerts(mac=norm, since_ts=since_ts, until_ts=until_ts)
    excluded["alerts_over_cap"] = max(0, int(total_alerts) - len(alerts))

    # Rule 3: evidence, minus do_not_publish, and the exclusions COUNTED.
    # Migration 009 added that column as forward-compat with no producer
    # and no consumer. Honouring it silently would turn an operator's
    # privacy control into a hole the document does not admit to.
    evidence: list[dict] = []
    dnp_excluded = 0
    fields_withheld = 0
    for alert in alerts:
        snapshot = db.get_evidence_for_alert(alert["id"])
        if snapshot is None:
            continue
        if snapshot.get("do_not_publish"):
            dnp_excluded += 1
            continue
        published, withheld = _project_evidence(snapshot)
        fields_withheld += withheld
        evidence.append(published)
    excluded["do_not_publish"] = dnp_excluded
    excluded["evidence_fields_withheld"] = fields_withheld

    # Rule 4: co-observers. Watchlisted are named and carry their
    # underlying pairs; everything else is counted and nothing more.
    named, aggregate, co_obs_meta = _resolve_co_observers(
        db, norm, now_ts=now_ts, since_ts=since_ts, until_ts=until_ts
    )
    excluded["co_observers_over_cap"] = co_obs_meta["over_cap"]

    retention_days, retention_known = _retention_days(config)
    last_prune = db.get_state(STATE_KEY_LAST_SIGHTINGS_PRUNE)

    window = {
        "since_ts": since_ts,
        "until_ts": until_ts if until_ts is not None else now_ts,
        # Spec section 4: the window has to say WHY it is what it is, or a
        # reader takes its edges for the edges of reality.
        "reason": (
            "all retained history"
            if since_ts is None
            else "explicitly requested by the operator at export time"
        ),
    }

    parameters = {
        "proximity_seconds": co_obs_meta["proximity_seconds"],
        "gap_seconds": co_obs_meta["gap_seconds"],
        "sighting_limit": sighting_limit,
        "sightings_retention_days": retention_days,
        "sightings_retention_known": retention_known,
        "evidence_retention_days": _evidence_retention_days(config),
        "last_sightings_prune_ts": int(last_prune) if last_prune else None,
        "schema_version": db.healthcheck()["schema_version"],
        "generated_at_ts": now_ts,
    }

    return CaseFile(
        device=device,
        window=window,
        locations=summary["locations"],
        sightings=sightings,
        alerts=alerts,
        evidence=evidence,
        co_observers_named=named,
        co_observers_aggregate=aggregate,
        parameters=parameters,
        limits=_build_limits(parameters),
        excluded_counts=excluded,
    )


def _project_evidence(snapshot: dict) -> tuple[dict, int]:
    """Cut a stored evidence snapshot down to what may be published.

    ⛔ A second disclosure rule, and it is not the co-observation one. A
    co-observed bystander is kept out of this document by being counted
    rather than named; a bystander whose address sits INSIDE the target's
    own Kismet record has to be kept out here, because shipping that
    record verbatim would hand a journalist the addresses of everyone
    whose phone was associated to the observed access point.

    Returns the projected snapshot and the number of record fields
    withheld, because the rule everywhere else in this feature is exclude
    AND count. A silent projection would leave a reader believing the
    evidence is the whole record.
    """
    record = snapshot.get("kismet_record")
    published = dict(snapshot)
    if not isinstance(record, dict):
        published["kismet_record"] = None
        published["kismet_record_projected"] = False
        return published, 0

    kept: dict = {}
    for key in PUBLISHED_EVIDENCE_FIELDS:
        if key not in record:
            continue
        value = record[key]
        # Scalars only. A dict or a list is where an address that is not
        # the target's has always turned out to be hiding.
        if isinstance(value, str | int | float | bool) or value is None:
            kept[key] = value

    published["kismet_record"] = kept
    published["kismet_record_projected"] = True
    return published, max(0, len(record) - len(kept))


def _resolve_co_observers(db, norm, *, now_ts, since_ts, until_ts):
    """⛔ THE disclosure rule. Watchlisted co-observers are named; every
    other co-observed device is counted and its MAC is never stored.

    A co-observed device that matched the watchlist is surveillance
    infrastructure and documenting it is the whole purpose of the
    product. An unmatched device is somebody's phone, and it must not be
    named in a document that may be handed to a third party. This mirrors
    the probe-SSID default's stated rationale exactly: capturing by
    default would aim Lynceus at bystanders instead of at surveillance
    gear.
    """
    result = db.list_co_observations(
        norm,
        now_ts=until_ts if until_ts is not None else now_ts,
        since_ts=since_ts if since_ts is not None else 0,
        proximity_seconds=DEFAULT_PROXIMITY_SECONDS,
        gap_seconds=DEFAULT_GAP_SECONDS,
        limit=MAX_CO_OBSERVERS,
    )

    by_mac: dict[str, dict] = {}
    aggregate_macs: set[str] = set()
    for candidate in result["candidates"]:
        candidate_mac = candidate["mac"]
        watchlist_id = db.resolve_matched_watchlist_id(mac=candidate_mac)
        if watchlist_id is None:
            # Counted. Nothing else. Not stored on the dataclass, not
            # keyed in a dict, not put in a log line.
            aggregate_macs.add(candidate_mac)
            continue

        entry = by_mac.setdefault(
            candidate_mac,
            {
                "mac": candidate_mac,
                "watchlist_id": watchlist_id,
                "watchlist": db.get_watchlist_with_metadata(watchlist_id),
                "locations": [],
                "pairs": [],
            },
        )
        entry["locations"].append(
            {
                "location_id": candidate["location_id"],
                "shared_anchor_runs": candidate["shared_anchor_runs"],
                "shared_days": candidate["shared_days"],
                "delta_min": candidate["delta_min"],
                "delta_median": candidate["delta_median"],
                "delta_max": candidate["delta_max"],
                "first_shared_ts": candidate["first_shared_ts"],
                "last_shared_ts": candidate["last_shared_ts"],
            }
        )
        # The pairs are two real logged sightings and the true delta
        # between them, nothing interpolated or bucketed. A count alone
        # has to be taken on trust; this product already built the
        # alternative, so the document ships it.
        pairs = db.list_co_observation_pairs(
            norm,
            candidate_mac,
            location_id=candidate["location_id"],
            now_ts=until_ts if until_ts is not None else now_ts,
            since_ts=since_ts if since_ts is not None else 0,
            proximity_seconds=DEFAULT_PROXIMITY_SECONDS,
            limit=MAX_PAIRS_PER_CO_OBSERVER,
        )
        for pair in pairs:
            # location_id is a parameter of that query rather than a
            # column of it, and a pair without its location is not
            # checkable: the criterion is per-location and never pooled.
            entry["pairs"].append({**pair, "location_id": candidate["location_id"]})

    total = result.get("total_candidates", 0)
    listed = len({c["mac"] for c in result["candidates"]})
    over_cap = max(0, int(total) - listed)

    named = sorted(by_mac.values(), key=lambda e: e["mac"])
    return named, len(aggregate_macs), {
        "over_cap": over_cap,
        "proximity_seconds": result["proximity_seconds"],
        "gap_seconds": result["gap_seconds"],
    }


def _retention_days(config):
    """Return ``(days, known)``.

    Three states, not two. Retention configured, retention off, and "we
    were not told" are different claims, and collapsing the third into
    the second would make the document assert that nothing was pruned on
    the strength of an argument nobody made.
    """
    if config is None:
        return None, False
    return getattr(config, "sightings_retention_days", None), True


def _evidence_retention_days(config):
    if config is None:
        return None
    return getattr(config, "evidence_retention_days", None)


def _build_limits(parameters: dict) -> list[dict]:
    """The five limits, per spec section 5, with 2 and 3 conditioned on
    what this database actually shows.

    Assembled here rather than in the template only so the retention
    wording can reflect the real configuration. The template carries the
    prose as static text as well, so an empty CaseFile cannot empty the
    limits section.
    """
    retention_days = parameters.get("sightings_retention_days")
    retention_known = parameters.get("sightings_retention_known")
    last_prune = parameters.get("last_sightings_prune_ts")

    if not retention_known:
        retention_note = (
            "The sighting retention setting for this installation was not "
            "available when this document was produced, so whether earlier "
            "sightings were deleted cannot be stated either way."
        )
    elif retention_days:
        retention_note = (
            f"Sighting retention is set to {retention_days} days on this "
            "installation, so the first seen date above is the earliest "
            "RETAINED sighting and not necessarily the earliest observation."
        )
    else:
        retention_note = (
            "No sighting retention limit is configured on this installation, "
            "so sightings are not deleted on a schedule."
        )
    if last_prune:
        retention_note += " A retention prune has run against this database."

    return [
        {
            "heading": "The record is keyed on MAC address",
            "body": (
                "A device that rotates its address appears here as unrelated "
                "rows. This works for surveillance infrastructure, which "
                "broadcasts from a stable address because it is not trying to "
                "hide. It does not work for consumer trackers."
            ),
        },
        {"heading": "Retention may have removed earlier sightings", "body": retention_note},
        {
            "heading": "A gap is not an absence",
            "body": (
                "Sensor uptime is not recorded anywhere, so absence of data "
                "cannot be distinguished from absence of a device. A gap in "
                "this record may mean the device was elsewhere, or it may mean "
                "nothing was listening."
            ),
        },
        {
            "heading": "GPS is the receiver's position",
            "body": (
                "Any coordinates here are where the recording sensor was, not "
                "where the observed device was. The two are close enough to be "
                "worth recording and they are not the same thing."
            ),
        },
        {
            "heading": "A watchlist match selects a device, it does not identify one",
            "body": (
                "A device is named in this record because it matched a rule in "
                "the operator's watchlist. Rules can cover a whole manufacturer "
                "prefix or an address range, so a match means the rule SELECTED "
                "this address, not that the device has been individually "
                "verified as the equipment the rule describes."
            ),
        },
        {
            "heading": "The hash does not prove the contents are true",
            "body": (
                "The manifest shows this bundle is unchanged since export. It "
                "is not a third-party attestation: the operator's own "
                "installation produced it, and the operator controls the "
                "database it was produced from."
            ),
        },
    ]
