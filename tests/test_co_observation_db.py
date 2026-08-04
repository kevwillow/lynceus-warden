import pytest

from lynceus.db import Database


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "lynceus.db"))
    yield database
    database.close()


def seed(db, mac, sightings):
    db._conn.execute(
        "INSERT INTO devices(mac, device_type, first_seen, last_seen, sighting_count, "
        "is_randomized) VALUES (?, 'wifi', ?, ?, ?, 0)",
        (mac, min(ts for ts, _ in sightings), max(ts for ts, _ in sightings), len(sightings)),
    )
    db._conn.executemany(
        "INSERT OR IGNORE INTO locations(id, label) VALUES (?, ?)",
        [(str(location_id), f"location {location_id}") for _, location_id in sightings],
    )
    db._conn.executemany(
        "INSERT INTO sightings(mac, ts, location_id) VALUES (?, ?, ?)",
        [(mac, ts, str(location_id)) for ts, location_id in sightings],
    )


def observed(db, mac="aa:aa:aa:aa:aa:01", **kwargs):
    return db.list_co_observations(
        mac,
        now_ts=kwargs.pop("now_ts", 10_000),
        since_ts=kwargs.pop("since_ts", 0),
        **kwargs,
    )


def test_returns_per_location_counts_deltas_and_local_dates(db):
    anchor = "aa:aa:aa:aa:aa:01"
    candidate = "bb:bb:bb:bb:bb:01"
    seed(db, anchor, [(100, 1), (200, 1), (300, 1), (400, 1)])
    seed(db, candidate, [(100, 1), (220, 1), (330, 1), (440, 1)])

    result = observed(
        db,
        anchor,
        now_ts=500,
        proximity_seconds=50,
        gap_seconds=50,
    )

    assert result == {
        "range": {"since_ts": 0, "now_ts": 500},
        "proximity_seconds": 50,
        "gap_seconds": 50,
        "anchor_runs_by_location": {"1": 4},
        "total_candidates": 1,
        "candidates": [
            {
                "mac": candidate,
                "location_id": "1",
                "shared_anchor_runs": 4,
                "shared_candidate_runs": 4,
                "candidate_total_runs": 4,
                "shared_days": 1,
                "delta_min": 0,
                "delta_median": 20,
                "delta_max": 40,
                "first_shared_ts": 100,
                "last_shared_ts": 400,
            }
        ],
    }

    local_anchor = "aa:aa:aa:aa:aa:02"
    local_candidate = "bb:bb:bb:bb:bb:02"
    seed(db, local_anchor, [(1_767_329_700, 2), (1_767_330_300, 2)])
    seed(db, local_candidate, [(1_767_329_700, 2), (1_767_330_300, 2)])
    local = observed(
        db,
        local_anchor,
        now_ts=1_767_330_400,
        since_ts=1_767_329_600,
        proximity_seconds=0,
        gap_seconds=900,
        tz_offset_seconds=-18_000,
    )
    assert local["candidates"][0]["shared_days"] == 2


@pytest.mark.parametrize("base_ts", [1_000, 81_000])
def test_proximity_boundary_is_independent_of_timestamp_alignment(db, base_ts):
    anchor = f"aa:aa:aa:aa:aa:{base_ts // 1000:02x}"
    included = f"bb:bb:bb:bb:bb:{base_ts // 1000:02x}"
    excluded = f"cc:cc:cc:cc:cc:{base_ts // 1000:02x}"
    seed(db, anchor, [(base_ts, 1)])
    seed(db, included, [(base_ts + 300, 1)])
    seed(db, excluded, [(base_ts + 301, 1)])

    result = observed(
        db,
        anchor,
        now_ts=base_ts + 400,
        since_ts=base_ts - 10,
        proximity_seconds=300,
    )

    assert [row["mac"] for row in result["candidates"]] == [included]
    assert result["candidates"][0]["delta_min"] == 300


def test_candidate_runs_and_anchor_runs_are_counted_separately(db):
    anchor = "aa:aa:aa:aa:aa:03"
    candidate = "bb:bb:bb:bb:bb:03"
    seed(db, anchor, [(ts, 1) for ts in range(0, 401, 10)])
    seed(db, candidate, [(0, 1), (100, 1), (200, 1), (300, 1), (400, 1)])

    result = observed(
        db,
        anchor,
        now_ts=400,
        proximity_seconds=0,
        gap_seconds=10,
    )

    row = result["candidates"][0]
    assert result["anchor_runs_by_location"] == {"1": 1}
    assert row["shared_anchor_runs"] == 1
    assert row["shared_candidate_runs"] == 5
    assert row["candidate_total_runs"] == 5


def test_limit_keeps_candidate_with_more_shared_anchor_runs(db):
    anchor = "aa:aa:aa:aa:aa:04"
    seed(db, anchor, [(0, 1), (100, 1), (200, 1)])
    featured = "bb:bb:bb:bb:bb:04"
    seed(db, featured, [(0, 1), (100, 1), (200, 1)])
    for suffix in range(3):
        mac = f"cc:cc:cc:cc:cc:{suffix:02x}"
        seed(db, mac, [(0, 1)] * 20)

    result = observed(
        db,
        anchor,
        now_ts=200,
        proximity_seconds=0,
        gap_seconds=50,
        limit=2,
    )

    assert result["total_candidates"] == 4
    assert featured in [row["mac"] for row in result["candidates"]]
    assert result["candidates"][0]["mac"] == featured


def test_rejects_invalid_parameters(db):
    seed(db, "aa:aa:aa:aa:aa:05", [(100, 1)])
    invalid = [
        {"now_ts": True},
        {"since_ts": 101, "now_ts": 100},
        {"proximity_seconds": -1},
        {"gap_seconds": 0},
        {"limit": 0},
        {"limit": 201},
        {"tz_offset_seconds": False},
    ]
    for kwargs in invalid:
        with pytest.raises(ValueError):
            observed(db, "aa:aa:aa:aa:aa:05", **kwargs)


def test_query_plan_starts_with_an_anchor_index_lookup(db):
    anchor = "aa:aa:aa:aa:aa:06"
    nearby = "bb:bb:bb:bb:bb:06"
    seed(db, anchor, [(5_000, 1)])
    seed(db, nearby, [(5_000, 1)])
    for device_number in range(50):
        mac = f"dd:dd:dd:{device_number:02x}:00:06"
        seed(db, mac, [(100_000 + ts, 1) for ts in range(150)])

    statements = []
    db._conn.set_trace_callback(statements.append)
    try:
        observed(
            db,
            anchor,
            now_ts=10_000,
            since_ts=0,
            proximity_seconds=30,
        )
    finally:
        db._conn.set_trace_callback(None)

    query = next(statement for statement in statements if "discovered_candidates" in statement)
    plan = db._conn.execute(f"EXPLAIN QUERY PLAN {query}").fetchall()
    details = [row[3] for row in plan]
    assert any("SEARCH sightings USING INDEX idx_sightings_mac_ts" in detail for detail in details)
    assert any("SEARCH c USING INDEX idx_sightings_ts" in detail for detail in details)
    # This is the load-bearing assertion. The replaced corpus-wide query could
    # not use idx_sightings_mac_ts at all, because it segmented every mac in the
    # window before filtering. Measured against that shape, the assertion fires.


def test_shipped_default_location_id_is_not_numeric(db):
    """config/lynceus.example.yaml ships `location_id: default`.

    An int() cast on location_id passes every fixture that happens to use
    numeric-looking ids and then raises ValueError on every stock install.
    """
    anchor = "aa:aa:aa:aa:aa:07"
    candidate = "bb:bb:bb:bb:bb:07"
    seed(db, anchor, [(5_000, "default")])
    seed(db, candidate, [(5_010, "default")])

    result = observed(db, anchor, proximity_seconds=60)

    assert result["anchor_runs_by_location"] == {"default": 1}
    assert result["candidates"][0]["location_id"] == "default"
    assert result["candidates"][0]["mac"] == candidate


def test_work_does_not_scale_with_in_window_corpus_size(db):
    """The query must be bounded by anchor data, not by how much else was logged.

    The plan assertion above proves the anchor lookup is index-driven; it does
    not prove the rest of the corpus is avoided. This counts rows actually read
    at two corpus sizes with all noise INSIDE the query window.
    """
    anchor = "aa:aa:aa:aa:aa:08"
    seed(db, anchor, [(5_000, 1)])
    seed(db, "bb:bb:bb:bb:bb:08", [(5_010, 1)])

    def steps_with(first, count):
        """VM steps consumed, via set_progress_handler.

        set_authorizer is the wrong instrument here: it fires once per column at
        statement-prepare time, so its count is identical whether the query
        touches ten rows or ten million. Measured -- an authorizer-based version
        of this test passed against a deliberately corpus-wide mutation.
        """
        for device_number in range(first, first + count):
            mac = f"ee:ee:ee:{device_number:02x}:00:08"
            seed(db, mac, [(20_000 + step * 30, 1) for step in range(100)])
        counter = [0]

        def on_progress():
            counter[0] += 1
            return 0

        db._conn.set_progress_handler(on_progress, 100)
        try:
            observed(db, anchor, now_ts=1_000_000, proximity_seconds=60)
        finally:
            db._conn.set_progress_handler(None, 0)
        return counter[0]

    small = steps_with(0, 5)
    large = steps_with(5, 40)  # cumulative 45 devices, 9x the noise, all in window

    # Bounded work: 9x the corpus must not cost anywhere near 9x the steps.
    assert large < small * 3, f"work scaled with corpus: {small} -> {large} VM steps"


# --- shared probe SSIDs -------------------------------------------------
#
# Corroborating metadata for the co-observation panel. It promotes nothing --
# v3 has no band left to promote -- so these tests pin the returned shape and
# the corpus-rarity denominator, never a ranking of suspicion.


def probed(db, mac, payload):
    """Seed a device row carrying a raw probe_ssids payload.

    Takes the payload as raw text, not a list, so the malformed-row cases can
    write exactly the bytes a hand-edited or truncated row would carry.
    """
    db._conn.execute(
        "INSERT OR REPLACE INTO devices(mac, device_type, first_seen, last_seen, "
        "sighting_count, is_randomized, probe_ssids) VALUES (?, 'wifi', 0, 0, 0, 0, ?)",
        (mac, payload),
    )


def test_shared_probe_ssids_returns_only_the_intersection(db):
    probed(db, "aa:1", '["home-net", "cafe", "attwifi"]')
    probed(db, "bb:1", '["cafe", "attwifi", "office"]')

    # Both are shared by exactly these two devices, so corpus rarity ties and
    # the documented ssid ASC tie-break decides -- which keeps the order total,
    # so the panel cannot reshuffle equal-rarity rows between refreshes.
    assert [r["ssid"] for r in db.shared_probe_ssids("aa:1", "bb:1")] == ["attwifi", "cafe"]


def test_shared_probe_ssids_orders_rarest_in_corpus_first(db):
    # attwifi is everywhere; kev-hotspot is shared by exactly the two devices.
    probed(db, "aa:1", '["attwifi", "kev-hotspot"]')
    probed(db, "bb:1", '["attwifi", "kev-hotspot"]')
    for n in range(8):
        probed(db, f"cc:{n}", '["attwifi"]')

    rows = db.shared_probe_ssids("aa:1", "bb:1")
    assert [(r["ssid"], r["corpus_devices"]) for r in rows] == [
        ("kev-hotspot", 2),
        ("attwifi", 10),
    ]


def test_shared_probe_ssids_counts_distinct_devices_not_rows(db):
    # The same SSID twice in one device's array is still one device.
    probed(db, "aa:1", '["dup", "dup"]')
    probed(db, "bb:1", '["dup"]')

    assert db.shared_probe_ssids("aa:1", "bb:1") == [{"ssid": "dup", "corpus_devices": 2}]


@pytest.mark.parametrize(
    "payload",
    [
        "not json at all",
        "",
        None,
        # ⭐ Both of these are VALID JSON, so json_valid() admits them and only
        # json_type(...) = 'array' rejects them. Each carries the shared SSID
        # itself, so if the array guard is dropped json_each unnests it as a
        # real value and corpus_devices silently reads 3 instead of 2. An
        # earlier version of this test used non-colliding names and therefore
        # passed with the guard removed -- it proved nothing. Measured.
        '"shared"',  # bare string: one scalar row
        '{"ssid": "shared"}',  # object: one member row
    ],
)
def test_shared_probe_ssids_skips_malformed_rows_without_throwing(db, payload):
    """A malformed row must skip silently, never 500 the panel, and never count.

    Two obligations, and the second is the one that bites: the row must not
    throw, AND it must not contribute to corpus_devices -- which is the number
    the operator reads to decide whether a shared SSID means anything.
    """
    probed(db, "aa:1", '["shared"]')
    probed(db, "bb:1", '["shared"]')
    probed(db, "zz:1", payload)

    assert db.shared_probe_ssids("aa:1", "bb:1") == [{"ssid": "shared", "corpus_devices": 2}]


def test_shared_probe_ssids_skips_non_string_elements(db):
    """Carried fix v1 18 / v2 9: non-string elements are skipped.

    A valid array can still contain numbers or nulls. Those are not network
    names and must not appear as SSIDs nor count toward corpus_devices.
    """
    probed(db, "aa:1", '[1, null, "real-net", 2.5]')
    probed(db, "bb:1", '[1, "real-net", null]')

    assert db.shared_probe_ssids("aa:1", "bb:1") == [{"ssid": "real-net", "corpus_devices": 2}]


def test_shared_probe_ssids_empty_when_probe_capture_is_off(db):
    """Probe capture is off by default, so [] is the common case, not an error."""
    probed(db, "aa:1", None)
    probed(db, "bb:1", None)

    assert db.shared_probe_ssids("aa:1", "bb:1") == []


def test_shared_probe_ssids_honours_limit(db):
    probed(db, "aa:1", '["a", "b", "c", "d"]')
    probed(db, "bb:1", '["a", "b", "c", "d"]')

    assert len(db.shared_probe_ssids("aa:1", "bb:1", limit=2)) == 2


@pytest.mark.parametrize("bad", [0, -1, 201, True, 1.5, "10"])
def test_shared_probe_ssids_rejects_out_of_range_limit(db, bad):
    with pytest.raises(ValueError):
        db.shared_probe_ssids("aa:1", "bb:1", limit=bad)
