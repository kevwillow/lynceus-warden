"""Defects found by red-teaming the finished feature, each with a guard.

An adversarial read of the disclosure contract by a cold model found
these after the seven planned tasks were done and green. They are kept
in one file because what they have in common is the lesson: every one is
a route to disclosure or to a wrong document that the ORIGINAL guards
could not see, because those guards checked the rules the design had
already thought of.

⛔ One reported defect is NOT here, because it was refuted rather than
fixed: "the exact-MAC alert filter still leaks bystander MACs from alert
text". Every rule message this product emits interpolates ``obs.mac``,
the alert's own device, and none quotes a second address. The finding was
right that row ownership is not the same as safe row contents, which is
why the redaction sweep below exists; it was wrong that a live path
produced it.
"""

from __future__ import annotations

import json

import pytest

from lynceus.casefile.bundle import (
    REDACTED_ADDRESS,
    BundleExists,
    build_artifacts,
    write_directory,
)
from lynceus.casefile.query import build_case_file
from lynceus.cli.export_case import main
from tests.test_casefile_query import NOW, START, TARGET, _add_evidence, _seed

STRANGER = "ca:fe:ba:be:00:77"


def test_a_second_export_refuses_rather_than_merging_into_the_first(tmp_path):
    """⛔ The bundle name is the MAC and the date, so exporting twice in a
    day collides. Merging leaves the FIRST export's files in place: an
    evidence snapshot since marked do_not_publish would still be sitting
    in the directory the operator hands over, while the new manifest and
    the new document both say it was withheld.
    """
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    case = build_case_file(db, TARGET, now_ts=NOW)
    out = tmp_path / "cases"

    root = write_directory(case, out)
    assert (root / "manifest.json").exists()

    with pytest.raises(BundleExists):
        write_directory(case, out)
    db.close()


def test_force_replaces_the_bundle_leaving_no_file_the_manifest_disclaims(tmp_path):
    """The whole point of refusing: after --force, every file present is
    one the new manifest covers."""
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    out = tmp_path / "cases"
    root = write_directory(build_case_file(db, TARGET, now_ts=NOW), out)

    # A leftover from an earlier export that the new one does not produce.
    stale = root / "evidence" / "9999.json"
    stale.write_text('{"mac": "aa:bb:cc:dd:ee:01"}')

    root = write_directory(build_case_file(db, TARGET, now_ts=NOW), out, overwrite=True)
    db.close()

    manifest = json.loads((root / "manifest.json").read_text())
    on_disk = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
    assert not stale.exists(), "a file from the previous export survived"
    assert on_disk - {"manifest.json"} == set(manifest["files"]), (
        "the bundle holds a file the manifest does not cover"
    )


def test_the_cli_refuses_the_second_export_and_says_how_to_proceed(tmp_path, capsys):
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    db.close()
    args = [TARGET, "--db", str(tmp_path / "case.db"), "--out", str(tmp_path / "cases")]

    assert main(args) == 0
    capsys.readouterr()
    assert main(args) != 0
    err = capsys.readouterr().err
    assert "already exists" in err
    assert "--force" in err, "a refusal must name the way forward"
    assert main([*args, "--force"]) == 0


def test_an_old_window_returns_its_rows_rather_than_none(tmp_path):
    """⛔ The window has to be applied in SQL. Filtering the newest capped
    rows afterwards returns nothing for an old window on a busy device,
    and then reports the rows it never looked at as over the cap: a
    document that says "no sightings" about a period full of them.
    """
    db, _ = _seed(tmp_path, name="busy.db")
    with db.transaction() as conn:
        # 1500 recent rows, comfortably past the cap, all AFTER the window.
        conn.executemany(
            "INSERT INTO sightings(mac, ts, rssi, ssid, location_id) VALUES (?,?,?,?,?)",
            [(TARGET, NOW - 3600 + i, -50, None, "loc-a") for i in range(1500)],
        )
    cf = build_case_file(db, TARGET, now_ts=NOW, since_ts=START - 10, until_ts=START + 100)
    db.close()
    assert cf.sightings, "the window's own rows were filtered away by the cap"
    assert all(START - 10 <= s["ts"] <= START + 100 for s in cf.sightings)


def test_alerts_past_the_cap_are_counted_and_disclosed(tmp_path):
    """⛔ Evidence is reached by iterating the alerts returned, so an alert
    past the cap takes its evidence with it, including a do_not_publish
    row whose exclusion would then go uncounted. Disclosing the alert cap
    is what keeps the withheld count honest about its own scope.
    """
    db, _ = _seed(tmp_path, name="manyalerts.db")
    with db.transaction() as conn:
        conn.executemany(
            "INSERT INTO alerts(ts, rule_name, mac, message, severity, rule_type) "
            "VALUES (?,?,?,?,?,?)",
            [
                (START + i, "watchlist-mac", TARGET, "seen", "high", "watchlist_mac")
                for i in range(1200)
            ],
        )
    cf = build_case_file(db, TARGET, now_ts=NOW)
    db.close()
    assert cf.excluded_counts["alerts_over_cap"] > 0
    readme = build_artifacts(cf)["README.txt"].decode()
    assert "not listed" in readme
    assert "capped" in readme


def test_an_address_in_free_text_is_redacted_and_counted(tmp_path):
    """⛔ The contract is "no unapproved address in any file", and the
    original guards enforced it field by field. Free text is the
    open-ended part: an SSID is whatever a nearby device calls itself.
    """
    db, _ = _seed(tmp_path, name="freetext.db")
    db.insert_sighting(TARGET, START + 500, -55, f"net-{STRANGER}", "loc-a")
    cf = build_case_file(db, TARGET, now_ts=NOW)
    artifacts = build_artifacts(cf)
    db.close()

    for name, payload in artifacts.items():
        assert STRANGER.encode() not in payload, f"a stranger's address survived in {name}"
    assert cf.excluded_counts["unapproved_addresses_redacted"] >= 1
    assert REDACTED_ADDRESS.encode() in artifacts["data/sightings.csv"]


def test_the_devices_own_address_is_never_redacted(tmp_path):
    """The sweep must not eat the record it exists to publish."""
    db, alert_id = _seed(tmp_path, name="keepmine.db")
    _add_evidence(db, alert_id, TARGET)
    artifacts = build_artifacts(build_case_file(db, TARGET, now_ts=NOW))
    db.close()
    assert TARGET.encode() in artifacts["case-file.html"]
    assert TARGET.encode() in artifacts["data/sightings.csv"]


def test_csv_cells_cannot_run_as_spreadsheet_formulas(tmp_path):
    """The repo neutralised this for the web UI's exports; the case file
    is the second exporter and must not be the weak one."""
    db, _ = _seed(tmp_path, name="formula.db")
    db.insert_sighting(TARGET, START + 600, -55, '=HYPERLINK("x","click")', "loc-a")
    artifacts = build_artifacts(build_case_file(db, TARGET, now_ts=NOW))
    db.close()
    sightings = artifacts["data/sightings.csv"].decode()
    assert "=HYPERLINK" in sightings, "the fixture value never reached the CSV"
    for line in sightings.splitlines():
        for cell in line.split(","):
            assert not cell.startswith("=HYPERLINK"), f"formula cell: {cell}"
    assert "'=HYPERLINK" in sightings, "not neutralised as a text literal"


def test_a_watchlist_match_is_not_presented_as_an_identification(tmp_path):
    """A rule can cover a whole manufacturer prefix, so a match selects an
    address rather than identifying the equipment."""
    db, alert_id = _seed(tmp_path, name="claims.db")
    _add_evidence(db, alert_id, TARGET)
    artifacts = build_artifacts(build_case_file(db, TARGET, now_ts=NOW))
    db.close()
    html = artifacts["case-file.html"].decode()
    readme = artifacts["README.txt"].decode()
    assert "does not mean" in html.lower() or "not that the device" in html.lower()
    assert "known surveillance equipment" not in readme, (
        "the README asserted the match proves what the device IS"
    )
    assert "not an identification" in readme


def test_the_empty_database_path_is_not_created_by_a_read(tmp_path):
    """Guards the CLI's existence check, which stops a typo producing an
    empty database, an empty case file and an exit code of zero."""
    missing = tmp_path / "typo.db"
    assert main([TARGET, "--db", str(missing), "--out", str(tmp_path / "o")]) != 0
    assert not missing.exists()


def test_an_evidence_filename_cannot_leave_the_bundle(tmp_path):
    """alert_id becomes a path component, so it is coerced to int."""
    db, alert_id = _seed(tmp_path, name="ids.db")
    _add_evidence(db, alert_id, TARGET)
    cf = build_case_file(db, TARGET, now_ts=NOW)
    db.close()
    for name in build_artifacts(cf):
        assert ".." not in name
        assert not name.startswith("/")


def test_the_manifest_still_covers_the_redacted_bytes(tmp_path):
    """⛔ Redaction happens BEFORE hashing. Hashing first would leave a
    manifest certifying a bundle nobody has."""
    from lynceus.casefile.manifest import build_manifest

    db, _ = _seed(tmp_path, name="order.db")
    db.insert_sighting(TARGET, START + 700, -55, f"net-{STRANGER}", "loc-a")
    artifacts = build_artifacts(build_case_file(db, TARGET, now_ts=NOW))
    db.close()

    shipped = json.loads(artifacts["manifest.json"])
    recomputed = build_manifest({k: v for k, v in artifacts.items() if k != "manifest.json"})
    assert shipped["files"] == recomputed["files"]
    assert shipped["manifest_sha256"] == recomputed["manifest_sha256"]


def test_until_covers_the_whole_of_the_named_day(tmp_path, capsys):
    """Midnight at the START of the day would exclude almost all of it,
    and the operator would see their own date printed with none of it."""
    db, _ = _seed(tmp_path, name="untilday.db")
    import datetime as _dt

    day = _dt.datetime.fromtimestamp(START, tz=_dt.UTC)
    midday = int(
        day.replace(hour=12, minute=0, second=0, microsecond=0).timestamp()
    )
    db.insert_sighting(TARGET, midday, -55, None, "loc-a")
    db.close()

    code = main(
        [
            TARGET,
            "--db",
            str(tmp_path / "untilday.db"),
            "--out", str(tmp_path / "cases"),
            "--since", day.strftime("%Y-%m-%d"),
            "--until", day.strftime("%Y-%m-%d"),
        ]
    )
    assert code == 0, capsys.readouterr().err
    bundle = next((tmp_path / "cases").iterdir())
    rows = (bundle / "data" / "sightings.csv").read_text().strip().splitlines()
    assert len(rows) > 1, "a same-day --since/--until window returned no rows"


def test_building_the_artifacts_twice_is_identical(tmp_path):
    """⛔ The CLI calls build_artifacts a second time to report the digest,
    and build_artifacts writes the redaction count back onto the CaseFile.
    That makes the second call see a different input from the first, so
    "the same bytes come out" is a property that has to be asserted rather
    than assumed: if it stopped holding, the digest printed on the
    terminal would not be the digest of the bundle on disk.
    """
    db, _ = _seed(tmp_path, name="idem.db")
    db.insert_sighting(TARGET, START + 500, -55, f"net-{STRANGER}", "loc-a")
    case = build_case_file(db, TARGET, now_ts=NOW)
    db.close()

    first = build_artifacts(case)
    second = build_artifacts(case)
    assert case.excluded_counts["unapproved_addresses_redacted"] >= 1, (
        "no redaction happened, so this would not exercise the write-back"
    )
    assert set(first) == set(second)
    for name in first:
        assert first[name] == second[name], f"second build differs: {name}"


def test_every_file_including_a_rebuilt_one_is_swept(tmp_path):
    """The README is rebuilt after the sweep so it can carry the count.
    A rebuilt file that skipped the sweep would be the one file in the
    bundle the rule had not been applied to."""
    db, _ = _seed(tmp_path, name="sweepall.db")
    db.insert_sighting(TARGET, START + 500, -55, f"net-{STRANGER}", "loc-a")
    artifacts = build_artifacts(build_case_file(db, TARGET, now_ts=NOW))
    db.close()
    for name, payload in artifacts.items():
        assert STRANGER.encode() not in payload, f"unswept: {name}"
