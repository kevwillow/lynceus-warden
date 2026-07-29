# Find My / Apple Continuity Decoder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify Apple BLE adverts by Continuity payload shape so `ble_manufacturer_id=004c` becomes a device class instead of a vendor-wide match.

**Architecture:** A pure stdlib decoder module is the only code that touches raw advertisement bytes; it returns a label and the bytes die with the local. The passive BLE bridge calls it inside the bleak callback, stores only the label, and threads it through the existing `process_observation` pipeline onto the device row and a new config-driven rule type.

**Tech Stack:** Python 3.11, pydantic v2, SQLite (WAL), FastAPI + Jinja2, pytest. No new dependencies.

**Source spec:** `docs/superpowers/specs/2026-07-28-ble-continuity-decoder-design.md` (commit `946a597`)

---

## Conventions for every task

- **Gate command** (Python 3.11 venv, never the system interpreter):
  `.venv/Scripts/python.exe -m pytest <args>`
- **Tests are gitignored in this repo (OPSEC).** Write them under `tests/`, run them, but **never `git add tests/`**. Every commit stages source/config/migration paths explicitly. Never `git add -A`.
- **Commit co-author line:** `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Do not bump `__version__`, do not tag, do not push.
- Known pre-existing failures that are NOT your regressions: the wheel-install packaging test on this Windows box, and `test_diag_home_ack_flow` under `-m diagnostic`.

---

### Task 1: Pure Continuity decoder module

**Files:**
- Create: `src/lynceus/ble_continuity.py`
- Test: `tests/test_ble_continuity.py` (gitignored — do not stage)

- [ ] **Step 1: Write the failing test**

```python
import pytest

from lynceus.ble_continuity import (
    APPLE_COMPANY_ID,
    CLASS_AIRPODS,
    CLASS_APPLE_UNKNOWN,
    CLASS_FIND_MY,
    CLASS_NEARBY,
    classify,
    classify_manufacturer_data,
)


def _tlv(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type, len(body)]) + body


def test_non_apple_company_id_returns_none():
    assert classify(0x0075, _tlv(0x12, b"\x00")) is None


def test_find_my_type_byte_classifies():
    assert classify(APPLE_COMPANY_ID, _tlv(0x12, b"\x00")) == CLASS_FIND_MY


def test_proximity_pairing_is_airpods():
    assert classify(APPLE_COMPANY_ID, _tlv(0x07, b"\x01\x02")) == CLASS_AIRPODS


def test_nearby_is_nearby():
    assert classify(APPLE_COMPANY_ID, _tlv(0x10, b"\x05")) == CLASS_NEARBY


def test_unknown_message_type_is_apple_unknown():
    assert classify(APPLE_COMPANY_ID, _tlv(0x0C, b"\xaa")) == CLASS_APPLE_UNKNOWN


def test_multi_tlv_find_my_outranks_nearby():
    payload = _tlv(0x10, b"\x05") + _tlv(0x12, b"\x00")
    assert classify(APPLE_COMPANY_ID, payload) == CLASS_FIND_MY


def test_empty_payload_returns_none():
    assert classify(APPLE_COMPANY_ID, b"") is None


def test_single_stray_byte_returns_none():
    assert classify(APPLE_COMPANY_ID, b"\x12") is None


def test_truncated_body_stops_without_raising():
    # Declares a 9-byte body but supplies 2 — must not raise, must not
    # invent a class from the partial parse.
    assert classify(APPLE_COMPANY_ID, b"\x12\x09\x00\x01") is None


def test_truncated_tail_keeps_earlier_valid_message():
    payload = _tlv(0x07, b"\x01") + b"\x12\x09\x00"
    assert classify(APPLE_COMPANY_ID, payload) == CLASS_AIRPODS


def test_zero_length_body_is_tolerated():
    assert classify(APPLE_COMPANY_ID, _tlv(0x12, b"")) == CLASS_FIND_MY


def test_classify_manufacturer_data_picks_highest_priority():
    data = {0x0075: b"\xff", APPLE_COMPANY_ID: _tlv(0x12, b"\x00")}
    assert classify_manufacturer_data(data) == CLASS_FIND_MY


def test_classify_manufacturer_data_empty_and_none():
    assert classify_manufacturer_data({}) is None
    assert classify_manufacturer_data(None) is None


def test_classify_manufacturer_data_tolerates_non_mapping():
    # The bridge's existing call sites accept tuples of company ids; a
    # non-mapping must degrade to None rather than raise.
    assert classify_manufacturer_data((0x004C, 0x0075)) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ble_continuity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'lynceus.ble_continuity'`

- [ ] **Step 3: Write the implementation**

Create `src/lynceus/ble_continuity.py`:

```python
"""Apple Continuity advertisement-payload decoder — pure, stdlib-only.

This module is the ONLY code in the project that reads raw BLE
advertisement payload bytes. It returns a derived class label and nothing
else; the bytes never leave the caller's stack frame. That is what keeps
the bridge's "we never retain advertisement content" invariant literally
true while still letting us tell an AirTag from a pair of AirPods.

Every Apple device advertises under company id 0x004C, so the company id
alone is useless as a signal. The discriminator is the Continuity
message-type byte inside the payload.
"""

from __future__ import annotations

APPLE_COMPANY_ID = 0x004C

_MSG_PROXIMITY_PAIRING = 0x07
_MSG_NEARBY = 0x10
_MSG_FIND_MY = 0x12

CLASS_FIND_MY_SEPARATED = "find_my_separated"
CLASS_FIND_MY = "find_my"
CLASS_AIRPODS = "airpods"
CLASS_NEARBY = "nearby"
CLASS_APPLE_UNKNOWN = "apple_unknown"

# Most surveillance-relevant first. A device emitting several Continuity
# messages in one advert resolves to the highest-ranked class present, so
# a tracker is never masked by a co-emitted Nearby message.
_PRIORITY = (
    CLASS_FIND_MY_SEPARATED,
    CLASS_FIND_MY,
    CLASS_AIRPODS,
    CLASS_NEARBY,
    CLASS_APPLE_UNKNOWN,
)

# UNVALIDATED — pending a real rig capture. Directly analogous to
# kismet._DRONE_ID_PATHS: the surrounding matcher is built and tested, but
# which bit of the Find My status byte means "separated from owner" has
# NOT been confirmed against hardware. Do not promote
# CLASS_FIND_MY_SEPARATED into an alerting rule until it has been.
_FIND_MY_SEPARATED_MASK = 0x04


def classify(company_id: int, payload: bytes) -> str | None:
    """Highest-priority Continuity class in one manufacturer-data entry.

    Returns None for a non-Apple company id and for any payload that
    yields no parseable message. Never raises.
    """
    if company_id != APPLE_COMPANY_ID:
        return None
    found: set[str] = set()
    i = 0
    n = len(payload)
    # Each message is [type][length][body]; a payload may chain several.
    while i + 1 < n:
        msg_type = payload[i]
        length = payload[i + 1]
        body = payload[i + 2 : i + 2 + length]
        if len(body) != length:
            # Truncated or lying length byte. Stop rather than attempt to
            # resync — a partial result from a bad parse is worse than none.
            break
        found.add(_classify_one(msg_type, body))
        i += 2 + length
    for cls in _PRIORITY:
        if cls in found:
            return cls
    return None


def classify_manufacturer_data(manufacturer_data) -> str | None:
    """Highest-priority class across every company-id entry in an advert.

    Accepts the bleak-shaped ``{company_id: payload_bytes}`` mapping. A
    non-mapping (some call sites pass a bare tuple of company ids) yields
    None rather than raising.
    """
    items = getattr(manufacturer_data, "items", None)
    if items is None:
        return None
    best: str | None = None
    for cid, payload in items():
        try:
            label = classify(int(cid), bytes(payload or b""))
        except (TypeError, ValueError):
            continue
        if label is None:
            continue
        if best is None or _PRIORITY.index(label) < _PRIORITY.index(best):
            best = label
    return best


def _classify_one(msg_type: int, body: bytes) -> str:
    if msg_type == _MSG_FIND_MY:
        if body and (body[0] & _FIND_MY_SEPARATED_MASK):
            return CLASS_FIND_MY_SEPARATED
        return CLASS_FIND_MY
    if msg_type == _MSG_PROXIMITY_PAIRING:
        return CLASS_AIRPODS
    if msg_type == _MSG_NEARBY:
        return CLASS_NEARBY
    return CLASS_APPLE_UNKNOWN
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ble_continuity.py -v`
Expected: PASS, 14 passed

- [ ] **Step 5: Lint**

Run: `.venv/Scripts/python.exe -m ruff check src/lynceus/ble_continuity.py`
Expected: `All checks passed!`

Do **not** run `ruff format` across the repo — this repo predates the current formatter's output and a repo-wide reformat would swamp the diff.

- [ ] **Step 6: Commit (source only — tests are gitignored)**

```bash
git add src/lynceus/ble_continuity.py && git commit -m "feat(ble): add pure Apple Continuity payload decoder

Classifies an Apple BLE advert by Continuity message type so company id
004c resolves to find_my / airpods / nearby rather than a vendor-wide
match. Pure and stdlib-only: this is the single place raw advertisement
bytes are read, and only a derived label leaves the function, so the
bridge's no-retained-payload invariant is preserved.

Multi-message adverts resolve by priority (find_my outranks nearby) so a
tracker is never masked by a co-emitted message. Malformed or truncated
payloads stop the walk and yield no class rather than resyncing.

The Find My separated-state bit is isolated in one constant flagged
UNVALIDATED pending a rig capture; nothing alerts on it yet.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Bridge wiring + observation field + privacy regression test

**Files:**
- Modify: `src/lynceus/kismet.py` (add field to `DeviceObservation` ~line 109; extend validator at ~line 196)
- Modify: `src/lynceus/bridges/ble.py` (import; `_BufferEntry` ~line 87; `_record_advert` ~line 153; `_build_observation` ~line 211)
- Test: `tests/test_ble_bridge_continuity.py` (gitignored — do not stage)

- [ ] **Step 1: Write the failing test**

```python
import dataclasses

from lynceus.ble_continuity import CLASS_AIRPODS, CLASS_FIND_MY
from lynceus.bridges.ble import _BufferEntry
from lynceus.kismet import DeviceObservation


def _tlv(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type, len(body)]) + body


def test_observation_accepts_device_class():
    obs = DeviceObservation(
        device_type="ble",
        mac="aa:bb:cc:dd:ee:ff",
        first_seen=1,
        last_seen=2,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        ble_device_class=CLASS_FIND_MY,
    )
    assert obs.ble_device_class == CLASS_FIND_MY


def test_device_class_blanked_for_non_ble():
    obs = DeviceObservation(
        device_type="wifi",
        mac="aa:bb:cc:dd:ee:ff",
        first_seen=1,
        last_seen=2,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        ble_device_class=CLASS_FIND_MY,
    )
    assert obs.ble_device_class is None


def test_buffer_entry_retains_no_raw_payload():
    """PRIVACY REGRESSION GUARD.

    The buffer must carry only the derived label. If someone later adds a
    raw-bytes field to _BufferEntry, this fails and forces the retention
    decision back into review rather than letting it drift.
    """
    field_types = {f.name: f.type for f in dataclasses.fields(_BufferEntry)}
    assert "device_class" in field_types
    for name, typ in field_types.items():
        assert "bytes" not in str(typ), f"{name} may retain raw payload bytes"


def test_record_advert_stores_label_not_bytes(ble_bridge):
    ble_bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:FF",
        rssi=-60,
        manufacturer_data={0x004C: _tlv(0x12, b"\x00")},
        service_uuids=(),
    )
    entry = ble_bridge._buffer["aa:bb:cc:dd:ee:ff"]
    assert entry.device_class == CLASS_FIND_MY
    assert 0x004C in entry.manufacturer_ids


def test_record_advert_none_for_non_apple(ble_bridge):
    ble_bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:11",
        rssi=-60,
        manufacturer_data={0x0075: b"\x01\x02"},
        service_uuids=(),
    )
    assert ble_bridge._buffer["aa:bb:cc:dd:ee:11"].device_class is None


def test_build_observation_carries_class(ble_bridge):
    ble_bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:22",
        rssi=-60,
        manufacturer_data={0x004C: _tlv(0x07, b"\x01")},
        service_uuids=(),
    )
    mac = "aa:bb:cc:dd:ee:22"
    obs = ble_bridge._build_observation(mac, ble_bridge._buffer[mac])
    assert obs.ble_device_class == CLASS_AIRPODS
```

Add this fixture to `tests/conftest.py` (gitignored) if an equivalent does not already exist — check first, and reuse the existing bridge fixture from `tests/test_ble_bridge.py` if one is there:

```python
import pytest

from lynceus.bridges.ble import BleBridge


@pytest.fixture
def ble_bridge(tmp_path):
    from lynceus.config import Config
    from lynceus.db import Database
    from lynceus.notify import NullNotifier
    from lynceus.rules import Ruleset

    config = Config(db_path=str(tmp_path / "t.db"))
    return BleBridge(
        db=Database(str(tmp_path / "t.db")),
        config=config,
        ruleset=Ruleset(rules=[]),
        allowlist_provider=lambda: None,
        notifier=NullNotifier(),
        severity_overrides=None,
        location_id="default",
        location_label="Default Location",
        adapter="hci1",
        flush_interval=5,
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ble_bridge_continuity.py -v`
Expected: FAIL — pydantic rejects the unknown field `ble_device_class` (`extra="forbid"` on `DeviceObservation`)

- [ ] **Step 3: Add the observation field**

In `src/lynceus/kismet.py`, immediately after the `ble_manufacturer_id` field declaration (~line 109), add:

```python
    # Derived Apple Continuity class (see ble_continuity.classify) — one of
    # 'find_my', 'find_my_separated', 'airpods', 'nearby', 'apple_unknown',
    # or None when the advert carried no decodable Continuity message. This
    # is a DERIVED label, never raw advertisement content; the payload bytes
    # it came from are not retained anywhere. Only the passive BLE bridge
    # populates it — the Kismet classic-HCI path has no payload and always
    # leaves it None.
    ble_device_class: str | None = None
```

Then extend the existing `_drop_uuids_for_non_ble` validator (~line 196) so the class is blanked for non-BLE observations too. Note the model is frozen, hence `object.__setattr__`:

```python
    @model_validator(mode="after")
    def _drop_uuids_for_non_ble(self) -> DeviceObservation:
        if self.device_type != "ble":
            if self.ble_service_uuids:
                object.__setattr__(self, "ble_service_uuids", ())
            if self.ble_device_class is not None:
                object.__setattr__(self, "ble_device_class", None)
        return self
```

- [ ] **Step 4: Wire the bridge**

In `src/lynceus/bridges/ble.py`, add to the relative imports (after the `..allowlist` import at line 31):

```python
from ..ble_continuity import classify_manufacturer_data
```

Add the field to `_BufferEntry` (~line 87), after `service_uuids`:

```python
    device_class: str | None = None
```

In `_record_advert`, immediately after the existing `uuids = tuple(service_uuids or ())` line, add:

```python
        # Raw payload bytes are read HERE and nowhere else, and only the
        # derived label is kept — see ble_continuity's module docstring.
        device_class = classify_manufacturer_data(manufacturer_data)
```

Then set it in both branches. The new-entry branch gains `device_class=device_class,` as the final constructor argument, and the existing-entry branch gains one more assignment alongside the others:

```python
            existing.device_class = device_class
```

In `_build_observation` (~line 217), add as the final constructor argument:

```python
            ble_device_class=entry.device_class,
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ble_bridge_continuity.py tests/test_ble_bridge.py tests/test_kismet.py -v`
Expected: PASS — including the pre-existing bridge and kismet suites, which must not regress

- [ ] **Step 6: Commit**

```bash
git add src/lynceus/kismet.py src/lynceus/bridges/ble.py && git commit -m "feat(ble): classify Apple adverts in the bridge callback

Decodes the Continuity class at the moment of receipt and buffers only
the derived label, so no raw advertisement payload is retained anywhere.
DeviceObservation gains ble_device_class, blanked for non-BLE
observations alongside ble_service_uuids.

The Kismet poll path is untouched and always leaves the field None —
classic HCI surfaces no advertisement payload.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Migration 023 + coalescing device persistence

**Files:**
- Create: `src/lynceus/migrations/023_devices_ble_device_class.sql`
- Create: `src/lynceus/migrations/023_devices_ble_device_class_down.sql`
- Modify: `src/lynceus/db.py` (`upsert_device` ~line 561; `list_devices` SELECT ~line 2005; `get_device`)
- Modify: `src/lynceus/poller.py` (`process_observation` `upsert_device` call ~line 218)
- Test: `tests/test_ble_device_class_persistence.py` (gitignored — do not stage)

- [ ] **Step 1: Write the failing test**

```python
from lynceus.ble_continuity import CLASS_AIRPODS, CLASS_FIND_MY
from lynceus.db import Database


def _db(tmp_path):
    return Database(str(tmp_path / "t.db"))


def test_upsert_stores_device_class(tmp_path):
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_FIND_MY,
    )
    assert db.get_device("aa:bb:cc:dd:ee:ff")["ble_device_class"] == CLASS_FIND_MY


def test_none_does_not_clobber_existing_class(tmp_path):
    """A later partial advert must not erase a class we already learned."""
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_FIND_MY,
    )
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=200,
        ble_device_class=None,
    )
    assert db.get_device("aa:bb:cc:dd:ee:ff")["ble_device_class"] == CLASS_FIND_MY


def test_new_class_overwrites_old(tmp_path):
    db = _db(tmp_path)
    for ts, cls in ((100, CLASS_FIND_MY), (200, CLASS_AIRPODS)):
        db.upsert_device(
            mac="aa:bb:cc:dd:ee:ff",
            device_type="ble",
            oui_vendor=None,
            is_randomized=0,
            now_ts=ts,
            ble_device_class=cls,
        )
    assert db.get_device("aa:bb:cc:dd:ee:ff")["ble_device_class"] == CLASS_AIRPODS


def test_default_arg_keeps_existing_callers_working(tmp_path):
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:01",
        device_type="wifi",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
    )
    assert db.get_device("aa:bb:cc:dd:ee:01")["ble_device_class"] is None


def test_list_devices_exposes_class(tmp_path):
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_AIRPODS,
    )
    rows = db.list_devices(limit=10)
    assert rows[0]["ble_device_class"] == CLASS_AIRPODS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ble_device_class_persistence.py -v`
Expected: FAIL — `TypeError: upsert_device() got an unexpected keyword argument 'ble_device_class'`

- [ ] **Step 3: Write the migration pair**

Create `src/lynceus/migrations/023_devices_ble_device_class.sql`:

```sql
-- Derived Apple Continuity class for BLE devices, populated only by the
-- passive BLE bridge (src/lynceus/ble_continuity.py). One of 'find_my',
-- 'find_my_separated', 'airpods', 'nearby', 'apple_unknown', or NULL when
-- the advert carried no decodable Continuity message.
--
-- This stores a DERIVED LABEL, never raw advertisement content. The
-- payload bytes it was computed from are read inside the bleak callback
-- and discarded there; nothing raw reaches the database.
--
-- Nullable with no default and no backfill: existing rows predate the
-- decoder and genuinely have no class. NULL means "unknown", which is
-- distinct from 'apple_unknown' (an Apple advert whose Continuity message
-- type we did not recognize).
--
-- Kismet-sourced devices keep NULL permanently — the classic-HCI capture
-- path surfaces no advertisement payload to decode.

ALTER TABLE devices ADD COLUMN ble_device_class TEXT;
```

Create `src/lynceus/migrations/023_devices_ble_device_class_down.sql`:

```sql
-- Reverses 023. SQLite has supported DROP COLUMN since 3.35 (2021-03);
-- the project's other reversible column migrations rely on the same.
ALTER TABLE devices DROP COLUMN ble_device_class;
```

- [ ] **Step 4: Update `upsert_device`**

Replace the method at `src/lynceus/db.py:561-582` with:

```python
    def upsert_device(
        self,
        mac: str,
        device_type: str,
        oui_vendor: str | None,
        is_randomized: int,
        now_ts: int,
        ble_device_class: str | None = None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO devices(
                    mac, device_type, first_seen, last_seen,
                    sighting_count, oui_vendor, is_randomized, ble_device_class
                )
                VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    sighting_count = devices.sighting_count + 1,
                    -- Coalescing, NOT clobbering: adverts are intermittent, so
                    -- a later capture that decodes to NULL must not erase a
                    -- class we already learned. A non-NULL new value wins.
                    ble_device_class = COALESCE(
                        excluded.ble_device_class, devices.ble_device_class
                    )
                """,
                (
                    mac,
                    device_type,
                    now_ts,
                    now_ts,
                    oui_vendor,
                    is_randomized,
                    ble_device_class,
                ),
            )
```

The parameter is keyword-optional so every existing call site keeps working unchanged.

- [ ] **Step 5: Expose the column to readers**

In `src/lynceus/db.py:2005-2006`, extend the `list_devices` SELECT column list:

```python
            "SELECT mac, device_type, first_seen, last_seen, sighting_count, "
            "oui_vendor, is_randomized, notes, probe_ssids, ble_name, "
            "ble_device_class, "
```

Then locate `get_device` and add `ble_device_class` to its SELECT the same way. If `get_device` uses `SELECT *`, no change is needed there — verify before editing:

Run: `.venv/Scripts/python.exe -c "import inspect, lynceus.db as d; print(inspect.getsource(d.Database.get_device))"`

- [ ] **Step 6: Thread it through the poller**

In `src/lynceus/poller.py`, the `upsert_device` call in `process_observation` (~line 218) gains one argument:

```python
    db.upsert_device(
        mac=obs.mac,
        device_type=obs.device_type,
        oui_vendor=obs.oui_vendor,
        is_randomized=int(obs.is_randomized),
        now_ts=now_ts,
        ble_device_class=obs.ble_device_class,
    )
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_ble_device_class_persistence.py tests/test_db.py tests/test_migration_rollback.py tests/test_poller.py -v`
Expected: PASS — the migration rollback suite must still pass, proving 023 reverses cleanly

- [ ] **Step 8: Commit**

```bash
git add src/lynceus/migrations/023_devices_ble_device_class.sql src/lynceus/migrations/023_devices_ble_device_class_down.sql src/lynceus/db.py src/lynceus/poller.py && git commit -m "feat(db): persist the derived BLE device class on devices (migration 023)

Adds nullable devices.ble_device_class and threads the decoded label from
the observation through process_observation. The upsert coalesces rather
than clobbers: adverts are intermittent, so a later capture decoding to
NULL must not erase a class already learned.

Stores a derived label only — no raw advertisement content reaches the
database. NULL means unknown, distinct from 'apple_unknown' (an Apple
advert whose message type we did not recognize).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `ble_device_class` rule type

**Files:**
- Modify: `src/lynceus/rules.py` (`RuleType` ~line 91-102; validator chain ~line 131-158; `evaluate` loop ~line 789)
- Modify: `config/rules.yaml` (commented example)
- Test: `tests/test_rules_ble_device_class.py` (gitignored — do not stage)

- [ ] **Step 1: Write the failing test**

```python
import pytest

from lynceus.ble_continuity import CLASS_AIRPODS, CLASS_FIND_MY
from lynceus.kismet import DeviceObservation
from lynceus.rules import Rule, Ruleset, evaluate


def _obs(device_class):
    return DeviceObservation(
        device_type="ble",
        mac="aa:bb:cc:dd:ee:ff",
        first_seen=1,
        last_seen=2,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        ble_device_class=device_class,
    )


def _ruleset(patterns):
    return Ruleset(
        rules=[
            Rule(
                name="find_my_tracker",
                rule_type="ble_device_class",
                severity="high",
                patterns=patterns,
                description="Find My tracker advertising nearby",
            )
        ]
    )


def test_matching_class_emits_hit():
    hits = evaluate(_ruleset([CLASS_FIND_MY]), _obs(CLASS_FIND_MY), is_new_device=True)
    assert len(hits) == 1
    assert hits[0].rule_type == "ble_device_class"
    assert hits[0].severity == "high"
    assert hits[0].mac == "aa:bb:cc:dd:ee:ff"
    assert CLASS_FIND_MY in hits[0].message


def test_non_matching_class_emits_nothing():
    hits = evaluate(_ruleset([CLASS_FIND_MY]), _obs(CLASS_AIRPODS), is_new_device=True)
    assert hits == []


def test_none_class_emits_nothing():
    hits = evaluate(_ruleset([CLASS_FIND_MY]), _obs(None), is_new_device=True)
    assert hits == []


def test_multiple_patterns_any_match():
    ruleset = _ruleset([CLASS_FIND_MY, CLASS_AIRPODS])
    assert len(evaluate(ruleset, _obs(CLASS_AIRPODS), is_new_device=True)) == 1


def test_empty_patterns_rejected():
    """No watchlist backs this rule type, so empty patterns cannot mean
    'delegate to the DB' the way they do for watchlist_* types."""
    with pytest.raises(ValueError, match="must have non-empty patterns"):
        Rule(
            name="bad",
            rule_type="ble_device_class",
            severity="high",
            patterns=[],
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_rules_ble_device_class.py -v`
Expected: FAIL — pydantic rejects `'ble_device_class'` as an invalid `RuleType` literal

- [ ] **Step 3: Add the rule type**

In `src/lynceus/rules.py`, add to the `RuleType` literal (before the closing `]` at line 102):

```python
    "ble_device_class",
```

- [ ] **Step 4: Add the validator branch**

In the `_validate_rule` chain, add a branch after the `watchful_recurrence` branch (~line 158) and before the delegation-capable `elif`:

```python
        elif self.rule_type == "ble_device_class":
            # Inverse of the watchlist_* types: no watchlist backs this
            # rule type, so empty patterns cannot mean "delegate to the DB".
            # The operator must name which decoded classes should alert.
            if not self.patterns:
                raise ValueError(
                    f"rule {self.name!r}: ble_device_class must have non-empty "
                    "patterns naming the device classes to alert on "
                    "(e.g. ['find_my'])"
                )
```

- [ ] **Step 5: Add the evaluate branch**

In `evaluate`, add inside the `for rule in ruleset.rules:` loop, alongside the other `rule.rule_type` branches:

```python
        if rule.rule_type == "ble_device_class":
            # In-memory only — the class is a decoded property of the
            # observation, not a curated watchlist identifier, so there is
            # no DB-delegation path here. Severity comes from the rule.
            if obs.ble_device_class and obs.ble_device_class in rule.patterns:
                msg = (
                    f"BLE device class {obs.ble_device_class} matched: "
                    f"{rule.description or rule.name}"
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
            continue
```

Match the surrounding branch style — if neighbouring branches use `elif` chaining rather than `continue`, follow that instead.

- [ ] **Step 6: Add the commented rules.yaml example**

In `config/rules.yaml`, near the commented `argus_ble_manufacturer_id` block (~line 135), add:

```yaml
  # Alerts on Apple devices whose Continuity payload decodes to a Find My
  # advert. Requires the passive BLE bridge (ble_bridge.enabled) — the
  # Kismet classic-HCI path surfaces no payload to decode, so this rule is
  # inert without it. Commented out by default.
  #
  # Deliberately matches 'find_my', not 'find_my_separated': the
  # separated-from-owner status bit is UNVALIDATED against real hardware
  # (see _FIND_MY_SEPARATED_MASK in ble_continuity.py). Add
  # 'find_my_separated' here only after a rig capture confirms it.
  #
  # - name: apple_find_my
  #   rule_type: ble_device_class
  #   severity: med
  #   patterns: [find_my]
  #   description: Apple Find My tracker advertising nearby
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_rules_ble_device_class.py tests/test_rules.py tests/test_seeds.py -v`
Expected: PASS — the existing rules suite must not regress

- [ ] **Step 8: Commit**

```bash
git add src/lynceus/rules.py config/rules.yaml && git commit -m "feat(rules): add the ble_device_class rule type

Matches a decoded Apple Continuity class against operator-named patterns,
with severity from rules.yaml. In-memory only — the class is a property of
the observation, not a curated watchlist identifier, so there is no
DB-delegation path.

Its validator REQUIRES non-empty patterns, the inverse of the watchlist_*
types: with no watchlist behind it, empty patterns cannot mean 'delegate
to the DB' and would silently match nothing.

Ships commented out in the template and matches 'find_my' rather than
'find_my_separated', which stays unvalidated pending a rig capture.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `/devices` UI column and detail row

**Files:**
- Modify: `src/lynceus/webui/templates/devices_list.html` (columns ~line 107-120; cells ~line 126-151)
- Modify: `src/lynceus/webui/templates/device_detail.html`
- Test: `tests/test_devices_ble_class_column.py` (gitignored — do not stage)

- [ ] **Step 1: Write the failing test**

```python
from lynceus.ble_continuity import CLASS_AIRPODS


def test_devices_list_shows_class_column(client, db):
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_AIRPODS,
    )
    body = client.get("/devices").text
    assert "BLE class" in body
    assert CLASS_AIRPODS in body


def test_devices_list_em_dash_when_no_class(client, db):
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:01",
        device_type="wifi",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
    )
    resp = client.get("/devices")
    assert resp.status_code == 200
    assert "BLE class" in resp.text


def test_device_detail_shows_class(client, db):
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_AIRPODS,
    )
    body = client.get("/devices/aa:bb:cc:dd:ee:ff").text
    assert CLASS_AIRPODS in body
```

Reuse the existing `client` and `db` fixtures from `tests/test_webui.py` / `tests/conftest.py`. Inspect those first and match their construction rather than inventing new fixtures.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_devices_ble_class_column.py -v`
Expected: FAIL — `assert "BLE class" in body`

- [ ] **Step 3: Add the column definition**

In `devices_list.html`, insert into `device_columns` immediately after the `'BLE name'` entry (line 112). The column carries no `sort` key, matching the other computed/unsorted columns:

```jinja
       {'label': 'BLE class', 'key': 'ble_device_class'},
```

- [ ] **Step 4: Add the matching cell**

Cell order must match column order exactly. Insert immediately after the `ble_name` cell (line 144):

```jinja
              <td>{{ d.ble_device_class or "—" }}</td>
```

- [ ] **Step 5: Add the detail row**

`device_detail.html` is **not** a table — it renders `<strong>label:</strong> value<br>` lines inside a `<p>` in an `<article>` (see lines 9-14), and its convention for an absent value is the literal word `unknown`, not the em-dash used in the list view. Add the line after the `vendor:` line at line 11:

```jinja
      <strong>BLE class:</strong> {{ device.ble_device_class or "unknown" }}<br>
```

Note the deliberate inconsistency with Step 4: the list view uses `—` because every other list column does, and the detail view uses `unknown` because every other detail line does. Each file keeps its own convention.

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_devices_ble_class_column.py tests/test_webui.py tests/test_devices_column_layout.py tests/test_columns_menu.py -v`
Expected: PASS — the column-layout and columns-menu suites assert column/cell alignment and will catch a mismatched insert

- [ ] **Step 7: Full gate**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS except the two known pre-existing failures (Windows wheel-install packaging test; `test_diag_home_ack_flow` under `-m diagnostic`). Any other failure is a regression — fix before committing.

Run: `.venv/Scripts/python.exe -m ruff check src/`
Expected: `All checks passed!`

- [ ] **Step 8: Commit**

```bash
git add src/lynceus/webui/templates/devices_list.html src/lynceus/webui/templates/device_detail.html && git commit -m "feat(ui): show the decoded BLE device class on /devices and device detail

Ambient Apple devices become legible instead of a wall of identical 004c
rows. Renders a neutral em-dash when absent, following the Category
column convention, so 'no class' and 'unknown class' read the same as
every other optional column.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## After all five tasks

- [ ] Add a CHANGELOG `[Unreleased]` entry describing the decoder (Added) — house style is a bold lead sentence followed by explanatory prose; match the existing BLE bridge entry directly above it.
- [ ] Update the BACKLOG `BLE-G1` entry: curation is now largely dissolved for Apple devices, and the remaining open item is validating `_FIND_MY_SEPARATED_MASK` on the rig before `find_my_separated` is promoted into any alerting rule.
- [ ] Do **not** bump the version, tag, or push. The release call is the operator's.

## Deliberately out of scope

- Follow-detection (a tracker persisting across locations) — the arc after this one.
- Enabling `ble_bridge.enabled` anywhere. BLE-G2 (the `kismet_sources` source-gate verification) is still unresolved and remains blocking for enablement.
- README claim softening — its own change, tracked as its own backlog entry.
