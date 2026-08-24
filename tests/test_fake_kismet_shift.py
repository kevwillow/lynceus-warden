"""Auto-shift-on-load, so a demo does not open on stale data."""
import json
import time

from lynceus.kismet import FIXTURE_ANCHOR_LAG_SECONDS, FakeKismetClient

_BASE = "kismet.device.base."


def _fixture(tmp_path, records):
    p = tmp_path / "fx.json"
    p.write_text(json.dumps(records), encoding="utf-8")
    return str(p)


def _rec(mac, first, last):
    return {
        f"{_BASE}macaddr": mac,
        f"{_BASE}first_time": first,
        f"{_BASE}last_time": last,
        f"{_BASE}type": "Wi-Fi AP",
        f"{_BASE}manuf": "Acme",
        f"{_BASE}signal": {"kismet.common.signal.last_signal": -40},
    }


def test_off_by_default_the_fixture_is_untouched(tmp_path):
    """The default MUST stay off: many suites assert on fixed fixture clocks."""
    path = _fixture(tmp_path, [_rec("aa:bb:cc:dd:ee:01", 1_700_000_000, 1_700_000_060)])
    c = FakeKismetClient(path)
    assert c._fixture[0][f"{_BASE}last_time"] == 1_700_000_060


def test_shift_puts_the_newest_record_an_hour_ago(tmp_path):
    path = _fixture(tmp_path, [_rec("aa:bb:cc:dd:ee:01", 1_700_000_000, 1_700_000_060)])
    before = int(time.time())
    c = FakeKismetClient(path, shift_to_now=True)
    after = int(time.time())
    newest = c._fixture[0][f"{_BASE}last_time"]
    assert before - FIXTURE_ANCHOR_LAG_SECONDS <= newest <= after - FIXTURE_ANCHOR_LAG_SECONDS


def test_shift_preserves_relative_spacing(tmp_path):
    """Spacing is the whole point: flattening it makes every per-hour widget uninformative."""
    path = _fixture(
        tmp_path,
        [
            _rec("aa:bb:cc:dd:ee:01", 1_700_000_000, 1_700_000_060),
            _rec("aa:bb:cc:dd:ee:02", 1_699_000_000, 1_699_900_000),
        ],
    )
    c = FakeKismetClient(path, shift_to_now=True)
    a, b = c._fixture
    assert a[f"{_BASE}last_time"] - b[f"{_BASE}last_time"] == 1_700_000_060 - 1_699_900_000
    assert a[f"{_BASE}last_time"] - a[f"{_BASE}first_time"] == 60


def test_shift_never_produces_a_future_timestamp(tmp_path):
    """The poller distrusts future-dated records; anchoring at `now` would create them."""
    path = _fixture(tmp_path, [_rec("aa:bb:cc:dd:ee:01", 1_700_000_000, 1_700_000_060)])
    c = FakeKismetClient(path, shift_to_now=True)
    now = int(time.time())
    for rec in c._fixture:
        assert rec[f"{_BASE}last_time"] <= now
        assert rec[f"{_BASE}first_time"] <= now


def test_shift_reaches_nested_seenby_times(tmp_path):
    """seenby carries its own clocks; leaving them behind splits one record across two eras."""
    rec = _rec("aa:bb:cc:dd:ee:01", 1_700_000_000, 1_700_000_060)
    rec[f"{_BASE}seenby"] = [
        {
            "kismet.common.seenby.first_time": 1_700_000_000,
            "kismet.common.seenby.last_time": 1_700_000_060,
            "kismet.common.seenby.source": {"kismet.datasource.name": "wlan0mon"},
        }
    ]
    path = _fixture(tmp_path, [rec])
    c = FakeKismetClient(path, shift_to_now=True)
    seen = c._fixture[0][f"{_BASE}seenby"][0]
    assert seen["kismet.common.seenby.last_time"] == c._fixture[0][f"{_BASE}last_time"]


def test_an_empty_fixture_does_not_explode(tmp_path):
    """max() over nothing raises; a demo fixture that got emptied must fail readably."""
    path = _fixture(tmp_path, [])
    c = FakeKismetClient(path, shift_to_now=True)
    assert c._fixture == []
