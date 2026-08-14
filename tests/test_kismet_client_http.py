"""Behavioural pin for the *real* Kismet HTTP client (``lynceus.kismet.KismetClient``).

WHY THIS FILE EXISTS
--------------------
Every other test in this suite reaches Kismet through ``FakeKismetClient`` or a
JSON fixture, both of which skip the HTTP layer entirely: they never construct a
URL, never call ``raise_for_status``, never decode a response body, and never
touch the urllib3 ``Retry`` policy mounted in ``KismetClient.__init__``. The
parser (``parse_kismet_device``) was therefore well covered while the transport
that feeds it had no test at all.

That gap hides failures that are individually silent and jointly load-bearing:

* **401/403.** A wrong or expired ``KISMET`` API key is the single most common
  field misconfiguration. If ``raise_for_status()`` were dropped from
  ``get_devices_since``, an auth rejection would decode as a non-list body and
  the poller would see "no devices" forever — a monitoring tool that reports
  all-clear while blind. ``health_check`` must additionally preserve the numeric
  ``status_code``, because the startup path keys its actionable message off the
  difference between "Kismet answered 401" and "nothing answered at all".
* **5xx and retry.** The mounted ``Retry`` exists so one transient Kismet blip
  does not abort a poll tick. Nothing pinned that 502/503/504 are actually
  retried, that a retry *succeeds* transparently, or that exhaustion surfaces
  the final status rather than hanging or silently returning empty. Equally,
  nothing pinned that 4xx is **not** retried — retrying a bad API key just
  multiplies the failure.
* **Malformed / non-list JSON.** Kismet behind a captive portal or a reverse
  proxy returns HTML, and some endpoints return an object where a list is
  expected. Both must raise rather than be iterated: iterating a ``dict`` yields
  its *keys*, so a missing ``isinstance(data, list)`` guard turns a bad payload
  into a stream of string "records" that the parser drops one by one, producing
  an empty poll with no error.

These tests drive a real loopback HTTP server rather than a mock, so the whole
shipped stack — requests, urllib3, the mounted ``HTTPAdapter`` and its ``Retry``
— is exercised as deployed. ``requests_mock``/``responses`` are not project
dependencies, and patching ``Session.get`` would sit *above* the retry logic and
so could not observe retries at all. Nothing here hard-codes an operator host:
the server binds an ephemeral port on 127.0.0.1.

NOTE ON THE AUTOUSE RETRY FIXTURE
---------------------------------
``tests/conftest.py`` defines an autouse ``_kismet_no_runtime_retry`` fixture
that patches ``urllib3.util.retry.Retry.increment`` to raise ``MaxRetryError``
immediately, making retries a no-op for the whole suite (a deliberate
wall-clock optimisation for the ~120 webui apps that probe a closed port).

Its docstring justifies the patch by saying the structural
``test_h5_session_retry_mounted_for_*`` tests still verify the configured
attributes. **Those tests do not exist** — the name appears nowhere in this
repository except that docstring and the BACKLOG entry recording the gap. Until
this file, *no* test observed retry behaviour, configured or actual.

This module therefore overrides that fixture with a no-op of the same name (see
``_kismet_no_runtime_retry`` below), restoring genuine retry behaviour for these
tests only. The override is self-proving: if it ever stopped taking effect, the
patched ``increment`` would raise on the first 503 and
``test_get_devices_since_retries_then_succeeds_after_transient_503`` would fail
instead of silently degrading to a no-retry assertion.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from lynceus.kismet import KismetClient

# A device record that parses cleanly, so a successful fetch can be asserted on
# its *content* rather than merely on "no exception was raised".
_GOOD_DEVICE = {
    "kismet.device.base.macaddr": "AA:BB:CC:11:22:33",
    "kismet.device.base.type": "Wi-Fi AP",
    "kismet.device.base.first_time": 1700000000,
    "kismet.device.base.last_time": 1700000100,
    "kismet.device.base.name": "test-ssid",
    "kismet.device.base.signal": {"kismet.common.signal.last_signal": -55},
}


@pytest.fixture(autouse=True)
def _kismet_no_runtime_retry():
    """Override conftest's autouse retry-disabling fixture with a no-op.

    conftest patches ``Retry.increment`` to raise immediately so the suite does
    not pay real backoff against closed ports. This module needs the genuine
    urllib3 retry loop, and pays nothing for it: every request here is answered
    by a live loopback server, so only the deliberate exhaustion test sleeps.

    Overriding by name is the documented way to opt a module out of an autouse
    fixture defined in a parent conftest.
    """
    yield


@dataclass
class _Exchange:
    """One scripted HTTP reply. The final entry repeats for later requests."""

    status: int
    body: str
    content_type: str = "application/json"


@dataclass
class _Recorder:
    """Requests the scripted server actually received."""

    paths: list[str] = field(default_factory=list)
    cookies: list[str | None] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.paths)


@contextmanager
def _scripted_kismet(*script: _Exchange) -> Iterator[tuple[str, _Recorder]]:
    """Run a loopback HTTP server that replays ``script``, yielding (base_url, recorder).

    Binds 127.0.0.1 on an ephemeral port, so this never contacts a real host and
    never encodes anything about the operator's rig.
    """
    recorder = _Recorder()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            with lock:
                index = recorder.count
                recorder.paths.append(self.path)
                recorder.cookies.append(self.headers.get("Cookie"))
            exchange = script[index] if index < len(script) else script[-1]
            payload = exchange.body.encode("utf-8")
            self.send_response(exchange.status)
            self.send_header("Content-Type", exchange.content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            """Silence stderr access logging."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _client(base_url: str, api_key: str | None = None) -> KismetClient:
    return KismetClient(base_url, api_key=api_key, timeout=5.0)


# --------------------------------------------------------------------------
# Auth failures: must raise, and must NOT be retried.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 403])
def test_get_devices_since_raises_on_auth_failure(status: int) -> None:
    """A rejected API key must surface as an HTTPError, not as an empty device list.

    Without ``raise_for_status()`` the poller would treat an auth rejection as a
    successful poll that happened to see nothing, and report all-clear forever.
    """
    with _scripted_kismet(_Exchange(status, '{"error": "denied"}')) as (url, rec):
        client = _client(url, api_key="wrong-key")
        with pytest.raises(requests.HTTPError) as excinfo:
            client.get_devices_since(1700000000)

    assert excinfo.value.response is not None
    assert excinfo.value.response.status_code == status
    # Auth failures are deliberately absent from status_forcelist: retrying a
    # bad key cannot change the answer. Exactly one request proves the absence.
    assert rec.count == 1


def test_health_check_reports_auth_status_code_and_stays_unreachable() -> None:
    """health_check must preserve the numeric status when Kismet answered 401.

    The startup path distinguishes "Kismet answered but rejected us" (status_code
    set) from "nothing answered" (status_code None) to pick its error message.
    Collapsing 401 to a bare unreachable result loses that distinction.
    """
    with _scripted_kismet(_Exchange(401, '{"error": "denied"}')) as (url, _rec):
        result = _client(url, api_key="wrong-key").health_check()

    assert result["reachable"] is False
    assert result["status_code"] == 401
    assert result["version"] is None
    assert result["error"]


def test_api_key_is_sent_as_kismet_cookie() -> None:
    """The configured API key must actually reach Kismet as the KISMET cookie."""
    body = json.dumps([_GOOD_DEVICE])
    with _scripted_kismet(_Exchange(200, body)) as (url, rec):
        _client(url, api_key="secret-key").get_devices_since(1700000000)

    assert rec.count == 1
    assert rec.cookies[0] is not None
    assert "KISMET=secret-key" in rec.cookies[0]


def test_no_api_key_sends_no_kismet_cookie() -> None:
    """Absence pin, paired with the presence test above: no key means no cookie."""
    body = json.dumps([_GOOD_DEVICE])
    with _scripted_kismet(_Exchange(200, body)) as (url, rec):
        observations = _client(url, api_key=None).get_devices_since(1700000000)

    assert len(observations) == 1  # the request really happened
    assert rec.count == 1
    assert "KISMET=" not in (rec.cookies[0] or "")


# --------------------------------------------------------------------------
# Server errors and retry behaviour.
# --------------------------------------------------------------------------


def test_get_devices_since_raises_on_500() -> None:
    """500 is not in status_forcelist: it must raise immediately, without retrying."""
    with _scripted_kismet(_Exchange(500, '{"error": "boom"}')) as (url, rec):
        client = _client(url)
        with pytest.raises(requests.HTTPError) as excinfo:
            client.get_devices_since(1700000000)

    assert excinfo.value.response is not None
    assert excinfo.value.response.status_code == 500
    assert rec.count == 1


def test_get_devices_since_retries_then_succeeds_after_transient_503() -> None:
    """One transient 503 must be retried transparently and the poll must still succeed.

    This is the whole point of the mounted Retry policy: a single Kismet blip
    must not abort a poll tick. It is also the self-check on this module's
    opt-out of conftest's retry-disabling fixture -- if that override stopped
    working, ``Retry.increment`` would raise on the first 503 and this fails.
    """
    body = json.dumps([_GOOD_DEVICE])
    script = (_Exchange(503, '{"error": "transient"}'), _Exchange(200, body))
    with _scripted_kismet(*script) as (url, rec):
        observations = _client(url).get_devices_since(1700000000)

    # The retry happened...
    assert rec.count == 2
    # ...and the caller got real parsed data, not an empty list.
    assert len(observations) == 1
    assert observations[0].mac == "aa:bb:cc:11:22:33"
    assert observations[0].device_type == "wifi"
    assert observations[0].ssid == "test-ssid"
    assert observations[0].rssi == -55


@pytest.mark.parametrize("status", [502, 503, 504])
def test_get_devices_since_retries_every_forcelisted_status(status: int) -> None:
    """Each status in status_forcelist must actually trigger a retry."""
    body = json.dumps([_GOOD_DEVICE])
    with _scripted_kismet(_Exchange(status, "{}"), _Exchange(200, body)) as (url, rec):
        observations = _client(url).get_devices_since(1700000000)

    assert rec.count == 2
    assert len(observations) == 1


def test_get_devices_since_retry_exhaustion_surfaces_the_failing_status() -> None:
    """A Kismet that is down for good must raise after the configured attempts.

    Retry(total=3) means 1 initial attempt + 3 retries. Exhaustion must surface
    the final 503 as an HTTPError -- never hang, and never quietly return [].
    """
    with _scripted_kismet(_Exchange(503, '{"error": "down"}')) as (url, rec):
        client = _client(url)
        with pytest.raises(requests.RequestException) as excinfo:
            client.get_devices_since(1700000000)

    assert rec.count == 4
    response = getattr(excinfo.value, "response", None)
    assert response is not None
    assert response.status_code == 503


# --------------------------------------------------------------------------
# Malformed and wrongly-shaped payloads.
# --------------------------------------------------------------------------


def test_get_devices_since_raises_on_malformed_json() -> None:
    """A non-JSON body (captive portal / proxy HTML) must raise, not be swallowed."""
    html = "<html><body>Sign in to continue</body></html>"
    with _scripted_kismet(_Exchange(200, html, content_type="text/html")) as (url, rec):
        client = _client(url)
        with pytest.raises(ValueError):  # requests' JSONDecodeError subclasses ValueError
            client.get_devices_since(1700000000)

    assert rec.count == 1


@pytest.mark.parametrize(
    "payload",
    ['{"kismet.device.base.macaddr": "aa:bb:cc:11:22:33"}', '"a string"', "42", "null"],
)
def test_get_devices_since_rejects_non_list_payload(payload: str) -> None:
    """A non-list body must raise ValueError rather than be iterated.

    Iterating a dict yields its *keys*, so without the isinstance guard a bad
    payload degrades into a batch of unparseable string "records" that the
    parser drops silently -- an empty poll that reports no error at all.
    """
    with _scripted_kismet(_Exchange(200, payload)) as (url, _rec):
        client = _client(url)
        with pytest.raises(ValueError, match="expected list response"):
            client.get_devices_since(1700000000)


def test_health_check_reports_invalid_json_without_raising() -> None:
    """health_check must convert a malformed body into a structured failure result.

    Pins ACTUAL behaviour, which is not what the source's shape implies.
    ``health_check`` orders its handlers ``except requests.RequestException``
    then ``except ValueError``, and the latter formats its message as
    ``f"invalid json: {e}"``. But ``response.json()`` raises
    ``requests.exceptions.JSONDecodeError``, whose MRO is::

        JSONDecodeError -> InvalidJSONError -> RequestException -> OSError
                        -> json.JSONDecodeError -> ValueError

    It is a ``RequestException`` *first*, so the earlier handler always wins and
    the ``ValueError`` branch is unreachable for any malformed HTTP body. The
    observable consequence is below: the ``invalid json:`` prefix never
    appears, and ``status_code`` is None (the wrapped decode error carries no
    ``response``), making a malformed body indistinguishable from an unreachable
    host in the field.

    This test records the behaviour as it ships, so it stays green today; if the
    handler order is ever corrected, this test fails loudly and is the note
    explaining what to expect instead.
    """
    with _scripted_kismet(_Exchange(200, "not json at all", content_type="text/html")) as (
        url,
        _rec,
    ):
        result = _client(url).health_check()

    assert result["reachable"] is False
    assert result["version"] is None
    assert result["status_code"] is None
    # Presence: the raw decoder message is what actually surfaces...
    assert "Expecting value" in result["error"]
    # ...and absence: the branch that would have prefixed it never runs.
    assert not result["error"].startswith("invalid json:")


def test_health_check_success_reports_version() -> None:
    """Presence baseline for the failure assertions above: a good probe reports up."""
    body = json.dumps({"kismet.system.version": "2026.01.1"})
    with _scripted_kismet(_Exchange(200, body)) as (url, _rec):
        result = _client(url).health_check()

    assert result["reachable"] is True
    assert result["version"] == "2026.01.1"
    assert result["error"] is None
    assert result["status_code"] == 200


def test_list_sources_rejects_non_list_payload() -> None:
    """list_sources documents ValueError on non-list payloads; pin that it does."""
    with _scripted_kismet(_Exchange(200, '{"not": "a list"}')) as (url, _rec):
        client = _client(url)
        with pytest.raises(ValueError, match="expected list response"):
            client.list_sources()


def test_list_sources_raises_on_auth_failure() -> None:
    """list_sources documents requests.HTTPError on non-2xx; pin that it does."""
    with _scripted_kismet(_Exchange(403, '{"error": "denied"}')) as (url, rec):
        client = _client(url, api_key="wrong-key")
        with pytest.raises(requests.HTTPError):
            client.list_sources()

    assert rec.count == 1


def test_list_sources_parses_running_sources_on_success() -> None:
    """Presence baseline: a good payload yields normalized, filtered source dicts."""
    body = json.dumps(
        [
            {
                "kismet.datasource.name": "wlan1mon",
                "kismet.datasource.interface": "wlan1",
                "kismet.datasource.capture_interface": "wlan1mon",
                "kismet.datasource.uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "kismet.datasource.running": True,
                "kismet.datasource.type_driver": {"kismet.datasource.driver.type": "linuxwifi"},
            },
            {"kismet.datasource.name": "stopped0", "kismet.datasource.running": False},
        ]
    )
    with _scripted_kismet(_Exchange(200, body)) as (url, _rec):
        sources = _client(url).list_sources()

    assert len(sources) == 1  # the not-running source was filtered out
    assert sources[0]["name"] == "wlan1mon"
    assert sources[0]["interface"] == "wlan1"
    assert sources[0]["driver"] == "linuxwifi"
    assert sources[0]["running"] is True
