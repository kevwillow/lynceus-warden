"""Tests for the notification layer."""

import logging
from unittest.mock import Mock

import pytest
import requests

from lynceus.config import Config
from lynceus.notify import (
    NtfyNotifier,
    NullNotifier,
    RecordingNotifier,
    build_metadata_suffix,
    build_notifier,
)

# ---------------------------------- helpers ----------------------------------


def _ok_response(status: int = 200) -> Mock:
    """Build a mock requests Response that records raise_for_status calls."""
    resp = Mock(spec=requests.Response)
    resp.status_code = status
    resp.text = ""
    resp.raise_for_status = Mock()
    return resp


# --------------------------------- NullNotifier ------------------------------


def test_null_notifier_returns_true():
    n = NullNotifier()
    assert n.send("low", "title", "msg") is True


def test_null_notifier_makes_no_http(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("NullNotifier must not make HTTP calls")

    monkeypatch.setattr("lynceus.notify.requests.post", boom)
    assert NullNotifier().send("high", "x", "y") is True


# ------------------------------- RecordingNotifier ---------------------------


def test_recording_notifier_returns_true():
    assert RecordingNotifier().send("low", "t", "m") is True


def test_recording_notifier_records_calls_in_order():
    n = RecordingNotifier()
    n.send("low", "t1", "m1")
    n.send("med", "t2", "m2")
    n.send("high", "t3", "m3")
    assert n.calls == [
        ("low", "t1", "m1"),
        ("med", "t2", "m2"),
        ("high", "t3", "m3"),
    ]


def test_recording_notifier_makes_no_http(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("RecordingNotifier must not make HTTP calls")

    monkeypatch.setattr("lynceus.notify.requests.post", boom)
    RecordingNotifier().send("low", "t", "m")


# ----------------------------- NtfyNotifier ctor -----------------------------


def test_ntfy_strips_trailing_slash():
    n = NtfyNotifier(base_url="https://ntfy.sh/", topic="myalerts")
    assert n.base_url == "https://ntfy.sh"


def test_ntfy_empty_topic_raises():
    with pytest.raises(ValueError):
        NtfyNotifier(base_url="https://ntfy.sh", topic="")


def test_ntfy_whitespace_topic_raises():
    with pytest.raises(ValueError):
        NtfyNotifier(base_url="https://ntfy.sh", topic="   ")


# ----------------------------- NtfyNotifier send -----------------------------


def test_ntfy_url_construction(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier(base_url="https://ntfy.sh", topic="myalerts").send("low", "t", "m")
    assert post.call_args.args[0] == "https://ntfy.sh/myalerts"


def test_ntfy_priority_low_is_2(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert post.call_args.kwargs["headers"]["Priority"] == "2"


def test_ntfy_priority_med_is_3(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("med", "t", "m")
    assert post.call_args.kwargs["headers"]["Priority"] == "3"


def test_ntfy_priority_high_is_5(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("high", "t", "m")
    assert post.call_args.kwargs["headers"]["Priority"] == "5"


def test_ntfy_tags_low_is_information_source(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert post.call_args.kwargs["headers"]["Tags"] == "information_source"


def test_ntfy_tags_med_is_warning(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("med", "t", "m")
    assert post.call_args.kwargs["headers"]["Tags"] == "warning"


def test_ntfy_tags_high_is_rotating_light(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("high", "t", "m")
    assert post.call_args.kwargs["headers"]["Tags"] == "rotating_light"


def test_ntfy_title_header(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("low", "Watchlist hit", "m")
    assert post.call_args.kwargs["headers"]["Title"] == "Watchlist hit"


def test_ntfy_body_is_utf8_message(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    msg = "Café 🚨"
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", msg)
    assert post.call_args.kwargs["data"] == msg.encode("utf-8")


def test_ntfy_no_auth_header_when_token_none(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t", auth_token=None).send("low", "t", "m")
    assert "Authorization" not in post.call_args.kwargs["headers"]


def test_ntfy_auth_header_when_token_set(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t", auth_token="xyz").send("low", "t", "m")
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer xyz"


def test_ntfy_timeout_passed_through(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t", timeout=5.0).send("low", "t", "m")
    assert post.call_args.kwargs["timeout"] == 5.0


def test_ntfy_200_returns_true(mocker):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(200))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is True


def test_ntfy_299_returns_true(mocker):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(299))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is True


def test_ntfy_300_returns_false(mocker):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(300))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_4xx_returns_false_and_logs(mocker, caplog):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(401))
    with caplog.at_level(logging.WARNING, logger="lynceus.notify"):
        result = NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert result is False
    assert any(r.levelname == "WARNING" for r in caplog.records)


def test_ntfy_5xx_returns_false(mocker):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(503))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_connection_error_returns_false(mocker):
    mocker.patch(
        "lynceus.notify.requests.post",
        side_effect=requests.exceptions.ConnectionError("nope"),
    )
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_timeout_exception_returns_false(mocker):
    mocker.patch(
        "lynceus.notify.requests.post",
        side_effect=requests.exceptions.Timeout("slow"),
    )
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_does_not_raise_for_status(mocker):
    resp = _ok_response(500)
    mocker.patch("lynceus.notify.requests.post", return_value=resp)
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert resp.raise_for_status.call_count == 0


# ---- send_with_detail: reused by lynceus-setup's ntfy test-publish ----------
#
# The setup wizard's test-publish (cli.setup.probe_ntfy) routes through this so
# its POST carries the EXACT daemon headers/format — a 200 at setup validates
# the production request shape, not a hand-rolled approximation. send() now
# delegates to send_with_detail; these tests pin the (ok, detail) contract and
# that the returned detail string never leaks the raw topic.


def test_send_with_detail_success_returns_true_none(mocker):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(200))
    ok, detail = NtfyNotifier("https://ntfy.sh", "t").send_with_detail("low", "ti", "msg")
    assert ok is True
    assert detail is None


def test_send_with_detail_non2xx_returns_false_and_status(mocker):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(503))
    ok, detail = NtfyNotifier("https://ntfy.sh", "t").send_with_detail("low", "ti", "msg")
    assert ok is False
    assert detail == "HTTP 503"


def test_send_with_detail_exception_returns_false_and_redacts_topic(mocker):
    mocker.patch(
        "lynceus.notify.requests.post",
        side_effect=requests.exceptions.ConnectionError(
            f"Max retries exceeded with url: /{_LEAK_TOPIC}"
        ),
    )
    ok, detail = NtfyNotifier("https://ntfy.sh", _LEAK_TOPIC).send_with_detail(
        "low", "ti", "msg"
    )
    assert ok is False
    assert "ConnectionError" in detail
    assert _LEAK_TOPIC not in detail


def test_send_with_detail_carries_daemon_headers(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(200))
    NtfyNotifier("https://ntfy.sh", "t").send_with_detail("low", "Lynceus setup test", "body")
    headers = post.call_args.kwargs["headers"]
    assert headers["Title"] == "Lynceus setup test"
    assert headers["Tags"] == "information_source"
    assert headers.get("X-Sequence-ID")


def test_send_delegates_to_send_with_detail(mocker):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(200))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is True


# ------ regression: each alert publishes as a distinct ntfy message ----------
#
# ntfy treats messages sharing an X-Sequence-ID as updates that OVERWRITE the
# prior one (server source parses x-sequence-id / sequence-id / sid into the
# message's SequenceID). notify.py now stamps a unique X-Sequence-ID per send
# so every detection lands as its own append-only history entry instead of
# repeated alerts collapsing into one overwritten message. THESE TESTS PIN
# THAT CONTRACT — they fail against the pre-fix code, which sent no such header.


def test_ntfy_sets_sequence_id_header(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    seq = post.call_args.kwargs["headers"].get("X-Sequence-ID")
    assert seq  # present and non-empty


def test_ntfy_sequence_id_unique_per_alert(mocker):
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    n = NtfyNotifier("https://ntfy.sh", "t")
    n.send("high", "Alert A", "device 1 seen")
    n.send("high", "Alert B", "device 2 seen")
    seq_ids = [c.kwargs["headers"]["X-Sequence-ID"] for c in post.call_args_list]
    assert len(seq_ids) == 2
    assert seq_ids[0] != seq_ids[1]


def test_ntfy_sequence_id_distinct_for_identical_repeat_alert(mocker):
    # The reported failure mode: repeat alerts for the SAME device (identical
    # severity/title/body) overwrote each other. Each must still get a distinct
    # sequence id so the broker keeps both.
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    n = NtfyNotifier("https://ntfy.sh", "t")
    n.send("high", "Pineapple seen", "AA:BB:CC:DD:EE:FF")
    n.send("high", "Pineapple seen", "AA:BB:CC:DD:EE:FF")
    seq_ids = [c.kwargs["headers"]["X-Sequence-ID"] for c in post.call_args_list]
    assert seq_ids[0] != seq_ids[1]


# --------------- regression: topic must never appear in logs ----------------
#
# The ntfy topic is a shared-secret URL path component on public brokers.
# Every log surface in notify.py runs the topic through the redact helper;
# these tests fence that contract. THESE TESTS MUST FAIL PRE-FIX.

_LEAK_TOPIC = "lynceus-supersecret-leak"


def test_ntfy_failure_log_does_not_leak_topic(mocker, caplog):
    mocker.patch(
        "lynceus.notify.requests.post",
        side_effect=requests.exceptions.ConnectionError("boom"),
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.notify"):
        NtfyNotifier("https://ntfy.sh", _LEAK_TOPIC).send("low", "t", "m")
    assert _LEAK_TOPIC not in caplog.text


def test_ntfy_failure_log_does_not_leak_topic_via_exception_repr(mocker, caplog):
    # `requests` exceptions' __str__() typically embeds the full URL
    # including the topic. The fix logs only the exception type name and
    # MUST NOT call str(exc) on the warning line.
    mocker.patch(
        "lynceus.notify.requests.post",
        side_effect=requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='ntfy.sh', port=443): "
            f"Max retries exceeded with url: /{_LEAK_TOPIC} (Caused by ...)"
        ),
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.notify"):
        NtfyNotifier("https://ntfy.sh", _LEAK_TOPIC).send("low", "t", "m")
    assert _LEAK_TOPIC not in caplog.text


def test_ntfy_non_2xx_warning_does_not_leak_topic(mocker, caplog):
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(503))
    with caplog.at_level(logging.WARNING, logger="lynceus.notify"):
        NtfyNotifier("https://ntfy.sh", _LEAK_TOPIC).send("low", "t", "m")
    assert _LEAK_TOPIC not in caplog.text


def test_ntfy_success_log_does_not_leak_topic(mocker, caplog):
    # Success path emits no info-level "publishing to {url}" line today, but
    # this test fences against future regressions: if anyone adds one, it
    # MUST go through the redact helper.
    mocker.patch("lynceus.notify.requests.post", return_value=_ok_response(200))
    with caplog.at_level(logging.DEBUG, logger="lynceus.notify"):
        result = NtfyNotifier("https://ntfy.sh", _LEAK_TOPIC).send("low", "t", "m")
    assert result is True
    assert _LEAK_TOPIC not in caplog.text


# --------------------------------- build_notifier ---------------------------


def test_build_notifier_returns_null_when_no_ntfy_config():
    cfg = Config()
    n = build_notifier(cfg)
    assert isinstance(n, NullNotifier)


def test_build_notifier_returns_ntfy_when_url_and_topic_set():
    cfg = Config(ntfy_url="https://ntfy.sh/", ntfy_topic="my-alerts")
    n = build_notifier(cfg)
    assert isinstance(n, NtfyNotifier)
    assert n.base_url == "https://ntfy.sh"
    assert n.topic == "my-alerts"
    assert n.auth_token is None


def test_build_notifier_passes_auth_token_through():
    cfg = Config(
        ntfy_url="https://ntfy.sh",
        ntfy_topic="my-alerts",
        ntfy_auth_token="secret-xyz",
    )
    n = build_notifier(cfg)
    assert isinstance(n, NtfyNotifier)
    assert n.auth_token == "secret-xyz"


# ------------------------- priority_override (migration 018) -----------------
# These tests cover the priority_override knob added for watchful escalation
# (OQ-1 resolution: option (b), one optional Notifier.send parameter at the
# emit-site). Severity-to-priority defaults are validated above; these
# tests assert the override path and the parallel-list bookkeeping on
# RecordingNotifier.


def test_ntfy_priority_override_overrides_severity_mapped_priority(mocker):
    """priority_override=4 must override SEVERITY_TO_PRIORITY['high']=5.

    This is the load-bearing assertion for OQ-1: the watchful escalation
    emit-site passes severity='high' (so /alerts renders the high badge)
    and priority_override=4 (so ntfy's notification prominence is the
    scare-factor-mitigated 4, not the urgent 5). Both must hold.
    """
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send(
        "high", "t", "m", priority_override=4
    )
    assert post.call_args.kwargs["headers"]["Priority"] == "4"


def test_ntfy_priority_override_keeps_severity_tag(mocker):
    """priority_override decouples priority from severity but NOT tag.

    The watchful escalation uses severity='high' so the rotating_light
    tag reflects the operator's 'this matters' intent; only Priority
    is decoupled. This guards against accidental tag override during
    future refactors of the priority_override path.
    """
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send(
        "high", "t", "m", priority_override=4
    )
    assert post.call_args.kwargs["headers"]["Tags"] == "rotating_light"


def test_ntfy_priority_override_none_uses_severity_default(mocker):
    """priority_override=None must be equivalent to omitting the kwarg.

    Regression guard: existing call sites pass three positional args
    only. If the priority_override default were ever changed from None
    to a numeric default, every existing ntfy notification would
    silently change priority. This test pins the default behavior.
    """
    post = mocker.patch("lynceus.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send(
        "high", "t", "m", priority_override=None
    )
    assert post.call_args.kwargs["headers"]["Priority"] == "5"


def test_recording_notifier_records_priority_overrides_in_parallel():
    """RecordingNotifier.priority_overrides parallels .calls by index.

    Existing tests positionally unpack ``severity, title, message =
    rec.calls[i]`` and depend on .calls being a 3-tuple. The new
    priority_override bookkeeping is a separate parallel list to
    preserve that shape; this test asserts both alignment and
    backward-compat.
    """
    n = RecordingNotifier()
    n.send("low", "t1", "m1")
    n.send("high", "t2", "m2", priority_override=4)
    n.send("med", "t3", "m3", priority_override=None)
    assert n.calls == [
        ("low", "t1", "m1"),
        ("high", "t2", "m2"),
        ("med", "t3", "m3"),
    ]
    assert n.priority_overrides == [None, 4, None]


def test_null_notifier_accepts_priority_override():
    """NullNotifier must accept priority_override without error.

    The watchful escalation path goes through Notifier.send regardless
    of the configured backend; NullNotifier (the default when ntfy is
    not configured) must not raise.
    """
    assert NullNotifier().send("high", "t", "m", priority_override=4) is True


# --------------------- build_metadata_suffix (vendor reconciliation) --------


def test_suffix_empty_when_metadata_none():
    assert build_metadata_suffix(None, oui_vendor="Liteon") == ""


def test_suffix_matched_only_when_oui_missing():
    # No OUI to reconcile against -> matched vendor alone.
    assert (
        build_metadata_suffix({"vendor": "Flock Safety"}, oui_vendor=None)
        == " | vendor: Flock Safety"
    )


def test_suffix_backward_compatible_without_oui_arg():
    # Existing call shape (metadata only) must keep working.
    assert build_metadata_suffix({"vendor": "Flock Safety"}) == " | vendor: Flock Safety"


def test_suffix_agreement_shows_single_vendor():
    # matched == oui -> no redundant doubling.
    assert (
        build_metadata_suffix({"vendor": "Apple"}, oui_vendor="Apple")
        == " | vendor: Apple"
    )


def test_suffix_agreement_is_case_insensitive_and_trimmed():
    assert (
        build_metadata_suffix({"vendor": "Apple"}, oui_vendor=" apple ")
        == " | vendor: Apple"
    )


def test_suffix_divergence_shows_both():
    assert (
        build_metadata_suffix({"vendor": "Flock Safety"}, oui_vendor="Liteon Technology")
        == " | vendor: Flock Safety (OUI: Liteon Technology)"
    )


def test_suffix_divergence_with_confidence_orders_oui_before_confidence():
    assert (
        build_metadata_suffix(
            {"vendor": "Flock Safety", "confidence": 90}, oui_vendor="Liteon Technology"
        )
        == " | vendor: Flock Safety (OUI: Liteon Technology) | confidence: 90"
    )


def test_suffix_no_matched_vendor_does_not_surface_oui():
    # The notification anchors on the matched (watchlist) vendor; an OUI
    # with no matched label has nothing to reconcile and is not shown.
    assert (
        build_metadata_suffix({"confidence": 42}, oui_vendor="Liteon Technology")
        == " | confidence: 42"
    )
