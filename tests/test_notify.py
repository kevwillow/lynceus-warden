"""Tests for the notification layer."""

import logging
from unittest.mock import Mock

import pytest
import requests

from talos.notify import NtfyNotifier, NullNotifier, RecordingNotifier

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

    monkeypatch.setattr("talos.notify.requests.post", boom)
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

    monkeypatch.setattr("talos.notify.requests.post", boom)
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
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier(base_url="https://ntfy.sh", topic="myalerts").send("low", "t", "m")
    assert post.call_args.args[0] == "https://ntfy.sh/myalerts"


def test_ntfy_priority_low_is_2(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert post.call_args.kwargs["headers"]["Priority"] == "2"


def test_ntfy_priority_med_is_3(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("med", "t", "m")
    assert post.call_args.kwargs["headers"]["Priority"] == "3"


def test_ntfy_priority_high_is_5(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("high", "t", "m")
    assert post.call_args.kwargs["headers"]["Priority"] == "5"


def test_ntfy_tags_low_is_information_source(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert post.call_args.kwargs["headers"]["Tags"] == "information_source"


def test_ntfy_tags_med_is_warning(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("med", "t", "m")
    assert post.call_args.kwargs["headers"]["Tags"] == "warning"


def test_ntfy_tags_high_is_rotating_light(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("high", "t", "m")
    assert post.call_args.kwargs["headers"]["Tags"] == "rotating_light"


def test_ntfy_title_header(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t").send("low", "Watchlist hit", "m")
    assert post.call_args.kwargs["headers"]["Title"] == "Watchlist hit"


def test_ntfy_body_is_utf8_message(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    msg = "Café 🚨"
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", msg)
    assert post.call_args.kwargs["data"] == msg.encode("utf-8")


def test_ntfy_no_auth_header_when_token_none(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t", auth_token=None).send("low", "t", "m")
    assert "Authorization" not in post.call_args.kwargs["headers"]


def test_ntfy_auth_header_when_token_set(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t", auth_token="xyz").send("low", "t", "m")
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer xyz"


def test_ntfy_timeout_passed_through(mocker):
    post = mocker.patch("talos.notify.requests.post", return_value=_ok_response())
    NtfyNotifier("https://ntfy.sh", "t", timeout=5.0).send("low", "t", "m")
    assert post.call_args.kwargs["timeout"] == 5.0


def test_ntfy_200_returns_true(mocker):
    mocker.patch("talos.notify.requests.post", return_value=_ok_response(200))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is True


def test_ntfy_299_returns_true(mocker):
    mocker.patch("talos.notify.requests.post", return_value=_ok_response(299))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is True


def test_ntfy_300_returns_false(mocker):
    mocker.patch("talos.notify.requests.post", return_value=_ok_response(300))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_4xx_returns_false_and_logs(mocker, caplog):
    mocker.patch("talos.notify.requests.post", return_value=_ok_response(401))
    with caplog.at_level(logging.WARNING, logger="talos.notify"):
        result = NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert result is False
    assert any(r.levelname == "WARNING" for r in caplog.records)


def test_ntfy_5xx_returns_false(mocker):
    mocker.patch("talos.notify.requests.post", return_value=_ok_response(503))
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_connection_error_returns_false(mocker):
    mocker.patch(
        "talos.notify.requests.post",
        side_effect=requests.exceptions.ConnectionError("nope"),
    )
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_timeout_exception_returns_false(mocker):
    mocker.patch(
        "talos.notify.requests.post",
        side_effect=requests.exceptions.Timeout("slow"),
    )
    assert NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m") is False


def test_ntfy_does_not_raise_for_status(mocker):
    resp = _ok_response(500)
    mocker.patch("talos.notify.requests.post", return_value=resp)
    NtfyNotifier("https://ntfy.sh", "t").send("low", "t", "m")
    assert resp.raise_for_status.call_count == 0
