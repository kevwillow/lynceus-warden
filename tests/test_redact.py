"""Tests for the shared ntfy redaction helpers."""

from __future__ import annotations

import pytest

from lynceus.redact import redact_ntfy_topic, redact_topic_in_url

# ---------- redact_ntfy_topic ----------------------------------------------


def test_redact_topic_none_returns_empty():
    assert redact_ntfy_topic(None) == ""


def test_redact_topic_empty_returns_empty():
    assert redact_ntfy_topic("") == ""


def test_redact_topic_short_4_chars_fully_masked():
    # < 6 chars collapses to "•••" so no portion of the secret leaks.
    out = redact_ntfy_topic("abcd")
    assert out == "•••"
    assert "abcd" not in out


def test_redact_topic_short_5_chars_fully_masked():
    out = redact_ntfy_topic("abcde")
    assert out == "•••"
    assert "abcde" not in out


def test_redact_topic_6_chars_keeps_prefix_and_suffix():
    out = redact_ntfy_topic("abcdef")
    # First 4 + bullets + last 2.
    assert out == "abcd•••ef"


def test_redact_topic_8_chars():
    out = redact_ntfy_topic("topic-42")
    assert out == "topi•••42"


def test_redact_topic_16_chars():
    out = redact_ntfy_topic("lynceus-deadbeef")
    assert out == "lync•••ef"
    # Middle is masked; full secret is not present.
    assert "lynceus-deadbeef" not in out
    assert "deadbe" not in out


def test_redact_topic_64_chars():
    topic = "a" * 60 + "wxyz"
    out = redact_ntfy_topic(topic)
    assert out == "aaaa•••yz"
    assert topic not in out


def test_redact_topic_unicode():
    # Topic of 6+ chars including unicode — first 4 + bullets + last 2,
    # operating on Python str semantics (code points, not bytes).
    out = redact_ntfy_topic("CaféStrasse")
    assert out.startswith("Café")
    assert out.endswith("se")
    assert "•••" in out


# ---------- redact_topic_in_url --------------------------------------------


def test_redact_url_bare_host_unchanged():
    assert redact_topic_in_url("https://ntfy.sh") == "https://ntfy.sh"


def test_redact_url_root_path_unchanged():
    assert redact_topic_in_url("https://ntfy.sh/") == "https://ntfy.sh/"


def test_redact_url_replaces_final_segment():
    out = redact_topic_in_url("https://ntfy.sh/lynceus-deadbeef")
    assert out == "https://ntfy.sh/lync•••ef"
    assert "lynceus-deadbeef" not in out


def test_redact_url_short_topic_fully_masked():
    out = redact_topic_in_url("https://ntfy.sh/abcd")
    assert out == "https://ntfy.sh/•••"
    assert "abcd" not in out


def test_redact_url_preserves_query_string():
    out = redact_topic_in_url("https://ntfy.sh/lynceus-deadbeef?priority=high")
    assert out == "https://ntfy.sh/lync•••ef?priority=high"
    assert "lynceus-deadbeef" not in out


def test_redact_url_preserves_fragment():
    out = redact_topic_in_url("https://ntfy.sh/lynceus-deadbeef#tab")
    assert out == "https://ntfy.sh/lync•••ef#tab"


def test_redact_url_preserves_query_and_fragment():
    out = redact_topic_in_url("https://ntfy.sh/lynceus-deadbeef?p=1#x")
    assert out == "https://ntfy.sh/lync•••ef?p=1#x"


def test_redact_url_preserves_trailing_slash():
    out = redact_topic_in_url("https://ntfy.sh/lynceus-deadbeef/")
    assert out == "https://ntfy.sh/lync•••ef/"


def test_redact_url_self_hosted_with_port():
    out = redact_topic_in_url("http://ntfy.example.invalid:8080/my-secret-topic")
    assert out == "http://ntfy.example.invalid:8080/my-s•••ic"
    assert "my-secret-topic" not in out


def test_redact_url_empty_string_returns_empty():
    assert redact_topic_in_url("") == ""


def test_redact_url_none_returns_empty():
    assert redact_topic_in_url(None) == ""


def test_redact_url_malformed_no_scheme_does_not_raise():
    # Contract is "never raise on weird input." urlsplit puts a no-scheme
    # input into the path, so the helper applies the topic redaction to
    # whatever final segment it finds. The exact rendering is implementation
    # detail; the important property is that no exception escapes.
    out = redact_topic_in_url("garbage")
    assert "•••" in out


def test_redact_url_just_a_slash_returns_unchanged():
    assert redact_topic_in_url("/") == "/"


@pytest.mark.parametrize(
    "url",
    [
        "https://ntfy.sh/lynceus-supersecret",
        "https://self-hosted.example/lynceus-supersecret",
        "https://ntfy.sh/lynceus-supersecret?priority=high",
        "https://ntfy.sh/lynceus-supersecret/",
    ],
)
def test_redact_url_never_contains_raw_topic(url):
    out = redact_topic_in_url(url)
    assert "lynceus-supersecret" not in out
    assert "supersecret" not in out
