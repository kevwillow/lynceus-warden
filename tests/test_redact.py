"""Tests for the shared ntfy redaction helpers."""

from __future__ import annotations

import pytest

from lynceus.redact import (
    REDACTED_PLACEHOLDER,
    redact_ntfy_topic,
    redact_topic_in_url,
    redact_yaml_config,
)

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


# ---------- redact_yaml_config ---------------------------------------------


def test_redact_yaml_only_lynceus_yaml_is_inspected():
    # Other config files have no secret-bearing fields; pass through.
    body = "rules:\n  - name: x\n    secret_token: nope\n"
    redacted, fields = redact_yaml_config("rules.yaml", body)
    assert redacted == body
    assert fields == []


def test_redact_yaml_passes_path_basename():
    # Caller may pass a full path; only the basename governs the decision.
    body = "kismet_api_key: leaked\n"
    redacted, fields = redact_yaml_config("/etc/lynceus/lynceus.yaml", body)
    assert "leaked" not in redacted
    assert REDACTED_PLACEHOLDER in redacted
    assert fields == ["kismet_api_key"]


def test_redact_yaml_masks_kismet_api_key():
    body = (
        "kismet_url: http://127.0.0.1:2501\n"
        "kismet_api_key: deadbeefcafe1234\n"
        "location_id: home\n"
    )
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert "deadbeefcafe1234" not in redacted
    assert f"kismet_api_key: {REDACTED_PLACEHOLDER}\n" in redacted
    assert "kismet_url: http://127.0.0.1:2501\n" in redacted
    assert "location_id: home\n" in redacted
    assert fields == ["kismet_api_key"]


def test_redact_yaml_masks_ntfy_auth_token_and_topic():
    body = (
        "ntfy_url: https://ntfy.sh\n"
        "ntfy_topic: lynceus-supersecret\n"
        "ntfy_auth_token: tk_abcdef\n"
    )
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert "lynceus-supersecret" not in redacted
    assert "tk_abcdef" not in redacted
    # ntfy_url has no userinfo and no path-embedded topic -> unchanged.
    assert "ntfy_url: https://ntfy.sh\n" in redacted
    assert fields == ["ntfy_topic", "ntfy_auth_token"]


def test_redact_yaml_preserves_quoted_value():
    # Quoted scalars are still recognized; the value (with quotes) is
    # replaced wholesale by the placeholder.
    body = 'kismet_api_key: "deadbeefcafe1234"\n'
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert "deadbeefcafe1234" not in redacted
    assert fields == ["kismet_api_key"]


def test_redact_yaml_empty_value_passes_through():
    # An empty / null secret value is not a secret — leave it alone so
    # the receiver can tell "operator didn't set this" apart from
    # "operator set this and we scrubbed it".
    body = (
        "kismet_api_key:\n"
        "ntfy_auth_token: null\n"
        "ntfy_topic: ~\n"
    )
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert redacted == body
    assert fields == []


def test_redact_yaml_preserves_comments_and_blank_lines():
    # The line-based redactor must not eat operator comments or whitespace.
    body = (
        "# Top comment\n"
        "\n"
        "kismet_url: http://127.0.0.1:2501  # broker\n"
        "kismet_api_key: secrettoken\n"
        "\n"
        "# trailing notes\n"
    )
    redacted, _ = redact_yaml_config("lynceus.yaml", body)
    assert "# Top comment\n" in redacted
    assert "# trailing notes\n" in redacted
    assert "kismet_url: http://127.0.0.1:2501  # broker\n" in redacted
    assert "secrettoken" not in redacted


def test_redact_yaml_indented_lookalike_not_redacted():
    # Schema forbids nested kismet_api_key, but a nested key in a comment
    # block or a manual mistake must not be silently mistaken for a top-
    # level secret. Top-level only — indented lines pass through.
    body = (
        "kismet_url: http://127.0.0.1:2501\n"
        "  kismet_api_key: not-a-real-field\n"
    )
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert redacted == body
    assert fields == []


def test_redact_yaml_strips_ntfy_url_userinfo():
    body = "ntfy_url: https://user:pass@ntfy.example/\n"
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert "user:pass" not in redacted
    assert "https://ntfy.example/" in redacted
    assert fields == ["ntfy_url:userinfo"]


def test_redact_yaml_ntfy_url_without_userinfo_unchanged():
    body = "ntfy_url: https://ntfy.sh\n"
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert redacted == body
    assert fields == []


def test_redact_yaml_preserves_crlf_line_endings():
    body = "kismet_api_key: secrettoken\r\nlocation_id: home\r\n"
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert "secrettoken" not in redacted
    # Both lines keep their CRLF endings.
    assert redacted.endswith("\r\n")
    assert "\r\n" in redacted.split(REDACTED_PLACEHOLDER, 1)[1]
    assert fields == ["kismet_api_key"]


def test_redact_yaml_idempotent():
    # Running the redactor twice yields the same result and reports the
    # field already-redacted as still redacted (the placeholder is not in
    # the empty-token set, so it's masked again to itself).
    body = "kismet_api_key: secrettoken\n"
    once, fields1 = redact_yaml_config("lynceus.yaml", body)
    twice, fields2 = redact_yaml_config("lynceus.yaml", once)
    assert twice == once
    assert fields1 == ["kismet_api_key"]
    # Second pass replaces "<REDACTED>" with "<REDACTED>" — semantically
    # a no-op but the field is still reported, which is fine and harmless.
    assert fields2 == ["kismet_api_key"]


def test_redact_yaml_multiple_fields_reported_in_file_order():
    body = (
        "kismet_api_key: a\n"
        "location_id: home\n"
        "ntfy_topic: b\n"
        "ntfy_auth_token: c\n"
    )
    _, fields = redact_yaml_config("lynceus.yaml", body)
    assert fields == ["kismet_api_key", "ntfy_topic", "ntfy_auth_token"]
