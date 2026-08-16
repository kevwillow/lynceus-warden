"""Tests for the shared ntfy redaction helpers."""

from __future__ import annotations

import pytest

from lynceus.redact import (
    REDACTED_PLACEHOLDER,
    RedactionFailure,
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
    # level secret. The line must pass through unchanged.
    #
    # ⚠️ This fixture is NOT valid YAML ("mapping values are not allowed
    # here") — measured, not assumed. It used to assert `fields == []`, which
    # the manifest renders as "considered and clean". That is a claim about a
    # file nothing can parse, and it is the same claim this module was found to
    # be making elsewhere: reporting a verification it had not performed. The
    # file still exports (backing up a BROKEN config is a documented
    # capability); it now says so instead of vouching for it.
    body = (
        "kismet_url: http://127.0.0.1:2501\n"
        "  kismet_api_key: not-a-real-field\n"
    )
    redacted, fields = redact_yaml_config("lynceus.yaml", body)
    assert redacted == body
    assert "kismet_api_key" not in fields
    assert fields == ["<unverified: file does not parse>"]


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


# ---------------------------------------------------------------------------
# The export bundle's documented third purpose is "sharing a sanitized snapshot
# with the maintainer for support". A cold read of that surface found TEN of
# ELEVEN YAML spellings of the same credential surviving redaction — and four
# of them were REPORTED in `redacted_fields` as though they had been removed.
#
# ⭐ The docstring disclosed the block-scalar limitation honestly. What it did
# not disclose is that the limitation was announced as a SUCCESS: a manifest
# saying `redaction_applied: true` over a live Kismet token is worse than one
# saying nothing, because the operator hands the archive over on the strength
# of it. The fix is not a better regex — it is refusing to claim what has not
# been verified.
# ---------------------------------------------------------------------------

_SECRET = "SUPERSECRET123"


@pytest.mark.parametrize(
    "label,content",
    [
        ("plain", f"kismet_api_key: {_SECRET}\n"),
        ("indented under a parent", f"capture:\n  kismet_api_key: {_SECRET}\n"),
        ("quoted key", f'"kismet_api_key": {_SECRET}\n'),
        ("flow mapping", f"{{kismet_api_key: {_SECRET}}}\n"),
        ("block scalar", f"kismet_api_key: |\n  {_SECRET}\n"),
        ("folded scalar", f"kismet_api_key: >\n  {_SECRET}\n"),
        ("value on the next line", f"kismet_api_key:\n  {_SECRET}\n"),
        ("anchor parks it under an innocent key",
         f"cred: &c {_SECRET}\nkismet_api_key: *c\n"),
        ("second document", f"---\na: 1\n---\nkismet_api_key: {_SECRET}\n"),
        ("kismet_url userinfo", f"kismet_url: https://a:{_SECRET}@k.local/\n"),
        ("ntfy_url token in the query", f"ntfy_url: https://ntfy.sh/t?token={_SECRET}\n"),
        ("password containing @", f"ntfy_url: https://a:p{_SECRET}@ss@n.example/t\n"),
        # ⚠️ The DISCRIMINATING case, added because a plant survived without it.
        # The one above puts the secret BEFORE the first '@', so splitting at
        # the first or the last '@' both remove it and the test could not tell
        # a correct implementation from the bug it was written for. Here the
        # secret sits AFTER the first '@': split-at-first leaves it as the new
        # netloc, rsplit-at-last drops it.
        ("secret after the first @ in userinfo",
         f"ntfy_url: https://user:p@{_SECRET}@n.example/t\n"),
    ],
)
def test_no_yaml_spelling_of_a_credential_survives_the_export(label, content):
    """The assertion is on the OUTPUT BYTES, not on the reported field list.

    Reporting is exactly what was wrong: four of these forms named the field in
    `redacted_fields` while the token sat in the file. A test that asserted the
    field list would have passed on every one of them.
    """
    try:
        out, _fields = redact_yaml_config("lynceus.yaml", content)
    except RedactionFailure:
        return  # refusing to emit the file is a correct outcome
    assert _SECRET not in out, f"{label}: credential survived redaction"


@pytest.mark.parametrize(
    "label,content",
    [
        ("no secrets at all", "db_path: /var/lib/lynceus/lynceus.db\n"),
        ("a URL with nothing to strip", "ntfy_url: https://ntfy.sh/mytopic\n"),
        ("an explicitly cleared field", "kismet_api_key: null\n"),
    ],
)
def test_a_clean_file_is_not_reported_as_redacted(label, content):
    """The controls, and they are half the guard. Without them a redactor that
    masked everything unconditionally — or claimed every field — would pass the
    parametrised test above. `null` matters on its own: disguising an UNSET
    credential as a redacted one tells the receiver a secret existed."""
    out, fields = redact_yaml_config("lynceus.yaml", content)
    assert fields == [], f"{label}: claimed a redaction that did not happen"
    assert out == content, f"{label}: rewrote a file with nothing to redact"


def test_the_anchor_case_names_the_innocent_key_that_held_the_secret(tmp_path):
    """Scrubbing by VALUE as well as by key name, so the operator is told where
    the credential actually was."""
    out, fields = redact_yaml_config(
        "lynceus.yaml", f"cred: &c {_SECRET}\nkismet_api_key: *c\n"
    )
    assert _SECRET not in out
    assert "cred" in fields and "kismet_api_key" in fields


def test_a_file_that_cannot_be_proven_clean_is_refused_not_shipped():
    """`RedactionFailure` is an exception rather than a warning on purpose:
    every other outcome in that module ends with a file inside a shareable
    archive, so a failure that merely logged would be a failure that shipped."""
    import lynceus.redact as R

    original = R._redact_semantically
    try:
        R._redact_semantically = lambda *_a, **_k: None  # force the fallback to fail
        with pytest.raises(RedactionFailure):
            redact_yaml_config("lynceus.yaml", f"kismet_api_key: |\n  {_SECRET}\n")
    finally:
        R._redact_semantically = original


def test_a_new_secret_bearing_config_field_cannot_be_forgotten():
    """⛔ `_SECRET_FIELDS` was maintained by a comment saying "Keep in sync with
    config.Config". A comment asking a future author to remember is not a
    mechanism — this project has already been bitten by that exact shape twice
    (the `/settings` pattern-type list, the reconciliation counter list).

    Any Config field whose NAME reads like a credential must be either redacted
    or explicitly recorded here as reviewed-and-not-a-secret.
    """
    from lynceus.config import Config
    from lynceus.redact import _SECRET_FIELDS, _URL_FIELDS

    suspicious = [
        name
        for name in Config.model_fields
        if any(t in name.lower() for t in ("key", "token", "secret", "password", "topic", "auth"))
    ]
    reviewed_not_secret: set[str] = set()
    unhandled = [
        n
        for n in suspicious
        if n not in _SECRET_FIELDS and n not in _URL_FIELDS and n not in reviewed_not_secret
    ]
    assert unhandled == [], (
        "these Config fields look credential-bearing but are neither redacted "
        f"nor recorded as reviewed: {unhandled}"
    )
