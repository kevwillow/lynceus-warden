"""Smoke tests for the Touch 4 prompt-helper re-import shim.

The 200-test setup_wizard suite already exercises every prompt
behavior. This file just verifies that the names re-exported by
``lynceus.cli.setup`` after the move to ``lynceus.setup.prompts`` are
the SAME objects as the ones tests expect to monkeypatch via
``wiz.<name>``.
"""

from __future__ import annotations

from lynceus.cli import setup as wiz
from lynceus.setup import prompts as setup_prompts


def test_prompt_helpers_share_identity_with_setup_prompts():
    """Every re-exported name on ``wiz`` IS the function defined in
    ``setup_prompts`` — identity, not just equality. If a future
    edit accidentally re-defines one locally in cli/setup.py, the
    object identity check catches the drift before tests do."""
    assert wiz.prompt_default is setup_prompts.prompt_default
    assert wiz.prompt_secret is setup_prompts.prompt_secret
    assert wiz.prompt_url is setup_prompts.prompt_url
    assert wiz.prompt_yes_no is setup_prompts.prompt_yes_no
    assert wiz.prompt_numbered_choice is setup_prompts.prompt_numbered_choice
    assert wiz._print_section is setup_prompts._print_section
    assert wiz._print_context is setup_prompts._print_context
    assert wiz._is_valid_url is setup_prompts._is_valid_url
    assert wiz._looks_like_ntfy_topic is setup_prompts._looks_like_ntfy_topic
    assert wiz._looks_like_path is setup_prompts._looks_like_path
    assert wiz._URLPromptAborted is setup_prompts._URLPromptAborted


def test_prompt_constants_share_identity_with_setup_prompts():
    assert wiz.URL_PROMPT_MAX_ATTEMPTS == setup_prompts.URL_PROMPT_MAX_ATTEMPTS
    assert wiz.NTFY_TOPIC_MAX_ATTEMPTS == setup_prompts.NTFY_TOPIC_MAX_ATTEMPTS
    assert wiz._NTFY_TOPIC_RE is setup_prompts._NTFY_TOPIC_RE
    assert wiz._NTFY_TOPIC_DENY_LIST is setup_prompts._NTFY_TOPIC_DENY_LIST


def test_url_validator_still_works_via_wiz_namespace():
    """One representative behavior smoke check that the re-import
    didn't accidentally break the function shape."""
    assert wiz._is_valid_url("http://127.0.0.1:2501") is True
    assert wiz._is_valid_url("https://ntfy.sh") is True
    assert wiz._is_valid_url("ntfy.sh") is False  # no scheme
    assert wiz._is_valid_url("") is False


def test_ntfy_topic_validator_still_works_via_wiz_namespace():
    assert wiz._looks_like_ntfy_topic("lynceus-abc123") is True
    assert wiz._looks_like_ntfy_topic("skip") is False  # in deny-list
    assert wiz._looks_like_ntfy_topic("ab") is False  # too short
    assert wiz._looks_like_ntfy_topic("") is False
