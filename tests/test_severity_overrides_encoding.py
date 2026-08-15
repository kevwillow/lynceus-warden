"""A malformed override file must not stop the daemon starting.

`load_runtime_severity_overrides`' docstring makes an unusually explicit
promise:

    "Failure modes are all benign — the runtime override layer is additive; the
     poller must never crash because the operator edited their override file
     into a malformed state. Every outcome — success and every failure mode —
     emits a log line..."

It caught `OSError` and `yaml.YAMLError`. But `open(..., encoding="utf-8")`
raises `UnicodeDecodeError` BEFORE yaml sees the bytes, so an encoding problem
was neither, and escaped.

⚠️ `poller.py` calls this UNWRAPPED while constructing the Poller, so the
exception took the daemon down at startup: one bad byte in an optional,
additive file and RF monitoring never begins. `cli/validate.py` wraps its own
call, so `lynceus-validate` survived what the daemon did not — the tool that
only reports was more robust than the one doing the watching.

The realistic triggers are not exotic: an editor that saves UTF-16, a file
copied off a Windows box, or a partial write that leaves a truncated multi-byte
sequence.
"""

from __future__ import annotations

import logging

from lynceus.rules import load_runtime_severity_overrides


def _write(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# --- presence assertions ---------------------------------------------------
# Without these, "malformed input returns None" is equally satisfied by a
# function that returns None for everything, including a valid file.


def test_a_valid_file_still_loads(tmp_path):
    path = _write(tmp_path, "ok.yaml", b"suppress_categories: [alpr]\n")

    assert load_runtime_severity_overrides(path) is not None


def test_malformed_yaml_is_still_handled(tmp_path):
    path = _write(tmp_path, "bad.yaml", b"suppress_categories: [unclosed\n")

    assert load_runtime_severity_overrides(path) is None


# --- the guard -------------------------------------------------------------


def test_an_invalid_utf8_byte_does_not_raise(tmp_path):
    """Measured before the fix: UnicodeDecodeError escaped, and the daemon's
    unwrapped call site meant it never finished starting."""
    path = _write(tmp_path, "badbyte.yaml", b"suppress_categories: [\xff\xfe]\n")

    assert load_runtime_severity_overrides(path) is None


def test_a_utf16_file_does_not_raise(tmp_path):
    """The likeliest real trigger: an editor that saves UTF-16, or a file
    copied off a Windows box."""
    path = _write(
        tmp_path, "utf16.yaml", "suppress_categories: [alpr]\n".encode("utf-16")
    )

    assert load_runtime_severity_overrides(path) is None


def test_the_encoding_failure_is_logged(tmp_path, caplog):
    """The docstring promises EVERY failure mode emits a log line, so an
    operator reading journalctl can see the layer is disabled. Silently
    returning None would satisfy the tests above and break that promise."""
    path = _write(tmp_path, "badbyte2.yaml", b"suppress_categories: [\xff]\n")

    with caplog.at_level(logging.WARNING):
        load_runtime_severity_overrides(path)

    assert any(
        "severity overrides" in r.getMessage() for r in caplog.records
    ), "an encoding failure disabled the layer without saying so in the log"
