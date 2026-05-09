"""Shared pytest fixtures for the Lynceus test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _kismet_no_runtime_retry(monkeypatch):
    """Make urllib3's ``Retry`` mechanism a no-op at runtime during tests.

    The H5 fix mounts a urllib3 ``Retry`` on ``KismetClient``'s session so a
    transient Kismet 5xx or connection error transparently retries 3 times
    with ``backoff_factor=0.5``. In production the recovery is the point.
    In tests, the webui suite alone constructs ~120 apps that each fire one
    Kismet status probe at a closed loopback port; on Windows each refused-
    connection attempt costs ~2s, so 4 attempts × 120 tests adds minutes of
    wall-clock for an outcome the tests already know.

    Patching ``Retry.increment`` to raise ``MaxRetryError`` immediately
    short-circuits the retry loop after the first failure — without
    altering the *configured* attributes (``total``, ``backoff_factor``,
    ``status_forcelist``, ``allowed_methods``). The structural
    ``test_h5_session_retry_mounted_for_*`` tests inspect those attributes
    on the mounted adapter and still pass.
    """
    from urllib3.exceptions import MaxRetryError
    from urllib3.util.retry import Retry

    def raise_immediately(
        self,
        method=None,
        url=None,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
    ):
        raise MaxRetryError(_pool, url, error or "test-mode no-retry")

    monkeypatch.setattr(Retry, "increment", raise_immediately)
