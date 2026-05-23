"""In-flight wizard session state.

One operator per wizard run, but request handlers run concurrently
inside the ASGI server, so the store is lock-guarded. Sessions are
keyed by the per-run setup token (the same token that gates auth) so
there is no separate session-id ceremony — the operator pasting the
token-bearing URL into their browser is the session.

State is in-memory only; nothing persists across server restarts. By
design: the wizard is run-once-on-demand, the operator either
completes it or starts over.

The ``answers`` dict mirrors the shape the CLI wizard builds up in
``cli/setup.py:run_wizard`` (kismet_url, kismet_api_key,
kismet_sources, probe_ssids, ble_friendly_names, ntfy_url,
ntfy_topic, min_rssi, etc.). Phase 2a's form handlers populate it
key-by-key; the Phase 2a review page reads it to construct the
final ``Config``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WizardSession:
    """One operator's in-flight answers for a wizard run."""

    token: str
    answers: dict[str, Any] = field(default_factory=dict)


class SessionStore:
    """Thread-safe ``{token: WizardSession}`` map."""

    def __init__(self) -> None:
        self._sessions: dict[str, WizardSession] = {}
        self._lock = threading.Lock()

    def get_or_create(self, token: str) -> WizardSession:
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                session = WizardSession(token=token)
                self._sessions[token] = session
            return session

    def get(self, token: str) -> WizardSession | None:
        with self._lock:
            return self._sessions.get(token)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
