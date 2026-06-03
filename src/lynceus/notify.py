"""Notification dispatch: deliver rule-triggered alerts via configured channels."""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Literal

import requests

from .redact import redact_topic_in_url

if TYPE_CHECKING:
    from .config import Config

logger = logging.getLogger(__name__)

SEVERITY_TO_PRIORITY: dict[str, int] = {"low": 2, "med": 3, "high": 5}
SEVERITY_TO_TAGS: dict[str, str] = {
    "low": "information_source",
    "med": "warning",
    "high": "rotating_light",
}
DEFAULT_TIMEOUT = 10.0


class Notifier(ABC):
    @abstractmethod
    def send(
        self,
        severity: Literal["low", "med", "high"],
        title: str,
        message: str,
        priority_override: int | None = None,
    ) -> bool: ...


class NullNotifier(Notifier):
    def send(
        self,
        severity: Literal["low", "med", "high"],
        title: str,
        message: str,
        priority_override: int | None = None,
    ) -> bool:
        logger.debug("NullNotifier dropped %s: %s", severity, title)
        return True


class RecordingNotifier(Notifier):
    """Test double that records every call.

    ``.calls`` preserves the historical 3-tuple shape
    ``(severity, title, message)`` -- existing tests unpack it
    positionally. ``.priority_overrides`` is a parallel list of
    the per-call ``priority_override`` arg (None when the caller
    used the severity-mapped default). Indexed alignment:
    ``priority_overrides[i]`` belongs to ``calls[i]``.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.priority_overrides: list[int | None] = []

    def send(
        self,
        severity: Literal["low", "med", "high"],
        title: str,
        message: str,
        priority_override: int | None = None,
    ) -> bool:
        self.calls.append((severity, title, message))
        self.priority_overrides.append(priority_override)
        return True


class NtfyNotifier(Notifier):
    def __init__(
        self,
        base_url: str,
        topic: str,
        auth_token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not topic.strip():
            raise ValueError("ntfy topic must be a non-empty string")
        self.base_url = base_url.rstrip("/")
        self.topic = topic
        self.auth_token = auth_token
        self.timeout = timeout

    def send(
        self,
        severity: Literal["low", "med", "high"],
        title: str,
        message: str,
        priority_override: int | None = None,
    ) -> bool:
        ok, _detail = self.send_with_detail(
            severity, title, message, priority_override=priority_override
        )
        return ok

    def send_with_detail(
        self,
        severity: Literal["low", "med", "high"],
        title: str,
        message: str,
        priority_override: int | None = None,
    ) -> tuple[bool, str | None]:
        """Publish via the real ntfy POST path, returning ``(ok, detail)``.

        ``detail`` is ``None`` on success, else a SAFE, topic-redacted
        one-line reason: ``"HTTP <code>"`` for a non-2xx response, or
        ``"<ExcType> (<redacted-url>)"`` for a transport error. The raw
        topic never appears in ``detail`` (it is a shared secret).

        ``send`` delegates here, so the daemon path is unchanged. The
        setup wizard's test-publish (``cli.setup.probe_ntfy``) calls this
        directly so its probe exercises the exact headers/format the
        daemon sends — a 200 at setup validates the production request
        shape — while still surfacing an operator-actionable failure
        reason that ``send``'s bare ``bool`` return discards.
        """
        url = f"{self.base_url}/{self.topic}"
        # ntfy topics are shared secrets; never let them reach log surfaces.
        # The exception's __str__() typically embeds the full URL+topic too,
        # so we log only the exception type name and reserve the full
        # traceback for explicit DEBUG operation (mirrors H-7).
        safe_url = redact_topic_in_url(url)
        # priority_override decouples ntfy notification prominence
        # from the severity literal: the watchful escalation emit
        # site passes severity="high" + priority_override=4 by
        # design (severity stays high so /alerts and /rules render
        # consistently with the operator's "this matters" intent,
        # but priority drops below the urgent-5 reserved for
        # watchlist hits the operator opted into). When None, the
        # severity-mapped default holds and existing call sites
        # see no behavior change. Tag follows severity in both
        # cases -- visual tone matches severity, prominence
        # follows priority.
        priority = (
            priority_override
            if priority_override is not None
            else SEVERITY_TO_PRIORITY[severity]
        )
        headers = {
            "Title": title,
            "Priority": str(priority),
            "Tags": SEVERITY_TO_TAGS[severity],
            # Unique id per alert so each detection lands as its own ntfy
            # message. With no id set, alerts were observed collapsing to a
            # single entry in the operator's ntfy view; a fresh id per send
            # keeps them distinct. This is defensive, not a claim about ntfy
            # internals: per ntfy's docs a shared sequence id only REPLACES
            # scheduled/delayed messages before delivery — delivered messages
            # are kept regardless — and which layer (server vs client app) was
            # collapsing ours is not documented.
            "X-Sequence-ID": uuid.uuid4().hex,
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        try:
            response = requests.post(
                url,
                data=message.encode("utf-8"),
                headers=headers,
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            logger.warning("ntfy POST to %s failed: %s", safe_url, type(e).__name__)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("ntfy POST exception detail", exc_info=True)
            return False, f"{type(e).__name__} ({safe_url})"
        if 200 <= response.status_code <= 299:
            return True, None
        logger.warning(
            "ntfy POST to %s returned non-2xx status %s",
            safe_url,
            response.status_code,
        )
        return False, f"HTTP {response.status_code}"


def build_metadata_suffix(metadata: dict | None, oui_vendor: str | None = None) -> str:
    """Return the ntfy body suffix for a watchlist_metadata row.

    Format: " | vendor: <vendor>" + " | confidence: <n>" when each is non-NULL,
    in that order. Empty string when metadata is None or both fields are NULL,
    so the v0.2 body is preserved by string concatenation.

    A watchlist match attributes the device to ``vendor`` (the Argus/watchlist
    label), while Kismet's OUI lookup may say something else. When the two
    disagree, the OUI vendor is appended in parentheses so the divergence is
    legible at a glance: " | vendor: Flock Safety (OUI: Liteon Technology)".
    Agreement (compared case-insensitively, trimmed) or a missing ``oui_vendor``
    shows the matched vendor alone -- there is nothing to reconcile. An
    ``oui_vendor`` with no matched ``vendor`` is never surfaced: the
    notification fires on a watchlist match, so the matched label is the anchor."""
    if not metadata:
        return ""
    parts: list[str] = []
    vendor = metadata.get("vendor")
    if vendor:
        if oui_vendor and oui_vendor.strip().casefold() != vendor.strip().casefold():
            parts.append(f" | vendor: {vendor} (OUI: {oui_vendor})")
        else:
            parts.append(f" | vendor: {vendor}")
    confidence = metadata.get("confidence")
    if confidence is not None:
        parts.append(f" | confidence: {confidence}")
    return "".join(parts)


def build_notifier(config: Config) -> Notifier:
    if config.ntfy_url and config.ntfy_topic:
        return NtfyNotifier(
            base_url=config.ntfy_url,
            topic=config.ntfy_topic,
            auth_token=config.ntfy_auth_token,
        )
    return NullNotifier()
