"""Notification dispatch: deliver rule-triggered alerts via configured channels."""

from __future__ import annotations

import logging
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
    ) -> bool: ...


class NullNotifier(Notifier):
    def send(
        self,
        severity: Literal["low", "med", "high"],
        title: str,
        message: str,
    ) -> bool:
        logger.debug("NullNotifier dropped %s: %s", severity, title)
        return True


class RecordingNotifier(Notifier):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def send(
        self,
        severity: Literal["low", "med", "high"],
        title: str,
        message: str,
    ) -> bool:
        self.calls.append((severity, title, message))
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
    ) -> bool:
        url = f"{self.base_url}/{self.topic}"
        # ntfy topics are shared secrets; never let them reach log surfaces.
        # The exception's __str__() typically embeds the full URL+topic too,
        # so we log only the exception type name and reserve the full
        # traceback for explicit DEBUG operation (mirrors H-7).
        safe_url = redact_topic_in_url(url)
        headers = {
            "Title": title,
            "Priority": str(SEVERITY_TO_PRIORITY[severity]),
            "Tags": SEVERITY_TO_TAGS[severity],
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
            return False
        if 200 <= response.status_code <= 299:
            return True
        logger.warning(
            "ntfy POST to %s returned non-2xx status %s",
            safe_url,
            response.status_code,
        )
        return False


def build_metadata_suffix(metadata: dict | None) -> str:
    """Return the ntfy body suffix for a watchlist_metadata row.

    Format: " | vendor: <vendor>" + " | confidence: <n>" when each is non-NULL,
    in that order. Empty string when metadata is None or both fields are NULL,
    so the v0.2 body is preserved by string concatenation."""
    if not metadata:
        return ""
    parts: list[str] = []
    vendor = metadata.get("vendor")
    if vendor:
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
