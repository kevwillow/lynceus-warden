"""Notification dispatch: deliver rule-triggered alerts via configured channels."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Literal

import requests

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
    ) -> bool:
        ...


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
            logger.warning("ntfy POST to %s failed: %s", url, e)
            return False
        if 200 <= response.status_code <= 299:
            return True
        logger.warning(
            "ntfy POST to %s returned non-2xx status %s",
            url,
            response.status_code,
        )
        return False
