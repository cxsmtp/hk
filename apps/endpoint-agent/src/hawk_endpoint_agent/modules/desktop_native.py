"""Native desktop AI-app coverage.

Discovers AI-capable native applications on the endpoint and reports them to Hawk's
discovery pipeline, so AI usage in native apps (assistant apps, AI IDEs/terminals,
local model runners) is covered without a browser extension. Interaction content
from these apps, when observed via the local proxy or a hook, is evaluated through
the interaction-security module (LLM gateway) — the decision stays server-authoritative.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..chatgpt_desktop import (
    ChatGPTInstallationObservation,
    CommandRunner,
    inspect_chatgpt_installation,
)
from ..collectors.base import ProcessInfo
from ..collectors.desktop_apps import DesktopAIApp, detect_desktop_ai_apps
from ..config import AgentConfig
from ..hawk_client import HawkApiError, HawkClient, HawkUnavailable
from ..signals import Signal, SignalKind


class DesktopNativeModule:
    def __init__(
        self,
        config: AgentConfig,
        client: HawkClient,
        *,
        chatgpt_installation_path: str | Path = "/Applications/ChatGPT.app",
        command_runner: CommandRunner | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._seen: set[str] = set()
        self._chatgpt_installation_path = Path(chatgpt_installation_path)
        self._command_runner = command_runner
        self._chatgpt_installation: ChatGPTInstallationObservation | None = None
        self._chatgpt_bundle_stamp: tuple[tuple[str, int, int] | None, ...] | None = None

    def _bundle_stamp(self) -> tuple[tuple[str, int, int] | None, ...]:
        paths = (
            self._chatgpt_installation_path,
            self._chatgpt_installation_path / "Contents" / "Info.plist",
            self._chatgpt_installation_path / "Contents" / "MacOS",
            self._chatgpt_installation_path / "Contents" / "_CodeSignature" / "CodeResources",
        )
        values: list[tuple[str, int, int] | None] = []
        for path in paths:
            try:
                stat = path.stat()
            except OSError:
                values.append(None)
            else:
                values.append((str(path), int(stat.st_mtime_ns), int(stat.st_size)))
        return tuple(values)

    def _installation(self) -> ChatGPTInstallationObservation:
        stamp = self._bundle_stamp()
        if self._chatgpt_installation is not None and stamp == self._chatgpt_bundle_stamp:
            return self._chatgpt_installation
        installation = inspect_chatgpt_installation(
            self._chatgpt_installation_path,
            command_runner=self._command_runner,
        )
        self._chatgpt_installation = installation
        self._chatgpt_bundle_stamp = stamp
        return installation

    def discover(self, *, processes: list[ProcessInfo]) -> list[Signal]:
        signals: list[Signal] = []
        installation = self._installation()
        for app in detect_desktop_ai_apps(processes, chatgpt_installation=installation):
            key = f"{app.label}:{app.pid}"
            if key in self._seen:
                continue
            self._seen.add(key)
            signals.append(self._to_signal(app))
        return signals

    def _to_signal(self, app: DesktopAIApp) -> Signal:
        return Signal(
            kind=SignalKind.AI_APP_DISCOVERED,
            subject=app.label,
            attributes={
                "surface": "desktop_native",
                "process_name": app.process_name,
                "pid": app.pid,
                "local_model_runner": app.local_model_runner,
                "chatgpt_desktop": app.composite_context,
            },
        )

    def report(self, signal: Signal) -> bool:
        payload: dict[str, Any] = {
            "event_type": "ai_tool_discovered",
            "domain": f"desktop-native/{signal.subject}".replace(" ", "-").lower(),
            "endpoint_id": self._config.endpoint_id,
            "hostname": self._config.hostname,
            "browser": "endpoint-agent",
            "extension_version": "endpoint-agent",
            "source_surface": "desktop_native",
            "correlation_id": f"desktop-{int(signal.ts)}",
            "application": signal.subject,
        }
        composite = signal.attributes.get("chatgpt_desktop")
        if isinstance(composite, dict):
            payload["chatgpt_desktop"] = composite
        try:
            self._client.report_discovery(payload)
            if isinstance(composite, dict):
                self._client.report_evidence(
                    {
                        "event_type": "chatgpt_desktop_observation",
                        "correlation_id": payload["correlation_id"],
                        "chatgpt_desktop": composite,
                    }
                )
            return True
        except (HawkUnavailable, HawkApiError):
            return False
