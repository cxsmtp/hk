"""Shadow-AI discovery on the endpoint.

Reports AI apps/tools observed on the device (by domain or process) to Hawk's
discovery pipeline. Discovery is observe-and-report (``detect_only`` / telemetry);
governance and any enforcement of an unsanctioned tool are decided centrally.
"""

from __future__ import annotations

from typing import Any

from ..catalog import match_ai_app
from ..collectors.base import Connection, ProcessInfo
from ..config import AgentConfig
from ..hawk_client import HawkClient, HawkApiError, HawkUnavailable
from ..signals import Signal, SignalKind


class ShadowAIModule:
    def __init__(self, config: AgentConfig, client: HawkClient) -> None:
        self._config = config
        self._client = client
        self._seen: set[str] = set()

    def discover(self, *, processes: list[ProcessInfo], connections: list[Connection]) -> list[Signal]:
        signals: list[Signal] = []
        for conn in connections:
            label = match_ai_app(conn.remote_host)
            if not label:
                continue
            key = f"domain:{conn.remote_host.lower()}"
            if key in self._seen:
                continue
            self._seen.add(key)
            signals.append(
                Signal(
                    kind=SignalKind.AI_APP_DISCOVERED,
                    subject=label,
                    attributes={"domain": conn.remote_host, "process": conn.process_name},
                )
            )
        return signals

    def report(self, signal: Signal) -> bool:
        payload: dict[str, Any] = {
            "event_type": "ai_tool_discovered",
            "domain": signal.attributes.get("domain") or "endpoint.local",
            "endpoint_id": self._config.endpoint_id,
            "hostname": self._config.hostname,
            "browser": "endpoint-agent",
            "extension_version": "endpoint-agent",
            "correlation_id": f"shadow-{int(signal.ts)}",
        }
        try:
            self._client.report_discovery(payload)
            return True
        except (HawkUnavailable, HawkApiError):
            return False
