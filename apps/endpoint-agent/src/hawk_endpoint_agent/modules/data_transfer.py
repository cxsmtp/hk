"""Data-transfer DLP — copy/paste and upload control via runtime-control.

Copy/paste of sensitive data into a public AI (or any untrusted destination) is
evaluated at ``/runtime-control/data-transfer-check``. Only a redacted preview and
a hash of the copied text leave the endpoint — never the raw sensitive content.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..config import AgentConfig
from ..decision import Decision
from ..enforcement import EnforcementOrchestrator
from ..hawk_client import HawkClient


def _redact_preview(text: str, limit: int = 80) -> str:
    snippet = (text or "")[:limit]
    # Coarse redaction so no raw secret leaves the device in the preview.
    import re

    snippet = re.sub(r"\b\d[\d ,-]{7,}\b", "[number]", snippet)
    snippet = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[email]", snippet)
    return snippet


class DataTransferModule:
    def __init__(self, config: AgentConfig, client: HawkClient, orchestrator: EnforcementOrchestrator) -> None:
        self._config = config
        self._client = client
        self._orch = orchestrator

    def evaluate(
        self,
        *,
        copied_text: str,
        source_domain: str | None = None,
        destination_domain: str | None = None,
        destination_app: str | None = None,
    ) -> Decision:
        copied_hash = hashlib.sha256((copied_text or "").encode("utf-8")).hexdigest()
        payload: dict[str, Any] = {
            "copy_context": {
                "copied_text_hash": copied_hash,
                "copied_text_preview_redacted": _redact_preview(copied_text),
                "source_domain": source_domain,
                "source_surface_type": "endpoint",
            },
            "paste_context": {
                "destination_domain": destination_domain,
                "destination_app_name": destination_app,
                "destination_surface_type": "public_ai" if destination_domain else "endpoint",
            },
            "platform_mode": "enforce",
            "endpoint_id": self._config.endpoint_id,
            "hostname": self._config.hostname,
        }
        return self._orch.evaluate(endpoint=self._client.check_data_transfer, payload=payload, surface="data_transfer")
