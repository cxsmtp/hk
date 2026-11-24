from __future__ import annotations

import json
from typing import Any
from urllib import request

from .models import GuardDecision, PromptSnapshot


class UnavailableApiClient:
    def __init__(self, *, reason: str) -> None:
        self.reason = str(reason or "unknown")

    def evaluate_prompt(self, snapshot: PromptSnapshot) -> GuardDecision:
        raise RuntimeError(f"Hawk API unavailable: {self.reason}")


class HawkApiClient:
    def __init__(self, *, api_url: str, access_token: str, tenant_id: str | None = None, timeout_seconds: float = 5.0) -> None:
        self.api_url = api_url.rstrip("/")
        self.access_token = access_token
        self.tenant_id = tenant_id
        self.timeout_seconds = float(timeout_seconds)

    def evaluate_prompt(self, snapshot: PromptSnapshot) -> GuardDecision:
        payload = snapshot.to_api_payload()
        req = request.Request(
            f"{self.api_url}/telemetry/desktop/interaction-eval",
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
        return GuardDecision.from_api(body)

    @classmethod
    def login(
        cls,
        *,
        api_url: str,
        email: str,
        password: str,
        tenant_id: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> "HawkApiClient":
        normalized_url = api_url.rstrip("/")
        req = request.Request(
            f"{normalized_url}/auth/login",
            data=json.dumps({"email": email, "password": password}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=float(timeout_seconds)) as response:
            body = json.loads(response.read().decode("utf-8"))
        access_token = str(body.get("access_token") or "").strip()
        resolved_tenant_id = str(tenant_id or body.get("selected_tenant_id") or "").strip()
        if not resolved_tenant_id:
            tenants = body.get("tenants") if isinstance(body.get("tenants"), list) else []
            resolved_tenant_id = str((tenants[0] or {}).get("id") or "").strip() if tenants else ""
        if not access_token or not resolved_tenant_id:
            raise RuntimeError("Hawk login response missing access token or tenant id")
        return cls(
            api_url=normalized_url,
            access_token=access_token,
            tenant_id=resolved_tenant_id,
            timeout_seconds=timeout_seconds,
        )

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id
        return headers
