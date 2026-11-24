from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

import httpx


def _json_canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _compute_payload_hash(payload: dict[str, Any]) -> str:
    return _sha256_hex(_json_canonical(payload))


def _compute_entry_hash(
    *,
    entry_id: str,
    timestamp: str,
    signal_type: str,
    payload_hash: str,
    prev_hash: str,
) -> str:
    material = "|".join(
        [
            entry_id,
            timestamp,
            signal_type,
            payload_hash,
            prev_hash,
        ]
    )
    return _sha256_hex(material)


class OnPremRetryableError(RuntimeError):
    pass


class OnPremGatewayClient:
    def __init__(
        self,
        *,
        cloud_base_url: str,
        bearer_token: str,
        tenant_id: str,
        gateway_id: str,
        signing_secret: str,
        cache_path: str | Path,
        timeout_seconds: float = 30.0,
        retry_max_attempts: int = 3,
        retry_backoff_seconds: float = 0.5,
        request_fn: Callable[[str, str, dict[str, str], dict[str, Any] | None], dict[str, Any]] | None = None,
    ) -> None:
        self.cloud_base_url = cloud_base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.tenant_id = tenant_id
        self.gateway_id = gateway_id
        self.signing_secret = signing_secret
        self.cache_path = Path(cache_path)
        self.timeout_seconds = timeout_seconds
        self.retry_max_attempts = max(1, int(retry_max_attempts))
        self.retry_backoff_seconds = max(0.0, float(retry_backoff_seconds))
        self._request_fn = request_fn

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.bearer_token}",
            "X-Tenant-ID": self.tenant_id,
            "Content-Type": "application/json",
        }

    def _request(
        self,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        headers = self._headers()
        last_error: Exception | None = None
        for attempt in range(1, self.retry_max_attempts + 1):
            try:
                if self._request_fn is not None:
                    return self._request_fn(method, path, headers, payload)
                return self._request_httpx(method=method, path=path, headers=headers, payload=payload)
            except Exception as exc:
                if not self._is_retryable_error(exc):
                    raise
                last_error = exc
                if attempt >= self.retry_max_attempts:
                    break
                sleep_seconds = self.retry_backoff_seconds * attempt
                if sleep_seconds > 0:
                    time.sleep(sleep_seconds)
        if last_error is not None:
            raise last_error
        raise RuntimeError("On-prem gateway request failed without error details")

    def _request_httpx(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        url = f"{self.cloud_base_url}{path}"
        with httpx.Client(timeout=self.timeout_seconds) as client:
            if method == "GET":
                response = client.get(url, headers=headers)
            else:
                response = client.request(method, url, headers=headers, json=payload)
        if response.status_code in (429, 500, 502, 503, 504):
            raise OnPremRetryableError(f"Cloud control plane unavailable: status={response.status_code}")
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        if isinstance(exc, OnPremRetryableError):
            return True
        if isinstance(exc, httpx.RequestError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            status_code = exc.response.status_code if exc.response is not None else None
            return status_code in (429, 500, 502, 503, 504)
        return False

    def _write_policy_cache(self, payload: dict[str, Any]) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(_json_canonical(payload), encoding="utf-8")

    def load_cached_policy(self) -> dict[str, Any]:
        if not self.cache_path.exists():
            return {}
        raw = self.cache_path.read_text(encoding="utf-8")
        return json.loads(raw)

    def sync_policy(self) -> dict[str, Any]:
        try:
            payload = self._request(method="GET", path="/onprem/policy-sync")
            self._write_policy_cache(payload)
            return payload
        except Exception as exc:
            cached = self.load_cached_policy()
            if cached:
                fallback_payload = dict(cached)
                fallback_payload["cache_fallback"] = True
                fallback_payload["sync_error"] = str(exc)
                return fallback_payload
            raise

    def build_evidence_bundle(
        self,
        *,
        events: list[dict[str, Any]],
        source_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        generated_at = datetime.now(timezone.utc).isoformat()
        prev_hash = "GENESIS"
        entries: list[dict[str, Any]] = []
        for index, event in enumerate(events):
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            entry_id = str(event.get("entry_id") or f"entry-{index + 1}")
            timestamp = str(event.get("timestamp") or generated_at)
            signal_type = str(event.get("signal_type") or "onprem.signal")
            payload_hash = _compute_payload_hash(payload)
            entry_hash = _compute_entry_hash(
                entry_id=entry_id,
                timestamp=timestamp,
                signal_type=signal_type,
                payload_hash=payload_hash,
                prev_hash=prev_hash,
            )
            row = {
                "entry_id": entry_id,
                "timestamp": timestamp,
                "signal_type": signal_type,
                "payload": payload,
                "payload_hash": payload_hash,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
            }
            entries.append(row)
            prev_hash = entry_hash

        root_hash = entries[-1]["entry_hash"] if entries else _sha256_hex("empty")
        bundle = {
            "schema_name": "hawk.source_evidence_bundle",
            "schema_version": "1.0",
            "provenance_role": "source_provenance",
            "canonical_authority": False,
            "bundle_id": str(uuid4()),
            "tenant_id": self.tenant_id,
            "gateway_id": self.gateway_id,
            "generated_at": generated_at,
            "source_metadata": source_metadata or {},
            "entries": entries,
            "root_hash": root_hash,
            "signature_algorithm": "hmac-sha256",
        }
        signature = hmac.new(
            self.signing_secret.encode("utf-8"),
            _json_canonical(bundle).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        bundle["signature"] = signature
        return bundle

    def upload_evidence_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            method="POST",
            path="/onprem/evidence-bundles/ingest",
            payload=bundle,
        )
