from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.onprem_gateway.client import OnPremGatewayClient


class BuildBundleRequest(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)
    source_metadata: dict[str, Any] = Field(default_factory=dict)


class UploadBundleRequest(BaseModel):
    bundle: dict[str, Any]


def _gateway_from_env() -> OnPremGatewayClient:
    cloud_base_url = os.getenv("ONPREM_CLOUD_BASE_URL", "http://localhost:8000")
    bearer_token = os.getenv("ONPREM_BEARER_TOKEN", "")
    tenant_id = os.getenv("ONPREM_TENANT_ID", "")
    gateway_id = os.getenv("ONPREM_GATEWAY_ID", "onprem-gateway-stub")
    signing_secret = os.getenv("ONPREM_SIGNING_SECRET", "").strip()
    cache_path = Path(os.getenv("ONPREM_POLICY_CACHE_PATH", "./onprem_cache/policy_sync.json"))
    timeout_seconds = float(os.getenv("ONPREM_HTTP_TIMEOUT_SECONDS", "30"))
    retry_max_attempts = int(os.getenv("ONPREM_RETRY_MAX_ATTEMPTS", "3"))
    retry_backoff_seconds = float(os.getenv("ONPREM_RETRY_BACKOFF_SECONDS", "0.5"))

    if not bearer_token or not tenant_id:
        raise RuntimeError("ONPREM_BEARER_TOKEN and ONPREM_TENANT_ID are required")
    if not signing_secret:
        raise RuntimeError("ONPREM_SIGNING_SECRET is required")
    if signing_secret == "dev-onprem-signing-secret" or len(signing_secret) < 32:
        raise RuntimeError(
            "ONPREM_SIGNING_SECRET must be a high-entropy secret and cannot use the development default"
        )

    return OnPremGatewayClient(
        cloud_base_url=cloud_base_url,
        bearer_token=bearer_token,
        tenant_id=tenant_id,
        gateway_id=gateway_id,
        signing_secret=signing_secret,
        cache_path=cache_path,
        timeout_seconds=timeout_seconds,
        retry_max_attempts=retry_max_attempts,
        retry_backoff_seconds=retry_backoff_seconds,
    )


app = FastAPI(title="On-Prem Gateway Stub", version="0.1.0")
_local_bearer = HTTPBearer(auto_error=False)


def require_local_gateway_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(_local_bearer),
) -> None:
    expected = os.getenv("ONPREM_LOCAL_AUTH_TOKEN", "").strip()
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="Local gateway authentication is not configured")
    supplied = credentials.credentials if credentials and credentials.scheme.lower() == "bearer" else ""
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid local gateway credential")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "onprem-gateway-stub"}


@app.post("/policy/sync", dependencies=[Depends(require_local_gateway_auth)])
def policy_sync() -> dict[str, Any]:
    try:
        gateway = _gateway_from_env()
        return gateway.sync_policy()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/policy/cache", dependencies=[Depends(require_local_gateway_auth)])
def policy_cache() -> dict[str, Any]:
    try:
        gateway = _gateway_from_env()
        cached = gateway.load_cached_policy()
        if not cached:
            raise HTTPException(status_code=404, detail="No cached policy")
        return cached
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/evidence/bundle", dependencies=[Depends(require_local_gateway_auth)])
def build_bundle(payload: BuildBundleRequest) -> dict[str, Any]:
    try:
        gateway = _gateway_from_env()
        return gateway.build_evidence_bundle(
            events=payload.events,
            source_metadata=payload.source_metadata,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/evidence/upload", dependencies=[Depends(require_local_gateway_auth)])
def upload_bundle(payload: UploadBundleRequest) -> dict[str, Any]:
    try:
        gateway = _gateway_from_env()
        return gateway.upload_evidence_bundle(payload.bundle)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
