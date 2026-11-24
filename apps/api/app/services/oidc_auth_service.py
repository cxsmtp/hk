"""Bounded, configuration-backed OIDC authorization-code PKCE support.

The service deliberately has no account-provisioning or email-linking path. A
successful assertion must match one exact issuer/subject binding and an active
database membership before Hawk tokens are issued.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import HTTPException, status
from jose import JWTError, jwt
from redis import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.services.auth_service import issue_tokens
from app.services.connector_secret_service import decrypt_connector_secrets, encrypt_connector_secrets
from app.services.outbound_destination_policy import (
    OutboundDestinationPolicyError,
    build_outbound_destination_policy,
    request_with_redirect_validation,
)


STATE_COOKIE = "hawk_oidc_state"
TICKET_COOKIE = "hawk_oidc_ticket"
_MAX_JSON_BYTES = 262_144
_CACHE: dict[str, tuple[float, bytes, Any]] = {}


class OIDCError(ValueError):
    """An intentionally generic, client-safe OIDC failure."""


@dataclass(frozen=True)
class OIDCProvider:
    key: str
    kind: str
    display_name: str
    workspace_slug: str
    issuer: str
    client_id: str
    tenant_id: str


def _json_config(raw: str, default: Any) -> Any:
    try:
        value = json.loads(raw or "")
    except (TypeError, json.JSONDecodeError) as exc:
        raise OIDCError("OIDC configuration unavailable") from exc
    return value if value is not None else default


def _provider_rows() -> list[dict[str, Any]]:
    rows = _json_config(settings.oidc_providers_json, [])
    if not isinstance(rows, list):
        raise OIDCError("OIDC configuration unavailable")
    if any(not isinstance(row, dict) for row in rows):
        raise OIDCError("OIDC configuration unavailable")
    return rows


def providers(*, workspace_slug: str | None = None) -> list[OIDCProvider]:
    out: list[OIDCProvider] = []
    seen: set[str] = set()
    for row in _provider_rows():
        try:
            provider = OIDCProvider(
                key=str(row["key"]).strip(),
                kind=str(row["kind"]).strip().lower(),
                display_name=str(row["display_name"]).strip(),
                workspace_slug=str(row["workspace_slug"]).strip(),
                issuer=str(row["issuer"]).strip().rstrip("/"),
                client_id=str(row["client_id"]).strip(),
                tenant_id=str(row["tenant_id"]).strip(),
            )
        except (KeyError, TypeError) as exc:
            raise OIDCError("OIDC configuration unavailable") from exc
        if provider.key in seen or provider.kind not in {"entra", "okta"}:
            raise OIDCError("OIDC configuration unavailable")
        if workspace_slug is None or provider.workspace_slug == workspace_slug:
            out.append(provider)
        seen.add(provider.key)
    return out


def provider_for(key: str, *, workspace_slug: str | None = None) -> OIDCProvider:
    for provider in providers(workspace_slug=workspace_slug):
        if secrets.compare_digest(provider.key, key):
            return provider
    raise OIDCError("OIDC provider unavailable")


def public_provider_rows(*, workspace_slug: str) -> list[dict[str, str]]:
    if not settings.company_sso_enabled:
        return []
    rows: list[dict[str, str]] = []
    for provider in providers(workspace_slug=workspace_slug):
        safe_key = re.sub(r"[^a-zA-Z0-9_-]", "", provider.key)[:64]
        safe_name = "".join(char for char in provider.display_name if char.isprintable())[:100]
        if safe_key and safe_name:
            rows.append({"key": safe_key, "display_name": safe_name, "kind": provider.kind})
    return rows


def _secret_rows() -> dict[str, Any]:
    try:
        raw = decrypt_connector_secrets(settings.oidc_provider_secrets_json)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise OIDCError("OIDC provider unavailable") from exc
    return raw if isinstance(raw, dict) else {}


def _provider_secret(provider: OIDCProvider) -> str:
    row = _secret_rows().get(provider.key)
    if isinstance(row, dict):
        value = row.get("client_secret")
    else:
        value = row
    if not isinstance(value, str) or not value:
        raise OIDCError("OIDC provider unavailable")
    return value


def _redis() -> Redis:
    return Redis.from_url(settings.redis_url, socket_connect_timeout=0.5, socket_timeout=0.5, decode_responses=False)


def _browser_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fernet_payload(payload: Mapping[str, Any]) -> str:
    encrypted = encrypt_connector_secrets(dict(payload))
    if not encrypted:
        raise OIDCError("OIDC state unavailable")
    return encrypted


def _consume(redis: Any, key: str) -> bytes | None:
    try:
        if hasattr(redis, "getdel"):
            return redis.getdel(key)
        result = redis.eval("local v=redis.call('get',KEYS[1]); if v then redis.call('del',KEYS[1]); end; return v", 1, key)
        return result
    except Exception as exc:
        raise OIDCError("OIDC service unavailable") from exc


def _cache_get(key: str) -> Any | None:
    current = _CACHE.get(key)
    if not current or current[0] <= time.time():
        _CACHE.pop(key, None)
        return None
    return current[2]


def _cache_put(key: str, value: Any) -> None:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > min(_MAX_JSON_BYTES, int(settings.oidc_cache_max_bytes)):
        raise OIDCError("OIDC provider metadata unavailable")
    _CACHE[key] = (time.time() + min(300, max(1, int(settings.oidc_cache_ttl_seconds))), raw, value)
    if len(_CACHE) > 32:
        oldest = min(_CACHE, key=lambda item: _CACHE[item][0])
        _CACHE.pop(oldest, None)


def _oidc_policy(provider: OIDCProvider):
    origin = f"{urlsplit(provider.issuer).scheme}://{urlsplit(provider.issuer).netloc}"
    return build_outbound_destination_policy({"oidc": (origin,)})


def _request(provider: OIDCProvider, method: str, url: str, **kwargs: Any) -> httpx.Response:
    try:
        response = request_with_redirect_validation(
            method,
            url,
            source="oidc",
            policy=_oidc_policy(provider),
            max_redirects=0,
            timeout=5.0,
            **kwargs,
        )
    except (OutboundDestinationPolicyError, httpx.HTTPError, OIDCError) as exc:
        raise OIDCError("OIDC provider unavailable") from exc
    if response.status_code >= 400:
        raise OIDCError("OIDC provider unavailable")
    if len(response.content) > min(_MAX_JSON_BYTES, int(settings.oidc_cache_max_bytes)):
        raise OIDCError("OIDC provider metadata unavailable")
    return response


def provider_metadata(provider: OIDCProvider) -> dict[str, Any]:
    key = f"metadata:{provider.key}:{provider.issuer}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    response = _request(provider, "GET", f"{provider.issuer}/.well-known/openid-configuration")
    try:
        value = response.json()
    except ValueError as exc:
        raise OIDCError("OIDC provider unavailable") from exc
    if not isinstance(value, dict) or value.get("issuer") != provider.issuer or not value.get("authorization_endpoint") or not value.get("token_endpoint") or not value.get("jwks_uri"):
        raise OIDCError("OIDC provider unavailable")
    issuer_origin = f"https://{urlsplit(provider.issuer).netloc.lower()}"
    if any(
        urlsplit(str(value[field])).scheme.lower() != "https"
        or f"https://{urlsplit(str(value[field])).netloc.lower()}" != issuer_origin
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri")
    ):
        raise OIDCError("OIDC provider unavailable")
    _cache_put(key, value)
    return value


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def build_authorization_url(provider: OIDCProvider, *, state: str, nonce: str, verifier: str, metadata: Mapping[str, Any]) -> str:
    challenge = _b64(hashlib.sha256(verifier.encode("ascii")).digest())
    query = {
        "client_id": provider.client_id,
        "redirect_uri": settings.oidc_callback_url,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{metadata['authorization_endpoint']}?{urlencode(query)}"


def start(*, provider_key: str, workspace_slug: str, redis: Any | None = None) -> tuple[str, str]:
    if not settings.company_sso_enabled:
        raise OIDCError("OIDC unavailable")
    provider = provider_for(provider_key, workspace_slug=workspace_slug)
    metadata = provider_metadata(provider)
    state = _b64(secrets.token_bytes(32))
    nonce = _b64(secrets.token_bytes(32))
    verifier = _b64(secrets.token_bytes(48))
    browser = _b64(secrets.token_bytes(32))
    payload = {"provider": provider.key, "workspace": workspace_slug, "nonce": nonce, "verifier": verifier, "browser": _browser_hash(browser), "created": int(time.time())}
    client = redis or _redis()
    try:
        client.setex(f"oidc:state:{state}", int(settings.oidc_state_ttl_seconds), _fernet_payload(payload))
    except Exception as exc:
        raise OIDCError("OIDC service unavailable") from exc
    return build_authorization_url(provider, state=state, nonce=nonce, verifier=verifier, metadata=metadata), browser


def _jwks(provider: OIDCProvider, metadata: Mapping[str, Any], *, force: bool = False) -> dict[str, Any]:
    key = f"jwks:{provider.key}:{metadata['jwks_uri']}"
    if not force:
        cached = _cache_get(key)
        if cached is not None:
            return cached
    response = _request(provider, "GET", str(metadata["jwks_uri"]))
    try:
        value = response.json()
    except ValueError as exc:
        raise OIDCError("OIDC provider unavailable") from exc
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        raise OIDCError("OIDC provider unavailable")
    _cache_put(key, value)
    return value


def _decode_id_token(token: str, provider: OIDCProvider, *, nonce: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise OIDCError("OIDC assertion rejected")
        metadata = provider_metadata(provider)
        jwks = _jwks(provider, metadata)
        key = next((item for item in jwks["keys"] if item.get("kid") == header["kid"]), None)
        if key is None:
            jwks = _jwks(provider, metadata, force=True)
            key = next((item for item in jwks["keys"] if item.get("kid") == header["kid"]), None)
        if key is None:
            raise OIDCError("OIDC assertion rejected")
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=provider.client_id, issuer=provider.issuer, options={"require_exp": True, "require_sub": True, "require_nonce": True})
    except (JWTError, KeyError, TypeError, ValueError) as exc:
        raise OIDCError("OIDC assertion rejected") from exc
    if claims.get("nonce") != nonce or not claims.get("sub"):
        raise OIDCError("OIDC assertion rejected")
    amr = claims.get("amr")
    if not (isinstance(amr, list) and "mfa" in amr):
        raise OIDCError("OIDC assertion rejected")
    return claims


def _binding(provider: OIDCProvider, claims: Mapping[str, Any]) -> tuple[str, str]:
    try:
        rows = _json_config(settings.oidc_bindings_json, [])
    except OIDCError:
        raise
    if not isinstance(rows, list):
        raise OIDCError("OIDC assertion rejected")
    matches = [row for row in rows if isinstance(row, dict) and row.get("provider_key") == provider.key and row.get("issuer") == provider.issuer and row.get("subject") == claims.get("sub")]
    if len(matches) != 1 or matches[0].get("tenant_id") != provider.tenant_id:
        raise OIDCError("OIDC assertion rejected")
    user_id, tenant_id = matches[0].get("user_id"), matches[0].get("tenant_id")
    if not isinstance(user_id, str) or not isinstance(tenant_id, str) or not user_id or not tenant_id:
        raise OIDCError("OIDC assertion rejected")
    return user_id, tenant_id


def callback(*, code: str, state: str, browser: str, redis: Any | None = None) -> str:
    client = redis or _redis()
    raw = _consume(client, f"oidc:state:{state}")
    if not raw:
        raise OIDCError("OIDC state expired")
    try:
        payload = decrypt_connector_secrets(raw.decode("utf-8") if isinstance(raw, bytes) else str(raw))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise OIDCError("OIDC state invalid") from exc
    if not secrets.compare_digest(str(payload.get("browser")), _browser_hash(browser)):
        raise OIDCError("OIDC state invalid")
    try:
        created = int(payload.get("created", 0))
    except (TypeError, ValueError) as exc:
        raise OIDCError("OIDC state invalid") from exc
    if created + int(settings.oidc_state_ttl_seconds) < int(time.time()):
        raise OIDCError("OIDC state expired")
    provider = provider_for(str(payload.get("provider")), workspace_slug=str(payload.get("workspace")))
    metadata = provider_metadata(provider)
    try:
        response = _request(provider, "POST", str(metadata["token_endpoint"]), data={"grant_type": "authorization_code", "code": code, "redirect_uri": settings.oidc_callback_url, "client_id": provider.client_id, "client_secret": _provider_secret(provider), "code_verifier": payload["verifier"]}, headers={"Accept": "application/json"})
        token = response.json().get("id_token")
    except (ValueError, AttributeError, KeyError, TypeError) as exc:
        raise OIDCError("OIDC provider unavailable") from exc
    if not isinstance(token, str):
        raise OIDCError("OIDC assertion rejected")
    claims = _decode_id_token(token, provider, nonce=str(payload.get("nonce")))
    user_id, tenant_id = _binding(provider, claims)
    ticket = _b64(secrets.token_bytes(32))
    ticket_payload = _fernet_payload({"user_id": user_id, "tenant_id": tenant_id, "workspace": provider.workspace_slug, "browser": _browser_hash(browser)})
    try:
        client.setex(f"oidc:ticket:{ticket}", int(settings.oidc_ticket_ttl_seconds), ticket_payload)
    except Exception as exc:
        raise OIDCError("OIDC service unavailable") from exc
    return ticket


def complete(*, ticket: str, browser: str, db: Session, redis: Any | None = None) -> dict[str, Any]:
    client = redis or _redis()
    raw = _consume(client, f"oidc:ticket:{ticket}")
    if not raw:
        raise OIDCError("OIDC ticket expired")
    try:
        payload = decrypt_connector_secrets(raw.decode("utf-8") if isinstance(raw, bytes) else str(raw))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise OIDCError("OIDC ticket invalid") from exc
    if not secrets.compare_digest(str(payload.get("browser")), _browser_hash(browser)):
        raise OIDCError("OIDC ticket invalid")
    user = db.scalar(select(User).where(User.id == payload.get("user_id"), User.is_active.is_(True)))
    membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == payload.get("user_id"), UserTenantRole.tenant_id == payload.get("tenant_id")))
    tenant = db.scalar(select(Tenant).where(Tenant.id == payload.get("tenant_id"), Tenant.slug == payload.get("workspace"), Tenant.is_active.is_(True)))
    if not user or not membership or not tenant:
        raise OIDCError("OIDC assertion rejected")
    tokens = issue_tokens(db, user=user, tenant_id=membership.tenant_id, role=membership.role)
    memberships = db.scalars(select(UserTenantRole).where(UserTenantRole.user_id == user.id)).all()
    tenants = []
    for row in memberships:
        item = db.get(Tenant, row.tenant_id)
        if item and item.is_active:
            tenants.append({"id": item.id, "name": item.name, "role": row.role})
    return {**tokens, "user": {"id": user.id, "email": user.email, "full_name": user.full_name}, "tenants": tenants, "selected_tenant_id": membership.tenant_id}


def as_http_error(exc: OIDCError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
