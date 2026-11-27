"""Single sign-on with OpenID Connect, aligned with CxMissionZero's src/oidc.js and src/routes/session.js
(/settings/guide/people-and-access).

- The authorization code flow with PKCE (S256), a ``state`` and a ``nonce``, kept in Redis for ten minutes
  (OIDC_STATE_TTL_SECONDS), used once, and tied to the browser that started by an HttpOnly, SameSite=Lax cookie made
  anew at every start.
- The ID token is verified here against the provider's published keys: RS256, PS256 or ES256 only (never "none",
  never a shared-secret HS*), then its issuer, audience (and authorized party), expiry, issue time, not-before and
  nonce, with a minute of clock difference. Hawk also keeps its own rule that the provider vouches for a second factor
  (``amr`` holds "mfa"): two-step sign-in is not asked again after single sign-on.
- The email comes from the ID token, or from the provider's userinfo address when the token has none (believed only
  for the same subject), and only when the provider marks it verified (unless an administrator turned that off; never
  for an owner or admin).
- Accounts link by (issuer, subject) at the first sign-in, found by email; from then on the person is that account,
  whatever its email says. OIDC_BINDINGS_JSON, Hawk's earlier fixed bindings, still link the subjects it lists.
- Who may sign in: people already here (the default), or everyone in the allowed email domains, added with a chosen
  role that is never owner or admin (Settings -> Sign-in).
- Provider configuration stays in OIDC_PROVIDERS_JSON / OIDC_PROVIDER_SECRETS_JSON; outgoing calls go through the
  outbound destination policy and follow no redirect.
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import HTTPException, status
from redis import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.services import account_security
from app.services.audit_service import write_audit_log
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


ID_TOKEN_ALGORITHMS = ("RS256", "PS256", "ES256")
#: How far the provider's clock and this server's may differ.
CLOCK_SKEW_SECONDS = 60
MAX_TOKEN_CHARS = 64 * 1024
_EMAIL = re.compile(r"^[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")


class OIDCError(ValueError):
    """An intentionally generic, client-safe OIDC failure. ``code`` picks the sentence the sign-in page shows
    (CxMissionZero's /#sso=<code>); the message is for the audit log and never holds a token or secret."""

    def __init__(self, message: str, code: str = "token", *, keys: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.keys = keys


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
        raise OIDCError("OIDC configuration unavailable", "setup") from exc
    return value if value is not None else default


def _provider_rows() -> list[dict[str, Any]]:
    rows = _json_config(settings.oidc_providers_json, [])
    if not isinstance(rows, list):
        raise OIDCError("OIDC configuration unavailable", "setup")
    if any(not isinstance(row, dict) for row in rows):
        raise OIDCError("OIDC configuration unavailable", "setup")
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
            raise OIDCError("OIDC configuration unavailable", "setup") from exc
        if provider.key in seen or provider.kind not in {"entra", "okta"}:
            raise OIDCError("OIDC configuration unavailable", "setup")
        if workspace_slug is None or provider.workspace_slug == workspace_slug:
            out.append(provider)
        seen.add(provider.key)
    return out


def provider_for(key: str, *, workspace_slug: str | None = None) -> OIDCProvider:
    for provider in providers(workspace_slug=workspace_slug):
        if secrets.compare_digest(provider.key, key):
            return provider
    raise OIDCError("OIDC provider unavailable", "provider")


def _public_rows(found: list[OIDCProvider]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for provider in found:
        safe_key = re.sub(r"[^a-zA-Z0-9_-]", "", provider.key)[:64]
        safe_name = "".join(char for char in provider.display_name if char.isprintable())[:100]
        if safe_key and safe_name:
            rows.append({"key": safe_key, "display_name": safe_name, "kind": provider.kind})
    return rows


def public_provider_rows(*, workspace_slug: str) -> list[dict[str, str]]:
    if not settings.company_sso_enabled:
        return []
    return _public_rows(providers(workspace_slug=workspace_slug))


def _provider_domains() -> dict[str, set[str]]:
    """Each provider's email domains, from its optional "domains" list in OIDC_PROVIDERS_JSON."""
    out: dict[str, set[str]] = {}
    for row in _provider_rows():
        raw = row.get("domains") or []
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            raise OIDCError("OIDC configuration unavailable", "setup")
        out[str(row.get("key", "")).strip()] = {str(d).strip().lower().lstrip("@") for d in raw if str(d).strip()}
    return out


def sign_in_providers() -> dict[str, Any]:
    """The single sign-on buttons for the sign-in page, which has no workspace box (an on-premises installation).

    Every provider when they all belong to one workspace; otherwise none, and the page asks for the email address
    first (discover_providers)."""
    if not settings.company_sso_enabled:
        return {"providers": [], "byEmail": False}
    found = providers()
    if len({p.workspace_slug.lower() for p in found}) <= 1:
        return {"providers": _public_rows(found), "byEmail": False}
    return {"providers": [], "byEmail": True}


def discover_providers(email: str) -> list[dict[str, str]]:
    """The providers for an email address's domain: those whose "domains" list it, or, with one workspace only, all.

    Decided by the domain alone, never by whether anyone has that address: the same answer for every address at a
    domain, so it cannot be used to find out who has an account."""
    if not settings.company_sso_enabled:
        return []
    domain = email.strip().lower().rpartition("@")[2].strip()
    if not domain or "." not in domain:
        return []
    found = providers()
    domains = _provider_domains()
    matched = [p for p in found if domain in domains.get(p.key, set())]
    if matched:
        return _public_rows(matched)
    if len({p.workspace_slug.lower() for p in found}) <= 1:
        return _public_rows(found)
    return []


def _secret_rows() -> dict[str, Any]:
    try:
        raw = decrypt_connector_secrets(settings.oidc_provider_secrets_json)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise OIDCError("OIDC provider unavailable", "provider") from exc
    return raw if isinstance(raw, dict) else {}


def _provider_secret(provider: OIDCProvider) -> str:
    row = _secret_rows().get(provider.key)
    if isinstance(row, dict):
        value = row.get("client_secret")
    else:
        value = row
    if not isinstance(value, str) or not value:
        raise OIDCError("OIDC provider unavailable", "provider")
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
        raise OIDCError("OIDC service unavailable", "provider") from exc


def _cache_get(key: str) -> Any | None:
    current = _CACHE.get(key)
    if not current or current[0] <= time.time():
        _CACHE.pop(key, None)
        return None
    return current[2]


def _cache_put(key: str, value: Any) -> None:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > min(_MAX_JSON_BYTES, int(settings.oidc_cache_max_bytes)):
        raise OIDCError("OIDC provider metadata unavailable", "provider")
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
        raise OIDCError("OIDC provider unavailable", "provider") from exc
    if response.status_code >= 400:
        raise OIDCError("OIDC provider unavailable", "provider")
    if len(response.content) > min(_MAX_JSON_BYTES, int(settings.oidc_cache_max_bytes)):
        raise OIDCError("OIDC provider metadata unavailable", "provider")
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
        raise OIDCError("OIDC provider unavailable", "provider") from exc
    if not isinstance(value, dict) or value.get("issuer") != provider.issuer or not value.get("authorization_endpoint") or not value.get("token_endpoint") or not value.get("jwks_uri"):
        raise OIDCError("OIDC provider unavailable", "provider")
    issuer_origin = f"https://{urlsplit(provider.issuer).netloc.lower()}"
    if any(
        urlsplit(str(value[field])).scheme.lower() != "https"
        or f"https://{urlsplit(str(value[field])).netloc.lower()}" != issuer_origin
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri")
    ):
        raise OIDCError("OIDC provider unavailable", "provider")
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


def start(*, provider_key: str, workspace_slug: str | None = None, redis: Any | None = None) -> tuple[str, str]:
    if not settings.company_sso_enabled:
        raise OIDCError("OIDC unavailable", "off")
    # Provider keys are unique across the installation: without a workspace, the provider's own is used.
    provider = provider_for(provider_key, workspace_slug=workspace_slug or None)
    workspace_slug = provider.workspace_slug
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
        raise OIDCError("OIDC service unavailable", "provider") from exc
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
        raise OIDCError("OIDC provider unavailable", "provider") from exc
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        raise OIDCError("OIDC provider unavailable", "provider")
    _cache_put(key, value)
    return value


def _b64decode(part: str) -> bytes:
    text = str(part)
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _token_part(part: str) -> dict[str, Any] | None:
    try:
        value = json.loads(_b64decode(part).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _int_of(value: Any) -> int:
    return int.from_bytes(_b64decode(str(value)), "big")


def _key_for(header: Mapping[str, Any], keys: list[Any]) -> Any:
    """The provider's key for a token, as a public key object; OIDCError when there is none that fits."""

    family = "EC" if header.get("alg") == "ES256" else "RSA"
    usable = [
        k
        for k in keys
        if isinstance(k, dict)
        and k.get("kty") == family
        and k.get("use") in (None, "sig")
        and k.get("alg") in (None, header.get("alg"))
        and (family != "EC" or k.get("crv") == "P-256")
    ]
    if "kid" in header:
        jwk = next((k for k in usable if k.get("kid") == header.get("kid")), None)
    else:
        jwk = usable[0] if len(usable) == 1 else None
    if jwk is None:
        raise OIDCError("the ID token is signed with a key the identity provider does not publish", keys=True)
    try:
        # Only the public parts are used, whatever else the key set carries.
        if family == "EC":
            key: Any = ec.EllipticCurvePublicNumbers(_int_of(jwk["x"]), _int_of(jwk["y"]), ec.SECP256R1()).public_key()
        else:
            key = rsa.RSAPublicNumbers(_int_of(jwk["e"]), _int_of(jwk["n"])).public_key()
    except (KeyError, ValueError, TypeError) as exc:
        raise OIDCError("the identity provider publishes a key that cannot be read") from exc
    if family == "RSA" and key.key_size < 2048:
        raise OIDCError("the identity provider's RSA key is shorter than 2048 bits")
    return key


def verify_id_token(token: str, *, keys: list[Any], issuer: str, client_id: str, nonce: str, now: float | None = None) -> dict[str, Any]:
    """Verify an ID token against the provider's keys and return its claims (CxMissionZero's verifyIdToken); raises
    OIDCError saying what was wrong, in words fit for the audit log (never the token)."""

    parts = token.split(".") if isinstance(token, str) and len(token) <= MAX_TOKEN_CHARS else []
    header = _token_part(parts[0]) if len(parts) == 3 else None
    claims = _token_part(parts[1]) if len(parts) == 3 else None
    if not header or not claims:
        raise OIDCError("the identity provider sent no ID token that can be read")
    # Only signatures made with the provider's private key: "none" and the shared-secret HS* are refused by name.
    if header.get("alg") not in ID_TOKEN_ALGORITHMS:
        raise OIDCError(f'the ID token is signed with "{str(header.get("alg") or "nothing")[:20]}", which is not accepted (only {", ".join(ID_TOKEN_ALGORITHMS)})')
    if "crit" in header:
        raise OIDCError("the ID token asks for an extension this server does not know")
    key = _key_for(header, keys if isinstance(keys, list) else [])
    signed = f"{parts[0]}.{parts[1]}".encode("ascii", "replace")
    try:
        signature = _b64decode(parts[2])
        if header["alg"] == "RS256":
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        elif header["alg"] == "PS256":
            key.verify(signature, signed, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        else:
            if len(signature) != 64:
                raise InvalidSignature()
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise OIDCError("the ID token's signature does not match the identity provider's key", keys=True) from exc

    seconds = int(time.time() if now is None else now)

    def number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    if not isinstance(claims.get("iss"), str) or claims["iss"] != issuer:
        raise OIDCError("the ID token comes from another issuer")
    audience = claims.get("aud") if isinstance(claims.get("aud"), list) else [claims.get("aud")]
    if client_id not in audience:
        raise OIDCError("the ID token was made for another application (audience)")
    if len(audience) > 1 and claims.get("azp") != client_id:
        raise OIDCError("the ID token names several audiences and another authorized party")
    if "azp" in claims and claims.get("azp") != client_id:
        raise OIDCError("the ID token was made for another application (authorized party)")
    if not number(claims.get("exp")) or claims["exp"] + CLOCK_SKEW_SECONDS <= seconds:
        raise OIDCError("the ID token has expired")
    if not number(claims.get("iat")) or claims["iat"] - CLOCK_SKEW_SECONDS > seconds:
        raise OIDCError("the ID token has no issue time, or one in the future")
    if "nbf" in claims and (not number(claims.get("nbf")) or claims["nbf"] - CLOCK_SKEW_SECONDS > seconds):
        raise OIDCError("the ID token is not valid yet")
    if not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(claims["nonce"].encode(), str(nonce).encode()):
        raise OIDCError("the ID token does not belong to this sign-in (nonce)")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OIDCError("the ID token names no subject")
    return claims


def _decode_id_token(token: str, provider: OIDCProvider, *, nonce: str) -> dict[str, Any]:
    metadata = provider_metadata(provider)
    issuer = str(metadata.get("issuer") or provider.issuer)

    def check(jwks: Mapping[str, Any]) -> dict[str, Any]:
        return verify_id_token(token, keys=list(jwks.get("keys") or []), issuer=issuer, client_id=provider.client_id, nonce=nonce)

    try:
        claims = check(_jwks(provider, metadata))
    except OIDCError as exc:
        # The provider may have changed its keys since they were read: read them again, once, and check again.
        if not exc.keys:
            raise
        claims = check(_jwks(provider, metadata, force=True))
    # Hawk's own rule, kept: the provider must say a second factor was used.
    amr = claims.get("amr")
    if not (isinstance(amr, list) and "mfa" in amr):
        raise OIDCError("the identity provider does not say a second factor was used (amr)", "mfa")
    return claims


def _email_of(value: Any) -> str:
    email = value.strip().lower() if isinstance(value, str) else ""
    return email if len(email) <= 254 and _EMAIL.match(email) else ""


def _verified_of(value: Any) -> bool:
    return value is True or value == "true"


def _printable(value: Any) -> str:
    return "".join(ch for ch in str(value or "") if ch.isprintable())[:120]


def identity_from(provider: OIDCProvider, claims: Mapping[str, Any], *, access_token: str | None, metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Who signed in: {email, verified, name, sub, issuer}. The email comes from the ID token, or from userinfo when
    the token carries none (believed only when it is about the same subject)."""

    identity: dict[str, Any] = {
        "email": _email_of(claims.get("email")),
        "verified": _verified_of(claims.get("email_verified")),
        "name": _printable(claims.get("name")),
        "sub": str(claims.get("sub") or ""),
        "issuer": provider.issuer,
    }
    endpoint = metadata.get("userinfo_endpoint")
    if not identity["email"] and isinstance(endpoint, str) and access_token:
        issuer_origin = f"https://{urlsplit(provider.issuer).netloc.lower()}"
        if urlsplit(endpoint).scheme == "https" and f"https://{urlsplit(endpoint).netloc.lower()}" == issuer_origin:
            try:
                info = _request(provider, "GET", endpoint, headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}).json()
            except (OIDCError, ValueError):
                info = None
            if isinstance(info, dict) and info.get("sub") == identity["sub"]:
                identity["email"] = _email_of(info.get("email"))
                identity["verified"] = _verified_of(info.get("email_verified"))
                identity["name"] = _printable(info.get("name")) or identity["name"]
    return identity


def identity_problem(policy_row: Any, identity: Mapping[str, Any]) -> OIDCError | None:
    """Why this identity may not sign in, or None: the email must be there, be marked verified by the provider (unless
    an administrator turned that check off), and be in one of the allowed domains (when any are listed)."""

    if not identity.get("sub") or len(str(identity["sub"])) > 255:
        return OIDCError("the identity provider names no subject this server can keep")
    if not identity.get("email"):
        return OIDCError("the identity provider gave no email address", "email")
    if policy_row.sso_require_verified_email and not identity.get("verified"):
        return OIDCError(f"the identity provider does not mark {identity['email']} as verified", "email")
    domains = account_security.sso_domains(policy_row)
    if domains and str(identity["email"]).rpartition("@")[2] not in domains:
        return OIDCError(f"{identity['email']} is not in an allowed email domain", "domain")
    return None


def _bound_user_id(provider: OIDCProvider, sub: str) -> str | None:
    """OIDC_BINDINGS_JSON: Hawk's earlier fixed (provider, issuer, subject) -> user bindings, still honoured."""

    try:
        rows = _json_config(settings.oidc_bindings_json, [])
    except OIDCError:
        return None
    if not isinstance(rows, list):
        return None
    matches = [row for row in rows if isinstance(row, dict) and row.get("provider_key") == provider.key and row.get("issuer") == provider.issuer and row.get("subject") == sub]
    if len(matches) != 1 or matches[0].get("tenant_id") != provider.tenant_id or not isinstance(matches[0].get("user_id"), str):
        return None
    return matches[0]["user_id"]


def _audit(db: Session, *, provider: OIDCProvider, user: User | None, action: str, reason: str) -> None:
    write_audit_log(
        db,
        tenant_id=provider.tenant_id if db.get(Tenant, provider.tenant_id) else None,
        actor_user_id=user.id if user else None,
        actor_type="human" if user else "system",
        action=action,
        resource_type="user",
        resource_id=user.id if user else "single-sign-on",
        payload={"reason": reason, "provider": provider.key},
    )


def audit_refusal(db: Session, *, provider_key: str, error: OIDCError) -> None:
    """A refused single sign-on, in the audit log: what was wrong, never a token or secret. Listed only so many a
    minute, as other refused sign-ins (app/services/refusal_audit.py)."""

    from app.services import refusal_audit

    if not refusal_audit.may_list(db, "sign_in", f"single sign-on {provider_key}"):
        return
    write_audit_log(
        db,
        tenant_id=None,
        actor_user_id=None,
        actor_type="system",
        action="auth.sso.refused",
        resource_type="single-sign-on",
        resource_id=provider_key or "single-sign-on",
        payload={"reason": f"Single sign-on refused ({error.code}): {error}."},
    )


def resolve_user(db: Session, provider: OIDCProvider, identity: Mapping[str, Any]) -> User:
    """The person an identity signs in as (CxMissionZero's callback): linked by (issuer, subject), or found by email
    once and linked from then on, or added when the administrator chose so. Raises OIDCError. The caller commits."""

    row = account_security.policy(db)
    problem = identity_problem(row, identity)
    if problem:
        raise problem
    sub = str(identity["sub"])
    linked = db.scalar(select(User).where(User.sso_issuer == provider.issuer, User.sso_subject == sub))
    if linked is None:
        bound = _bound_user_id(provider, sub)
        if bound:
            linked = db.scalar(select(User).where(User.id == bound))
    user = linked or account_security.find_by_email(db, str(identity["email"]))
    if user is not None and linked is None:
        if user.sso_subject:
            raise OIDCError(f"{user.email} is linked to another account at the identity provider (reset the single sign-on link under Settings -> Sign-in if that account was made anew)", "link")
        # Whatever the "verified" switch says: owners and admins are never linked on an address the provider does not vouch for.
        if not identity.get("verified") and account_security.is_admin(db, user):
            raise OIDCError(f"the identity provider does not mark {identity['email']} as verified, and an owner or admin is not signed in on such an address until they are linked", "email")
    if user is None and row.sso_provision == "create":
        role = row.sso_role if row.sso_role in account_security.SSO_ROLES else "viewer"
        tenant = db.get(Tenant, provider.tenant_id)
        if tenant is None or not tenant.is_active:
            raise OIDCError("the workspace of this identity provider is not active", "setup")
        from app.services import activation_service

        user = User(
            email=str(identity["email"]),
            full_name=str(identity.get("name") or "")[:255],
            # No password: an unusable hash (app/core/security.py verify_password answers False for it).
            hashed_password="!sso-" + secrets.token_hex(16),
            is_active=True,
        )
        db.add(user)
        db.flush()
        activation_service.assert_may_add_member(db, tenant.id)
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
        db.flush()
        _audit(db, provider=provider, user=user, action="auth.sso.provisioned", reason=f"Added {user.email} as {role} at their first single sign-on.")
    if user is None:
        raise OIDCError(f"{identity['email']} has no access here", "unknown")
    if not user.is_active:
        raise OIDCError("the account is disabled", "disabled")
    membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user.id, UserTenantRole.tenant_id == provider.tenant_id))
    if membership is None:
        raise OIDCError(f"{user.email} has no access to this workspace", "unknown")
    if not user.sso_subject:
        user.sso_issuer = provider.issuer
        user.sso_subject = sub
        db.flush()
        _audit(db, provider=provider, user=user, action="auth.sso.linked", reason=f"{user.email} was linked to their account at the identity provider at their first single sign-on.")
    return user


def callback(*, code: str, state: str, browser: str, db: Session | None = None, redis: Any | None = None) -> str:
    client = redis or _redis()
    raw = _consume(client, f"oidc:state:{state}")
    if not raw:
        raise OIDCError("OIDC state expired", "expired")
    try:
        payload = decrypt_connector_secrets(raw.decode("utf-8") if isinstance(raw, bytes) else str(raw))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise OIDCError("OIDC state invalid", "expired") from exc
    if not secrets.compare_digest(str(payload.get("browser")), _browser_hash(browser)):
        raise OIDCError("OIDC state invalid", "expired")
    try:
        created = int(payload.get("created", 0))
    except (TypeError, ValueError) as exc:
        raise OIDCError("OIDC state invalid", "expired") from exc
    if created + int(settings.oidc_state_ttl_seconds) < int(time.time()):
        raise OIDCError("OIDC state expired", "expired")
    provider = provider_for(str(payload.get("provider")), workspace_slug=str(payload.get("workspace")))
    metadata = provider_metadata(provider)
    try:
        response = _request(provider, "POST", str(metadata["token_endpoint"]), data={"grant_type": "authorization_code", "code": code, "redirect_uri": settings.oidc_callback_url, "client_id": provider.client_id, "client_secret": _provider_secret(provider), "code_verifier": payload["verifier"]}, headers={"Accept": "application/json"})
        answer = response.json()
        token = answer.get("id_token")
    except (ValueError, AttributeError, KeyError, TypeError) as exc:
        raise OIDCError("OIDC provider unavailable", "provider") from exc
    if not isinstance(token, str):
        raise OIDCError("OIDC assertion rejected")
    claims = _decode_id_token(token, provider, nonce=str(payload.get("nonce")))
    access_token = answer.get("access_token") if isinstance(answer.get("access_token"), str) else None
    identity = identity_from(provider, claims, access_token=access_token, metadata=metadata)
    if db is None:
        raise OIDCError("OIDC service unavailable", "provider")
    user = resolve_user(db, provider, identity)
    ticket = _b64(secrets.token_bytes(32))
    ticket_payload = _fernet_payload({"user_id": user.id, "tenant_id": provider.tenant_id, "workspace": provider.workspace_slug, "browser": _browser_hash(browser)})
    try:
        client.setex(f"oidc:ticket:{ticket}", int(settings.oidc_ticket_ttl_seconds), ticket_payload)
    except Exception as exc:
        raise OIDCError("OIDC service unavailable", "provider") from exc
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
