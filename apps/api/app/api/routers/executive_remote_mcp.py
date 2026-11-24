from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from html import escape
import secrets
from urllib.parse import parse_qs, urlencode
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import ROLE_ORDER
from app.core.security import create_token, decode_token
from app.core.tenant import TenantContext
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.models.executive_mcp import ExecutiveMCPDeviceAuthorization
from app.db.session import get_db
from app.services.auth_service import authenticate_user
from app.services.audit_service import write_audit_log
from app.services.executive_mcp_service import (
    ExecutiveQuery,
    build_executive_mcp_summary,
    create_executive_mcp_presentation,
    query_executive_mcp_metrics,
)
from app.services.executive_remote_mcp_service import (
    EXECUTIVE_REMOTE_MCP_TOOLS,
    EXECUTIVE_REMOTE_MCP_SCOPE_PRESENTATION,
    EXECUTIVE_REMOTE_MCP_SCOPE_READ,
    build_oauth_authorization_server_metadata,
    build_oauth_protected_resource_metadata,
    build_executive_remote_mcp_metadata,
    build_initialize_result,
    build_jsonrpc_error,
    build_jsonrpc_result,
    build_tool_call_result,
    build_tools_list_result,
)


router = APIRouter(prefix="/mcp/executive", tags=["executive-remote-mcp"])
compatibility_router = APIRouter(tags=["executive-remote-mcp"])
_bearer = HTTPBearer(auto_error=False)
_CONNECTOR_TOKEN_MINUTES = 60
_OAUTH_CODE_MINUTES = 5
_DEVICE_CODE_MINUTES = 15
_DEVICE_POLL_INTERVAL_SECONDS = 5

_QUERY_METRICS = set(
    next(tool for tool in EXECUTIVE_REMOTE_MCP_TOOLS if tool["name"] == "query_executive_metrics")["inputSchema"][
        "properties"
    ]["metric"]["enum"]
)


class RemoteMCPRequest(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: str | int | None = None
    method: str
    params: dict[str, Any] | None = None


def require_remote_mcp_context(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    x_tenant_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> TenantContext:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Executive MCP connector authorization required",
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{_base_url(request)}/mcp/executive/.well-known/oauth-protected-resource"'},
        )

    try:
        payload = decode_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MCP bearer token") from exc

    token_type = str(payload.get("type") or "")
    user = _require_active_user(db, str(payload.get("sub") or ""))

    if token_type == "mcp_connector":
        scope = set(str(payload.get("scope") or "").split())
        if EXECUTIVE_REMOTE_MCP_SCOPE_READ not in scope:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Executive MCP scope is missing")
        return _resolve_authorized_tenant_context(
            db,
            user=user,
            requested_tenant_id=str(payload.get("tenant_id") or ""),
            token_role=str(payload.get("role") or ""),
        )

    if token_type == "access":
        return _resolve_authorized_tenant_context(
            db,
            user=user,
            requested_tenant_id=x_tenant_id or str(payload.get("tenant_id") or ""),
            token_role=str(payload.get("role") or ""),
        )

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unsupported MCP token type")


@router.get("")
def executive_remote_mcp_metadata(
    include_tools: bool = Query(default=True),
) -> dict[str, Any]:
    metadata = build_executive_remote_mcp_metadata()
    if not include_tools:
        metadata = dict(metadata)
        metadata["tools"] = []
    return metadata


@router.get("/.well-known/oauth-protected-resource")
def executive_remote_mcp_protected_resource_metadata(request: Request) -> dict[str, Any]:
    return build_oauth_protected_resource_metadata(_base_url(request))


@router.get("/.well-known/oauth-authorization-server")
def executive_remote_mcp_authorization_server_metadata(request: Request) -> dict[str, Any]:
    return build_oauth_authorization_server_metadata(_base_url(request))


@compatibility_router.get("/.well-known/mcp")
def executive_remote_mcp_root_metadata(
    include_tools: bool = Query(default=True),
) -> dict[str, Any]:
    metadata = build_executive_remote_mcp_metadata()
    if not include_tools:
        metadata = dict(metadata)
        metadata["tools"] = []
    return metadata


@compatibility_router.get("/.well-known/oauth-protected-resource")
def executive_remote_mcp_root_protected_resource_metadata(
    request: Request,
    resource: str | None = Query(default=None),
) -> dict[str, Any]:
    # Some hosted MCP clients discover OAuth metadata from the origin root
    # instead of the resource path. The optional resource query is accepted for
    # RFC 9728-style compatibility, but the only protected MCP resource served
    # by this router is the executive endpoint.
    del resource
    return build_oauth_protected_resource_metadata(_base_url(request))


@compatibility_router.get("/.well-known/oauth-authorization-server")
@compatibility_router.get("/.well-known/oauth-authorization-server/mcp/executive")
def executive_remote_mcp_root_authorization_server_metadata(request: Request) -> dict[str, Any]:
    return build_oauth_authorization_server_metadata(_base_url(request))


@router.post("/register")
async def executive_remote_mcp_register_client(request: Request) -> dict[str, Any]:
    payload = await _read_request_payload(request)
    client_name = _bounded_string(payload.get("client_name"), default="Claude executive connector", max_length=80)
    redirect_uris = payload.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        redirect_uris = ["http://localhost"]
    redirect_uris = [str(uri)[:512] for uri in redirect_uris[:10]]
    return {
        "client_id": _stable_client_id(client_name, redirect_uris),
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "client_id_issued_at": 0,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": f"{EXECUTIVE_REMOTE_MCP_SCOPE_READ} {EXECUTIVE_REMOTE_MCP_SCOPE_PRESENTATION}",
    }


@router.get("/authorize", response_class=HTMLResponse)
def executive_remote_mcp_authorize_page(
    request: Request,
    response_type: str = Query(default="code"),
    client_id: str = Query(default=""),
    redirect_uri: str = Query(default=""),
    state: str = Query(default=""),
    scope: str = Query(default=EXECUTIVE_REMOTE_MCP_SCOPE_READ),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
) -> HTMLResponse:
    if response_type != "code" or not redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported OAuth authorization request")
    hidden = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": _normalize_scope(scope),
        "code_challenge": code_challenge or "",
        "code_challenge_method": code_challenge_method or "",
    }
    return HTMLResponse(_authorization_html(hidden))


@router.post("/device_authorization")
async def executive_remote_mcp_device_authorization(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    payload = await _read_request_payload(request)
    scope = _normalize_scope(str(payload.get("scope") or EXECUTIVE_REMOTE_MCP_SCOPE_READ))
    client_id = _bounded_string(payload.get("client_id"), default="claude-device-client", max_length=255)
    device_code = secrets.token_urlsafe(48)
    user_code = _new_user_code()
    now = datetime.now(timezone.utc)
    record = ExecutiveMCPDeviceAuthorization(
        client_id=client_id,
        scope=scope,
        device_code_hash=_secret_hash(device_code),
        user_code_hash=_secret_hash(user_code),
        status="PENDING",
        expires_at=now + timedelta(minutes=_DEVICE_CODE_MINUTES),
    )
    db.add(record)
    db.commit()
    verification_uri = f"{_base_url(request)}/mcp/executive/device"
    return {
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": f"{verification_uri}?user_code={user_code}",
        "expires_in": _DEVICE_CODE_MINUTES * 60,
        "interval": _DEVICE_POLL_INTERVAL_SECONDS,
    }


@router.get("/device", response_class=HTMLResponse)
def executive_remote_mcp_device_page(user_code: str = Query(default="")) -> HTMLResponse:
    return HTMLResponse(_device_authorization_html(user_code))


@router.post("/device", response_class=HTMLResponse)
async def executive_remote_mcp_device_submit(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    form = await _read_form_body(request)
    user_code = form.get("user_code", "").strip().upper()
    email = form.get("email", "")
    password = form.get("password", "")
    tenant_id = form.get("tenant_id", "")
    if not user_code or not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing device authorization form fields")

    record = _get_pending_device_authorization(db, user_code=user_code)
    user = authenticate_user(db, email=email, password=password)
    ctx = _resolve_authorized_tenant_context(db, user=user, requested_tenant_id=tenant_id or None)
    now = datetime.now(timezone.utc)
    record.tenant_id = ctx.tenant.id
    record.user_id = user.id
    record.role = ctx.role
    record.status = "APPROVED"
    record.approved_at = now
    db.commit()
    return HTMLResponse(_device_authorized_html())


@router.post("/authorize")
async def executive_remote_mcp_authorize_submit(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    form = await _read_form_body(request)
    email = form.get("email", "")
    password = form.get("password", "")
    tenant_id = form.get("tenant_id", "")
    redirect_uri = form.get("redirect_uri", "")
    if not email or not password or not redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing authorization form fields")

    user = authenticate_user(db, email=email, password=password)
    ctx = _resolve_authorized_tenant_context(db, user=user, requested_tenant_id=tenant_id or None)
    scope = _normalize_scope(form.get("scope", EXECUTIVE_REMOTE_MCP_SCOPE_READ))
    code = create_token(
        subject=user.id,
        token_type="mcp_oauth_code",
        expires_delta=timedelta(minutes=_OAUTH_CODE_MINUTES),
        extra={
            "tenant_id": ctx.tenant.id,
            "role": ctx.role,
            "scope": scope,
            "redirect_uri": redirect_uri,
            "client_id": form.get("client_id", ""),
            "code_challenge": form.get("code_challenge", ""),
            "code_challenge_method": form.get("code_challenge_method", ""),
        },
    )
    params = {"code": code}
    if form.get("state"):
        params["state"] = form["state"]
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(params)}", status_code=status.HTTP_302_FOUND)


@router.post("/token")
async def executive_remote_mcp_token(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    payload = await _read_request_payload(request)
    grant_type = str(payload.get("grant_type") or "")
    if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        return _exchange_device_code(db, str(payload.get("device_code") or ""))
    if grant_type != "authorization_code":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported grant_type")
    code = str(payload.get("code") or "")
    redirect_uri = str(payload.get("redirect_uri") or "")
    if not code or not redirect_uri:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing authorization code or redirect_uri")
    try:
        code_payload = decode_token(code)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization code") from exc
    if code_payload.get("type") != "mcp_oauth_code":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization code type")
    if code_payload.get("redirect_uri") != redirect_uri:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization code redirect mismatch")
    _verify_pkce(code_payload, str(payload.get("code_verifier") or ""))

    user = _require_active_user(db, str(code_payload.get("sub") or ""))
    ctx = _resolve_authorized_tenant_context(
        db,
        user=user,
        requested_tenant_id=str(code_payload.get("tenant_id") or ""),
    )
    token_scope = _normalize_scope(str(code_payload.get("scope") or EXECUTIVE_REMOTE_MCP_SCOPE_READ))
    connector_token = _create_connector_token(user=user, ctx=ctx, scope=token_scope)
    return {
        "access_token": connector_token,
        "token_type": "Bearer",
        "expires_in": _CONNECTOR_TOKEN_MINUTES * 60,
        "scope": token_scope,
    }


@router.post("", response_model=None)
def executive_remote_mcp_rpc(
    payload: dict[str, Any] | list[Any],
    ctx: TenantContext = Depends(require_remote_mcp_context),
    db: Session = Depends(get_db),
) -> dict[str, Any] | Response:
    return _execute_remote_mcp_rpc(payload, ctx=ctx, db=db)


@router.post("/rpc", response_model=None)
def executive_remote_mcp_rpc_compat(
    payload: dict[str, Any] | list[Any],
    ctx: TenantContext = Depends(require_remote_mcp_context),
    db: Session = Depends(get_db),
) -> dict[str, Any] | Response:
    return _execute_remote_mcp_rpc(payload, ctx=ctx, db=db)


def _execute_remote_mcp_rpc(
    payload: dict[str, Any] | list[Any],
    *,
    ctx: TenantContext,
    db: Session,
) -> dict[str, Any] | Response:
    if isinstance(payload, list):
        return build_jsonrpc_error(None, -32600, "Batch MCP requests are not supported on this endpoint")

    try:
        request = RemoteMCPRequest.model_validate(payload)
    except ValidationError as exc:
        return build_jsonrpc_error(
            payload.get("id") if isinstance(payload, dict) else None,
            -32600,
            "Invalid JSON-RPC request",
            {"errors": exc.errors()},
        )

    if request.jsonrpc != "2.0":
        return build_jsonrpc_error(request.id, -32600, "Only JSON-RPC 2.0 is supported")

    if request.method == "notifications/initialized":
        return Response(status_code=202)

    if request.method == "initialize":
        _audit_remote_mcp_call(db, ctx, method=request.method)
        db.commit()
        return build_jsonrpc_result(request.id, build_initialize_result())

    if request.method == "tools/list":
        _audit_remote_mcp_call(db, ctx, method=request.method)
        db.commit()
        return build_jsonrpc_result(request.id, build_tools_list_result())

    if request.method == "tools/call":
        return _handle_tool_call(request, ctx=ctx, db=db)

    return build_jsonrpc_error(request.id, -32601, "Method not found")


def _handle_tool_call(request: RemoteMCPRequest, *, ctx: TenantContext, db: Session) -> dict[str, Any]:
    params = request.params or {}
    tool_name = str(params.get("name") or "")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return build_jsonrpc_error(request.id, -32602, "Tool arguments must be an object")

    try:
        result = _execute_tool(tool_name, arguments, ctx=ctx, db=db)
    except ValueError as exc:
        return build_jsonrpc_error(request.id, -32602, str(exc))

    _audit_remote_mcp_call(
        db,
        ctx,
        method=request.method,
        tool_name=tool_name,
        arguments=_bounded_audit_arguments(arguments),
    )
    db.commit()
    return build_jsonrpc_result(
        request.id,
        build_tool_call_result(jsonable_encoder(result)),
    )


def _execute_tool(tool_name: str, arguments: dict[str, Any], *, ctx: TenantContext, db: Session) -> dict[str, Any]:
    if tool_name == "get_executive_summary":
        return build_executive_mcp_summary(
            db,
            tenant_id=ctx.tenant.id,
            role=ctx.role,
            window_days=_bounded_int(arguments.get("window_days"), default=30, minimum=1, maximum=366),
        )

    if tool_name == "query_executive_metrics":
        metric = str(arguments.get("metric") or "")
        if metric not in _QUERY_METRICS:
            raise ValueError("query_executive_metrics requires a supported metric")
        return query_executive_mcp_metrics(
            db,
            tenant_id=ctx.tenant.id,
            role=ctx.role,
            query=ExecutiveQuery(
                metric=metric,  # type: ignore[arg-type]
                window_days=_bounded_int(arguments.get("window_days"), default=30, minimum=1, maximum=366),
                group_by=_optional_string(arguments.get("group_by"), max_length=64),
                limit=_bounded_int(arguments.get("limit"), default=10, minimum=1, maximum=100),
                include_named_users=bool(arguments.get("include_named_users", False)),
            ),
        )

    if tool_name == "create_executive_presentation":
        return create_executive_mcp_presentation(
            db,
            tenant_id=ctx.tenant.id,
            role=ctx.role,
            title=_bounded_string(arguments.get("title"), default="Executive AI Governance Brief", max_length=120),
            window_days=_bounded_int(arguments.get("window_days"), default=30, minimum=1, maximum=366),
        )

    raise ValueError(f"Unknown executive MCP tool: {tool_name}")


def _audit_remote_mcp_call(
    db: Session,
    ctx: TenantContext,
    *,
    method: str,
    tool_name: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="executive_mcp.remote.call",
        resource_type="executive_remote_mcp",
        resource_id=tool_name or method,
        payload={
            "method": method,
            "tool": tool_name,
            "arguments": arguments or {},
            "raw_prompt_content_included": False,
        },
    )


def _bounded_audit_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key in ("metric", "group_by", "window_days", "limit", "include_named_users", "title"):
        if key in arguments:
            safe[key] = arguments[key]
    return safe


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        integer = default
    return max(minimum, min(integer, maximum))


def _optional_string(value: Any, *, max_length: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:max_length] or None


def _bounded_string(value: Any, *, default: str, max_length: int) -> str:
    text = str(value or "").strip()
    return (text or default)[:max_length]


def _base_url(request: Request) -> str:
    configured = str(settings.api_base_url or "").strip().rstrip("/")
    if configured:
        return configured

    forwarded_proto = str(request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    forwarded_host = str(request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    if forwarded_proto and forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}".rstrip("/")

    return str(request.base_url).rstrip("/")


async def _read_request_payload(request: Request) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        payload = await request.json()
        return payload if isinstance(payload, dict) else {}
    return await _read_form_body(request)


async def _read_form_body(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8")
    parsed = parse_qs(raw, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def _stable_client_id(client_name: str, redirect_uris: list[str]) -> str:
    seed = f"{client_name}\n{','.join(redirect_uris)}"
    return "trinya_exec_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _normalize_scope(scope: str) -> str:
    allowed = {EXECUTIVE_REMOTE_MCP_SCOPE_READ, EXECUTIVE_REMOTE_MCP_SCOPE_PRESENTATION}
    requested = {part for part in str(scope or "").split() if part in allowed}
    requested.add(EXECUTIVE_REMOTE_MCP_SCOPE_READ)
    return " ".join(sorted(requested))


def _authorization_html(hidden: dict[str, str]) -> str:
    hidden_inputs = "\n".join(
        f'<input type="hidden" name="{escape(key)}" value="{escape(value)}" />' for key, value in hidden.items()
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize Trinya Executive MCP</title>
  <style>
    body {{ font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #071019; color: #eef6ff; }}
    main {{ max-width: 520px; margin: 8vh auto; padding: 32px; border: 1px solid #203040; border-radius: 18px; background: #0d1724; }}
    label {{ display: block; margin-top: 16px; color: #a9b8c9; font-size: 14px; }}
    input {{ box-sizing: border-box; width: 100%; margin-top: 6px; padding: 12px; border-radius: 10px; border: 1px solid #2f4358; background: #071019; color: #eef6ff; }}
    button {{ margin-top: 24px; width: 100%; padding: 12px; border: 0; border-radius: 10px; background: #ff7a18; color: #111827; font-weight: 700; }}
    p {{ color: #a9b8c9; line-height: 1.45; }}
    code {{ color: #70e1f5; }}
  </style>
</head>
<body>
  <main>
    <h1>Connect Executive MCP</h1>
    <p>This grants a short-lived, tenant-scoped connector token for executive summaries, metrics, and presentation generation. Raw prompt content is not exposed.</p>
    <form method="post" action="/mcp/executive/authorize">
      {hidden_inputs}
      <label>Email<input name="email" type="email" autocomplete="username" required /></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
      <label>Tenant ID <span style="color:#7f8ea3">(optional if your user has one tenant)</span><input name="tenant_id" placeholder="5043d9f6-..." /></label>
      <button type="submit">Authorize connector</button>
    </form>
  </main>
</body>
</html>"""


def _device_authorization_html(user_code: str) -> str:
    safe_user_code = escape(user_code.strip().upper())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize Trinya Executive MCP Device</title>
  <style>
    body {{ font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #071019; color: #eef6ff; }}
    main {{ max-width: 520px; margin: 8vh auto; padding: 32px; border: 1px solid #203040; border-radius: 18px; background: #0d1724; }}
    label {{ display: block; margin-top: 16px; color: #a9b8c9; font-size: 14px; }}
    input {{ box-sizing: border-box; width: 100%; margin-top: 6px; padding: 12px; border-radius: 10px; border: 1px solid #2f4358; background: #071019; color: #eef6ff; }}
    button {{ margin-top: 24px; width: 100%; padding: 12px; border: 0; border-radius: 10px; background: #ff7a18; color: #111827; font-weight: 700; }}
    p {{ color: #a9b8c9; line-height: 1.45; }}
  </style>
</head>
<body>
  <main>
    <h1>Authorize Executive MCP device</h1>
    <p>Enter the code shown by Claude or Codex. This grants a short-lived, tenant-scoped executive connector token.</p>
    <form method="post" action="/mcp/executive/device">
      <label>Device code<input name="user_code" value="{safe_user_code}" required /></label>
      <label>Email<input name="email" type="email" autocomplete="username" required /></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
      <label>Tenant ID <span style="color:#7f8ea3">(optional if your user has one tenant)</span><input name="tenant_id" placeholder="5043d9f6-..." /></label>
      <button type="submit">Authorize device</button>
    </form>
  </main>
</body>
</html>"""


def _device_authorized_html() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><title>Device authorized</title>
<style>body{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#071019;color:#eef6ff;margin:0}main{max-width:520px;margin:12vh auto;padding:32px;border:1px solid #203040;border-radius:18px;background:#0d1724}p{color:#a9b8c9}</style>
</head><body><main><h1>Connector authorized</h1><p>You can return to Claude or Codex. The connector token is short-lived and tenant-scoped.</p></main></body></html>"""


def _require_active_user(db: Session, user_id: str) -> User:
    user = db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive or not found")
    return user


def _resolve_authorized_tenant_context(
    db: Session,
    *,
    user: User,
    requested_tenant_id: str | None,
    token_role: str | None = None,
) -> TenantContext:
    membership_query = select(UserTenantRole).where(UserTenantRole.user_id == user.id)
    if requested_tenant_id:
        membership_query = membership_query.where(UserTenantRole.tenant_id == requested_tenant_id)
    memberships = db.scalars(membership_query).all()
    if not memberships:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant membership not found")
    if len(memberships) > 1 and not requested_tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tenant ID is required for users with multiple tenants")
    membership = memberships[0]
    effective_role = _lower_role(membership.role, token_role)
    if ROLE_ORDER.get(effective_role, -1) < ROLE_ORDER.get("viewer", 99):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    tenant = db.scalar(select(Tenant).where(Tenant.id == membership.tenant_id))
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    if not tenant.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant is inactive")
    return TenantContext(tenant=tenant, role=effective_role, user=user)


def _lower_role(actual_role: str, token_role: str | None) -> str:
    if not token_role:
        return actual_role
    return actual_role if ROLE_ORDER.get(actual_role, -1) <= ROLE_ORDER.get(token_role, -1) else token_role


def _create_connector_token(*, user: User, ctx: TenantContext, scope: str) -> str:
    return create_token(
        subject=user.id,
        token_type="mcp_connector",
        expires_delta=timedelta(minutes=_CONNECTOR_TOKEN_MINUTES),
        extra={
            "tenant_id": ctx.tenant.id,
            "role": ctx.role,
            "scope": _normalize_scope(scope),
            "connector": "executive_remote_mcp",
        },
    )


def _verify_pkce(code_payload: dict[str, Any], code_verifier: str) -> None:
    challenge = str(code_payload.get("code_challenge") or "")
    method = str(code_payload.get("code_challenge_method") or "")
    if not challenge:
        return
    if not code_verifier:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing PKCE verifier")
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    elif method in {"plain", ""}:
        computed = code_verifier
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported PKCE method")
    if computed != challenge:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid PKCE verifier")


def _new_user_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(2))


def _secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _get_pending_device_authorization(db: Session, *, user_code: str) -> ExecutiveMCPDeviceAuthorization:
    record = db.scalar(
        select(ExecutiveMCPDeviceAuthorization).where(
            ExecutiveMCPDeviceAuthorization.user_code_hash == _secret_hash(user_code),
        )
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device code not found")
    now = datetime.now(timezone.utc)
    if _as_utc(record.expires_at) < now:
        record.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device code expired")
    if record.status != "PENDING":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device code is not pending")
    return record


def _exchange_device_code(db: Session, device_code: str) -> dict[str, Any]:
    if not device_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing device_code")
    record = db.scalar(
        select(ExecutiveMCPDeviceAuthorization).where(
            ExecutiveMCPDeviceAuthorization.device_code_hash == _secret_hash(device_code),
        )
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device_code")
    now = datetime.now(timezone.utc)
    if _as_utc(record.expires_at) < now:
        record.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "expired_token"})
    if record.status == "PENDING":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "authorization_pending"})
    if record.status != "APPROVED" or record.consumed_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "access_denied"})
    if not record.user_id or not record.tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "access_denied"})

    user = _require_active_user(db, record.user_id)
    ctx = _resolve_authorized_tenant_context(
        db,
        user=user,
        requested_tenant_id=record.tenant_id,
        token_role=record.role,
    )
    connector_token = _create_connector_token(user=user, ctx=ctx, scope=record.scope)
    record.consumed_at = now
    record.status = "CONSUMED"
    db.commit()
    return {
        "access_token": connector_token,
        "token_type": "Bearer",
        "expires_in": _CONNECTOR_TOKEN_MINUTES * 60,
        "scope": _normalize_scope(record.scope),
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
