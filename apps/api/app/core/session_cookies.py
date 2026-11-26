"""The console's sign-in in cookies, never in the browser's storage, where any script on the page could read it.

The console asks for it with the header ``X-Hawk-Session: cookie`` when signing in. The tokens then come back as
HttpOnly, SameSite=Strict cookies and are left out of the JSON body; every other client (the SDK, the MCP proxy, the
endpoint agent, the browser extension, scripts) sends no such header and keeps getting the tokens in the body and
signing its requests with ``Authorization: Bearer``, exactly as before.

- access token: ``__Host-hawk_access``, Path=/ (every API call; ``__Host-`` requires Path=/)
- refresh token: ``__Secure-hawk_refresh``, Path=<API prefix>/auth/refresh, so it goes nowhere but the refresh and
  sign-out endpoints (``__Host-`` would require Path=/, so it has the weaker ``__Secure-`` prefix)
- CSRF token: ``__Host-hawk_csrf``, readable by the console, which echoes it in ``X-CSRF-Token`` on every request that
  changes something (double submit: a page on another site can neither read the cookie nor set the header)

Over plain http (a developer's localhost, or an installation left in HTTP mode) the cookies cannot be Secure, so the
prefixes, which browsers only accept on Secure cookies, are dropped: ``hawk_access``, ``hawk_refresh``, ``hawk_csrf``.
An https request reads only the prefixed names, so a cookie planted over http or by a sibling host is never used.
"""

from __future__ import annotations

import hmac
import re
import secrets
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.config import settings


SESSION_HEADER = "X-Hawk-Session"
CSRF_HEADER = "X-CSRF-Token"
CSRF_REFUSED = "The request was refused (CSRF check). Reload the page and try again."
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_PREFIX = re.compile(r"^(/[A-Za-z0-9._~-]+){0,4}$")


def secure(request: Request) -> bool:
    # Behind the front proxy, uvicorn takes the scheme from X-Forwarded-Proto (--proxy-headers).
    return request.url.scheme == "https"


def access_name(request: Request) -> str:
    return "__Host-hawk_access" if secure(request) else "hawk_access"


def refresh_name(request: Request) -> str:
    return "__Secure-hawk_refresh" if secure(request) else "hawk_refresh"


def csrf_name(request: Request) -> str:
    return "__Host-hawk_csrf" if secure(request) else "hawk_csrf"


def _api_prefix(request: Request) -> str:
    """Where the browser reaches the API: the front proxy strips /api (deploy/compose.yaml) and says so in
    X-Forwarded-Prefix; otherwise the path of API_BASE_URL. Only the refresh cookie's Path depends on it."""

    for candidate in (request.headers.get("x-forwarded-prefix") or "", urlsplit(settings.api_base_url or "").path):
        candidate = candidate.strip().rstrip("/")
        if candidate and _PREFIX.match(candidate):
            return candidate
    return ""


def refresh_path(request: Request) -> str:
    return f"{_api_prefix(request)}/auth/refresh"


def access_cookie(request: Request) -> str:
    return request.cookies.get(access_name(request)) or ""


def refresh_cookie(request: Request) -> str:
    return request.cookies.get(refresh_name(request)) or ""


def wanted(request: Request) -> bool:
    """The console's session: asked for at sign-in, or the request itself came with the session cookies. Tokens from a
    cookie are never handed back in a body, where a script on the page could read them."""

    return (
        (request.headers.get(SESSION_HEADER) or "").strip().lower() == "cookie"
        or bool(getattr(request.state, "cookie_session", False))
    )


def require_csrf(request: Request) -> None:
    """Double submit, for a request signed in by cookie that changes something: the X-CSRF-Token header must equal the
    CSRF cookie. Bearer requests never come here: a browser does not add an Authorization header by itself."""

    if request.method.upper() in _SAFE_METHODS:
        return
    cookie = request.cookies.get(csrf_name(request)) or ""
    header = request.headers.get(CSRF_HEADER) or ""
    if not cookie or not header or not hmac.compare_digest(cookie.encode("utf-8"), header.encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=CSRF_REFUSED)


def _set(response: Response, request: Request, name: str, value: str, *, max_age: int, path: str, httponly: bool) -> None:
    response.set_cookie(name, value, max_age=max_age, path=path, secure=secure(request), httponly=httponly, samesite="strict")


def deliver(request: Request, response: Response, tokens: dict[str, Any], *, keep_csrf: bool = False) -> dict[str, Any]:
    """For the console's session: the tokens as cookies on ``response``, and the body without them. For anyone else
    ``tokens`` unchanged. ``keep_csrf`` (a refresh): the CSRF token stays the same, so requests already on their way
    from other tabs are not refused for carrying the one before."""

    if not wanted(request):
        return tokens
    access_seconds = max(60, int(settings.access_token_expire_minutes) * 60)
    refresh_seconds = max(60, int(settings.refresh_token_expire_minutes) * 60)
    csrf = request.cookies.get(csrf_name(request)) if keep_csrf else ""
    csrf = csrf or secrets.token_urlsafe(32)
    _set(response, request, access_name(request), str(tokens.get("access_token") or ""), max_age=access_seconds, path="/", httponly=True)
    _set(response, request, refresh_name(request), str(tokens.get("refresh_token") or ""), max_age=refresh_seconds, path=refresh_path(request), httponly=True)
    _set(response, request, csrf_name(request), csrf, max_age=refresh_seconds, path="/", httponly=False)
    response.headers["Cache-Control"] = "no-store"
    return {**tokens, "access_token": "", "refresh_token": ""}


def answer(request: Request, content: dict[str, Any], status_code: int = 200) -> JSONResponse:
    """``deliver`` for a route that answers with a JSONResponse of its own (never cached: it may hold tokens)."""

    out = JSONResponse(status_code=status_code, content={}, headers={"Cache-Control": "no-store"})
    body = deliver(request, out, content)
    out.body = out.render(body)
    out.headers["content-length"] = str(len(out.body))
    return out


def clear(request: Request, response: Response) -> None:
    for name, path in ((access_name(request), "/"), (refresh_name(request), refresh_path(request)), (csrf_name(request), "/")):
        response.delete_cookie(name, path=path, secure=secure(request), httponly=name != csrf_name(request), samesite="strict")
