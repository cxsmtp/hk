"""The licence gate (app/services/activation_service.py, /settings/guide/licence).

Once an installation's 3-day trial is over without a licence, or its licence has expired, Hawk AI stops: every
request is refused with the message that it has been deactivated, and the console shows the deactivation page,
where an owner or admin of the installation signs in and imports a ``.hawkai`` licence file. Only the health
checks, the licence routes, first-run setup and signing in stay open (a token got this way reaches nothing else).
Nothing is deleted.
"""

from __future__ import annotations

from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.services import activation_service


LICENCE_OPEN = frozenset(
    {
        "/health",
        "/health/live",
        "/health/ready",
        "/health/schema",
        "/licence",
        "/licence/status",
        "/licence/request",
        "/licence/import",
        # First-run setup (app/api/routers/access.py): an installation nobody has set up yet can still be.
        "/setup",
        # Signing in, so an owner or admin can import a licence on the deactivation page.
        "/auth/login",
        "/auth/two-step",
        "/auth/refresh",
        "/auth/refresh/sign-out",
        "/auth/sign-in-options",
    }
)


def deactivated_response() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": activation_service.DEACTIVATED_MESSAGE, "deactivated": True},
        headers={"Cache-Control": "no-store"},
    )


async def licence_gate(request, call_next):
    # Let's Encrypt's check (app/api/routers/https.py) stays answered, so a renewal never fails on the licence.
    if request.url.path in LICENCE_OPEN or request.url.path.startswith("/.well-known/acme-challenge/"):
        return await call_next(request)
    if await run_in_threadpool(activation_service.licence_active):
        return await call_next(request)
    return deactivated_response()
