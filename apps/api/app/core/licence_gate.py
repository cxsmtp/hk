"""The licence gate (app/services/activation_service.py, /settings/guide/licence).

After the end of 31 January 2027 (UTC), or a product code's date if later, Hawk AI stops: every request is refused
with the message that it has been deactivated, and the console shows the deactivation page with a field for the
activation code. Only the health checks, the licence itself and the route that takes a code stay open. Nothing is
deleted.
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
        "/licence/activate",
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
