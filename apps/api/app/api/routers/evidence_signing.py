"""Evidence signing (app/services/evidence_signing.py): the key that signs the evidence Hawk AI hands to auditors, its
public keys, a check of a signature, and a rotation.

- GET  /evidence-signing: the backend, the key that signs (key id = fingerprint) and the retired keys (evidence.view).
- GET  /evidence-signing/keys: every public key ever used, current and retired (evidence.view).
- POST /evidence-signing/verify: check signed evidence: a JSON document with its ``evidence_signature``, or bytes with
  a detached signature (evidence.export, "Verify and export evidence").
- POST /evidence-signing/rotate: a new signing key; old public keys stay published (settings.manage: owners, admins).
- GET  /.well-known/hawk-evidence-keys.json: the public keys, for anyone (they are public), so an auditor can fetch
  them without an account; the front proxy passes this path to the API (app/services/https_proxy.py).
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.installation import is_installation_admin, require_installation_admin
from app.core.rbac import holds, require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services import evidence_signing
from app.services.audit_service import write_audit_log

router = APIRouter(tags=["evidence-signing"])

#: The largest content a verify request may carry (base64 of up to 10 MB).
MAX_VERIFY_BYTES = 10 * 1024 * 1024


class VerifyRequest(BaseModel):
    document: dict[str, Any] | None = Field(default=None, description="A signed JSON document (with evidence_signature).")
    content_base64: str | None = Field(default=None, description="The exact bytes of a file, base64.")
    signature: dict[str, Any] | str | None = Field(default=None, description="The detached signature: the .sig.json envelope, or the X-Hawk-Evidence-Signature header value.")


def _error(error: evidence_signing.EvidenceSigningError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={"code": "evidence_signing_unavailable", "message": str(error)})


@router.get("/evidence-signing")
def signing_status(ctx: TenantContext = Depends(require_permission("evidence.view")), db: Session = Depends(get_db)) -> dict[str, Any]:
    out = evidence_signing.service().status()
    # One signing key for the whole server: only its administrators rotate it (app/core/installation.py).
    return {**out, "can_rotate": holds(ctx, "settings.manage") and is_installation_admin(db, ctx)}


@router.get("/evidence-signing/keys")
async def signing_keys(ctx: TenantContext = Depends(require_permission("evidence.view"))) -> dict[str, Any]:  # noqa: ARG001
    try:
        return await run_in_threadpool(lambda: evidence_signing.service().public_keys())
    except evidence_signing.EvidenceSigningError as error:
        raise _error(error) from error


@router.get(evidence_signing.WELL_KNOWN_PATH, include_in_schema=False)
async def well_known_keys() -> JSONResponse:
    try:
        keys = await run_in_threadpool(lambda: evidence_signing.service().public_keys())
    except evidence_signing.EvidenceSigningError:
        return JSONResponse({"detail": "The evidence signing keys cannot be read right now."}, status_code=503)
    return JSONResponse(keys, headers={"Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*"})


@router.post("/evidence-signing/verify")
def verify(body: VerifyRequest, ctx: TenantContext = Depends(require_permission("evidence.export"))) -> dict[str, Any]:  # noqa: ARG001
    signing = evidence_signing.service()
    try:
        if body.document is not None:
            return signing.verify_document(body.document)
        if body.content_base64 is None or body.signature is None:
            raise HTTPException(status_code=422, detail="Give a signed JSON document, or the file's content (base64) with its signature.")
        if len(body.content_base64) > MAX_VERIFY_BYTES * 4 // 3 + 4:
            raise HTTPException(status_code=413, detail="That file is too large to check here (10 MB at most); check it offline with tools/verify_evidence.py.")
        try:
            content = base64.b64decode(body.content_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise HTTPException(status_code=422, detail="content_base64 is not base64.") from error
        try:
            envelope = evidence_signing.decode_header(body.signature) if isinstance(body.signature, str) else body.signature
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return signing.verify(envelope, data=content)
    except evidence_signing.EvidenceSigningError as error:
        raise _error(error) from error


@router.post("/evidence-signing/rotate")
def rotate(ctx: TenantContext = Depends(require_installation_admin("settings.manage")), db: Session = Depends(get_db)) -> dict[str, Any]:
    signing = evidence_signing.service()
    try:
        result = signing.rotate()
    except evidence_signing.EvidenceSigningError as error:
        raise _error(error) from error
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human" if ctx.user else "system",
        action="evidence_signing.rotated" if result["rotated"] else "evidence_signing.rotate_unchanged",
        resource_type="evidence_signing_key",
        resource_id=str(result["active"])[:64],
        payload={
            "outcome": "info",
            "reason": "Rotated the evidence signing key; the previous public key stays published." if result["rotated"] else "The configured signing key is unchanged: rotate it in the key service (a new key or version), then rotate here.",
            "previous": result["previous"],
            "active": result["active"],
        },
    )
    db.commit()
    return {**result, "status": {**signing.status(), "can_rotate": True}}
