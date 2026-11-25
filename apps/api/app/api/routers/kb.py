from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.auth import get_current_user
from app.core.observability import get_correlation_id
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.knowledge_base import KBControl, KBFramework
from app.db.models.user import User
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.brain.rag.retriever import retrieve_knowledge_bundle
from app.services.evidence_service import create_evidence_node


router = APIRouter(prefix="/kb", tags=["kb"])


class KBFrameworkDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    version: str
    source_type: str
    created_at: datetime


class KBControlDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    framework_id: str
    title: str
    objective: str
    requirement_level: str
    applicability_tags: list[Any]
    created_at: datetime


class KBSearchRequest(BaseModel):
    question: str
    ai_system_id: str | None = None
    frameworks_in_scope: list[str] = Field(default_factory=list)


class KBSearchResponse(BaseModel):
    top_controls: list[str]
    top_guardian_contracts: list[str]
    top_sim_templates: list[str]
    top_docs: list[str]
    evidence_hooks: list[dict[str, Any]]


@router.get("/frameworks", response_model=ListEnvelope[KBFrameworkDTO])
def list_frameworks(
    page: int = 1,
    page_size: int = 50,
    _ctx: TenantContext = Depends(require_permission("assistant.use")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(KBFramework).order_by(KBFramework.name.asc(), KBFramework.version.asc())).all()
    dto_rows = [KBFrameworkDTO.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[KBFrameworkDTO](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/controls", response_model=ListEnvelope[KBControlDTO])
def list_controls(
    framework: str | None = Query(default=None),
    page: int = 1,
    page_size: int = 50,
    _ctx: TenantContext = Depends(require_permission("assistant.use")),
    db: Session = Depends(get_db),
):
    query = select(KBControl).order_by(KBControl.id.asc())
    if framework and framework.strip():
        key = framework.strip().lower()
        framework_ids = db.scalars(
            select(KBFramework.id).where(
                (KBFramework.id == framework.strip()) | (func.lower(KBFramework.name) == key)
            )
        ).all()
        if not framework_ids:
            return ListEnvelope[KBControlDTO](items=[], total=0, page=max(1, page), page_size=max(1, page_size))
        query = query.where(KBControl.framework_id.in_(framework_ids))

    rows = db.scalars(query).all()
    dto_rows = [KBControlDTO.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[KBControlDTO](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.post("/search", response_model=KBSearchResponse)
def kb_search(
    payload: KBSearchRequest,
    request: Request,
    ctx: TenantContext = Depends(require_permission("assistant.use")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not payload.question.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="question is required")

    retrieval = retrieve_knowledge_bundle(
        db,
        question=payload.question,
        tenant_id=ctx.tenant.id,
        ai_system_id=payload.ai_system_id,
        frameworks_in_scope=payload.frameworks_in_scope,
    )

    result = KBSearchResponse(
        top_controls=[str(row.get("control_id")) for row in retrieval.get("top_controls", []) if row.get("control_id")],
        top_guardian_contracts=[
            str(row.get("guardian_contract_id"))
            for row in retrieval.get("top_guardian_contracts", [])
            if row.get("guardian_contract_id")
        ],
        top_sim_templates=[
            str(row.get("simulation_template_id"))
            for row in retrieval.get("top_sim_templates", [])
            if row.get("simulation_template_id")
        ],
        top_docs=[str(row.get("doc_id")) for row in retrieval.get("top_docs", []) if row.get("doc_id")],
        evidence_hooks=[hook for hook in retrieval.get("evidence_hooks", []) if isinstance(hook, dict)],
    )

    correlation_id = getattr(request.state, "correlation_id", None) or get_correlation_id() or "unknown"
    question_hash = hashlib.sha256(payload.question.encode("utf-8")).hexdigest()
    try:
        audit = write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            actor_type="human",
            action="kb.search",
            resource_type="knowledge_base",
            resource_id=question_hash,
            payload={
                "question_hash": question_hash,
                "frameworks_in_scope": payload.frameworks_in_scope,
                "top_controls": result.top_controls,
                "top_guardian_contracts": result.top_guardian_contracts,
                "top_sim_templates": result.top_sim_templates,
                "top_docs": result.top_docs,
                "correlation_id": correlation_id,
            },
            correlation_id=correlation_id,
        )
        create_evidence_node(
            db,
            tenant_id=ctx.tenant.id,
            node_type="kb_search",
            signal_type="kb.search",
            label="Knowledge base retrieval executed",
            payload={
                "question_hash": question_hash,
                "retrieved_ids": {
                    "controls": result.top_controls,
                    "guardians": result.top_guardian_contracts,
                    "sim_templates": result.top_sim_templates,
                    "docs": result.top_docs,
                },
                "evidence_hooks": result.evidence_hooks,
                "correlation_id": correlation_id,
                "audit_log_id": audit.id,
            },
            correlation_id=correlation_id,
        )
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to persist kb.search audit/evidence: {exc}") from exc

    return result
