from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps_control_plane import require_control_plane_healthy
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.ai_iam import AgentIdentity
from app.db.session import get_db
from app.services.fail_secure_service import enforce_fail_secure_or_raise


router = APIRouter(
    prefix="/agents",
    tags=["agents"],
    dependencies=[Depends(require_control_plane_healthy(module="ai_iam"))],
)


class AgentDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: str
    status: str
    owner_attested_at: datetime | None = None
    owner_attestation_expiry: datetime | None = None
    max_chain_depth: int
    capability_inheritance: bool
    action_scope: list[str]
    tool_registry: list[str]
    external_system_access: list[str]
    agent_type: str
    autonomy_level: str


@router.get("/{agent_id}", response_model=AgentDetailResponse)
def get_agent(
    agent_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"agents.get:{agent_id}",
    )
    row = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return AgentDetailResponse.model_validate(row)
