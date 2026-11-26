from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.control_graph_service import (
    build_runtime_control_view,
    build_simulation_control_view,
    list_control_explorer,
)
from app.services.deployment_coverage_service import get_deployment_coverage
from app.services.enterprise_developer_ai_control import build_enterprise_developer_ai_control_from_db
from app.services.github_repository_access_service import (
    get_github_repository_detail,
    get_github_repository_detail_payload,
    bind_github_repository_runtime,
    list_github_runtime_bindings,
    list_github_ai_connections,
    list_github_developers,
    list_github_organizations,
    list_github_repositories,
    serialize_github_page,
    serialize_github_projection,
    issue_github_repository_mutation_approval,
    revoke_github_repository_mutation_approval,
    revoke_github_repository_runtime,
    save_github_repository_agent_policy,
    save_github_repository_operation_controls,
    update_github_repository_governance,
)
from app.services.simulation_template_service import get_control_coverage, get_framework_coverage
from app.services.tenant_default_seed_service import persist_tenant_canonical_controls


router = APIRouter(tags=["coverage"])


class DeploymentCoverageSurface(BaseModel):
    surface: str
    label: str
    covered: bool
    coverage_percent: float
    observed_event_count: int
    policy_enforced_count: int
    last_seen_at: datetime | None = None


class DeploymentCoveragePolicies(BaseModel):
    total_enforcement_events: int
    policy_bound_enforcement_events: int
    decision_counts: dict[str, int]


class DeploymentCoverageConnectorPosture(BaseModel):
    total_connectors: int
    enabled_connectors: int


class DeploymentCoverageResponse(BaseModel):
    tenant_id: str
    coverage_percent: float
    surfaces: list[DeploymentCoverageSurface]
    policies_enforced: DeploymentCoveragePolicies
    connector_posture: DeploymentCoverageConnectorPosture
    provider_catalog: dict[str, object] = Field(default_factory=dict)
    observed_surface_counts: dict[str, int] = Field(default_factory=dict)
    observed_provider_category_counts: dict[str, int] = Field(default_factory=dict)
    observed_provider_counts: dict[str, int] = Field(default_factory=dict)
    provider_surface_mode_counts: dict[str, dict[str, int]] = Field(default_factory=dict)
    provider_blind_spots_by_category: dict[str, list[str]] = Field(default_factory=dict)
    coverage_by_surface_type: dict[str, int] = Field(default_factory=dict)
    enforcement_capability: dict[str, object] = Field(default_factory=dict)
    gaps: list[str]


class ControlExplorerResponse(BaseModel):
    tenant_id: str
    foundation_only: bool = True
    foundation_control_ids: list[str] = Field(default_factory=list)
    framework_catalog: list[dict[str, str]]
    legacy_aliases: dict[str, str]
    total_controls: int
    category_counts: dict[str, int]
    framework_counts: dict[str, int]
    crq_summary: dict[str, float] = Field(default_factory=dict)
    controls: list[dict[str, object]]


class RuntimeControlViewResponse(BaseModel):
    tenant_id: str
    foundation_only: bool = True
    foundation_control_ids: list[str] = Field(default_factory=list)
    lookback_hours: int
    event_count: int
    control_count: int
    crq_summary: dict[str, float] = Field(default_factory=dict)
    controls: list[dict[str, object]]


class SimulationControlViewResponse(BaseModel):
    tenant_id: str
    foundation_only: bool = True
    foundation_control_ids: list[str] = Field(default_factory=list)
    control_count: int
    crq_summary: dict[str, float] = Field(default_factory=dict)
    controls: list[dict[str, object]]


class GitHubRepositoryGovernanceUpdate(BaseModel):
    decision: str = Field(pattern="^(APPROVED|UNAPPROVED)$")
    expected_governance_version: int = Field(ge=0)
    assignment_id: str | None = Field(default=None, max_length=64)
    deny_posture: Literal["BLOCK_CHANGES", "BLOCK_ALL"] | None = None


class GitHubRepositoryRuntimeBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(min_length=1, max_length=64)
    expected_governance_version: int = Field(ge=0)


class GitHubRepositoryOperationControlsUpdate(BaseModel):
    controls: dict[str, Literal["ALLOW", "BLOCK"]]
    expected_governance_version: int = Field(ge=0)


class GitHubRepositoryAgentPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: dict[str, object] = Field(default_factory=dict)
    expected_governance_version: int = Field(ge=0)


class GitHubRepositoryMutationApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval_request_id: str = Field(min_length=1, max_length=64)
    ttl_seconds: int = Field(default=900, ge=60, le=3600)


@router.get("/coverage", response_model=DeploymentCoverageResponse)
def deployment_coverage(
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    payload = get_deployment_coverage(
        db,
        tenant_id=ctx.tenant.id,
    )
    return DeploymentCoverageResponse.model_validate(payload)


@router.get("/control-coverage/source-control/github-repository-boundary")
def github_repository_boundary_control(
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    return build_enterprise_developer_ai_control_from_db(db, tenant_id=ctx.tenant.id)


@router.get("/control-coverage/source-control/github-repositories/organizations")
def github_repository_organizations(
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=32),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    return serialize_github_page(list_github_organizations(db, tenant_id=ctx.tenant.id, limit=limit, cursor=cursor))


@router.get("/control-coverage/source-control/github-repositories/repositories")
def github_repositories(
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=32),
    visibility: str | None = Query(default=None, max_length=32),
    host: str | None = Query(default=None, max_length=255),
    source_organization_id: str | None = Query(default=None, max_length=64),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    filters = {key: value for key, value in {"visibility": visibility, "host": host, "source_organization_id": source_organization_id}.items() if value}
    return serialize_github_page(list_github_repositories(db, tenant_id=ctx.tenant.id, limit=limit, cursor=cursor, filters=filters or None))


@router.get("/control-coverage/source-control/github-repositories/repositories/{repository_id}")
def github_repository_detail(
    repository_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    try:
        return get_github_repository_detail_payload(db, tenant_id=ctx.tenant.id, repository_id=repository_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="GitHub repository is not available in this tenant") from exc


@router.put("/control-coverage/source-control/github-repositories/repositories/{repository_id}/governance")
def update_github_repository_governance_route(
    repository_id: str,
    body: GitHubRepositoryGovernanceUpdate,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
):
    try:
        repository = update_github_repository_governance(
            db,
            tenant_id=ctx.tenant.id,
            repository_id=repository_id,
            decision=body.decision,
            expected_governance_version=body.expected_governance_version,
            assignment_id=body.assignment_id,
            actor_user_id=ctx.user.id if ctx.user else None,
            deny_posture=body.deny_posture,
        )
        db.commit()
        return serialize_github_projection(repository)
    except ValueError as exc:
        db.rollback()
        detail = str(exc)
        status_code = status.HTTP_409_CONFLICT if detail == "governance version conflict" else status.HTTP_422_UNPROCESSABLE_ENTITY
        raise HTTPException(status_code=status_code, detail=detail) from exc


@router.get("/control-coverage/source-control/github-repositories/runtime-bindings")
def github_repository_runtime_bindings(
    repository_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=200),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    return list_github_runtime_bindings(db, tenant_id=ctx.tenant.id, repository_id=repository_id, limit=limit)


@router.put("/control-coverage/source-control/github-repositories/repositories/{repository_id}/runtime-binding")
def bind_github_repository_runtime_route(
    repository_id: str,
    body: GitHubRepositoryRuntimeBindingRequest,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
):
    try:
        binding = bind_github_repository_runtime(db, tenant_id=ctx.tenant.id, repository_id=repository_id, observation_id=body.observation_id, actor_id=ctx.user.id if ctx.user else None, expected_governance_version=body.expected_governance_version)
        db.commit()
        return serialize_github_projection(binding)
    except ValueError as exc:
        db.rollback()
        detail = str(exc)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT if detail == "governance version conflict" else status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail) from exc


@router.delete("/control-coverage/source-control/github-repositories/runtime-bindings/{binding_id}")
def revoke_github_repository_runtime_route(
    binding_id: str,
    expected_governance_version: int = Query(ge=0),
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
):
    try:
        binding = revoke_github_repository_runtime(db, tenant_id=ctx.tenant.id, binding_id=binding_id, expected_governance_version=expected_governance_version, actor_id=ctx.user.id if ctx.user else None)
        db.commit()
        return serialize_github_projection(binding)
    except ValueError as exc:
        db.rollback()
        detail = str(exc)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND if detail == "runtime binding not found" else status.HTTP_409_CONFLICT if detail == "governance version conflict" else status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail) from exc


@router.put("/control-coverage/source-control/github-repositories/repositories/{repository_id}/operation-controls")
def save_github_repository_operation_controls_route(
    repository_id: str,
    body: GitHubRepositoryOperationControlsUpdate,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
):
    try:
        repository = save_github_repository_operation_controls(db, tenant_id=ctx.tenant.id, repository_id=repository_id, controls=body.controls, expected_governance_version=body.expected_governance_version, actor_user_id=ctx.user.id if ctx.user else None)
        db.commit()
        return serialize_github_projection(repository)
    except ValueError as exc:
        db.rollback()
        detail = str(exc)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT if detail == "governance version conflict" else status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail) from exc


@router.put("/control-coverage/source-control/github-repositories/repositories/{repository_id}/agent-policy")
def save_github_repository_agent_policy_route(
    repository_id: str,
    body: GitHubRepositoryAgentPolicyUpdate,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
):
    try:
        repository = save_github_repository_agent_policy(db, tenant_id=ctx.tenant.id, repository_id=repository_id, policy=body.policy, expected_governance_version=body.expected_governance_version, actor_user_id=ctx.user.id if ctx.user else None)
        db.commit()
        return serialize_github_projection(repository)
    except ValueError as exc:
        db.rollback()
        detail = str(exc)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT if detail == "governance version conflict" else status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail) from exc


@router.post("/control-coverage/source-control/github-repositories/mutation-approvals")
def issue_github_repository_mutation_approval_route(
    body: GitHubRepositoryMutationApprovalRequest,
    # An approver surface, like the approval decision itself; the request's own
    # required roles are checked again in the service.
    ctx: TenantContext = Depends(require_permission("policies.operate")),
    db: Session = Depends(get_db),
):
    try:
        grant = issue_github_repository_mutation_approval(db, tenant_id=ctx.tenant.id, approval_request_id=body.approval_request_id, issued_by=ctx.user.id if ctx.user else None, approver_role=ctx.role, ttl_seconds=body.ttl_seconds)
        db.commit()
        return serialize_github_projection(grant)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        detail = str(exc)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND if detail == "approval request not found" else status.HTTP_409_CONFLICT, detail=detail) from exc


@router.delete("/control-coverage/source-control/github-repositories/mutation-approvals/{approval_binding_id}")
def revoke_github_repository_mutation_approval_route(
    approval_binding_id: str,
    ctx: TenantContext = Depends(require_permission("policies.operate")),
    db: Session = Depends(get_db),
):
    try:
        grant = revoke_github_repository_mutation_approval(db, tenant_id=ctx.tenant.id, approval_binding_id=approval_binding_id, actor_user_id=ctx.user.id if ctx.user else None)
        db.commit()
        return serialize_github_projection(grant)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/control-coverage/source-control/github-repositories/developers")
def github_repository_developers(
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=32),
    repository_id: str | None = Query(default=None, max_length=64),
    access_path: str | None = Query(default=None, max_length=32),
    principal_type: str | None = Query(default=None, max_length=32),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    filters = {key: value for key, value in {"repository_id": repository_id, "access_path": access_path, "principal_type": principal_type}.items() if value}
    return serialize_github_page(list_github_developers(db, tenant_id=ctx.tenant.id, limit=limit, cursor=cursor, filters=filters or None))


@router.get("/control-coverage/source-control/github-repositories/ai-connections")
def github_repository_ai_connections(
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=32),
    repository_id: str | None = Query(default=None, max_length=64),
    provider: str | None = Query(default=None, max_length=128),
    model: str | None = Query(default=None, max_length=255),
    agent_id: str | None = Query(default=None, max_length=255),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    filters = {key: value for key, value in {"repository_id": repository_id, "provider": provider, "model": model, "agent_id": agent_id}.items() if value}
    return serialize_github_page(list_github_ai_connections(db, tenant_id=ctx.tenant.id, limit=limit, cursor=cursor, filters=filters or None))


@router.get("/controls/{control_id}/coverage")
def control_coverage(
    control_id: str,
    trend_points: int = Query(default=20, ge=1, le=200),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_canonical_controls(db, tenant_id=ctx.tenant.id)
    try:
        return get_control_coverage(
            db,
            tenant_id=ctx.tenant.id,
            control_id=control_id,
            trend_points=trend_points,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/frameworks/{framework_name}/coverage")
def framework_coverage(
    framework_name: str,
    min_simulations: int = Query(default=1, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_canonical_controls(db, tenant_id=ctx.tenant.id)
    try:
        return get_framework_coverage(
            db,
            tenant_id=ctx.tenant.id,
            framework_name=framework_name,
            min_simulations=min_simulations,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/controls/explorer", response_model=ControlExplorerResponse)
def control_explorer(
    foundation_only: bool = Query(default=True),
    framework: str | None = Query(default=None),
    category: str | None = Query(default=None),
    enforcement_point: str | None = Query(default=None),
    risk_tag: str | None = Query(default=None),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_canonical_controls(db, tenant_id=ctx.tenant.id)
    payload = list_control_explorer(
        db,
        tenant_id=ctx.tenant.id,
        foundation_only=foundation_only,
        framework=framework,
        category=category,
        enforcement_point=enforcement_point,
        risk_tag=risk_tag,
    )
    return ControlExplorerResponse.model_validate(payload)


@router.get("/controls/runtime-view", response_model=RuntimeControlViewResponse)
def runtime_control_view(
    lookback_hours: int = Query(default=24, ge=1, le=24 * 30),
    foundation_only: bool = Query(default=True),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_canonical_controls(db, tenant_id=ctx.tenant.id)
    payload = build_runtime_control_view(
        db,
        tenant_id=ctx.tenant.id,
        lookback_hours=lookback_hours,
        foundation_only=foundation_only,
    )
    return RuntimeControlViewResponse.model_validate(payload)


@router.get("/controls/simulation-view", response_model=SimulationControlViewResponse)
def simulation_control_view(
    foundation_only: bool = Query(default=True),
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_canonical_controls(db, tenant_id=ctx.tenant.id)
    payload = build_simulation_control_view(
        db,
        tenant_id=ctx.tenant.id,
        foundation_only=foundation_only,
    )
    return SimulationControlViewResponse.model_validate(payload)
