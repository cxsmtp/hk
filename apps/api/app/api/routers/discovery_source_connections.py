"""Tenant-scoped setup for HMAIR customer-owned source prerequisites."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.api.routers.discovery_scans import require_hmair_core
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.hmair.source_connectors.contracts import (
    HMAIRSourceCapability,
    HMAIRSourceConnectionInput,
)
from app.services.hmair.source_connectors.service import (
    HMAIRSourceConnectionRecord,
    get_source_connection,
    list_source_connections,
    provision_source_connection,
    validate_source_connection,
)


class SourceConnectionTargetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    target_type: str
    environment: str


class SourceConnectionCollectorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    collector_type: str
    health: str


class SourceConnectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connection_id: str
    provider_key: str
    display_name: str
    status: str
    account_scope_kind: Literal["ORGANIZATION", "PERSONAL", "UNKNOWN"] = "UNKNOWN"
    target: SourceConnectionTargetResponse
    collector: SourceConnectionCollectorResponse
    capability: HMAIRSourceCapability


class SourceConnectionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SourceConnectionResponse]
    total: int


class SourceConnectionSetupFlowResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: Literal["github", "m365_teams", "identity", "saas", "cloud"]
    title: str
    summary: str
    entrypoint_href: str
    provider_keys: list[str]
    visibility: list[str]
    required_authority: list[str]
    credential_requirements: list[str]
    validation_mode: str
    limitations: list[str]
    status: Literal["setup_required"]


class SourceConnectionSetupCatalogResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SourceConnectionSetupFlowResponse]
    total: int


class EnterpriseDenominatorItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: Literal[
        "users",
        "devices",
        "browser",
        "repositories",
        "saas_apps",
        "cloud_runtimes",
        "models",
    ]
    label: str
    state: Literal["authoritative", "partial", "observed_only", "missing"]
    authoritative: bool
    required_source_family: Literal["github", "m365_teams", "identity", "saas", "cloud"] | None
    required_source_title: str | None
    connect_href: str
    denominator: int | None
    connection_count: int
    fresh_at: str | None
    evidence: list[str]
    next_action: str
    limitation: str


class EnterpriseDenominatorStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall_state: Literal[
        "authoritative",
        "partial_authority",
        "observed_only",
        "missing_authoritative_sources",
    ]
    authoritative_denominator_complete: bool
    authoritative_count: int
    total_domains: int
    items: list[EnterpriseDenominatorItemResponse]
    how_to_get_full_authority: list[str]


router = APIRouter(
    prefix="/discovery/source-connections",
    tags=["discovery"],
)


def _domain_flow(
    family: Literal["github", "m365_teams", "identity", "saas", "cloud"] | None,
) -> SourceConnectionSetupFlowResponse | None:
    if family is None:
        return None
    return next((item for item in SOURCE_CONNECTION_SETUP_CATALOG if item.family == family), None)


def _connection_authority(
    records: tuple[HMAIRSourceConnectionRecord, ...],
    *,
    provider_keys: set[str],
) -> tuple[str, bool, int | None, int, str | None, list[str]]:
    """Summarize source authority without promoting observation into coverage."""

    matched = tuple(row for row in records if row.connector.provider_key in provider_keys)
    if not matched:
        return "missing", False, None, 0, None, []

    denominator = sum(
        int(row.capability.denominator)
        for row in matched
        if row.capability.denominator is not None
    )
    has_denominator = any(row.capability.denominator is not None for row in matched)
    fresh_values = tuple(
        row.capability.fresh_at.isoformat()
        for row in matched
        if row.capability.fresh_at is not None
    )
    evidence = [
        f"{row.connector.name}:{row.capability.state}"
        for row in matched
    ]
    if any(
        row.capability.state == "ready" and row.capability.denominator is not None
        for row in matched
    ):
        return (
            "authoritative",
            True,
            denominator,
            len(matched),
            max(fresh_values) if fresh_values else None,
            evidence,
        )
    if any(row.capability.state in {"ready", "partial", "empty"} for row in matched):
        return (
            "partial",
            False,
            denominator if has_denominator else None,
            len(matched),
            max(fresh_values) if fresh_values else None,
            evidence,
        )
    return "missing", False, None, len(matched), max(fresh_values) if fresh_values else None, evidence


def _denominator_item(
    *,
    domain: Literal[
        "users",
        "devices",
        "browser",
        "repositories",
        "saas_apps",
        "cloud_runtimes",
        "models",
    ],
    label: str,
    state: Literal["authoritative", "partial", "observed_only", "missing"],
    authoritative: bool,
    family: Literal["github", "m365_teams", "identity", "saas", "cloud"] | None,
    denominator: int | None,
    connection_count: int,
    fresh_at: str | None,
    evidence: list[str],
    next_action: str,
    limitation: str,
) -> EnterpriseDenominatorItemResponse:
    flow = _domain_flow(family)
    return EnterpriseDenominatorItemResponse(
        domain=domain,
        label=label,
        state=state,
        authoritative=authoritative,
        required_source_family=family,
        required_source_title=flow.title if flow else None,
        connect_href=flow.entrypoint_href if flow else "/integrations",
        denominator=denominator,
        connection_count=connection_count,
        fresh_at=fresh_at,
        evidence=evidence,
        next_action=next_action,
        limitation=limitation,
    )


def _response(record: HMAIRSourceConnectionRecord) -> SourceConnectionResponse:
    metadata = record.connector.metadata_json if isinstance(record.connector.metadata_json, dict) else {}
    contract = metadata.get("hmair_source_contract") if isinstance(metadata.get("hmair_source_contract"), dict) else {}
    source_metadata = contract.get("source_metadata") if isinstance(contract.get("source_metadata"), dict) else {}
    account_scope_kind = str(source_metadata.get("account_scope_kind") or "UNKNOWN").upper()
    if account_scope_kind not in {"ORGANIZATION", "PERSONAL"}:
        account_scope_kind = "UNKNOWN"
    return SourceConnectionResponse(
        connection_id=record.connector.id,
        provider_key=record.connector.provider_key,
        display_name=record.connector.name,
        status=record.connector.status,
        account_scope_kind=account_scope_kind,
        target=SourceConnectionTargetResponse(
            target_id=record.target.target_id,
            target_type=record.target.target_type,
            environment=record.target.environment,
        ),
        collector=SourceConnectionCollectorResponse(
            collector_id=record.collector.collector_id,
            collector_type=record.collector.collector_type,
            health=record.collector.health,
        ),
        capability=record.capability,
    )


SOURCE_CONNECTION_SETUP_CATALOG = (
    SourceConnectionSetupFlowResponse(
        family="github",
        title="GitHub repositories",
        summary="Install a GitHub App on selected repositories, inventory repo access, and govern AI tool actions by repository scope.",
        entrypoint_href="/control-coverage/source-control/github-repository-boundary",
        provider_keys=["hmair_github_cloud", "hmair_github_ghes"],
        visibility=[
            "GitHub organizations, personal accounts, repositories, members and teams where the installed app is authorized",
            "AI agents and MCP tools connected to repositories",
            "Repository actions including read, branch, write file, create PR, push, merge and PR approval",
        ],
        required_authority=[
            "Customer-owned GitHub App installation on selected repositories or approved GitHub Enterprise Server host",
            "Repository selection confirmed by an administrator; selected repositories are approved and everything else remains blocked by policy",
        ],
        credential_requirements=[
            "GitHub App ID",
            "Installation ID",
            "Private key PEM stored write-only",
        ],
        validation_mode="Validate by calling GitHub metadata APIs and creating a fresh repository-inventory receipt.",
        limitations=[
            "No coverage is claimed until validation produces fresh source evidence.",
            "Personal account repositories never imply enterprise organization membership.",
        ],
        status="setup_required",
    ),
    SourceConnectionSetupFlowResponse(
        family="m365_teams",
        title="M365 / Teams",
        summary="Connect Microsoft Graph to discover tenant Copilot, Teams, meeting, mailbox, SharePoint and OneDrive metadata needed for AI governance.",
        entrypoint_href="/integrations?source=m365_teams",
        provider_keys=["hmair_microsoft365_copilot", "microsoft_365", "teams", "outlook", "onedrive_sharepoint", "entra_id"],
        visibility=[
            "Microsoft 365 tenant and Copilot source metadata",
            "Teams meeting and note-taker evidence where Graph permissions allow it",
            "SharePoint, OneDrive, Exchange and Entra user/group context",
        ],
        required_authority=[
            "Microsoft tenant-admin consent for the customer-owned application registration",
            "Explicit approval for the selected Graph permission profile",
        ],
        credential_requirements=[
            "Directory tenant ID",
            "Application client ID",
            "Client secret or certificate credential",
        ],
        validation_mode="Prepare admin-consent URL, save encrypted credentials, then run a live metadata pull.",
        limitations=[
            "No coverage is claimed until validation produces fresh source evidence.",
            "Graph permission scope determines whether Teams, Copilot and file evidence is visible.",
        ],
        status="setup_required",
    ),
    SourceConnectionSetupFlowResponse(
        family="identity",
        title="Identity directory",
        summary="Connect the authoritative directory so users, groups, departments, managers and tenant membership can be resolved safely.",
        entrypoint_href="/integrations?source=identity",
        provider_keys=["entra_id", "scim", "okta", "google_workspace"],
        visibility=[
            "Users, service accounts, groups, departments and manager relationships",
            "Department-to-policy and group-to-policy assignment denominators",
            "Cross-tenant identity boundaries and explicit revocation state",
        ],
        required_authority=[
            "Customer-owned IdP administrator approval for read-only directory or SCIM access",
            "Tenant-scoped attribute mapping confirmation before assignments are inferred",
        ],
        credential_requirements=[
            "IdP tenant or base URL",
            "SCIM token, OAuth client or directory app credential",
            "Approved attribute mapping",
        ],
        validation_mode="Run a bounded directory metadata pull and reconcile user/group denominators.",
        limitations=[
            "No coverage is claimed until validation produces fresh source evidence.",
            "Fuzzy department matching is never silently accepted without administrator confirmation.",
        ],
        status="setup_required",
    ),
    SourceConnectionSetupFlowResponse(
        family="saas",
        title="SaaS applications",
        summary="Connect approved SaaS systems to discover AI activity, collaboration context, exports, uploads and business-system actions.",
        entrypoint_href="/integrations?source=saas",
        provider_keys=["slack", "jira", "salesforce", "google_workspace", "microsoft_365"],
        visibility=[
            "SaaS application usage and AI-adjacent activity metadata",
            "Business-system actions, exports, uploads and sharing destinations where APIs support it",
            "SaaS account class and workspace/tenant context",
        ],
        required_authority=[
            "Customer-owned SaaS administrator OAuth consent or API token",
            "Approved source contract for each SaaS vendor before collection is enabled",
        ],
        credential_requirements=[
            "SaaS workspace or tenant identifier",
            "OAuth application credential or admin API token",
            "Approved capability scope",
        ],
        validation_mode="Run a vendor-specific metadata pull and record unsupported dimensions as blind spots.",
        limitations=[
            "No coverage is claimed until validation produces fresh source evidence.",
            "Common SaaS usage is not treated as approved behavior without a policy assignment.",
        ],
        status="setup_required",
    ),
    SourceConnectionSetupFlowResponse(
        family="cloud",
        title="Cloud / AI runtimes",
        summary="Connect cloud and AI runtime inventories to discover model endpoints, agents, workload identities, gateways and data destinations.",
        entrypoint_href="/integrations?source=cloud",
        provider_keys=["aws", "azure_openai", "microsoft_foundry", "gcp", "openai_enterprise"],
        visibility=[
            "Cloud-hosted model endpoints, gateways, runtimes and workload identities",
            "AI agents, tools, execution resources and destinations where control-plane APIs expose them",
            "Runtime control coverage and stale or regressed control points",
        ],
        required_authority=[
            "Customer-owned cloud administrator approval for read-only inventory roles or service principals",
            "Explicit environment and account/subscription/project scope selection",
        ],
        credential_requirements=[
            "Cloud account, subscription or project scope",
            "Read-only inventory role, service principal or workload identity",
            "Approved region and environment mapping",
        ],
        validation_mode="Run bounded cloud inventory and runtime metadata collection with explicit account denominators.",
        limitations=[
            "No coverage is claimed until validation produces fresh source evidence.",
            "Cloud inventory visibility does not imply pre-execution enforcement unless a verified control point exists.",
        ],
        status="setup_required",
    ),
)


@router.get("/setup-catalog", response_model=SourceConnectionSetupCatalogResponse)
def get_source_connection_setup_catalog(
    _: TenantContext = Depends(require_permission("discovery.view")),
) -> SourceConnectionSetupCatalogResponse:
    return SourceConnectionSetupCatalogResponse(
        items=list(SOURCE_CONNECTION_SETUP_CATALOG),
        total=len(SOURCE_CONNECTION_SETUP_CATALOG),
    )


@router.get("/authority-status", response_model=EnterpriseDenominatorStatusResponse)
def get_enterprise_denominator_authority_status(
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> EnterpriseDenominatorStatusResponse:
    """Show exactly which enterprise denominators are authoritative.

    This endpoint deliberately does not convert observed browser, endpoint or
    provider activity into an enterprise denominator. It is the control-plane
    truth used by the UI to explain why a page is still partial or unknown.
    """

    records = list_source_connections(db, tenant_id=ctx.tenant.id)
    github_state, github_authoritative, github_denominator, github_count, github_fresh, github_evidence = _connection_authority(
        records,
        provider_keys={"hmair_github_cloud", "hmair_github_ghes"},
    )
    m365_state, m365_authoritative, m365_denominator, m365_count, m365_fresh, m365_evidence = _connection_authority(
        records,
        provider_keys={"hmair_microsoft365_copilot"},
    )

    items = [
        _denominator_item(
            domain="users",
            label="Users, groups and departments",
            state="missing",
            authoritative=False,
            family="identity",
            denominator=None,
            connection_count=0,
            fresh_at=None,
            evidence=[],
            next_action="Connect an authoritative IdP or SCIM directory and validate user, group, department and revocation denominators.",
            limitation="Browser or AI-client observations can identify activity, but they cannot prove the full employee population.",
        ),
        _denominator_item(
            domain="devices",
            label="Managed devices and endpoint posture",
            state="missing",
            authoritative=False,
            family="identity",
            denominator=None,
            connection_count=0,
            fresh_at=None,
            evidence=[],
            next_action="Connect device inventory through MDM/EDR or the endpoint fleet enrollment source and validate signed heartbeats.",
            limitation="One enrolled laptop proves that endpoint only; it does not establish a fleet denominator.",
        ),
        _denominator_item(
            domain="browser",
            label="Managed browsers and extensions",
            state="observed_only",
            authoritative=False,
            family="identity",
            denominator=None,
            connection_count=0,
            fresh_at=None,
            evidence=[],
            next_action="Connect managed-browser policy/MDM inventory and reconcile approved extension IDs with signed extension heartbeats.",
            limitation="Extension events prove observed browser activity, not the full browser fleet or enforced extension installation.",
        ),
        _denominator_item(
            domain="repositories",
            label="Git repositories and repo access",
            state=github_state,  # type: ignore[arg-type]
            authoritative=github_authoritative,
            family="github",
            denominator=github_denominator,
            connection_count=github_count,
            fresh_at=github_fresh,
            evidence=github_evidence,
            next_action=(
                "Install the GitHub App on selected organization repositories, validate inventory, then approve repo actions."
                if not github_authoritative
                else "Repository denominator is authoritative for the validated selected GitHub scope; use GitHub Access & AI to approve or block actions."
            ),
            limitation="Personal GitHub repositories never imply enterprise organization membership; unselected repositories remain blocked or unknown.",
        ),
        _denominator_item(
            domain="saas_apps",
            label="SaaS apps, Teams and collaboration surfaces",
            state=m365_state if m365_count else "missing",  # type: ignore[arg-type]
            authoritative=m365_authoritative,
            family="m365_teams",
            denominator=m365_denominator,
            connection_count=m365_count,
            fresh_at=m365_fresh,
            evidence=m365_evidence,
            next_action=(
                "Connect Microsoft Graph and SaaS admin APIs with tenant-admin consent, then validate fresh metadata pulls."
                if not m365_authoritative
                else "Microsoft 365 denominator is authoritative for the validated permission scope; add other SaaS sources as needed."
            ),
            limitation="M365 visibility is limited by Graph permissions; Slack, Salesforce, Jira and other SaaS need their own source contracts.",
        ),
        _denominator_item(
            domain="cloud_runtimes",
            label="Cloud accounts, AI runtimes and workload identities",
            state="missing",
            authoritative=False,
            family="cloud",
            denominator=None,
            connection_count=0,
            fresh_at=None,
            evidence=[],
            next_action="Connect AWS, Azure/OpenAI Foundry, GCP or other runtime inventories with explicit account/subscription/project scope.",
            limitation="Observed runtime calls do not prove the full cloud estate without cloud-account denominators.",
        ),
        _denominator_item(
            domain="models",
            label="Providers, workspaces and models",
            state="observed_only",
            authoritative=False,
            family="cloud",
            denominator=None,
            connection_count=0,
            fresh_at=None,
            evidence=[],
            next_action="Connect provider-native admin usage APIs, gateways or cloud runtimes to make model and workspace inventory authoritative.",
            limitation="Browser or MCP events can show a model was used, but provider-native or gateway inventory is needed for full model coverage.",
        ),
    ]
    authoritative_count = sum(1 for item in items if item.authoritative)
    if authoritative_count == len(items):
        overall_state = "authoritative"
    elif authoritative_count > 0:
        overall_state = "partial_authority"
    elif any(item.state == "observed_only" for item in items):
        overall_state = "missing_authoritative_sources"
    else:
        overall_state = "observed_only"
    return EnterpriseDenominatorStatusResponse(
        overall_state=overall_state,  # type: ignore[arg-type]
        authoritative_denominator_complete=authoritative_count == len(items),
        authoritative_count=authoritative_count,
        total_domains=len(items),
        items=items,
        how_to_get_full_authority=[
            "Connect identity/SCIM or IdP first for users, groups, departments and revocation.",
            "Connect endpoint fleet and managed-browser/MDM inventory for device and extension denominators.",
            "Connect GitHub App or GHES on selected repositories for repository and developer access authority.",
            "Connect M365/Teams and other SaaS admin APIs for collaboration, files, meetings and account context.",
            "Connect cloud/runtime/provider-native inventory for models, agents, gateways and workload identities.",
            "Run validation after each source; only fresh validated denominators become authoritative.",
        ],
    )


@router.post("", response_model=SourceConnectionResponse, status_code=status.HTTP_201_CREATED)
def create_source_connection(
    payload: HMAIRSourceConnectionInput,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
    _: None = Depends(require_hmair_core),
) -> SourceConnectionResponse:
    record = provision_source_connection(db, tenant_id=ctx.tenant.id, input=payload)
    if record.created:
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id if ctx.user else None,
            actor_type="human",
            action="discovery.source_connection.create",
            resource_type="discovery_source_connection",
            resource_id=record.connector.id,
            payload={
                "provider_key": record.connector.provider_key,
                "target_type": record.target.target_type,
                "requested_capability_count": len(payload.requested_capabilities),
                "credentials_supplied": bool(record.connector.encrypted_secrets),
            },
        )
    db.commit()
    return _response(record)


@router.get("", response_model=SourceConnectionListResponse)
def list_connections(
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
    _: None = Depends(require_hmair_core),
) -> SourceConnectionListResponse:
    records = list_source_connections(db, tenant_id=ctx.tenant.id)
    return SourceConnectionListResponse(items=[_response(record) for record in records], total=len(records))


@router.get("/{connection_id}", response_model=SourceConnectionResponse)
def get_connection(
    connection_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
    _: None = Depends(require_hmair_core),
) -> SourceConnectionResponse:
    record = get_source_connection(db, tenant_id=ctx.tenant.id, connection_id=connection_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source connection not found")
    return _response(record)


@router.post("/{connection_id}/validate", response_model=SourceConnectionResponse)
def validate_connection(
    connection_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
    _: None = Depends(require_hmair_core),
) -> SourceConnectionResponse:
    record = validate_source_connection(
        db, tenant_id=ctx.tenant.id, connection_id=connection_id
    )
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source connection not found")
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="discovery.source_connection.validate_requested",
        resource_type="discovery_source_connection",
        resource_id=record.connector.id,
        payload={
            "provider_key": record.connector.provider_key,
            "source_state": record.capability.state,
            "allowed_capability_count": len(record.capability.allowed_capabilities),
            "denominator_available": record.capability.denominator is not None,
        },
    )
    db.commit()
    return _response(record)


__all__ = ["router"]
