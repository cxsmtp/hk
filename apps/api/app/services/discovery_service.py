from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.discovery import DiscoveryApplication
from app.db.models.finding import Finding
from app.db.models.user import UserTenantRole
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.simulation_scheduler_service import schedule_for_high_risk_tier


APPLICATION_STATUSES = {"discovered", "monitoring", "approved", "blocked"}
RISK_TIERS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def tool_key_for_name(tool_name: str) -> str:
    raw = str(tool_name or "").strip().lower()
    if not raw:
        return "unknown"
    normalized_chars: list[str] = []
    prev_sep = False
    for ch in raw:
        if ch.isalnum():
            normalized_chars.append(ch)
            prev_sep = False
            continue
        if not prev_sep:
            normalized_chars.append("_")
            prev_sep = True
    out = "".join(normalized_chars).strip("_")
    return out or "unknown"


def _infer_vendor(tool_name: str) -> str:
    lower = str(tool_name or "").strip().lower()
    mapping = [
        ("openai", "OpenAI"),
        ("anthropic", "Anthropic"),
        ("claude", "Anthropic"),
        ("gemini", "Google"),
        ("google", "Google"),
        ("microsoft", "Microsoft"),
        ("copilot", "Microsoft"),
        ("aws", "AWS"),
        ("azure", "Microsoft"),
        ("jira", "Atlassian"),
        ("servicenow", "ServiceNow"),
    ]
    for token, vendor in mapping:
        if token in lower:
            return vendor
    return "Unknown"


def _normalize_risk_tier(value: str | None) -> str | None:
    normalized = str(value or "").strip().upper()
    if not normalized:
        return None
    if normalized not in RISK_TIERS:
        return None
    return normalized


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def get_discovery_application(
    db: Session,
    *,
    tenant_id: str,
    application_id: str,
) -> DiscoveryApplication | None:
    return db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.id == application_id,
            DiscoveryApplication.tenant_id == tenant_id,
        )
    )


def get_discovery_application_by_tool(
    db: Session,
    *,
    tenant_id: str,
    tool_name: str,
) -> DiscoveryApplication | None:
    key = tool_key_for_name(tool_name)
    return db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == tenant_id,
            DiscoveryApplication.tool_key == key,
        )
    )


def touch_discovery_application_from_finding(db: Session, *, finding: Finding) -> DiscoveryApplication:
    tool_name = str(finding.ai_tool or "").strip() or "unknown"
    key = tool_key_for_name(tool_name)
    now = datetime.now(timezone.utc)
    app = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == finding.tenant_id,
            DiscoveryApplication.tool_key == key,
        )
    )

    is_shadow_finding = (
        str(finding.risk_category or "").strip().lower() == "shadow_ai"
        or str(finding.finding_type or "").strip().lower().startswith("shadow_ai")
        or str(finding.finding_type or "").strip().lower() in {
            "unregistered_ai_system",
            "repeated_unknown_ai_network_usage",
            "unsanctioned_model_api_usage",
            "cross_surface_shadow_ai_confirmation",
        }
    )

    if app is None:
        app = DiscoveryApplication(
            tenant_id=finding.tenant_id,
            tool_key=key,
            tool_name=tool_name,
            vendor=_infer_vendor(tool_name),
            status="discovered" if is_shadow_finding else "monitoring",
            owner_user_id=finding.user_id,
            owner_department=finding.department,
            provisional_risk_tier=_normalize_risk_tier(finding.data_classification),
            ai_system_id=finding.ai_system_id,
            first_seen_at=finding.first_seen_at or now,
            last_seen_at=finding.last_seen_at or now,
            metadata_json={"source": "finding", "finding_ids": [finding.finding_id]},
        )
        db.add(app)
        db.flush()
        return app

    app.tool_name = tool_name
    app.vendor = app.vendor or _infer_vendor(tool_name)
    if app.status not in {"approved", "blocked"} and is_shadow_finding:
        app.status = "discovered"

    if finding.user_id and not app.owner_user_id:
        app.owner_user_id = finding.user_id
    if finding.department and not app.owner_department:
        app.owner_department = finding.department
    if finding.ai_system_id and not app.ai_system_id:
        app.ai_system_id = finding.ai_system_id
    current_seen = _to_utc(app.last_seen_at) or now
    incoming_seen = _to_utc(finding.last_seen_at) or _to_utc(finding.updated_at) or now
    app.last_seen_at = incoming_seen if incoming_seen >= current_seen else current_seen

    metadata = dict(app.metadata_json or {})
    finding_ids = [str(item) for item in metadata.get("finding_ids", []) if str(item).strip()]
    if finding.finding_id not in finding_ids:
        finding_ids.append(finding.finding_id)
    metadata["finding_ids"] = finding_ids[-100:]
    app.metadata_json = metadata
    db.flush()
    return app


def assign_discovery_application_owner(
    db: Session,
    *,
    tenant_id: str,
    application: DiscoveryApplication,
    owner_user_id: str | None,
    owner_department: str | None,
    actor_user_id: str | None,
) -> DiscoveryApplication:
    if owner_user_id:
        membership = db.scalar(
            select(UserTenantRole).where(
                UserTenantRole.tenant_id == tenant_id,
                UserTenantRole.user_id == owner_user_id,
            )
        )
        if membership is None:
            raise ValueError("owner_user_id not found in tenant")

    application.owner_user_id = owner_user_id
    application.owner_department = owner_department

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="discovery.application.assign_owner",
        resource_type="discovery_application",
        resource_id=application.id,
        payload={
            "owner_user_id": owner_user_id,
            "owner_department": owner_department,
        },
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="discovery_transition",
        signal_type="discovery.application.owner_assigned",
        label=f"Owner assigned for discovery application {application.tool_name}",
        payload={
            "application_id": application.id,
            "owner_user_id": owner_user_id,
            "owner_department": owner_department,
        },
    )
    db.flush()
    return application


def promote_discovery_application(
    db: Session,
    *,
    tenant_id: str,
    application: DiscoveryApplication,
    action: str,
    provisional_risk_tier: str | None,
    actor_user_id: str | None,
) -> DiscoveryApplication:
    normalized_action = str(action or "").strip().lower()
    if normalized_action not in {"approve", "keep_monitoring"}:
        raise ValueError("action must be approve or keep_monitoring")

    risk_tier = _normalize_risk_tier(provisional_risk_tier) or _normalize_risk_tier(application.provisional_risk_tier) or "MEDIUM"
    application.provisional_risk_tier = risk_tier

    if normalized_action == "keep_monitoring":
        application.status = "monitoring"
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="human",
            action="discovery.application.keep_monitoring",
            resource_type="discovery_application",
            resource_id=application.id,
            payload={"provisional_risk_tier": risk_tier},
        )
        create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="discovery_transition",
            signal_type="discovery.application.monitoring",
            label=f"Discovery application set to monitoring: {application.tool_name}",
            payload={"application_id": application.id, "provisional_risk_tier": risk_tier},
        )
        db.flush()
        return application

    ai_system = None
    if application.ai_system_id:
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.id == application.ai_system_id,
                AISystem.tenant_id == tenant_id,
            )
        )

    # The AI system is approved only through the approval workflow (app/services/ai_system_approval_service.py):
    # promoting the application registers it and asks for its approval, under its risk tier's policy.
    if ai_system is None:
        ai_system = AISystem(
            tenant_id=tenant_id,
            name=application.tool_name,
            description=f"Promoted from discovery application {application.id}",
            risk_tier=risk_tier,
            status="draft",
            metadata_json={
                "lifecycle_state": "PENDING_APPROVAL",
                "discovery_application_id": application.id,
                "discovery_tool_key": application.tool_key,
            },
        )
        db.add(ai_system)
        db.flush()
    else:
        ai_system.risk_tier = risk_tier
        metadata = dict(ai_system.metadata_json or {})
        metadata["discovery_application_id"] = application.id
        metadata["discovery_tool_key"] = application.tool_key
        ai_system.metadata_json = metadata

    application.ai_system_id = ai_system.id
    application.status = "approved"
    approval_request_id = _ask_for_ai_system_approval(
        db, tenant_id=tenant_id, ai_system=ai_system, application=application, actor_user_id=actor_user_id
    )

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="discovery.application.promote",
        resource_type="discovery_application",
        resource_id=application.id,
        payload={
            "action": normalized_action,
            "ai_system_id": ai_system.id,
            "risk_tier": risk_tier,
            "approval_request_id": approval_request_id,
        },
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="discovery_transition",
        signal_type="discovery.application.promoted",
        label=f"Discovery application promoted: {application.tool_name}",
        payload={
            "application_id": application.id,
            "ai_system_id": ai_system.id,
            "risk_tier": risk_tier,
        },
    )

    schedule_for_high_risk_tier(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        risk_tier=risk_tier,
        actor_user_id=actor_user_id,
    )

    db.flush()
    return application


def _ask_for_ai_system_approval(
    db: Session,
    *,
    tenant_id: str,
    ai_system: AISystem,
    application: DiscoveryApplication,
    actor_user_id: str | None,
) -> str | None:
    """The approval request for a promoted application's AI system: the one waiting already, or a new one in the
    promoter's name. None when the system is approved already, cannot be approved (its tier), or nobody signed in
    promoted it."""

    from app.services import ai_system_approval_service as approvals
    from app.services.governance_resolution import ai_system_is_approved

    if ai_system_is_approved(ai_system):
        return None
    pending = approvals.pending_request_for(db, tenant_id, ai_system.id)
    if pending is not None:
        return pending.id
    if not actor_user_id:
        return None
    try:
        request = approvals.request_approval(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system.id,
            actor_user_id=actor_user_id,
            reason=f"Promoted from discovery: {application.tool_name}",
            origin="discovery_promotion",
        )
    except approvals.ApprovalWorkflowError:
        return None
    return request.id


def block_discovery_application(
    db: Session,
    *,
    tenant_id: str,
    application: DiscoveryApplication,
    reason: str | None,
    actor_user_id: str | None,
) -> DiscoveryApplication:
    application.status = "blocked"
    if application.ai_system_id:
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.id == application.ai_system_id,
                AISystem.tenant_id == tenant_id,
            )
        )
        if ai_system is not None:
            ai_system.status = "prohibited"
            metadata = dict(ai_system.metadata_json or {})
            metadata["governance_state"] = "BLOCKED"
            metadata["lifecycle_state"] = "PROHIBITED"
            metadata["discovery_application_id"] = application.id
            ai_system.metadata_json = metadata

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="discovery.application.block",
        resource_type="discovery_application",
        resource_id=application.id,
        payload={"reason": reason},
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="discovery_transition",
        signal_type="discovery.application.blocked",
        label=f"Discovery application blocked: {application.tool_name}",
        payload={"application_id": application.id, "reason": reason},
    )
    db.flush()
    return application
