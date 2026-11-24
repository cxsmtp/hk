"""Tenant-safe projections and authorization helpers for User Visibility.

This module deliberately composes existing activity, policy-pack, evidence,
and lineage records. It never makes a policy decision or stores another copy
of prompt content.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, case, desc, func, or_, select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction, AIActionAlert, AISession, PromptPayload, UserRegistry
from app.db.models.account_boundary import AIAccountIdentity, AIAccountSession
from app.db.models.audit import AuditLog
from app.db.models.provider_signal import ProviderSignalRecord
from app.db.models.user import User, UserTenantRole
from app.db.models.user_visibility import UserVisibilityAccessGrant, UserVisibilityContentAccessGrant
from app.services.audit_service import write_audit_log
from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackInstance, PolicyPackUserGroup
from app.db.models.tenant import Tenant
from app.services.policy_pack_platform.service import (
    resolve_effective_policy_explanation,
    resolve_group_member_ids,
    resolve_group_refs_for_user,
)


MAX_REDACTED_PREVIEW_LENGTH = 2_000
VIEW_AGGREGATES = "view_aggregates"
VIEW_USER_METADATA = "view_user_metadata"
VIEW_ACTION_DETAILS = "view_action_details"
VIEW_EVIDENCE = "view_evidence"
REVEAL_PROMPT_CONTENT = "reveal_prompt_content"
MANAGE_GROUPS = "manage_groups"
MANAGE_PACK_ASSIGNMENTS = "manage_pack_assignments"
MANAGE_PRIVACY = "manage_privacy"
VISIBILITY_CAPABILITIES = frozenset(
    {
        VIEW_AGGREGATES,
        VIEW_USER_METADATA,
        VIEW_ACTION_DETAILS,
        VIEW_EVIDENCE,
        REVEAL_PROMPT_CONTENT,
        MANAGE_GROUPS,
        MANAGE_PACK_ASSIGNMENTS,
        MANAGE_PRIVACY,
    }
)
TENANT_VISIBILITY_ROLES = frozenset({"viewer", "operator", "auditor", "admin", "owner"})
VISIBILITY_ADMIN_ROLES = frozenset({"admin", "owner"})
CONTENT_REVEAL_TENANT_ROLES = frozenset({"auditor", "admin", "owner"})
PROMPT_REVEAL_PURPOSES = frozenset({"security_investigation", "audit", "incident_response", "privacy_review"})
USER_DIRECTORY_SORT_FIELDS = frozenset({"last_activity", "display_name", "department", "action_count"})
USER_360_SECTIONS = frozenset({"overview", "usage", "accounts", "prompts", "actions", "policies", "controls", "lineage", "maturity"})
ACCOUNT_CONTEXT_LIMIT = 100
ACCOUNT_CONTEXT_MODEL_LIMIT = 50
ACCOUNT_CONTEXT_EVIDENCE_LIMIT = 20
COMPANY_ENTERPRISE_CLASSES = frozenset({"ENTERPRISE_MANAGED", "ENTERPRISE_MEMBER_PERSONAL_IDENTITY", "ENTERPRISE_MANAGED_USER", "ENTERPRISE_SERVICE_IDENTITY"})
PARTNER_EXTERNAL_CLASSES = frozenset({"PARTNER_ENTERPRISE", "EXTERNAL_ENTERPRISE"})
PERSONAL_CLASSES = frozenset({"PERSONAL_FREE", "PERSONAL_PAID", "PERSONAL_DEVELOPER"})
CURRENT_ENTERPRISE_SESSION_STATES = frozenset({"ENTERPRISE_VERIFIED"})
ACTION_SCOPED_ASSIGNMENT_KEYS = frozenset(
    {
        "application",
        "account_class",
        "provider",
        "model",
        "agent",
        "tool",
        "mcp",
        "deployment_surface",
        "environment",
        "action_class",
    }
)


class UserVisibilityError(ValueError):
    """Expected safe service-boundary failure."""


@dataclass(frozen=True)
class VisibilityScope:
    capabilities: frozenset[str]
    departments: frozenset[str] | None

    def allows_department(self, department: str | None) -> bool:
        if self.departments is None:
            return True
        normalized = _department_token(department)
        return bool(normalized and normalized in self.departments)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _account_display_category(account_class: str | None) -> str:
    normalized = str(account_class or "UNKNOWN").strip().upper()
    if normalized in COMPANY_ENTERPRISE_CLASSES:
        return "COMPANY_ENTERPRISE"
    if normalized in PARTNER_EXTERNAL_CLASSES:
        return "PARTNER_EXTERNAL_ENTERPRISE"
    if normalized in PERSONAL_CLASSES:
        return "PERSONAL"
    if normalized == "ANONYMOUS":
        return "ANONYMOUS"
    return "UNKNOWN"


def _mask_identifier(value: str | None, *, include_identifiers: bool) -> str | None:
    if not value:
        return None
    return value if include_identifiers else "MASKED"


def _mask_identifier_list(values: list[str] | None, *, include_identifiers: bool) -> list[str]:
    normalized = sorted({str(value).strip() for value in (values or []) if str(value).strip()})
    return normalized if include_identifiers else (["MASKED"] if normalized else [])


def _department_token(value: Any) -> str:
    return str(value or "").strip().casefold()


def _directory_sorting(*, sort_by: str | None, sort_direction: str | None) -> tuple[str, str]:
    field = str(sort_by or "last_activity").strip().casefold()
    direction = str(sort_direction or "desc").strip().casefold()
    if field not in USER_DIRECTORY_SORT_FIELDS or direction not in {"asc", "desc"}:
        raise UserVisibilityError("visibility_sort_invalid")
    return field, direction


def _directional(expression: Any, *, direction: str) -> Any:
    return expression.asc() if direction == "asc" else expression.desc()


def _bounded_text(value: Any, *, maximum: int, code: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise UserVisibilityError(code)
    return result


def _active_visibility_scope(db: Session, *, tenant_id: str, user_id: str, now: datetime | None = None) -> VisibilityScope:
    current = now or _now()
    rows = list(
        db.scalars(
            select(UserVisibilityAccessGrant).where(
                UserVisibilityAccessGrant.tenant_id == tenant_id,
                UserVisibilityAccessGrant.user_id == user_id,
                UserVisibilityAccessGrant.active.is_(True),
                or_(
                    UserVisibilityAccessGrant.expires_at.is_(None),
                    UserVisibilityAccessGrant.expires_at > current,
                ),
            )
        ).all()
    )
    capabilities: set[str] = set()
    departments: set[str] = set()
    organization_wide = False
    for row in rows:
        capabilities.update(
            item
            for item in (str(value).strip() for value in list(row.capabilities or []))
            if item in VISIBILITY_CAPABILITIES
        )
        scoped_departments = {_department_token(value) for value in list(row.department_scope or [])}
        scoped_departments.discard("")
        if not scoped_departments:
            organization_wide = True
        else:
            departments.update(scoped_departments)
    return VisibilityScope(
        capabilities=frozenset(capabilities),
        departments=None if organization_wide else frozenset(departments),
    )


def require_visibility_capability(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    tenant_role: str,
    capability: str,
    target_department: str | None = None,
) -> VisibilityScope:
    if tenant_role not in TENANT_VISIBILITY_ROLES:
        raise UserVisibilityError("visibility_role_not_allowed")
    if capability not in VISIBILITY_CAPABILITIES:
        raise UserVisibilityError("visibility_capability_invalid")
    scope = _active_visibility_scope(db, tenant_id=tenant_id, user_id=actor_user_id)
    if capability not in scope.capabilities:
        raise UserVisibilityError("visibility_capability_required")
    if target_department is not None and not scope.allows_department(target_department):
        raise UserVisibilityError("visibility_department_scope_denied")
    return scope


def _tenant_member_exists(db: Session, *, tenant_id: str, user_id: str) -> bool:
    return db.scalar(
        select(UserTenantRole.user_id).where(
            UserTenantRole.tenant_id == tenant_id,
            UserTenantRole.user_id == user_id,
        )
    ) is not None


def _serialize_access_grant(row: UserVisibilityAccessGrant) -> dict[str, Any]:
    return {
        "grant_id": row.id,
        "user_id": row.user_id,
        "capabilities": sorted({str(value) for value in list(row.capabilities or []) if str(value) in VISIBILITY_CAPABILITIES}),
        "department_scope": list(row.department_scope or []),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "active": bool(row.active),
        "reason": row.reason,
        "granted_by_user_id": row.granted_by_user_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def create_visibility_access_grant(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    tenant_role: str,
    user_id: str,
    capabilities: list[str],
    department_scope: list[str],
    reason: str,
    expires_at: datetime | None = None,
) -> UserVisibilityAccessGrant:
    if tenant_role not in VISIBILITY_ADMIN_ROLES:
        raise UserVisibilityError("visibility_grant_administration_denied")
    if not _tenant_member_exists(db, tenant_id=tenant_id, user_id=user_id):
        raise UserVisibilityError("visibility_grant_subject_not_found")
    normalized_capabilities = sorted({str(value).strip() for value in capabilities if str(value).strip()})
    if not normalized_capabilities or len(normalized_capabilities) > len(VISIBILITY_CAPABILITIES):
        raise UserVisibilityError("visibility_capabilities_invalid")
    if any(item not in VISIBILITY_CAPABILITIES for item in normalized_capabilities):
        raise UserVisibilityError("visibility_capabilities_invalid")
    if len(department_scope) > 64:
        raise UserVisibilityError("visibility_department_scope_invalid")
    normalized_departments = sorted({_bounded_text(item, maximum=128, code="visibility_department_scope_invalid") for item in department_scope})
    if normalized_departments:
        known_departments = {
            _department_token(value)
            for value in db.scalars(
                select(UserRegistry.department).where(
                    UserRegistry.tenant_id == tenant_id,
                    UserRegistry.department.is_not(None),
                )
            ).all()
        }
        if not {_department_token(value) for value in normalized_departments} <= known_departments:
            raise UserVisibilityError("visibility_department_scope_invalid")
    if expires_at is not None:
        candidate_expiry = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=timezone.utc)
        if candidate_expiry <= _now():
            raise UserVisibilityError("visibility_grant_expiry_invalid")
        expires_at = candidate_expiry
    grant = UserVisibilityAccessGrant(
        tenant_id=tenant_id,
        user_id=user_id,
        capabilities=normalized_capabilities,
        department_scope=normalized_departments,
        expires_at=expires_at,
        granted_by_user_id=actor_user_id,
        reason=_bounded_text(reason, maximum=1_000, code="visibility_grant_reason_invalid"),
        active=True,
    )
    db.add(grant)
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="user_visibility.access_grant.created",
        resource_type="user_visibility_access_grant",
        resource_id=grant.id,
        payload={
            "subject_user_id": user_id,
            "capabilities": normalized_capabilities,
            "department_scope": normalized_departments,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    return grant


def list_visibility_access_grants(db: Session, *, tenant_id: str) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(UserVisibilityAccessGrant)
        .where(UserVisibilityAccessGrant.tenant_id == tenant_id)
        .order_by(desc(UserVisibilityAccessGrant.created_at))
        .limit(500)
    ).all()
    return [_serialize_access_grant(row) for row in rows]


def _directory_usage_by_user(db: Session, *, tenant_id: str, user_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not user_ids:
        return {}
    usage: dict[str, dict[str, Any]] = {
        user_id: {
            "applications": set(),
            "providers": set(),
            "models": set(),
            "agents": set(),
            "tools": set(),
            "account_classes": set(),
            "prompt_request_count": 0,
            "action_count": 0,
            "sensitive_data_event_count": 0,
            "warning_approval_block_count": 0,
        }
        for user_id in user_ids
    }
    aggregate_rows = db.execute(
        select(
            AIAction.user_id,
            func.count(AIAction.action_id),
            func.sum(case((AIAction.data_classification.is_not(None), 1), else_=0)),
            func.sum(case((AIAction.enforcement_action.in_(("warned", "held", "blocked", "modified")), 1), else_=0)),
        )
        .where(AIAction.tenant_id == tenant_id, AIAction.user_id.in_(user_ids))
        .group_by(AIAction.user_id)
    ).all()
    for user_id, action_count, sensitive_count, outcome_count in aggregate_rows:
        if user_id in usage:
            usage[user_id].update(
                {
                    "action_count": int(action_count or 0),
                    "sensitive_data_event_count": int(sensitive_count or 0),
                    "warning_approval_block_count": int(outcome_count or 0),
                }
            )
    prompt_rows = db.execute(
        select(AIAction.user_id, func.count(PromptPayload.action_id))
        .join(PromptPayload, PromptPayload.action_id == AIAction.action_id)
        .where(AIAction.tenant_id == tenant_id, AIAction.user_id.in_(user_ids))
        .group_by(AIAction.user_id)
    ).all()
    for user_id, prompt_count in prompt_rows:
        if user_id in usage:
            usage[user_id]["prompt_request_count"] = int(prompt_count or 0)
    dimensions = (
        ("applications", AIAction.ai_app),
        ("models", AIAction.ai_model),
        ("providers", _json_text(AIAction.metadata_json, "provider")),
        ("agents", _json_text(AIAction.metadata_json, "agent_id")),
        ("tools", _json_text(AIAction.metadata_json, "tool")),
        ("account_classes", _json_text(AIAction.metadata_json, "account_class")),
    )
    for key, column in dimensions:
        rows = db.execute(
            select(AIAction.user_id, column)
            .where(AIAction.tenant_id == tenant_id, AIAction.user_id.in_(user_ids), column.is_not(None))
            .distinct()
            .limit(5_000)
        ).all()
        for user_id, value in rows:
            if user_id in usage and str(value or "").strip() and len(usage[user_id][key]) < 50:
                usage[user_id][key].add(str(value))
    return {
        user_id: {
            **values,
            **{key: sorted(value) for key, value in values.items() if isinstance(value, set)},
        }
        for user_id, values in usage.items()
    }


def _action_for_tenant(db: Session, *, tenant_id: str, action_id: str) -> AIAction:
    action = db.scalar(
        select(AIAction).where(AIAction.tenant_id == tenant_id, AIAction.action_id == action_id)
    )
    if action is None:
        raise UserVisibilityError("visibility_action_not_found")
    return action


def _privacy_settings_for_tenant(db: Session, *, tenant_id: str) -> Tenant:
    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if tenant is None:
        raise UserVisibilityError("visibility_tenant_not_found")
    return tenant


def get_privacy_settings(db: Session, *, tenant_id: str) -> dict[str, Any]:
    tenant = _privacy_settings_for_tenant(db, tenant_id=tenant_id)
    return {
        "full_content_reveal_enabled": bool(tenant.user_visibility_full_content_reveal_enabled),
        "retention_days": int(tenant.user_visibility_prompt_retention_days or 0),
    }


def update_privacy_settings(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    tenant_role: str,
    full_content_reveal_enabled: bool,
    retention_days: int,
) -> dict[str, Any]:
    if tenant_role not in CONTENT_REVEAL_TENANT_ROLES:
        raise UserVisibilityError("visibility_privacy_administration_denied")
    require_visibility_capability(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        tenant_role=tenant_role,
        capability=MANAGE_PRIVACY,
    )
    safe_retention_days = int(retention_days)
    if safe_retention_days < 0 or safe_retention_days > 3_650:
        raise UserVisibilityError("visibility_retention_days_invalid")
    if full_content_reveal_enabled and safe_retention_days < 1:
        raise UserVisibilityError("visibility_retention_days_invalid")
    tenant = _privacy_settings_for_tenant(db, tenant_id=tenant_id)
    tenant.user_visibility_full_content_reveal_enabled = bool(full_content_reveal_enabled)
    tenant.user_visibility_prompt_retention_days = safe_retention_days if full_content_reveal_enabled else 0
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="user_visibility.privacy_settings.updated",
        resource_type="tenant",
        resource_id=tenant_id,
        payload={
            "full_content_reveal_enabled": bool(full_content_reveal_enabled),
            "retention_days": tenant.user_visibility_prompt_retention_days,
        },
    )
    return get_privacy_settings(db, tenant_id=tenant_id)


def _action_department(db: Session, *, tenant_id: str, action: AIAction) -> str | None:
    if not action.user_id:
        return None
    return db.scalar(
        select(UserRegistry.department).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id == action.user_id,
        )
    )


def request_prompt_reveal(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    tenant_role: str,
    action_id: str,
    purpose: str,
    reason: str,
) -> UserVisibilityContentAccessGrant:
    if tenant_role not in CONTENT_REVEAL_TENANT_ROLES:
        raise UserVisibilityError("visibility_content_role_denied")
    action = _action_for_tenant(db, tenant_id=tenant_id, action_id=action_id)
    require_visibility_capability(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        tenant_role=tenant_role,
        capability=REVEAL_PROMPT_CONTENT,
        target_department=_action_department(db, tenant_id=tenant_id, action=action),
    )
    normalized_purpose = str(purpose or "").strip()
    if normalized_purpose not in PROMPT_REVEAL_PURPOSES:
        raise UserVisibilityError("visibility_content_purpose_invalid")
    privacy_settings = _privacy_settings_for_tenant(db, tenant_id=tenant_id)
    retention_days = int(privacy_settings.user_visibility_prompt_retention_days or 0)
    if not privacy_settings.user_visibility_full_content_reveal_enabled or retention_days < 1:
        raise UserVisibilityError("visibility_content_retention_disabled")
    if _as_utc(action.timestamp) < _now() - timedelta(days=retention_days):
        raise UserVisibilityError("visibility_content_retention_expired")
    prompt = db.get(PromptPayload, action.action_id)
    if prompt is None or prompt.storage_mode != "full" or not prompt.raw_prompt:
        raise UserVisibilityError("visibility_content_unavailable")
    grant = UserVisibilityContentAccessGrant(
        tenant_id=tenant_id,
        requester_user_id=actor_user_id,
        action_id=action.action_id,
        purpose=normalized_purpose,
        reason=_bounded_text(reason, maximum=1_000, code="visibility_content_reason_invalid"),
        expires_at=_now() + timedelta(minutes=5),
    )
    db.add(grant)
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="user_visibility.prompt_reveal.requested",
        resource_type="ai_action",
        resource_id=action.action_id,
        payload={"grant_id": grant.id, "purpose": normalized_purpose},
    )
    return grant


def consume_prompt_reveal(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    grant_id: str,
) -> dict[str, Any]:
    grant = db.scalar(
        select(UserVisibilityContentAccessGrant)
        .where(
            UserVisibilityContentAccessGrant.id == grant_id,
            UserVisibilityContentAccessGrant.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    if grant is None or grant.requester_user_id != actor_user_id:
        raise UserVisibilityError("visibility_content_grant_not_found")
    if grant.consumed_at is not None:
        raise UserVisibilityError("visibility_content_grant_consumed")
    if _as_utc(grant.expires_at) <= _now():
        raise UserVisibilityError("visibility_content_grant_expired")
    action = _action_for_tenant(db, tenant_id=tenant_id, action_id=grant.action_id)
    prompt = db.get(PromptPayload, action.action_id)
    if prompt is None or prompt.storage_mode != "full" or not prompt.raw_prompt:
        raise UserVisibilityError("visibility_content_unavailable")
    grant.consumed_at = _now()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="user_visibility.prompt_reveal.consumed",
        resource_type="ai_action",
        resource_id=action.action_id,
        payload={"grant_id": grant.id, "purpose": grant.purpose},
    )
    return {
        "action_id": action.action_id,
        "content": prompt.raw_prompt,
        "expires_at": _as_utc(grant.expires_at).isoformat(),
    }


def list_users(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    q: str | None,
    department: str | None,
    status_value: str | None,
    role: str | None,
    group_id: str | None,
    application: str | None,
    account_class: str | None,
    provider: str | None,
    model: str | None,
    last_activity_after: datetime | None,
    page: int,
    page_size: int,
    sort_by: str | None = None,
    sort_direction: str | None = None,
) -> dict[str, Any]:
    safe_page = max(1, int(page))
    safe_page_size = max(1, min(int(page_size), 100))
    requested_department = str(department or "").strip() or None
    if requested_department and not actor_scope.allows_department(requested_department):
        raise UserVisibilityError("visibility_department_scope_denied")

    stmt = (
        select(UserTenantRole, User, UserRegistry)
        .join(User, User.id == UserTenantRole.user_id)
        .outerjoin(
            UserRegistry,
            and_(
                UserRegistry.tenant_id == UserTenantRole.tenant_id,
                UserRegistry.user_id == UserTenantRole.user_id,
            ),
        )
        .where(UserTenantRole.tenant_id == tenant_id, User.is_active.is_(True))
    )
    scope_departments = actor_scope.departments
    if scope_departments is not None:
        stmt = stmt.where(func.lower(UserRegistry.department).in_(sorted(scope_departments)))
    if requested_department:
        stmt = stmt.where(func.lower(UserRegistry.department) == _department_token(requested_department))
    normalized_status = str(status_value or "").strip().casefold()
    if normalized_status:
        if normalized_status == "active":
            stmt = stmt.where(or_(UserRegistry.status.is_(None), func.lower(UserRegistry.status) == normalized_status))
        else:
            stmt = stmt.where(func.lower(UserRegistry.status) == normalized_status)
    normalized_role = str(role or "").strip().casefold()
    if normalized_role:
        stmt = stmt.where(func.lower(func.coalesce(UserRegistry.role, UserTenantRole.role)) == normalized_role)
    if group_id:
        group = db.scalar(
            select(PolicyPackUserGroup).where(
                PolicyPackUserGroup.tenant_id == tenant_id,
                PolicyPackUserGroup.id == group_id,
                PolicyPackUserGroup.active.is_(True),
            )
        )
        if group is None:
            raise UserVisibilityError("visibility_group_not_found")
        member_ids = _visible_member_ids(
            db,
            tenant_id=tenant_id,
            member_ids=resolve_group_member_ids(db, tenant_id=tenant_id, group_id=group.id),
            actor_scope=actor_scope,
        )
        stmt = stmt.where(UserTenantRole.user_id.in_(member_ids))
    if last_activity_after is not None:
        lower_bound = _as_utc(last_activity_after)
        if lower_bound < _now() - timedelta(days=90):
            raise UserVisibilityError("visibility_time_range_invalid")
        stmt = stmt.where(UserRegistry.last_seen_at >= lower_bound)

    action_predicates = [
        AIAction.tenant_id == tenant_id,
        AIAction.user_id == UserTenantRole.user_id,
    ]
    action_filters = (
        (application, AIAction.ai_app),
        (model, AIAction.ai_model),
        (account_class, _json_text(AIAction.metadata_json, "account_class")),
        (provider, _json_text(AIAction.metadata_json, "provider")),
    )
    has_action_filter = False
    for value, column in action_filters:
        if value:
            action_predicates.append(func.lower(column) == str(value).strip().casefold())
            has_action_filter = True
    if has_action_filter:
        stmt = stmt.where(select(AIAction.action_id).where(*action_predicates).exists())
    query = str(q or "").strip().casefold()
    if query:
        stmt = stmt.where(
            or_(
                func.lower(User.email).contains(query),
                func.lower(User.full_name).contains(query),
                func.lower(UserRegistry.display_name).contains(query),
                func.lower(UserRegistry.department).contains(query),
            )
        )
    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    sort_field, direction = _directory_sorting(sort_by=sort_by, sort_direction=sort_direction)
    action_count = (
        select(func.count(AIAction.action_id))
        .where(
            AIAction.tenant_id == tenant_id,
            AIAction.user_id == UserTenantRole.user_id,
        )
        .scalar_subquery()
    )
    if sort_field == "display_name":
        sort_expression = func.lower(func.coalesce(UserRegistry.display_name, User.full_name, User.email))
    elif sort_field == "department":
        sort_expression = func.lower(func.coalesce(UserRegistry.department, ""))
    elif sort_field == "action_count":
        sort_expression = action_count
    else:
        sort_expression = UserRegistry.last_seen_at
    rows = db.execute(
        stmt.order_by(_directional(sort_expression, direction=direction), User.email.asc(), UserTenantRole.user_id.asc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
    ).all()
    usage_by_user = _directory_usage_by_user(
        db,
        tenant_id=tenant_id,
        user_ids=[str(role_row.user_id) for role_row, _user_row, _registry_row in rows],
    )
    items: list[dict[str, Any]] = []
    for role_row, user_row, registry_row in rows:
        items.append(
            {
                "user_id": role_row.user_id,
                "display_name": (registry_row.display_name if registry_row and registry_row.display_name else user_row.full_name),
                "email": (registry_row.email if registry_row and registry_row.email else user_row.email),
                "department": registry_row.department if registry_row else None,
                "role": registry_row.role if registry_row and registry_row.role else role_row.role,
                "status": registry_row.status if registry_row else "active",
                "deployment_surfaces": list(registry_row.deployment_surfaces or []) if registry_row else [],
                "last_ai_activity": registry_row.last_seen_at.isoformat() if registry_row and registry_row.last_seen_at else None,
                "ai_usage": usage_by_user.get(str(role_row.user_id), {}),
                "maturity_stage": "unknown",
                "evidence_quality": "unknown",
            }
        )
    return {"items": items, "total": total, "page": safe_page, "page_size": safe_page_size}


def directory_summary(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
) -> dict[str, Any]:
    users = (
        select(UserTenantRole.user_id)
        .join(User, User.id == UserTenantRole.user_id)
        .outerjoin(
            UserRegistry,
            and_(
                UserRegistry.tenant_id == UserTenantRole.tenant_id,
                UserRegistry.user_id == UserTenantRole.user_id,
            ),
        )
        .where(UserTenantRole.tenant_id == tenant_id, User.is_active.is_(True))
    )
    if actor_scope.departments is not None:
        users = users.where(func.lower(UserRegistry.department).in_(sorted(actor_scope.departments)))
    visible_user_ids = users.subquery()
    action_user_ids = select(AIAction.user_id).where(
        AIAction.tenant_id == tenant_id,
        AIAction.user_id.in_(select(visible_user_ids.c.user_id)),
    )
    active_ai_user_count = int(db.scalar(select(func.count(func.distinct(action_user_ids.subquery().c.user_id)))) or 0)
    personal_account_user_count = int(
        db.scalar(
            select(func.count(func.distinct(AIAction.user_id))).where(
                AIAction.tenant_id == tenant_id,
                AIAction.user_id.in_(select(visible_user_ids.c.user_id)),
                func.lower(_json_text(AIAction.metadata_json, "account_class")).like("personal%"),
            )
        )
        or 0
    )
    blocked_action_user_count = int(
        db.scalar(
            select(func.count(func.distinct(AIAction.user_id))).where(
                AIAction.tenant_id == tenant_id,
                AIAction.user_id.in_(select(visible_user_ids.c.user_id)),
                func.lower(AIAction.enforcement_action).in_({"blocked", "block", "denied", "deny"}),
            )
        )
        or 0
    )
    return {
        "known_user_count": int(db.scalar(select(func.count()).select_from(visible_user_ids)) or 0),
        "active_ai_user_count": active_ai_user_count,
        "personal_account_user_count": personal_account_user_count,
        "blocked_action_user_count": blocked_action_user_count,
        "policy_gap_user_count": None,
        "evidence_quality": "unknown",
        "generated_at": _now().isoformat(),
    }


def _user_for_tenant(db: Session, *, tenant_id: str, user_id: str) -> tuple[UserTenantRole, User, UserRegistry | None]:
    row = db.execute(
        select(UserTenantRole, User, UserRegistry)
        .join(User, User.id == UserTenantRole.user_id)
        .outerjoin(
            UserRegistry,
            and_(
                UserRegistry.tenant_id == UserTenantRole.tenant_id,
                UserRegistry.user_id == UserTenantRole.user_id,
            ),
        )
        .where(UserTenantRole.tenant_id == tenant_id, UserTenantRole.user_id == user_id)
    ).first()
    if row is None:
        raise UserVisibilityError("visibility_user_not_found")
    return row


def _safe_action_metadata(metadata: Any) -> dict[str, Any]:
    values = metadata if isinstance(metadata, dict) else {}
    allowed_keys = {
        "provider",
        "account_class",
        "agent_id",
        "tool",
        "destination",
        "integrity",
        "control_state",
        "business_purpose",
        "environment",
        "model",
        "application",
        "represented_subject",
        "resource",
        "target",
        "side_effect",
        "executing_principal",
        "approval",
        "execution_result",
        "evidence_quality",
        "policy_pack",
        "control_point",
        "drift",
    }
    projection: dict[str, Any] = {}
    for key in allowed_keys:
        value = values.get(key)
        if isinstance(value, str) and value.strip():
            projection[key] = value[:255]
        elif isinstance(value, (bool, int, float)):
            projection[key] = value
    return projection


def _action_payload(
    action: AIAction,
    *,
    session: AISession | None,
    registry: UserRegistry | None,
    prompt: PromptPayload | None,
    alerts: list[AIActionAlert],
) -> dict[str, Any]:
    metadata = _safe_action_metadata(action.metadata_json)
    return {
        "action_id": action.action_id,
        "timestamp": action.timestamp.isoformat() if action.timestamp else None,
        "user_id": action.user_id,
        "user_display_name": registry.display_name if registry else None,
        "department": registry.department if registry else None,
        "session_id": action.session_id,
        "action_class": action.action_type,
        "application": action.ai_app,
        "model": action.ai_model,
        "provider": metadata.get("provider"),
        "source_surface": session.source_surface if session else None,
        "account_class": metadata.get("account_class"),
        "agent": metadata.get("agent_id"),
        "tool": metadata.get("tool"),
        "destination": metadata.get("destination"),
        "represented_subject": metadata.get("represented_subject"),
        "resource": metadata.get("resource"),
        "target": metadata.get("target"),
        "side_effect": metadata.get("side_effect"),
        "data_classification": action.data_classification,
        "decision": action.enforcement_action,
        "executing_principal": metadata.get("executing_principal"),
        "approval": metadata.get("approval") or "unknown",
        "execution_result": metadata.get("execution_result") or "unknown",
        "evidence_quality": metadata.get("evidence_quality") or "unknown",
        "policy_pack": metadata.get("policy_pack"),
        "control_point": metadata.get("control_point") or "unknown",
        "drift": metadata.get("drift") or "unknown",
        "policy_triggered": action.policy_triggered,
        "integrity": metadata.get("integrity"),
        "control_state": metadata.get("control_state"),
        "prompt_payload": project_prompt_payload(prompt),
        "alerts": [
            {
                "alert_id": alert.id,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "enforcement_action": alert.enforcement_action,
            }
            for alert in alerts
        ],
        "receipt_refs": {
            "audit_log_id": action.audit_log_id,
            "evidence_node_id": action.evidence_node_id,
            "evidence_bundle_id": action.evidence_bundle_id,
        },
        "lineage_refs": {
            "runtime_event_id": action.runtime_event_id,
            "monitoring_signal_id": action.monitoring_signal_id,
            "correlation_id": action.correlation_id,
        },
        "metadata": metadata,
    }


def _json_text(column, key: str):
    return column[key].as_string()


def _normalized_range(start_time: datetime | None, end_time: datetime | None) -> tuple[datetime, datetime]:
    current = _now()
    start = _as_utc(start_time) if start_time is not None else current - timedelta(days=90)
    end = _as_utc(end_time) if end_time is not None else current
    if start > end or end - start > timedelta(days=90):
        raise UserVisibilityError("visibility_time_range_invalid")
    return start, end


def list_actions(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    user_id: str | None,
    group_id: str | None,
    department: str | None,
    application: str | None,
    account_class: str | None,
    provider: str | None,
    model: str | None,
    agent: str | None,
    tool: str | None,
    action_class: str | None,
    resource: str | None,
    target: str | None,
    destination: str | None,
    data_class: str | None,
    side_effect: str | None,
    decision: str | None,
    integrity: str | None,
    control_state: str | None,
    surface: str | None,
    start_time: datetime | None,
    end_time: datetime | None,
    page: int,
    page_size: int,
) -> dict[str, Any]:
    safe_page = max(1, int(page))
    safe_page_size = max(1, min(int(page_size), 100))
    start, end = _normalized_range(start_time, end_time)
    requested_department = str(department or "").strip() or None
    if requested_department and not actor_scope.allows_department(requested_department):
        raise UserVisibilityError("visibility_department_scope_denied")
    stmt = (
        select(AIAction, AISession, UserRegistry)
        .join(
            AISession,
            and_(AISession.session_id == AIAction.session_id, AISession.tenant_id == AIAction.tenant_id),
            isouter=True,
        )
        .outerjoin(
            UserRegistry,
            and_(UserRegistry.user_id == AIAction.user_id, UserRegistry.tenant_id == AIAction.tenant_id),
        )
        .where(AIAction.tenant_id == tenant_id, AIAction.timestamp >= start, AIAction.timestamp <= end)
    )
    if actor_scope.departments is not None:
        stmt = stmt.where(func.lower(UserRegistry.department).in_(sorted(actor_scope.departments)))
    if user_id:
        stmt = stmt.where(AIAction.user_id == user_id)
    if group_id:
        group = db.scalar(
            select(PolicyPackUserGroup).where(
                PolicyPackUserGroup.tenant_id == tenant_id,
                PolicyPackUserGroup.id == group_id,
                PolicyPackUserGroup.active.is_(True),
            )
        )
        if group is None:
            raise UserVisibilityError("visibility_group_not_found")
        member_ids = _visible_member_ids(
            db,
            tenant_id=tenant_id,
            member_ids=resolve_group_member_ids(db, tenant_id=tenant_id, group_id=group.id),
            actor_scope=actor_scope,
        )
        stmt = stmt.where(AIAction.user_id.in_(member_ids))
    if requested_department:
        stmt = stmt.where(func.lower(UserRegistry.department) == _department_token(requested_department))
    simple_filters = (
        (application, AIAction.ai_app),
        (model, AIAction.ai_model),
        (action_class, AIAction.action_type),
        (data_class, AIAction.data_classification),
        (decision, AIAction.enforcement_action),
        (surface, AISession.source_surface),
    )
    for value, column in simple_filters:
        if value:
            stmt = stmt.where(func.lower(column) == str(value).strip().casefold())
    metadata_filters = (
        (account_class, "account_class"),
        (provider, "provider"),
        (agent, "agent_id"),
        (tool, "tool"),
        (resource, "resource"),
        (target, "target"),
        (destination, "destination"),
        (side_effect, "side_effect"),
        (integrity, "integrity"),
        (control_state, "control_state"),
    )
    for value, key in metadata_filters:
        if value:
            stmt = stmt.where(func.lower(_json_text(AIAction.metadata_json, key)) == str(value).strip().casefold())
    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    prompt_first = case(
        (AIAction.action_id.in_(select(PromptPayload.action_id)), 0),
        else_=1,
    )
    rows = db.execute(
        stmt.order_by(prompt_first, desc(AIAction.timestamp), AIAction.action_id.asc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
    ).all()
    action_ids = [action.action_id for action, _session, _registry in rows]
    prompt_by_action = {
        row.action_id: row
        for row in db.scalars(select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))).all()
    } if action_ids else {}
    alerts_by_action: dict[str, list[AIActionAlert]] = {}
    if action_ids:
        for alert in db.scalars(
            select(AIActionAlert).where(
                AIActionAlert.tenant_id == tenant_id,
                AIActionAlert.action_id.in_(action_ids),
            )
        ).all():
            alerts_by_action.setdefault(alert.action_id, []).append(alert)
    return {
        "items": [
            _action_payload(
                action,
                session=session,
                registry=registry,
                prompt=prompt_by_action.get(action.action_id),
                alerts=alerts_by_action.get(action.action_id, []),
            )
            for action, session, registry in rows
        ],
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def get_user_360(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    user_id: str,
) -> dict[str, Any]:
    tenant_role, user, registry = _user_for_tenant(db, tenant_id=tenant_id, user_id=user_id)
    if not actor_scope.allows_department(registry.department if registry else None):
        raise UserVisibilityError("visibility_department_scope_denied")
    action_count = int(
        db.scalar(
            select(func.count()).select_from(AIAction).where(
                AIAction.tenant_id == tenant_id,
                AIAction.user_id == user_id,
            )
        )
        or 0
    )
    application_counts = db.execute(
        select(AIAction.ai_app, func.count())
        .where(AIAction.tenant_id == tenant_id, AIAction.user_id == user_id)
        .group_by(AIAction.ai_app)
        .order_by(desc(func.count()))
        .limit(50)
    ).all()
    decision_counts = db.execute(
        select(AIAction.enforcement_action, func.count())
        .where(AIAction.tenant_id == tenant_id, AIAction.user_id == user_id)
        .group_by(AIAction.enforcement_action)
    ).all()
    prompt_request_count = int(
        db.scalar(
            select(func.count(PromptPayload.action_id))
            .join(AIAction, AIAction.action_id == PromptPayload.action_id)
            .where(AIAction.tenant_id == tenant_id, AIAction.user_id == user_id)
        )
        or 0
    )
    recent = list_actions(
        db,
        tenant_id=tenant_id,
        actor_scope=actor_scope,
        user_id=user_id,
        group_id=None,
        department=registry.department if registry else None,
        application=None,
        account_class=None,
        provider=None,
        model=None,
        agent=None,
        tool=None,
        action_class=None,
        resource=None,
        target=None,
        destination=None,
        data_class=None,
        side_effect=None,
        decision=None,
        integrity=None,
        control_state=None,
        surface=None,
        start_time=None,
        end_time=None,
        page=1,
        page_size=20,
    )
    policy_references = get_effective_policy_references(
        db,
        tenant_id=tenant_id,
        actor_scope=actor_scope,
        user_id=user_id,
    )
    recent_action_refs = [
        {
            "action_id": str(item["action_id"]),
            **dict(item.get("lineage_refs") or {}),
        }
        for item in recent["items"]
    ]
    receipt_refs = [
        {
            "action_id": str(item["action_id"]),
            **dict(item.get("receipt_refs") or {}),
        }
        for item in recent["items"]
    ]
    known_evidence_quality = sorted(
        {
            str(item.get("evidence_quality") or "").strip()
            for item in recent["items"]
            if str(item.get("evidence_quality") or "").strip().casefold() not in {"", "unknown"}
        }
    )
    evidence_quality = (
        known_evidence_quality[0]
        if len(known_evidence_quality) == 1
        else "mixed"
        if known_evidence_quality
        else "unknown"
    )
    prompt_levels = sorted(
        {
            str((item.get("prompt_payload") or {}).get("content_access_level") or "CONTENT_UNAVAILABLE")
            for item in recent["items"]
        }
    )
    data_classifications = sorted(
        {str(item["data_classification"]) for item in recent["items"] if item.get("data_classification")}
    )
    destinations = sorted({str(item["destination"]) for item in recent["items"] if item.get("destination")})
    return {
        "user": {
            "user_id": tenant_role.user_id,
            "display_name": registry.display_name if registry and registry.display_name else user.full_name,
            "email": registry.email if registry and registry.email else user.email,
            "department": registry.department if registry else None,
            "role": registry.role if registry and registry.role else tenant_role.role,
            "status": registry.status if registry else "active",
            "deployment_surfaces": list(registry.deployment_surfaces or []) if registry else [],
            "last_ai_activity": registry.last_seen_at.isoformat() if registry and registry.last_seen_at else None,
        },
        "ai_usage": {
            "action_count": action_count,
            "prompt_request_count": prompt_request_count,
            "applications": [{"name": name or "Unknown", "count": int(count)} for name, count in application_counts],
            "policy_outcomes": {str(name): int(count) for name, count in decision_counts},
        },
        "identity_groups": {
            "group_refs": policy_references["group_refs"],
            "department": registry.department if registry else None,
            "deployment_surfaces": list(registry.deployment_surfaces or []) if registry else [],
        },
        "prompt_request_summary": {
            "prompt_request_count": prompt_request_count,
            "content_access_levels": prompt_levels,
        },
        "data_destinations": {
            "data_classifications": data_classifications,
            "destinations": destinations,
        },
        "policies": policy_references,
        "approvals_exceptions": {
            "approval_states": sorted(
                {str(item["approval"]) for item in recent["items"] if item.get("approval") and item["approval"] != "unknown"}
            ),
            "exception_state": "unknown",
        },
        "controls_evidence": {
            "evidence_quality": evidence_quality,
            "receipt_refs": receipt_refs,
        },
        "lineage": {"recent_action_refs": recent_action_refs},
        "trends": {
            "window": "recent_20_actions",
            "status": "source_backed" if recent["items"] else "CONTENT_UNAVAILABLE",
        },
        "recent_actions": recent["items"],
        "recent_actions_total": recent["total"],
    }


def _user_account_tenant_contexts(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    include_identifiers: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_now = now or _now()
    rows = db.execute(
        select(AIAccountSession, AIAccountIdentity)
        .join(
            AIAccountIdentity,
            and_(
                AIAccountIdentity.id == AIAccountSession.account_identity_ref,
                AIAccountIdentity.tenant_id == tenant_id,
            ),
        )
        .where(
            AIAccountSession.tenant_id == tenant_id,
            AIAccountSession.user_identity_ref == user_id,
        )
        .order_by(AIAccountSession.last_verified_at.desc(), AIAccountSession.id.asc())
        .limit(ACCOUNT_CONTEXT_LIMIT + 1)
    ).all()
    truncated = len(rows) > ACCOUNT_CONTEXT_LIMIT
    rows = rows[:ACCOUNT_CONTEXT_LIMIT]
    reference_targets: dict[str, set[str]] = {}
    sessions: dict[str, AIAccountSession] = {}
    for account_session, _identity in rows:
        sessions[account_session.id] = account_session
        for reference in (account_session.id, account_session.account_session_id):
            reference_targets.setdefault(reference, set()).add(account_session.id)
    signals = list(
        db.scalars(
            select(ProviderSignalRecord)
            .where(ProviderSignalRecord.tenant_id == tenant_id, ProviderSignalRecord.user_id == user_id)
            .order_by(ProviderSignalRecord.occurred_at.desc(), ProviderSignalRecord.id.asc())
            .limit(5_000)
        ).all()
    )
    signals_by_session: dict[str, list[ProviderSignalRecord]] = {session_id: [] for session_id in sessions}
    unmatched_signals: list[ProviderSignalRecord] = []
    for signal in signals:
        targets = reference_targets.get(signal.session_ref or "", set())
        if signal.session_ref and len(targets) == 1:
            signals_by_session[next(iter(targets))].append(signal)
        else:
            unmatched_signals.append(signal)

    items: list[dict[str, Any]] = []
    for account_session, identity in rows:
        category = _account_display_category(identity.account_class)
        if category == "COMPANY_ENTERPRISE" and (
            identity.verification_status != "VERIFIED" or identity.verification_method != "server_owned_adapter"
        ):
            category = "UNKNOWN"
        current = (
            identity.verification_status == "VERIFIED"
            and identity.account_class in COMPANY_ENTERPRISE_CLASSES
            and account_session.session_state in CURRENT_ENTERPRISE_SESSION_STATES
            and str(account_session.drift_state or "NONE").upper() in {"", "NONE"}
            and _as_utc(account_session.expires_at) > observed_now
            and identity.verification_method == "server_owned_adapter"
            and account_session.verification_method == "server_owned_adapter"
        )
        bound_signals = signals_by_session[account_session.id]
        models = sorted({str(signal.model).strip() for signal in bound_signals if str(signal.model or "").strip()})[:ACCOUNT_CONTEXT_MODEL_LIMIT]
        clients = sorted({str(signal.client).strip() for signal in bound_signals if str(signal.client or "").strip()})[:ACCOUNT_CONTEXT_MODEL_LIMIT]
        relationship_state = (
            "CURRENT" if current else "EXPIRED" if _as_utc(account_session.expires_at) <= observed_now
            else "DRIFTED" if str(account_session.drift_state or "NONE").upper() not in {"", "NONE"} else "UNVERIFIED"
        )
        items.append({
            "context_id": f"account-session:{account_session.id}", "application": account_session.product,
            "provider": account_session.provider, "product": account_session.product, "models": models, "clients": clients,
            "display_category": category, "account_class": identity.account_class,
            "provider_subject_ref": _mask_identifier(identity.provider_subject_ref, include_identifiers=include_identifiers),
            "provider_tenant": {
                "organisation_ids": _mask_identifier_list(identity.organisation_ids, include_identifiers=include_identifiers),
                "workspace_ids": _mask_identifier_list(identity.workspace_ids, include_identifiers=include_identifiers),
                "tenant_ids": _mask_identifier_list(identity.tenant_ids, include_identifiers=include_identifiers),
                "selected_organisation_id": _mask_identifier(account_session.organisation_id, include_identifiers=include_identifiers),
                "selected_workspace_id": _mask_identifier(account_session.workspace_id, include_identifiers=include_identifiers),
                "selected_tenant_id": _mask_identifier(account_session.tenant_id_external, include_identifiers=include_identifiers),
                "verification": "VERIFIED" if current else "UNKNOWN",
            },
            "subscription_class": identity.subscription_class, "licence_state": identity.licence_state,
            "assurance_level": account_session.assurance_level, "verification_status": identity.verification_status,
            "verification_method": identity.verification_method, "session_state": account_session.session_state,
            "relationship_state": relationship_state, "drift_state": account_session.drift_state,
            "surfaces": [account_session.surface], "device_count": 1,
            "first_seen": account_session.issued_at.isoformat(),
            "last_seen": (account_session.last_verified_at or account_session.issued_at).isoformat(),
            "last_verified": account_session.last_verified_at.isoformat() if account_session.last_verified_at else None,
            "expires_at": account_session.expires_at.isoformat(), "session_count": 1, "activity_count": len(bound_signals),
            "evidence_quality": "VERIFIED" if current else "OBSERVED",
            "evidence_refs": list(identity.evidence_refs or [])[:ACCOUNT_CONTEXT_EVIDENCE_LIMIT] if include_identifiers else [],
            "current": current, "user_binding": "DIRECT",
            "limitations": [] if current else ["provider_tenant_membership_not_current"],
        })
    for signal in unmatched_signals:
        if len(items) >= ACCOUNT_CONTEXT_LIMIT:
            truncated = True
            break
        items.append({
            "context_id": f"provider-signal:{signal.id}", "application": signal.product or "Unknown", "provider": signal.provider or "Unknown",
            "product": signal.product or "Unknown", "models": [signal.model] if signal.model else [], "clients": [signal.client] if signal.client else [],
            "display_category": "UNKNOWN", "account_class": "UNKNOWN", "provider_subject_ref": None,
            "provider_tenant": {"organisation_ids": [], "workspace_ids": [], "tenant_ids": [], "selected_organisation_id": None, "selected_workspace_id": None, "selected_tenant_id": None, "verification": "UNKNOWN"},
            "subscription_class": None, "licence_state": None, "assurance_level": "UNKNOWN", "verification_status": "UNKNOWN", "verification_method": "UNKNOWN", "session_state": "UNKNOWN", "relationship_state": "UNMATCHED", "drift_state": "UNKNOWN", "surfaces": [], "device_count": 0,
            "first_seen": signal.occurred_at.isoformat(), "last_seen": signal.occurred_at.isoformat(), "last_verified": None, "expires_at": None, "session_count": 0, "activity_count": 1,
            "evidence_quality": signal.evidence_quality, "evidence_refs": [], "current": False, "user_binding": "OBSERVED_UNMATCHED", "limitations": ["unmatched_provider_session_reference"],
        })
    summary = {
        "total": len(items), "company_enterprise": sum(item["display_category"] == "COMPANY_ENTERPRISE" for item in items),
        "current_company_enterprise": sum(item["display_category"] == "COMPANY_ENTERPRISE" and item["current"] for item in items),
        "partner_external_enterprise": sum(item["display_category"] == "PARTNER_EXTERNAL_ENTERPRISE" for item in items),
        "personal": sum(item["display_category"] == "PERSONAL" for item in items), "anonymous": sum(item["display_category"] == "ANONYMOUS" for item in items), "unknown": sum(item["display_category"] == "UNKNOWN" for item in items),
    }
    return {"summary": summary, "items": items, "truncated": truncated, "limit": ACCOUNT_CONTEXT_LIMIT, "limitations": ["direct_user_binding_only", "unmatched_activity_remains_unknown"]}


def get_user_360_section(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    user_id: str,
    section: str,
    page: int,
    page_size: int,
) -> dict[str, Any]:
    selected_section = str(section or "").strip().casefold()
    if selected_section not in USER_360_SECTIONS:
        raise UserVisibilityError("visibility_section_invalid")
    tenant_role, user, registry = _user_for_tenant(db, tenant_id=tenant_id, user_id=user_id)
    if not actor_scope.allows_department(registry.department if registry else None):
        raise UserVisibilityError("visibility_department_scope_denied")
    user_payload = {
        "user_id": tenant_role.user_id,
        "display_name": registry.display_name if registry and registry.display_name else user.full_name,
        "email": registry.email if registry and registry.email else user.email,
        "department": registry.department if registry else None,
        "role": registry.role if registry and registry.role else tenant_role.role,
        "status": registry.status if registry else "active",
        "deployment_surfaces": list(registry.deployment_surfaces or []) if registry else [],
        "last_ai_activity": registry.last_seen_at.isoformat() if registry and registry.last_seen_at else None,
    }
    usage = _directory_usage_by_user(db, tenant_id=tenant_id, user_ids=[user_id]).get(
        user_id,
        {
            "applications": [],
            "providers": [],
            "models": [],
            "agents": [],
            "tools": [],
            "account_classes": [],
            "prompt_request_count": 0,
            "action_count": 0,
            "sensitive_data_event_count": 0,
            "warning_approval_block_count": 0,
        },
    )
    if selected_section == "overview":
        return {
            "section": selected_section,
            "data": {
                "user": user_payload,
                "ai_usage": usage,
                "group_refs": resolve_group_refs_for_user(db, tenant_id=tenant_id, user_id=user_id),
                "maturity_stage": "unknown",
                "evidence_quality": "unknown",
            },
        }
    if selected_section == "usage":
        return {"section": selected_section, "data": usage}
    if selected_section == "accounts":
        return {
            "section": selected_section,
            "data": _user_account_tenant_contexts(
                db,
                tenant_id=tenant_id,
                user_id=user_id,
                include_identifiers=VIEW_EVIDENCE in actor_scope.capabilities,
            ),
        }
    if selected_section in {"prompts", "actions"}:
        actions = list_actions(
            db,
            tenant_id=tenant_id,
            actor_scope=actor_scope,
            user_id=user_id,
            group_id=None,
            department=registry.department if registry else None,
            application=None,
            account_class=None,
            provider=None,
            model=None,
            agent=None,
            tool=None,
            action_class=None,
            resource=None,
            target=None,
            destination=None,
            data_class=None,
            side_effect=None,
            decision=None,
            integrity=None,
            control_state=None,
            surface=None,
            start_time=None,
            end_time=None,
            page=page,
            page_size=page_size,
        )
        return {"section": selected_section, "data": actions}
    if selected_section == "policies":
        return {
            "section": selected_section,
            "data": get_effective_policy_stack(
                db,
                tenant_id=tenant_id,
                actor_scope=actor_scope,
                user_id=user_id,
            ),
        }
    actions = list_actions(
        db,
        tenant_id=tenant_id,
        actor_scope=actor_scope,
        user_id=user_id,
        group_id=None,
        department=registry.department if registry else None,
        application=None,
        account_class=None,
        provider=None,
        model=None,
        agent=None,
        tool=None,
        action_class=None,
        resource=None,
        target=None,
        destination=None,
        data_class=None,
        side_effect=None,
        decision=None,
        integrity=None,
        control_state=None,
        surface=None,
        start_time=None,
        end_time=None,
        page=page,
        page_size=page_size,
    )
    if selected_section == "controls":
        evidence_quality = sorted(
            {
                str(item.get("evidence_quality") or "").strip()
                for item in actions["items"]
                if str(item.get("evidence_quality") or "").strip().casefold() not in {"", "unknown"}
            }
        )
        return {
            "section": selected_section,
            "data": {
                "evidence_quality": evidence_quality[0] if len(evidence_quality) == 1 else "mixed" if evidence_quality else "unknown",
                "receipt_refs": [item["receipt_refs"] for item in actions["items"]],
                "control_states": sorted({str(item.get("control_state") or "unknown") for item in actions["items"]}),
            },
        }
    if selected_section == "lineage":
        return {
            "section": selected_section,
            "data": {"recent_action_refs": [item["lineage_refs"] for item in actions["items"]]},
        }
    return {
        "section": selected_section,
        "data": {"stage": "unknown", "state": "unknown", "maturity_link": "/maturity"},
    }


def list_departments(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    page: int,
    page_size: int,
) -> dict[str, Any]:
    safe_page = max(1, int(page))
    safe_page_size = max(1, min(int(page_size), 100))
    stmt = select(
        UserRegistry.department,
        func.count(UserRegistry.user_id).label("user_count"),
        func.max(UserRegistry.last_seen_at).label("last_activity"),
    ).where(UserRegistry.tenant_id == tenant_id, UserRegistry.department.is_not(None))
    if actor_scope.departments is not None:
        stmt = stmt.where(func.lower(UserRegistry.department).in_(sorted(actor_scope.departments)))
    grouped = stmt.group_by(UserRegistry.department)
    total = int(db.scalar(select(func.count()).select_from(grouped.subquery())) or 0)
    rows = db.execute(
        grouped.order_by(UserRegistry.department.asc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
    ).all()
    departments = [str(department) for department, _user_count, _last_activity in rows]
    action_counts = {
        str(department): int(count)
        for department, count in db.execute(
            select(UserRegistry.department, func.count(AIAction.action_id))
            .join(
                AIAction,
                and_(AIAction.tenant_id == UserRegistry.tenant_id, AIAction.user_id == UserRegistry.user_id),
            )
            .where(UserRegistry.tenant_id == tenant_id, UserRegistry.department.in_(departments))
            .group_by(UserRegistry.department)
        ).all()
    } if departments else {}
    return {
        "items": [
            {
                "department": department,
                "user_count": int(user_count),
                "action_count": action_counts.get(str(department), 0),
                "last_ai_activity": last_activity.isoformat() if last_activity else None,
            }
            for department, user_count, last_activity in rows
        ],
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def organization_summary(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    lookback_hours: int,
) -> dict[str, Any]:
    safe_lookback = max(1, min(int(lookback_hours), 24 * 90))
    start = _now() - timedelta(hours=safe_lookback)
    action_stmt = (
        select(AIAction)
        .outerjoin(
            UserRegistry,
            and_(AIAction.tenant_id == UserRegistry.tenant_id, AIAction.user_id == UserRegistry.user_id),
        )
        .where(AIAction.tenant_id == tenant_id, AIAction.timestamp >= start)
    )
    if actor_scope.departments is not None:
        action_stmt = action_stmt.where(func.lower(UserRegistry.department).in_(sorted(actor_scope.departments)))
    action_count = int(db.scalar(select(func.count()).select_from(action_stmt.subquery())) or 0)
    user_stmt = select(UserRegistry.user_id).where(UserRegistry.tenant_id == tenant_id)
    if actor_scope.departments is not None:
        user_stmt = user_stmt.where(func.lower(UserRegistry.department).in_(sorted(actor_scope.departments)))
    user_count = int(db.scalar(select(func.count()).select_from(user_stmt.subquery())) or 0)
    app_stmt = (
        select(AIAction.ai_app, func.count())
        .outerjoin(
            UserRegistry,
            and_(AIAction.tenant_id == UserRegistry.tenant_id, AIAction.user_id == UserRegistry.user_id),
        )
        .where(AIAction.tenant_id == tenant_id, AIAction.timestamp >= start)
    )
    if actor_scope.departments is not None:
        app_stmt = app_stmt.where(func.lower(UserRegistry.department).in_(sorted(actor_scope.departments)))
    app_rows = db.execute(
        app_stmt.group_by(AIAction.ai_app)
        .order_by(desc(func.count()))
        .limit(50)
    ).all()
    return {
        "lookback_hours": safe_lookback,
        "user_count": user_count,
        "action_count": action_count,
        "applications": [{"name": name or "Unknown", "count": int(count)} for name, count in app_rows],
        "evidence_quality": "unknown",
    }


def _assignment_references_group(targets: Any, group_id: str) -> bool:
    values = targets if isinstance(targets, dict) else {}
    for key in {"group", "directory_group", "dynamic_group"}:
        target = values.get(key)
        if isinstance(target, list) and group_id in {str(item) for item in target}:
            return True
        if isinstance(target, str) and target == group_id:
            return True
    return False


def _assignment_references_user(targets: Any, user_id: str) -> bool:
    values = targets if isinstance(targets, dict) else {}
    target = values.get("user")
    if isinstance(target, list):
        return user_id in {str(item) for item in target}
    return isinstance(target, str) and target == user_id


def _assignment_target_tokens(targets: Any, key: str) -> set[str]:
    values = targets if isinstance(targets, dict) else {}
    target = values.get(key)
    if isinstance(target, list):
        return {str(item).strip() for item in target if str(item).strip()}
    if isinstance(target, str) and target.strip():
        return {target.strip()}
    return set()


def _assignment_references_department(targets: Any, department: str | None) -> bool:
    token = _department_token(department)
    return bool(token and token in {item.casefold() for item in _assignment_target_tokens(targets, "department")})


def _assignment_references_role(targets: Any, role: str | None) -> bool:
    token = str(role or "").strip().casefold()
    return bool(token and token in {item.casefold() for item in _assignment_target_tokens(targets, "role")})


def _assignment_references_organization(targets: Any) -> bool:
    return bool(_assignment_target_tokens(targets, "organization"))


def _assignment_applies_to_user_context(
    targets: Any,
    *,
    user_id: str,
    group_refs: list[str],
    department: str | None,
    role: str | None,
) -> bool:
    return (
        _assignment_references_user(targets, user_id)
        or any(_assignment_references_group(targets, group_id) for group_id in group_refs)
        or _assignment_references_department(targets, department)
        or _assignment_references_role(targets, role)
        or _assignment_references_organization(targets)
    )


def _assignment_kind(
    targets: Any,
    *,
    user_id: str,
    group_refs: list[str],
    department: str | None,
    role: str | None,
) -> str:
    if _assignment_references_user(targets, user_id):
        return "direct"
    if any(_assignment_references_group(targets, group_id) for group_id in group_refs):
        return "inherited"
    if _assignment_references_department(targets, department) or _assignment_references_role(targets, role):
        return "inherited"
    return "pack"


def _assignment_scope_explanation(
    targets: Any,
    *,
    user_id: str,
    group_refs: list[str],
    department: str | None,
    role: str | None,
) -> str:
    if _assignment_references_user(targets, user_id):
        return "Assigned directly to this user."
    if any(_assignment_references_group(targets, group_id) for group_id in group_refs):
        return "Inherited through a matching directory or policy group."
    if _assignment_references_department(targets, department):
        return "Inherited through the user's department."
    if _assignment_references_role(targets, role):
        return "Inherited through the user's role."
    if _assignment_references_organization(targets):
        return "Inherited from the organization baseline."
    return "This assignment has contextual selectors that require an action context."


def _assignment_requires_action_context(targets: Any) -> bool:
    values = targets if isinstance(targets, dict) else {}
    return any(bool(_assignment_target_tokens(values, key)) for key in ACTION_SCOPED_ASSIGNMENT_KEYS)


def _safe_assignment_payload(row: PolicyPackAssignment) -> dict[str, Any]:
    return {
        "assignment_id": row.id,
        "instance_id": row.instance_id,
        "assignment_key": row.assignment_key,
        "targets": row.targets if isinstance(row.targets, dict) else {},
        "precedence_layer": row.precedence_layer,
        "inherited_path": list(row.inherited_path or []),
        "active": bool(row.active),
    }


def _visible_member_ids(
    db: Session,
    *,
    tenant_id: str,
    member_ids: list[str],
    actor_scope: VisibilityScope,
) -> list[str]:
    if actor_scope.departments is None:
        return member_ids
    if not member_ids:
        return []
    rows = db.execute(
        select(UserRegistry.user_id, UserRegistry.department).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id.in_(member_ids),
        )
    ).all()
    return sorted(
        user_id
        for user_id, department in rows
        if actor_scope.allows_department(department)
    )


def _group_assignments(db: Session, *, tenant_id: str, group_id: str) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(PolicyPackAssignment)
        .where(PolicyPackAssignment.tenant_id == tenant_id, PolicyPackAssignment.active.is_(True))
        .order_by(PolicyPackAssignment.precedence_layer.asc(), PolicyPackAssignment.assignment_key.asc())
        .limit(500)
    ).all()
    return [_safe_assignment_payload(row) for row in rows if _assignment_references_group(row.targets, group_id)]


def _audit_refs_for_resource(
    db: Session,
    *,
    tenant_id: str,
    resource_type: str,
    resource_id: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.resource_type == resource_type,
            AuditLog.resource_id == resource_id,
        )
        .order_by(desc(AuditLog.created_at), AuditLog.id.asc())
        .limit(max(1, min(limit, 100)))
    ).all()
    return [
        {
            "audit_log_id": row.id,
            "action": row.action,
            "actor_user_id": row.actor_user_id,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


def list_groups(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    page: int,
    page_size: int,
) -> dict[str, Any]:
    safe_page = max(1, int(page))
    safe_page_size = max(1, min(int(page_size), 100))
    stmt = select(PolicyPackUserGroup).where(
        PolicyPackUserGroup.tenant_id == tenant_id,
        PolicyPackUserGroup.active.is_(True),
    )
    if actor_scope.departments is None:
        total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        groups = db.scalars(
            stmt.order_by(PolicyPackUserGroup.name.asc())
            .offset((safe_page - 1) * safe_page_size)
            .limit(safe_page_size)
        ).all()
    else:
        candidate_groups = db.scalars(stmt.order_by(PolicyPackUserGroup.name.asc()).limit(200)).all()
        groups = []
        for group in candidate_groups:
            member_ids = _visible_member_ids(
                db,
                tenant_id=tenant_id,
                member_ids=resolve_group_member_ids(db, tenant_id=tenant_id, group_id=group.id),
                actor_scope=actor_scope,
            )
            if member_ids:
                groups.append(group)
        total = len(groups)
        groups = groups[(safe_page - 1) * safe_page_size : safe_page * safe_page_size]
    items: list[dict[str, Any]] = []
    for group in groups:
        member_ids = _visible_member_ids(
            db,
            tenant_id=tenant_id,
            member_ids=resolve_group_member_ids(db, tenant_id=tenant_id, group_id=group.id),
            actor_scope=actor_scope,
        )
        items.append(
            {
                "group_id": group.id,
                "group_key": group.group_key,
                "name": group.name,
                "group_type": group.group_type,
                "source_ref": group.source_ref,
                "active": bool(group.active),
                "member_count": len(member_ids),
                "policy_pack_assignments": _group_assignments(db, tenant_id=tenant_id, group_id=group.id),
            }
        )
    return {"items": items, "total": total, "page": safe_page, "page_size": safe_page_size}


def get_group_detail(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    group_id: str,
    page: int,
    page_size: int,
) -> dict[str, Any]:
    group = db.scalar(
        select(PolicyPackUserGroup).where(
            PolicyPackUserGroup.tenant_id == tenant_id,
            PolicyPackUserGroup.id == group_id,
            PolicyPackUserGroup.active.is_(True),
        )
    )
    if group is None:
        raise UserVisibilityError("visibility_group_not_found")
    member_ids = _visible_member_ids(
        db,
        tenant_id=tenant_id,
        member_ids=resolve_group_member_ids(db, tenant_id=tenant_id, group_id=group.id),
        actor_scope=actor_scope,
    )
    if actor_scope.departments is not None and not member_ids:
        raise UserVisibilityError("visibility_department_scope_denied")
    safe_page = max(1, int(page))
    safe_page_size = max(1, min(int(page_size), 100))
    page_member_ids = member_ids[(safe_page - 1) * safe_page_size : safe_page * safe_page_size]
    return {
        "group_id": group.id,
        "group_key": group.group_key,
        "name": group.name,
        "group_type": group.group_type,
        "membership_rule": group.membership_rule if isinstance(group.membership_rule, dict) else {},
        "nested_group_ids": list(group.nested_group_ids or []),
        "source_ref": group.source_ref,
        "active": bool(group.active),
        "member_ids": page_member_ids,
        "member_count": len(member_ids),
        "member_page": safe_page,
        "member_page_size": safe_page_size,
        "policy_pack_assignments": _group_assignments(db, tenant_id=tenant_id, group_id=group.id),
        "audit_refs": _audit_refs_for_resource(
            db,
            tenant_id=tenant_id,
            resource_type="policy_pack_user_group",
            resource_id=group.id,
        ),
    }


def get_effective_policy_references(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    user_id: str,
) -> dict[str, Any]:
    _tenant_role, _user, registry = _user_for_tenant(db, tenant_id=tenant_id, user_id=user_id)
    if not actor_scope.allows_department(registry.department if registry else None):
        raise UserVisibilityError("visibility_department_scope_denied")
    group_refs = resolve_group_refs_for_user(db, tenant_id=tenant_id, user_id=user_id)
    assignments = db.scalars(
        select(PolicyPackAssignment)
        .where(PolicyPackAssignment.tenant_id == tenant_id, PolicyPackAssignment.active.is_(True))
        .order_by(PolicyPackAssignment.precedence_layer.asc(), PolicyPackAssignment.assignment_key.asc())
        .limit(500)
    ).all()
    user_role = registry.role if registry and registry.role else None
    pack_assignments = [
        _safe_assignment_payload(row)
        for row in assignments
        if _assignment_applies_to_user_context(
            row.targets,
            user_id=user_id,
            group_refs=group_refs,
            department=registry.department if registry else None,
            role=user_role,
        )
    ]
    context = {
        "actor_user_id": user_id,
        "actor_group": group_refs,
        "actor_department": registry.department if registry else None,
        "actor_role": user_role,
    }
    return {
        "group_refs": group_refs,
        "pack_assignments": pack_assignments,
        "effective_policy": resolve_effective_policy_explanation(db, tenant_id=tenant_id, context=context),
    }


def get_effective_policy_stack(
    db: Session,
    *,
    tenant_id: str,
    actor_scope: VisibilityScope,
    user_id: str,
) -> dict[str, Any]:
    """Return a source-backed policy stack for one user without re-evaluating actions.

    A row can include action-scoped selectors (for example a model or a
    deployment surface).  Such a row is shown as a contextual policy rather
    than claimed to be active for every action the user takes.
    """

    references = get_effective_policy_references(
        db,
        tenant_id=tenant_id,
        actor_scope=actor_scope,
        user_id=user_id,
    )
    _tenant_role, _user, registry = _user_for_tenant(db, tenant_id=tenant_id, user_id=user_id)
    group_refs = list(references["group_refs"])
    instance_ids = sorted({str(item["instance_id"]) for item in references["pack_assignments"] if item.get("instance_id")})
    instances = {
        instance.id: instance
        for instance in db.scalars(
            select(PolicyPackInstance).where(
                PolicyPackInstance.tenant_id == tenant_id,
                PolicyPackInstance.id.in_(instance_ids),
            )
        ).all()
    } if instance_ids else {}
    user_role = registry.role if registry and registry.role else None
    entries: list[dict[str, Any]] = []
    for assignment in references["pack_assignments"]:
        instance = instances.get(str(assignment["instance_id"]))
        targets = assignment.get("targets") if isinstance(assignment.get("targets"), dict) else {}
        entries.append(
            {
                **assignment,
                "assignment_kind": _assignment_kind(
                    targets,
                    user_id=user_id,
                    group_refs=group_refs,
                    department=registry.department if registry else None,
                    role=user_role,
                ),
                "scope_explanation": _assignment_scope_explanation(
                    targets,
                    user_id=user_id,
                    group_refs=group_refs,
                    department=registry.department if registry else None,
                    role=user_role,
                ),
                "requires_action_context": _assignment_requires_action_context(targets),
                "source_pack": instance.source_pack_id if instance else None,
                "source_pack_version": instance.source_pack_version if instance else None,
                "pack_instance_state": instance.state if instance else "unknown",
                "selected_surfaces": list(instance.selected_surfaces or []) if instance else [],
                "parameter_override_keys": sorted((instance.local_overrides or {}).keys()) if instance else [],
                "has_customer_parameters": bool(instance and instance.customer_parameters),
                "update_available": bool(instance and instance.update_available),
            }
        )
    entries.sort(
        key=lambda item: (
            -int(item.get("precedence_layer") or 0),
            str(item.get("assignment_key") or ""),
        )
    )
    effective_policy = references["effective_policy"]
    return {
        "user_id": user_id,
        "group_refs": group_refs,
        "entries": entries,
        "effective_policy": effective_policy,
        "final": effective_policy.get("final") if isinstance(effective_policy, dict) else {},
        "matched": bool(effective_policy.get("matched")) if isinstance(effective_policy, dict) else False,
        "explanation": effective_policy.get("explanation") if isinstance(effective_policy, dict) else None,
        "matched_selectors": list(effective_policy.get("matched_selectors") or []) if isinstance(effective_policy, dict) else [],
    }


def project_prompt_payload(row: PromptPayload | None) -> dict[str, Any]:
    """Return the normal-view prompt representation without source content."""

    if row is None:
        return {
            "content_access_level": "CONTENT_UNAVAILABLE",
            "reason": "source_not_captured",
        }

    common = {
        "storage_mode": row.storage_mode,
        "pii_detected": bool(row.pii_detected),
        "sensitive_entities": list(row.sensitive_entities or []),
        "data_classifications": list(row.sensitive_entities or []),
        "prompt_hash": row.prompt_hash,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    if row.storage_mode == "hashed_only":
        return {"content_access_level": "METADATA_ONLY", **common}

    preview = str(row.redacted_prompt or "").strip()
    if preview:
        return {
            "content_access_level": "REDACTED_PREVIEW",
            "redacted_preview": preview[:MAX_REDACTED_PREVIEW_LENGTH],
            **common,
        }
    return {"content_access_level": "METADATA_ONLY", **common}
