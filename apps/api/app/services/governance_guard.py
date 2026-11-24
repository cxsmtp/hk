from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import get_correlation_id, log_structured
from app.db.models.ai_system import AISystem
from app.db.models.monitoring import MonitoringSignal
from app.db.session import SessionLocal
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.governance_resolution import resolve_ai_system_status


GOVERNANCE_VERSION = "g1"
PROHIBITED_LIFECYCLE_STATES = {"PROHIBITED"}
PROHIBITED_RISK_TIERS = {"PROHIBITED"}


@dataclass
class GovernanceCheckResult:
    ai_system_id: str | None
    reason_code: str
    governance_state: str | None
    lifecycle_state: str | None
    risk_tier: str | None
    status: str | None = None
    enforcement_mode: str | None = None
    source: str | None = None


class GovernanceViolationError(Exception):
    def __init__(self, reason_code: str, *, status_code: int = 403, message: str = "Governance context blocked") -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code
        self.message = message


class GovernanceFailSecureError(Exception):
    def __init__(self, reason_code: str = "governance_unavailable", message: str = "Governance unavailable - fail secure") -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


def _check_db_connectivity(db: Session) -> None:
    db.execute(text("SELECT 1"))


def _resolve_governance_state(ai_system: AISystem) -> str:
    metadata = ai_system.metadata_json if isinstance(ai_system.metadata_json, dict) else {}
    explicit = metadata.get("governance_state")
    if explicit:
        return str(explicit).strip().upper()
    return "UNKNOWN"


def _resolve_lifecycle_state(ai_system: AISystem) -> str:
    metadata = ai_system.metadata_json if isinstance(ai_system.metadata_json, dict) else {}
    explicit = metadata.get("lifecycle_state")
    if explicit:
        return str(explicit).strip().upper()
    return str(ai_system.status or "").strip().upper()


def _metadata_payload(
    *,
    reason_code: str,
    correlation_id: str | None,
    tenant_id: str,
    ai_system_id: str | None,
    route: str,
    module: str,
    governance_action: str,
) -> dict[str, Any]:
    return {
        "reason_code": reason_code,
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "ai_system_id": ai_system_id,
        "route": route,
        "module": module,
        "governance_action": governance_action,
        "governance_version": GOVERNANCE_VERSION,
    }


def _source_surface(route: str, module: str) -> str:
    route_norm = str(route or "").strip().lower()
    module_norm = str(module or "").strip().lower()
    if route_norm.startswith("/gateway") or route_norm.startswith("/llm-gateway") or "gateway" in module_norm:
        return "gateway"
    if "extension" in route_norm or "browser" in route_norm or "browser" in module_norm:
        return "browser"
    if "mcp" in route_norm or "ai-iam" in route_norm or "ai_iam" in module_norm:
        return "aiiam"
    if "monitor" in route_norm or "monitor" in module_norm:
        return "monitoring"
    return "connector"


def _safe_int(value: Any, *, fallback: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return fallback


def _ensure_unknown_ai_candidate(
    db: Session,
    *,
    tenant_id: str,
    requested_ai_system_id: str | None,
    route: str,
    module: str,
    reason_code: str,
) -> None:
    candidate_name = str(requested_ai_system_id or "").strip()
    if not candidate_name:
        return

    source_surface = _source_surface(route, module)
    repeat_threshold = max(3, int(settings.runtime_intelligence_repeat_threshold or 3))
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.tenant_id == tenant_id,
            AISystem.name == candidate_name,
        )
    )
    created = False
    if ai_system is None:
        ai_system = AISystem(
            tenant_id=tenant_id,
            name=candidate_name,
            description="Auto-registered from unknown AI usage detected on an enforcement path.",
            risk_tier="HIGH",
            status="pending_review",
            metadata_json={
                "source": "SHADOW_DISCOVERY",
                "governance_state": "REVIEW",
                "lifecycle_state": "PENDING_REVIEW",
                "ownership_state": "UNKNOWN",
                "business_owner": "UNKNOWN",
                "technical_owner": "UNKNOWN",
                "discovered_via": [source_surface],
                "classification_inference": {
                    "ai_type": "unknown",
                    "deployment_type": "unknown",
                    "data_access": "unknown",
                },
                "strict_unknown_usage_blocking": False,
                "require_justification_on_repeated_shadow_usage": False,
                "notify_admin_on_repeat_shadow_usage": False,
                "shadow_usage_repeat_count": 1,
                "requires_reapproval": True,
            },
        )
        db.add(ai_system)
        db.flush()
        created = True

    metadata = dict(ai_system.metadata_json or {})
    previous_repeat = _safe_int(metadata.get("shadow_usage_repeat_count"), fallback=0)
    if created and previous_repeat <= 0:
        repeat_count = 1
    else:
        repeat_count = max(1, previous_repeat + 1)
    strict_unknown_usage_blocking = bool(metadata.get("strict_unknown_usage_blocking")) or repeat_count >= repeat_threshold
    require_justification = bool(metadata.get("require_justification_on_repeated_shadow_usage")) or repeat_count >= repeat_threshold
    notify_admin = bool(metadata.get("notify_admin_on_repeat_shadow_usage")) or repeat_count >= repeat_threshold
    discovered_via = [str(item).strip() for item in (metadata.get("discovered_via") or []) if str(item).strip()]
    if source_surface not in discovered_via:
        discovered_via.append(source_surface)

    metadata.update(
        {
            "source": str(metadata.get("source") or "SHADOW_DISCOVERY"),
            "governance_state": str(metadata.get("governance_state") or "REVIEW"),
            "lifecycle_state": str(metadata.get("lifecycle_state") or "PENDING_REVIEW"),
            "ownership_state": str(metadata.get("ownership_state") or "UNKNOWN"),
            "business_owner": str(metadata.get("business_owner") or "UNKNOWN"),
            "technical_owner": str(metadata.get("technical_owner") or "UNKNOWN"),
            "strict_unknown_usage_blocking": strict_unknown_usage_blocking,
            "require_justification_on_repeated_shadow_usage": require_justification,
            "notify_admin_on_repeat_shadow_usage": notify_admin,
            "shadow_usage_repeat_count": repeat_count,
            "requires_reapproval": True,
            "discovered_via": sorted(set(discovered_via)),
            "classification_inference": {
                **dict(metadata.get("classification_inference") or {}),
                "ai_type": "unknown",
                "deployment_type": "unknown",
                "data_access": str(
                    (dict(metadata.get("classification_inference") or {})).get("data_access") or "unknown"
                ),
            },
        }
    )
    ai_system.risk_tier = "HIGH"
    ai_system.status = "pending_review"
    ai_system.metadata_json = metadata
    db.flush()

    if notify_admin and repeat_count >= repeat_threshold:
        signal = MonitoringSignal(
            tenant_id=tenant_id,
            ai_system_id=ai_system.id,
            signal_type="remediation.shadow_ai.repeat_usage_admin_notification",
            severity="high",
            payload={
                "ai_system_id": ai_system.id,
                "reason_code": reason_code,
                "repeat_count": repeat_count,
                "strict_unknown_usage_blocking": strict_unknown_usage_blocking,
                "require_justification": require_justification,
                "recommended_action": "notify_admin_and_require_justification",
            },
        )
        db.add(signal)
        db.flush()


def _emit_unregistered_ai_finding(
    db: Session,
    *,
    tenant_id: str,
    requested_ai_system_id: str | None,
    correlation_id: str | None,
    route: str,
    module: str,
    reason_code: str,
    evidence_node_id: str,
) -> None:
    source_surface = _source_surface(route, module)
    evidence_ids = [evidence_node_id]
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_runtime_event
        from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

        runtime_row = ingest_runtime_event(
            db,
            payload=RuntimeEventIngestPayload(
                tenant_id=tenant_id,
                source_surface=source_surface,  # type: ignore[arg-type]
                event_type="unregistered_ai_system",
                ai_system_id=None,
                app_id=(requested_ai_system_id or route),
                user_id=None,
                agent_id=None,
                risk_tier="HIGH",
                policy_version_id=None,
                governance_version=GOVERNANCE_VERSION,
                severity="high",
                confidence_tier="clear_positive",
                evidence_node_ids=[evidence_node_id],
                correlation_id=correlation_id,
                metadata={
                    "requested_ai_system_id": requested_ai_system_id,
                    "governance_state": "UNKNOWN",
                    "governance_reason": reason_code,
                    "route": route,
                    "module": module,
                },
            ),
        )
        if runtime_row is not None and runtime_row.evidence_node_ids:
            evidence_ids = [str(node_id) for node_id in runtime_row.evidence_node_ids if str(node_id).strip()]
    except Exception as exc:  # pragma: no cover - must remain non-blocking
        log_structured(
            "governance_unknown_runtime_ingest_failed",
            module="governance_guard",
            tenant_id=tenant_id,
            requested_ai_system_id=requested_ai_system_id,
            correlation_id=correlation_id,
            route=route,
            error=str(exc),
        )

    try:
        from app.services.findings_service import generate_unregistered_ai_system_finding

        generate_unregistered_ai_system_finding(
            db,
            tenant_id=tenant_id,
            source_surface=source_surface,
            ai_tool=(requested_ai_system_id or route or "unknown_ai_system"),
            requested_ai_system_id=requested_ai_system_id,
            policy_version_id=None,
            evidence_node_ids=evidence_ids,
            recommended_action=(
                "Unknown AI system detected on an enforcement path. Register it in Trust Center and approve governance state before use."
            ),
        )
    except Exception as exc:  # pragma: no cover - must remain non-blocking
        log_structured(
            "governance_unknown_finding_failed",
            module="governance_guard",
            tenant_id=tenant_id,
            requested_ai_system_id=requested_ai_system_id,
            correlation_id=correlation_id,
            route=route,
            error=str(exc),
        )


def _emit_log_pair(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    correlation_id: str | None,
    action: str,
    node_type: str,
    signal_type: str,
    label: str,
    payload: dict[str, Any],
) -> tuple[str, str]:
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action=action,
        resource_type="ai_system" if ai_system_id else "tenant",
        resource_id=ai_system_id or tenant_id,
        payload=payload,
        correlation_id=correlation_id,
    )
    node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type=node_type,
        signal_type=signal_type,
        label=label,
        payload=payload,
        correlation_id=correlation_id,
    )
    return audit.id, node.id


def _emit_with_optional_legacy(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    correlation_id: str | None,
    action: str,
    node_type: str,
    signal_type: str,
    label: str,
    payload: dict[str, Any],
    legacy_action: str | None = None,
    legacy_node_type: str | None = None,
    legacy_signal_type: str | None = None,
    legacy_label: str | None = None,
) -> dict[str, Any]:
    canonical_audit_id, canonical_node_id = _emit_log_pair(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        correlation_id=correlation_id,
        action=action,
        node_type=node_type,
        signal_type=signal_type,
        label=label,
        payload=payload,
    )
    out: dict[str, Any] = {
        "canonical_audit_log_id": canonical_audit_id,
        "canonical_evidence_node_id": canonical_node_id,
    }

    if settings.event_dual_write_legacy and legacy_action and legacy_node_type and legacy_signal_type:
        legacy_audit_id, legacy_node_id = _emit_log_pair(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            correlation_id=correlation_id,
            action=legacy_action,
            node_type=legacy_node_type,
            signal_type=legacy_signal_type,
            label=legacy_label or label,
            payload=payload,
        )
        out["legacy_audit_log_id"] = legacy_audit_id
        out["legacy_evidence_node_id"] = legacy_node_id
    return out


def _best_effort_fail_secure_logs(
    *,
    tenant_id: str,
    ai_system_id: str | None,
    correlation_id: str | None,
    route: str,
    module: str,
    governance_action: str,
    reason_code: str,
) -> None:
    payload = _metadata_payload(
        reason_code=reason_code,
        correlation_id=correlation_id,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        route=route,
        module=module,
        governance_action=governance_action,
    )
    try:
        with SessionLocal() as fallback_db:
            _emit_with_optional_legacy(
                fallback_db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                correlation_id=correlation_id,
                action="governance.fail_secure.activated",
                node_type="fail_secure_block",
                signal_type="governance.fail_secure.activated",
                label=f"Fail-secure activated for {module}",
                payload=payload,
                legacy_action="fail_secure_block",
                legacy_node_type="fail_secure_block",
                legacy_signal_type="control_plane.fail_secure",
                legacy_label=f"Fail secure activated for {module}",
            )
            _emit_with_optional_legacy(
                fallback_db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                correlation_id=correlation_id,
                action="governance.fail_secure.blocked",
                node_type="fail_secure_block",
                signal_type="governance.fail_secure.blocked",
                label=f"Fail-secure blocked {module}",
                payload=payload,
                legacy_action="fail_secure_block",
                legacy_node_type="fail_secure_block",
                legacy_signal_type="control_plane.fail_secure",
                legacy_label=f"Fail secure blocked {module}",
            )
            fallback_db.commit()
    except Exception:
        return


def enforce(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    action: str,
    route: str,
    module: str,
    tenant_scope: bool = False,
    commit_logs: bool = False,
    emit_logs: bool = True,
    missing_ai_reason_code: str = "ai_system_id_missing",
    missing_ai_message: str = "ai_system_id is required",
) -> GovernanceCheckResult:
    correlation_id = get_correlation_id()

    if not ai_system_id and not tenant_scope:
        payload = _metadata_payload(
            reason_code=missing_ai_reason_code,
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            route=route,
            module=module,
            governance_action=action,
        )
        if emit_logs:
            _emit_with_optional_legacy(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                correlation_id=correlation_id,
                action="governance.context.blocked",
                node_type="governance_context_block",
                signal_type="governance.context.blocked",
                label=f"Governance context blocked for {module}",
                payload=payload,
                legacy_action="governance_violation",
                legacy_node_type="governance_violation",
                legacy_signal_type="governance.violation",
                legacy_label=f"Governance violation for {module}",
            )
            try:
                node = create_evidence_node(
                    db,
                    tenant_id=tenant_id,
                    node_type="governance_context_block",
                    signal_type="governance.context.blocked",
                    label=f"Missing ai_system_id blocked for {module}",
                    payload=payload,
                    correlation_id=correlation_id,
                )
                _emit_unregistered_ai_finding(
                    db,
                    tenant_id=tenant_id,
                    requested_ai_system_id=None,
                    correlation_id=correlation_id,
                    route=route,
                    module=module,
                    reason_code=missing_ai_reason_code,
                    evidence_node_id=node.id,
                )
            except Exception:
                pass
        if commit_logs and emit_logs:
            db.commit()
        raise GovernanceViolationError(
            missing_ai_reason_code,
            status_code=400,
            message=missing_ai_message,
        )

    try:
        _check_db_connectivity(db)
    except SQLAlchemyError as exc:
        _best_effort_fail_secure_logs(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            correlation_id=correlation_id,
            route=route,
            module=module,
            governance_action=action,
            reason_code="db_unavailable",
        )
        raise GovernanceFailSecureError(reason_code="db_unavailable") from exc

    check_payload = _metadata_payload(
        reason_code="check_started",
        correlation_id=correlation_id,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        route=route,
        module=module,
        governance_action=action,
    )
    if emit_logs:
        _emit_with_optional_legacy(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            correlation_id=correlation_id,
            action="governance.context.check",
            node_type="governance_context_check",
            signal_type="governance.context.check",
            label=f"Governance context check for {module}",
            payload=check_payload,
        )

    ai_system: AISystem | None = None
    governance_resolution = resolve_ai_system_status(
        ai_system_id,
        {
            "db": db,
            "tenant_id": tenant_id,
            "route": route,
            "module": module,
            "source_hint": "trust_center",
        },
    )
    if ai_system_id:
        try:
            ai_system = db.scalar(
                select(AISystem).where(
                    AISystem.id == ai_system_id,
                    AISystem.tenant_id == tenant_id,
                )
            )
        except SQLAlchemyError as exc:
            _best_effort_fail_secure_logs(
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                correlation_id=correlation_id,
                route=route,
                module=module,
                governance_action=action,
                reason_code="governance_query_failed",
            )
            raise GovernanceFailSecureError(reason_code="governance_query_failed") from exc

        if governance_resolution.get("status") == "UNKNOWN" or ai_system is None:
            reason_code = str(governance_resolution.get("reason") or "ai_system_not_registered")
            if emit_logs:
                _ensure_unknown_ai_candidate(
                    db,
                    tenant_id=tenant_id,
                    requested_ai_system_id=ai_system_id,
                    route=route,
                    module=module,
                    reason_code=reason_code,
                )
                blocked_payload = _metadata_payload(
                    reason_code=reason_code,
                    correlation_id=correlation_id,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    route=route,
                    module=module,
                    governance_action=action,
                )
                emitted = _emit_with_optional_legacy(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    correlation_id=correlation_id,
                    action="governance.context.blocked",
                    node_type="governance_context_block",
                    signal_type="governance.context.blocked",
                    label=f"Governance context blocked for {module}",
                    payload=blocked_payload,
                    legacy_action="governance_violation",
                    legacy_node_type="governance_violation",
                    legacy_signal_type="governance.violation",
                    legacy_label=f"Governance violation for {module}",
                )
                _emit_unregistered_ai_finding(
                    db,
                    tenant_id=tenant_id,
                    requested_ai_system_id=ai_system_id,
                    correlation_id=correlation_id,
                    route=route,
                    module=module,
                    reason_code=reason_code,
                    evidence_node_id=str(emitted.get("canonical_evidence_node_id") or ""),
                )
            should_block_unknown = (
                settings.governance_strict_mode
                or str(route or "").strip().lower().startswith("/gateway")
                or str(route or "").strip().lower().startswith("/llm-gateway")
                or str(module or "").strip().lower() in {"gateway", "gateway_service"}
            )
            if commit_logs and emit_logs:
                db.commit()
            if should_block_unknown:
                raise GovernanceViolationError(reason_code, status_code=403)
            return GovernanceCheckResult(
                ai_system_id=ai_system_id,
                reason_code=reason_code,
                governance_state="UNKNOWN",
                lifecycle_state=None,
                risk_tier="HIGH",
                status="UNKNOWN",
                enforcement_mode=str(governance_resolution.get("enforcement_mode") or "monitor"),
                source=str(governance_resolution.get("source") or "shadow_discovery"),
            )

    governance_state = str(governance_resolution.get("status") or "").strip().upper() if ai_system is not None else None
    lifecycle_state = _resolve_lifecycle_state(ai_system) if ai_system is not None else None
    risk_tier = str(ai_system.risk_tier).strip().upper() if ai_system is not None and ai_system.risk_tier else None

    if ai_system is not None and not risk_tier:
        if emit_logs:
            blocked_payload = _metadata_payload(
                reason_code="risk_tier_missing",
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                route=route,
                module=module,
                governance_action=action,
            )
            _emit_with_optional_legacy(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                correlation_id=correlation_id,
                action="governance.context.blocked",
                node_type="governance_context_block",
                signal_type="governance.context.blocked",
                label=f"Governance context blocked for {module}",
                payload=blocked_payload,
                legacy_action="governance_violation",
                legacy_node_type="governance_violation",
                legacy_signal_type="governance.violation",
                legacy_label=f"Governance violation for {module}",
            )
        if commit_logs and emit_logs:
            db.commit()
        raise GovernanceViolationError("risk_tier_missing", status_code=403)

    if ai_system is not None and governance_state != "APPROVED":
        if emit_logs:
            blocked_payload = _metadata_payload(
                reason_code="governance_state_not_approved",
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                route=route,
                module=module,
                governance_action=action,
            )
            _emit_with_optional_legacy(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                correlation_id=correlation_id,
                action="governance.context.blocked",
                node_type="governance_context_block",
                signal_type="governance.context.blocked",
                label=f"Governance context blocked for {module}",
                payload=blocked_payload,
                legacy_action="governance_violation",
                legacy_node_type="governance_violation",
                legacy_signal_type="governance.violation",
                legacy_label=f"Governance violation for {module}",
            )
        if commit_logs and emit_logs:
            db.commit()
        raise GovernanceViolationError("governance_state_not_approved", status_code=403)

    if ai_system is not None and (
        (lifecycle_state or "") in PROHIBITED_LIFECYCLE_STATES or (risk_tier or "") in PROHIBITED_RISK_TIERS
    ):
        if emit_logs:
            blocked_payload = _metadata_payload(
                reason_code="lifecycle_state_prohibited",
                correlation_id=correlation_id,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                route=route,
                module=module,
                governance_action=action,
            )
            _emit_with_optional_legacy(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                correlation_id=correlation_id,
                action="governance.context.blocked",
                node_type="governance_context_block",
                signal_type="governance.context.blocked",
                label=f"Governance context blocked for {module}",
                payload=blocked_payload,
                legacy_action="governance_violation",
                legacy_node_type="governance_violation",
                legacy_signal_type="governance.violation",
                legacy_label=f"Governance violation for {module}",
            )
        if commit_logs and emit_logs:
            db.commit()
        raise GovernanceViolationError("lifecycle_state_prohibited", status_code=403)

    ok_payload = _metadata_payload(
        reason_code="ok",
        correlation_id=correlation_id,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        route=route,
        module=module,
        governance_action=action,
    )
    if emit_logs:
        _emit_with_optional_legacy(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            correlation_id=correlation_id,
            action="governance.context.ok",
            node_type="governance_context_check",
            signal_type="governance.context.ok",
            label=f"Governance context ok for {module}",
            payload=ok_payload,
        )

    if commit_logs and emit_logs:
        db.commit()

    return GovernanceCheckResult(
        ai_system_id=ai_system_id,
        reason_code="ok",
        governance_state=governance_state,
        lifecycle_state=lifecycle_state,
        risk_tier=risk_tier,
        status=str(governance_resolution.get("status") or governance_state or "").upper() or None,
        enforcement_mode=str(governance_resolution.get("enforcement_mode") or "").strip().lower() or None,
        source=str(governance_resolution.get("source") or "").strip().lower() or None,
    )
