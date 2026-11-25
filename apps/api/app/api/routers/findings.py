from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.auth import get_current_user
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.discovery import DiscoveryApplication
from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.maturity import ControlMaturity
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.remediation import RemediationAction
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.db.models.snapshot import AuditorSnapshot
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.discovery_service import tool_key_for_name
from app.services.evidence_service import create_evidence_node
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError
from app.services.remediation import (
    apply_remediation_action,
    approve_remediation_action,
    list_remediation_actions,
    reject_remediation_action,
    rollback_remediation_action,
)
from app.services.simulation_service import run_simulation


router = APIRouter(prefix="/findings", tags=["findings"])

ALLOWED_FINDING_STATUSES = {"open", "reviewing", "resolved", "accepted_risk"}
ESCALATION_CHAIN = ["low", "med", "high", "critical"]


class ChainReplayCompletenessResponse(BaseModel):
    has_finding: bool
    has_action: bool
    has_policy: bool
    has_chain: bool
    has_evidence: bool
    has_trace: bool


class ChainReplayItemResponse(BaseModel):
    stage: str
    title: str
    status: str
    timestamp: datetime | None = None
    summary: str
    references: dict[str, Any] = Field(default_factory=dict)
    href: str | None = None
    control_mode: str | None = None
    decision: str | None = None


class ChainReplayResponse(BaseModel):
    finding_id: str
    chain_id: str | None = None
    root_action_id: str | None = None
    control_mode: str | None = None
    decision: str | None = None
    integrity_status: str
    completeness: ChainReplayCompletenessResponse
    items: list[ChainReplayItemResponse]


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    tenant_id: str
    source_surface: str
    ai_tool: str
    ai_system_id: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    agent_id: str | None = None
    machine_id: str | None = None
    browser_type: str | None = None
    application: str | None = None
    department: str | None = None
    severity: str
    finding_type: str
    risk_category: str
    data_classification: str | None = None
    decision: str | None = None
    status: str
    recommended_action: str
    policy_id: str | None = None
    policy_version_id: str | None = None
    evidence_node_ids: list
    evidence_status: str | None = None
    related_event_ids: list
    related_control_ids: list
    remediation_action_ids: list
    related_runtime_event_id: str | None = None
    related_trace_ids: list[str] = Field(default_factory=list)
    ai_action_id: str | None = None
    control_mode: str | None = None
    decision_badge: str | None = None
    policy_snapshot: dict[str, Any] = Field(default_factory=dict)
    decision_explanation: dict[str, Any] = Field(default_factory=dict)
    evidence_bundle: dict[str, Any] = Field(default_factory=dict)
    recommended_actions: list[str] = Field(default_factory=list)
    action_panel: list[dict[str, Any]] = Field(default_factory=list)
    drilldowns: list[dict[str, Any]] = Field(default_factory=list)
    chain_replay: ChainReplayResponse | None = None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class FindingStatusUpdateRequest(BaseModel):
    status: str


class FindingAcceptRecommendationRequest(BaseModel):
    note: str | None = None


class FindingAssignOwnerRequest(BaseModel):
    owner_user_id: str | None = None
    owner_department: str | None = None


class FindingEscalateRequest(BaseModel):
    reason: str | None = None


class FindingValidationPackRequest(BaseModel):
    simulation_ids: list[str] = Field(default_factory=list)
    mode: str = "deterministic"
    limit: int = Field(default=3, ge=1, le=10)
    inputs_used: dict = Field(default_factory=dict)


class FindingCreateTicketRequest(BaseModel):
    system: str = "jira"
    severity_override: str | None = None
    note: str | None = None


class FindingValidationRunItemResponse(BaseModel):
    simulation_id: str
    simulation_name: str
    run_id: str
    result: str
    pass_rate: float
    evidence_node_ids: list[str]
    control_maturity_delta: list[dict]
    enforcement_strictness_delta: list[dict]


class FindingValidationPackResponse(BaseModel):
    finding_id: str
    ai_system_id: str
    total_runs: int
    runs: list[FindingValidationRunItemResponse]


class FindingTicketResponse(BaseModel):
    finding: FindingResponse
    ticket_id: str
    ticket_system: str
    severity: str
    created_at: datetime


class RemediationActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    remediation_type: str
    target_type: str
    target_id: str
    source_trigger_type: str
    source_trigger_id: str
    recommendation_text: str
    action_mode: str
    status: str
    risk_level: str
    requires_approval: bool
    approved_by: str | None = None
    justification: str | None = None
    rollback_supported: bool
    rollback_payload: dict
    created_at: datetime
    applied_at: datetime | None = None


class RemediationActionRequest(BaseModel):
    justification: str | None = None


class PolicyVersionSummaryResponse(BaseModel):
    id: str
    version: str
    pack_id: str
    pack_name: str | None = None
    created_at: datetime


class EvidenceNodeSummaryResponse(BaseModel):
    id: str
    correlation_id: str | None = None
    node_type: str
    signal_type: str
    label: str
    payload: dict
    created_at: datetime


class ControlSummaryResponse(BaseModel):
    id: str
    name: str
    category: str
    description: str
    mapped_framework_refs: list[dict]


class EnforcementEventSummaryResponse(BaseModel):
    id: str
    correlation_id: str | None = None
    request_id: str
    timestamp: datetime
    final_decision: str
    policy_version_id: str | None = None
    evidence_nodes_created: list
    controls_impacted: list
    audit_log_id: str


class SimulationRunSummaryResponse(BaseModel):
    id: str
    simulation_id: str
    started_at: datetime
    finished_at: datetime | None = None
    mode: str
    result: str
    pass_rate: float
    evidence_node_ids: list[str]
    control_maturity_delta: list[dict]
    enforcement_strictness_delta: list[dict]


class ControlMaturitySummaryResponse(BaseModel):
    control_id: str
    maturity_score: float
    status: str
    confidence_score: float
    technical_enforcement_score: float
    simulation_pass_rate: float
    coverage_score: float
    updated_at: datetime


class AuditorSnapshotSummaryResponse(BaseModel):
    id: str
    ai_system_id: str | None = None
    trigger_type: str
    artifact_path: str
    artifact_hash: str
    created_at: datetime


class DiscoveryApplicationSummaryResponse(BaseModel):
    id: str
    tool_key: str
    tool_name: str
    vendor: str
    status: str
    owner_user_id: str | None = None
    owner_department: str | None = None
    provisional_risk_tier: str | None = None
    ai_system_id: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime


class ProofTimelineStepResponse(BaseModel):
    step: int
    title: str
    status: str
    timestamp: datetime | None = None
    summary: str
    references: dict[str, Any]


class FindingTraceabilityResponse(BaseModel):
    finding: FindingResponse
    discovery_application: DiscoveryApplicationSummaryResponse | None = None
    policy_version: PolicyVersionSummaryResponse | None = None
    evidence_nodes: list[EvidenceNodeSummaryResponse]
    related_controls: list[ControlSummaryResponse]
    enforcement_events: list[EnforcementEventSummaryResponse]
    simulation_runs: list[SimulationRunSummaryResponse]
    maturity_effects: list[ControlMaturitySummaryResponse]
    auditor_snapshots: list[AuditorSnapshotSummaryResponse]
    gateway_traces: list[dict[str, Any]]
    recommended_actions: list[str]
    action_panel: list[dict[str, Any]]
    proof_timeline: list[ProofTimelineStepResponse]
    chain_replay: ChainReplayResponse | None = None


def _normalize_severity(value: str | None) -> str:
    normalized = str(value or "low").strip().lower()
    if normalized == "medium":
        return "med"
    if normalized not in {"low", "med", "high", "critical"}:
        return "low"
    return normalized


def _escalate_severity(current: str) -> str:
    normalized = _normalize_severity(current)
    idx = ESCALATION_CHAIN.index(normalized)
    return ESCALATION_CHAIN[min(idx + 1, len(ESCALATION_CHAIN) - 1)]


def _unique_strings(values: list[Any]) -> list[str]:
    out = sorted({str(value).strip() for value in values if str(value).strip()})
    return out


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _first_nested_string(value: Any, keys: set[str], depth: int = 0) -> str | None:
    if depth > 5:
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys and str(item or "").strip():
                return str(item).strip()
            nested = _first_nested_string(item, keys, depth + 1)
            if nested:
                return nested
    if isinstance(value, list):
        for item in value:
            nested = _first_nested_string(item, keys, depth + 1)
            if nested:
                return nested
    return None


def _looks_like_chain_id(value: str) -> bool:
    normalized = str(value or "").strip().lower()
    return bool(normalized) and (
        normalized.startswith("chain")
        or normalized.startswith("aci-chain")
        or "chain_" in normalized
        or "chain-" in normalized
    )


def _overlap(left: list[str], right: list[str]) -> bool:
    if not left or not right:
        return False
    return bool(set(left).intersection(set(right)))


def _finding_or_404(db: Session, *, finding_id: str, tenant_id: str) -> Finding:
    row = db.scalar(
        select(Finding).where(
            Finding.finding_id == finding_id,
            Finding.tenant_id == tenant_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return row


def _split_recommended_actions(finding: Finding) -> list[str]:
    raw = str(finding.recommended_action or "").strip()
    if not raw:
        return []
    actions = [line.strip(" -\t") for line in raw.splitlines() if line.strip(" -\t")]
    return actions or [raw]


def _gateway_trace_from_event(event: EnforcementEvent) -> dict[str, Any] | None:
    if not isinstance(event.final_actions, dict):
        return None
    trace = event.final_actions.get("_trace")
    if not isinstance(trace, dict):
        return None
    out = dict(trace)
    out.setdefault("trace_id", event.request_id)
    out.setdefault("decision", event.final_decision)
    out.setdefault("policy_applied", event.policy_version_id)
    out.setdefault("timestamp", event.timestamp.isoformat() if event.timestamp else None)
    out["enforcement_event_id"] = event.id
    out["request_id"] = event.request_id
    out["correlation_id"] = event.correlation_id
    return out


def _matched_gateway_events(db: Session, *, finding: Finding, tenant_id: str, limit: int = 25) -> list[EnforcementEvent]:
    evidence_ids = _unique_strings(finding.evidence_node_ids or [])
    related_event_ids = set(_unique_strings(finding.related_event_ids or []))
    pool = db.scalars(
        select(EnforcementEvent).where(EnforcementEvent.tenant_id == tenant_id).order_by(EnforcementEvent.timestamp.desc()).limit(200)
    ).all()
    matched: list[EnforcementEvent] = []
    for event in pool:
        if event.id in related_event_ids or event.request_id in related_event_ids:
            matched.append(event)
            continue
        if finding.ai_system_id and event.ai_system_id != finding.ai_system_id:
            continue
        event_evidence_ids = _unique_strings(event.evidence_nodes_created or [])
        policy_match = bool(finding.policy_version_id and event.policy_version_id == finding.policy_version_id)
        evidence_match = _overlap(event_evidence_ids, evidence_ids)
        if evidence_match or policy_match:
            matched.append(event)
    if not matched and finding.finding_type == "enforcement_event" and finding.ai_system_id:
        for event in pool:
            if event.ai_system_id == finding.ai_system_id:
                matched.append(event)
                break
    deduped: dict[str, EnforcementEvent] = {}
    for event in matched:
        deduped[event.id] = event
    return sorted(deduped.values(), key=lambda row: (row.timestamp, row.id), reverse=True)[:limit]


def _gateway_traces_for_finding(db: Session, *, finding: Finding, tenant_id: str, limit: int = 25) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for event in _matched_gateway_events(db, finding=finding, tenant_id=tenant_id, limit=limit):
        trace = _gateway_trace_from_event(event)
        if trace:
            traces.append(trace)
    return traces


def _runtime_events_for_finding(db: Session, *, finding: Finding, tenant_id: str) -> list[RuntimeEvent]:
    event_ids = _unique_strings(
        [
            finding.related_runtime_event_id,
            *(finding.related_event_ids or []),
        ]
    )
    if not event_ids:
        return []
    rows = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.event_id.in_(event_ids),
        )
    ).all()
    ordered = {row.event_id: row for row in rows}
    return [ordered[event_id] for event_id in event_ids if event_id in ordered]


def _evidence_ai_action_for_finding(db: Session, *, finding: Finding, tenant_id: str) -> dict[str, Any]:
    evidence_ids = _unique_strings(finding.evidence_node_ids or [])
    if not evidence_ids:
        return {}
    rows = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id.in_(evidence_ids),
        )
    ).all()
    for row in rows:
        payload = _safe_dict(row.payload)
        ai_action = _safe_dict(payload.get("ai_action"))
        if ai_action:
            return ai_action
    return {}


def _public_decision_badge(control_mode: str | None, decision_badge: str | None) -> str | None:
    normalized_mode = str(control_mode or "").strip().lower()
    if normalized_mode == "inline_prevented":
        return "Prevented"
    if normalized_mode == "warned":
        return "Warned"
    if normalized_mode == "inline_allowed":
        return "Allowed"
    if normalized_mode in {"detected_only", "telemetry_only"}:
        return "Detected-only"
    if normalized_mode == "shadow_would_block":
        return "Shadow would block"
    if normalized_mode == "external_required":
        return "External required"
    if normalized_mode == "external_action_triggered":
        return "External action triggered"
    if normalized_mode == "incomplete":
        return "Incomplete"
    return str(decision_badge or "").strip() or None


def _decision_spine_for_finding(db: Session, *, finding: Finding, tenant_id: str) -> dict[str, Any]:
    ai_action: dict[str, Any] = {}
    runtime_metadata: dict[str, Any] = {}
    for runtime_event in _runtime_events_for_finding(db, finding=finding, tenant_id=tenant_id):
        runtime_metadata = _safe_dict(runtime_event.metadata_json)
        ai_action = _safe_dict(runtime_metadata.get("ai_action"))
        if ai_action:
            break
    if not ai_action:
        ai_action = _evidence_ai_action_for_finding(db, finding=finding, tenant_id=tenant_id)

    policy = _safe_dict(ai_action.get("policy"))
    policy_snapshot = _safe_dict(ai_action.get("policy_snapshot") or runtime_metadata.get("policy_snapshot"))
    decision_explanation = _safe_dict(
        ai_action.get("decision_explanation") or runtime_metadata.get("decision_explanation")
    )
    evidence_bundle = _safe_dict(ai_action.get("evidence_bundle") or runtime_metadata.get("evidence_bundle"))
    control_mode = str(policy.get("control_mode") or runtime_metadata.get("control_mode") or "").strip() or None
    decision_badge = _public_decision_badge(
        control_mode,
        str(policy.get("decision_badge") or runtime_metadata.get("decision_badge") or "").strip() or None,
    )

    if decision_explanation and control_mode and not decision_explanation.get("control_mode"):
        decision_explanation = {
            **decision_explanation,
            "control_mode": control_mode,
        }
    if decision_explanation and decision_badge and not decision_explanation.get("decision_badge"):
        decision_explanation = {
            **decision_explanation,
            "decision_badge": decision_badge,
        }

    return {
        "ai_action_id": str(ai_action.get("action_id") or "").strip() or None,
        "control_mode": control_mode,
        "decision_badge": decision_badge,
        "policy_snapshot": policy_snapshot,
        "decision_explanation": decision_explanation,
        "evidence_bundle": evidence_bundle,
    }


def _action_panel_for_finding(finding: Finding) -> list[dict[str, Any]]:
    base_context = {
        "finding_id": finding.finding_id,
        "user_id": finding.user_id,
        "agent_id": finding.agent_id,
        "machine_id": finding.machine_id,
        "policy_version_id": finding.policy_version_id,
    }
    actions = [
        {
            "action": "route_finding",
            "label": "Route finding",
            "method": "POST",
            "endpoint": f"/findings/{finding.finding_id}/assign-owner",
            "enabled": True,
            "context": base_context,
        },
        {
            "action": "run_validation",
            "label": "Run validation pack",
            "method": "POST",
            "endpoint": f"/findings/{finding.finding_id}/run-validation-pack",
            "enabled": bool(finding.ai_system_id),
            "context": base_context,
        },
        {
            "action": "create_ticket",
            "label": "Create ticket",
            "method": "POST",
            "endpoint": f"/findings/{finding.finding_id}/create-ticket",
            "enabled": True,
            "context": base_context,
        },
        {
            "action": "block_user",
            "label": "Block user",
            "method": "POST",
            "endpoint": f"/ai-iam/users/{finding.user_id}/disable" if finding.user_id else None,
            "enabled": bool(finding.user_id),
            "context": base_context,
        },
        {
            "action": "disable_agent",
            "label": "Disable agent",
            "method": "POST",
            "endpoint": f"/ai-iam/agents/{finding.agent_id}/disable" if finding.agent_id else None,
            "enabled": bool(finding.agent_id),
            "context": base_context,
        },
        {
            "action": "revoke_token",
            "label": "Revoke token",
            "method": "POST",
            "endpoint": f"/ai-iam/agents/{finding.agent_id}/tokens/revoke" if finding.agent_id else None,
            "enabled": bool(finding.agent_id),
            "context": base_context,
        },
        {
            "action": "enforce_strict_policy",
            "label": "Enforce strict policy",
            "method": "POST",
            "endpoint": "/policies/packs",
            "enabled": bool(finding.policy_version_id or finding.ai_system_id),
            "context": base_context,
        },
    ]
    return actions


def _chain_id_for_finding(*, decision_spine: dict[str, Any], related_trace_ids: list[str]) -> str | None:
    chain_id = _first_nested_string(
        decision_spine,
        {
            "chain_id",
            "agentic_chain_id",
            "root_chain_id",
            "action_chain_id",
        },
    )
    if chain_id:
        return chain_id
    for trace_id in related_trace_ids:
        if _looks_like_chain_id(trace_id):
            return trace_id
    return None


def _drilldowns_for_finding(
    finding: Finding,
    *,
    decision_spine: dict[str, Any],
    related_trace_ids: list[str],
) -> list[dict[str, Any]]:
    finding_id = str(finding.finding_id)
    action_id = str(decision_spine.get("ai_action_id") or "").strip()
    chain_id = _chain_id_for_finding(decision_spine=decision_spine, related_trace_ids=related_trace_ids)
    raw: list[dict[str, Any]] = [
        {
            "type": "finding_detail",
            "label": "Finding detail",
            "href": f"/discovery/findings/{finding_id}",
            "enabled": True,
        },
        {
            "type": "traceability",
            "label": "Traceability",
            "href": f"/discovery/findings/{finding_id}#traceability",
            "enabled": True,
        },
        {
            "type": "evidence",
            "label": "Evidence",
            "href": f"/discovery/findings/{finding_id}#evidence",
            "enabled": True,
        },
    ]
    if action_id:
        raw.extend(
            [
                {
                    "type": "action_trace",
                    "label": "Action trace",
                    "href": f"/runtime-intelligence/action-trace/{action_id}",
                    "enabled": True,
                },
                {
                    "type": "action_graph",
                    "label": "Action graph",
                    "href": f"/runtime-intelligence/action-graph/{action_id}",
                    "enabled": True,
                },
            ]
        )
    if chain_id:
        raw.extend(
            [
                {
                    "type": "chain_graph",
                    "label": "Chain graph",
                    "href": f"/runtime-intelligence/chains/{chain_id}/graph",
                    "enabled": True,
                },
                {
                    "type": "chain_evidence",
                    "label": "Chain evidence",
                    "href": f"/runtime-intelligence/chains/{chain_id}/evidence",
                    "enabled": True,
                },
            ]
        )
    if finding.agent_id:
        raw.append(
            {
                "type": "agent_touchpoints",
                "label": "Agent touchpoints",
                "href": f"/ai-iam/agents/{finding.agent_id}",
                "enabled": True,
            }
        )

    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in raw:
        deduped[(str(item.get("type")), str(item.get("href")))] = item
    return list(deduped.values())


def _chain_replay_for_finding(
    finding: Finding,
    *,
    decision_spine: dict[str, Any],
    related_trace_ids: list[str],
    evidence_node_ids: list[str] | None = None,
    gateway_traces: list[dict[str, Any]] | None = None,
) -> ChainReplayResponse:
    finding_id = str(finding.finding_id)
    ai_action_id = str(
        decision_spine.get("ai_action_id")
        or finding.related_runtime_event_id
        or ""
    ).strip()
    policy_snapshot = _safe_dict(decision_spine.get("policy_snapshot"))
    decision_explanation = _safe_dict(decision_spine.get("decision_explanation"))
    decision_summary = _safe_dict(decision_explanation.get("decision_summary"))
    evidence_bundle = _safe_dict(decision_spine.get("evidence_bundle"))
    evidence_ids = _unique_strings(evidence_node_ids if evidence_node_ids is not None else (finding.evidence_node_ids or []))
    traces = list(gateway_traces or [])
    chain_id = _chain_id_for_finding(decision_spine=decision_spine, related_trace_ids=related_trace_ids)
    control_mode = str(
        decision_spine.get("control_mode")
        or decision_summary.get("control_mode")
        or finding.decision
        or ""
    ).strip() or None
    decision = str(
        finding.decision
        or decision_summary.get("final_decision")
        or decision_explanation.get("final_decision")
        or ""
    ).strip() or None

    has_finding = True
    has_action = bool(ai_action_id)
    has_policy = bool(policy_snapshot or decision_explanation or finding.policy_version_id or finding.policy_id or finding.related_control_ids)
    has_chain = bool(chain_id)
    has_evidence = bool(evidence_ids or evidence_bundle)
    has_trace = bool(related_trace_ids or traces or finding.related_event_ids)
    integrity_status = str(evidence_bundle.get("integrity_status") or "").strip()
    if not integrity_status:
        integrity_status = "valid" if has_action and has_policy and has_evidence and has_trace else "incomplete"

    items = [
        ChainReplayItemResponse(
            stage="finding",
            title="Finding created",
            status=str(finding.status or "open"),
            timestamp=finding.first_seen_at or finding.created_at,
            summary=f"{finding.finding_type} detected on {finding.source_surface or 'unknown surface'}.",
            references={
                "finding_id": finding_id,
                "severity": finding.severity,
                "risk_category": finding.risk_category,
                "ai_tool": finding.ai_tool,
            },
            href=f"/discovery/findings/{finding_id}",
            control_mode=control_mode,
            decision=decision,
        ),
        ChainReplayItemResponse(
            stage="action",
            title="AI action recorded",
            status="linked" if has_action else "incomplete",
            timestamp=finding.updated_at,
            summary=(
                f"Finding links to canonical AI action {ai_action_id}."
                if has_action
                else "No canonical AI action id is linked yet."
            ),
            references={
                "ai_action_id": ai_action_id or None,
                "related_runtime_event_id": finding.related_runtime_event_id,
                "related_event_ids": finding.related_event_ids or [],
            },
            href=f"/runtime-intelligence/action-trace/{ai_action_id}" if ai_action_id else None,
            control_mode=control_mode,
            decision=decision,
        ),
        ChainReplayItemResponse(
            stage="chain",
            title="Action chain linked",
            status="linked" if has_chain else "incomplete",
            timestamp=finding.updated_at,
            summary=(
                f"Chain {chain_id} links this action to upstream and downstream context."
                if has_chain
                else "No chain id is available yet; replay is limited to finding/action/evidence context."
            ),
            references={"chain_id": chain_id},
            href=f"/runtime-intelligence/chains/{chain_id}/graph" if chain_id else None,
            control_mode=control_mode,
            decision=decision,
        ),
        ChainReplayItemResponse(
            stage="policy",
            title="Policy decision explained",
            status="linked" if has_policy else "incomplete",
            timestamp=finding.updated_at,
            summary=str(
                decision_summary.get("plain_english_reason")
                or decision_explanation.get("plain_english_reason")
                or (
                    f"Policy {finding.policy_id or finding.policy_version_id} is linked to this finding."
                    if has_policy
                    else "No policy snapshot or decision explanation is linked yet."
                )
            ),
            references={
                "policy_id": finding.policy_id,
                "policy_version_id": finding.policy_version_id,
                "policy_snapshot_id": policy_snapshot.get("policy_snapshot_id"),
                "decision_explanation_id": decision_explanation.get("explanation_id"),
                "control_ids": finding.related_control_ids or [],
            },
            control_mode=control_mode,
            decision=decision,
        ),
        ChainReplayItemResponse(
            stage="evidence",
            title="Evidence bundled",
            status=str(evidence_bundle.get("integrity_status") or ("linked" if has_evidence else "incomplete")),
            timestamp=finding.updated_at,
            summary=(
                f"{len(evidence_ids)} evidence nodes are linked to this finding."
                if evidence_ids
                else (
                    "Evidence bundle is linked to this finding."
                    if evidence_bundle
                    else "No evidence bundle or evidence node is linked yet."
                )
            ),
            references={
                "evidence_node_ids": evidence_ids,
                "evidence_bundle_id": evidence_bundle.get("evidence_bundle_id"),
                "bundle_hash": evidence_bundle.get("bundle_hash"),
                "integrity_status": evidence_bundle.get("integrity_status"),
            },
            href=f"/discovery/findings/{finding_id}#evidence",
            control_mode=control_mode,
            decision=decision,
        ),
        ChainReplayItemResponse(
            stage="trace",
            title="Execution trace linked",
            status="linked" if has_trace else "incomplete",
            timestamp=finding.last_seen_at or finding.updated_at,
            summary=(
                f"{len(related_trace_ids)} trace identifiers connect this finding to runtime execution."
                if related_trace_ids
                else (
                    f"{len(traces)} gateway traces are linked to this finding."
                    if traces
                    else "No execution trace is linked yet."
                )
            ),
            references={
                "trace_ids": related_trace_ids,
                "gateway_trace_count": len(traces),
            },
            href=f"/discovery/findings/{finding_id}#traceability",
            control_mode=control_mode,
            decision=decision,
        ),
    ]

    return ChainReplayResponse(
        finding_id=finding_id,
        chain_id=chain_id,
        root_action_id=ai_action_id or None,
        control_mode=control_mode,
        decision=decision,
        integrity_status=integrity_status,
        completeness=ChainReplayCompletenessResponse(
            has_finding=has_finding,
            has_action=has_action,
            has_policy=has_policy,
            has_chain=has_chain,
            has_evidence=has_evidence,
            has_trace=has_trace,
        ),
        items=items,
    )


def _finding_response(db: Session, *, finding: Finding, tenant_id: str) -> FindingResponse:
    traces = _gateway_traces_for_finding(db, finding=finding, tenant_id=tenant_id, limit=10)
    related_trace_ids = _unique_strings(
        [
            *(finding.related_event_ids or []),
            *[str(trace.get("trace_id") or "") for trace in traces],
            *[str(trace.get("request_id") or "") for trace in traces],
        ]
    )
    decision_spine = _decision_spine_for_finding(db, finding=finding, tenant_id=tenant_id)
    drilldowns = _drilldowns_for_finding(finding, decision_spine=decision_spine, related_trace_ids=related_trace_ids)
    chain_replay = _chain_replay_for_finding(
        finding,
        decision_spine=decision_spine,
        related_trace_ids=related_trace_ids,
        gateway_traces=traces,
    )
    return FindingResponse.model_validate(finding).model_copy(
        update={
            "related_trace_ids": related_trace_ids,
            **decision_spine,
            "recommended_actions": _split_recommended_actions(finding),
            "action_panel": _action_panel_for_finding(finding),
            "drilldowns": drilldowns,
            "chain_replay": chain_replay,
        }
    )


def _remediation_or_404(db: Session, *, remediation_id: str, tenant_id: str) -> RemediationAction:
    row = db.scalar(
        select(RemediationAction).where(
            RemediationAction.id == remediation_id,
            RemediationAction.tenant_id == tenant_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation action not found")
    return row


@router.get("", response_model=ListEnvelope[FindingResponse])
def list_findings(
    status_filter: str | None = None,
    severity_filter: str | None = None,
    finding_type_filter: str | None = None,
    department_filter: str | None = None,
    tool_filter: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("findings.view")),
    db: Session = Depends(get_db),
):
    query = select(Finding).where(Finding.tenant_id == ctx.tenant.id)
    if status_filter:
        query = query.where(Finding.status == status_filter)
    if severity_filter:
        query = query.where(Finding.severity == severity_filter)
    if finding_type_filter:
        query = query.where(Finding.finding_type == finding_type_filter)
    if department_filter:
        query = query.where(Finding.department == department_filter)
    if tool_filter:
        query = query.where(Finding.ai_tool == tool_filter)

    rows = db.scalars(query.order_by(Finding.updated_at.desc())).all()
    dto_rows = [_finding_response(db, finding=row, tenant_id=ctx.tenant.id) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[FindingResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/remediations", response_model=ListEnvelope[RemediationActionResponse])
def list_remediations(
    status_filter: str | None = None,
    source_trigger_type: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    finding_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("findings.view")),
    db: Session = Depends(get_db),
):
    rows = list_remediation_actions(
        db,
        tenant_id=ctx.tenant.id,
        status=status_filter,
        source_trigger_type=source_trigger_type,
        target_type=target_type,
        target_id=target_id,
        finding_id=finding_id,
    )
    dto_rows = [RemediationActionResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RemediationActionResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/{finding_id}/remediations", response_model=ListEnvelope[RemediationActionResponse])
def finding_remediations(
    finding_id: str,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("findings.view")),
    db: Session = Depends(get_db),
):
    _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)
    rows = list_remediation_actions(
        db,
        tenant_id=ctx.tenant.id,
        finding_id=finding_id,
    )
    dto_rows = [RemediationActionResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RemediationActionResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/remediations/{remediation_id}/approve", response_model=RemediationActionResponse)
def approve_remediation(
    remediation_id: str,
    payload: RemediationActionRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _remediation_or_404(db, remediation_id=remediation_id, tenant_id=ctx.tenant.id)
    row = approve_remediation_action(
        db,
        tenant_id=ctx.tenant.id,
        remediation_id=remediation_id,
        approved_by=current_user.id,
        justification=payload.justification,
    )
    db.commit()
    db.refresh(row)
    return RemediationActionResponse.model_validate(row)


@router.post("/remediations/{remediation_id}/reject", response_model=RemediationActionResponse)
def reject_remediation(
    remediation_id: str,
    payload: RemediationActionRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _remediation_or_404(db, remediation_id=remediation_id, tenant_id=ctx.tenant.id)
    row = reject_remediation_action(
        db,
        tenant_id=ctx.tenant.id,
        remediation_id=remediation_id,
        actor_user_id=current_user.id,
        justification=payload.justification,
    )
    db.commit()
    db.refresh(row)
    return RemediationActionResponse.model_validate(row)


@router.post("/remediations/{remediation_id}/apply", response_model=RemediationActionResponse)
def apply_remediation(
    remediation_id: str,
    payload: RemediationActionRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _remediation_or_404(db, remediation_id=remediation_id, tenant_id=ctx.tenant.id)
    try:
        row = apply_remediation_action(
            db,
            tenant_id=ctx.tenant.id,
            remediation_id=remediation_id,
            actor_user_id=current_user.id,
            justification=payload.justification,
        )
        db.commit()
        db.refresh(row)
        return RemediationActionResponse.model_validate(row)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/remediations/{remediation_id}/rollback", response_model=RemediationActionResponse)
def rollback_remediation(
    remediation_id: str,
    payload: RemediationActionRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _remediation_or_404(db, remediation_id=remediation_id, tenant_id=ctx.tenant.id)
    try:
        row = rollback_remediation_action(
            db,
            tenant_id=ctx.tenant.id,
            remediation_id=remediation_id,
            actor_user_id=current_user.id,
            justification=payload.justification,
        )
        db.commit()
        db.refresh(row)
        return RemediationActionResponse.model_validate(row)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    ctx: TenantContext = Depends(require_permission("findings.view")),
    db: Session = Depends(get_db),
):
    row = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)
    return _finding_response(db, finding=row, tenant_id=ctx.tenant.id)


@router.post("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdateRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    db: Session = Depends(get_db),
):
    normalized = str(payload.status or "").strip().lower()
    if normalized not in ALLOWED_FINDING_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status. Allowed: {', '.join(sorted(ALLOWED_FINDING_STATUSES))}",
        )

    row = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)

    row.status = normalized
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="findings.status.update",
        resource_type="finding",
        resource_id=row.finding_id,
        payload={"status": normalized},
    )
    db.commit()
    db.refresh(row)
    return _finding_response(db, finding=row, tenant_id=ctx.tenant.id)


@router.post("/{finding_id}/assign-owner", response_model=FindingResponse)
def assign_finding_owner(
    finding_id: str,
    payload: FindingAssignOwnerRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    owner_user_id = str(payload.owner_user_id or "").strip() or None
    owner_department = str(payload.owner_department or "").strip() or None
    if not owner_user_id and not owner_department:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide owner_user_id or owner_department",
        )

    if owner_user_id:
        membership = db.scalar(
            select(UserTenantRole).where(
                UserTenantRole.tenant_id == ctx.tenant.id,
                UserTenantRole.user_id == owner_user_id,
            )
        )
        if membership is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="owner_user_id not found in tenant",
            )

    row = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)
    row.user_id = owner_user_id
    row.department = owner_department or row.department

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="findings.owner.assign",
        resource_type="finding",
        resource_id=row.finding_id,
        payload={
            "owner_user_id": owner_user_id,
            "owner_department": owner_department,
        },
    )
    create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="finding_action",
        signal_type="findings.owner.assigned",
        label=f"Owner assigned to finding {row.finding_id}",
        payload={
            "finding_id": row.finding_id,
            "owner_user_id": owner_user_id,
            "owner_department": owner_department,
        },
    )
    db.commit()
    db.refresh(row)
    return _finding_response(db, finding=row, tenant_id=ctx.tenant.id)


@router.post("/{finding_id}/escalate", response_model=FindingResponse)
def escalate_finding(
    finding_id: str,
    payload: FindingEscalateRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)
    previous_severity = row.severity
    row.severity = _escalate_severity(row.severity)
    if row.status in {"open", "reviewing"}:
        row.status = "reviewing"

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="findings.escalate",
        resource_type="finding",
        resource_id=row.finding_id,
        payload={
            "from_severity": previous_severity,
            "to_severity": row.severity,
            "reason": payload.reason,
        },
    )
    create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="finding_action",
        signal_type="findings.escalated",
        label=f"Finding escalated: {row.finding_id}",
        payload={
            "finding_id": row.finding_id,
            "from_severity": previous_severity,
            "to_severity": row.severity,
            "reason": payload.reason,
        },
    )
    db.commit()
    db.refresh(row)
    return _finding_response(db, finding=row, tenant_id=ctx.tenant.id)


@router.post("/{finding_id}/run-validation-pack", response_model=FindingValidationPackResponse)
def run_finding_validation_pack(
    finding_id: str,
    payload: FindingValidationPackRequest,
    ctx: TenantContext = Depends(require_permission("findings.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)
    if not finding.ai_system_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This finding is not linked to an AI system and cannot run validation pack.",
        )

    selected_ids = _unique_strings(payload.simulation_ids)
    sims: list[SimulationDefinition] = []
    if selected_ids:
        sims = db.scalars(
            select(SimulationDefinition).where(
                SimulationDefinition.tenant_id == ctx.tenant.id,
                SimulationDefinition.id.in_(selected_ids),
            )
        ).all()
    else:
        related_controls = _unique_strings(finding.related_control_ids or [])
        all_defs = db.scalars(
            select(SimulationDefinition).where(SimulationDefinition.tenant_id == ctx.tenant.id).order_by(SimulationDefinition.created_at.asc())
        ).all()
        for sim in all_defs:
            mapped_controls = _unique_strings((sim.dsl_json or {}).get("maps_to_controls") or [])
            if related_controls and _overlap(mapped_controls, related_controls):
                sims.append(sim)
        if not sims and all_defs:
            sims = all_defs[: payload.limit]

    if not sims:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No simulation definitions available for this finding",
        )

    sims = sorted(sims, key=lambda row: (row.name, row.id))[: payload.limit]
    run_rows: list[SimulationRun] = []
    try:
        for sim in sims:
            run_rows.append(
                run_simulation(
                    db,
                    tenant_id=ctx.tenant.id,
                    simulation=sim,
                    ai_system_id=finding.ai_system_id,
                    mode=payload.mode,
                    stochastic_runs=1,
                    inputs_used=payload.inputs_used,
                    actor_user_id=current_user.id,
                )
            )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc

    run_ids = [row.id for row in run_rows]
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="findings.validation_pack.run",
        resource_type="finding",
        resource_id=finding.finding_id,
        payload={"simulation_ids": [row.simulation_id for row in run_rows], "run_ids": run_ids},
    )
    create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="finding_action",
        signal_type="findings.validation_pack.ran",
        label=f"Validation pack executed for finding {finding.finding_id}",
        payload={"finding_id": finding.finding_id, "run_ids": run_ids},
    )

    db.commit()
    for row in run_rows:
        db.refresh(row)

    run_by_simulation = {row.simulation_id: row for row in run_rows}
    output_runs: list[FindingValidationRunItemResponse] = []
    for sim in sims:
        run = run_by_simulation.get(sim.id)
        if run is None:
            continue
        results = run.results or {}
        output_runs.append(
            FindingValidationRunItemResponse(
                simulation_id=sim.id,
                simulation_name=sim.name,
                run_id=run.id,
                result=str(results.get("result") or "fail"),
                pass_rate=float(results.get("pass_rate") or 0.0),
                evidence_node_ids=[str(item) for item in (results.get("evidence_node_ids") or []) if str(item).strip()],
                control_maturity_delta=[item for item in (results.get("control_maturity_delta") or []) if isinstance(item, dict)],
                enforcement_strictness_delta=[item for item in (results.get("enforcement_strictness_delta") or []) if isinstance(item, dict)],
            )
        )

    return FindingValidationPackResponse(
        finding_id=finding.finding_id,
        ai_system_id=finding.ai_system_id,
        total_runs=len(output_runs),
        runs=output_runs,
    )


@router.post("/{finding_id}/create-ticket", response_model=FindingTicketResponse)
def create_finding_ticket(
    finding_id: str,
    payload: FindingCreateTicketRequest,
    ctx: TenantContext = Depends(require_permission("findings.review")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)
    now = datetime.now(timezone.utc)
    ticket_id = f"TKT-{finding.finding_id[:8].upper()}-{int(now.timestamp())}"
    ticket_system = str(payload.system or "jira").strip().lower() or "jira"
    ticket_severity = _normalize_severity(payload.severity_override or finding.severity)
    finding.status = "reviewing" if finding.status == "open" else finding.status
    note_suffix = f"Ticket {ticket_system.upper()}:{ticket_id} created at {now.isoformat()}."
    finding.recommended_action = f"{finding.recommended_action}\n\n{note_suffix}"
    if payload.note:
        finding.recommended_action = f"{finding.recommended_action}\nNote: {payload.note.strip()}"

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="findings.ticket.create",
        resource_type="finding",
        resource_id=finding.finding_id,
        payload={
            "ticket_id": ticket_id,
            "ticket_system": ticket_system,
            "severity": ticket_severity,
            "note": payload.note,
        },
    )
    evidence = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="finding_action",
        signal_type="findings.ticket.created",
        label=f"Ticket created for finding {finding.finding_id}",
        payload={
            "finding_id": finding.finding_id,
            "ticket_id": ticket_id,
            "ticket_system": ticket_system,
            "severity": ticket_severity,
            "note": payload.note,
        },
    )
    finding.evidence_node_ids = _unique_strings([*(finding.evidence_node_ids or []), evidence.id])
    db.commit()
    db.refresh(finding)
    return FindingTicketResponse(
        finding=_finding_response(db, finding=finding, tenant_id=ctx.tenant.id),
        ticket_id=ticket_id,
        ticket_system=ticket_system,
        severity=ticket_severity,
        created_at=now,
    )


@router.post("/{finding_id}/recommendation/accept", response_model=FindingResponse)
def accept_finding_recommendation(
    finding_id: str,
    payload: FindingAcceptRecommendationRequest,
    ctx: TenantContext = Depends(require_permission("findings.manage")),
    db: Session = Depends(get_db),
):
    row = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)

    row.status = "accepted_risk"
    if payload.note:
        row.recommended_action = f"{row.recommended_action}\n\nAccepted note: {payload.note.strip()}"

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="findings.recommendation.accept",
        resource_type="finding",
        resource_id=row.finding_id,
        payload={"status": "accepted_risk", "note": payload.note},
    )
    db.commit()
    db.refresh(row)
    return _finding_response(db, finding=row, tenant_id=ctx.tenant.id)


def _timeline_step(
    *,
    step: int,
    title: str,
    status_value: str,
    timestamp: datetime | None,
    summary: str,
    references: dict[str, Any],
) -> ProofTimelineStepResponse:
    return ProofTimelineStepResponse(
        step=step,
        title=title,
        status=status_value,
        timestamp=timestamp,
        summary=summary,
        references=references,
    )


@router.get("/{finding_id}/traceability", response_model=FindingTraceabilityResponse)
def get_finding_traceability(
    finding_id: str,
    ctx: TenantContext = Depends(require_permission("findings.view")),
    db: Session = Depends(get_db),
):
    finding = _finding_or_404(db, finding_id=finding_id, tenant_id=ctx.tenant.id)
    evidence_ids = _unique_strings(finding.evidence_node_ids or [])
    control_ids = _unique_strings(finding.related_control_ids or [])
    discovery_app = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == ctx.tenant.id,
            DiscoveryApplication.tool_key == tool_key_for_name(finding.ai_tool or "unknown"),
        )
    )

    evidence_rows = (
        db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == ctx.tenant.id,
                EvidenceNode.id.in_(evidence_ids),
            )
        ).all()
        if evidence_ids
        else []
    )
    evidence_rows = sorted(evidence_rows, key=lambda row: (row.created_at, row.id))

    controls = (
        db.scalars(
            select(Control).where(
                Control.id.in_(control_ids),
                Control.tenant_id == ctx.tenant.id,
            )
        ).all()
        if control_ids
        else []
    )
    controls = sorted(controls, key=lambda row: (row.category, row.name, row.id))

    policy_summary: PolicyVersionSummaryResponse | None = None
    if finding.policy_version_id:
        version = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.id == finding.policy_version_id,
                PolicyVersion.tenant_id == ctx.tenant.id,
            )
        )
        if version is not None:
            pack = db.scalar(
                select(PolicyPack).where(
                    PolicyPack.id == version.pack_id,
                    PolicyPack.tenant_id == ctx.tenant.id,
                )
            )
            policy_summary = PolicyVersionSummaryResponse(
                id=version.id,
                version=version.version,
                pack_id=version.pack_id,
                pack_name=pack.name if pack else None,
                created_at=version.created_at,
            )

    matched_events = _matched_gateway_events(db, finding=finding, tenant_id=ctx.tenant.id, limit=25)
    gateway_traces = [_gateway_trace_from_event(event) for event in matched_events]
    gateway_traces = [trace for trace in gateway_traces if trace]

    simulation_runs: list[SimulationRun] = []
    if finding.ai_system_id:
        run_rows = db.scalars(
            select(SimulationRun)
            .where(
                SimulationRun.tenant_id == ctx.tenant.id,
                SimulationRun.ai_system_id == finding.ai_system_id,
            )
            .order_by(SimulationRun.started_at.desc())
            .limit(200)
        ).all()
        for run in run_rows:
            impacted = _unique_strings([item.get("control_id") for item in (run.controls_impacted or []) if isinstance(item, dict)])
            result_deltas = _unique_strings(
                [item.get("control_id") for item in ((run.results or {}).get("control_maturity_delta") or []) if isinstance(item, dict)]
            )
            run_evidence = _unique_strings(((run.results or {}).get("evidence_node_ids") or []))
            if control_ids and (_overlap(impacted, control_ids) or _overlap(result_deltas, control_ids)):
                simulation_runs.append(run)
                continue
            if _overlap(run_evidence, evidence_ids):
                simulation_runs.append(run)

        if not simulation_runs:
            simulation_runs = run_rows[:10]

    maturity_rows = (
        db.scalars(
            select(ControlMaturity).where(
                ControlMaturity.tenant_id == ctx.tenant.id,
                ControlMaturity.ai_system_id == finding.ai_system_id,
                ControlMaturity.control_id.in_(control_ids) if control_ids else ControlMaturity.control_id == "__none__",
            )
        ).all()
        if finding.ai_system_id
        else []
    )
    maturity_rows = sorted(maturity_rows, key=lambda row: (row.updated_at, row.control_id), reverse=True)

    snapshot_query = select(AuditorSnapshot).where(AuditorSnapshot.tenant_id == ctx.tenant.id)
    if finding.ai_system_id:
        snapshot_query = snapshot_query.where(
            or_(AuditorSnapshot.ai_system_id == finding.ai_system_id, AuditorSnapshot.ai_system_id.is_(None))
        )
    else:
        snapshot_query = snapshot_query.where(AuditorSnapshot.ai_system_id.is_(None))
    snapshots = db.scalars(snapshot_query.order_by(AuditorSnapshot.created_at.desc()).limit(25)).all()

    latest_event = matched_events[0] if matched_events else None
    latest_run = simulation_runs[0] if simulation_runs else None
    latest_snapshot = snapshots[0] if snapshots else None
    has_maturity_delta = any(
        isinstance(item, dict) and float(item.get("delta") or 0.0) != 0.0
        for run in simulation_runs
        for item in ((run.results or {}).get("control_maturity_delta") or [])
    )

    policy_status = "complete" if policy_summary else "missing"
    action_status = "complete" if (latest_event is not None or finding.status != "open") else "missing"
    evidence_status = "complete" if evidence_rows else "missing"
    controls_status = "complete" if (controls or control_ids) else "missing"
    sim_status = "complete" if simulation_runs else "partial"
    maturity_status = "complete" if (maturity_rows or has_maturity_delta) else "partial"
    auditor_status = "complete" if snapshots else "partial"
    decision_spine = _decision_spine_for_finding(db, finding=finding, tenant_id=ctx.tenant.id)

    timeline = [
        _timeline_step(
            step=1,
            title="Detection",
            status_value="complete",
            timestamp=finding.first_seen_at or finding.created_at,
            summary=f"Finding detected as {finding.finding_type} with severity {finding.severity}.",
            references={"finding_id": finding.finding_id, "ai_tool": finding.ai_tool},
        ),
        _timeline_step(
            step=2,
            title="Policy Evaluated",
            status_value=policy_status,
            timestamp=policy_summary.created_at if policy_summary else (latest_event.timestamp if latest_event else None),
            summary=(
                f"Policy version {policy_summary.version} ({policy_summary.id}) applied."
                if policy_summary
                else "No policy version linked to this finding."
            ),
            references={"policy_version_id": finding.policy_version_id, "enforcement_event_ids": [row.id for row in matched_events]},
        ),
        _timeline_step(
            step=3,
            title="Action Taken",
            status_value=action_status,
            timestamp=latest_event.timestamp if latest_event else finding.updated_at,
            summary=(
                f"Latest enforcement decision: {latest_event.final_decision}."
                if latest_event
                else f"Finding status is currently {finding.status}."
            ),
            references={"enforcement_event_ids": [row.id for row in matched_events[:5]], "finding_status": finding.status},
        ),
        _timeline_step(
            step=4,
            title="Evidence Created",
            status_value=evidence_status,
            timestamp=evidence_rows[-1].created_at if evidence_rows else None,
            summary=f"{len(evidence_rows)} evidence nodes linked to this finding.",
            references={"evidence_node_ids": evidence_ids},
        ),
        _timeline_step(
            step=5,
            title="Controls Impacted",
            status_value=controls_status,
            timestamp=latest_event.timestamp if latest_event else None,
            summary=f"{len(control_ids)} controls mapped to this finding.",
            references={"control_ids": control_ids},
        ),
        _timeline_step(
            step=6,
            title="Simulation Triggered",
            status_value=sim_status,
            timestamp=latest_run.started_at if latest_run else None,
            summary=(
                f"{len(simulation_runs)} simulations linked to impacted controls."
                if simulation_runs
                else "No simulation runs linked yet."
            ),
            references={"simulation_run_ids": [row.id for row in simulation_runs[:10]]},
        ),
        _timeline_step(
            step=7,
            title="Maturity Effect",
            status_value=maturity_status,
            timestamp=maturity_rows[0].updated_at if maturity_rows else (latest_run.finished_at if latest_run else None),
            summary=(
                "Maturity impact present from recent simulation runs."
                if has_maturity_delta or maturity_rows
                else "Maturity impact not yet recorded."
            ),
            references={
                "control_maturity_ids": [row.control_id for row in maturity_rows[:10]],
                "has_delta": has_maturity_delta,
            },
        ),
        _timeline_step(
            step=8,
            title="Auditor Visibility",
            status_value=auditor_status,
            timestamp=latest_snapshot.created_at if latest_snapshot else None,
            summary=(
                f"{len(snapshots)} auditor snapshots include this system scope."
                if snapshots
                else "No auditor snapshots linked yet."
            ),
            references={"snapshot_ids": [row.id for row in snapshots[:10]]},
        ),
    ]

    ai_action_id = str(decision_spine.get("ai_action_id") or "").strip()
    policy_snapshot = _safe_dict(decision_spine.get("policy_snapshot"))
    decision_explanation = _safe_dict(decision_spine.get("decision_explanation"))
    evidence_bundle = _safe_dict(decision_spine.get("evidence_bundle"))
    if ai_action_id:
        timeline.append(
            _timeline_step(
                step=len(timeline) + 1,
                title="AI Action Normalized",
                status_value="complete",
                timestamp=finding.updated_at,
                summary=f"Runtime event normalized into canonical AI action {ai_action_id}.",
                references={
                    "ai_action_id": ai_action_id,
                    "related_runtime_event_id": finding.related_runtime_event_id,
                    "control_mode": decision_spine.get("control_mode"),
                },
            )
        )
    if policy_snapshot:
        timeline.append(
            _timeline_step(
                step=len(timeline) + 1,
                title="Policy Snapshot Stored",
                status_value="complete",
                timestamp=finding.updated_at,
                summary="The decision is tied to an immutable policy snapshot reference.",
                references={
                    "policy_snapshot_id": policy_snapshot.get("policy_snapshot_id"),
                    "policy_id": policy_snapshot.get("policy_id"),
                    "policy_version": policy_snapshot.get("policy_version"),
                },
            )
        )
    if decision_explanation:
        decision_summary = _safe_dict(decision_explanation.get("decision_summary"))
        timeline.append(
            _timeline_step(
                step=len(timeline) + 1,
                title="Decision Explained",
                status_value="complete",
                timestamp=finding.updated_at,
                summary=str(
                    decision_summary.get("plain_english_reason")
                    or decision_explanation.get("plain_english_reason")
                    or "Decision explanation is linked to this finding."
                ),
                references={
                    "decision_explanation_id": decision_explanation.get("explanation_id"),
                    "decision_id": decision_explanation.get("decision_id"),
                    "control_mode": decision_spine.get("control_mode"),
                    "decision_badge": decision_spine.get("decision_badge"),
                },
            )
        )
    if evidence_bundle:
        timeline.append(
            _timeline_step(
                step=len(timeline) + 1,
                title="Evidence Bundle Linked",
                status_value=str(evidence_bundle.get("integrity_status") or "unchecked"),
                timestamp=finding.updated_at,
                summary="Decision evidence bundle links action, policy, trace, and evidence references.",
                references={
                    "evidence_bundle_id": evidence_bundle.get("evidence_bundle_id"),
                    "integrity_status": evidence_bundle.get("integrity_status"),
                    "evidence_refs": list(evidence_bundle.get("evidence_refs") or []),
                    "related_action_ids": list(evidence_bundle.get("related_action_ids") or []),
                },
            )
        )

    chain_replay = _chain_replay_for_finding(
        finding,
        decision_spine=decision_spine,
        related_trace_ids=_unique_strings(
            [
                *(finding.related_event_ids or []),
                *[str(trace.get("trace_id") or "") for trace in gateway_traces],
                *[str(trace.get("request_id") or "") for trace in gateway_traces],
            ]
        ),
        evidence_node_ids=evidence_ids,
        gateway_traces=gateway_traces,
    )

    return FindingTraceabilityResponse(
        finding=_finding_response(db, finding=finding, tenant_id=ctx.tenant.id),
        discovery_application=(
            DiscoveryApplicationSummaryResponse(
                id=discovery_app.id,
                tool_key=discovery_app.tool_key,
                tool_name=discovery_app.tool_name,
                vendor=discovery_app.vendor,
                status=discovery_app.status,
                owner_user_id=discovery_app.owner_user_id,
                owner_department=discovery_app.owner_department,
                provisional_risk_tier=discovery_app.provisional_risk_tier,
                ai_system_id=discovery_app.ai_system_id,
                first_seen_at=discovery_app.first_seen_at,
                last_seen_at=discovery_app.last_seen_at,
            )
            if discovery_app
            else None
        ),
        policy_version=policy_summary,
        evidence_nodes=[
            EvidenceNodeSummaryResponse(
                id=row.id,
                correlation_id=row.correlation_id,
                node_type=row.node_type,
                signal_type=row.signal_type,
                label=row.label,
                payload=row.payload,
                created_at=row.created_at,
            )
            for row in evidence_rows
        ],
        related_controls=[
            ControlSummaryResponse(
                id=row.id,
                name=row.name,
                category=row.category,
                description=row.description,
                mapped_framework_refs=row.mapped_framework_refs or [],
            )
            for row in controls
        ],
        enforcement_events=[
            EnforcementEventSummaryResponse(
                id=row.id,
                correlation_id=row.correlation_id,
                request_id=row.request_id,
                timestamp=row.timestamp,
                final_decision=row.final_decision,
                policy_version_id=row.policy_version_id,
                evidence_nodes_created=row.evidence_nodes_created or [],
                controls_impacted=row.controls_impacted or [],
                audit_log_id=row.audit_log_id,
            )
            for row in matched_events
        ],
        simulation_runs=[
            SimulationRunSummaryResponse(
                id=row.id,
                simulation_id=row.simulation_id,
                started_at=row.started_at,
                finished_at=row.finished_at,
                mode=row.mode,
                result=str((row.results or {}).get("result") or "fail"),
                pass_rate=float((row.results or {}).get("pass_rate") or 0.0),
                evidence_node_ids=[str(item) for item in ((row.results or {}).get("evidence_node_ids") or []) if str(item).strip()],
                control_maturity_delta=[item for item in ((row.results or {}).get("control_maturity_delta") or []) if isinstance(item, dict)],
                enforcement_strictness_delta=[item for item in ((row.results or {}).get("enforcement_strictness_delta") or []) if isinstance(item, dict)],
            )
            for row in simulation_runs[:25]
        ],
        maturity_effects=[
            ControlMaturitySummaryResponse(
                control_id=row.control_id,
                maturity_score=row.maturity_score,
                status=row.status,
                confidence_score=row.confidence_score,
                technical_enforcement_score=row.technical_enforcement_score,
                simulation_pass_rate=row.simulation_pass_rate,
                coverage_score=row.coverage_score,
                updated_at=row.updated_at,
            )
            for row in maturity_rows[:25]
        ],
        auditor_snapshots=[
            AuditorSnapshotSummaryResponse(
                id=row.id,
                ai_system_id=row.ai_system_id,
                trigger_type=row.trigger_type,
                artifact_path=row.artifact_path,
                artifact_hash=row.artifact_hash,
                created_at=row.created_at,
            )
            for row in snapshots
        ],
        gateway_traces=gateway_traces,
        recommended_actions=_split_recommended_actions(finding),
        action_panel=_action_panel_for_finding(finding),
        proof_timeline=timeline,
        chain_replay=chain_replay,
    )
