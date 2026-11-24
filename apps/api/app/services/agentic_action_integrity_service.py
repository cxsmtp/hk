from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.db.models.ai_iam import JITGrantBinding
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.policy import ApprovalBinding, ApprovalRequest, ToolFingerprint, ToolScanResult
from app.db.models.runtime_intelligence import (
    AgentTouchpointEdge,
    BlastRadiusSnapshot,
    ChainEvent,
    DeferredSideEffect,
    RuntimeEvent,
    RuntimeBehaviorEdge,
    TaintLabel,
)
from app.core.observability import log_structured
from app.services.evidence_service import create_evidence_node


HIGH_RISK_SIDE_EFFECTS = {
    "webhook",
    "external_callback",
    "scheduled_job",
    "scheduled_workflow",
    "workflow_automation",
    "api_token",
    "oauth_app",
    "service_account",
    "role_assignment",
    "mailbox_forwarding",
    "persistent_memory",
}
TOOL_POISONING_DECISIONS = {
    "allow",
    "warn",
    "redact",
    "hold_for_approval",
    "block",
}
TOOL_POISONING_DECISION_RANK = {
    "allow": 0,
    "warn": 1,
    "redact": 2,
    "hold_for_approval": 3,
    "block": 4,
}
MCP_TOOL_AUTHORITY_CHAIN_PREFIX = "mcp-authority:"
MCP_TOOL_RECEIPT_CHAIN_PREFIX = "mcp-receipt:"
_TOOL_POISONING_AUTHORITY_LOCKS = tuple(
    threading.Lock() for _ in range(64)
)

FINDING_RECOMMENDATIONS = {
    "APPROVAL_SUMMARY_MISMATCH": "Review the trusted canonical action instead of the agent-written approval summary.",
    "APPROVAL_REQUEST_INCOMPLETE": "Require the agent to provide exact target resource, tool, arguments, and side-effect scope.",
    "APPROVAL_EXECUTION_DRIFT": "Block execution and require a new approval because material fields changed after approval.",
    "TAINTED_CONTEXT_IN_APPROVAL_CHAIN": "Require trusted review because untrusted context influenced the approval chain.",
    "MCP_TOOL_METADATA_DRIFT": "Review and approve the changed MCP tool fingerprint before allowing tool calls.",
    "MCP_TOOL_SCHEMA_CHANGED": "Review the changed MCP tool schema before allowing tool calls.",
    "HIGH_RISK_MCP_ACTION": "Block or require approval for write, admin, execute, credential, or persistent MCP actions.",
    "MCP_TOOL_ATTEMPTED_CODE_WRITE": "Require approval before allowing MCP tools to write files, code, roles, or administrative resources.",
    "AI_AGENT_SECRET_ACCESS_ATTEMPT": "Block MCP tool calls that attempt to access credentials, secrets, tokens, keys, or .env material.",
    "TOOL_PARAMETER_POLICY_VIOLATION": "Review MCP tool parameters because they exceed the approved tool/action boundary.",
    "UNAPPROVED_MCP_TOOL_VERSION": "Review and approve the MCP tool fingerprint before allowing this version.",
    "JIT_SCOPE_EXCEEDS_APPROVED_TASK": "Narrow the JIT grant to the approved task scope before execution.",
    "JIT_PRIVILEGE_ESCALATION": "Block or require second approval for privileged JIT actions.",
    "DEFERRED_SIDE_EFFECT_REQUIRES_APPROVAL": "Require approval before creating persistent or future side effects.",
    "AGENT_CREATED_WEBHOOK": "Review the external callback/webhook and bind it to an approved scope.",
    "AGENT_CREATED_SCHEDULED_JOB": "Review the scheduled job and bind it to an approved scope.",
    "AGENT_CREATED_PERSISTENT_MEMORY": "Review the persistent memory write and restrict future instruction persistence.",
}


def _json_hash(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _safe_str(value: Any, *, max_len: int = 255) -> str:
    return str(value or "").strip()[:max_len]


def _tool_poisoning_authority_chain_id(tool_fingerprint_id: str) -> str:
    return (
        f"{MCP_TOOL_AUTHORITY_CHAIN_PREFIX}"
        f"{_safe_str(tool_fingerprint_id, max_len=48)}"
    )


def _tool_scan_receipt_chain_id(chain_id: str | None) -> str | None:
    normalized = _safe_str(chain_id, max_len=64)
    if not normalized:
        return None
    if not normalized.startswith(MCP_TOOL_AUTHORITY_CHAIN_PREFIX):
        return normalized
    digest = hashlib.sha256(str(chain_id).encode("utf-8")).hexdigest()
    return f"{MCP_TOOL_RECEIPT_CHAIN_PREFIX}{digest[:52]}"


def _observe_external_capability_for_mcp_scan(
    db: Session,
    *,
    tenant_id: str,
    mcp_server_id: str,
    tool_name: str,
    tool_version: str,
    description: str,
    schema: dict[str, Any],
    examples: list[Any],
    manifest: dict[str, Any] | None,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    observation_manifest = manifest if isinstance(manifest, dict) else {}
    try:
        from app.services.external_capability_integrity import ExternalCapabilityIntegrityService

        nested = db.begin_nested()
        try:
            state = ExternalCapabilityIntegrityService().observe_mcp_capability(
                db,
                tenant_id=tenant_id,
                capability_ref=f"mcp:{_safe_str(mcp_server_id, max_len=128)}",
                observation={
                    "configured_locator": observation_manifest.get("configured_locator")
                    or observation_manifest.get("url")
                    or observation_manifest.get("endpoint")
                    or f"mcp://{_safe_str(mcp_server_id, max_len=128)}",
                    "registry_source": observation_manifest.get("registry_source"),
                    "registry_identity": observation_manifest.get("registry_identity")
                    or mcp_server_id,
                    "publisher_identity": observation_manifest.get("publisher_identity"),
                    "observed_endpoint": observation_manifest.get("observed_endpoint")
                    or observation_manifest.get("endpoint"),
                    "domain": observation_manifest.get("domain"),
                    "transport": observation_manifest.get("transport"),
                    "auth_mode": observation_manifest.get("auth_mode"),
                    "protocol_version": observation_manifest.get("protocol_version"),
                    "server_metadata": observation_manifest.get("server_metadata")
                    if isinstance(observation_manifest.get("server_metadata"), dict)
                    else {
                        "name": mcp_server_id,
                        "version": observation_manifest.get("server_version")
                        or observation_manifest.get("version")
                        or "unknown",
                    },
                    "tools": [
                        {
                            "name": tool_name,
                            "version": tool_version,
                            "description": description,
                            "inputSchema": schema,
                            "annotations": observation_manifest.get("annotations")
                            if isinstance(observation_manifest.get("annotations"), dict)
                            else {},
                        }
                    ],
                    "resources": observation_manifest.get("resources") or [],
                    "instructions": observation_manifest.get("instructions") or examples,
                },
                observed_at=datetime.now(timezone.utc),
                evidence_refs=evidence_refs or [],
            )
        except Exception:
            nested.rollback()
            raise
        else:
            nested.commit()
        return {
            "capability_id": state.capability_id,
            "capability_ref": state.capability_ref,
            "trust_state": state.trust_state,
            "material_fingerprint": state.material_fingerprint,
            "baseline_material_fingerprint": state.baseline_material_fingerprint,
            "capability_epoch": state.capability_epoch,
            "tool_fingerprints": state.tool_fingerprints,
        }
    except Exception as exc:  # noqa: BLE001 - scan must fail safe without hiding the gap
        log_structured(
            "external_capability_observation_failed",
            module="agentic_action_integrity_service",
            tenant_id=tenant_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return {
            "trust_state": "UNKNOWN",
            "reason": "external_capability_observation_failed",
        }


def _tool_poisoning_decision_from_factors(risk_factors: list[Any]) -> str:
    strongest = "allow"
    for factor in risk_factors:
        marker, separator, candidate = str(factor).partition(":")
        if marker != "tool_poisoning_decision" or not separator:
            continue
        normalized = candidate.strip().lower()
        if TOOL_POISONING_DECISION_RANK.get(
            normalized,
            0,
        ) > TOOL_POISONING_DECISION_RANK.get(strongest, 0):
            strongest = normalized
    return strongest


def _tool_poisoning_authority_decision(
    authority: ToolScanResult | None,
) -> str:
    if authority is None:
        return "allow"
    state_prefix = "poisoning:"
    state = _safe_str(authority.trust_status, max_len=32).lower()
    if state.startswith(state_prefix):
        candidate = state.removeprefix(state_prefix)
        if candidate in TOOL_POISONING_DECISIONS:
            return candidate
    return _tool_poisoning_decision_from_factors(
        list(authority.risk_factors or [])
    )


def _risk_factors_with_tool_poisoning_decision(
    risk_factors: list[Any],
    decision: str,
) -> list[str]:
    cleaned = {
        str(factor)
        for factor in risk_factors
        if not str(factor).startswith("tool_poisoning_decision:")
    }
    if decision != "allow":
        cleaned.add(f"tool_poisoning_decision:{decision}")
    return sorted(cleaned)


def _tool_poisoning_lock_statement(
    *,
    tenant_id: str,
    tool_fingerprint_id: str,
):
    return (
        select(ToolFingerprint.id)
        .where(
            ToolFingerprint.id == tool_fingerprint_id,
            ToolFingerprint.tenant_id == tenant_id,
        )
        .with_for_update()
    )


@contextmanager
def _serialized_tool_poisoning_authority(
    db: Session,
    *,
    tenant_id: str,
    tool_fingerprint_id: str,
):
    bind = db.get_bind()
    if bind.dialect.name == "sqlite":
        stripe_key = hashlib.sha256(
            f"{tenant_id}:{tool_fingerprint_id}".encode("utf-8")
        ).digest()[0]
        with _TOOL_POISONING_AUTHORITY_LOCKS[
            stripe_key % len(_TOOL_POISONING_AUTHORITY_LOCKS)
        ]:
            yield
        return
    with db.no_autoflush:
        db.execute(
            _tool_poisoning_lock_statement(
                tenant_id=tenant_id,
                tool_fingerprint_id=tool_fingerprint_id,
            )
        )
    yield


def _commit_tool_poisoning_authority(
    db: Session,
    *,
    tenant_id: str,
    fingerprint: ToolFingerprint,
    mcp_server_id: str,
    tool_name: str,
    proposed_decision: str,
    persist_scan: Callable[[str], str | None],
) -> str:
    authority_chain_id = _tool_poisoning_authority_chain_id(fingerprint.id)
    try:
        with _serialized_tool_poisoning_authority(
            db,
            tenant_id=tenant_id,
            tool_fingerprint_id=fingerprint.id,
        ):
            with db.no_autoflush:
                authority = db.scalar(
                    select(ToolScanResult)
                    .where(
                        ToolScanResult.id == fingerprint.id,
                        ToolScanResult.tenant_id == tenant_id,
                        ToolScanResult.chain_id == authority_chain_id,
                        ToolScanResult.tool_fingerprint_id == fingerprint.id,
                    )
                    .limit(1)
                )
            current_decision = _tool_poisoning_authority_decision(authority)
            final_decision = (
                current_decision
                if TOOL_POISONING_DECISION_RANK.get(current_decision, 0)
                > TOOL_POISONING_DECISION_RANK.get(proposed_decision, 0)
                else proposed_decision
            )
            evidence_node_id = persist_scan(final_decision)
            authority_risk_factors = (
                [f"tool_poisoning_decision:{final_decision}"]
                if final_decision != "allow"
                else []
            )
            if authority is None:
                authority = ToolScanResult(
                    id=fingerprint.id,
                    tenant_id=tenant_id,
                    chain_id=authority_chain_id,
                    tool_fingerprint_id=fingerprint.id,
                    mcp_server_id=mcp_server_id,
                    tool_name=tool_name,
                    trust_status=f"poisoning:{final_decision}",
                    risk_factors=authority_risk_factors,
                    evidence_node_id=evidence_node_id,
                )
                db.add(authority)
            else:
                authority.trust_status = f"poisoning:{final_decision}"
                authority.risk_factors = authority_risk_factors
                if evidence_node_id is not None:
                    authority.evidence_node_id = evidence_node_id
            db.commit()
            return final_decision
    except Exception:
        db.rollback()
        raise


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _list_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({_safe_str(item, max_len=255) for item in value if _safe_str(item, max_len=255)})


def _strict_material_str(value: Any, *, field: str, max_len: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if len(normalized) > max_len:
        raise ValueError(f"{field} exceeds maximum length {max_len}")
    return normalized


def _strict_material_list(value: Any, *, field: str, max_len: int = 255) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of strings")
    normalized: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} must be a list of strings")
        token = _strict_material_str(item, field=field, max_len=max_len)
        if token:
            normalized.add(token)
    return sorted(normalized)


def _list_from_metadata(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted({_safe_str(item, max_len=128) for item in value if _safe_str(item, max_len=128)})
    if isinstance(value, str):
        return [_safe_str(value, max_len=128)] if _safe_str(value, max_len=128) else []
    return []


def _finding_severity(finding_type: str) -> str:
    if finding_type in {
        "APPROVAL_EXECUTION_DRIFT",
        "JIT_PRIVILEGE_ESCALATION",
        "AGENT_CREATED_WEBHOOK",
        "AGENT_CREATED_SCHEDULED_JOB",
        "AGENT_CREATED_PERSISTENT_MEMORY",
        "HIGH_RISK_MCP_ACTION",
        "MCP_TOOL_ATTEMPTED_CODE_WRITE",
        "AI_AGENT_SECRET_ACCESS_ATTEMPT",
    }:
        return "critical"
    if finding_type in {
        "APPROVAL_SUMMARY_MISMATCH",
        "TAINTED_CONTEXT_IN_APPROVAL_CHAIN",
        "MCP_TOOL_METADATA_DRIFT",
        "MCP_TOOL_SCHEMA_CHANGED",
        "TOOL_PARAMETER_POLICY_VIOLATION",
        "UNAPPROVED_MCP_TOOL_VERSION",
        "JIT_SCOPE_EXCEEDS_APPROVED_TASK",
        "DEFERRED_SIDE_EFFECT_REQUIRES_APPROVAL",
    }:
        return "high"
    return "med"


def _record_agentic_finding(
    db: Session,
    *,
    tenant_id: str,
    finding_type: str,
    chain_id: str,
    evidence_node_id: str | None,
    source_surface: str = "aiiam",
    ai_tool: str = "agentic_chain",
    agent_id: str | None = None,
    decision: str | None = None,
    control_mode: str | None = None,
    action_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    dedupe_material = {
        "finding_type": finding_type,
        "chain_id": chain_id,
        "action_id": action_id,
        "agent_id": agent_id,
        "ai_tool": ai_tool,
    }
    dedupe_key = "agentic:" + _json_hash(dedupe_material)[:119]
    existing = db.scalar(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.dedupe_key == dedupe_key,
            Finding.status.in_(["open", "reviewing"]),
        )
    )
    now = datetime.now(timezone.utc)
    evidence_ids = [evidence_node_id] if evidence_node_id else []
    if existing is not None:
        existing.occurrence_count += 1
        existing.last_seen_at = now
        existing.decision = _safe_str(decision, max_len=32) or existing.decision
        merged = sorted(set((existing.evidence_node_ids or []) + evidence_ids))
        existing.evidence_node_ids = merged
        existing.evidence_status = "complete" if merged else "incomplete"
        db.flush()
        return existing

    finding = Finding(
        tenant_id=tenant_id,
        source_surface=_safe_str(source_surface, max_len=16) or "aiiam",
        ai_tool=_safe_str(ai_tool, max_len=128) or "agentic_chain",
        ai_system_id=None,
        user_id=None,
        agent_id=_safe_str(agent_id, max_len=64) or None,
        machine_id=None,
        user_email=None,
        browser_type=None,
        application="Agentic Action Integrity",
        department=None,
        severity=_finding_severity(finding_type),
        finding_type=_safe_str(finding_type, max_len=64),
        risk_category="agentic_chain_integrity",
        data_classification=None,
        decision=_safe_str(decision, max_len=32) or None,
        status="open",
        recommended_action=FINDING_RECOMMENDATIONS.get(
            finding_type,
            "Review the agentic chain, policy decision, and evidence before allowing execution.",
        ),
        policy_id="agentic_action_integrity",
        policy_version_id=None,
        evidence_node_ids=evidence_ids,
        related_event_ids=[chain_id],
        related_control_ids=["agentic_action_integrity"],
        remediation_action_ids=[],
        evidence_status="complete" if evidence_ids else "incomplete",
        related_runtime_event_id=action_id,
        dedupe_key=dedupe_key,
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    if metadata:
        finding.recommended_action = (
            finding.recommended_action
            + " Context: "
            + json.dumps(metadata, sort_keys=True, default=str)[:700]
        )
    db.add(finding)
    db.flush()
    return finding


def _material_fields(canonical_action: dict[str, Any]) -> dict[str, Any]:
    arguments = canonical_action.get("arguments")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    return {
        "action_id": _strict_material_str(canonical_action.get("action_id"), field="action_id", max_len=64),
        "approved_action_type": _strict_material_str(canonical_action.get("action_type"), field="action_type", max_len=128),
        "tool_name": _strict_material_str(canonical_action.get("tool_name"), field="tool_name", max_len=128),
        "tool_version": _strict_material_str(canonical_action.get("tool_version"), field="tool_version", max_len=64),
        "tool_fingerprint": _strict_material_str(canonical_action.get("tool_fingerprint"), field="tool_fingerprint", max_len=128),
        "arguments_hash": _json_hash(arguments),
        "target_resource": _strict_material_str(canonical_action.get("target_resource"), field="target_resource", max_len=255),
        "affected_resources": _strict_material_list(canonical_action.get("affected_resources"), field="affected_resources"),
        "identity_scope": _strict_material_list(canonical_action.get("identity_scope"), field="identity_scope"),
        "data_destination": _strict_material_str(canonical_action.get("data_destination"), field="data_destination", max_len=128),
        "side_effect_class": _strict_material_str(canonical_action.get("side_effect_class"), field="side_effect_class", max_len=128),
        "persistence_risk": _strict_material_str(canonical_action.get("persistence_risk"), field="persistence_risk", max_len=64),
        "external_destination": _strict_material_str(canonical_action.get("external_destination"), field="external_destination", max_len=255),
        "time_window": _strict_material_str(canonical_action.get("time_window"), field="time_window", max_len=64),
        "requester_agent_id": _strict_material_str(canonical_action.get("requester_agent_id"), field="requester_agent_id", max_len=128),
    }


def _approval_binding_contract(
    canonical_action: dict[str, Any], *, tenant_id: str
) -> tuple[dict[str, Any], str]:
    if canonical_action.get("schema_name") == "hawk.ai_action":
        from app.services.receipt_service import approval_binding_contract

        contract = approval_binding_contract(canonical_action, tenant_id=tenant_id)
        return dict(contract["material_fields"]), str(contract["canonical_action_hash"])
    legacy_material = {
        "approval_material_schema": "agentic_action_integrity/1.0",
        **_material_fields(canonical_action),
    }
    return legacy_material, _json_hash(legacy_material)


def _trusted_approval_text(canonical_action: dict[str, Any], material_fields: dict[str, Any]) -> str:
    tool_name = material_fields.get("tool_name") or "unknown_tool"
    action_type = material_fields.get("approved_action_type") or "unknown_action"
    target = material_fields.get("target_resource") or "unknown_resource"
    destination = material_fields.get("data_destination") or "not_declared"
    side_effect = material_fields.get("side_effect_class") or "none"
    persistence = material_fields.get("persistence_risk") or "unknown"
    scope = ", ".join(material_fields.get("identity_scope") or []) or "none"
    return (
        f"Approve {action_type} using {tool_name} against {target}. "
        f"Identity scope: {scope}. Data destination: {destination}. "
        f"Side effect: {side_effect}. Persistence risk: {persistence}."
    )


def _record_chain_event(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    event_type: str,
    action_id: str | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
    source_id: str | None = None,
    destination_id: str | None = None,
    source_trust_level: str | None = None,
    destination_trust_level: str | None = None,
    evidence_bundle_id: str | None = None,
    taint_labels: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ChainEvent:
    row = ChainEvent(
        tenant_id=tenant_id,
        chain_id=chain_id,
        action_id=action_id,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        source_id=source_id,
        destination_id=destination_id,
        source_trust_level=source_trust_level,
        destination_trust_level=destination_trust_level,
        evidence_bundle_id=evidence_bundle_id,
        taint_labels=taint_labels or [],
        metadata_json=metadata or {},
    )
    db.add(row)
    db.flush()
    return row


def _record_behavior_edge(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    source_node_type: str,
    source_node_id: str,
    target_node_type: str,
    target_node_id: str,
    relationship_type: str,
    evidence_node_id: str | None = None,
    source_label: str | None = None,
    target_label: str | None = None,
    payload: dict[str, Any] | None = None,
) -> RuntimeBehaviorEdge:
    row = RuntimeBehaviorEdge(
        tenant_id=tenant_id,
        event_id=None,
        ai_system_id=None,
        source_node_type=source_node_type,
        source_node_id=source_node_id,
        source_node_label=source_label,
        target_node_type=target_node_type,
        target_node_id=target_node_id,
        target_node_label=target_label,
        relationship_type=relationship_type,
        evidence_node_id=evidence_node_id,
        payload={"chain_id": chain_id, **(payload or {})},
    )
    db.add(row)
    db.flush()
    return row


def _record_touchpoint_edge(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    source_node_type: str,
    source_node_id: str,
    target_node_type: str,
    target_node_id: str,
    edge_type: str,
    risk_level: str = "low",
    control_mode: str = "detected_only",
    evidence_bundle_id: str | None = None,
) -> AgentTouchpointEdge:
    row = AgentTouchpointEdge(
        tenant_id=tenant_id,
        chain_id=chain_id,
        source_node_type=source_node_type,
        source_node_id=source_node_id,
        target_node_type=target_node_type,
        target_node_id=target_node_id,
        edge_type=edge_type,
        risk_level=risk_level,
        control_mode=control_mode,
        evidence_bundle_id=evidence_bundle_id,
    )
    db.add(row)
    db.flush()
    return row


def _record_touchpoint_edge_once(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    source_node_type: str,
    source_node_id: str,
    target_node_type: str,
    target_node_id: str,
    edge_type: str,
    risk_level: str = "low",
    control_mode: str = "detected_only",
    evidence_bundle_id: str | None = None,
    action_id: str | None = None,
) -> AgentTouchpointEdge:
    source_id = _safe_str(source_node_id, max_len=128)
    target_id = _safe_str(target_node_id, max_len=128)
    existing = db.scalar(
        select(AgentTouchpointEdge).where(
            AgentTouchpointEdge.tenant_id == tenant_id,
            AgentTouchpointEdge.chain_id == _safe_str(chain_id, max_len=64),
            AgentTouchpointEdge.source_node_type == _safe_str(source_node_type, max_len=32),
            AgentTouchpointEdge.source_node_id == source_id,
            AgentTouchpointEdge.target_node_type == _safe_str(target_node_type, max_len=32),
            AgentTouchpointEdge.target_node_id == target_id,
            AgentTouchpointEdge.edge_type == _safe_str(edge_type, max_len=64),
        )
    )
    if existing is not None:
        existing.risk_level = _safe_str(risk_level, max_len=16) or existing.risk_level
        existing.control_mode = _safe_str(control_mode, max_len=32) or existing.control_mode
        existing.evidence_bundle_id = evidence_bundle_id or existing.evidence_bundle_id
        existing.action_id = action_id or existing.action_id
        db.flush()
        return existing
    row = _record_touchpoint_edge(
        db,
        tenant_id=tenant_id,
        chain_id=_safe_str(chain_id, max_len=64),
        source_node_type=_safe_str(source_node_type, max_len=32),
        source_node_id=source_id,
        target_node_type=_safe_str(target_node_type, max_len=32),
        target_node_id=target_id,
        edge_type=_safe_str(edge_type, max_len=64),
        risk_level=risk_level,
        control_mode=control_mode,
        evidence_bundle_id=evidence_bundle_id,
    )
    row.action_id = action_id
    db.flush()
    return row


def _surface_control_mode(row: RuntimeEvent, metadata: dict[str, Any], nested: dict[str, Any]) -> str:
    decision = _safe_str(metadata.get("final_decision") or metadata.get("decision") or row.decision).lower()
    gateway_routed = bool(metadata.get("gateway_routed") or nested.get("gateway_enforced") or nested.get("gateway_routed"))
    source_surface = _safe_str(row.source_surface or metadata.get("source_surface")).lower()
    if source_surface in {"foundry", "copilot"} and not gateway_routed:
        return "telemetry_only"
    if decision == "block":
        return "inline_prevented" if gateway_routed else "shadow_would_block"
    if decision == "warn":
        return "warned"
    return "inline_allowed" if gateway_routed else "detected_only"


def record_surface_agent_touchpoints(
    db: Session,
    *,
    tenant_id: str,
    runtime_event_id: str,
) -> dict[str, Any]:
    row = db.scalar(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.event_id == runtime_event_id,
        )
    )
    if row is None or not _safe_str(row.agent_id, max_len=128):
        return {"recorded": 0, "reason": "missing_runtime_event_or_agent"}

    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    nested = dict(metadata.get("metadata") or {}) if isinstance(metadata.get("metadata"), dict) else {}
    chain_id = _safe_str(row.chain_id or row.context_id or row.correlation_id or row.event_id, max_len=64)
    agent_id = _safe_str(row.agent_id, max_len=128)
    control_mode = _surface_control_mode(row, metadata, nested)
    risk_level = _safe_str(row.severity or metadata.get("severity"), max_len=16) or "low"
    evidence_id = _safe_str((row.evidence_node_ids or [None])[-1]) if row.evidence_node_ids else None
    recorded = 0

    def add_edge(
        source_type: str,
        source_id: str | None,
        target_type: str,
        target_id: str | None,
        edge_type: str,
        *,
        risk: str | None = None,
        mode: str | None = None,
    ) -> None:
        nonlocal recorded
        if not _safe_str(source_id, max_len=128) or not _safe_str(target_id, max_len=128):
            return
        _record_touchpoint_edge_once(
            db,
            tenant_id=tenant_id,
            chain_id=chain_id,
            source_node_type=source_type,
            source_node_id=_safe_str(source_id, max_len=128),
            target_node_type=target_type,
            target_node_id=_safe_str(target_id, max_len=128),
            edge_type=edge_type,
            risk_level=risk or risk_level,
            control_mode=mode or control_mode,
            evidence_bundle_id=evidence_id,
            action_id=row.event_id,
        )
        recorded += 1

    user_id = _safe_str(row.user_id or nested.get("user_principal_name") or nested.get("entra_user_id"), max_len=128)
    add_edge("human_user", user_id, "agent", agent_id, "initiated")

    app_id = _safe_str(row.app_id or metadata.get("domain") or metadata.get("app"), max_len=128)
    add_edge("agent", agent_id, "saas_app", app_id, "observed_on_surface")

    project_id = _safe_str(
        nested.get("foundry_project_id") or nested.get("project_id") or nested.get("workspace_id"),
        max_len=128,
    )
    add_edge("agent", agent_id, "foundry_project", project_id, "belongs_to_project")

    model_id = _safe_str(
        metadata.get("model_name")
        or nested.get("model_deployment")
        or nested.get("model_deployment_id")
        or nested.get("model"),
        max_len=128,
    )
    add_edge("agent", agent_id, "model", model_id, "uses_model")

    authority = dict(nested.get("authority") or {}) if isinstance(nested.get("authority"), dict) else {}
    authority_ids = [
        authority.get("service_principal_id"),
        authority.get("managed_identity_id"),
        authority.get("entra_app_id"),
        authority.get("authority_id"),
        nested.get("service_principal_id"),
        nested.get("managed_identity_id"),
        nested.get("entra_app_id"),
    ]
    for authority_id in authority_ids:
        add_edge("agent", agent_id, "service_identity", _safe_str(authority_id, max_len=128), "used_authority")

    tool_names = _list_from_metadata(nested.get("tool_names")) or _list_from_metadata(metadata.get("tool_name"))
    for tool_name in tool_names:
        add_edge("agent", agent_id, "mcp_tool", tool_name, "invoked_tool")

    data_sources = (
        _list_from_metadata(nested.get("data_source_ids"))
        or _list_from_metadata(metadata.get("data_source"))
        or _list_from_metadata(nested.get("data_source"))
    )
    for data_source in data_sources:
        add_edge("agent", agent_id, "data_source", data_source, "accessed_data")

    api_endpoint = _safe_str(metadata.get("api_endpoint") or nested.get("api_endpoint"), max_len=128)
    add_edge("agent", agent_id, "api", api_endpoint, "called_api")

    return {
        "recorded": recorded,
        "agent_id": agent_id,
        "chain_id": chain_id,
        "control_mode": control_mode,
    }


def scan_approval_request(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    canonical_action: dict[str, Any],
    original_user_intent: str = "",
    agent_summary: str = "",
    source_context_type: str = "unknown",
    source_trust_level: str = "unknown",
) -> dict[str, Any]:
    material = _material_fields(canonical_action)
    trusted_text = _trusted_approval_text(canonical_action, material)
    risk_factors: list[str] = []

    summary_lower = str(agent_summary or "").lower()
    for required in (material["tool_name"], material["target_resource"], material["side_effect_class"]):
        if required and required.lower() not in summary_lower:
            risk_factors.append("agent_summary_mismatch")
            break
    if not material["target_resource"]:
        risk_factors.append("missing_target_resource")
    if material["side_effect_class"] or material["persistence_risk"] in {"persistent", "future"}:
        risk_factors.append("deferred_side_effect_risk")
    if source_trust_level in {"untrusted", "unknown"}:
        risk_factors.append("tainted_source_context")

    decision = "allow"
    if "deferred_side_effect_risk" in risk_factors and "tainted_source_context" in risk_factors:
        decision = "require_second_approval"
    elif risk_factors:
        decision = "require_approval"

    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="agentic_chain_approval_scan",
        signal_type="agentic.approval.scan",
        label=f"Approval scan for {material['approved_action_type'] or 'unknown action'}",
        payload={
            "chain_id": chain_id,
            "decision": decision,
            "risk_factors": risk_factors,
            "trusted_approval_text": trusted_text,
            "material_fields": material,
            "original_user_intent_hash": _json_hash(original_user_intent),
        },
    )
    _record_chain_event(
        db,
        tenant_id=tenant_id,
        chain_id=chain_id,
        event_type="approval_scanned",
        actor_type="agent",
        actor_id=material["requester_agent_id"] or None,
        source_trust_level=source_trust_level,
        evidence_bundle_id=evidence.id,
        metadata={"decision": decision, "risk_factors": risk_factors},
    )
    if "agent_summary_mismatch" in risk_factors:
        _record_agentic_finding(
            db,
            tenant_id=tenant_id,
            finding_type="APPROVAL_SUMMARY_MISMATCH",
            chain_id=chain_id,
            evidence_node_id=evidence.id,
            source_surface="aiiam",
            ai_tool=material["tool_name"] or "agentic_chain",
            agent_id=material["requester_agent_id"] or None,
            decision=decision,
            control_mode="external_required" if decision != "allow" else "inline_allowed",
            metadata={"risk_factors": risk_factors},
        )
    if "missing_target_resource" in risk_factors:
        _record_agentic_finding(
            db,
            tenant_id=tenant_id,
            finding_type="APPROVAL_REQUEST_INCOMPLETE",
            chain_id=chain_id,
            evidence_node_id=evidence.id,
            source_surface="aiiam",
            ai_tool=material["tool_name"] or "agentic_chain",
            agent_id=material["requester_agent_id"] or None,
            decision=decision,
            control_mode="external_required" if decision != "allow" else "inline_allowed",
            metadata={"risk_factors": risk_factors},
        )
    if source_trust_level in {"untrusted", "unknown"}:
        taint = TaintLabel(
            tenant_id=tenant_id,
            chain_id=chain_id,
            action_id=None,
            source_type=source_context_type,
            source_ref=_json_hash(original_user_intent)[:32],
            trust_level=source_trust_level,
            taint_type="external_content" if source_context_type != "unknown" else "unknown",
        )
        db.add(taint)
        db.flush()
        _record_chain_event(
            db,
            tenant_id=tenant_id,
            chain_id=chain_id,
            event_type="taint_propagated",
            actor_type="system",
            source_id=source_context_type,
            source_trust_level=source_trust_level,
            evidence_bundle_id=evidence.id,
            taint_labels=[taint.id],
        )
        _record_agentic_finding(
            db,
            tenant_id=tenant_id,
            finding_type="TAINTED_CONTEXT_IN_APPROVAL_CHAIN",
            chain_id=chain_id,
            evidence_node_id=evidence.id,
            source_surface="aiiam",
            ai_tool=material["tool_name"] or "agentic_chain",
            agent_id=material["requester_agent_id"] or None,
            decision=decision,
            control_mode="external_required" if decision != "allow" else "inline_allowed",
            metadata={"source_context_type": source_context_type, "source_trust_level": source_trust_level},
        )
    db.commit()
    return {
        "chain_id": chain_id,
        "decision": decision,
        "control_mode": "external_required" if decision != "allow" else "inline_allowed",
        "trusted_approval_text": trusted_text,
        "risk_factors": sorted(set(risk_factors)),
        "evidence_bundle_id": evidence.id,
        "material_fields": material,
    }


def bind_or_verify_approval(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    approval_id: str,
    canonical_action: dict[str, Any],
    approver_user_id: str | None,
    expires_at: datetime | None = None,
    verify_binding_id: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    clock_fn = clock or (lambda: datetime.now(timezone.utc))
    material, canonical_hash = _approval_binding_contract(
        canonical_action, tenant_id=tenant_id
    )
    if verify_binding_id:
        binding = db.scalar(
            select(ApprovalBinding).where(
                ApprovalBinding.tenant_id == tenant_id,
                ApprovalBinding.id == verify_binding_id,
            )
        )
        if binding is None:
            raise ValueError("approval binding not found")
        if binding.approval_id != approval_id or binding.chain_id != chain_id:
            raise ValueError("approval binding does not match approval or chain authority")
        if binding.status != "active":
            if binding.status == "used":
                raise ValueError("approval binding was already used")
            raise ValueError("approval binding is not active")
        binding_expiry = binding.expires_at
        verification_now = _utc_datetime(clock_fn())
        if binding_expiry is not None:
            binding_expiry = _utc_datetime(binding_expiry)
            if verification_now >= binding_expiry:
                raise ValueError("approval binding expired")
        previous = dict(binding.material_fields or {})
        expected_receipt_material_hash = (
            _json_hash(material)
            if material.get("receipt_material_schema") == "1.0"
            else None
        )
        if (binding.action_id or "") != (previous.get("action_id") or ""):
            raise ValueError("approval binding action_id does not match stored material")
        drifted = sorted(key for key, value in material.items() if previous.get(key) != value)
        if binding.receipt_material_hash != expected_receipt_material_hash:
            drifted.append("receipt_material_hash")
            drifted = sorted(set(drifted))
        if drifted:
            next_status = "invalidated"
            invalidation_reason = "material_fields_changed:" + ",".join(drifted)
            decision = "block"
            event_type = "approval_invalidated"
        else:
            next_status = "used"
            invalidation_reason = None
            decision = "allow"
            event_type = "approval_bound"
        consumed = db.execute(
            update(ApprovalBinding)
            .where(
                ApprovalBinding.id == binding.id,
                ApprovalBinding.tenant_id == tenant_id,
                ApprovalBinding.status == "active",
                or_(ApprovalBinding.expires_at.is_(None), ApprovalBinding.expires_at > verification_now),
            )
            .values(status=next_status, invalidation_reason=invalidation_reason)
            .execution_options(synchronize_session=False)
        )
        if consumed.rowcount != 1:
            raise ValueError("approval binding was already used or is not active")
        if binding_expiry is not None and _utc_datetime(clock_fn()) >= binding_expiry:
            db.rollback()
            raise ValueError("approval binding expired during verification")
        db.flush()
        db.refresh(binding)
        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="approval_binding_verification",
            signal_type="agentic.approval.binding.verify",
            label=f"Approval binding {binding.status}",
            payload={
                "chain_id": chain_id,
                "approval_binding_id": binding.id,
                "decision": decision,
                "drifted_fields": drifted,
                "canonical_action_hash": canonical_hash,
            },
        )
        _record_chain_event(
            db,
            tenant_id=tenant_id,
            chain_id=chain_id,
            event_type=event_type,
            actor_type="human",
            actor_id=binding.approver_user_id,
            evidence_bundle_id=evidence.id,
            metadata={"decision": decision, "drifted_fields": drifted},
        )
        if drifted:
            _record_agentic_finding(
                db,
                tenant_id=tenant_id,
                finding_type="APPROVAL_EXECUTION_DRIFT",
                chain_id=chain_id,
                evidence_node_id=evidence.id,
                source_surface="aiiam",
                ai_tool=material.get("tool_name") or material.get("tool_fingerprint") or "agentic_chain",
                agent_id=material.get("requester_agent_id") or None,
                decision=decision,
                control_mode="inline_prevented",
                action_id=binding.action_id,
                metadata={"drifted_fields": drifted, "approval_binding_id": binding.id},
            )
        db.commit()
        return {
            "binding_id": binding.id,
            "status": binding.status,
            "decision": decision,
            "control_mode": "inline_prevented" if decision == "block" else "inline_allowed",
            "drifted_fields": drifted,
            "evidence_bundle_id": evidence.id,
        }

    approval = db.scalar(
        select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.tenant_id == tenant_id,
        )
    )
    if approval is None:
        raise ValueError("approval request not found")
    if approval.status != "approved" or approval.decision != "approve":
        raise ValueError("approval request is not approved or was already consumed")
    now = _utc_datetime(clock_fn())
    created_at = _utc_datetime(approval.created_at)
    deadline = created_at + timedelta(minutes=int(approval.sla_minutes))
    decided_at = _utc_datetime(approval.decided_at) if approval.decided_at is not None else None
    if now > deadline or (decided_at is not None and decided_at > deadline):
        raise ValueError("approval request expired outside its SLA")
    request_payload = dict(approval.request_payload or {})
    approved_action = request_payload.get("canonical_action")
    if (
        request_payload.get("type") != "agentic_action_approval"
        or request_payload.get("chain_id") != chain_id
        or not isinstance(approved_action, dict)
    ):
        raise ValueError("approval request does not match action semantics")
    approved_material, approved_hash = _approval_binding_contract(
        approved_action, tenant_id=tenant_id
    )
    if approved_material != material or approved_hash != canonical_hash:
        raise ValueError("approval request does not match action semantics")
    if not approval.decided_by or decided_at is None:
        raise ValueError("approval request lacks authenticated approval authority")

    explicit_expiry: datetime | None = None
    if expires_at is not None:
        if not isinstance(expires_at, datetime):
            raise ValueError("binding expiry must be a datetime")
        explicit_expiry = _utc_datetime(expires_at)
        if explicit_expiry <= now:
            raise ValueError("binding expiry is in the past")
    effective_expiry = min(deadline, explicit_expiry) if explicit_expiry is not None else deadline

    consumed = db.execute(
        update(ApprovalRequest)
        .where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.tenant_id == tenant_id,
            ApprovalRequest.status == "approved",
            ApprovalRequest.decision == "approve",
        )
        .values(status="used")
        .execution_options(synchronize_session=False)
    )
    if consumed.rowcount != 1:
        raise ValueError("approved approval request was already consumed")
    if _utc_datetime(clock_fn()) >= effective_expiry:
        db.rollback()
        raise ValueError("approval request or binding expired during consumption")
    db.flush()

    receipt = _json_hash({"approval_id": approval_id, "canonical_action_hash": canonical_hash, "tenant_id": tenant_id})
    binding = ApprovalBinding(
        tenant_id=tenant_id,
        chain_id=chain_id,
        action_id=material["action_id"] or None,
        approval_id=approval_id,
        canonical_action_hash=canonical_hash,
        receipt_material_hash=(
            _json_hash(material)
            if material.get("receipt_material_schema") == "1.0"
            else None
        ),
        signed_receipt=receipt,
        material_fields=material,
        approver_user_id=approval.decided_by,
        approved_at=decided_at,
        expires_at=effective_expiry,
        status="active",
    )
    db.add(binding)
    db.flush()
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="approval_binding",
        signal_type="agentic.approval.binding",
        label="Approval binding created",
        payload={"chain_id": chain_id, "approval_binding_id": binding.id, "material_fields": material},
    )
    _record_chain_event(
        db,
        tenant_id=tenant_id,
        chain_id=chain_id,
        event_type="approval_bound",
        actor_type="human",
        actor_id=approval.decided_by,
        evidence_bundle_id=evidence.id,
    )
    db.commit()
    return {
        "binding_id": binding.id,
        "status": binding.status,
        "decision": "allow",
        "control_mode": "inline_allowed",
        "drifted_fields": [],
        "evidence_bundle_id": evidence.id,
        "signed_receipt": receipt,
    }


def scan_mcp_tool(
    db: Session,
    *,
    tenant_id: str,
    mcp_server_id: str,
    tool_name: str,
    tool_version: str,
    description: str,
    schema: dict[str, Any],
    examples: list[Any],
    manifest: dict[str, Any] | None = None,
    chain_id: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    manifest_hash = _json_hash(manifest or {"tool_name": tool_name, "tool_version": tool_version})
    description_hash = _json_hash(description)
    schema_hash = _json_hash(schema)
    examples_hash = _json_hash(examples)
    receipt_chain_id = _tool_scan_receipt_chain_id(chain_id)
    row = db.scalar(
        select(ToolFingerprint).where(
            ToolFingerprint.tenant_id == tenant_id,
            ToolFingerprint.mcp_server_id == mcp_server_id,
            ToolFingerprint.tool_name == tool_name,
            ToolFingerprint.tool_version == tool_version,
        )
    )
    prior_version = None
    if row is None:
        prior_version = db.scalar(
            select(ToolFingerprint)
            .where(
                ToolFingerprint.tenant_id == tenant_id,
                ToolFingerprint.mcp_server_id == mcp_server_id,
                ToolFingerprint.tool_name == tool_name,
                ToolFingerprint.tool_version != tool_version,
            )
            .order_by(ToolFingerprint.last_scanned_at.desc())
        )
    existing_scan = None
    if (
        row is not None
        and receipt_chain_id
        and row.manifest_hash == manifest_hash
        and row.description_hash == description_hash
        and row.schema_hash == schema_hash
        and row.examples_hash == examples_hash
    ):
        existing_scan = db.scalar(
            select(ToolScanResult)
            .where(
                ToolScanResult.tenant_id == tenant_id,
                ToolScanResult.chain_id == receipt_chain_id,
                ToolScanResult.tool_fingerprint_id == row.id,
                ToolScanResult.tool_name == tool_name,
                ToolScanResult.trust_status == row.trust_status,
            )
            .order_by(ToolScanResult.created_at.desc())
        )
    risk_factors: list[str] = []
    trust_status = "unknown"
    if row is None:
        if prior_version is not None:
            risk_factors.append("tool_version_drift")
            trust_status = "changed"
        row = ToolFingerprint(
            tenant_id=tenant_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            tool_version=tool_version,
            manifest_hash=manifest_hash,
            description_hash=description_hash,
            schema_hash=schema_hash,
            examples_hash=examples_hash,
            trust_status=trust_status,
        )
        db.add(row)
        db.flush()
    else:
        if row.manifest_hash != manifest_hash:
            risk_factors.append("manifest_drift")
        if row.description_hash != description_hash:
            risk_factors.append("description_drift")
        if row.schema_hash != schema_hash:
            risk_factors.append("schema_drift")
        if row.examples_hash != examples_hash:
            risk_factors.append("examples_drift")
        if risk_factors:
            trust_status = "changed"
            row.trust_status = "changed"
            row.description_hash = description_hash
            row.schema_hash = schema_hash
            row.examples_hash = examples_hash
            row.manifest_hash = manifest_hash
            row.last_scanned_at = datetime.now(timezone.utc)
        else:
            trust_status = row.trust_status

    # The manifest can carry dynamic instructions and declarations that are
    # not duplicated in the MCP name, description, schema, or examples.  It
    # is therefore part of the same pre-exposure inspection unit; otherwise a
    # hostile registration could hide prompt-injection material there and be
    # approved before the model-facing exposure gate sees it.
    inspection_context = json.dumps(
        {"schema": schema, "examples": examples, "manifest": manifest or {}},
        default=str,
    )
    suspicious_text = " ".join([description, inspection_context]).lower()
    if "send" in suspicious_text and "external" in suspicious_text:
        risk_factors.append("external_destination_hint")
    if "ignore previous" in suspicious_text or "system prompt" in suspicious_text:
        risk_factors.append("instruction_like_metadata")

    # Extended tool-poisoning coverage: OWASP LLM/Agentic Top 10 + MITRE ATLAS.
    tool_scan_findings: list[dict[str, Any]] = []
    try:
        from app.services.guardians.threat_detectors import evaluate_threat_detectors

        detector_hits = evaluate_threat_detectors(
            prompt=description,
            context_summary=inspection_context,
            tool_output=json.dumps(examples, default=str),
            surface="mcp",
        )
        if isinstance(detector_hits, (str, bytes, dict)):
            raise ValueError("invalid detector response")
        for hit in detector_hits:
            if not isinstance(hit, dict):
                raise ValueError("invalid detector finding")
            raw_decision = hit.get("decision")
            if not isinstance(raw_decision, str):
                raise ValueError("invalid detector decision")
            detector_decision = raw_decision.strip().lower()
            if detector_decision not in TOOL_POISONING_DECISIONS:
                raise ValueError("invalid detector decision")
            threat_types = hit.get("threat_types") or []
            if not isinstance(threat_types, list) or any(
                not isinstance(threat_type, str) for threat_type in threat_types
            ):
                raise ValueError("invalid detector threat types")
            for threat_type in threat_types:
                risk_factors.append(f"tool_poisoning:{threat_type}")
            tool_scan_findings.append(
                {
                    "detector": hit.get("guardian_id"),
                    "threat_types": threat_types,
                    "decision": detector_decision,
                    "framework_refs": hit.get("framework_refs"),
                }
            )
    except Exception:  # noqa: BLE001 - detector internals are never exposed
        db.rollback()
        return {
            "scan_result_id": None,
            "request_id": request_id,
            "status": "failed",
            "idempotent_replay": False,
            "tool_fingerprint_id": None,
            "trust_status": "unknown",
            "risk_factors": ["tool_poisoning_scan_failed"],
            "evidence_bundle_id": None,
            "tool_poisoning_decision": "block",
            "tool_scan_findings": [],
            "error": "MCP tool metadata scan failed",
        }

    poisoning_decision = "allow"
    for finding in tool_scan_findings:
        candidate = str(finding.get("decision") or "allow").strip().lower()
        if TOOL_POISONING_DECISION_RANK.get(
            candidate,
            0,
        ) > TOOL_POISONING_DECISION_RANK.get(poisoning_decision, 0):
            poisoning_decision = candidate

    prior_risk_factors = (
        list(existing_scan.risk_factors or [])
        if existing_scan is not None
        else []
    )
    prior_poisoning_decision = _tool_poisoning_decision_from_factors(
        prior_risk_factors
    )
    if TOOL_POISONING_DECISION_RANK.get(
        prior_poisoning_decision,
        0,
    ) > TOOL_POISONING_DECISION_RANK.get(poisoning_decision, 0):
        poisoning_decision = prior_poisoning_decision
    risk_factors.extend(prior_risk_factors)
    risk_factors = _risk_factors_with_tool_poisoning_decision(
        risk_factors,
        poisoning_decision,
    )

    if existing_scan is not None:
        def persist_existing_scan(final_decision: str) -> str | None:
            final_risk_factors = _risk_factors_with_tool_poisoning_decision(
                risk_factors,
                final_decision,
            )
            existing_scan.risk_factors = final_risk_factors
            evidence = db.scalar(
                select(EvidenceNode).where(
                    EvidenceNode.id == existing_scan.evidence_node_id,
                    EvidenceNode.tenant_id == tenant_id,
                )
            )
            if evidence is not None:
                evidence_payload = dict(evidence.payload or {})
                evidence_payload["risk_factors"] = final_risk_factors
                evidence_payload["tool_poisoning_decision"] = final_decision
                evidence.payload = evidence_payload
            return existing_scan.evidence_node_id

        poisoning_decision = _commit_tool_poisoning_authority(
            db,
            tenant_id=tenant_id,
            fingerprint=row,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            proposed_decision=poisoning_decision,
            persist_scan=persist_existing_scan,
        )
        risk_factors = list(existing_scan.risk_factors or [])
        external_capability = _observe_external_capability_for_mcp_scan(
            db,
            tenant_id=tenant_id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            tool_version=tool_version,
            description=description,
            schema=schema,
            examples=examples,
            manifest=manifest,
            evidence_refs=[existing_scan.evidence_node_id] if existing_scan.evidence_node_id else [],
        )
        db.commit()
        return {
            "scan_result_id": existing_scan.id,
            "request_id": request_id,
            "status": "completed",
            "idempotent_replay": True,
            "tool_fingerprint_id": row.id,
            "trust_status": trust_status,
            "risk_factors": risk_factors,
            "evidence_bundle_id": existing_scan.evidence_node_id,
            "tool_poisoning_decision": poisoning_decision,
            "tool_scan_findings": tool_scan_findings,
            "external_capability": external_capability,
        }

    persisted: dict[str, Any] = {}

    def persist_new_scan(final_decision: str) -> str:
        final_risk_factors = _risk_factors_with_tool_poisoning_decision(
            risk_factors,
            final_decision,
        )
        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="mcp_tool_scan",
            signal_type="agentic.mcp.tool.scan",
            label=f"MCP tool scan: {tool_name}",
            payload={
                "mcp_server_id": mcp_server_id,
                "tool_name": tool_name,
                "tool_version": tool_version,
                "trust_status": trust_status,
                "risk_factors": final_risk_factors,
                "tool_poisoning_decision": final_decision,
                "fingerprint_id": row.id,
            },
        )
        scan = ToolScanResult(
            tenant_id=tenant_id,
            chain_id=receipt_chain_id,
            tool_fingerprint_id=row.id,
            mcp_server_id=mcp_server_id,
            tool_name=tool_name,
            trust_status=trust_status,
            risk_factors=final_risk_factors,
            evidence_node_id=evidence.id,
        )
        db.add(scan)
        db.flush()
        if chain_id:
            _record_chain_event(
                db,
                tenant_id=tenant_id,
                chain_id=chain_id,
                event_type="mcp_tool_scanned",
                source_id=mcp_server_id,
                destination_id=tool_name,
                evidence_bundle_id=evidence.id,
                metadata={
                    "trust_status": trust_status,
                    "risk_factors": final_risk_factors,
                },
            )
        if trust_status == "changed" or final_risk_factors:
            _record_agentic_finding(
                db,
                tenant_id=tenant_id,
                finding_type="MCP_TOOL_METADATA_DRIFT",
                chain_id=chain_id or f"mcp-tool:{mcp_server_id}:{tool_name}",
                evidence_node_id=evidence.id,
                source_surface="gateway",
                ai_tool=tool_name,
                decision=(
                    "require_approval"
                    if trust_status == "changed"
                    else "warn"
                ),
                control_mode=(
                    "external_required"
                    if trust_status == "changed"
                    else "warned"
                ),
                metadata={
                    "mcp_server_id": mcp_server_id,
                    "risk_factors": final_risk_factors,
                },
            )
        if "schema_drift" in final_risk_factors:
            _record_agentic_finding(
                db,
                tenant_id=tenant_id,
                finding_type="MCP_TOOL_SCHEMA_CHANGED",
                chain_id=chain_id or f"mcp-tool:{mcp_server_id}:{tool_name}",
                evidence_node_id=evidence.id,
                source_surface="gateway",
                ai_tool=tool_name,
                decision="require_approval",
                control_mode="external_required",
                metadata={
                    "mcp_server_id": mcp_server_id,
                    "risk_factors": final_risk_factors,
                },
            )
        persisted.update(
            {
                "scan": scan,
                "evidence": evidence,
                "risk_factors": final_risk_factors,
            }
        )
        return evidence.id

    poisoning_decision = _commit_tool_poisoning_authority(
        db,
        tenant_id=tenant_id,
        fingerprint=row,
        mcp_server_id=mcp_server_id,
        tool_name=tool_name,
        proposed_decision=poisoning_decision,
        persist_scan=persist_new_scan,
    )
    scan = persisted["scan"]
    evidence = persisted["evidence"]
    risk_factors = persisted["risk_factors"]
    external_capability = _observe_external_capability_for_mcp_scan(
        db,
        tenant_id=tenant_id,
        mcp_server_id=mcp_server_id,
        tool_name=tool_name,
        tool_version=tool_version,
        description=description,
        schema=schema,
        examples=examples,
        manifest=manifest,
        evidence_refs=[evidence.id],
    )
    db.commit()
    return {
        "scan_result_id": scan.id,
        "request_id": request_id,
        "status": "completed",
        "idempotent_replay": False,
        "tool_fingerprint_id": row.id,
        "trust_status": trust_status,
        "risk_factors": risk_factors,
        "evidence_bundle_id": evidence.id,
        "tool_poisoning_decision": poisoning_decision,
        "tool_scan_findings": tool_scan_findings,
        "external_capability": external_capability,
    }


def evaluate_mcp_tool_call_integrity(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    action_id: str,
    agent_id: str | None,
    action: str,
    resource: str,
    tool_name: str | None,
    tool_version: str | None = None,
    tool_fingerprint_id: str | None = None,
    mcp_server_id: str | None = None,
    api_endpoint: str | None = None,
    parameters: dict[str, Any] | list[Any] | None = None,
    current_decision: str = "allow",
) -> dict[str, Any]:
    resolved_tool = _safe_str(tool_name or action, max_len=128) or "unknown_mcp_tool"
    resolved_version = _safe_str(tool_version or "unknown", max_len=64) or "unknown"
    resolved_chain = _safe_str(chain_id or action_id, max_len=64) or _json_hash({"action_id": action_id})[:32]
    resolved_agent = _safe_str(agent_id or "unknown_agent", max_len=128) or "unknown_agent"
    resolved_server = _safe_str(mcp_server_id, max_len=128)
    if not resolved_server:
        endpoint = _safe_str(api_endpoint, max_len=255)
        if endpoint.startswith("mcp://"):
            resolved_server = endpoint.removeprefix("mcp://").split("/", 1)[0][:128]
    if not resolved_server:
        resolved_server = _safe_str(resource, max_len=128).split("/", 1)[0] or "unknown_mcp_server"

    fingerprint = db.scalar(
        select(ToolFingerprint).where(
            ToolFingerprint.tenant_id == tenant_id,
            ToolFingerprint.mcp_server_id == resolved_server,
            ToolFingerprint.tool_name == resolved_tool,
            ToolFingerprint.tool_version == resolved_version,
        )
    )
    claimed_tool_fingerprint_id = _safe_str(tool_fingerprint_id, max_len=128)
    current_tool_fingerprint_id = _safe_str(
        getattr(fingerprint, "id", None),
        max_len=128,
    )
    tool_fingerprint_mismatch = bool(
        claimed_tool_fingerprint_id
        and claimed_tool_fingerprint_id != current_tool_fingerprint_id
    )
    trust_status = _safe_str(getattr(fingerprint, "trust_status", None), max_len=32) or "unknown"
    fingerprint_unchanged = bool(
        fingerprint is not None
        and _safe_str(getattr(fingerprint, "approved_hash", None), max_len=128)
        and _safe_str(getattr(fingerprint, "approved_hash", None), max_len=128)
        == _safe_str(getattr(fingerprint, "manifest_hash", None), max_len=128)
    )
    exact_approved_fingerprint_authority = bool(
        claimed_tool_fingerprint_id
        and claimed_tool_fingerprint_id == current_tool_fingerprint_id
        and trust_status == "approved"
        and fingerprint_unchanged
    )
    try:
        from app.services.external_capability_integrity import ExternalCapabilityIntegrityService

        external_capability = ExternalCapabilityIntegrityService().resolve_for_mcp_tool(
            db,
            tenant_id=tenant_id,
            tool_fingerprint=claimed_tool_fingerprint_id or current_tool_fingerprint_id,
        )
    except Exception:  # noqa: BLE001 - ECI must fail closed without exposing internals
        external_capability = {
            "trust_state": "UNKNOWN",
            "reason": "external_capability_resolution_failed",
        }
    persisted_poisoning_decision = "allow"
    poisoning_decision_rank = {
        "allow": 0,
        "warn": 1,
        "redact": 2,
        "hold_for_approval": 3,
        "block": 4,
    }
    if fingerprint is not None:
        persisted_scan = db.scalar(
            select(ToolScanResult)
            .where(
                ToolScanResult.id == fingerprint.id,
                ToolScanResult.tenant_id == tenant_id,
                ToolScanResult.chain_id
                == _tool_poisoning_authority_chain_id(fingerprint.id),
                ToolScanResult.tool_fingerprint_id == fingerprint.id,
            )
            .limit(1)
        )
        if persisted_scan is not None:
            for factor in persisted_scan.risk_factors or []:
                marker, separator, candidate = str(factor).partition(":")
                if marker != "tool_poisoning_decision" or not separator:
                    continue
                normalized_candidate = candidate.strip().lower()
                if poisoning_decision_rank.get(
                    normalized_candidate,
                    0,
                ) > poisoning_decision_rank.get(persisted_poisoning_decision, 0):
                    persisted_poisoning_decision = normalized_candidate

    risk_factors: set[str] = set()
    finding_types: set[str] = set()
    text = " ".join(
        [
            _safe_str(action, max_len=256),
            _safe_str(resource, max_len=512),
            resolved_tool,
            _safe_str(api_endpoint, max_len=512),
            json.dumps(parameters or {}, sort_keys=True, default=str)[:4000],
        ]
    ).lower()

    write_admin_tokens = (
        "write",
        "delete",
        "update",
        "modify",
        "grant",
        "role",
        "admin",
        "permission",
        "deploy",
        "trigger_pipeline",
        "create_pr",
        "create_webhook",
        "scheduled_job",
        "execute",
        "terminal",
        "shell",
    )
    secret_tokens = (
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "credential",
        "password",
        ".env",
        "connection_string",
    )
    external_tokens = ("webhook", "callback", "external", "http://", "https://")

    if any(token in text for token in write_admin_tokens):
        risk_factors.add("high_risk_mcp_action")
        finding_types.add("HIGH_RISK_MCP_ACTION")
    if any(token in text for token in ("write", "delete", "modify", "grant", "role", "admin", "create_pr", "deploy")):
        risk_factors.add("write_or_admin_side_effect")
        finding_types.add("MCP_TOOL_ATTEMPTED_CODE_WRITE")
    if any(token in text for token in secret_tokens):
        risk_factors.add("secret_or_credential_access")
        finding_types.add("AI_AGENT_SECRET_ACCESS_ATTEMPT")
    if any(token in text for token in external_tokens):
        risk_factors.add("external_destination_or_deferred_side_effect")
    if "admin:*" in text or "\"role\": \"admin\"" in text or "'role': 'admin'" in text:
        risk_factors.add("admin_scope_parameter")
        finding_types.add("TOOL_PARAMETER_POLICY_VIOLATION")
    if fingerprint is None or trust_status == "unknown":
        risk_factors.add(f"tool_trust_{trust_status}")
    external_trust_state = _safe_str(
        external_capability.get("trust_state"),
        max_len=32,
    ).upper() or "UNKNOWN"
    if external_trust_state != "TRUSTED_CURRENT":
        risk_factors.add(f"external_capability_trust_{external_trust_state.lower()}")
        finding_types.add("MCP_TOOL_METADATA_DRIFT")
    if not claimed_tool_fingerprint_id:
        risk_factors.add("tool_fingerprint_missing")
    if tool_fingerprint_mismatch:
        risk_factors.add("tool_fingerprint_mismatch")
    if not exact_approved_fingerprint_authority:
        finding_types.add("MCP_TOOL_METADATA_DRIFT")
        if fingerprint is not None and trust_status == "approved" and not fingerprint_unchanged:
            risk_factors.add("tool_fingerprint_not_current")
    if trust_status in {"changed", "blocked", "under_review"}:
        risk_factors.add(f"tool_trust_{trust_status}")
        finding_types.add("UNAPPROVED_MCP_TOOL_VERSION")
    if trust_status == "changed":
        finding_types.add("MCP_TOOL_METADATA_DRIFT")
    if persisted_poisoning_decision != "allow":
        risk_factors.add(
            f"tool_poisoning_decision:{persisted_poisoning_decision}"
        )
        finding_types.add("MCP_TOOL_METADATA_DRIFT")

    decision = current_decision or "allow"
    if (
        not exact_approved_fingerprint_authority
        or external_trust_state in {"REGRESSED", "REVOKED"}
        or persisted_poisoning_decision in {"redact", "block"}
        or any(
        factor in risk_factors
        for factor in ("secret_or_credential_access", "write_or_admin_side_effect")
        )
    ):
        decision = "block"
        control_mode = "inline_prevented"
    elif (
        "high_risk_mcp_action" in risk_factors
        or trust_status in {"changed", "under_review", "blocked"}
        or persisted_poisoning_decision in {"warn", "hold_for_approval"}
    ):
        decision = "require_approval" if decision == "allow" else decision
        control_mode = "external_required" if decision != "block" else "inline_prevented"
    else:
        control_mode = "inline_allowed" if decision == "allow" else "warned"

    risk_level = "critical" if decision == "block" else "high" if risk_factors else "low"
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="mcp_tool_call_integrity",
        signal_type="agentic.mcp.tool_call.integrity",
        label=f"MCP tool call integrity: {resolved_tool}",
        payload={
            "chain_id": resolved_chain,
            "action_id": _safe_str(action_id, max_len=64),
            "agent_id": resolved_agent,
            "mcp_server_id": resolved_server,
            "tool_name": resolved_tool,
            "tool_version": resolved_version,
            "tool_fingerprint_id": getattr(fingerprint, "id", None),
            "claimed_tool_fingerprint_id": claimed_tool_fingerprint_id or None,
            "external_capability": external_capability,
            "trust_status": trust_status,
            "decision": decision,
            "control_mode": control_mode,
            "risk_factors": sorted(risk_factors),
            "parameter_keys": sorted((parameters or {}).keys()) if isinstance(parameters, dict) else [],
            "target_resource_ref": _json_hash(resource)[:24],
        },
    )
    _record_chain_event(
        db,
        tenant_id=tenant_id,
        chain_id=resolved_chain,
        action_id=_safe_str(action_id, max_len=64),
        event_type="mcp_tool_called",
        actor_type="agent",
        actor_id=resolved_agent,
        source_id=resolved_agent,
        destination_id=resolved_tool,
        evidence_bundle_id=evidence.id,
        metadata={
            "policy_decision": decision,
            "mcp_server_id": resolved_server,
            "tool_name": resolved_tool,
            "trust_status": trust_status,
            "external_capability": external_capability,
            "risk_factors": sorted(risk_factors),
            "control_mode": control_mode,
        },
    )
    _record_touchpoint_edge_once(
        db,
        tenant_id=tenant_id,
        chain_id=resolved_chain,
        source_node_type="agent",
        source_node_id=resolved_agent,
        target_node_type="mcp_server",
        target_node_id=resolved_server,
        edge_type="connects_to",
        risk_level=risk_level,
        control_mode=control_mode,
        evidence_bundle_id=evidence.id,
        action_id=_safe_str(action_id, max_len=64),
    )
    _record_touchpoint_edge_once(
        db,
        tenant_id=tenant_id,
        chain_id=resolved_chain,
        source_node_type="agent",
        source_node_id=resolved_agent,
        target_node_type="mcp_tool",
        target_node_id=resolved_tool,
        edge_type="invoked_tool",
        risk_level=risk_level,
        control_mode=control_mode,
        evidence_bundle_id=evidence.id,
        action_id=_safe_str(action_id, max_len=64),
    )
    if decision == "block":
        _record_touchpoint_edge_once(
            db,
            tenant_id=tenant_id,
            chain_id=resolved_chain,
            source_node_type="policy",
            source_node_id="agentic_action_integrity",
            target_node_type="mcp_tool",
            target_node_id=resolved_tool,
            edge_type="blocked_by_policy",
            risk_level=risk_level,
            control_mode=control_mode,
            evidence_bundle_id=evidence.id,
            action_id=_safe_str(action_id, max_len=64),
        )

    for finding_type in sorted(finding_types):
        _record_agentic_finding(
            db,
            tenant_id=tenant_id,
            finding_type=finding_type,
            chain_id=resolved_chain,
            evidence_node_id=evidence.id,
            source_surface="gateway",
            ai_tool=resolved_tool,
            agent_id=resolved_agent if resolved_agent != "unknown_agent" else None,
            decision=decision,
            control_mode=control_mode,
            action_id=_safe_str(action_id, max_len=64),
            metadata={
                "mcp_server_id": resolved_server,
                "tool_version": resolved_version,
                "claimed_tool_fingerprint_id": claimed_tool_fingerprint_id or None,
                "trust_status": trust_status,
                "external_capability": external_capability,
                "risk_factors": sorted(risk_factors),
            },
        )

    return {
        "decision": decision,
        "control_mode": control_mode,
        "risk_level": risk_level,
        "risk_factors": sorted(risk_factors),
        "finding_types": sorted(finding_types),
        "evidence_bundle_id": evidence.id,
        "tool_fingerprint_id": getattr(fingerprint, "id", None),
        "claimed_tool_fingerprint_id": claimed_tool_fingerprint_id or None,
        "trust_status": trust_status,
        "external_capability": external_capability,
        "mcp_server_id": resolved_server,
        "tool_name": resolved_tool,
        "tool_version": resolved_version,
    }


def evaluate_jit_grant(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    agent_id: str,
    requested_scope: list[str],
    approved_scope: list[str],
    approved_task: str,
    actual_action: str,
    identity_provider: str | None = None,
    grant_type: str = "temporary",
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    requested = set(_list_strings(requested_scope))
    approved = set(_list_strings(approved_scope))
    delta = sorted(requested - approved)
    risk_factors: list[str] = []
    if delta:
        risk_factors.append("scope_exceeds_approved_task")
    if any(token in actual_action.lower() for token in ("grant", "admin", "token", "oauth", "role")):
        risk_factors.append("persistent_or_privileged_action")
    decision = "allow"
    if "persistent_or_privileged_action" in risk_factors:
        decision = "block" if delta else "require_approval"
    elif delta:
        decision = "require_approval"
    binding = JITGrantBinding(
        tenant_id=tenant_id,
        chain_id=chain_id,
        agent_id=agent_id,
        requested_scope=sorted(requested),
        approved_scope=sorted(approved),
        identity_provider=identity_provider,
        grant_type=grant_type,
        expires_at=expires_at,
        task_binding_hash=_json_hash({"approved_task": approved_task, "actual_action": actual_action}),
        privilege_delta=delta,
        persistence_risk="persistent" if "persistent_or_privileged_action" in risk_factors else "none",
        status="blocked" if decision == "block" else "review_required" if decision != "allow" else "approved",
    )
    db.add(binding)
    db.flush()
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="jit_grant_evaluation",
        signal_type="agentic.jit.evaluate",
        label=f"JIT grant {binding.status}",
        payload={
            "chain_id": chain_id,
            "agent_id": agent_id,
            "decision": decision,
            "risk_factors": risk_factors,
            "privilege_delta": delta,
            "task_binding_hash": binding.task_binding_hash,
        },
    )
    binding.evidence_bundle_id = evidence.id
    _record_chain_event(
        db,
        tenant_id=tenant_id,
        chain_id=chain_id,
        event_type="jit_grant_evaluated",
        actor_type="agent",
        actor_id=agent_id,
        evidence_bundle_id=evidence.id,
        metadata={"decision": decision, "risk_factors": risk_factors},
    )
    _record_behavior_edge(
        db,
        tenant_id=tenant_id,
        chain_id=chain_id,
        source_node_type="agent",
        source_node_id=agent_id,
        target_node_type="jit_grant",
        target_node_id=binding.id,
        relationship_type="requested_jit_grant",
        evidence_node_id=evidence.id,
        payload={"decision": decision, "risk_factors": risk_factors},
    )
    _record_touchpoint_edge(
        db,
        tenant_id=tenant_id,
        chain_id=chain_id,
        source_node_type="agent",
        source_node_id=agent_id,
        target_node_type="jit_grant",
        target_node_id=binding.id,
        edge_type="requested_jit_grant",
        risk_level="high" if decision != "allow" else "low",
        control_mode="inline_prevented" if decision == "block" else "external_required" if decision != "allow" else "inline_allowed",
        evidence_bundle_id=evidence.id,
    )
    if delta:
        _record_agentic_finding(
            db,
            tenant_id=tenant_id,
            finding_type="JIT_SCOPE_EXCEEDS_APPROVED_TASK",
            chain_id=chain_id,
            evidence_node_id=evidence.id,
            source_surface="aiiam",
            ai_tool="jit_grant",
            agent_id=agent_id,
            decision=decision,
            control_mode="inline_prevented" if decision == "block" else "external_required",
            metadata={"privilege_delta": delta, "actual_action": actual_action},
        )
    if "persistent_or_privileged_action" in risk_factors:
        _record_agentic_finding(
            db,
            tenant_id=tenant_id,
            finding_type="JIT_PRIVILEGE_ESCALATION",
            chain_id=chain_id,
            evidence_node_id=evidence.id,
            source_surface="aiiam",
            ai_tool="jit_grant",
            agent_id=agent_id,
            decision=decision,
            control_mode="inline_prevented" if decision == "block" else "external_required",
            metadata={"actual_action": actual_action, "risk_factors": risk_factors},
        )
    db.commit()
    return {
        "jit_grant_binding_id": binding.id,
        "decision": decision,
        "control_mode": "inline_prevented" if decision == "block" else "external_required" if decision != "allow" else "inline_allowed",
        "risk_factors": sorted(set(risk_factors)),
        "evidence_bundle_id": evidence.id,
    }


def record_deferred_side_effect(
    db: Session,
    *,
    tenant_id: str,
    chain_id: str,
    action_id: str | None,
    agent_id: str | None,
    side_effect_type: str,
    target_system: str | None,
    target_resource: str | None,
    external_destination: str | None,
    persistence_duration: str | None,
) -> dict[str, Any]:
    normalized_type = _safe_str(side_effect_type, max_len=64).lower() or "unknown"
    requires_approval = normalized_type in HIGH_RISK_SIDE_EFFECTS or bool(external_destination)
    decision = "require_approval" if requires_approval else "warn"
    row = DeferredSideEffect(
        tenant_id=tenant_id,
        chain_id=chain_id,
        action_id=action_id,
        agent_id=agent_id,
        side_effect_type=normalized_type,
        target_system=_safe_str(target_system, max_len=128) or None,
        target_resource=_safe_str(target_resource, max_len=255) or None,
        external_destination=_safe_str(external_destination, max_len=255) or None,
        persistence_duration=_safe_str(persistence_duration, max_len=64) or None,
        approval_required=requires_approval,
        monitoring_status="pending",
    )
    db.add(row)
    db.flush()
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="deferred_side_effect",
        signal_type="agentic.deferred_side_effect",
        label=f"Deferred side effect: {normalized_type}",
        payload={
            "chain_id": chain_id,
            "action_id": action_id,
            "agent_id": agent_id,
            "side_effect_type": normalized_type,
            "target_system": target_system,
            "target_resource": target_resource,
            "external_destination": external_destination,
            "decision": decision,
        },
    )
    row.evidence_bundle_id = evidence.id
    _record_chain_event(
        db,
        tenant_id=tenant_id,
        chain_id=chain_id,
        action_id=action_id,
        event_type="deferred_side_effect_created",
        actor_type="agent" if agent_id else "unknown",
        actor_id=agent_id,
        destination_id=external_destination or target_resource,
        evidence_bundle_id=evidence.id,
        metadata={"decision": decision, "side_effect_type": normalized_type},
    )
    if requires_approval:
        _record_agentic_finding(
            db,
            tenant_id=tenant_id,
            finding_type="DEFERRED_SIDE_EFFECT_REQUIRES_APPROVAL",
            chain_id=chain_id,
            evidence_node_id=evidence.id,
            source_surface="aiiam",
            ai_tool=normalized_type,
            agent_id=agent_id,
            decision=decision,
            control_mode="external_required",
            action_id=action_id,
            metadata={"side_effect_type": normalized_type, "external_destination": external_destination},
        )
        specific_type = {
            "webhook": "AGENT_CREATED_WEBHOOK",
            "external_callback": "AGENT_CREATED_WEBHOOK",
            "scheduled_job": "AGENT_CREATED_SCHEDULED_JOB",
            "scheduled_workflow": "AGENT_CREATED_SCHEDULED_JOB",
            "persistent_memory": "AGENT_CREATED_PERSISTENT_MEMORY",
        }.get(normalized_type)
        if specific_type:
            _record_agentic_finding(
                db,
                tenant_id=tenant_id,
                finding_type=specific_type,
                chain_id=chain_id,
                evidence_node_id=evidence.id,
                source_surface="aiiam",
                ai_tool=normalized_type,
                agent_id=agent_id,
                decision=decision,
                control_mode="external_required",
                action_id=action_id,
                metadata={"side_effect_type": normalized_type, "external_destination": external_destination},
            )
    if agent_id:
        _record_behavior_edge(
            db,
            tenant_id=tenant_id,
            chain_id=chain_id,
            source_node_type="agent",
            source_node_id=agent_id,
            target_node_type="deferred_side_effect",
            target_node_id=row.id,
            relationship_type="created_side_effect",
            evidence_node_id=evidence.id,
            target_label=normalized_type,
            payload={"decision": decision},
        )
        _record_touchpoint_edge(
            db,
            tenant_id=tenant_id,
            chain_id=chain_id,
            source_node_type="agent",
            source_node_id=agent_id,
            target_node_type="deferred_side_effect",
            target_node_id=row.id,
            edge_type="created_side_effect",
            risk_level="high" if requires_approval else "medium",
            control_mode="external_required" if requires_approval else "warned",
            evidence_bundle_id=evidence.id,
        )
        if external_destination:
            _record_behavior_edge(
                db,
                tenant_id=tenant_id,
                chain_id=chain_id,
                source_node_type="deferred_side_effect",
                source_node_id=row.id,
                target_node_type="external_destination",
                target_node_id=_safe_str(external_destination, max_len=128),
                relationship_type="sends_to_external",
                evidence_node_id=evidence.id,
            )
    db.commit()
    return {
        "deferred_side_effect_id": row.id,
        "decision": decision,
        "control_mode": "external_required" if requires_approval else "warned",
        "approval_required": requires_approval,
        "evidence_bundle_id": evidence.id,
    }


def chain_graph(db: Session, *, tenant_id: str, chain_id: str) -> dict[str, Any]:
    rows = db.scalars(select(RuntimeBehaviorEdge).where(RuntimeBehaviorEdge.tenant_id == tenant_id)).all()
    rows = [row for row in rows if isinstance(row.payload, dict) and row.payload.get("chain_id") == chain_id]
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for row in rows:
        source_key = f"{row.source_node_type}:{row.source_node_id}"
        target_key = f"{row.target_node_type}:{row.target_node_id}"
        nodes[source_key] = {"node_type": row.source_node_type, "node_id": row.source_node_id, "label": row.source_node_label}
        nodes[target_key] = {"node_type": row.target_node_type, "node_id": row.target_node_id, "label": row.target_node_label}
        edges.append(
            {
                "edge_id": row.id,
                "relationship_type": row.relationship_type,
                "source_node_type": row.source_node_type,
                "source_node_id": row.source_node_id,
                "target_node_type": row.target_node_type,
                "target_node_id": row.target_node_id,
                "evidence_node_id": row.evidence_node_id,
                "payload": row.payload or {},
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        )
    events = db.scalars(
        select(ChainEvent).where(ChainEvent.tenant_id == tenant_id, ChainEvent.chain_id == chain_id)
    ).all()
    return {
        "chain_id": chain_id,
        "nodes": sorted(nodes.values(), key=lambda item: (item["node_type"], item["node_id"])),
        "edges": edges,
        "total_edges": len(edges),
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "action_id": event.action_id,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "evidence_bundle_id": event.evidence_bundle_id,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }
            for event in events
        ],
    }


def chain_evidence(db: Session, *, tenant_id: str, chain_id: str) -> dict[str, Any]:
    events = db.scalars(
        select(ChainEvent).where(ChainEvent.tenant_id == tenant_id, ChainEvent.chain_id == chain_id)
    ).all()
    evidence_ids = sorted({event.evidence_bundle_id for event in events if event.evidence_bundle_id})
    nodes = db.scalars(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id.in_(evidence_ids))).all() if evidence_ids else []
    return {
        "chain_id": chain_id,
        "evidence_bundle_ids": evidence_ids,
        "evidence": [
            {
                "id": node.id,
                "node_type": node.node_type,
                "signal_type": node.signal_type,
                "label": node.label,
                "payload": node.payload,
                "created_at": node.created_at.isoformat() if node.created_at else None,
            }
            for node in nodes
        ],
    }


def agent_touchpoints(db: Session, *, tenant_id: str, agent_id: str) -> dict[str, Any]:
    rows = db.scalars(
        select(AgentTouchpointEdge).where(
            AgentTouchpointEdge.tenant_id == tenant_id,
            (AgentTouchpointEdge.source_node_id == agent_id) | (AgentTouchpointEdge.target_node_id == agent_id),
        )
    ).all()
    edges = [
        {
            "id": row.id,
            "source_node_type": row.source_node_type,
            "source_node_id": row.source_node_id,
            "target_node_type": row.target_node_type,
            "target_node_id": row.target_node_id,
            "edge_type": row.edge_type,
            "chain_id": row.chain_id,
            "action_id": row.action_id,
            "risk_level": row.risk_level,
            "control_mode": row.control_mode,
            "evidence_bundle_id": row.evidence_bundle_id,
            "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        }
        for row in rows
    ]
    nodes_by_key: dict[str, dict[str, Any]] = {}
    for edge in edges:
        for side in ("source", "target"):
            node_type = str(edge.get(f"{side}_node_type") or "unknown")
            node_id = str(edge.get(f"{side}_node_id") or "unknown")
            key = f"{node_type}:{node_id}"
            node = nodes_by_key.setdefault(
                key,
                {
                    "id": key,
                    "node_type": node_type,
                    "node_id": node_id,
                    "incoming": 0,
                    "outgoing": 0,
                    "risk_levels": [],
                    "control_modes": [],
                    "evidence_count": 0,
                },
            )
            if side == "source":
                node["outgoing"] += 1
            else:
                node["incoming"] += 1
            if edge.get("risk_level"):
                node["risk_levels"].append(edge["risk_level"])
            if edge.get("control_mode"):
                node["control_modes"].append(edge["control_mode"])
            if edge.get("evidence_bundle_id"):
                node["evidence_count"] += 1

    evidence_count = sum(1 for edge in edges if edge.get("evidence_bundle_id"))
    total_edges = len(edges)
    missing_evidence = max(0, total_edges - evidence_count)
    evidence_summary = {
        "total_edges": total_edges,
        "edges_with_evidence": evidence_count,
        "missing_evidence": missing_evidence,
        "completeness_score": evidence_count / total_edges if total_edges else 1.0,
    }
    risk_badges: list[dict[str, str]] = []
    if any(edge.get("risk_level") in {"high", "critical"} and edge.get("target_node_type") in {"mcp_tool", "tool"} for edge in edges):
        risk_badges.append({"id": "high_risk_tool_action", "label": "High-risk tool action", "severity": "critical"})
    if any(edge.get("control_mode") == "inline_prevented" for edge in edges):
        risk_badges.append({"id": "inline_prevention", "label": "Inline prevention observed", "severity": "high"})
    if any(edge.get("control_mode") == "external_required" for edge in edges):
        risk_badges.append({"id": "external_enforcement_required", "label": "External enforcement required", "severity": "medium"})
    if any(edge.get("target_node_type") == "saas_app" for edge in edges):
        risk_badges.append({"id": "saas_touchpoint", "label": "SaaS/admin touchpoint", "severity": "medium"})
    if any(edge.get("target_node_type") in {"data_source", "repo"} for edge in edges):
        risk_badges.append({"id": "sensitive_resource_reach", "label": "Data or repo reach", "severity": "medium"})
    if missing_evidence:
        risk_badges.append({"id": "incomplete_evidence", "label": "Incomplete evidence", "severity": "medium"})

    timeline = [
        {
            "id": edge["id"],
            "chain_id": edge.get("chain_id"),
            "action_id": edge.get("action_id"),
            "event": edge.get("edge_type"),
            "source": {
                "type": edge.get("source_node_type"),
                "id": edge.get("source_node_id"),
            },
            "target": {
                "type": edge.get("target_node_type"),
                "id": edge.get("target_node_id"),
            },
            "control_mode": edge.get("control_mode"),
            "risk_level": edge.get("risk_level"),
            "evidence_bundle_id": edge.get("evidence_bundle_id"),
            "evidence_linked": bool(edge.get("evidence_bundle_id")),
            "last_seen_at": edge.get("last_seen_at"),
        }
        for edge in sorted(edges, key=lambda item: str(item.get("last_seen_at") or ""))
    ]
    return {
        "agent_id": agent_id,
        "edges": edges,
        "nodes": list(nodes_by_key.values()),
        "risk_badges": risk_badges,
        "evidence_summary": evidence_summary,
        "timeline": timeline,
        "total_edges": total_edges,
    }


def agent_blast_radius(db: Session, *, tenant_id: str, agent_id: str) -> dict[str, Any]:
    touchpoints = agent_touchpoints(db, tenant_id=tenant_id, agent_id=agent_id)["edges"]
    target_types = [row["target_node_type"] for row in touchpoints]
    chain_ids = {row.get("chain_id") for row in touchpoints if row.get("chain_id")}
    side_effect_rows = []
    if chain_ids:
        side_effect_rows = db.scalars(
            select(DeferredSideEffect).where(
                DeferredSideEffect.tenant_id == tenant_id,
                DeferredSideEffect.chain_id.in_(chain_ids),
            )
        ).all()
    persistent = [row for row in side_effect_rows if str(row.persistence_duration or "").lower() in {"persistent", "future"} or row.approval_required]
    external = [row for row in side_effect_rows if str(row.external_destination or "").strip()]
    high_risk = sum(1 for row in touchpoints if row["risk_level"] in {"high", "critical"})
    counts = {
        "reachable_tools_count": target_types.count("mcp_tool"),
        "reachable_mcp_servers_count": target_types.count("mcp_server"),
        "reachable_saas_apps_count": target_types.count("saas_app"),
        "reachable_repos_count": target_types.count("repo"),
        "reachable_data_sources_count": target_types.count("data_source"),
        "high_risk_actions_count": high_risk,
        "persistent_side_effects_count": len(persistent),
        "external_destinations_count": len(external),
        "delegation_depth_max": 0,
    }
    summary = {"agent_id": agent_id, **counts}
    scores = {
        "data_access_score": min(1.0, counts["reachable_data_sources_count"] / 5),
        "tool_action_score": min(1.0, (counts["reachable_tools_count"] + high_risk) / 5),
        "privilege_score": 1.0 if high_risk else 0.0,
        "persistence_score": min(1.0, len(persistent) / 3),
        "external_exfiltration_score": min(1.0, len(external) / 3),
        "delegation_score": 0.0,
    }
    overall = max(scores.values()) if scores else 0.0
    snapshot = BlastRadiusSnapshot(
        tenant_id=tenant_id,
        subject_type="agent",
        subject_id=agent_id,
        **counts,
        **scores,
        overall_blast_radius_score=overall,
    )
    db.add(snapshot)
    db.commit()
    return {**summary, **scores, "overall_blast_radius_score": overall, "snapshot_id": snapshot.id}
