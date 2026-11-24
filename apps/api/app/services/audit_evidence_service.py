from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.simulation import Control


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_float(value: Any) -> float | None:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    if num < 0.0:
        return 0.0
    if num > 1.0:
        return 1.0
    return round(num, 4)


def _normalize_framework_name(name: str) -> str:
    text = name.strip()
    lower = text.lower()
    if "iso" in lower:
        return "ISO 42001"
    if "gdpr" in lower:
        return "GDPR"
    if "eu ai act" in lower:
        return "EU AI Act"
    if "nist" in lower:
        return "NIST AI RMF"
    if "owasp" in lower:
        return "OWASP GenAI"
    if "mitre" in lower:
        return "MITRE ATLAS"
    return text or "Unmapped"


def _framework_rows_from_policy(
    db: Session,
    *,
    tenant_id: str,
    policy_version: PolicyVersion | None,
    evidence_payload: dict[str, Any],
) -> list[dict[str, Any]]:
    buckets: dict[str, set[str]] = defaultdict(set)

    payload_framework = evidence_payload.get("framework_mapping")
    if isinstance(payload_framework, dict):
        for key, values in payload_framework.items():
            framework = _normalize_framework_name(_safe_text(key))
            if isinstance(values, list):
                for value in values:
                    ref = _safe_text(value)
                    if ref:
                        buckets[framework].add(ref)
            elif _safe_text(values):
                buckets[framework].add(_safe_text(values))

    control_ids: set[str] = set()
    if policy_version is not None:
        for contract in list(policy_version.guardian_contracts or []):
            if not isinstance(contract, dict):
                continue
            framework_mappings = contract.get("framework_mappings")
            if isinstance(framework_mappings, dict):
                for key, values in framework_mappings.items():
                    framework = _normalize_framework_name(_safe_text(key))
                    if isinstance(values, list):
                        for value in values:
                            ref = _safe_text(value)
                            if ref:
                                buckets[framework].add(ref)
                    elif _safe_text(values):
                        buckets[framework].add(_safe_text(values))

            evidence = contract.get("evidence")
            if isinstance(evidence, dict):
                for control_id in list(evidence.get("link_to_controls") or []):
                    normalized = _safe_text(control_id)
                    if normalized:
                        control_ids.add(normalized)
            control_impact = contract.get("control_impact")
            if isinstance(control_impact, dict):
                for control_id in list(control_impact.get("control_ids") or []):
                    normalized = _safe_text(control_id)
                    if normalized:
                        control_ids.add(normalized)

    if control_ids:
        rows = db.scalars(
            select(Control).where(
                Control.tenant_id == tenant_id,
                Control.id.in_(sorted(control_ids)),
            )
        ).all()
        seen_control_ids = {str(row.id) for row in rows}
        for control in rows:
            mapped = list(control.mapped_framework_refs or [])
            for ref in mapped:
                if not isinstance(ref, dict):
                    continue
                framework = _normalize_framework_name(_safe_text(ref.get("framework")))
                control_ref = _safe_text(ref.get("control_ref") or ref.get("id") or ref.get("name"))
                if control_ref:
                    buckets[framework].add(control_ref)
        for control_id in control_ids:
            if control_id in seen_control_ids:
                continue
            lower = control_id.lower()
            if "iso" in lower:
                buckets["ISO 42001"].add(control_id)
            elif "gdpr" in lower:
                buckets["GDPR"].add(control_id)
            elif "eu" in lower:
                buckets["EU AI Act"].add(control_id)
            elif "nist" in lower:
                buckets["NIST AI RMF"].add(control_id)

    rows: list[dict[str, Any]] = []
    for framework in sorted(buckets.keys()):
        rows.append({"framework": framework, "controls": sorted(buckets[framework])})
    return rows


def _extract_reason(
    *,
    evidence: EvidenceNode,
    evidence_payload: dict[str, Any],
    enforcement_event: EnforcementEvent | None,
) -> str:
    reason = (
        _safe_text(evidence_payload.get("reason"))
        or _safe_text(evidence_payload.get("reason_code"))
        or _safe_text(evidence_payload.get("violation_reason"))
    )
    if reason:
        return reason.replace("_", " ")

    for key in ("threat_types", "reason_codes", "input_signal_types"):
        values = evidence_payload.get(key)
        if isinstance(values, list):
            merged = " ".join(_safe_text(item).lower() for item in values)
            if "sensitive_data" in merged or "pii" in merged:
                return "PII detected"

    if enforcement_event is not None:
        for row in list(enforcement_event.guardian_results or []):
            if not isinstance(row, dict):
                continue
            decision = _safe_text(row.get("decision")).lower()
            if decision in {"block", "redact", "hold_for_approval", "require_approval"}:
                row_reason = _safe_text(row.get("reason") or row.get("reason_code"))
                if row_reason:
                    return row_reason.replace("_", " ")
                guardian_id = _safe_text(row.get("guardian_id")).lower()
                if "sensitive_data" in guardian_id:
                    return "PII detected"

    combined = f"{_safe_text(evidence.signal_type).lower()} {_safe_text(evidence.label).lower()}"
    if "sensitive_data" in combined or "pii" in combined:
        return "PII detected"
    if "prompt_injection" in combined:
        return "Prompt injection pattern detected"
    return "Policy violation detected"


def explain_evidence_node(db: Session, *, tenant_id: str, evidence_id: str) -> dict[str, Any] | None:
    evidence = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == evidence_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    if evidence is None:
        return None

    evidence_payload = dict(evidence.payload or {}) if isinstance(evidence.payload, dict) else {}
    enforcement_rows = db.scalars(
        select(EnforcementEvent)
        .where(EnforcementEvent.tenant_id == tenant_id)
        .order_by(desc(EnforcementEvent.timestamp))
        .limit(1500)
    ).all()
    enforcement_event = next(
        (row for row in enforcement_rows if evidence_id in [str(item) for item in (row.evidence_nodes_created or [])]),
        None,
    )

    runtime_rows = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == tenant_id)
        .order_by(desc(RuntimeEvent.created_at))
        .limit(1500)
    ).all()
    runtime_event = next(
        (row for row in runtime_rows if evidence_id in [str(item) for item in (row.evidence_node_ids or [])]),
        None,
    )

    policy_version_id = (
        _safe_text(evidence_payload.get("policy_version_id"))
        or _safe_text((evidence_payload.get("trace") or {}).get("policy_version_id"))
        or _safe_text(getattr(enforcement_event, "policy_version_id", None))
        or _safe_text(getattr(runtime_event, "policy_version_id", None))
        or None
    )

    policy_version: PolicyVersion | None = None
    policy_pack_name: str | None = None
    if policy_version_id:
        policy_version = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.id == policy_version_id,
                PolicyVersion.tenant_id == tenant_id,
            )
        )
        if policy_version is not None:
            policy_pack_name = db.scalar(select(PolicyPack.name).where(PolicyPack.id == policy_version.pack_id))

    confidence_score = (
        _safe_float(evidence_payload.get("confidence"))
        or _safe_float(evidence_payload.get("confidence_score"))
        or _safe_float(evidence_payload.get("sensitive_confidence_score"))
        or _safe_float(evidence_payload.get("risk_score"))
        or _safe_float(getattr(runtime_event, "risk_score", None))
        or 0.0
    )

    final_decision = (
        _safe_text(evidence_payload.get("final_decision"))
        or _safe_text((evidence_payload.get("trace") or {}).get("final_decision"))
        or _safe_text(getattr(enforcement_event, "final_decision", None))
        or _safe_text((getattr(runtime_event, "metadata_json", {}) or {}).get("decision"))
        or "unknown"
    ).lower()

    reason = _extract_reason(
        evidence=evidence,
        evidence_payload=evidence_payload,
        enforcement_event=enforcement_event,
    )
    framework_mapping = _framework_rows_from_policy(
        db,
        tenant_id=tenant_id,
        policy_version=policy_version,
        evidence_payload=evidence_payload,
    )

    return {
        "evidence_id": evidence.id,
        "decision": final_decision,
        "reason": reason,
        "violated_policy": {
            "policy_version_id": policy_version.id if policy_version is not None else policy_version_id,
            "policy_version": policy_version.version if policy_version is not None else None,
            "policy_pack_id": policy_version.pack_id if policy_version is not None else None,
            "policy_pack_name": policy_pack_name,
        },
        "confidence_score": float(confidence_score),
        "framework_mapping": framework_mapping,
        "signal_type": evidence.signal_type,
        "label": evidence.label,
        "correlation_id": evidence.correlation_id,
        "created_at": evidence.created_at,
        "trace": {
            "enforcement_event_id": enforcement_event.id if enforcement_event is not None else None,
            "runtime_event_id": runtime_event.event_id if runtime_event is not None else None,
        },
    }
