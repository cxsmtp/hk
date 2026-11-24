from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.runtime_intelligence import RuntimeEvent, RuntimePattern
from app.services.runtime_intelligence.schemas import CorrelatedFindingCandidate


SEVERITY_RANK = {"low": 0, "med": 1, "high": 2, "critical": 3}

PATTERN_TYPE_MAP: dict[str, str] = {
    "repeated_prompt_injection_attempts": "repeated_violations",
    "repeated_tool_denials": "repeated_violations",
    "unknown_ai_adoption_spike": "repeated_violations",
    "abnormal_agent_chains": "repeated_violations",
    "justification_trend_risk": "repeated_violations",
    "repeated_sensitive_data_attempts": "data_exfil_patterns",
    "multi_tool_data_exposure": "data_exfil_patterns",
    "asymmetry_risk_spike": "data_exfil_patterns",
    "unusual_tool_sequences": "unusual_tool_sequences",
}


def _normalize_severity(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "medium":
        normalized = "med"
    if normalized not in SEVERITY_RANK:
        return "low"
    return normalized


def _pick_stricter_severity(left: str | None, right: str | None) -> str:
    l = _normalize_severity(left)
    r = _normalize_severity(right)
    return l if SEVERITY_RANK[l] >= SEVERITY_RANK[r] else r


def _normalize_entities(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    dedup: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        entity_type = str(row.get("type") or "").strip().lower()
        entity_id = str(row.get("id") or "").strip()
        if not entity_type or not entity_id:
            continue
        dedup[(entity_type, entity_id)] = {"type": entity_type, "id": entity_id}
    return sorted(dedup.values(), key=lambda item: (item["type"], item["id"]))


def _entity_rows(event: RuntimeEvent, candidate: CorrelatedFindingCandidate) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if event.user_id:
        out.append({"type": "user", "id": str(event.user_id)})
    if event.agent_id:
        out.append({"type": "agent", "id": str(event.agent_id)})
    if event.ai_system_id:
        out.append({"type": "ai_system", "id": str(event.ai_system_id)})
    if event.app_id:
        out.append({"type": "app", "id": str(event.app_id)})
    if event.entity_type and event.entity_id:
        out.append({"type": str(event.entity_type), "id": str(event.entity_id)})
    if candidate.finding_type == "unusual_tool_sequences":
        metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}
        tool_name = str(metadata.get("tool_name") or "").strip()
        if tool_name:
            out.append({"type": "tool", "id": tool_name})
    return _normalize_entities(out)


def _pattern_type(candidate: CorrelatedFindingCandidate) -> str:
    return PATTERN_TYPE_MAP.get(candidate.finding_type, candidate.finding_type)


def upsert_runtime_pattern(
    db: Session,
    *,
    event: RuntimeEvent,
    candidate: CorrelatedFindingCandidate,
    severity: str,
) -> RuntimePattern:
    pattern_type = _pattern_type(candidate)
    row = db.scalar(
        select(RuntimePattern).where(
            RuntimePattern.tenant_id == event.tenant_id,
            RuntimePattern.type == pattern_type,
        )
    )
    entities_now = _entity_rows(event, candidate)
    frequency = max(1, int(candidate.repeated_count or 1))

    if row is None:
        row = RuntimePattern(
            tenant_id=event.tenant_id,
            type=pattern_type,
            frequency=frequency,
            severity=_normalize_severity(severity),
            affected_entities=entities_now,
        )
        db.add(row)
        db.flush()
        return row

    existing_entities_raw = list(row.affected_entities or []) if isinstance(row.affected_entities, list) else []
    existing_entities = [
        {"type": str(item.get("type") or ""), "id": str(item.get("id") or "")}
        for item in existing_entities_raw
        if isinstance(item, dict)
    ]
    row.frequency = max(int(row.frequency or 0), frequency)
    row.severity = _pick_stricter_severity(row.severity, severity)
    row.affected_entities = _normalize_entities([*existing_entities, *entities_now])
    db.flush()
    return row
