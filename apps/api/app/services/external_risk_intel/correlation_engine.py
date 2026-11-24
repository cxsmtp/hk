from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentIdentity
from app.db.models.ai_system import AISystem
from app.db.models.monitoring import Connector


def _text_blob(*parts: str) -> str:
    return " ".join(str(part or "").strip().lower() for part in parts if str(part or "").strip())


def _contains_any(text: str, terms: list[str]) -> bool:
    return any(term in text for term in terms)


def _control_ids_for_record(*, asset_type: str, blob: str) -> list[str]:
    controls: set[str] = {"POLICY_ENFORCEMENT_CONTROL"}

    if _contains_any(blob, ["cve", "model", "provider", "endpoint", "llm", "gpt", "claude", "gemini"]):
        controls.add("MODEL_ACCESS_CONTROL")
        controls.add("MODEL_OUTPUT_VALIDATION")

    if _contains_any(blob, ["tool", "plugin", "connector", "agent", "server", "oauth"]):
        controls.add("TOOL_CALL_VALIDATION")
        controls.add("AGENT_ACTION_AUTHORIZATION")

    if _contains_any(blob, ["auth", "token", "credential", "identity", "scope", "secret"]):
        controls.add("AI_IDENTITY_BINDING")
        controls.add("TOKEN_SCOPE_ENFORCEMENT")
        controls.add("PRIVILEGE_DRIFT_DETECTION")

    if _contains_any(blob, ["rag", "ingestion", "dependency", "package", "supply chain", "poison"]):
        controls.add("RAG_POISONING_DETECTION")

    if _contains_any(blob, ["data leak", "pii", "exfil", "sensitive"]):
        controls.add("SENSITIVE_DATA_DETECTION")
        controls.add("PII_EXFILTRATION_PREVENTION")

    if asset_type == "connector":
        controls.add("TOOL_CALL_VALIDATION")
    if asset_type in {"agent_runtime", "agent"}:
        controls.add("AGENT_ACTION_AUTHORIZATION")
    if asset_type in {"model_endpoint", "ai_system", "provider"}:
        controls.add("MODEL_ACCESS_CONTROL")

    return sorted(controls)


def _component_tokens(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for component in record.get("affected_components") or []:
        text = str(component or "").strip().lower()
        if text:
            values.append(text)
    for ref in record.get("references") or []:
        text = str(ref or "").strip().lower()
        if text:
            values.append(text)
    title = str(record.get("title") or "").strip().lower()
    description = str(record.get("description") or "").strip().lower()
    if title:
        values.append(title)
    if description:
        values.append(description)
    return values


def correlate_risk_record(
    db: Session,
    *,
    tenant_id: str,
    record: dict[str, Any],
) -> list[dict[str, Any]]:
    tokens = _component_tokens(record)
    blob = " ".join(tokens)

    ai_systems = db.scalars(select(AISystem).where(AISystem.tenant_id == tenant_id)).all()
    connectors = db.scalars(select(Connector).where(Connector.tenant_id == tenant_id)).all()
    agents = db.scalars(select(AgentIdentity).where(AgentIdentity.tenant_id == tenant_id)).all()

    mappings: list[dict[str, Any]] = []

    for row in ai_systems:
        metadata = dict(row.metadata_json or {})
        labels = _text_blob(
            row.id,
            row.name,
            metadata.get("provider"),
            metadata.get("model"),
            metadata.get("endpoint"),
            metadata.get("runtime"),
        )
        if labels and any(token in labels or labels in token for token in tokens):
            confidence = 0.92
        elif _contains_any(blob, ["openai", "anthropic", "gemini", "claude", "gpt", row.name.lower()]):
            confidence = 0.58
        else:
            continue

        mappings.append(
            {
                "asset_type": "ai_system",
                "asset_id": row.id,
                "environment": str(metadata.get("environment") or "prod" if row.status == "active" else "unknown"),
                "confidence": confidence,
                "mapping_reason": "matched_ai_system_metadata_or_provider",
                "control_ids": _control_ids_for_record(asset_type="ai_system", blob=blob),
            }
        )

    for row in connectors:
        labels = _text_blob(row.id, row.name, row.provider_key, row.connector_type)
        if labels and any(token in labels or labels in token for token in tokens):
            confidence = 0.86
        elif _contains_any(blob, [row.provider_key.lower(), row.connector_type.lower()]):
            confidence = 0.54
        else:
            continue

        mappings.append(
            {
                "asset_type": "connector",
                "asset_id": row.id,
                "environment": str((row.metadata_json or {}).get("environment") or "prod"),
                "confidence": confidence,
                "mapping_reason": "matched_connector_identity",
                "control_ids": _control_ids_for_record(asset_type="connector", blob=blob),
            }
        )

    for row in agents:
        labels = _text_blob(row.id, row.name, *[str(item) for item in (row.tool_registry or [])])
        if labels and any(token in labels or labels in token for token in tokens):
            confidence = 0.82
        elif _contains_any(blob, ["agent", row.name.lower()]):
            confidence = 0.48
        else:
            continue

        mappings.append(
            {
                "asset_type": "agent_runtime",
                "asset_id": row.id,
                "environment": "prod" if str(row.status or "").lower() == "active" else "unknown",
                "confidence": confidence,
                "mapping_reason": "matched_agent_identity_or_tool_registry",
                "control_ids": _control_ids_for_record(asset_type="agent_runtime", blob=blob),
            }
        )

    # Fallback global mapping if no tenant-local asset match was found.
    if not mappings:
        mappings.append(
            {
                "asset_type": "tenant_surface",
                "asset_id": "global",
                "environment": "unknown",
                "confidence": 0.25,
                "mapping_reason": "no_specific_asset_match",
                "control_ids": _control_ids_for_record(asset_type="tenant_surface", blob=blob),
            }
        )

    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in mappings:
        key = (str(row.get("asset_type")), str(row.get("asset_id")), str(row.get("environment")))
        current = dedup.get(key)
        if current is None or float(row.get("confidence") or 0.0) > float(current.get("confidence") or 0.0):
            dedup[key] = row

    return list(dedup.values())
