from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_intelligence import DiscoveryShadowClassification
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes


MANAGEMENT_CLASSES = frozenset(
    {"enterprise_managed", "enterprise_approved", "personal", "unmanaged", "unknown"}
)
SHADOW_TYPES = frozenset(
    {
        "unapproved_ai_app",
        "personal_ai_on_managed_device",
        "direct_model_api",
        "unmanaged_agent",
        "unknown_ai_workload",
        "unapproved_model",
        "unmanaged_mcp",
        "unapproved_saas_ai",
        "unregistered_rag",
        "unknown_vector_store",
    }
)


@dataclass(frozen=True, slots=True)
class ManagementClassification:
    classification: str
    confidence: float
    evidence_sources: tuple[str, ...]
    explanation: str


@dataclass(frozen=True, slots=True)
class ShadowClassificationResult:
    shadow_type: str | None
    severity: str
    confidence: float
    verification_state: str
    required_action: str
    explanation: str


def classify_management_context(
    *, evidence: Mapping[str, Any]
) -> ManagementClassification:
    raw_sources = evidence.get("independent_sources", ())
    if type(raw_sources) is not tuple or any(
        type(item) is not str or not item or len(item) > 64 for item in raw_sources
    ):
        raise ValueError("management evidence sources are invalid")
    sources = tuple(sorted(set(raw_sources)))
    corroborated = len(sources) >= 2
    if (
        evidence.get("enterprise_sso") is True
        and evidence.get("provider_managed_tenant") is True
        and corroborated
    ):
        return ManagementClassification(
            "enterprise_managed", 0.95, sources,
            "Enterprise SSO and provider-tenant evidence agree across independent sources",
        )
    if (
        evidence.get("governance_approval") is True
        and evidence.get("enterprise_identity") is True
        and corroborated
    ):
        return ManagementClassification(
            "enterprise_approved", 0.9, sources,
            "Governance approval and enterprise identity are corroborated",
        )
    if (
        evidence.get("provider_account_type") == "personal"
        and evidence.get("managed_device") is True
        and corroborated
    ):
        return ManagementClassification(
            "personal", 0.9, sources,
            "Personal provider context is corroborated on a managed device",
        )
    if (
        evidence.get("governance_status") == "unapproved"
        and evidence.get("observed_usage") is True
        and corroborated
    ):
        return ManagementClassification(
            "unmanaged", 0.85, sources,
            "Observed usage and unapproved governance state are corroborated",
        )
    return ManagementClassification(
        "unknown",
        0.0 if not sources else min(0.49, len(sources) * 0.2),
        sources,
        "Evidence is insufficient to classify enterprise, personal, or unmanaged context",
    )


def classify_shadow_ai(
    *,
    asset_type: str,
    approved_status: str,
    management_class: str,
    usage_state: str,
    observed_signals: tuple[str, ...],
    owner_state: str,
    capabilities: tuple[str, ...],
) -> ShadowClassificationResult:
    if management_class not in MANAGEMENT_CLASSES:
        raise ValueError("management classification is invalid")
    if type(observed_signals) is not tuple or type(capabilities) is not tuple:
        raise ValueError("shadow evidence must be exact tuples")
    signals = frozenset(observed_signals)
    capabilities_set = frozenset(capabilities)
    active = usage_state in {"occasional", "active", "high_usage"}
    unapproved = approved_status in {"unapproved", "expired_approval"}

    if not active:
        return ShadowClassificationResult(
            None,
            "none",
            0.0,
            "unknown" if usage_state == "unknown" else "partially_verified",
            "Collect usage evidence before classification.",
            "Configuration, installation, license, static-domain, or dependency evidence alone does not prove Shadow AI",
        )
    if approved_status in {"approved", "conditionally_approved", "exception"}:
        return ShadowClassificationResult(
            None,
            "none",
            0.9,
            "verified",
            "No Shadow AI action required.",
            "Active use is tied to an approved governance state",
        )

    shadow_type: str | None = None
    confidence = 0.0
    if management_class == "personal" and "managed_device" in signals:
        shadow_type, confidence = "personal_ai_on_managed_device", 0.9
    elif active and "direct_model_api" in signals and len(signals) >= 2:
        shadow_type, confidence = "direct_model_api", 0.9
    elif asset_type in {"agent", "agent_framework"} and unapproved:
        shadow_type, confidence = "unmanaged_agent", 0.86
    elif asset_type == "unknown_ai_candidate" and len(signals) >= 3:
        shadow_type, confidence = "unknown_ai_workload", 0.78
    elif asset_type in {"model", "model_endpoint"} and unapproved:
        shadow_type, confidence = "unapproved_model", 0.84
    elif asset_type in {"mcp_client", "mcp_server", "mcp_tool"} and unapproved:
        shadow_type, confidence = "unmanaged_mcp", 0.86
    elif asset_type in {"ai_saas", "ai_feature"} and unapproved:
        shadow_type, confidence = "unapproved_saas_ai", 0.84
    elif asset_type in {"knowledge_base", "prompt_store", "memory_store"} and owner_state == "unknown":
        shadow_type, confidence = "unregistered_rag", 0.76
    elif asset_type == "vector_database" and owner_state == "unknown":
        shadow_type, confidence = "unknown_vector_store", 0.72
    elif unapproved and asset_type in {"ai_application", "endpoint_application", "browser_extension"}:
        shadow_type, confidence = "unapproved_ai_app", 0.82

    if shadow_type is None:
        return ShadowClassificationResult(
            None,
            "none",
            0.0,
            "unknown",
            "Create a bounded verification task.",
            "The available evidence does not meet a supported Shadow AI rule",
        )

    consequential = bool(
        capabilities_set
        & {"customer_data_access", "secret_access", "code_execution", "cloud_admin"}
    )
    if shadow_type == "unknown_ai_workload":
        severity = "medium" if consequential else "low"
    elif consequential:
        severity = "high"
    elif shadow_type in {"direct_model_api", "unmanaged_agent", "unmanaged_mcp"}:
        severity = "medium"
    else:
        severity = "medium"
    return ShadowClassificationResult(
        shadow_type,
        severity,
        confidence,
        "verified" if confidence >= 0.85 else "partially_verified",
        "Run evidence-backed verification and route the asset to governance review.",
        "Active usage and corroborated governance or management evidence match a documented Shadow AI rule",
    )


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def persist_shadow_classification(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    management_class: str,
    shadow_type: str,
    severity: str,
    confidence: float,
    verification_state: str,
    evidence_node_ids: tuple[str, ...],
    first_observed_at: datetime,
    last_observed_at: datetime,
    methodology_id: str,
    limitations: tuple[str, ...],
    idempotency_key: str,
) -> DiscoveryShadowClassification:
    if management_class not in MANAGEMENT_CLASSES or shadow_type not in SHADOW_TYPES:
        raise ValueError("shadow classification type is invalid")
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError("shadow severity is invalid")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise ValueError("shadow confidence is invalid")
    if verification_state not in {
        "verified", "partially_verified", "inferred", "contradicted", "stale", "unknown"
    }:
        raise ValueError("shadow verification is invalid")
    if not evidence_node_ids or len(evidence_node_ids) > 64 or len(set(evidence_node_ids)) != len(evidence_node_ids):
        raise ValueError("shadow evidence references are invalid")
    if not methodology_id or len(methodology_id) > 128:
        raise ValueError("shadow methodology is invalid")
    if not idempotency_key or len(idempotency_key) > 128:
        raise ValueError("shadow idempotency key is invalid")
    if len(limitations) > 32 or any(not item or len(item) > 255 for item in limitations):
        raise ValueError("shadow limitations are invalid")
    first = _utc(first_observed_at, field_name="first_observed_at")
    last = _utc(last_observed_at, field_name="last_observed_at")
    if first > last:
        raise ValueError("shadow timestamps are out of order")

    asset = db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )
    evidence_count = len(
        db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id.in_(evidence_node_ids),
            )
        ).all()
    )
    if asset is None or evidence_count != len(evidence_node_ids):
        raise ValueError("shadow classification authority is unavailable")
    material = {
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "management_class": management_class,
        "shadow_type": shadow_type,
        "severity": severity,
        "confidence": confidence,
        "verification_state": verification_state,
        "evidence_node_ids": evidence_node_ids,
        "first_observed_at": first.isoformat(),
        "last_observed_at": last.isoformat(),
        "methodology_id": methodology_id,
        "limitations": limitations,
    }
    digest = hashlib.sha256(
        b"hawk:discovery:shadow-classification:v1" + canonical_json_bytes(material)
    ).hexdigest()
    existing = db.scalar(
        select(DiscoveryShadowClassification).where(
            DiscoveryShadowClassification.tenant_id == tenant_id,
            DiscoveryShadowClassification.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != digest:
            raise ValueError("shadow classification idempotency conflict")
        return existing
    row = DiscoveryShadowClassification(
        classification_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_id=asset_id,
        management_class=management_class,
        shadow_type=shadow_type,
        severity=severity,
        confidence=confidence,
        verification_state=verification_state,
        primary_evidence_node_id=evidence_node_ids[0],
        evidence_node_ids_json=list(evidence_node_ids),
        first_observed_at=first,
        last_observed_at=last,
        methodology_id=methodology_id,
        limitations_json=list(limitations),
        idempotency_key=idempotency_key,
        input_digest=digest,
    )
    db.add(row)
    asset.shadow_ai_status = (
        "confirmed_shadow"
        if verification_state == "verified" and confidence >= 0.85
        else "suspected_shadow"
    )
    db.flush()
    return row


__all__ = [
    "MANAGEMENT_CLASSES",
    "SHADOW_TYPES",
    "ManagementClassification",
    "ShadowClassificationResult",
    "classify_management_context",
    "classify_shadow_ai",
    "persist_shadow_classification",
]
