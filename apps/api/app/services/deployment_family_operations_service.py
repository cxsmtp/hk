"""Bounded read-only deployment-family operations projections."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
import math
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.control_coverage import METHODOLOGY_VERSION as V1_METHODOLOGY
from app.core.deployment_family_coverage import (
    ContainmentEvidence,
    evaluate_containment,
    sanitize_evidence_refs,
)
from app.db.models.activity_audit import AIAction
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    DeploymentSurface,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.deployment_family_coverage_service import (
    _latest_snapshot,
    read_deployment_family_coverage,
)
from app.services.deployment_family_read_service import FAMILY_ORDER, HEALTH_ORDER


OPERATIONS_METHODOLOGY: Final = "deployment-family-coverage/1.0"
MAX_HEALTH_SURFACES = 10_000
MAX_HEALTH_ACTIONS = 20_000
MAX_BLIND_PATHS = 10_000
MAX_BLIND_FINDINGS = 10_000
MAX_BLIND_ASSERTIONS = 70_000
MAX_BLIND_EVIDENCE_NODES = 20_000
MAX_BLIND_EVENTS = 20_000
_LINK_CONTROL_MODES: Final = frozenset(
    {
        "inline_prevented",
        "inline_allowed",
        "warned",
        "review_required",
        "shadow_would_block",
        "detected_only",
        "telemetry_only",
        "external_required",
        "external_action_triggered",
        "incomplete",
    }
)
_LINK_AUTHORIZATION_PATHS: Final = frozenset(
    {
        "inline_pre_execution",
        "telemetry_observation",
        "external_control",
        "post_execution",
        "unknown",
    }
)
_SAFE_TOKEN_MAX: Final = {
    "collector_id": 128,
    "technical_surface_type": 64,
}
_HEALTH_STRING_FIELDS: Final = {
    "gateway_version": 64,
    "active_policy_id": 64,
    "active_policy_version": 64,
    "cache_state": 32,
    "export_state": 32,
    "bypass_state": 32,
    "upgrade_state": 32,
}
_HEALTH_NUMBER_FIELDS: Final = {
    "policy_age_seconds": (int, 31_536_000),
    "decision_latency_ms": (float, 60_000),
    "evidence_lag_seconds": (float, 31_536_000),
    "event_lag_seconds": (float, 31_536_000),
    "fail_open_count": (int, 1_000_000_000),
    "fail_safe_count": (int, 1_000_000_000),
}
_OPERATIONAL_FIELDS: Final = (
    "collector_version",
    "gateway_version",
    "active_policy_id",
    "active_policy_version",
    "policy_age_seconds",
    "cache_state",
    "decision_latency_ms",
    "evidence_lag_seconds",
    "event_lag_seconds",
    "export_state",
    "degraded_mode",
    "bypass_state",
    "upgrade_state",
    "fail_open_count",
    "fail_safe_count",
)
_SECRET_MARKERS: Final = (
    "bearer",
    "secret",
    "password",
    "credential",
    "api_key",
    "apikey",
    "token",
    "sk-",
    "ghp_",
    "xox",
    "akia",
    "asia",
    "aiza",
)
_DEPLOYMENT_TOKEN_CHARACTERS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_.:-"
)
BLIND_SPOT_RULES: Final = {
    "UNPROTECTED_LLM_ROUTE": {
        "dimension": "authorization",
        "states": ("not_covered",),
        "reasons": ("monitor_only_surface",),
        "evidence_signal_types": ("unprotected_path.llm",),
        "reachable": True,
        "observed_fact": "An LLM route was observed without verified inline authorization.",
        "recommended_deployment_action": (
            "If this route is in scope, route eligible LLM actions through "
            "a verified pre-execution authorization surface."
        ),
    },
    "UNPROTECTED_MCP_ROUTE": {
        "dimension": "authorization",
        "states": ("not_covered",),
        "reasons": ("monitor_only_surface",),
        "evidence_signal_types": ("unprotected_path.mcp",),
        "reachable": True,
        "observed_fact": "An MCP route was observed without verified inline authorization.",
        "recommended_deployment_action": (
            "If this route is in scope, route eligible MCP actions through "
            "a verified pre-execution authorization surface."
        ),
    },
    "DEPLOYMENT_SURFACE_OFFLINE": {
        "dimension": "deployment",
        "states": ("not_covered",),
        "reasons": ("surface_offline",),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "A deployment surface was observed offline.",
        "recommended_deployment_action": (
            "If this surface remains in scope, restore its verified operational connection."
        ),
    },
    "DEPLOYMENT_POLICY_STALE": {
        "dimension": "deployment",
        "states": (),
        "reasons": (),
        "evidence_signal_types": (),
        "reachable": False,
        "observed_fact": "A deployment surface reported stale policy state.",
        "recommended_deployment_action": (
            "If this surface remains in scope, verify and refresh its assigned policy state."
        ),
    },
    "DEPLOYMENT_IDENTITY_UNRESOLVED": {
        "dimension": "identity",
        "states": ("not_covered",),
        "reasons": ("missing_identity_binding",),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "A deployment path has no verified resolved identity.",
        "recommended_deployment_action": (
            "If this path is in scope, connect it to a verified tenant identity source."
        ),
    },
    "EVIDENCE_SOURCE_MISSING": {
        "dimension": "evidence",
        "states": ("not_covered",),
        "reasons": ("missing_execution_proof",),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "A deployment path is missing a required evidence source.",
        "recommended_deployment_action": (
            "If this path is in scope, connect and verify the required evidence source."
        ),
    },
    "UNMANAGED_AI_ACCOUNT": {
        "dimension": "identity",
        "states": ("not_covered",),
        "reasons": ("missing_identity_binding",),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "An AI account was observed without verified management binding.",
        "recommended_deployment_action": (
            "If this account is in scope, bind it to verified tenant identity governance."
        ),
    },
    "UNKNOWN_AI_RUNTIME": {
        "dimension": "runtime",
        "states": ("not_covered", "unknown"),
        "reasons": ("runtime_unmanaged", "insufficient_evidence"),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "An AI runtime was observed without verified runtime identity.",
        "recommended_deployment_action": (
            "If this runtime is in scope, register and verify its deployment identity."
        ),
    },
    "UNKNOWN_MCP_SERVER": {
        "dimension": "runtime",
        "states": ("not_covered", "unknown"),
        "reasons": ("runtime_unmanaged", "insufficient_evidence"),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "An MCP server was observed without verified server identity.",
        "recommended_deployment_action": (
            "If this server is in scope, register and verify its deployment identity."
        ),
    },
    "GATEWAY_BYPASS_SUSPECTED": {
        "dimension": "bypass",
        "states": ("covered", "not_covered"),
        "reasons": ("bypass_observed",),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "Evidence indicates a route may have bypassed the verified gateway path.",
        "recommended_deployment_action": (
            "If this route is in scope, investigate and close the verified gateway path gap."
        ),
    },
    "DISCOVERY_COVERAGE_GAP": {
        "dimension": "discovery",
        "states": ("not_covered", "unknown"),
        "reasons": ("confirmed_unmanaged_path", "insufficient_evidence"),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "A deployment path has incomplete verified discovery coverage.",
        "recommended_deployment_action": (
            "If this path is in scope, add and verify an eligible discovery source."
        ),
    },
    "AUTHORIZATION_COVERAGE_GAP": {
        "dimension": "authorization",
        "states": ("not_covered", "unknown"),
        "reasons": ("monitor_only_surface", "insufficient_evidence"),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "A deployment path has incomplete verified authorization coverage.",
        "recommended_deployment_action": (
            "If this path is in scope, add a verified pre-execution authorization path."
        ),
    },
    "CONTAINMENT_COVERAGE_GAP": {
        "dimension": "containment",
        "states": ("not_covered",),
        "reasons": ("monitor_only_surface", "surface_offline"),
        "evidence_signal_types": (),
        "reachable": True,
        "observed_fact": "A deployment path has incomplete verified containment capability.",
        "recommended_deployment_action": (
            "If this path is in scope, connect and verify an eligible containment path."
        ),
    },
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_token(value: object, *, maximum: int) -> str | None:
    if type(value) is not str or not value or len(value) > maximum:
        return None
    if value != value.strip() or any(character.isspace() for character in value):
        return None
    if any(character in value for character in ("?", "#", "&", "/", "\\")):
        return None
    return value


def _unknown_linkage(
    *,
    technical_surface_type: str = "unknown",
    collector_id: str | None = None,
    authorization_path: str = "unknown",
    control_mode: str = "incomplete",
) -> dict[str, object]:
    return {
        "verified": False,
        "deployment_instance_id": None,
        "technical_surface_type": technical_surface_type,
        "deployment_family": "unknown",
        "collector_id": collector_id,
        "authorization_path": authorization_path,
        "control_mode": control_mode,
        "evidence_capability_at_decision_time": "unknown",
    }


def resolve_trusted_deployment_linkage(
    db: Session,
    *,
    tenant_id: str,
    technical_surface_type: str,
    source_kind: str,
    source_id: str,
    collector_id: str,
    authorization_path: str,
    control_mode: str,
) -> dict[str, object]:
    """Resolve a server-owned deployment linkage by exact tenant/source identity."""

    safe_surface = _safe_token(
        technical_surface_type,
        maximum=_SAFE_TOKEN_MAX["technical_surface_type"],
    )
    safe_collector = _safe_token(
        collector_id,
        maximum=_SAFE_TOKEN_MAX["collector_id"],
    )
    if (
        safe_surface is None
        or safe_collector is None
        or authorization_path not in _LINK_AUTHORIZATION_PATHS
        or control_mode not in _LINK_CONTROL_MODES
        or _safe_token(source_kind, maximum=32) is None
        or _safe_token(source_id, maximum=128) is None
    ):
        return _unknown_linkage()
    surface = db.scalar(
        select(DeploymentSurface).where(
            DeploymentSurface.tenant_id == tenant_id,
            DeploymentSurface.surface_type == safe_surface,
            DeploymentSurface.source_kind == source_kind,
            DeploymentSurface.source_id == source_id,
        )
    )
    if surface is None:
        return _unknown_linkage(
            technical_surface_type=safe_surface,
            collector_id=safe_collector,
            authorization_path=authorization_path,
            control_mode=control_mode,
        )
    return {
        "verified": True,
        "deployment_instance_id": surface.id,
        "technical_surface_type": surface.surface_type,
        "deployment_family": surface.deployment_family,
        "collector_id": safe_collector,
        "authorization_path": authorization_path,
        "control_mode": control_mode,
        "evidence_capability_at_decision_time": surface.evidence_capability,
    }


def _bounded_metadata_string(
    metadata: Mapping[str, object],
    key: str,
    maximum: int,
) -> str | None:
    value = metadata.get(key)
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(character.isspace() for character in value)
        or any(character not in _DEPLOYMENT_TOKEN_CHARACTERS for character in value)
        or any(marker in value.lower() for marker in _SECRET_MARKERS)
    ):
        return None
    return value


def _bounded_number(
    metadata: Mapping[str, object],
    key: str,
    target: type[int] | type[float],
    maximum: int,
) -> int | float | None:
    value = metadata.get(key)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
        or value > maximum
    ):
        return None
    if target is int:
        return int(value) if isinstance(value, int) else None
    return float(value)


def _safe_health_evidence_refs(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        ref
        for ref in sanitize_evidence_refs(value)
        if not any(marker in ref.lower() for marker in _SECRET_MARKERS)
        and not any(
            character in ref
            for character in ("/", "\\", "@", "=")
        )
    ]


def _health_projection(
    surface: DeploymentSurface,
    *,
    last_action_at: datetime | None,
) -> dict[str, object]:
    metadata = (
        surface.metadata_json
        if isinstance(surface.metadata_json, Mapping)
        else {}
    )
    item: dict[str, object] = {
        "instance_id": surface.id,
        "deployment_family": (
            surface.deployment_family
            if surface.deployment_family in FAMILY_ORDER
            else "unknown"
        ),
        "technical_surface_type": surface.surface_type,
        "health_status": (
            surface.health_status
            if surface.health_status in HEALTH_ORDER
            else "unknown"
        ),
        "health_reason": surface.health_reason,
        "last_heartbeat_at": _utc(surface.last_heartbeat_at),
        "last_action_at": _utc(last_action_at),
        "collector_version": surface.collector_version,
    }
    for key, maximum in _HEALTH_STRING_FIELDS.items():
        item[key] = _bounded_metadata_string(metadata, key, maximum)
    for key, (target, maximum) in _HEALTH_NUMBER_FIELDS.items():
        item[key] = _bounded_number(
            metadata,
            key,
            target,
            maximum,
        )
    item["degraded_mode"] = (
        metadata.get("degraded_mode")
        if isinstance(metadata.get("degraded_mode"), bool)
        else None
    )
    item["evidence_refs"] = _safe_health_evidence_refs(
        metadata.get("evidence_refs")
    )
    return item


def _trusted_action_times(
    db: Session,
    *,
    tenant_id: str,
    instance_ids: set[str],
) -> tuple[dict[str, datetime], bool]:
    latest: dict[str, datetime] = {}
    rows = db.execute(
        select(AIAction.timestamp, AIAction.metadata_json).where(
            AIAction.tenant_id == tenant_id
        ).limit(MAX_HEALTH_ACTIONS + 1)
    ).all()
    if len(rows) > MAX_HEALTH_ACTIONS:
        return {}, True
    for timestamp, raw_metadata in rows:
        metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
        if metadata.get("deployment_linkage_verified") is not True:
            continue
        ai_action = (
            metadata.get("ai_action")
            if isinstance(metadata.get("ai_action"), Mapping)
            else {}
        )
        deployment = (
            ai_action.get("deployment")
            if isinstance(ai_action.get("deployment"), Mapping)
            else {}
        )
        instance_id = deployment.get("deployment_instance_id")
        if (
            type(instance_id) is not str
            or instance_id not in instance_ids
            or not _valid_persisted_deployment_snapshot(deployment)
        ):
            continue
        observed = _utc(timestamp)
        if observed is not None and (
            instance_id not in latest or observed > latest[instance_id]
        ):
            latest[instance_id] = observed
    return latest, False


def _valid_persisted_deployment_snapshot(
    deployment: Mapping[str, object],
) -> bool:
    return bool(
        _safe_token(
            deployment.get("deployment_instance_id"),
            maximum=36,
        )
        and _safe_token(
            deployment.get("technical_surface_type"),
            maximum=64,
        )
        and _safe_token(
            deployment.get("collector_id"),
            maximum=128,
        )
        and deployment.get("deployment_family") in FAMILY_ORDER
        and deployment.get("authorization_path")
        in _LINK_AUTHORIZATION_PATHS
        and deployment.get("control_mode") in _LINK_CONTROL_MODES
        and deployment.get("evidence_capability_at_decision_time")
        in {"complete", "partial", "metadata_only", "none", "unknown"}
    )


def read_deployment_health(
    db: Session,
    *,
    tenant_id: str,
    page: int = 1,
    page_size: int = 50,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    if page < 1 or not 1 <= page_size <= 200:
        raise ValueError("invalid health pagination")
    total = int(
        db.scalar(
            select(func.count())
            .select_from(DeploymentSurface)
            .where(DeploymentSurface.tenant_id == tenant_id)
        )
        or 0
    )
    if total > MAX_HEALTH_SURFACES:
        return _empty_health(
            tenant_id=tenant_id,
            generated_at=generated_at,
            page=page,
            page_size=page_size,
            total=total,
        )
    all_surfaces = db.scalars(
        select(DeploymentSurface)
        .where(DeploymentSurface.tenant_id == tenant_id)
        .order_by(
            DeploymentSurface.last_seen_at.desc(),
            DeploymentSurface.id.asc(),
        )
        .limit(MAX_HEALTH_SURFACES)
    ).all()
    surfaces = all_surfaces[
        (page - 1) * page_size : page * page_size
    ]
    action_times, action_limit_exceeded = _trusted_action_times(
        db,
        tenant_id=tenant_id,
        instance_ids={surface.id for surface in all_surfaces},
    )
    if action_limit_exceeded:
        return _empty_health(
            tenant_id=tenant_id,
            generated_at=generated_at,
            page=page,
            page_size=page_size,
            total=total,
        )
    families = []
    for family in FAMILY_ORDER:
        rows = [
            surface
            for surface in all_surfaces
            if surface.deployment_family == family
        ]
        counts = Counter(
            surface.health_status
            if surface.health_status in HEALTH_ORDER
            else "unknown"
            for surface in rows
        )
        heartbeats = [
            normalized
            for surface in rows
            if (
                normalized := _utc(surface.last_heartbeat_at)
            )
            is not None
        ]
        family_actions = [
            action_times[surface.id]
            for surface in rows
            if surface.id in action_times
        ]
        projections = [
            _health_projection(
                surface,
                last_action_at=action_times.get(surface.id),
            )
            for surface in rows
        ]
        families.append(
            {
                "deployment_family": family,
                "count": len(rows),
                "health_counts": {
                    status: counts.get(status, 0)
                    for status in HEALTH_ORDER
                },
                "last_heartbeat_at": max(heartbeats) if heartbeats else None,
                "last_action_at": (
                    max(family_actions)
                    if family_actions
                    else None
                ),
                "operational_field_counts": {
                    field: {
                        "known": sum(
                            item.get(field) is not None
                            for item in projections
                        ),
                        "unknown": sum(
                            item.get(field) is None
                            for item in projections
                        ),
                    }
                    for field in _OPERATIONAL_FIELDS
                },
            }
        )
    return {
        "tenant_id": tenant_id,
        "generated_at": generated_at or datetime.now(timezone.utc),
        "items": [
            _health_projection(
                surface,
                last_action_at=action_times.get(surface.id),
            )
            for surface in surfaces
        ],
        "families": families,
        "total": total,
        "page": page,
        "page_size": page_size,
        "diagnostics": [],
    }


def _empty_health(
    *,
    tenant_id: str,
    generated_at: datetime | None,
    page: int,
    page_size: int,
    total: int,
) -> dict[str, object]:
    return {
        "tenant_id": tenant_id,
        "generated_at": generated_at or datetime.now(timezone.utc),
        "items": [],
        "families": [
            {
                "deployment_family": family,
                "count": 0,
                "health_counts": {
                    status: 0 for status in HEALTH_ORDER
                },
                "last_heartbeat_at": None,
                "last_action_at": None,
                "operational_field_counts": {
                    field: {"known": 0, "unknown": 0}
                    for field in _OPERATIONAL_FIELDS
                },
            }
            for family in FAMILY_ORDER
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "diagnostics": [
            "deployment_health_processing_limit_exceeded"
        ],
    }


def _empty_blind_spots(
    *,
    tenant_id: str,
    calculated_at: datetime,
    diagnostics: list[str],
    freshness_status: str = "unknown",
) -> dict[str, object]:
    return {
        "tenant_id": tenant_id,
        "methodology": OPERATIONS_METHODOLOGY,
        "calculated_at": calculated_at,
        "freshness_status": freshness_status,
        "items": [],
        "total": 0,
        "page": 1,
        "page_size": 50,
        "diagnostics": diagnostics,
    }


def _blind_processing_limit(
    *,
    tenant_id: str,
    calculated_at: datetime,
) -> dict[str, object]:
    return _empty_blind_spots(
        tenant_id=tenant_id,
        calculated_at=calculated_at,
        diagnostics=[
            "deployment_blind_spot_processing_limit_exceeded"
        ],
    )


def _assertions_are_current_and_consistent(
    assertions: list[ControlCoverageAssertion],
    *,
    current: datetime,
    snapshot_computed_at: datetime,
) -> bool:
    return bool(assertions) and all(
        assertion.reason_code not in {
            "stale_evidence",
            "conflicting_evidence",
        }
        and assertion.valid_until is not None
        and (_utc(assertion.valid_until) or current) > current
        and (_utc(assertion.evaluated_at) or current)
        <= snapshot_computed_at
        and (_utc(assertion.observed_at) or current)
        <= snapshot_computed_at
        for assertion in assertions
    )


def _nodes_are_current_and_consistent(
    nodes: list[EvidenceNode],
    *,
    rule: Mapping[str, object],
    snapshot_start: datetime,
    snapshot_computed_at: datetime,
) -> list[EvidenceNode]:
    expected_signals = set(rule["evidence_signal_types"])
    matching = [
        node
        for node in nodes
        if (not expected_signals or node.signal_type in expected_signals)
        and (_utc(node.created_at) or snapshot_start) >= snapshot_start
        and (_utc(node.created_at) or snapshot_computed_at)
        <= snapshot_computed_at
    ]
    if not matching:
        return []
    states = {
        payload.get("fact_state")
        for node in matching
        if isinstance((payload := node.payload), Mapping)
        and payload.get("fact_state") is not None
    }
    if (
        any(
            isinstance(node.payload, Mapping)
            and node.payload.get("conflicting") is True
            for node in matching
        )
        or len(states) > 1
        or any(state not in {"current"} for state in states)
    ):
        return []
    return matching


def _blind_fact_matches(
    finding_type: str,
    *,
    surface: DeploymentSurface,
    event: RuntimeEvent,
    path: ControlCoveragePath,
    assertions: list[ControlCoverageAssertion],
    matching_nodes: list[EvidenceNode],
) -> bool:
    metadata = (
        event.metadata_json
        if isinstance(event.metadata_json, Mapping)
        else {}
    )
    if not matching_nodes:
        return False
    if finding_type == "UNPROTECTED_LLM_ROUTE":
        return any(
            isinstance(node.payload, Mapping)
            and node.payload.get("route_kind") == "llm"
            for node in matching_nodes
        )
    if finding_type == "UNPROTECTED_MCP_ROUTE":
        return any(
            isinstance(node.payload, Mapping)
            and node.payload.get("route_kind") == "mcp"
            for node in matching_nodes
        )
    if finding_type == "UNKNOWN_MCP_SERVER":
        return bool(
            "mcp" in surface.surface_type.lower()
            and bool(metadata.get("mcp_server_id"))
        )
    if finding_type == "DEPLOYMENT_SURFACE_OFFLINE":
        return bool(
            surface.health_status == "offline"
            and surface.health_reason
            in {
                "verified_offline",
                "collector_offline",
                "heartbeat_offline",
                "surface_offline",
            }
        )
    if finding_type == "DEPLOYMENT_POLICY_STALE":
        return any(
            isinstance(node.payload, Mapping)
            and node.payload.get("policy_state") == "stale"
            for node in matching_nodes
        )
    if finding_type == "DEPLOYMENT_IDENTITY_UNRESOLVED":
        return bool(
            path.identity_type == "unknown"
            and path.identity_ref.startswith("unknown_identity:")
        )
    if finding_type == "EVIDENCE_SOURCE_MISSING":
        return True
    if finding_type == "UNMANAGED_AI_ACCOUNT":
        return metadata.get("confirmed_unmanaged") is True
    if finding_type == "UNKNOWN_AI_RUNTIME":
        return bool(
            path.runtime_ref.startswith("unknown_runtime:")
            and "mcp" not in surface.surface_type.lower()
        )
    if finding_type == "GATEWAY_BYPASS_SUSPECTED":
        return bool(
            metadata.get("gateway_bypass_detected") is True
            and metadata.get("gateway_routed") is False
            and metadata.get("enforcement_path")
            == "observed_unprotected_route"
            and metadata.get("control_mode") == "post_execution"
        )
    if finding_type in {
        "DISCOVERY_COVERAGE_GAP",
        "AUTHORIZATION_COVERAGE_GAP",
    }:
        return True
    if finding_type == "CONTAINMENT_COVERAGE_GAP":
        by_dimension = {
            assertion.dimension: assertion
            for assertion in assertions
        }
        authorization = by_dimension.get("authorization")
        deployment = by_dimension.get("deployment")
        refs = sanitize_evidence_refs(
            ref
            for assertion in assertions
            for ref in (
                assertion.evidence_refs
                if isinstance(assertion.evidence_refs, list)
                else []
            )
        )
        result = evaluate_containment(
            ContainmentEvidence(
                capability=surface.containment_capability,
                health_status=surface.health_status,
                authorization_monitor_only_proven=bool(
                    authorization is not None
                    and authorization.state == "not_covered"
                    and authorization.reason_code == "monitor_only_surface"
                ),
                deployment_offline_proven=bool(
                    deployment is not None
                    and deployment.state == "not_covered"
                    and deployment.reason_code == "surface_offline"
                ),
                evidence_refs=refs,
            )
        )
        return result.state == "not_covered"
    return False


def read_deployment_blind_spots(
    db: Session,
    *,
    tenant_id: str,
    calculated_at: datetime | None = None,
) -> dict[str, object]:
    current = calculated_at or datetime.now(timezone.utc)
    coverage = read_deployment_family_coverage(
        db,
        tenant_id=tenant_id,
        calculated_at=current,
        window_days=settings.control_coverage_default_window_days,
    )
    if coverage.freshness_status != "current" or coverage.diagnostics:
        return _empty_blind_spots(
            tenant_id=tenant_id,
            calculated_at=current,
            diagnostics=list(coverage.diagnostics),
            freshness_status=coverage.freshness_status,
        )
    snapshot, selection_diagnostic = _latest_snapshot(
        db,
        tenant_id=tenant_id,
        window_days=settings.control_coverage_default_window_days,
    )
    if snapshot is None:
        return _empty_blind_spots(
            tenant_id=tenant_id,
            calculated_at=current,
            diagnostics=[
                selection_diagnostic
                or "missing_current_control_coverage_snapshot"
            ],
        )

    paths = db.scalars(
        select(ControlCoveragePath)
        .where(
            ControlCoveragePath.tenant_id == tenant_id,
            ControlCoveragePath.last_seen_at >= snapshot.window_start,
            ControlCoveragePath.last_seen_at <= snapshot.window_end,
            ControlCoveragePath.deployment_surface_id.is_not(None),
        )
        .limit(MAX_BLIND_PATHS + 1)
    ).all()
    if len(paths) > MAX_BLIND_PATHS:
        return _blind_processing_limit(
            tenant_id=tenant_id,
            calculated_at=current,
        )
    paths_by_event: dict[str, list[ControlCoveragePath]] = {}
    for path in paths:
        refs = (
            path.source_refs
            if isinstance(path.source_refs, list)
            else []
        )
        for ref in refs:
            if type(ref) is str and ref.startswith("runtime_event:"):
                paths_by_event.setdefault(ref.removeprefix("runtime_event:"), []).append(path)

    findings = db.scalars(
        select(Finding)
        .where(
            Finding.tenant_id == tenant_id,
            Finding.status == "open",
            Finding.finding_type.in_(tuple(BLIND_SPOT_RULES)),
        )
        .order_by(Finding.last_seen_at.desc(), Finding.finding_id.asc())
        .limit(MAX_BLIND_FINDINGS + 1)
    ).all()
    if len(findings) > MAX_BLIND_FINDINGS:
        return _blind_processing_limit(
            tenant_id=tenant_id,
            calculated_at=current,
        )
    snapshot_start = _utc(snapshot.window_start)
    snapshot_end = _utc(snapshot.window_end)
    snapshot_computed_at = _utc(snapshot.computed_at)
    if (
        snapshot_start is None
        or snapshot_end is None
        or snapshot_computed_at is None
    ):
        return _empty_blind_spots(
            tenant_id=tenant_id,
            calculated_at=current,
            diagnostics=["control_coverage_snapshot_incoherent"],
        )

    event_ids = {
        value
        for finding in findings
        for value in (
            finding.related_event_ids
            if isinstance(finding.related_event_ids, list)
            else []
        )
        if type(value) is str
    }
    if len(event_ids) > MAX_BLIND_EVENTS:
        return _blind_processing_limit(
            tenant_id=tenant_id,
            calculated_at=current,
        )
    events = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.event_id.in_(event_ids),
        )
        .limit(MAX_BLIND_EVENTS + 1)
    ).all()
    if len(events) > MAX_BLIND_EVENTS:
        return _blind_processing_limit(
            tenant_id=tenant_id,
            calculated_at=current,
        )
    events_by_id = {event.event_id: event for event in events}

    surface_ids = {
        path.deployment_surface_id
        for path in paths
        if path.deployment_surface_id is not None
    }
    surfaces = db.scalars(
        select(DeploymentSurface)
        .where(
            DeploymentSurface.tenant_id == tenant_id,
            DeploymentSurface.id.in_(surface_ids),
        )
        .limit(MAX_BLIND_PATHS + 1)
    ).all()
    surfaces_by_id = {surface.id: surface for surface in surfaces}

    path_ids = {path.id for path in paths}
    assertions = db.scalars(
        select(ControlCoverageAssertion)
        .where(
            ControlCoverageAssertion.tenant_id == tenant_id,
            ControlCoverageAssertion.path_id.in_(path_ids),
            ControlCoverageAssertion.methodology_version
            == V1_METHODOLOGY,
        )
        .order_by(
            ControlCoverageAssertion.path_id,
            ControlCoverageAssertion.dimension,
        )
        .limit(MAX_BLIND_ASSERTIONS + 1)
    ).all()
    if len(assertions) > MAX_BLIND_ASSERTIONS:
        return _blind_processing_limit(
            tenant_id=tenant_id,
            calculated_at=current,
        )
    assertions_by_path: dict[str, list[ControlCoverageAssertion]] = {}
    for assertion in assertions:
        assertions_by_path.setdefault(
            assertion.path_id,
            [],
        ).append(assertion)

    evidence_node_ids = {
        value
        for finding in findings
        for value in (
            finding.evidence_node_ids
            if isinstance(finding.evidence_node_ids, list)
            else []
        )
        if type(value) is str
    }
    if len(evidence_node_ids) > MAX_BLIND_EVIDENCE_NODES:
        return _blind_processing_limit(
            tenant_id=tenant_id,
            calculated_at=current,
        )
    evidence_nodes = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id.in_(evidence_node_ids),
        )
        .limit(MAX_BLIND_EVIDENCE_NODES + 1)
    ).all()
    if len(evidence_nodes) > MAX_BLIND_EVIDENCE_NODES:
        return _blind_processing_limit(
            tenant_id=tenant_id,
            calculated_at=current,
        )
    evidence_by_id = {node.id: node for node in evidence_nodes}

    items: list[dict[str, object]] = []
    for finding in findings:
        finding_seen_at = _utc(finding.last_seen_at)
        if (
            finding_seen_at is None
            or finding_seen_at < snapshot_start
            or finding_seen_at > snapshot_end
        ):
            continue
        rule = BLIND_SPOT_RULES[finding.finding_type]
        if rule.get("reachable") is not True:
            continue
        related_events = (
            finding.related_event_ids
            if isinstance(finding.related_event_ids, list)
            else []
        )
        linked = [
            (event_id, path)
            for event_id in sorted(
                {
                    value
                    for value in related_events
                    if type(value) is str
                }
            )
            for path in paths_by_event.get(event_id, ())
        ]
        if len(linked) != 1:
            continue
        event_id, path = linked[0]
        surface = surfaces_by_id.get(path.deployment_surface_id)
        event = events_by_id.get(event_id)
        if surface is None or event is None:
            continue
        path_assertions = assertions_by_path.get(path.id, [])
        if rule["dimension"] == "containment":
            substantiating_assertions = [
                assertion
                for assertion in path_assertions
                if (
                    assertion.dimension == "authorization"
                    and assertion.state == "not_covered"
                    and assertion.reason_code == "monitor_only_surface"
                )
                or (
                    assertion.dimension == "deployment"
                    and assertion.state == "not_covered"
                    and assertion.reason_code == "surface_offline"
                )
            ]
        else:
            substantiating_assertions = [
                assertion
                for assertion in path_assertions
                if assertion.dimension == rule["dimension"]
                and assertion.state in rule["states"]
                and assertion.reason_code in rule["reasons"]
            ]
        if not _assertions_are_current_and_consistent(
            substantiating_assertions,
            current=current,
            snapshot_computed_at=snapshot_computed_at,
        ):
            continue
        assertion_refs = {
            ref
            for assertion in substantiating_assertions
            for ref in (
                assertion.evidence_refs
                if isinstance(assertion.evidence_refs, list)
                else []
            )
            if type(ref) is str
        }
        source_evidence_ids = {
            value
            for value in (
                event.evidence_node_ids
                if isinstance(event.evidence_node_ids, list)
                else []
            )
            if type(value) is str
        }
        finding_evidence_ids = {
            value
            for value in (
                finding.evidence_node_ids
                if isinstance(finding.evidence_node_ids, list)
                else []
            )
            if type(value) is str and value in evidence_by_id
        }
        linked_evidence_ids = {
            evidence_id
            for evidence_id in finding_evidence_ids
            if (
                f"evidence:{evidence_id}" in assertion_refs
                or evidence_id in source_evidence_ids
            )
        }
        if not linked_evidence_ids:
            continue
        matching_nodes = _nodes_are_current_and_consistent(
            [
                evidence_by_id[evidence_id]
                for evidence_id in linked_evidence_ids
            ],
            rule=rule,
            snapshot_start=snapshot_start,
            snapshot_computed_at=snapshot_computed_at,
        )
        if not _blind_fact_matches(
            finding.finding_type,
            surface=surface,
            event=event,
            path=path,
            assertions=path_assertions,
            matching_nodes=matching_nodes,
        ):
            continue
        metadata = (
            event.metadata_json
            if isinstance(event.metadata_json, Mapping)
            else {}
        )
        refs = sanitize_evidence_refs(
            [
                *(
                    f"evidence:{node.id}"
                    for node in matching_nodes
                ),
                f"finding:{finding.finding_id}",
                f"runtime_event:{event_id}",
            ]
        )
        if not refs:
            continue
        items.append(
            {
                "finding_id": finding.finding_id,
                "finding_type": finding.finding_type,
                "observed_fact": rule["observed_fact"],
                "observing_source": finding.source_surface,
                "reason": substantiating_assertions[0].reason_code,
                "confidence": "high",
                "freshness_status": "current",
                "deployment_family": surface.deployment_family,
                "technical_surface_type": surface.surface_type,
                "deployment_instance_id": surface.id,
                "path_id": path.id,
                "assertion_ids": [
                    assertion.id
                    for assertion in substantiating_assertions
                ],
                "control_mode": (
                    metadata.get("control_mode")
                    if metadata.get("control_mode") in _LINK_CONTROL_MODES
                    else "incomplete"
                ),
                "evidence_refs": list(refs),
                "recommended_deployment_action": rule[
                    "recommended_deployment_action"
                ],
                "conditional": True,
            }
        )
    return {
        "tenant_id": tenant_id,
        "methodology": OPERATIONS_METHODOLOGY,
        "calculated_at": current,
        "freshness_status": "current",
        "items": items[:50],
        "total": len(items),
        "page": 1,
        "page_size": 50,
        "diagnostics": [],
    }
