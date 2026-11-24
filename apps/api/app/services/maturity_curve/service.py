"""Deterministic maturity-stage derivation.

This module intentionally evaluates only evidence gates.  It does not make a
policy decision, does not alter an AI action, and does not replace Control
Coverage or Continuous Assurance.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction, AISession
from app.db.models.continuous_assurance import ControlAssertion
from app.db.models.control_coverage import ControlCoverageSnapshot, DeploymentSurface
from app.db.models.maturity_curve import (
    MATURITY_SCOPE_TYPES,
    MaturityAssessment,
    MaturityObservationWindow,
    MaturityObservedUsagePattern,
    MaturityPolicyEffectivenessSnapshot,
    MaturityPolicyRecommendation,
    MaturityPolicyRollout,
    MaturityPolicySimulation,
    MaturityScope,
    MaturityUsageBaseline,
)
from app.services.maturity_curve.entitlements import require_maturity_capability


MATURITY_STAGES = (
    "UNKNOWN",
    "CONNECTED",
    "MONITORING",
    "UNDERSTANDING",
    "POLICY_READY",
    "CONTROLLED",
    "ASSURED",
)
MAX_ACTIONS_PER_OBSERVATION_WINDOW = 10_000
OBSERVATION_WINDOW_DAYS = 30


@dataclass(frozen=True)
class MaturityEvidence:
    """Bounded, already-normalized evidence gates for one maturity scope."""

    connected: bool
    observation_count: int
    source_kinds: tuple[str, ...]
    asset_identity_known: bool
    usage_baseline_ready: bool
    recommendation_ready: bool
    simulation_passed: bool
    controlled: bool
    assurance_current: bool
    surface_health_current: bool = True
    blocking_gaps: tuple[str, ...] = ()


@dataclass(frozen=True)
class MaturityStageResult:
    stage: str
    missing_gates: tuple[str, ...]
    blocking_gaps: tuple[str, ...]


@dataclass(frozen=True)
class MaturityMaterialization:
    scope: MaturityScope
    observation_window: MaturityObservationWindow
    baseline: MaturityUsageBaseline
    assessment: MaturityAssessment
    patterns: tuple[MaturityObservedUsagePattern, ...]


def _distinct_sources(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({str(value).strip().lower() for value in values if str(value).strip()}))


def derive_maturity_stage(evidence: MaturityEvidence) -> MaturityStageResult:
    """Return the highest evidence-earned stage without averaging gaps away."""

    sources = _distinct_sources(evidence.source_kinds)
    observation_ready = evidence.observation_count > 0 and bool(sources)
    if not evidence.connected and not observation_ready:
        return MaturityStageResult(
            stage="UNKNOWN",
            missing_gates=("connected", "observation"),
            blocking_gaps=tuple(sorted(set(evidence.blocking_gaps))),
        )

    stage = "CONNECTED"
    missing: list[str] = []
    if observation_ready:
        stage = "MONITORING"
    else:
        missing.append("observation")

    understanding_ready = (
        observation_ready
        and evidence.asset_identity_known
        and evidence.usage_baseline_ready
    )
    if understanding_ready:
        stage = "UNDERSTANDING"
    elif stage == "MONITORING":
        if not evidence.asset_identity_known:
            missing.append("asset_identity")
        if not evidence.usage_baseline_ready:
            missing.append("usage_baseline")

    policy_ready = understanding_ready and evidence.recommendation_ready and evidence.simulation_passed
    if policy_ready:
        stage = "POLICY_READY"
    elif stage == "UNDERSTANDING":
        if not evidence.recommendation_ready:
            missing.append("recommendation")
        if not evidence.simulation_passed:
            missing.append("simulation")

    if policy_ready and evidence.controlled:
        stage = "CONTROLLED"
    elif policy_ready:
        missing.append("controlled_policy")

    if stage == "CONTROLLED" and evidence.assurance_current and evidence.surface_health_current and not evidence.blocking_gaps:
        stage = "ASSURED"
    elif stage == "CONTROLLED" and not evidence.assurance_current:
        missing.append("assurance")
    elif stage == "CONTROLLED" and not evidence.surface_health_current:
        missing.append("surface_health")

    # A current high-risk unknown prevents the strongest assurance assertion.
    if stage == "ASSURED" and evidence.blocking_gaps:
        stage = "CONTROLLED"

    return MaturityStageResult(
        stage=stage,
        missing_gates=tuple(sorted(set(missing))),
        blocking_gaps=tuple(sorted(set(evidence.blocking_gaps))),
    )


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_token(value: Any) -> str:
    return str(value or "").strip().lower()


def _bounded_refs(values: Iterable[str], *, maximum: int = 500) -> list[str]:
    return sorted({str(value) for value in values if str(value)})[:maximum]


def _scope_filter_values(scope: MaturityScope, key: str) -> set[str]:
    filters = scope.filters if isinstance(scope.filters, dict) else {}
    raw = filters.get(key, filters.get(f"{key}s", []))
    if raw is None:
        return set()
    if not isinstance(raw, list):
        raw = [raw]
    return {_normalize_token(value) for value in raw if _normalize_token(value)}


_SCOPE_TYPE_FILTERS = {
    "business_unit": "business_unit",
    "department": "actor_department",
    "group": "actor_group",
    "surface": "source_surface",
    "application": "application",
    "provider": "provider",
    "model": "model",
    "agent": "agent_id",
    "tool_mcp": "tool_name",
    "action_class": "action_class",
    "policy_family": "policy_family",
    "environment": "environment",
}


def _implicit_scope_value(scope: MaturityScope, field: str) -> set[str]:
    """Use a conventional ``type:value`` key only when no explicit filter exists."""

    expected = _SCOPE_TYPE_FILTERS.get(scope.scope_type)
    if expected != field or _scope_filter_values(scope, field):
        return set()
    prefix, separator, value = str(scope.scope_key or "").partition(":")
    if separator and _normalize_token(prefix) == _normalize_token(scope.scope_type):
        normalized = _normalize_token(value)
        if normalized and normalized not in {"all", "*"}:
            return {normalized}
    return set()


def _matches_scope(scope: MaturityScope, action: dict[str, Any]) -> bool:
    selector_fields = {
        "actor_user_id": "actor_user_id",
        "actor_group": "actor_group",
        "actor_department": "actor_department",
        "business_unit": "business_unit",
        "source_surface": "source_surface",
        "application": "application",
        "provider": "provider",
        "model": "model",
        "agent": "agent_id",
        "tool_mcp": "tool_name",
        "mcp_server": "mcp_server",
        "action_class": "action_type",
        "account_class": "account_class",
        "destination": "destination",
        "policy_family": "policy_family",
        "environment": "environment",
        "business_purpose": "business_purpose",
    }
    for filter_key, action_key in selector_fields.items():
        values = _scope_filter_values(scope, filter_key) or _implicit_scope_value(scope, action_key)
        if values and _normalize_token(action.get(action_key)) not in values:
            return False
    return True


def _chunked(values: list[str], size: int = 500) -> Iterable[list[str]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _load_sessions(db: Session, *, tenant_id: str, session_ids: list[str]) -> dict[str, AISession]:
    rows: dict[str, AISession] = {}
    for identifiers in _chunked(session_ids):
        for session in db.scalars(
            select(AISession).where(
                AISession.tenant_id == tenant_id,
                AISession.session_id.in_(identifiers),
            )
        ).all():
            rows[str(session.session_id)] = session
    return rows


def _safe_metadata_value(value: Any) -> Any:
    """Return bounded structured metadata or an explicit empty value.

    Maturity uses only already-normalized canonical-action metadata.  This
    prevents accidental retention of prompts, documents, tokens, or tool
    outputs in the baseline path.
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, str):
            return value.strip()[:255]
        return value
    if isinstance(value, (list, tuple, set)):
        return [_safe_metadata_value(item) for item in list(value)[:64] if _safe_metadata_value(item) not in (None, "")]
    return None


def _metadata_first(metadata: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = _safe_metadata_value(metadata.get(key))
        if value not in (None, "", []):
            return value
    return None


def _action_projection(action: AIAction, session: AISession | None) -> dict[str, Any]:
    metadata = action.metadata_json if isinstance(action.metadata_json, dict) else {}
    return {
        "action_id": str(action.action_id),
        "source_surface": _normalize_token(session.source_surface if session is not None else metadata.get("source_surface")),
        "actor_user_id": _normalize_token(action.user_id),
        "actor_group": _normalize_token(_metadata_first(metadata, "actor_group", "group", "user_group")),
        "actor_role": _normalize_token(_metadata_first(metadata, "actor_role", "role")),
        "actor_department": _normalize_token(_metadata_first(metadata, "actor_department", "department")),
        "business_unit": _normalize_token(_metadata_first(metadata, "business_unit", "business_unit_id")),
        "account_class": _normalize_token(_metadata_first(metadata, "account_class", "ai_account_class")),
        "account_workspace": _normalize_token(_metadata_first(metadata, "account_workspace", "workspace", "provider_workspace")),
        "account_assurance": _normalize_token(_metadata_first(metadata, "account_assurance")),
        "endpoint_id": _normalize_token(action.endpoint_id),
        "device_managed": _metadata_first(metadata, "device_managed", "managed_device"),
        "device_group": _normalize_token(_metadata_first(metadata, "device_group")),
        "device_os": _normalize_token(_metadata_first(metadata, "device_os", "os")),
        "endpoint_health": _normalize_token(_metadata_first(metadata, "endpoint_health", "device_health")),
        "tamper_state": _normalize_token(_metadata_first(metadata, "tamper_state")),
        "application": _normalize_token(action.ai_app or (session.ai_app if session is not None else "") or metadata.get("application")),
        "provider": _normalize_token(metadata.get("provider")),
        "provider_status": _normalize_token(_metadata_first(metadata, "provider_status")),
        "provider_workspace": _normalize_token(_metadata_first(metadata, "provider_workspace", "workspace")),
        "model": _normalize_token(action.ai_model or (session.ai_model if session is not None else "") or metadata.get("model")),
        "model_family": _normalize_token(_metadata_first(metadata, "model_family")),
        "model_risk_class": _normalize_token(_metadata_first(metadata, "model_risk_class")),
        "model_status": _normalize_token(_metadata_first(metadata, "model_status")),
        "agent_id": _normalize_token(metadata.get("agent_id")),
        "agent_owner": _normalize_token(_metadata_first(metadata, "agent_owner")),
        "agent_framework": _normalize_token(_metadata_first(metadata, "agent_framework", "framework")),
        "executing_principal": _normalize_token(_metadata_first(metadata, "executing_principal", "workload_identity")),
        "delegation_root": _normalize_token(_metadata_first(metadata, "delegation_root")),
        "delegation_depth": _metadata_first(metadata, "delegation_depth"),
        "tool_name": _normalize_token(metadata.get("tool_name") or metadata.get("tool") or metadata.get("mcp_tool")),
        "mcp_server": _normalize_token(metadata.get("mcp_server") or metadata.get("mcp_server_id")),
        "tool_fingerprint": _normalize_token(_metadata_first(metadata, "tool_fingerprint")),
        "schema_fingerprint": _normalize_token(_metadata_first(metadata, "schema_fingerprint")),
        "tool_trust_state": _normalize_token(_metadata_first(metadata, "tool_trust_state", "trust_state")),
        "tool_lifecycle_state": _normalize_token(_metadata_first(metadata, "tool_lifecycle_state", "lifecycle_state")),
        "resource_class": _normalize_token(_metadata_first(metadata, "resource_class")),
        "target_system": _normalize_token(_metadata_first(metadata, "target_system")),
        "target_environment": _normalize_token(_metadata_first(metadata, "target_environment")),
        "target_tenant": _normalize_token(_metadata_first(metadata, "target_tenant")),
        "represented_subject": _normalize_token(_metadata_first(metadata, "represented_subject", "subject_ref")),
        "subject_type": _normalize_token(_metadata_first(metadata, "subject_type")),
        "authority_type": _normalize_token(_metadata_first(metadata, "authority_type")),
        "authority_scope": _metadata_first(metadata, "authority_scope"),
        "privilege_class": _normalize_token(_metadata_first(metadata, "privilege_class")),
        "environment": _normalize_token(metadata.get("environment")),
        "business_purpose": _normalize_token(metadata.get("business_purpose") or metadata.get("purpose")),
        "action_type": _normalize_token(action.action_type),
        "action_class": _normalize_token(_metadata_first(metadata, "action_class") or action.action_type),
        "action_risk": _normalize_token(_metadata_first(metadata, "action_risk", "risk_tier")),
        "operation": _normalize_token(_metadata_first(metadata, "operation") or action.action_type),
        "side_effect": _normalize_token(_metadata_first(metadata, "side_effect")),
        "persistence": _normalize_token(_metadata_first(metadata, "persistence")),
        "reversibility": _normalize_token(_metadata_first(metadata, "reversibility")),
        "decision": _normalize_token(action.enforcement_action),
        "policy_decision": _normalize_token(_metadata_first(metadata, "policy_decision") or action.enforcement_action),
        "policy_family": _normalize_token(_metadata_first(metadata, "policy_family")),
        "approval_state": _normalize_token(_metadata_first(metadata, "approval_state", "approval_status")),
        "control_response": _normalize_token(_metadata_first(metadata, "control_response")),
        "control_health": _normalize_token(_metadata_first(metadata, "control_health")),
        "evidence_quality": _normalize_token(_metadata_first(metadata, "evidence_quality")),
        "data_classification": _normalize_token(action.data_classification),
        "sensitivity_score": float(action.sensitivity_score or 0.0),
        "destination": _normalize_token(_metadata_first(metadata, "destination", "destination_domain", "domain")),
        "destination_class": _normalize_token(_metadata_first(metadata, "destination_class", "destination_type")),
        "destination_region": _normalize_token(_metadata_first(metadata, "destination_region", "region")),
        "record_count": _metadata_first(metadata, "record_count"),
        "file_size": _metadata_first(metadata, "file_size"),
        "recipient_count": _metadata_first(metadata, "recipient_count"),
        "timestamp": action.timestamp.isoformat() if action.timestamp is not None else "",
    }


def create_maturity_scope(
    db: Session,
    *,
    tenant_id: str,
    scope_key: str,
    scope_type: str,
    display_name: str,
    filters: dict[str, Any],
) -> MaturityScope:
    require_maturity_capability(db, tenant_id=tenant_id, capability="visibility")
    normalized_type = _normalize_token(scope_type)
    normalized_key = str(scope_key or "").strip()
    if normalized_type not in MATURITY_SCOPE_TYPES:
        raise ValueError("unsupported_maturity_scope_type")
    if not normalized_key or len(normalized_key) > 255 or not str(display_name or "").strip():
        raise ValueError("invalid_maturity_scope")
    if not isinstance(filters, dict):
        raise ValueError("invalid_maturity_scope_filters")

    existing = db.scalar(
        select(MaturityScope).where(
            MaturityScope.tenant_id == tenant_id,
            MaturityScope.scope_key == normalized_key,
        )
    )
    if existing is not None:
        return existing
    scope = MaturityScope(
        tenant_id=tenant_id,
        scope_key=normalized_key,
        scope_type=normalized_type,
        display_name=str(display_name).strip(),
        filters={str(key): value for key, value in filters.items()},
        active=True,
    )
    db.add(scope)
    db.flush()
    return scope


def _source_context_refs(db: Session, *, tenant_id: str) -> tuple[list[str], bool]:
    refs: list[str] = []
    coverage = db.scalar(
        select(ControlCoverageSnapshot)
        .where(ControlCoverageSnapshot.tenant_id == tenant_id)
        .order_by(ControlCoverageSnapshot.computed_at.desc(), ControlCoverageSnapshot.id.desc())
    )
    if coverage is not None:
        refs.append(f"control_coverage:{coverage.id}")
    current_assertion = db.scalar(
        select(ControlAssertion.id)
        .where(
            ControlAssertion.tenant_id == tenant_id,
            ControlAssertion.assurance_state == "CURRENT",
        )
        .limit(1)
    )
    if current_assertion:
        refs.append(f"continuous_assurance:{current_assertion}")
    return refs, bool(current_assertion)


def _surface_context(
    db: Session,
    *,
    tenant_id: str,
    scope: MaturityScope,
) -> tuple[set[str], dict[str, int], list[str], list[str], bool]:
    """Return connected families, health counts, refs, gaps, and freshness.

    DeploymentSurface remains the source of truth for connection and health.
    Canonical actions complement it with observed activity; they do not turn an
    unregistered or unhealthy deployment into an assured surface.
    """

    rows = list(
        db.scalars(
            select(DeploymentSurface).where(DeploymentSurface.tenant_id == tenant_id)
        ).all()
    )
    selected = _scope_filter_values(scope, "source_surface") or _implicit_scope_value(scope, "source_surface")
    if selected:
        rows = [row for row in rows if _normalize_token(row.deployment_family) in selected]
    health_counts = dict(Counter(_normalize_token(row.health_status) or "unknown" for row in rows))
    connected: set[str] = set()
    gaps: list[str] = []
    refs: list[str] = []
    current = True
    for row in rows:
        family = _normalize_token(row.deployment_family)
        health = _normalize_token(row.health_status) or "unknown"
        status = _normalize_token(row.status)
        refs.append(f"deployment_surface:{row.id}")
        if status not in {"disabled", "offline", "retired", "uninstalled"} and health not in {"offline", "unknown"}:
            if family:
                connected.add(family)
        if health in {"degraded", "offline", "stale", "unknown"}:
            current = False
            if family:
                gaps.append(f"surface_{family}_{health}")
    return connected, health_counts, _bounded_refs(refs, maximum=100), sorted(set(gaps)), current


def _critical_scope_gaps(db: Session, *, tenant_id: str, scope: MaturityScope) -> list[str]:
    """Never average an explicitly critical immature surface into an org stage."""

    if scope.scope_type != "organization":
        return []
    gaps: list[str] = []
    surface_scopes = list(
        db.scalars(
            select(MaturityScope).where(
                MaturityScope.tenant_id == tenant_id,
                MaturityScope.scope_type == "surface",
                MaturityScope.active.is_(True),
            )
        ).all()
    )
    for child in surface_scopes:
        filters = child.filters if isinstance(child.filters, dict) else {}
        criticality = _normalize_token(filters.get("criticality"))
        if criticality not in {"high", "critical"}:
            continue
        assessment = db.scalar(
            select(MaturityAssessment)
            .where(MaturityAssessment.tenant_id == tenant_id, MaturityAssessment.scope_id == child.id)
            .order_by(MaturityAssessment.computed_at.desc(), MaturityAssessment.id.desc())
        )
        if assessment is not None and assessment.stage not in {"CONTROLLED", "ASSURED"}:
            gaps.append(f"critical_scope:{child.scope_key}:{assessment.stage.lower()}")
    return sorted(set(gaps))


def _latest_control_state(db: Session, *, tenant_id: str, scope_id: str) -> tuple[bool, bool]:
    rollout = db.scalar(
        select(MaturityPolicyRollout)
        .where(
            MaturityPolicyRollout.tenant_id == tenant_id,
            MaturityPolicyRollout.scope_id == scope_id,
            MaturityPolicyRollout.state.in_(("ENFORCE", "MONITOR")),
            MaturityPolicyRollout.policy_version_id.is_not(None),
        )
        .order_by(MaturityPolicyRollout.updated_at.desc(), MaturityPolicyRollout.id.desc())
    )
    if rollout is None:
        return False, False
    effectiveness = db.scalar(
        select(MaturityPolicyEffectivenessSnapshot)
        .where(
            MaturityPolicyEffectivenessSnapshot.tenant_id == tenant_id,
            MaturityPolicyEffectivenessSnapshot.rollout_id == rollout.id,
        )
        .order_by(MaturityPolicyEffectivenessSnapshot.created_at.desc(), MaturityPolicyEffectivenessSnapshot.id.desc())
    )
    return True, effectiveness is not None and effectiveness.status == "CURRENT"


def _recommendation_state(db: Session, *, tenant_id: str, scope_id: str) -> tuple[bool, bool]:
    recommendation = db.scalar(
        select(MaturityPolicyRecommendation)
        .where(
            MaturityPolicyRecommendation.tenant_id == tenant_id,
            MaturityPolicyRecommendation.scope_id == scope_id,
            MaturityPolicyRecommendation.status.in_(("DRAFT", "REVIEW", "APPROVED")),
        )
        .order_by(MaturityPolicyRecommendation.updated_at.desc(), MaturityPolicyRecommendation.id.desc())
    )
    if recommendation is None:
        return False, False
    simulation = db.scalar(
        select(MaturityPolicySimulation)
        .where(
            MaturityPolicySimulation.tenant_id == tenant_id,
            MaturityPolicySimulation.recommendation_id == recommendation.id,
            MaturityPolicySimulation.passed.is_(True),
        )
        .order_by(MaturityPolicySimulation.created_at.desc(), MaturityPolicySimulation.id.desc())
    )
    return True, simulation is not None


def _pattern_rows(
    db: Session,
    *,
    tenant_id: str,
    scope_id: str,
    observation_window_id: str,
    projections: list[dict[str, Any]],
) -> tuple[MaturityObservedUsagePattern, ...]:
    existing = tuple(
        db.scalars(
            select(MaturityObservedUsagePattern).where(
                MaturityObservedUsagePattern.tenant_id == tenant_id,
                MaturityObservedUsagePattern.scope_id == scope_id,
                MaturityObservedUsagePattern.observation_window_id == observation_window_id,
            )
        ).all()
    )
    if existing:
        return existing

    dimensions = (
        "source_surface",
        "actor_group",
        "actor_department",
        "business_unit",
        "application",
        "provider",
        "model",
        "account_class",
        "agent_id",
        "tool_name",
        "mcp_server",
        "action_type",
        "data_classification",
        "destination",
        "destination_class",
        "side_effect",
        "policy_decision",
        "policy_family",
        "business_purpose",
        "environment",
    )
    counts: dict[tuple[str, str], int] = Counter()
    evidence: dict[tuple[str, str], list[str]] = defaultdict(list)
    matching_actions: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for action in projections:
        for dimension in dimensions:
            value = _normalize_token(action.get(dimension))
            if not value:
                continue
            key = (dimension, value)
            counts[key] += 1
            evidence[key].append(f"ai_action:{action['action_id']}")
            matching_actions[key].append(action)

    previous_rows = list(
        db.scalars(
            select(MaturityObservedUsagePattern).where(
                MaturityObservedUsagePattern.tenant_id == tenant_id,
                MaturityObservedUsagePattern.scope_id == scope_id,
                MaturityObservedUsagePattern.observation_window_id != observation_window_id,
            )
        ).all()
    )
    prior_counts: dict[tuple[str, str], int] = {}
    prior_dimensions = {row.dimension for row in previous_rows}
    for row in previous_rows:
        value = str(row.value_ref or "").partition(":")[2]
        key = (_normalize_token(row.dimension), _normalize_token(value))
        prior_counts[key] = max(prior_counts.get(key, 0), int(row.observation_count or 0))

    def labels(key: tuple[str, str], count: int) -> tuple[str, str, str, str]:
        dimension, value = key
        previous = prior_counts.get(key, 0)
        if previous == 0 and dimension in prior_dimensions:
            pattern_type = "NEW"
        elif previous and count >= max(2, previous * 2):
            pattern_type = "INCREASING"
        elif previous and count * 2 <= previous:
            pattern_type = "DECREASING"
        elif count >= 5:
            pattern_type = "COMMON"
        elif count == 1:
            pattern_type = "RARE"
        else:
            pattern_type = "OCCASIONAL"

        scoped = matching_actions.get(key, [])
        max_sensitivity = max((float(item.get("sensitivity_score") or 0.0) for item in scoped), default=0.0)
        if any(_normalize_token(item.get("action_risk")) == "critical" for item in scoped) or max_sensitivity >= 0.95:
            risk_state = "CRITICAL"
        elif max_sensitivity >= 0.7:
            risk_state = "HIGH"
        elif max_sensitivity > 0:
            risk_state = "MEDIUM"
        else:
            risk_state = "UNKNOWN"

        explicit_approval = {_normalize_token(item.get("approval_state")) for item in scoped}
        if dimension == "account_class" and any(token in value for token in ("personal", "external", "anonymous")):
            approval_state = "UNAPPROVED"
        elif "unapproved" in explicit_approval:
            approval_state = "UNAPPROVED"
        elif "approved" in explicit_approval or (dimension == "account_class" and "enterprise" in value):
            approval_state = "APPROVED"
        else:
            approval_state = "UNKNOWN"

        decisions = {_normalize_token(item.get("policy_decision")) for item in scoped}
        if decisions & {"block", "blocked"}:
            control_state = "BLOCKED"
        elif decisions & {"require_approval", "hold_for_approval", "require_step_up"}:
            control_state = "APPROVAL_REQUIRED"
        elif decisions & {"warn", "warning"}:
            control_state = "WARNED"
        elif decisions & {"allow", "allowed", "monitor"}:
            control_state = "MONITORED"
        else:
            control_state = "UNKNOWN"
        return pattern_type, approval_state, risk_state, control_state

    total = max(len(projections), 1)
    created: list[MaturityObservedUsagePattern] = []
    for (dimension, value), count in sorted(counts.items()):
        pattern_type, approval_state, risk_state, control_state = labels((dimension, value), count)
        row = MaturityObservedUsagePattern(
            tenant_id=tenant_id,
            scope_id=scope_id,
            observation_window_id=observation_window_id,
            pattern_key=f"{dimension}:{_canonical_digest(value)[:16]}",
            dimension=dimension,
            value_ref=f"{dimension}:{value}",
            pattern_type=pattern_type,
            approval_state=approval_state,
            risk_state=risk_state,
            control_state=control_state,
            observation_count=count,
            confidence=min(1.0, count / total),
            evidence_refs=_bounded_refs(evidence[(dimension, value)], maximum=20),
        )
        db.add(row)
        created.append(row)
    db.flush()
    return tuple(created)


def materialize_maturity_scope(
    db: Session,
    *,
    tenant_id: str,
    scope_id: str,
    now: datetime | None = None,
    window_days: int = OBSERVATION_WINDOW_DAYS,
) -> MaturityMaterialization:
    """Materialize a bounded, metadata-only maturity observation for one scope."""

    require_maturity_capability(db, tenant_id=tenant_id, capability="baselines")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if window_days <= 0 or window_days > 365:
        raise ValueError("invalid_maturity_window_days")
    scope = db.scalar(
        select(MaturityScope).where(MaturityScope.tenant_id == tenant_id, MaturityScope.id == scope_id)
    )
    if scope is None:
        raise ValueError("maturity_scope_not_found")

    window_start = now - timedelta(days=window_days)
    raw_actions = list(
        db.scalars(
            select(AIAction)
            .where(
                AIAction.tenant_id == tenant_id,
                AIAction.timestamp >= window_start,
                AIAction.timestamp <= now,
            )
            .order_by(AIAction.timestamp.asc(), AIAction.action_id.asc())
            .limit(MAX_ACTIONS_PER_OBSERVATION_WINDOW + 1)
        ).all()
    )
    truncated = len(raw_actions) > MAX_ACTIONS_PER_OBSERVATION_WINDOW
    if truncated:
        raw_actions = raw_actions[:MAX_ACTIONS_PER_OBSERVATION_WINDOW]
    sessions = _load_sessions(
        db,
        tenant_id=tenant_id,
        session_ids=sorted({str(action.session_id) for action in raw_actions if action.session_id}),
    )
    projections = [
        _action_projection(action, sessions.get(str(action.session_id)))
        for action in raw_actions
    ]
    projections = [action for action in projections if _matches_scope(scope, action)]

    action_refs = _bounded_refs(f"ai_action:{action['action_id']}" for action in projections)
    connected_surface_families, surface_health, surface_refs, surface_gaps, surface_health_current = _surface_context(
        db,
        tenant_id=tenant_id,
        scope=scope,
    )
    source_counts = {
        "ai_actions": len(projections),
        "source_surfaces": len({item["source_surface"] for item in projections if item["source_surface"]}),
        "registered_surfaces": sum(surface_health.values()),
    }
    source_watermarks = {
        "ai_actions": max((item["timestamp"] for item in projections), default=""),
        "window_days": window_days,
        "truncated": truncated,
    }
    input_digest = _canonical_digest(
        {
            "scope_id": scope.id,
            "window_start": window_start.isoformat(),
            "window_end": now.isoformat(),
            "actions": [(item["action_id"], item["timestamp"]) for item in projections],
            "truncated": truncated,
        }
    )
    observation_window = db.scalar(
        select(MaturityObservationWindow).where(
            MaturityObservationWindow.tenant_id == tenant_id,
            MaturityObservationWindow.scope_id == scope.id,
            MaturityObservationWindow.input_digest == input_digest,
        )
    )
    source_refs, assurance_signal_current = _source_context_refs(db, tenant_id=tenant_id)
    if observation_window is None:
        observation_window = MaturityObservationWindow(
            tenant_id=tenant_id,
            scope_id=scope.id,
            window_start=window_start,
            window_end=now,
            input_digest=input_digest,
            source_watermarks=source_watermarks,
            source_counts=source_counts,
            evidence_refs=_bounded_refs([*action_refs, *surface_refs, *source_refs]),
        )
        db.add(observation_window)
        db.flush()

    patterns = _pattern_rows(
        db,
        tenant_id=tenant_id,
        scope_id=scope.id,
        observation_window_id=observation_window.id,
        projections=projections,
    )
    baseline = db.scalar(
        select(MaturityUsageBaseline).where(
            MaturityUsageBaseline.tenant_id == tenant_id,
            MaturityUsageBaseline.scope_id == scope.id,
            MaturityUsageBaseline.observation_window_id == observation_window.id,
        )
    )
    source_surfaces = {item["source_surface"] for item in projections if item["source_surface"]}
    if baseline is None:
        previous_version = db.scalar(
            select(MaturityUsageBaseline.baseline_version)
            .where(
                MaturityUsageBaseline.tenant_id == tenant_id,
                MaturityUsageBaseline.scope_id == scope.id,
            )
            .order_by(MaturityUsageBaseline.baseline_version.desc())
            .limit(1)
        )
        aggregate_dimensions = (
            "decision",
            "source_surface",
            "actor_group",
            "actor_department",
            "business_unit",
            "application",
            "provider",
            "model",
            "account_class",
            "agent_id",
            "tool_name",
            "mcp_server",
            "action_type",
            "data_classification",
            "destination",
            "destination_class",
            "side_effect",
            "policy_family",
            "business_purpose",
            "environment",
        )
        aggregates = {
            "decision_counts": dict(Counter(item["decision"] or "unknown" for item in projections)),
            "source_surface_counts": dict(Counter(item["source_surface"] or "unknown" for item in projections)),
            "action_type_counts": dict(Counter(item["action_type"] or "unknown" for item in projections)),
            "provider_counts": dict(Counter(item["provider"] or "unknown" for item in projections)),
        }
        for dimension in aggregate_dimensions:
            key = f"{dimension}_counts"
            if key in aggregates:
                continue
            aggregates[key] = dict(
                Counter(_normalize_token(item.get(dimension)) or "unknown" for item in projections)
            )
        baseline = MaturityUsageBaseline(
            tenant_id=tenant_id,
            scope_id=scope.id,
            observation_window_id=observation_window.id,
            baseline_version=int(previous_version or 0) + 1,
            baseline_digest=_canonical_digest(aggregates),
            sample_count=len(projections),
            source_diversity=len(source_surfaces),
            aggregates=aggregates,
            status="COMPLETE"
            if len(projections) >= 5
            and bool(source_surfaces)
            and all(item["action_type"] and (item["application"] or item["model"]) for item in projections)
            and not truncated
            else "PARTIAL",
        )
        db.add(baseline)
        db.flush()

    known_app_identity = bool(projections) and all(item["application"] or item["model"] for item in projections)
    identity_completeness = (
        sum(1 for item in projections if item["actor_user_id"] or item["agent_id"] or item["executing_principal"])
        / max(len(projections), 1)
    )
    action_semantic_completeness = (
        sum(1 for item in projections if item["action_type"] and (item["tool_name"] or item["operation"]))
        / max(len(projections), 1)
    )
    recommendation_ready, simulation_passed = _recommendation_state(db, tenant_id=tenant_id, scope_id=scope.id)
    controlled, effectiveness_current = _latest_control_state(db, tenant_id=tenant_id, scope_id=scope.id)
    high_risk_unknown = any(
        item["sensitivity_score"] >= 0.7 and (not item["provider"] or not item["source_surface"])
        for item in projections
    )
    blocking_gaps = tuple(
        sorted(
            set(
                [
                    *surface_gaps,
                    *_critical_scope_gaps(db, tenant_id=tenant_id, scope=scope),
                    *(
                        value
                        for value, present in (
                            ("observation_limit_exceeded", truncated),
                            ("high_risk_scope_unknown", high_risk_unknown),
                        )
                        if present
                    ),
                ]
            )
        )
    )
    evidence = MaturityEvidence(
        connected=bool(connected_surface_families or projections),
        observation_count=len(projections),
        source_kinds=tuple(source_surfaces),
        asset_identity_known=known_app_identity,
        usage_baseline_ready=baseline.status == "COMPLETE",
        recommendation_ready=recommendation_ready,
        simulation_passed=simulation_passed,
        controlled=controlled,
        assurance_current=effectiveness_current and assurance_signal_current,
        surface_health_current=surface_health_current,
        blocking_gaps=blocking_gaps,
    )
    stage_result = derive_maturity_stage(evidence)
    assessment = db.scalar(
        select(MaturityAssessment).where(
            MaturityAssessment.tenant_id == tenant_id,
            MaturityAssessment.scope_id == scope.id,
            MaturityAssessment.observation_window_id == observation_window.id,
            MaturityAssessment.methodology_version == "maturity-v1",
        )
    )
    confidence = 0.0 if not projections else 0.5 if len(source_surfaces) == 1 else 0.75 if known_app_identity else 0.5
    if baseline.status == "COMPLETE" and known_app_identity:
        confidence = 1.0
    indicators = {
        "observed_actions": len(projections),
        "source_surfaces": sorted(source_surfaces),
        "registered_surface_families": sorted(connected_surface_families),
        "surface_health": surface_health,
        "surface_health_current": surface_health_current,
        "asset_identity_known": known_app_identity,
        "identity_completeness": round(identity_completeness, 4),
        "action_semantic_completeness": round(action_semantic_completeness, 4),
        "usage_baseline_ready": baseline.status == "COMPLETE",
        "recommendation_ready": recommendation_ready,
        "simulation_passed": simulation_passed,
        "controlled": controlled,
        "assurance_current": effectiveness_current and assurance_signal_current,
        "input_truncated": truncated,
    }
    if assessment is None:
        # Confidence levels are threshold labels, not a blended risk score.
        assessment = MaturityAssessment(
            tenant_id=tenant_id,
            scope_id=scope.id,
            observation_window_id=observation_window.id,
            stage=stage_result.stage,
            confidence=confidence,
            source_diversity=len(source_surfaces),
            indicators=indicators,
            missing_gates=list(stage_result.missing_gates),
            blocking_gaps=list(stage_result.blocking_gaps),
            evidence_refs=_bounded_refs([*action_refs, *surface_refs, *source_refs]),
            status="CURRENT" if projections and not truncated else "UNKNOWN",
            methodology_version="maturity-v1",
        )
        db.add(assessment)
        db.flush()
    else:
        previous_stage = assessment.stage
        assessment.stage = stage_result.stage
        assessment.confidence = confidence
        assessment.source_diversity = len(source_surfaces)
        assessment.indicators = {**indicators, "previous_stage": previous_stage}
        assessment.missing_gates = list(stage_result.missing_gates)
        assessment.blocking_gaps = list(stage_result.blocking_gaps)
        assessment.evidence_refs = _bounded_refs([*action_refs, *surface_refs, *source_refs])
        assessment.status = "CURRENT" if projections and not truncated else "UNKNOWN"
        db.flush()

    return MaturityMaterialization(
        scope=scope,
        observation_window=observation_window,
        baseline=baseline,
        assessment=assessment,
        patterns=patterns,
    )
