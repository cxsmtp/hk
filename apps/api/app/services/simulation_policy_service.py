from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.simulation import SimulationDefinition, SimulationPolicy, SimulationRun
from app.services.simulation_executor_registry import (
    ALL_CATEGORIES,
    ALL_SURFACES,
    ensure_executor_registry,
    executor_surface_support,
    infer_required_executor,
    resolve_executor_for_simulation,
)
from app.services.simulation_orchestrator import publish_simulation_update


SEVERITY_ORDER = {"low": 0, "med": 1, "medium": 1, "high": 2, "critical": 3}
ALLOWED_EXECUTION_MODES = {"manual", "scheduled", "batch"}
DEFAULT_ENV_SCOPE = ["sandbox", "staging", "prod-approved"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        token = str(item or "").strip().lower()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(str(value or "").strip().lower(), 0)


def _default_policy_payload(name: str | None = None) -> dict[str, Any]:
    return {
        "name": str(name or "Default Simulation Policy").strip() or "Default Simulation Policy",
        "enabled": True,
        "enabled_categories": list(ALL_CATEGORIES),
        "enabled_surfaces": list(ALL_SURFACES),
        "blocked_categories": [],
        "minimum_severity": "low",
        "require_approval_for": ["severity:critical"],
        "allowed_execution_modes": ["manual", "scheduled", "batch"],
        "environment_scope": list(DEFAULT_ENV_SCOPE),
        "tenant_isolation_required": True,
        "evidence_retention_days": 90,
        "max_parallel_runs": 2,
        "notify_on_fail": True,
        "framework_filters": [],
        "control_filters": [],
        "active": True,
    }


def _hydrate_policy_values(payload: dict[str, Any]) -> dict[str, Any]:
    hydrated = deepcopy(_default_policy_payload())
    hydrated.update(payload or {})

    hydrated["name"] = str(hydrated.get("name") or "Default Simulation Policy").strip() or "Default Simulation Policy"
    hydrated["enabled"] = bool(hydrated.get("enabled", True))
    hydrated["enabled_categories"] = _normalize_str_list(hydrated.get("enabled_categories")) or list(ALL_CATEGORIES)
    hydrated["enabled_surfaces"] = _normalize_str_list(hydrated.get("enabled_surfaces")) or list(ALL_SURFACES)
    hydrated["blocked_categories"] = _normalize_str_list(hydrated.get("blocked_categories"))

    minimum_severity = str(hydrated.get("minimum_severity") or "low").strip().lower()
    if minimum_severity not in {"low", "med", "medium", "high", "critical"}:
        minimum_severity = "low"
    hydrated["minimum_severity"] = "med" if minimum_severity == "medium" else minimum_severity

    hydrated["require_approval_for"] = _normalize_str_list(hydrated.get("require_approval_for"))
    hydrated["allowed_execution_modes"] = [
        mode for mode in _normalize_str_list(hydrated.get("allowed_execution_modes")) if mode in ALLOWED_EXECUTION_MODES
    ] or ["manual"]
    hydrated["environment_scope"] = _normalize_str_list(hydrated.get("environment_scope")) or list(DEFAULT_ENV_SCOPE)

    hydrated["tenant_isolation_required"] = bool(hydrated.get("tenant_isolation_required", True))
    try:
        hydrated["evidence_retention_days"] = max(1, int(hydrated.get("evidence_retention_days", 90)))
    except (TypeError, ValueError):
        hydrated["evidence_retention_days"] = 90
    try:
        hydrated["max_parallel_runs"] = max(1, int(hydrated.get("max_parallel_runs", 2)))
    except (TypeError, ValueError):
        hydrated["max_parallel_runs"] = 2

    hydrated["notify_on_fail"] = bool(hydrated.get("notify_on_fail", True))
    hydrated["framework_filters"] = _normalize_str_list(hydrated.get("framework_filters"))
    hydrated["control_filters"] = _normalize_str_list(hydrated.get("control_filters"))
    hydrated["active"] = bool(hydrated.get("active", False))
    return hydrated


def _validate_policy_payload(
    db: Session,
    *,
    tenant_id: str,
    values: dict[str, Any],
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not values.get("name"):
        errors.append("policy_name_required")
    if int(values.get("max_parallel_runs") or 0) <= 0:
        errors.append("max_parallel_runs_must_be_positive")
    if int(values.get("evidence_retention_days") or 0) <= 0:
        errors.append("evidence_retention_days_must_be_positive")

    if not values.get("allowed_execution_modes"):
        errors.append("allowed_execution_modes_required")

    surface_support = executor_surface_support(db, tenant_id=tenant_id)
    for surface in values.get("enabled_surfaces") or []:
        if surface not in surface_support:
            errors.append(f"unsupported_surface:{surface}")

    return (len(errors) == 0, errors)


def _apply_policy_values(row: SimulationPolicy, values: dict[str, Any]) -> SimulationPolicy:
    row.name = str(values["name"])
    row.enabled = bool(values["enabled"])
    row.enabled_categories = list(values["enabled_categories"])
    row.enabled_surfaces = list(values["enabled_surfaces"])
    row.blocked_categories = list(values["blocked_categories"])
    row.minimum_severity = str(values["minimum_severity"])
    row.require_approval_for = list(values["require_approval_for"])
    row.allowed_execution_modes = list(values["allowed_execution_modes"])
    row.environment_scope = list(values["environment_scope"])
    row.tenant_isolation_required = bool(values["tenant_isolation_required"])
    row.evidence_retention_days = int(values["evidence_retention_days"])
    row.max_parallel_runs = int(values["max_parallel_runs"])
    row.notify_on_fail = bool(values["notify_on_fail"])
    row.framework_filters = list(values["framework_filters"])
    row.control_filters = list(values["control_filters"])
    row.active = bool(values["active"])
    return row


def list_simulation_policies(db: Session, *, tenant_id: str) -> list[SimulationPolicy]:
    ensure_default_policy(db, tenant_id=tenant_id)
    rows = db.scalars(
        select(SimulationPolicy)
        .where(SimulationPolicy.tenant_id == tenant_id)
        .order_by(SimulationPolicy.active.desc(), SimulationPolicy.updated_at.desc())
    ).all()
    return rows


def get_simulation_policy(db: Session, *, tenant_id: str, policy_id: str) -> SimulationPolicy | None:
    return db.scalar(
        select(SimulationPolicy).where(
            SimulationPolicy.id == policy_id,
            SimulationPolicy.tenant_id == tenant_id,
        )
    )


def ensure_default_policy(db: Session, *, tenant_id: str) -> SimulationPolicy:
    ensure_executor_registry(db, tenant_id=tenant_id)
    rows = db.scalars(
        select(SimulationPolicy)
        .where(SimulationPolicy.tenant_id == tenant_id)
        .order_by(SimulationPolicy.updated_at.desc())
    ).all()

    if not rows:
        row = SimulationPolicy(tenant_id=tenant_id)
        _apply_policy_values(row, _default_policy_payload())
        db.add(row)
        db.flush()
        return row

    active = next((item for item in rows if bool(item.active)), None)
    if active is not None:
        return active

    latest = rows[0]
    latest.active = True
    db.flush()
    return latest


def create_simulation_policy(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
) -> tuple[SimulationPolicy, list[str]]:
    ensure_executor_registry(db, tenant_id=tenant_id)
    values = _hydrate_policy_values(payload)
    existing_rows = db.scalars(select(SimulationPolicy).where(SimulationPolicy.tenant_id == tenant_id)).all()
    if not existing_rows:
        values["active"] = True

    valid, errors = _validate_policy_payload(db, tenant_id=tenant_id, values=values)
    if not valid:
        raise ValueError(";".join(errors))

    if values.get("active"):
        for row in existing_rows:
            row.active = False

    row = SimulationPolicy(tenant_id=tenant_id)
    _apply_policy_values(row, values)
    db.add(row)
    db.flush()
    return row, errors


def patch_simulation_policy(
    db: Session,
    *,
    tenant_id: str,
    policy_id: str,
    payload: dict[str, Any],
) -> tuple[SimulationPolicy, list[str]]:
    row = get_simulation_policy(db, tenant_id=tenant_id, policy_id=policy_id)
    if row is None:
        raise ValueError("simulation_policy_not_found")

    base = {
        "name": row.name,
        "enabled": row.enabled,
        "enabled_categories": list(row.enabled_categories or []),
        "enabled_surfaces": list(row.enabled_surfaces or []),
        "blocked_categories": list(row.blocked_categories or []),
        "minimum_severity": row.minimum_severity,
        "require_approval_for": list(row.require_approval_for or []),
        "allowed_execution_modes": list(row.allowed_execution_modes or []),
        "environment_scope": list(row.environment_scope or []),
        "tenant_isolation_required": row.tenant_isolation_required,
        "evidence_retention_days": row.evidence_retention_days,
        "max_parallel_runs": row.max_parallel_runs,
        "notify_on_fail": row.notify_on_fail,
        "framework_filters": list(row.framework_filters or []),
        "control_filters": list(row.control_filters or []),
        "active": row.active,
    }
    base.update(payload or {})
    values = _hydrate_policy_values(base)
    valid, errors = _validate_policy_payload(db, tenant_id=tenant_id, values=values)
    if not valid:
        raise ValueError(";".join(errors))

    if values.get("active"):
        other_rows = db.scalars(
            select(SimulationPolicy).where(
                SimulationPolicy.tenant_id == tenant_id,
                SimulationPolicy.id != row.id,
            )
        ).all()
        for other in other_rows:
            other.active = False

    _apply_policy_values(row, values)
    db.flush()
    return row, errors


def activate_simulation_policy(db: Session, *, tenant_id: str, policy_id: str) -> SimulationPolicy:
    row = get_simulation_policy(db, tenant_id=tenant_id, policy_id=policy_id)
    if row is None:
        raise ValueError("simulation_policy_not_found")

    values = _hydrate_policy_values(
        {
            "name": row.name,
            "enabled": row.enabled,
            "enabled_categories": list(row.enabled_categories or []),
            "enabled_surfaces": list(row.enabled_surfaces or []),
            "blocked_categories": list(row.blocked_categories or []),
            "minimum_severity": row.minimum_severity,
            "require_approval_for": list(row.require_approval_for or []),
            "allowed_execution_modes": list(row.allowed_execution_modes or []),
            "environment_scope": list(row.environment_scope or []),
            "tenant_isolation_required": row.tenant_isolation_required,
            "evidence_retention_days": row.evidence_retention_days,
            "max_parallel_runs": row.max_parallel_runs,
            "notify_on_fail": row.notify_on_fail,
            "framework_filters": list(row.framework_filters or []),
            "control_filters": list(row.control_filters or []),
            "active": True,
        }
    )
    valid, errors = _validate_policy_payload(db, tenant_id=tenant_id, values=values)
    if not valid:
        raise ValueError(";".join(errors))

    others = db.scalars(
        select(SimulationPolicy).where(
            SimulationPolicy.tenant_id == tenant_id,
            SimulationPolicy.id != row.id,
        )
    ).all()
    for other in others:
        other.active = False

    _apply_policy_values(row, values)
    db.flush()
    return row


def get_active_policy(db: Session, *, tenant_id: str) -> SimulationPolicy:
    active = db.scalar(
        select(SimulationPolicy).where(
            SimulationPolicy.tenant_id == tenant_id,
            SimulationPolicy.active.is_(True),
        )
    )
    if active is not None:
        return active
    return ensure_default_policy(db, tenant_id=tenant_id)


def _approval_required(policy: SimulationPolicy, *, category: str, severity: str, simulation_key: str, surface: str) -> bool:
    requirements = _normalize_str_list(policy.require_approval_for)
    if not requirements:
        return False

    severity_rank = _severity_rank(severity)
    for token in requirements:
        if token == "all":
            return True
        if token in {"critical", "high", "med", "low"} and severity_rank >= _severity_rank(token):
            return True
        if token.startswith("severity:") and severity_rank >= _severity_rank(token.split(":", maxsplit=1)[1]):
            return True
        if token.startswith("category:") and category == token.split(":", maxsplit=1)[1]:
            return True
        if token.startswith("simulation:") and simulation_key == token.split(":", maxsplit=1)[1]:
            return True
        if token.startswith("surface:") and surface == token.split(":", maxsplit=1)[1]:
            return True
    return False


def pre_run_check(
    db: Session,
    *,
    tenant_id: str,
    simulation: SimulationDefinition,
    execution_mode: str,
    execution_environment: str,
    approval_granted: bool = False,
) -> dict[str, Any]:
    policy = get_active_policy(db, tenant_id=tenant_id)
    ensure_executor_registry(db, tenant_id=tenant_id)

    dsl = dict(simulation.dsl_json or {})
    category = str(dsl.get("category") or simulation.category or "").strip().lower()
    surface = str(dsl.get("target_surface") or "gateway").strip().lower()
    severity = str(dsl.get("severity") or "med").strip().lower()
    simulation_key = str(dsl.get("id") or simulation.id).strip()
    mapped_controls = _normalize_str_list(dsl.get("maps_to_controls"))
    framework_names = _normalize_str_list([item.get("framework") for item in (dsl.get("framework_mappings") or []) if isinstance(item, dict)])
    required_executor = infer_required_executor(dsl=dsl, category=category)

    output: dict[str, Any] = {
        "status": "approved_to_run",
        "policy_id": policy.id,
        "policy_name": policy.name,
        "policy_enabled": bool(policy.enabled),
        "required_executor": required_executor,
        "execution_mode": str(execution_mode or "manual").strip().lower(),
        "execution_environment": str(execution_environment or "sandbox").strip().lower(),
        "category": category,
        "surface": surface,
        "severity": severity,
        "simulation_key": simulation_key,
        "enabled_surfaces": list(policy.enabled_surfaces or []),
        "enabled_categories": list(policy.enabled_categories or []),
        "allowed_execution_modes": list(policy.allowed_execution_modes or []),
        "environment_scope": list(policy.environment_scope or []),
        "require_approval_for": list(policy.require_approval_for or []),
        "evidence_retention_days": int(policy.evidence_retention_days or 90),
        "max_parallel_runs": int(policy.max_parallel_runs or 1),
        "reasons": [],
        "approval_required": False,
        "executor_resolution": {},
    }

    if simulation.tenant_id != tenant_id and policy.tenant_isolation_required:
        output["status"] = "blocked_by_policy"
        output["reasons"].append("tenant_isolation_mismatch")
        return output

    if not policy.enabled:
        output["status"] = "blocked_by_policy"
        output["reasons"].append("policy_disabled")
        return output

    if category in set(_normalize_str_list(policy.blocked_categories)):
        output["status"] = "blocked_by_policy"
        output["reasons"].append(f"category_blocked:{category}")
        return output

    enabled_categories = set(_normalize_str_list(policy.enabled_categories))
    if enabled_categories and category not in enabled_categories:
        output["status"] = "blocked_by_policy"
        output["reasons"].append(f"category_not_enabled:{category}")
        return output

    enabled_surfaces = set(_normalize_str_list(policy.enabled_surfaces))
    if enabled_surfaces and surface not in enabled_surfaces:
        output["status"] = "blocked_by_policy"
        output["reasons"].append(f"surface_not_enabled:{surface}")
        return output

    mode = output["execution_mode"]
    if mode not in set(_normalize_str_list(policy.allowed_execution_modes)):
        output["status"] = "blocked_by_policy"
        output["reasons"].append(f"execution_mode_not_allowed:{mode}")
        return output

    env = output["execution_environment"]
    if env not in set(_normalize_str_list(policy.environment_scope)):
        output["status"] = "blocked_by_policy"
        output["reasons"].append(f"environment_not_allowed:{env}")
        return output

    minimum_rank = _severity_rank(policy.minimum_severity)
    if _severity_rank(severity) < minimum_rank:
        output["status"] = "blocked_by_policy"
        output["reasons"].append(f"severity_below_policy_threshold:{severity}")
        return output

    control_filter = set(_normalize_str_list(policy.control_filters))
    if control_filter and not control_filter.intersection(set(mapped_controls)):
        output["status"] = "blocked_by_policy"
        output["reasons"].append("control_filter_excluded")
        return output

    framework_filter = set(_normalize_str_list(policy.framework_filters))
    if framework_filter and not framework_filter.intersection(set(framework_names)):
        output["status"] = "blocked_by_policy"
        output["reasons"].append("framework_filter_excluded")
        return output

    in_flight = db.scalar(
        select(func.count())
        .select_from(SimulationRun)
        .where(
            SimulationRun.tenant_id == tenant_id,
            SimulationRun.finished_at.is_(None),
        )
    )
    if int(in_flight or 0) >= int(policy.max_parallel_runs):
        output["status"] = "blocked_by_policy"
        output["reasons"].append("max_parallel_runs_exceeded")
        return output

    resolution = resolve_executor_for_simulation(db, tenant_id=tenant_id, simulation=simulation)
    output["executor_resolution"] = resolution
    support_status = str(resolution.get("support_status") or "not_yet_executable")
    output["required_executor"] = str(resolution.get("required_executor") or required_executor)

    if support_status == "not_yet_executable":
        output["status"] = "not_executable"
        output["reasons"].append(str(resolution.get("reason") or "executor_missing_or_unsupported"))
        return output

    if _approval_required(
        policy,
        category=category,
        severity=severity,
        simulation_key=simulation_key,
        surface=surface,
    ) and not approval_granted:
        output["status"] = "approval_required"
        output["approval_required"] = True
        output["reasons"].append("policy_requires_approval")
        return output

    if support_status == "partially_executable":
        output["reasons"].append(str(resolution.get("reason") or "executor_partial_capability"))

    return output


def create_pre_run_blocked_result(
    db: Session,
    *,
    tenant_id: str,
    simulation: SimulationDefinition,
    ai_system_id: str,
    mode: str,
    inputs_used: dict[str, Any],
    pre_run_policy: dict[str, Any],
    live_session_id: str | None = None,
) -> SimulationRun:
    status = str(pre_run_policy.get("status") or "blocked_by_policy").strip().lower()
    reasons = [str(item) for item in (pre_run_policy.get("reasons") or []) if str(item).strip()]
    support_status = str((pre_run_policy.get("executor_resolution") or {}).get("support_status") or "not_yet_executable")

    run = SimulationRun(
        tenant_id=tenant_id,
        simulation_id=simulation.id,
        ai_system_id=ai_system_id,
        mode=str(mode or "deterministic").strip().lower() or "deterministic",
        inputs_used=dict(inputs_used or {}),
        finished_at=_utcnow(),
        results={
            "result": "not_executable",
            "final_outcome": "not_executable",
            "failed_assertions": [f"pre_run_policy:{status}", *reasons],
            "enforcement_events_linked": [],
            "evidence_nodes_created": [],
            "pass_rate": 0.0,
            "passes": 0,
            "iterations": 0,
            "expected_controls": list((simulation.dsl_json or {}).get("maps_to_controls") or []),
            "triggered_controls": [],
            "missed_controls": list((simulation.dsl_json or {}).get("maps_to_controls") or []),
            "severity": str((simulation.dsl_json or {}).get("severity") or "med"),
            "evaluator_reasoning": "Simulation execution was prevented by active simulation policy pre-run checks.",
            "confidence": 1.0,
            "execution_status": support_status,
            "execution_support_matrix": [],
            "enforcement_summary": {},
            "step_trace_ids": [],
            "non_executable_steps": [
                {
                    "status": status,
                    "reason": "; ".join(reasons) or status,
                    "required_executor": pre_run_policy.get("required_executor"),
                }
            ],
            "iteration_outputs": [],
            "pre_run_policy": pre_run_policy,
        },
        controls_impacted=[],
        notes="simulation_pre_run_blocked",
    )
    db.add(run)
    db.flush()

    publish_simulation_update(
        tenant_id=tenant_id,
        event_type="simulation.run.started",
        payload={
            "run_id": run.id,
            "simulation_id": simulation.id,
            "ai_system_id": ai_system_id,
            "mode": run.mode,
            "iterations": 0,
            "live_session_id": live_session_id,
            "timestamp": _utcnow().isoformat(),
        },
    )
    publish_simulation_update(
        tenant_id=tenant_id,
        event_type="simulation.run.completed",
        payload={
            "run_id": run.id,
            "simulation_id": simulation.id,
            "ai_system_id": ai_system_id,
            "live_session_id": live_session_id,
            "timestamp": _utcnow().isoformat(),
            "final_outcome": "not_executable",
            "result": "not_executable",
            "execution_status": support_status,
            "reason": "; ".join(reasons) or status,
            "policy_status": status,
            "policy_name": pre_run_policy.get("policy_name"),
            "required_executor": pre_run_policy.get("required_executor"),
            "pre_run_policy": pre_run_policy,
        },
    )
    return run
