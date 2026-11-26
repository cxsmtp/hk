from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.simulation import SimulationDefinition, SimulationExecutor
from app.services.simulation_orchestrator import browser_executor_available


@dataclass(frozen=True)
class ExecutorTemplate:
    name: str
    supported_surfaces: tuple[str, ...]
    supported_categories: tuple[str, ...]
    supported_simulation_ids: tuple[str, ...]
    status: str
    evidence_types: tuple[str, ...]
    requires: tuple[str, ...]


ALL_SURFACES = ("browser", "gateway", "api", "agent", "connector", "monitoring")
ALL_CATEGORIES = (
    "injection",
    "leakage",
    "agent_misuse",
    "identity_abuse",
    "rag_poisoning",
    "output_safety",
    "resource_abuse",
    "infra_misconfig",
)


BASE_EXECUTOR_TEMPLATES: tuple[ExecutorTemplate, ...] = (
    ExecutorTemplate(
        name="browser_executor",
        supported_surfaces=("browser",),
        supported_categories=("injection", "leakage", "output_safety"),
        supported_simulation_ids=(),
        status="inactive",
        evidence_types=("runtime_event", "policy_decision", "simulation_result", "browser_artifact"),
        requires=("playwright_runner", "browser_execution_enabled"),
    ),
    ExecutorTemplate(
        # The server-side browser control: the evaluation the Hawk extension asks the API for, run in-process with
        # the payload the extension sends. The live Chromium capture leg stays with browser_executor (Playwright).
        name="browser_control_executor",
        supported_surfaces=("browser",),
        supported_categories=("injection", "leakage", "output_safety"),
        supported_simulation_ids=(),
        status="active",
        evidence_types=("runtime_event", "policy_decision", "simulation_result"),
        requires=("browser_interaction_eval",),
    ),
    ExecutorTemplate(
        name="gateway_executor",
        supported_surfaces=("gateway", "api"),
        supported_categories=ALL_CATEGORIES,
        supported_simulation_ids=(),
        status="active",
        evidence_types=("runtime_event", "policy_decision", "simulation_result"),
        requires=("gateway_intercept",),
    ),
    ExecutorTemplate(
        name="agent_executor",
        supported_surfaces=("agent", "gateway"),
        supported_categories=("agent_misuse", "identity_abuse", "resource_abuse"),
        supported_simulation_ids=(),
        status="active",
        evidence_types=("runtime_event", "policy_decision", "simulation_result"),
        requires=("mcp_authorize",),
    ),
    ExecutorTemplate(
        name="rag_executor",
        supported_surfaces=("gateway", "browser"),
        supported_categories=("rag_poisoning",),
        supported_simulation_ids=(),
        # Retrieved context is inspected at the gateway (llm_intercept context); every catalogue RAG scenario has a
        # runner in the unit suite (app/services/simulation_catalog_runners.py), so the executor is no longer partial.
        status="active",
        evidence_types=("runtime_event", "policy_decision", "simulation_result"),
        requires=("retrieval_context_signal",),
    ),
    ExecutorTemplate(
        name="model_registry_executor",
        supported_surfaces=("connector", "gateway"),
        supported_categories=("infra_misconfig",),
        supported_simulation_ids=(),
        status="experimental",
        evidence_types=("runtime_event", "policy_decision", "simulation_result"),
        requires=("model_registry_integration",),
    ),
    ExecutorTemplate(
        name="resource_executor",
        supported_surfaces=("monitoring", "gateway", "agent"),
        supported_categories=("resource_abuse", "output_safety", "identity_abuse"),
        supported_simulation_ids=(),
        status="active",
        evidence_types=("runtime_event", "simulation_result", "audit_log"),
        requires=("monitoring_signal",),
    ),
)


_SURFACE_EXECUTOR_FALLBACK = {
    "browser": "browser_executor",
    "gateway": "gateway_executor",
    "api": "gateway_executor",
    "agent": "agent_executor",
    "connector": "model_registry_executor",
    "monitoring": "resource_executor",
}


_CATEGORY_EXECUTOR_FALLBACK = {
    "rag_poisoning": "rag_executor",
    "resource_abuse": "resource_executor",
    "identity_abuse": "agent_executor",
    "agent_misuse": "agent_executor",
    "infra_misconfig": "model_registry_executor",
    "injection": "gateway_executor",
    "leakage": "gateway_executor",
    "output_safety": "gateway_executor",
}


def _normalize_list(value: Any) -> list[str]:
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


def _dynamic_template_status(template: ExecutorTemplate) -> tuple[str, str]:
    if template.name != "browser_executor":
        return template.status, ""

    available, reason = browser_executor_available()
    if available:
        return "active", reason
    return "inactive", reason


def ensure_executor_registry(db: Session, *, tenant_id: str | None = None) -> list[SimulationExecutor]:
    templates = BASE_EXECUTOR_TEMPLATES
    rows: list[SimulationExecutor] = []

    for template in templates:
        row = db.scalar(
            select(SimulationExecutor).where(
                SimulationExecutor.tenant_id.is_(None),
                SimulationExecutor.is_global.is_(True),
                SimulationExecutor.name == template.name,
            )
        )

        resolved_status, dynamic_reason = _dynamic_template_status(template)
        requires = list(template.requires)
        if dynamic_reason and template.name == "browser_executor":
            requires = [*requires, f"runtime:{dynamic_reason}"]

        if row is None:
            row = SimulationExecutor(
                tenant_id=None,
                is_global=True,
                name=template.name,
                supported_surfaces=list(template.supported_surfaces),
                supported_categories=list(template.supported_categories),
                supported_simulation_ids=list(template.supported_simulation_ids),
                status=resolved_status,
                evidence_types=list(template.evidence_types),
                requires=requires,
            )
            db.add(row)
        else:
            row.supported_surfaces = list(template.supported_surfaces)
            row.supported_categories = list(template.supported_categories)
            row.supported_simulation_ids = list(template.supported_simulation_ids)
            row.status = resolved_status
            row.evidence_types = list(template.evidence_types)
            row.requires = requires
        rows.append(row)

    db.flush()

    if tenant_id:
        return list_executors(db, tenant_id=tenant_id)
    return rows


def list_executors(db: Session, *, tenant_id: str) -> list[SimulationExecutor]:
    ensure_executor_registry(db)
    rows = db.scalars(
        select(SimulationExecutor)
        .where(
            or_(
                SimulationExecutor.tenant_id == tenant_id,
                SimulationExecutor.tenant_id.is_(None),
            )
        )
        .order_by(SimulationExecutor.is_global.desc(), SimulationExecutor.name.asc())
    ).all()

    dedup: dict[str, SimulationExecutor] = {}
    for row in rows:
        key = str(row.name or "").strip().lower()
        if not key:
            continue
        existing = dedup.get(key)
        if existing is None:
            dedup[key] = row
            continue
        if existing.tenant_id is None and row.tenant_id is not None:
            dedup[key] = row
    return list(dedup.values())


def infer_required_executor(*, dsl: dict[str, Any], category: str | None = None) -> str:
    required = str(dsl.get("required_executor") or "").strip().lower()
    if required:
        return required

    surface = str(dsl.get("target_surface") or "").strip().lower()
    if surface in _SURFACE_EXECUTOR_FALLBACK:
        return _SURFACE_EXECUTOR_FALLBACK[surface]

    category_token = str(category or dsl.get("category") or "").strip().lower()
    return _CATEGORY_EXECUTOR_FALLBACK.get(category_token, "gateway_executor")


def resolve_executor_for_simulation(
    db: Session,
    *,
    tenant_id: str,
    simulation: SimulationDefinition,
) -> dict[str, Any]:
    executors = list_executors(db, tenant_id=tenant_id)
    dsl = dict(simulation.dsl_json or {})
    category = str(dsl.get("category") or simulation.category or "").strip().lower()
    surface = str(dsl.get("target_surface") or "gateway").strip().lower()
    simulation_key = str(dsl.get("id") or simulation.id).strip()
    required_name = infer_required_executor(dsl=dsl, category=category)

    row = next((item for item in executors if str(item.name or "").strip().lower() == required_name), None)
    if row is None:
        return {
            "required_executor": required_name,
            "support_status": "not_yet_executable",
            "reason": f"Executor '{required_name}' is not registered.",
        }

    if str(row.status or "").strip().lower() == "inactive":
        return {
            "required_executor": required_name,
            "executor_id": row.id,
            "support_status": "not_yet_executable",
            "reason": f"Executor '{required_name}' is inactive.",
        }

    supported_surfaces = set(_normalize_list(row.supported_surfaces))
    supported_categories = set(_normalize_list(row.supported_categories))
    supported_simulation_ids = set(_normalize_list(row.supported_simulation_ids))

    if supported_surfaces and surface not in supported_surfaces:
        return {
            "required_executor": required_name,
            "executor_id": row.id,
            "support_status": "not_yet_executable",
            "reason": f"Executor '{required_name}' does not support surface '{surface}'.",
        }

    if supported_categories and category not in supported_categories:
        return {
            "required_executor": required_name,
            "executor_id": row.id,
            "support_status": "not_yet_executable",
            "reason": f"Executor '{required_name}' does not support category '{category}'.",
        }

    if supported_simulation_ids and simulation_key.lower() not in supported_simulation_ids:
        return {
            "required_executor": required_name,
            "executor_id": row.id,
            "support_status": "partially_executable",
            "reason": f"Executor '{required_name}' is not explicitly scoped for simulation '{simulation_key}'.",
            "status": str(row.status or "active").strip().lower(),
            "supported_surfaces": sorted(supported_surfaces),
            "supported_categories": sorted(supported_categories),
        }

    support_status = "executable_now"
    if str(row.status or "").strip().lower() == "experimental":
        support_status = "partially_executable"

    return {
        "required_executor": required_name,
        "executor_id": row.id,
        "support_status": support_status,
        "reason": "executor_resolved",
        "status": str(row.status or "active").strip().lower(),
        "supported_surfaces": sorted(supported_surfaces),
        "supported_categories": sorted(supported_categories),
    }


def executor_surface_support(db: Session, *, tenant_id: str) -> dict[str, set[str]]:
    rows = list_executors(db, tenant_id=tenant_id)
    support: dict[str, set[str]] = {}
    for row in rows:
        if str(row.status or "").strip().lower() == "inactive":
            continue
        for surface in _normalize_list(row.supported_surfaces):
            support.setdefault(surface, set()).add(str(row.name or "").strip().lower())
    return support
