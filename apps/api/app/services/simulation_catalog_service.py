from __future__ import annotations

from collections import OrderedDict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.simulation import SimulationCatalogEntry, SimulationDefinition, SimulationExecutor
from app.services.simulation_catalog_source import REQUIRED_CATEGORY_COUNTS, load_simulation_catalog_entries
from app.services.simulation_executor_registry import infer_required_executor, list_executors, resolve_executor_for_simulation


CATEGORY_TARGET_COUNTS: OrderedDict[str, int] = OrderedDict(REQUIRED_CATEGORY_COUNTS.items())


CATEGORY_NORMALIZATION = {
    "injection": "prompt_instruction_attacks",
    "leakage": "data_leakage_inference",
    "agent_misuse": "tool_agent_abuse",
    "output_injection": "tool_agent_abuse",
    "identity_abuse": "ai_identity_access_abuse",
    "rag_poisoning": "training_rag_poisoning",
    "infra_misconfig": "model_supply_chain_integrity",
    "resource_abuse": "resource_abuse_cost_exploitation",
    "output_safety": "overreliance_unsafe_decisioning",
}


EXECUTOR_CATEGORY_HINT = {
    "prompt_instruction_attacks": "injection",
    "data_leakage_inference": "leakage",
    "tool_agent_abuse": "agent_misuse",
    "ai_identity_access_abuse": "identity_abuse",
    "training_rag_poisoning": "rag_poisoning",
    "model_supply_chain_integrity": "infra_misconfig",
    "resource_abuse_cost_exploitation": "resource_abuse",
    "overreliance_unsafe_decisioning": "output_safety",
}


DEFAULT_CONTROLS = {
    "prompt_instruction_attacks": ["PROMPT_INJECTION_DETECTION", "JAILBREAK_DETECTION"],
    "data_leakage_inference": ["SENSITIVE_DATA_DETECTION", "PII_EXFILTRATION_PREVENTION"],
    "tool_agent_abuse": ["TOOL_CALL_VALIDATION", "AGENT_ACTION_AUTHORIZATION"],
    "ai_identity_access_abuse": ["AI_IDENTITY_BINDING", "TOKEN_SCOPE_ENFORCEMENT"],
    "training_rag_poisoning": ["RAG_POISONING_DETECTION", "MODEL_OUTPUT_VALIDATION"],
    "model_supply_chain_integrity": ["MODEL_ACCESS_CONTROL", "MODEL_OUTPUT_VALIDATION"],
    "resource_abuse_cost_exploitation": ["CHAIN_OF_ACTION_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
    "overreliance_unsafe_decisioning": ["MODEL_OUTPUT_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
}


DEFAULT_FRAMEWORKS = {
    "prompt_instruction_attacks": [
        {"framework": "OWASP Top 10 for LLM Applications", "reference": "LLM01", "control_area": "Prompt Injection"},
        {"framework": "MITRE ATLAS", "reference": "Prompt Injection", "control_area": "Adversarial Tactics"},
    ],
    "data_leakage_inference": [
        {"framework": "ISO / IEC 42001", "reference": "A.8", "control_area": "Data Protection"},
        {"framework": "EU AI Act", "reference": "Art. 9", "control_area": "Privacy"},
    ],
    "tool_agent_abuse": [
        {"framework": "OWASP Top 10 for Agentic Applications", "reference": "AGENT01", "control_area": "Tool Abuse"},
    ],
    "ai_identity_access_abuse": [
        {"framework": "ISO / IEC 42001", "reference": "Identity", "control_area": "Identity"},
    ],
    "training_rag_poisoning": [
        {"framework": "MITRE ATLAS", "reference": "Data Poisoning", "control_area": "Poisoning"},
    ],
    "model_supply_chain_integrity": [
        {"framework": "Google SAIF", "reference": "SAIF-P2", "control_area": "Model Integrity"},
    ],
    "resource_abuse_cost_exploitation": [
        {"framework": "NIST AI RMF", "reference": "MANAGE", "control_area": "Operational Risk"},
    ],
    "overreliance_unsafe_decisioning": [
        {"framework": "Microsoft Responsible AI Standard", "reference": "RS6", "control_area": "Safety"},
    ],
}


DEFAULT_SURFACE = {
    "prompt_instruction_attacks": "browser",
    "data_leakage_inference": "browser",
    "tool_agent_abuse": "agent",
    "ai_identity_access_abuse": "agent",
    "training_rag_poisoning": "gateway",
    "model_supply_chain_integrity": "connector",
    "resource_abuse_cost_exploitation": "gateway",
    "overreliance_unsafe_decisioning": "gateway",
}


DEFAULT_SEVERITY = {
    "prompt_instruction_attacks": "high",
    "data_leakage_inference": "high",
    "tool_agent_abuse": "high",
    "ai_identity_access_abuse": "high",
    "training_rag_poisoning": "high",
    "model_supply_chain_integrity": "med",
    "resource_abuse_cost_exploitation": "med",
    "overreliance_unsafe_decisioning": "med",
}


_ALLOWED_EXEC_STATUS = {"executable_now", "partially_executable", "not_yet_executable"}
_SEVERITY_MAP = {"low": "low", "medium": "med", "med": "med", "high": "high", "critical": "critical"}


def _normalized_category(raw_category: str | None) -> str:
    category = str(raw_category or "").strip().lower()
    if category in CATEGORY_TARGET_COUNTS:
        return category
    return CATEGORY_NORMALIZATION.get(category, "overreliance_unsafe_decisioning")


def _clean_unique(values: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _normalize_severity(value: Any, *, default_value: str = "med") -> str:
    token = str(value or "").strip().lower()
    return _SEVERITY_MAP.get(token, _SEVERITY_MAP.get(str(default_value).strip().lower(), "med"))


def _clean_framework_mappings(values: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return out
    for item in values:
        if not isinstance(item, dict):
            continue
        framework = str(item.get("framework") or "").strip()
        reference = str(item.get("reference") or "").strip()
        control_area = str(item.get("control_area") or "").strip()
        if not framework:
            continue
        out.append(
            {
                "framework": framework,
                "reference": reference,
                "control_area": control_area,
            }
        )
    return out


def _simulation_key(definition: SimulationDefinition) -> str:
    dsl = dict(definition.dsl_json or {})
    return str(dsl.get("id") or definition.id).strip()


def _resolved_executor_and_status(
    db: Session,
    *,
    tenant_id: str,
    definition: SimulationDefinition,
) -> tuple[str, str]:
    dsl = dict(definition.dsl_json or {})
    resolution = resolve_executor_for_simulation(db, tenant_id=tenant_id, simulation=definition)
    required_executor = str(resolution.get("required_executor") or infer_required_executor(dsl=dsl, category=definition.category)).strip().lower()
    resolved_status = str(resolution.get("support_status") or "not_yet_executable").strip().lower()

    dsl_status = str(dsl.get("executable_status") or "").strip().lower()
    if dsl_status not in _ALLOWED_EXEC_STATUS:
        dsl_status = resolved_status

    if resolved_status == "not_yet_executable":
        final_status = "not_yet_executable"
    elif dsl_status == "not_yet_executable":
        final_status = "not_yet_executable"
    elif resolved_status == "partially_executable" or dsl_status == "partially_executable":
        final_status = "partially_executable"
    else:
        final_status = "executable_now"

    return required_executor, final_status


def _executor_map(db: Session, *, tenant_id: str) -> dict[str, SimulationExecutor]:
    return {
        str(row.name or "").strip().lower(): row
        for row in list_executors(db, tenant_id=tenant_id)
        if str(row.name or "").strip()
    }


def _resolve_catalog_executor_status(
    *,
    executors_by_name: dict[str, SimulationExecutor],
    category: str,
    target_surface: str,
    desired_status: str,
    required_executor: str,
) -> tuple[str, str]:
    required = str(required_executor or "").strip().lower() or infer_required_executor(
        dsl={"target_surface": target_surface, "category": EXECUTOR_CATEGORY_HINT.get(category, category)},
        category=EXECUTOR_CATEGORY_HINT.get(category, category),
    )
    desired = str(desired_status or "not_yet_executable").strip().lower()
    if desired not in _ALLOWED_EXEC_STATUS:
        desired = "not_yet_executable"

    row = executors_by_name.get(required)
    if row is None:
        return required, "not_yet_executable"

    status = str(row.status or "").strip().lower()
    if status == "inactive":
        return required, "not_yet_executable"

    supported_surfaces = set(_clean_unique(list(row.supported_surfaces or [])))
    if supported_surfaces and str(target_surface).strip().lower() not in supported_surfaces:
        return required, "not_yet_executable"

    supported_categories = set(_clean_unique(list(row.supported_categories or [])))
    category_hint = EXECUTOR_CATEGORY_HINT.get(category, category)
    if supported_categories and category_hint not in supported_categories:
        return required, "not_yet_executable"

    if desired == "not_yet_executable":
        return required, "not_yet_executable"
    if status == "experimental":
        return required, "partially_executable"
    if desired == "partially_executable":
        return required, "partially_executable"
    return required, "executable_now"


def sync_simulation_catalog(db: Session, *, tenant_id: str) -> dict[str, Any]:
    source_entries = load_simulation_catalog_entries()
    definitions = db.scalars(
        select(SimulationDefinition)
        .where(SimulationDefinition.tenant_id == tenant_id)
        .order_by(SimulationDefinition.created_at.asc(), SimulationDefinition.id.asc())
    ).all()
    existing_rows = db.scalars(
        select(SimulationCatalogEntry).where(SimulationCatalogEntry.tenant_id == tenant_id)
    ).all()

    by_simulation_id = {str(row.simulation_id): row for row in existing_rows}
    touched_ids: set[str] = set()
    executors_by_name = _executor_map(db, tenant_id=tenant_id)

    # 1) Persist full catalog source (defined catalog entries).
    for entry in source_entries:
        simulation_id = str(entry.get("simulation_id") or "").strip()
        if not simulation_id:
            continue
        category = _normalized_category(str(entry.get("category") or ""))
        target_surface = str(entry.get("target_surface") or DEFAULT_SURFACE.get(category) or "gateway").strip().lower()
        required_executor, executable_status = _resolve_catalog_executor_status(
            executors_by_name=executors_by_name,
            category=category,
            target_surface=target_surface,
            desired_status=str(entry.get("executable_status") or "not_yet_executable"),
            required_executor=str(entry.get("required_executor") or ""),
        )

        row = by_simulation_id.get(simulation_id)
        if row is None:
            row = SimulationCatalogEntry(
                tenant_id=tenant_id,
                simulation_id=simulation_id,
            )
            db.add(row)
            by_simulation_id[simulation_id] = row

        row.category = category
        row.subcategory = str(entry.get("subcategory") or "catalog").strip().lower() or "catalog"
        row.severity = _normalize_severity(entry.get("severity"), default_value=DEFAULT_SEVERITY.get(category, "med"))
        row.control_ids = _clean_unique(list(entry.get("control_ids") or DEFAULT_CONTROLS.get(category, [])))
        row.framework_mappings = _clean_framework_mappings(entry.get("framework_mappings") or DEFAULT_FRAMEWORKS.get(category, []))
        row.target_surface = target_surface
        row.executable_status = executable_status
        row.required_executor = required_executor
        row.defined = bool(entry.get("defined", True))
        row.implemented = bool(entry.get("implemented", False))
        row.version = str(entry.get("version") or "v1")
        touched_ids.add(simulation_id)

    # 2) Overlay real simulation definitions as implemented entries.
    for definition in definitions:
        dsl = dict(definition.dsl_json or {})
        simulation_id = _simulation_key(definition)
        category = _normalized_category(str(dsl.get("category") or definition.category))
        required_executor, executable_status = _resolved_executor_and_status(
            db,
            tenant_id=tenant_id,
            definition=definition,
        )

        row = by_simulation_id.get(simulation_id)
        if row is None:
            row = SimulationCatalogEntry(
                tenant_id=tenant_id,
                simulation_id=simulation_id,
            )
            db.add(row)
            by_simulation_id[simulation_id] = row

        row.category = category
        row.subcategory = str(dsl.get("subcategory") or row.subcategory or "seed_pack").strip().lower() or "seed_pack"
        row.severity = _normalize_severity(dsl.get("severity"), default_value=DEFAULT_SEVERITY.get(category, "med"))
        row.control_ids = _clean_unique(list(dsl.get("maps_to_controls") or row.control_ids or DEFAULT_CONTROLS.get(category, [])))
        row.framework_mappings = _clean_framework_mappings(dsl.get("framework_mappings") or row.framework_mappings or DEFAULT_FRAMEWORKS.get(category, []))
        row.target_surface = str(dsl.get("target_surface") or row.target_surface or DEFAULT_SURFACE.get(category) or "gateway").strip().lower()
        row.executable_status = executable_status
        row.required_executor = required_executor
        row.defined = True
        row.implemented = True
        row.version = str(definition.version or row.version or "v1")
        touched_ids.add(simulation_id)

    # 3) Remove stale rows not represented by source catalog or existing definitions.
    stale_rows = [row for sim_id, row in by_simulation_id.items() if sim_id not in touched_ids]
    for row in stale_rows:
        db.delete(row)

    db.flush()
    return get_catalog_coverage(db, tenant_id=tenant_id)


def list_catalog_entries(db: Session, *, tenant_id: str) -> list[SimulationCatalogEntry]:
    rows = db.scalars(
        select(SimulationCatalogEntry)
        .where(SimulationCatalogEntry.tenant_id == tenant_id)
        .order_by(SimulationCatalogEntry.category.asc(), SimulationCatalogEntry.simulation_id.asc())
    ).all()
    return rows


def get_catalog_coverage(db: Session, *, tenant_id: str) -> dict[str, Any]:
    rows = list_catalog_entries(db, tenant_id=tenant_id)

    by_status: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}
    by_framework: dict[str, dict[str, int]] = {}
    by_control: dict[str, dict[str, int]] = {}
    executable_now = 0
    partially_executable = 0
    not_yet_executable = 0
    implemented = 0

    for row in rows:
        status = str(row.executable_status or "not_yet_executable").strip().lower()
        category = _normalized_category(row.category)

        by_status[status] = by_status.get(status, 0) + 1
        bucket = by_category.setdefault(
            category,
            {
                "defined": 0,
                "implemented": 0,
                "executable_now": 0,
                "partially_executable": 0,
                "not_yet_executable": 0,
            },
        )
        bucket["defined"] += 1

        if row.implemented:
            implemented += 1
            bucket["implemented"] += 1

        if status == "executable_now":
            executable_now += 1
            bucket["executable_now"] += 1
        elif status == "partially_executable":
            partially_executable += 1
            bucket["partially_executable"] += 1
        else:
            not_yet_executable += 1
            bucket["not_yet_executable"] += 1

        frameworks_seen: set[str] = set()
        for mapping in _clean_framework_mappings(row.framework_mappings):
            framework = str(mapping.get("framework") or "").strip()
            if not framework or framework in frameworks_seen:
                continue
            frameworks_seen.add(framework)
            framework_bucket = by_framework.setdefault(
                framework,
                {"simulations": 0, "implemented": 0, "executable_now": 0, "partially_executable": 0, "not_yet_executable": 0},
            )
            framework_bucket["simulations"] += 1
            if row.implemented:
                framework_bucket["implemented"] += 1
            if status == "executable_now":
                framework_bucket["executable_now"] += 1
            elif status == "partially_executable":
                framework_bucket["partially_executable"] += 1
            else:
                framework_bucket["not_yet_executable"] += 1

        controls_seen: set[str] = set()
        for control_id in _clean_unique(list(row.control_ids or [])):
            if control_id in controls_seen:
                continue
            controls_seen.add(control_id)
            control_bucket = by_control.setdefault(
                control_id,
                {"simulations": 0, "implemented": 0, "executable_now": 0, "partially_executable": 0, "not_yet_executable": 0},
            )
            control_bucket["simulations"] += 1
            if row.implemented:
                control_bucket["implemented"] += 1
            if status == "executable_now":
                control_bucket["executable_now"] += 1
            elif status == "partially_executable":
                control_bucket["partially_executable"] += 1
            else:
                control_bucket["not_yet_executable"] += 1

    total_defined = len(rows)
    planned_only = max(0, total_defined - implemented)
    coverage_ratio = (executable_now / float(total_defined)) if total_defined else 0.0

    return {
        "tenant_id": tenant_id,
        "total_required": int(sum(CATEGORY_TARGET_COUNTS.values())),
        "total_defined": total_defined,
        "total_implemented": implemented,
        "planned_only": planned_only,
        "executable_now": executable_now,
        "partially_executable": partially_executable,
        "not_yet_executable": not_yet_executable,
        "coverage_ratio": round(coverage_ratio, 6),
        "required_by_category": dict(CATEGORY_TARGET_COUNTS),
        "by_executable_status": by_status,
        "by_category": by_category,
        "coverage_by_category": by_category,
        "coverage_by_framework": dict(sorted(by_framework.items(), key=lambda item: item[0].lower())),
        "coverage_by_control": dict(sorted(by_control.items(), key=lambda item: item[0].lower())),
    }

