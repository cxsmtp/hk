from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
from typing import Any

from app.services.control_graph_service import normalize_control_ids


def _default_required_executor(*, target_surface: str, category: str) -> str:
    surface = str(target_surface or "").strip().lower()
    if surface == "browser":
        return "browser_executor"
    if surface in {"gateway", "api"}:
        return "gateway_executor"
    if surface == "agent":
        return "agent_executor"
    if surface == "connector":
        return "model_registry_executor"
    if surface == "monitoring":
        return "resource_executor"
    category_token = str(category or "").strip().lower()
    if category_token == "rag_poisoning":
        return "rag_executor"
    return "gateway_executor"


def _load_simulation_contract_model():
    repo_root = Path(__file__).resolve().parents[4]
    packages_dir = repo_root / "packages"
    if packages_dir.exists() and str(packages_dir) not in sys.path:
        sys.path.append(str(packages_dir))

    try:
        from shared.schemas.simulation_dsl import SimulationDefContract
    except Exception:
        return None
    return SimulationDefContract


def _fallback_validate(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    required_top = [
        "id",
        "tenant_id",
        "name",
        "category",
        "target_module",
        "version",
        "safety",
        "inputs_schema",
        "steps",
        "assertions",
        "maps_to_controls",
        "expected_outcomes",
    ]
    for key in required_top:
        if key not in payload:
            errors.append(f"missing top-level field: {key}")

    maps = payload.get("maps_to_controls")
    if not isinstance(maps, list) or len(maps) == 0:
        errors.append("maps_to_controls must be a non-empty list")

    safety = payload.get("safety") or {}
    if safety.get("no_external_network") is not True:
        errors.append("safety.no_external_network must be true")

    if "deterministic_flag" in payload and not isinstance(payload.get("deterministic_flag"), bool):
        errors.append("deterministic_flag must be bool")
    if "safe_testing_boundaries" in payload and not isinstance(payload.get("safe_testing_boundaries"), dict):
        errors.append("safe_testing_boundaries must be an object")
    if "expected_outputs" in payload and not isinstance(payload.get("expected_outputs"), dict):
        errors.append("expected_outputs must be an object")
    if "pass_fail_criteria" in payload and not isinstance(payload.get("pass_fail_criteria"), dict):
        errors.append("pass_fail_criteria must be an object")
    if "evidence_emission_requirements" in payload and not isinstance(payload.get("evidence_emission_requirements"), dict):
        errors.append("evidence_emission_requirements must be an object")
    if "preconditions" in payload and not isinstance(payload.get("preconditions"), list):
        errors.append("preconditions must be a list")
    if "attack_steps" in payload and not isinstance(payload.get("attack_steps"), list):
        errors.append("attack_steps must be a list")
    if "expected_control_behavior" in payload and not isinstance(payload.get("expected_control_behavior"), dict):
        errors.append("expected_control_behavior must be an object")
    if "framework_mappings" in payload and not isinstance(payload.get("framework_mappings"), list):
        errors.append("framework_mappings must be a list")
    if "evidence_requirements" in payload and not isinstance(payload.get("evidence_requirements"), list):
        errors.append("evidence_requirements must be a list")
    if "remediation_template_refs" in payload and not isinstance(payload.get("remediation_template_refs"), list):
        errors.append("remediation_template_refs must be a list")

    return errors


def validate_and_normalize_simulation_dsl(
    *,
    dsl_json: dict[str, Any],
    tenant_id: str,
    simulation_id: str | None,
    name: str,
    category: str,
    target_module: str,
    version: str,
) -> dict[str, Any]:
    if not isinstance(dsl_json, dict):
        raise ValueError("dsl_json must be an object")

    normalized = deepcopy(dsl_json)

    if simulation_id:
        normalized.setdefault("id", simulation_id)
    if not normalized.get("id"):
        raise ValueError("dsl_json.id is required")

    normalized.setdefault("tenant_id", tenant_id)
    normalized.setdefault("name", name)
    normalized.setdefault("category", category)
    normalized.setdefault("target_module", target_module)
    normalized.setdefault("version", version)

    if normalized.get("tenant_id") != tenant_id:
        raise ValueError("dsl_json.tenant_id must match request tenant")
    if normalized.get("name") != name:
        raise ValueError("dsl_json.name must match simulation name")
    if normalized.get("category") != category:
        raise ValueError("dsl_json.category must match simulation category")
    if normalized.get("target_module") != target_module:
        raise ValueError("dsl_json.target_module must match simulation target_module")
    if normalized.get("version") != version:
        raise ValueError("dsl_json.version must match simulation version")

    maps_to_controls = normalized.get("maps_to_controls")
    if not isinstance(maps_to_controls, list) or len(maps_to_controls) == 0:
        raise ValueError("dsl_json.maps_to_controls must contain at least one control id")

    canonical_controls = normalize_control_ids([str(raw).strip() for raw in maps_to_controls])
    if not canonical_controls:
        raise ValueError("dsl_json.maps_to_controls contains no valid control ids")
    normalized["maps_to_controls"] = canonical_controls

    safety = normalized.get("safety") or {}
    if safety.get("no_external_network") is False:
        raise ValueError("dsl_json.safety.no_external_network must be true")
    safety.setdefault("no_external_network", True)
    normalized["safety"] = safety

    normalized.setdefault("deterministic_flag", True)
    normalized.setdefault("target_surface", "gateway")
    normalized.setdefault("executable_status", "executable_now")
    required_executor = str(normalized.get("required_executor") or "").strip().lower()
    if not required_executor:
        normalized["required_executor"] = _default_required_executor(
            target_surface=str(normalized.get("target_surface") or ""),
            category=str(normalized.get("category") or ""),
        )
    else:
        normalized["required_executor"] = required_executor
    normalized.setdefault("preconditions", [])
    normalized.setdefault("attack_steps", [])
    normalized.setdefault(
        "expected_control_behavior",
        {
            "expected_controls": list(normalized.get("maps_to_controls") or []),
            "expected_decision": None,
            "expected_risk_level": None,
        },
    )
    normalized.setdefault("framework_mappings", [])
    normalized.setdefault("evidence_requirements", [])
    normalized.setdefault("remediation_template_refs", [])
    normalized.setdefault(
        "safe_testing_boundaries",
        {
            "allowed_data_classes": ["synthetic", "sanitized"],
            "disallow_production_data": True,
        },
    )
    normalized.setdefault(
        "expected_outputs",
        {
            "result": {"type": "string", "enum": ["pass", "fail", "partial", "not_executable"]},
            "pass_rate": {"type": "number"},
            "evidence_node_ids": {"type": "array", "items": {"type": "string"}},
        },
    )
    normalized.setdefault(
        "pass_fail_criteria",
        {
            "pass_conditions": list((normalized.get("expected_outcomes") or {}).get("pass_conditions") or []),
            "fail_conditions": list((normalized.get("expected_outcomes") or {}).get("fail_conditions") or []),
        },
    )
    normalized.setdefault(
        "evidence_emission_requirements",
        {
            "required_signal_types": [],
            "min_evidence_nodes": 0,
            "require_audit_log": True,
        },
    )

    model = _load_simulation_contract_model()
    if model is not None:
        try:
            validated = model.model_validate(normalized)
        except Exception as exc:
            raise ValueError(f"invalid simulation dsl: {exc}") from exc
        return validated.model_dump(mode="json")

    fallback_errors = _fallback_validate(normalized)
    if fallback_errors:
        raise ValueError("invalid simulation dsl: " + "; ".join(fallback_errors))

    return normalized
