from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from datetime import datetime, timezone
from math import floor
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.observability import get_correlation_id, log_structured
from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.maturity import ControlMaturity, ControlMaturityHistory
from app.db.models.policy import ControlGuardianBinding, GuardianContractBindingV2
from app.db.models.simulation import Control, SimulationDefinition, SimulationExecutionStep, SimulationRun
from app.services.audit_service import write_audit_log
from app.services.browser_extension_service import evaluate_browser_interaction_and_record
from app.services.control_validator import evaluate_final_outcome, evaluate_iteration_outcome
from app.services.crq_service import compute_simulation_crq
from app.services.evidence_service import create_evidence_node
from app.services.gateway_service import llm_intercept, mcp_authorize
from app.services.runtime_control_agent_action_service import evaluate_agent_action_and_record
from app.services.governance_guard import enforce as enforce_governance
from app.services.maturity_service import recalculate_control_maturity
from app.services.monitoring_service import ingest_monitoring_signal, ingest_shadow_event
from app.services.policy_service import tighten_enforcement_for_failed_controls
from app.services.simulation_policy_service import create_pre_run_blocked_result, pre_run_check
from app.services.simulation_orchestrator import (
    build_execution_support_matrix as build_execution_support_matrix_orchestrator,
    overall_execution_status as overall_execution_status_orchestrator,
    publish_simulation_update,
    run_browser_step,
    step_execution_profile as step_execution_profile_orchestrator,
    write_run_evidence_bundle,
)
from app.services.snapshot_service import create_auditor_snapshot


def _simulation_request_id(*, run_id: str, step_id: str, base_request_id: str, iteration: int | None) -> str:
    # EnforcementEvent.request_id is VARCHAR(36) in PostgreSQL. Preserve the
    # simulation prefix (which prevents recursive scheduling), while binding
    # the full run, step and iteration identity without truncating source IDs.
    material = json.dumps(["hawk-simulation-request/1", run_id, step_id, base_request_id, iteration], separators=(",", ":"))
    return "sim-" + hashlib.sha256(material.encode()).hexdigest()[:32]


def _resolve_binding(bindings: dict[str, Any], key: str, default: Any = None) -> Any:
    value = bindings.get(key, default)
    return value


def _synthetic_variables() -> dict[str, str]:
    from app.services.simulation_catalog_runners import synthetic_variables

    return synthetic_variables()


def _substitute(template: Any, variables: dict[str, Any]) -> Any:
    if isinstance(template, str):
        out = template
        for k, v in variables.items():
            out = out.replace("{{" + k + "}}", str(v))
        return out
    if isinstance(template, list):
        return [_substitute(item, variables) for item in template]
    if isinstance(template, dict):
        return {k: _substitute(v, variables) for k, v in template.items()}
    return template


def _read_path(payload: dict[str, Any], field: str) -> Any:
    current: Any = payload
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _check_assertion(operator: str, actual: Any, expected: Any) -> bool:
    if operator == "exists":
        exists = actual is not None and actual != "" and actual != [] and actual != {}
        if isinstance(expected, bool):
            return exists == expected
        return exists
    if operator == "equals":
        return actual == expected
    if operator == "in":
        return actual in expected if isinstance(expected, (list, tuple, set)) else False
    if operator == "contains":
        return str(expected) in str(actual)
    if operator == "gt":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False
    if operator == "lt":
        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False
    return False


_ASSERTION_ECHO_KEYS = {
    "payload",
    "payload_template",
    "input_payload_ref",
    "inputs_used",
    "prompt",
    "prompt_or_content",
    "prompt_preview",
    "prompt_preview_redacted",
    "original_intent",
}


def _observed_assertion_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _observed_assertion_value(item)
            for key, item in value.items()
            if str(key).strip().lower() not in _ASSERTION_ECHO_KEYS
        }
    if isinstance(value, list):
        return [_observed_assertion_value(item) for item in value]
    return value


def _observed_assertion_payload(step_outputs: dict[str, Any]) -> dict[str, Any]:
    observed = {
        step_id: _observed_assertion_value(output)
        for step_id, output in dict(step_outputs or {}).items()
        if isinstance(output, dict)
    }
    if not observed:
        return {}
    first_output = next(iter(observed.values()))
    if isinstance(first_output, dict):
        return {**observed, **first_output}
    return observed


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _unique_preserve_order(values: list[Any]) -> list[Any]:
    seen = set()
    out = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _strength_rank(level: str | None) -> int:
    mapping = {"baseline": 0, "strict": 1, "maximum": 2}
    return mapping.get(str(level or "").strip().lower(), 0)


_EXECUTION_STEP_CATALOG: dict[str, dict[str, str]] = {
    "llm_intercept": {
        "step_type": "intercept",
        "title": "Gateway LLM Intercept",
        "actor": "gateway",
        "target_surface": "gateway",
        "support_status": "executable_now",
        "support_reason": "Gateway interception is wired and callable.",
    },
    "mcp_authorize": {
        "step_type": "policy_eval",
        "title": "MCP Authorization",
        "actor": "ai_iam",
        "target_surface": "gateway",
        "support_status": "executable_now",
        "support_reason": "MCP authorization path is wired and callable.",
    },
    "shadow_event_ingest": {
        "step_type": "ingest",
        "title": "Shadow Event Ingest",
        "actor": "monitoring",
        "target_surface": "monitoring",
        "support_status": "executable_now",
        "support_reason": "Shadow ingest service is available in-process.",
    },
    "monitoring_signal": {
        "step_type": "ingest",
        "title": "Monitoring Signal Ingest",
        "actor": "monitoring",
        "target_surface": "monitoring",
        "support_status": "executable_now",
        "support_reason": "Monitoring ingest service is available in-process.",
    },
    "auditor_snapshot": {
        "step_type": "evaluate",
        "title": "Auditor Snapshot",
        "actor": "auditor",
        "target_surface": "auditor",
        "support_status": "executable_now",
        "support_reason": "Auditor snapshot creation is available in-process.",
    },
    "browser_navigate": {
        "step_type": "navigate",
        "title": "Browser Navigate",
        "actor": "browser_automation",
        "target_surface": "browser",
        "support_status": "not_yet_executable",
        "support_reason": "No browser automation runner is wired into simulation execution yet.",
    },
    "browser_prompt_inject": {
        "step_type": "inject_prompt",
        "title": "Browser Prompt Injection",
        "actor": "browser_automation",
        "target_surface": "browser",
        "support_status": "not_yet_executable",
        "support_reason": "No browser automation runner is wired into simulation execution yet.",
    },
    "browser_upload_file": {
        "step_type": "upload_file",
        "title": "Browser File Upload",
        "actor": "browser_automation",
        "target_surface": "browser",
        "support_status": "not_yet_executable",
        "support_reason": "No browser file-upload automation runner is wired yet.",
    },
    "connector_action": {
        "step_type": "connector_action",
        "title": "Connector Action",
        "actor": "connector",
        "target_surface": "connector",
        "support_status": "not_yet_executable",
        "support_reason": "Connector simulation executor is not implemented yet.",
    },
    "api_gateway_call": {
        "step_type": "api_call",
        "title": "API Gateway Call",
        "actor": "gateway",
        "target_surface": "api",
        "support_status": "not_yet_executable",
        "support_reason": "Dedicated API attack runner is not implemented yet.",
    },
}


def _safe_json_ref(payload: Any, max_len: int = 4000) -> dict[str, Any]:
    if isinstance(payload, dict):
        output: dict[str, Any] = {}
        for key, value in payload.items():
            text = str(value)
            output[str(key)] = text[:max_len]
        return output
    if isinstance(payload, list):
        return {"items": [str(item)[:512] for item in payload[:32]], "count": len(payload)}
    if payload is None:
        return {}
    return {"value": str(payload)[:max_len]}


def _step_execution_profile(kind: str, step_id: str) -> dict[str, str]:
    return step_execution_profile_orchestrator(kind, step_id)


def build_execution_support_matrix(dsl: dict[str, Any]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for index, step in enumerate(dsl.get("steps", []), start=1):
        step_id = str(step.get("step_id") or f"step_{index}")
        kind = str(step.get("kind") or "").strip()
        profile = step_execution_profile_orchestrator(kind, step_id)
        matrix.append(
            {
                "step_id": step_id,
                "step_order": index,
                "step_kind": kind or "unknown",
                "step_type": profile["step_type"],
                "target_surface": profile["target_surface"],
                "support_status": profile["support_status"],
                "support_reason": profile["support_reason"],
            }
        )
    return matrix


def _overall_execution_status(matrix: list[dict[str, Any]]) -> str:
    return overall_execution_status_orchestrator(matrix)


def _extract_control_refs(step_output: dict[str, Any]) -> list[str]:
    controls: list[str] = []
    for item in (step_output.get("controls_impacted") or []):
        if not isinstance(item, dict):
            continue
        control_id = str(item.get("control_id") or "").strip()
        if control_id:
            controls.append(control_id)
    for item in (step_output.get("triggered_controls") or []):
        control_id = str(item or "").strip()
        if control_id:
            controls.append(control_id)
    browser_eval = step_output.get("browser_interaction_eval")
    if isinstance(browser_eval, dict):
        for item in (browser_eval.get("triggered_controls") or []):
            control_id = str(item or "").strip()
            if control_id:
                controls.append(control_id)
    control_decision = step_output.get("control_decision")
    if isinstance(control_decision, dict):
        for item in (control_decision.get("triggered_controls") or []):
            control_id = str(item or "").strip()
            if control_id:
                controls.append(control_id)
    return _unique_preserve_order(controls)


def _extract_decision_ref(step_output: dict[str, Any]) -> dict[str, Any]:
    if "final_decision" in step_output:
        return {
            "decision": step_output.get("final_decision"),
            "event_id": step_output.get("event_id"),
            "policy_version_id": step_output.get("policy_version_id"),
            "platform_mode": step_output.get("platform_mode"),
        }
    if "decision" in step_output:
        return {
            "decision": step_output.get("decision"),
            "event_id": step_output.get("event_id"),
            "reason": step_output.get("reason"),
            "policy_version_id": step_output.get("policy_version_id"),
            "platform_mode": step_output.get("platform_mode"),
        }
    browser_eval = step_output.get("browser_interaction_eval")
    if isinstance(browser_eval, dict) and "decision" in browser_eval:
        return {
            "decision": browser_eval.get("decision"),
            "event_id": browser_eval.get("event_id") or browser_eval.get("runtime_event_id"),
            "reason": (browser_eval.get("reason_codes") or [""])[0] if isinstance(browser_eval.get("reason_codes"), list) else browser_eval.get("reason"),
            "policy_version_id": browser_eval.get("policy_version"),
            "platform_mode": browser_eval.get("platform_mode"),
        }
    return {}


def _decision_rank(decision: str | None) -> int:
    token = str(decision or "").strip().lower()
    rank_map = {
        "deny": 100,
        "block": 95,
        "modify": 80,
        "redact": 80,
        "hold_for_approval": 75,
        "require_approval": 75,
        "step_up": 70,
        "warn": 55,
        "allow_with_warning": 55,
        "defer": 40,
        "allow": 10,
    }
    return rank_map.get(token, 0)


def _dominant_decision(decisions: list[str]) -> str:
    normalized = [str(item).strip().lower() for item in decisions if str(item).strip()]
    if not normalized:
        return "unknown"
    return sorted(normalized, key=lambda item: _decision_rank(item), reverse=True)[0]


def _decision_matches_expected(*, expected: str | None, actual: str | None) -> bool:
    exp = str(expected or "").strip().lower()
    act = str(actual or "").strip().lower()
    if not exp:
        return True
    if exp in {"block", "deny"}:
        return act in {"block", "deny"}
    if exp in {"modify"}:
        return act in {"modify", "redact"}
    if exp in {"allow_with_warning", "warn"}:
        return act in {"warn", "allow_with_warning"}
    if exp in {"step_up"}:
        return act in {"step_up", "hold_for_approval", "require_approval"}
    if exp in {"defer"}:
        return act in {"defer"}
    if exp in {"allow"}:
        return act in {"allow"}
    return exp == act


def _compact_payload(payload: dict[str, Any], *, max_items: int = 6) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for idx, (key, value) in enumerate(dict(payload or {}).items()):
        if idx >= max_items:
            break
        output[str(key)] = str(value)[:320]
    return output


def _normalize_domain_for_simulation(url_or_domain: str | None) -> str:
    token = str(url_or_domain or "").strip()
    if not token:
        return ""
    if "://" not in token:
        return token.lower()
    parsed = urlparse(token)
    return str(parsed.netloc or "").strip().lower()


def _build_browser_interaction_payload_for_step(
    *,
    step_kind: str,
    step_payload: dict[str, Any],
    step_output: dict[str, Any],
    ai_system_id: str,
    run_id: str,
    step_id: str,
    iteration_index: int,
) -> dict[str, Any]:
    target_url = str(step_payload.get("url") or step_output.get("final_url") or step_output.get("target_url") or "").strip()
    domain = _normalize_domain_for_simulation(step_payload.get("domain") or target_url)
    prompt = str(step_payload.get("prompt") or "").strip()
    prompt_preview = prompt[:512] if prompt else "simulation-upload-evaluation"
    file_meta: list[dict[str, Any]] = []
    if step_kind == "browser_upload_file":
        file_path = str(step_output.get("file_path") or step_payload.get("file_path") or "").strip()
        file_meta = [
            {
                "name": str(step_payload.get("file_name") or file_path.rsplit("/", maxsplit=1)[-1] or "simulation_upload"),
                "mime_type": str(step_payload.get("mime_type") or "application/octet-stream"),
                "file_path": file_path,
            }
        ]

    return {
        "correlation_id": f"sim-browser-{run_id}-{step_id}-{iteration_index + 1}",
        "domain": domain or None,
        "url": target_url or None,
        "prompt_preview_redacted": prompt_preview,
        "raw_prompt": prompt or None,
        "file_meta": file_meta,
        "input_signal_types": [
            "simulation_execution",
            f"simulation_step:{step_kind}",
        ],
        "ai_system_id": ai_system_id,
        "browser": "playwright",
        "browser_profile": "simulation",
        "extension_version": "simulation-runtime",
        "endpoint_id": f"simulation-endpoint-{run_id}",
        "source_surface": "browser",
        "platform_mode": "enforce",
    }


def _publish_live_step_update(
    *,
    tenant_id: str,
    run_id: str,
    simulation_id: str,
    live_session_id: str | None,
    step_id: str,
    step_order: int,
    step_type: str,
    title: str,
    status: str,
    target_surface: str,
    target_app: str | None = None,
    reason: str | None = None,
    decision: str | None = None,
    control_ids: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    input_summary: dict[str, Any] | None = None,
    output_summary: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "run_id": run_id,
        "simulation_id": simulation_id,
        "live_session_id": live_session_id,
        "step_id": step_id,
        "step_order": step_order,
        "step_type": step_type,
        "title": title,
        "status": status,
        "target_surface": target_surface,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if target_app:
        payload["target_app"] = target_app
    if reason:
        payload["reason"] = reason
    if decision:
        payload["decision"] = decision
    if control_ids:
        payload["control_ids"] = list(control_ids)
    if evidence_refs:
        payload["evidence_refs"] = list(evidence_refs)
    if input_summary is not None:
        payload["input_summary"] = dict(input_summary)
    if output_summary is not None:
        payload["output_summary"] = dict(output_summary)
    publish_simulation_update(
        tenant_id=tenant_id,
        event_type="simulation.step.updated",
        payload=payload,
    )


def _severity_from_failures(assertions: list[dict[str, Any]], failed_assertions: list[str]) -> str:
    if not failed_assertions:
        return "low"
    severity_rank = {"low": 0, "med": 1, "medium": 1, "high": 2, "critical": 3}
    rank = 0
    failed = {str(item) for item in failed_assertions}
    for assertion in assertions:
        assertion_id = str(assertion.get("assertion_id") or "").strip()
        if assertion_id not in failed:
            continue
        raw = str((assertion.get("on_fail") or {}).get("severity") or "med").strip().lower()
        rank = max(rank, severity_rank.get(raw, 1))
    reverse = {0: "low", 1: "med", 2: "high", 3: "critical"}
    return reverse.get(rank, "med")


def _serialize_execution_step(row: SimulationExecutionStep) -> dict[str, Any]:
    return {
        "id": row.id,
        "simulation_run_id": row.simulation_run_id,
        "iteration_index": int(row.iteration_index),
        "step_id": row.step_id,
        "step_order": int(row.step_order),
        "step_type": row.step_type,
        "title": row.title,
        "status": row.status,
        "timestamp_started": row.timestamp_started.isoformat() if row.timestamp_started else None,
        "timestamp_completed": row.timestamp_completed.isoformat() if row.timestamp_completed else None,
        "actor": row.actor,
        "target_surface": row.target_surface,
        "input_payload_ref": dict(row.input_payload_ref or {}),
        "output_payload_ref": dict(row.output_payload_ref or {}),
        "control_refs": list(row.control_refs or []),
        "decision_ref": dict(row.decision_ref or {}),
        "evidence_refs": list(row.evidence_refs or []),
        "notes": row.notes,
    }


def _snapshot_control_maturity_scores(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_ids: list[str],
) -> dict[str, float]:
    if not control_ids:
        return {}
    rows = db.scalars(
        select(ControlMaturity).where(
            ControlMaturity.tenant_id == tenant_id,
            ControlMaturity.ai_system_id == ai_system_id,
            ControlMaturity.control_id.in_(control_ids),
        )
    ).all()
    return {row.control_id: float(row.maturity_score or 0.0) for row in rows}


def _snapshot_enforcement_strength(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_ids: list[str],
) -> dict[str, dict[str, Any]]:
    if not control_ids:
        return {}

    snapshot: dict[str, dict[str, Any]] = {}
    v1_rows = db.scalars(
        select(ControlGuardianBinding).where(ControlGuardianBinding.control_id.in_(control_ids))
    ).all()
    guardian_ids = sorted({str(row.guardian_contract_id) for row in v1_rows if str(row.guardian_contract_id).strip()})
    for row in v1_rows:
        key = f"v1:{row.control_id}:{row.guardian_contract_id}"
        snapshot[key] = {
            "binding_type": "v1",
            "control_id": str(row.control_id),
            "guardian_contract_id": str(row.guardian_contract_id),
            "strength": str(row.enforcement_strength or "baseline").strip().lower(),
        }

    if guardian_ids:
        v2_rows = db.scalars(
            select(GuardianContractBindingV2).where(
                GuardianContractBindingV2.tenant_id == tenant_id,
                GuardianContractBindingV2.enabled.is_(True),
                GuardianContractBindingV2.guardian_contract_id.in_(guardian_ids),
                or_(
                    GuardianContractBindingV2.ai_system_id.is_(None),
                    GuardianContractBindingV2.ai_system_id == ai_system_id,
                ),
            )
        ).all()
        for row in v2_rows:
            key = f"v2:{row.id}"
            snapshot[key] = {
                "binding_type": "v2",
                "binding_id": str(row.id),
                "control_id": "n/a",
                "guardian_contract_id": str(row.guardian_contract_id),
                "strength": str(row.enforcement_strength or "baseline").strip().lower(),
            }
    return snapshot


def _compute_control_maturity_delta(
    *,
    before_scores: dict[str, float],
    after_scores: dict[str, float],
    control_ids: list[str],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for control_id in _unique_preserve_order([str(item) for item in control_ids if str(item).strip()]):
        before = float(before_scores.get(control_id, 0.0))
        after = float(after_scores.get(control_id, 0.0))
        output.append(
            {
                "control_id": control_id,
                "before": round(before, 6),
                "after": round(after, 6),
                "delta": round(after - before, 6),
            }
        )
    return output


def _compute_enforcement_strictness_delta(
    *,
    before_snapshot: dict[str, dict[str, Any]],
    after_snapshot: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    keys = sorted(set(before_snapshot.keys()) | set(after_snapshot.keys()))
    for key in keys:
        before = before_snapshot.get(key, {})
        after = after_snapshot.get(key, {})
        before_strength = str(before.get("strength") or "baseline").strip().lower()
        after_strength = str(after.get("strength") or "baseline").strip().lower()
        if before_strength == after_strength:
            continue
        output.append(
            {
                "binding_key": key,
                "binding_type": str(after.get("binding_type") or before.get("binding_type") or "v1"),
                "control_id": str(after.get("control_id") or before.get("control_id") or "n/a"),
                "guardian_contract_id": str(after.get("guardian_contract_id") or before.get("guardian_contract_id") or ""),
                "before": before_strength,
                "after": after_strength,
                "delta": _strength_rank(after_strength) - _strength_rank(before_strength),
            }
        )
    return output


def _evaluate_evidence_emission_requirements(
    db: Session,
    *,
    tenant_id: str,
    evidence_node_ids: list[str],
    requirements: dict[str, Any],
) -> list[str]:
    required_count = _as_int(requirements.get("min_evidence_nodes"), 0)
    required_signals = [str(item).strip() for item in (requirements.get("required_signal_types") or []) if str(item).strip()]
    failures: list[str] = []

    unique_ids = _unique_preserve_order([str(item).strip() for item in evidence_node_ids if str(item).strip()])
    if len(unique_ids) < max(0, required_count):
        failures.append(
            f"evidence_nodes_below_minimum(required={max(0, required_count)},actual={len(unique_ids)})"
        )

    if required_signals:
        rows = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id.in_(unique_ids) if unique_ids else EvidenceNode.id == "__none__",
            )
        ).all()
        present = {str(row.signal_type or "").strip() for row in rows if str(row.signal_type or "").strip()}
        missing_signals = [signal for signal in required_signals if signal not in present]
        if missing_signals:
            failures.append(f"missing_required_signal_types({','.join(sorted(missing_signals))})")
    return failures


def _normalize_success_criteria(criteria: Any) -> dict[str, Any]:
    base = {
        "required_sim_pass_rate": 0.8,
        "required_evidence_sources": ["telemetry", "simulation", "config"],
        "min_maturity": 3,
    }
    if not isinstance(criteria, dict):
        return base

    normalized = dict(base)
    try:
        normalized["required_sim_pass_rate"] = _clamp01(float(criteria.get("required_sim_pass_rate", base["required_sim_pass_rate"])))
    except (TypeError, ValueError):
        normalized["required_sim_pass_rate"] = base["required_sim_pass_rate"]

    sources = criteria.get("required_evidence_sources")
    if isinstance(sources, list):
        normalized["required_evidence_sources"] = [str(item) for item in sources if str(item).strip()]

    try:
        min_maturity = int(criteria.get("min_maturity", base["min_maturity"]))
    except (TypeError, ValueError):
        min_maturity = base["min_maturity"]
    normalized["min_maturity"] = max(0, min(5, min_maturity))
    return normalized


def _maturity_level_from_pass_rate(pass_rate: float) -> int:
    return max(0, min(5, floor(_clamp01(pass_rate) * 5)))


def _maturity_score_from_level(level: int) -> float:
    return round(max(0, min(5, int(level))) / 5.0, 6)


def _maturity_level_from_score(score: float) -> int:
    normalized = float(score)
    if normalized <= 1.0:
        return _maturity_level_from_pass_rate(normalized)
    return max(0, min(5, floor(normalized)))


def _escalate_guardian_enforcement_strength(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_ids: list[str],
) -> list[dict[str, str]]:
    if not control_ids:
        return []

    strength_map = {
        "baseline": "strict",
        "strict": "maximum",
        "maximum": "maximum",
    }
    rows = db.scalars(
        select(ControlGuardianBinding).where(ControlGuardianBinding.control_id.in_(control_ids))
    ).all()
    if not rows:
        return []

    rows.sort(key=lambda row: (str(row.control_id), str(row.guardian_contract_id)))
    guardian_ids = sorted({str(row.guardian_contract_id) for row in rows if str(row.guardian_contract_id).strip()})
    v2_rows = (
        db.scalars(
            select(GuardianContractBindingV2).where(
                GuardianContractBindingV2.tenant_id == tenant_id,
                GuardianContractBindingV2.enabled.is_(True),
                GuardianContractBindingV2.guardian_contract_id.in_(guardian_ids),
                or_(
                    GuardianContractBindingV2.ai_system_id.is_(None),
                    GuardianContractBindingV2.ai_system_id == ai_system_id,
                ),
            )
        ).all()
        if guardian_ids
        else []
    )
    v2_rows.sort(
        key=lambda row: (
            str(row.guardian_contract_id),
            str(row.ai_system_id or ""),
            str(row.policy_version_id or ""),
            str(row.id),
        )
    )

    guardian_ids_with_v2 = {str(row.guardian_contract_id) for row in v2_rows}
    escalated: list[dict[str, str]] = []
    for row in v2_rows:
        current = str(row.enforcement_strength or "baseline").strip().lower()
        next_strength = strength_map.get(current, current)
        if next_strength == current:
            continue
        row.enforcement_strength = next_strength
        escalated.append(
            {
                "binding_type": "v2",
                "binding_id": str(row.id),
                "control_id": "n/a",
                "guardian_contract_id": str(row.guardian_contract_id),
                "previous_strength": current,
                "new_strength": next_strength,
            }
        )

    for row in rows:
        if str(row.guardian_contract_id) in guardian_ids_with_v2:
            continue
        current = str(row.enforcement_strength or "baseline").strip().lower()
        next_strength = strength_map.get(current, current)
        if next_strength == current:
            continue
        row.enforcement_strength = next_strength
        escalated.append(
            {
                "binding_type": "v1",
                "binding_id": "n/a",
                "control_id": str(row.control_id),
                "guardian_contract_id": str(row.guardian_contract_id),
                "previous_strength": current,
                "new_strength": next_strength,
            }
        )
    return escalated


def _apply_failure_penalty(db: Session, *, tenant_id: str, ai_system_id: str, control_ids: list[str], reason: str) -> None:
    _apply_failure_penalty_with_delta(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=control_ids,
        reason=reason,
        delta=0.1,
    )


def _apply_failure_penalty_with_delta(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_ids: list[str],
    reason: str,
    delta: float,
) -> None:
    query = select(ControlMaturity).where(
        ControlMaturity.tenant_id == tenant_id,
        ControlMaturity.ai_system_id == ai_system_id,
    )
    if control_ids:
        query = query.where(ControlMaturity.control_id.in_(control_ids))
    rows = db.scalars(query).all()
    penalty = max(0.0, float(delta or 0.1))

    for row in rows:
        row.maturity_score = max(0.0, row.maturity_score - penalty)
        hist = ControlMaturityHistory(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_id=row.control_id,
            technical_enforcement_score=row.technical_enforcement_score,
            simulation_pass_rate=row.simulation_pass_rate,
            coverage_score=row.coverage_score,
            maturity_score=row.maturity_score,
            status=row.status,
            confidence_score=row.confidence_score,
            confidence_inputs=row.confidence_inputs,
            reason=reason,
        )
        db.add(hist)


def _count_failed_simulation_runs(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    simulation_id: str,
    exclude_run_id: str | None = None,
) -> int:
    rows = db.scalars(
        select(SimulationRun).where(
            SimulationRun.tenant_id == tenant_id,
            SimulationRun.ai_system_id == ai_system_id,
            SimulationRun.simulation_id == simulation_id,
        )
    ).all()
    total = 0
    excluded = str(exclude_run_id or "").strip()
    for row in rows:
        if excluded and str(row.id) == excluded:
            continue
        result = str((row.results or {}).get("result") or "fail").strip().lower()
        if result != "pass":
            total += 1
    return total


def _is_high_risk_simulation_failure(*, ai_system: AISystem, dsl: dict[str, Any]) -> bool:
    risk_tier = str(ai_system.risk_tier or "").strip().upper()
    category = str(dsl.get("category") or "").strip().lower()
    high_risk_categories = {
        "injection",
        "leakage",
        "identity_abuse",
        "rag_poisoning",
        "resource_abuse",
        "output_safety",
        "agent_misuse",
        "output_injection",
    }
    return risk_tier in {"HIGH", "CRITICAL", "RESTRICTED", "PROHIBITED"} or category in high_risk_categories


def _apply_simulation_failure_deployment_block(
    db: Session,
    *,
    tenant_id: str,
    ai_system: AISystem,
    simulation_id: str,
    run_id: str,
    repeated_failures: int,
    related_control_ids: list[str],
    actor_user_id: str | None,
) -> dict[str, Any]:
    before = {
        "status": str(ai_system.status or ""),
        "risk_tier": str(ai_system.risk_tier or ""),
        "metadata_json": dict(ai_system.metadata_json or {}),
    }

    ai_system.status = "restricted"
    current_risk = str(ai_system.risk_tier or "").strip().upper()
    ai_system.risk_tier = "CRITICAL" if current_risk not in {"CRITICAL", "PROHIBITED"} else current_risk
    metadata = dict(ai_system.metadata_json or {})
    metadata["deployment_blocked"] = True
    metadata["deployment_block_reason"] = "repeated_critical_simulation_failures"
    metadata["deployment_blocked_at"] = datetime.now(timezone.utc).isoformat()
    metadata["deployment_blocked_by_run_id"] = run_id
    metadata["deployment_blocked_by_simulation_id"] = simulation_id
    metadata["simulation_failure_repeat_count"] = max(int(metadata.get("simulation_failure_repeat_count") or 0), int(repeated_failures))
    metadata["requires_reapproval"] = True
    metadata["governance_state"] = "REVIEW"
    metadata["lifecycle_state"] = "RESTRICTED"
    metadata["remediation_required"] = True
    metadata["related_control_ids"] = sorted(
        {
            *[str(item).strip() for item in (metadata.get("related_control_ids") or []) if str(item).strip()],
            *[str(control_id).strip() for control_id in (related_control_ids or []) if str(control_id).strip()],
        }
    )
    ai_system.metadata_json = metadata
    db.flush()

    payload = {
        "ai_system_id": ai_system.id,
        "simulation_id": simulation_id,
        "simulation_run_id": run_id,
        "repeated_failures": repeated_failures,
        "related_control_ids": list(related_control_ids),
        "before": before,
        "after": {
            "status": ai_system.status,
            "risk_tier": ai_system.risk_tier,
            "metadata_json": dict(ai_system.metadata_json or {}),
        },
    }
    audit_row = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="system" if actor_user_id is None else "human",
        action="simulation.deployment.blocked",
        resource_type="ai_system",
        resource_id=ai_system.id,
        payload=payload,
    )
    evidence_row = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="simulation_failure_escalation",
        signal_type="simulation.deployment.blocked",
        label=f"Deployment blocked for {ai_system.id} after repeated critical simulation failures",
        payload={**payload, "audit_log_id": audit_row.id},
    )
    return {
        "blocked": True,
        "audit_log_id": audit_row.id,
        "evidence_node_id": evidence_row.id,
        "status_after": ai_system.status,
        "risk_tier_after": ai_system.risk_tier,
    }


def _apply_control_success_criteria(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_ids: list[str],
    pass_rate: float,
    simulation_id: str,
    actor_user_id: str | None,
) -> None:
    normalized_control_ids = _unique_preserve_order([str(control_id) for control_id in control_ids if str(control_id).strip()])
    if not normalized_control_ids:
        return

    controls = db.scalars(
        select(Control).where(
            Control.id.in_(normalized_control_ids),
            Control.tenant_id == tenant_id,
        )
    ).all()
    control_by_id = {row.id: row for row in controls}

    for control_id in normalized_control_ids:
        control = control_by_id.get(control_id)
        if control is None:
            continue

        criteria = _normalize_success_criteria(control.success_criteria)
        required_rate = float(criteria["required_sim_pass_rate"])
        if pass_rate >= required_rate:
            continue

        computed_level = _maturity_level_from_pass_rate(pass_rate)
        maturity = db.scalar(
            select(ControlMaturity).where(
                ControlMaturity.tenant_id == tenant_id,
                ControlMaturity.ai_system_id == ai_system_id,
                ControlMaturity.control_id == control_id,
            )
        )
        previous_score = maturity.maturity_score if maturity else 1.0
        previous_level = _maturity_level_from_score(previous_score)
        applied_level = min(previous_level, computed_level)
        applied_score = _maturity_score_from_level(applied_level)

        if maturity is None:
            maturity = ControlMaturity(
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                control_id=control_id,
                technical_enforcement_score=0.0,
                simulation_pass_rate=pass_rate,
                coverage_score=0.0,
                maturity_score=applied_score,
                status="needs_review",
                confidence_score=0.0,
                confidence_inputs={"source": "control_success_criteria"},
            )
            db.add(maturity)
        else:
            maturity.simulation_pass_rate = pass_rate
            maturity.maturity_score = min(maturity.maturity_score, applied_score)
            if maturity.status != "contested":
                maturity.status = "needs_review"
            maturity.updated_at = datetime.now(timezone.utc)

        history = ControlMaturityHistory(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_id=control_id,
            technical_enforcement_score=maturity.technical_enforcement_score,
            simulation_pass_rate=maturity.simulation_pass_rate,
            coverage_score=maturity.coverage_score,
            maturity_score=maturity.maturity_score,
            status=maturity.status,
            confidence_score=maturity.confidence_score,
            confidence_inputs=maturity.confidence_inputs,
            reason=f"control_success_criteria:{simulation_id}",
        )
        db.add(history)

        escalated_bindings = _escalate_guardian_enforcement_strength(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_ids=[control_id],
        )
        degradation_payload = {
            "ai_system_id": ai_system_id,
            "simulation_id": simulation_id,
            "required_sim_pass_rate": required_rate,
            "actual_pass_rate": round(pass_rate, 6),
            "new_maturity": computed_level,
            "computed_new_maturity": computed_level,
            "applied_new_maturity": applied_level,
            "applied_new_maturity_score": round(maturity.maturity_score, 6),
            "previous_maturity_score": round(previous_score, 6),
            "required_evidence_sources": criteria.get("required_evidence_sources", []),
            "min_maturity": criteria.get("min_maturity"),
            "escalated_guardian_bindings": escalated_bindings,
        }
        audit_row = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="system" if actor_user_id is None else "human",
            action="control.degraded",
            resource_type="control",
            resource_id=control_id,
            payload=degradation_payload,
        )
        create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="control_degradation",
            signal_type="control.degraded",
            label=f"Control {control_id} degraded",
            payload={
                **degradation_payload,
                "audit_log_id": audit_row.id,
                "control_id": control_id,
            },
        )


_LLM_INTERCEPT_OPTIONAL_FIELDS = (
    "response_text",
    "provider",
    "model_name",
    "model_version",
    "tool_name",
    "tool_category",
    "api_endpoint",
    "data_source",
    "chain_depth",
    "parent_agent_id",
)
_MCP_AUTHORIZE_OPTIONAL_FIELDS = (
    "tool_name",
    "tool_category",
    "api_endpoint",
    "provider",
    "model_name",
    "session_id",
    "session_context",
    "initiating_user_id",
    "parent_agent_id",
    "chain_id",
)
_AGENT_ACTION_PAYLOAD_FIELDS = {
    "agent_id",
    "capability_token",
    "action_type",
    "tool_name",
    "target_resource",
    "input_context",
    "chain_depth",
    "chain_id",
    "parent_agent_id",
    "platform_mode",
    "ai_system_id",
}


def _optional_step_fields(payload: dict[str, Any], names: tuple[str, ...]) -> dict[str, Any]:
    """Optional gateway arguments a step may carry (provider, endpoint, session...); absent or empty ones are left out."""

    out: dict[str, Any] = {}
    for name in names:
        value = (payload or {}).get(name)
        if value is None or value == "" or value == {} or value == []:
            continue
        if name == "chain_depth":
            try:
                value = int(value)
            except (TypeError, ValueError):
                continue
        out[name] = value
    return out


def _execute_simulation_iteration(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    dsl: dict[str, Any],
    inputs_used: dict[str, Any],
    actor_user_id: str | None,
    run_id: str,
    simulation_id: str,
    iteration_index: int,
    stochastic_mode: bool,
    live_session_id: str | None,
) -> dict[str, Any]:
    step_outputs: dict[str, Any] = {}
    evidence_nodes: list[str] = []
    linked_events: list[str] = []
    step_trace_ids: list[str] = []
    step_traces: list[dict[str, Any]] = []
    non_executable_steps: list[dict[str, Any]] = []
    triggered_controls: list[str] = []
    observed_decisions: list[str] = []
    steps = list(dsl.get("steps", []))

    for step_order, step in enumerate(steps, start=1):
        step_id = str(step.get("step_id") or f"step_{step_order}")
        bindings = step.get("variable_bindings", {})
        variables = {
            **{f"input.{k}": v for k, v in inputs_used.items()},
            **{k: _resolve_binding(bindings, k) for k in bindings.keys()},
            "ai_system_id": ai_system_id,
            "run_id": run_id,
            "iteration.index": iteration_index + 1,
            # Test card numbers and files holding one, made only now: a stored definition never holds a full PAN.
            **_synthetic_variables(),
        }
        payload = _substitute(step.get("payload_template", {}), variables)
        kind = str(step.get("kind") or "").strip()
        profile = step_execution_profile_orchestrator(kind, step_id)

        step_row = SimulationExecutionStep(
            tenant_id=tenant_id,
            simulation_run_id=run_id,
            iteration_index=iteration_index + 1,
            step_id=step_id,
            step_order=step_order,
            step_type=profile["step_type"],
            title=profile["title"],
            status="running",
            timestamp_started=datetime.now(timezone.utc),
            actor=profile["actor"],
            target_surface=profile["target_surface"],
            input_payload_ref=_safe_json_ref(payload),
            output_payload_ref={},
            control_refs=[],
            decision_ref={},
            evidence_refs=[],
            notes="",
        )
        db.add(step_row)
        db.flush()
        step_trace_ids.append(step_row.id)
        publish_simulation_update(
            tenant_id=tenant_id,
            event_type="simulation.step.updated",
            payload={
                "run_id": run_id,
                "simulation_id": simulation_id,
                "live_session_id": live_session_id,
                "step_id": step_id,
                "step_order": step_order,
                "step_type": profile["step_type"],
                "title": profile["title"],
                "status": "running",
                "target_surface": profile["target_surface"],
                "target_app": str(payload.get("url") or payload.get("domain") or payload.get("api_endpoint") or "").strip() or None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "input_summary": _compact_payload(payload),
            },
        )

        if profile["support_status"] != "executable_now":
            step_output = {
                "execution_status": "not_yet_executable",
                "reason": profile["support_reason"],
                "step_kind": kind or "unknown",
            }
            step_outputs[step_id] = step_output
            non_executable_steps.append(
                {
                    "step_id": step_id,
                    "step_order": step_order,
                    "step_kind": kind or "unknown",
                    "support_reason": profile["support_reason"],
                }
            )
            step_row.status = "skipped"
            step_row.timestamp_completed = datetime.now(timezone.utc)
            step_row.output_payload_ref = _safe_json_ref(step_output)
            step_row.notes = profile["support_reason"]
            step_traces.append(_serialize_execution_step(step_row))
            publish_simulation_update(
                tenant_id=tenant_id,
                event_type="simulation.step.updated",
                payload={
                    "run_id": run_id,
                    "simulation_id": simulation_id,
                    "live_session_id": live_session_id,
                    "step_id": step_id,
                    "step_order": step_order,
                    "step_type": profile["step_type"],
                    "title": profile["title"],
                    "status": "skipped",
                    "target_surface": profile["target_surface"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": profile["support_reason"],
                    "output_summary": _compact_payload(step_output),
                },
            )
            continue

        try:
            step_output: dict[str, Any]
            if kind == "llm_intercept":
                base_req_id = str(payload.get("request_id", f"sim-{run_id}-{step_id}"))
                req_id = _simulation_request_id(run_id=run_id, step_id=step_id, base_request_id=base_req_id, iteration=iteration_index + 1 if stochastic_mode else None)

                res = llm_intercept(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    actor_type=payload.get("actor_type", "system"),
                    actor_id=payload.get("actor_id", "simulator"),
                    request_id=req_id,
                    prompt=payload.get("prompt", inputs_used.get("prompt", "")),
                    context_summary=payload.get("context_summary", inputs_used.get("rag_context", "")),
                    attachments_meta=payload.get("attachments_meta", []),
                    tool_output=payload.get("tool_output", inputs_used.get("tool_output")),
                    audit_actor_user_id=actor_user_id,
                    **_optional_step_fields(payload, _LLM_INTERCEPT_OPTIONAL_FIELDS),
                )
                step_output = res
                evidence_nodes.extend(res.get("evidence_nodes_created", []))
                linked_events.append(res.get("event_id"))

            elif kind == "mcp_authorize":
                base_req_id = str(payload.get("request_id", f"sim-{run_id}-{step_id}"))
                req_id = _simulation_request_id(run_id=run_id, step_id=step_id, base_request_id=base_req_id, iteration=iteration_index + 1 if stochastic_mode else None)

                res = mcp_authorize(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    actor_id=payload.get("actor_id", "simulator-agent"),
                    capability_token=payload.get("capability_token", inputs_used.get("capability_token", "missing-token")),
                    action=payload.get("action", inputs_used.get("agent_action", "unknown")),
                    resource=payload.get("resource", "simulation"),
                    chain_depth=int(payload.get("chain_depth", 0)),
                    request_id=req_id,
                    audit_actor_user_id=actor_user_id,
                    **_optional_step_fields(payload, _MCP_AUTHORIZE_OPTIONAL_FIELDS),
                )
                step_output = res
                evidence_nodes.extend(res.get("evidence_nodes_created", []))
                linked_events.append(res.get("event_id"))

            elif kind == "agent_action_intercept":
                agent_payload = {
                    key: value
                    for key, value in dict(payload or {}).items()
                    if key in _AGENT_ACTION_PAYLOAD_FIELDS and value not in (None, "")
                }
                agent_payload.setdefault("ai_system_id", ai_system_id)
                agent_payload["correlation_id"] = _simulation_request_id(
                    run_id=run_id,
                    step_id=step_id,
                    base_request_id=str(payload.get("request_id") or step_id),
                    iteration=iteration_index + 1,
                )
                res = evaluate_agent_action_and_record(
                    db,
                    tenant_id=tenant_id,
                    actor_user_id=actor_user_id,
                    payload=agent_payload,
                )
                step_output = dict(res)
                step_output["final_decision"] = str(res.get("decision") or "").strip().lower() or None
                step_output["reason"] = res.get("reason_code")
                evidence_id = str(res.get("evidence_node_id") or "").strip()
                if evidence_id:
                    evidence_nodes.append(evidence_id)
                runtime_event_id = str(res.get("runtime_event_id") or "").strip()
                if runtime_event_id:
                    linked_events.append(runtime_event_id)

            elif kind == "browser_interaction_eval":
                # The decision the Hawk extension asks the API for, evaluated in-process with the payload the
                # extension sends. It proves the server-side browser control, not the live Chromium capture leg.
                browser_payload = _build_browser_interaction_payload_for_step(
                    step_kind="browser_prompt_inject",
                    step_payload=dict(payload or {}),
                    step_output={},
                    ai_system_id=ai_system_id,
                    run_id=run_id,
                    step_id=step_id,
                    iteration_index=iteration_index,
                )
                file_meta = [item for item in (payload.get("file_meta") or []) if isinstance(item, dict)]
                if file_meta:
                    browser_payload["file_meta"] = file_meta
                    if not str(payload.get("prompt") or "").strip():
                        browser_payload["prompt_preview_redacted"] = "simulation-upload-evaluation"
                res = evaluate_browser_interaction_and_record(
                    db,
                    tenant_id=tenant_id,
                    actor_user_id=actor_user_id,
                    payload=browser_payload,
                )
                step_output = dict(res)
                step_output["final_decision"] = str(res.get("decision") or "").strip().lower() or None
                reason_codes = res.get("reason_codes")
                step_output["reason"] = (reason_codes[0] if isinstance(reason_codes, list) and reason_codes else None)
                evidence_id = str(res.get("evidence_node_id") or "").strip()
                if evidence_id:
                    evidence_nodes.append(evidence_id)
                runtime_event_id = str(res.get("runtime_event_id") or "").strip()
                if runtime_event_id:
                    linked_events.append(runtime_event_id)

            elif kind == "shadow_event_ingest":
                signal = ingest_shadow_event(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    event_type=payload.get("event_type", "unknown"),
                    payload=payload,
                    actor_user_id=actor_user_id,
                )
                step_output = {"signal_id": signal.id, "payload": payload}

            elif kind == "monitoring_signal":
                signal = ingest_monitoring_signal(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    signal_type=payload.get("signal_type", "simulation.signal"),
                    severity=payload.get("severity", "low"),
                    payload=payload,
                    actor_user_id=actor_user_id,
                )
                step_output = {"signal_id": signal.id, "payload": payload}

            elif kind == "auditor_snapshot":
                snapshot = create_auditor_snapshot(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    trigger_type="simulation",
                    payload={"simulation_run_id": run_id, "payload": payload},
                    actor_user_id=actor_user_id,
                )
                step_output = {"snapshot_id": snapshot.id, "payload": payload}

            elif kind in {"browser_navigate", "browser_prompt_inject", "browser_upload_file"}:
                step_output = run_browser_step(
                    kind=kind,
                    payload=dict(payload or {}),
                    tenant_id=tenant_id,
                    simulation_run_id=run_id,
                    step_id=step_id,
                    iteration_index=iteration_index + 1,
                )
                if str(step_output.get("execution_status") or "").strip().lower() != "executed":
                    non_executable_steps.append(
                        {
                            "step_id": step_id,
                            "step_order": step_order,
                            "step_kind": kind,
                            "support_reason": str(step_output.get("reason") or "browser executor unavailable"),
                        }
                    )
                    step_row.status = "skipped"
                    step_row.timestamp_completed = datetime.now(timezone.utc)
                    step_row.output_payload_ref = _safe_json_ref(step_output)
                    step_row.notes = str(step_output.get("reason") or "browser executor unavailable")
                    step_outputs[step_id] = step_output
                    step_traces.append(_serialize_execution_step(step_row))
                    publish_simulation_update(
                        tenant_id=tenant_id,
                        event_type="simulation.step.updated",
                        payload={
                            "run_id": run_id,
                            "simulation_id": simulation_id,
                            "live_session_id": live_session_id,
                            "step_id": step_id,
                            "step_order": step_order,
                            "step_type": profile["step_type"],
                            "title": profile["title"],
                            "status": "skipped",
                            "target_surface": profile["target_surface"],
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "reason": str(step_output.get("reason") or "browser executor unavailable"),
                            "output_summary": _compact_payload(step_output),
                        },
                    )
                    continue

                # Browser prompt/file steps must pass through the same extension-backed
                # interaction evaluation service used by runtime browser traffic.
                if kind in {"browser_prompt_inject", "browser_upload_file"}:
                    target_app = str(step_output.get("final_url") or step_output.get("target_url") or payload.get("url") or "").strip() or None
                    interaction_step_order = (step_order * 100) + 10
                    evaluation_step_order = (step_order * 100) + 20
                    decision_step_order = (step_order * 100) + 30

                    _publish_live_step_update(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        simulation_id=simulation_id,
                        live_session_id=live_session_id,
                        step_id=f"{step_id}.intercept",
                        step_order=interaction_step_order,
                        step_type="intercept",
                        title="Hawk AI Interception Triggered",
                        status="running",
                        target_surface="browser",
                        target_app=target_app,
                        input_summary=_compact_payload(step_output),
                    )
                    browser_eval_payload = _build_browser_interaction_payload_for_step(
                        step_kind=kind,
                        step_payload=dict(payload or {}),
                        step_output=dict(step_output or {}),
                        ai_system_id=ai_system_id,
                        run_id=run_id,
                        step_id=step_id,
                        iteration_index=iteration_index,
                    )
                    browser_eval = evaluate_browser_interaction_and_record(
                        db,
                        tenant_id=tenant_id,
                        actor_user_id=actor_user_id,
                        payload=browser_eval_payload,
                    )
                    browser_controls = [
                        str(item).strip()
                        for item in (
                            browser_eval.get("triggered_controls")
                            or (browser_eval.get("control_decision") or {}).get("triggered_controls")
                            or []
                        )
                        if str(item).strip()
                    ]
                    browser_decision = str(browser_eval.get("decision") or "").strip().lower()
                    browser_reason = ""
                    reason_codes = browser_eval.get("reason_codes")
                    if isinstance(reason_codes, list) and reason_codes:
                        browser_reason = str(reason_codes[0] or "").strip()
                    browser_reason = browser_reason or str(browser_eval.get("control_decision_reasoning") or "").strip()
                    browser_evidence_refs = _unique_preserve_order(
                        [
                            str(browser_eval.get("evidence_node_id") or "").strip(),
                            str(browser_eval.get("runtime_event_id") or "").strip(),
                        ]
                    )
                    _publish_live_step_update(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        simulation_id=simulation_id,
                        live_session_id=live_session_id,
                        step_id=f"{step_id}.intercept",
                        step_order=interaction_step_order,
                        step_type="intercept",
                        title="Hawk AI Interception Triggered",
                        status="completed",
                        target_surface="browser",
                        target_app=target_app,
                        decision=browser_decision or None,
                        reason=browser_reason or None,
                        control_ids=browser_controls,
                        evidence_refs=browser_evidence_refs,
                        output_summary=_compact_payload(browser_eval),
                    )

                    _publish_live_step_update(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        simulation_id=simulation_id,
                        live_session_id=live_session_id,
                        step_id=f"{step_id}.policy_eval",
                        step_order=evaluation_step_order,
                        step_type="policy_eval",
                        title="Evaluating Controls",
                        status="running",
                        target_surface="browser",
                        target_app=target_app,
                    )
                    _publish_live_step_update(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        simulation_id=simulation_id,
                        live_session_id=live_session_id,
                        step_id=f"{step_id}.policy_eval",
                        step_order=evaluation_step_order,
                        step_type="policy_eval",
                        title="Evaluating Controls",
                        status="completed",
                        target_surface="browser",
                        target_app=target_app,
                        control_ids=browser_controls,
                        reason=browser_reason or None,
                        output_summary={
                            "triggered_controls": ", ".join(browser_controls) if browser_controls else "none",
                            "total_risk": str(browser_eval.get("control_decision_total_risk") or ""),
                            "dominant_control": str(browser_eval.get("dominant_control") or ""),
                        },
                    )

                    decision_title = "Allowed with Monitoring"
                    if browser_decision in {"block", "deny"}:
                        decision_title = "Blocked by Hawk AI"
                    elif browser_decision in {"warn", "allow_with_warning", "step_up", "hold_for_approval"}:
                        decision_title = "Policy Action Required"
                    _publish_live_step_update(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        simulation_id=simulation_id,
                        live_session_id=live_session_id,
                        step_id=f"{step_id}.decision",
                        step_order=decision_step_order,
                        step_type="enforcement",
                        title=decision_title,
                        status="completed",
                        target_surface="browser",
                        target_app=target_app,
                        decision=browser_decision or None,
                        reason=browser_reason or None,
                        control_ids=browser_controls,
                        evidence_refs=browser_evidence_refs,
                        output_summary={
                            "decision": browser_decision or "unknown",
                            "policy_version": str(browser_eval.get("policy_version") or ""),
                            "reason_codes": ", ".join(reason_codes) if isinstance(reason_codes, list) else "",
                        },
                    )

                    # Link browser-eval evidence/runtime to run-level aggregates.
                    runtime_event_id = str(browser_eval.get("runtime_event_id") or "").strip()
                    evidence_node_id = str(browser_eval.get("evidence_node_id") or "").strip()
                    if runtime_event_id:
                        linked_events.append(runtime_event_id)
                    if evidence_node_id:
                        evidence_nodes.append(evidence_node_id)
                    step_output["browser_interaction_eval"] = browser_eval
                    step_output["decision"] = browser_decision or step_output.get("decision")
                    step_output["final_decision"] = browser_decision or step_output.get("final_decision")
                    step_output["reason"] = browser_reason or step_output.get("reason")

            else:
                step_output = {
                    "execution_status": "not_yet_executable",
                    "reason": f"Step kind '{kind}' has no executor implementation.",
                    "step_kind": kind,
                }
                non_executable_steps.append(
                    {
                        "step_id": step_id,
                        "step_order": step_order,
                        "step_kind": kind,
                        "support_reason": str(step_output.get("reason") or ""),
                    }
                )
                step_row.status = "skipped"
                step_row.timestamp_completed = datetime.now(timezone.utc)
                step_row.output_payload_ref = _safe_json_ref(step_output)
                step_row.notes = str(step_output.get("reason") or "")
                step_outputs[step_id] = step_output
                step_traces.append(_serialize_execution_step(step_row))
                publish_simulation_update(
                    tenant_id=tenant_id,
                    event_type="simulation.step.updated",
                    payload={
                        "run_id": run_id,
                        "simulation_id": simulation_id,
                        "live_session_id": live_session_id,
                        "step_id": step_id,
                        "step_order": step_order,
                        "step_type": profile["step_type"],
                        "title": profile["title"],
                        "status": "skipped",
                        "target_surface": profile["target_surface"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "reason": str(step_output.get("reason") or ""),
                        "output_summary": _compact_payload(step_output),
                    },
                )
                continue

            step_outputs[step_id] = step_output
            step_output["step_id"] = step_id
            step_output["iteration_index"] = iteration_index + 1
            step_output.setdefault("execution_status", "executed")
            control_refs = _extract_control_refs(step_output)
            triggered_controls.extend(control_refs)
            decision_ref = _extract_decision_ref(step_output)
            decision_value = str(decision_ref.get("decision") or "").strip()
            if decision_value:
                observed_decisions.append(decision_value)
            evidence_refs = _unique_preserve_order(
                [
                    *[str(item).strip() for item in (step_output.get("evidence_nodes_created") or []) if str(item).strip()],
                    *[str(item).strip() for item in (step_output.get("evidence_node_ids") or []) if str(item).strip()],
                    str(step_output.get("evidence_node_id") or "").strip(),
                ]
            )

            step_row.output_payload_ref = _safe_json_ref(step_output)
            step_row.control_refs = control_refs
            step_row.decision_ref = decision_ref
            step_row.evidence_refs = evidence_refs
            step_row.status = "completed"
            step_row.timestamp_completed = datetime.now(timezone.utc)
            step_row.notes = "executed"
            step_traces.append(_serialize_execution_step(step_row))
            publish_simulation_update(
                tenant_id=tenant_id,
                event_type="simulation.step.updated",
                payload={
                    "run_id": run_id,
                    "simulation_id": simulation_id,
                    "live_session_id": live_session_id,
                    "step_id": step_id,
                    "step_order": step_order,
                    "step_type": profile["step_type"],
                    "title": profile["title"],
                    "status": "completed",
                    "target_surface": profile["target_surface"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "control_ids": control_refs,
                    "decision": decision_value or None,
                    "reason": str(step_output.get("reason") or step_output.get("evaluator_reasoning") or "").strip() or None,
                    "evidence_refs": evidence_refs,
                    "output_summary": _compact_payload(step_output),
                },
            )
        except Exception as exc:
            step_row.output_payload_ref = {"error": str(exc)}
            step_row.status = "failed"
            step_row.timestamp_completed = datetime.now(timezone.utc)
            step_row.notes = f"Execution failed: {exc}"
            step_traces.append(_serialize_execution_step(step_row))
            publish_simulation_update(
                tenant_id=tenant_id,
                event_type="simulation.step.updated",
                payload={
                    "run_id": run_id,
                    "simulation_id": simulation_id,
                    "live_session_id": live_session_id,
                    "step_id": step_id,
                    "step_order": step_order,
                    "step_type": profile["step_type"],
                    "title": profile["title"],
                    "status": "failed",
                    "target_surface": profile["target_surface"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": str(exc),
                },
            )
            raise

    assertion_failures: list[str] = []
    assertion_payload = _observed_assertion_payload(step_outputs)
    for assertion in dsl.get("assertions", []):
        check = assertion.get("check", {})
        field = check.get("field", "")
        actual = _read_path(assertion_payload, field)
        ok = _check_assertion(check.get("operator", "equals"), actual, check.get("value"))
        if not ok:
            assertion_failures.append(assertion.get("assertion_id", "unknown"))
    has_unavailable = bool(non_executable_steps)
    all_unavailable = bool(steps) and len(non_executable_steps) == len(steps)
    evaluated = evaluate_iteration_outcome(
        assertions=list(dsl.get("assertions") or []),
        failed_assertions=assertion_failures,
        has_unavailable_steps=has_unavailable,
        all_steps_unavailable=all_unavailable,
    )
    result = str(evaluated["result"])

    expected_controls = _unique_preserve_order([str(item).strip() for item in (dsl.get("maps_to_controls") or []) if str(item).strip()])
    triggered_controls_unique = _unique_preserve_order([str(item).strip() for item in triggered_controls if str(item).strip()])
    missed_controls = [control_id for control_id in expected_controls if control_id not in set(triggered_controls_unique)]
    severity = str(evaluated["severity"])
    evaluator_reasoning = str(evaluated["evaluator_reasoning"])
    confidence = float(evaluated["confidence"])
    return {
        "result": result,
        "final_outcome": result,
        "failed_assertions": assertion_failures,
        "enforcement_events_linked": [e for e in linked_events if e],
        "evidence_nodes_created": [n for n in evidence_nodes if n],
        "step_outputs": step_outputs,
        "step_trace_ids": step_trace_ids,
        "execution_steps": step_traces,
        "non_executable_steps": non_executable_steps,
        "expected_controls": expected_controls,
        "triggered_controls": triggered_controls_unique,
        "missed_controls": missed_controls,
        "severity": severity,
        "evaluator_reasoning": evaluator_reasoning,
        "confidence": confidence,
        "observed_decisions": _unique_preserve_order(observed_decisions),
    }


def run_simulation(
    db: Session,
    *,
    tenant_id: str,
    simulation: SimulationDefinition,
    ai_system_id: str,
    mode: str,
    stochastic_runs: int,
    inputs_used: dict[str, Any],
    actor_user_id: str | None,
    live_session_id: str | None = None,
    execution_mode: str = "manual",
    execution_environment: str = "sandbox",
    approval_granted: bool = False,
) -> SimulationRun:
    enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="simulations.run",
        route="/simulations/definitions/{simulation_id}/run",
        module="simulation_service",
    )
    correlation_id = get_correlation_id()
    if simulation.tenant_id != tenant_id:
        raise ValueError("Simulation definition not found for tenant")

    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if not ai_system:
        raise ValueError("AI system not found for tenant")

    mode_normalized = str(mode or "deterministic").strip().lower()
    if mode_normalized not in {"deterministic", "stochastic"}:
        raise ValueError("Simulation mode must be deterministic or stochastic")

    run_count = 1 if mode_normalized == "deterministic" else max(1, _as_int(stochastic_runs, 5))
    execution_mode_normalized = str(execution_mode or "manual").strip().lower() or "manual"
    execution_environment_normalized = str(execution_environment or "sandbox").strip().lower() or "sandbox"

    pre_run_policy = pre_run_check(
        db,
        tenant_id=tenant_id,
        simulation=simulation,
        execution_mode=execution_mode_normalized,
        execution_environment=execution_environment_normalized,
        approval_granted=approval_granted,
    )
    if str(pre_run_policy.get("status") or "").strip().lower() != "approved_to_run":
        return create_pre_run_blocked_result(
            db,
            tenant_id=tenant_id,
            simulation=simulation,
            ai_system_id=ai_system_id,
            mode=mode_normalized,
            inputs_used=inputs_used,
            pre_run_policy=pre_run_policy,
            live_session_id=live_session_id,
        )

    run = SimulationRun(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        simulation_id=simulation.id,
        ai_system_id=ai_system_id,
        mode=mode_normalized,
        inputs_used=inputs_used,
        results={
            "result": "fail",
            "failed_assertions": [],
            "enforcement_events_linked": [],
            "evidence_nodes_created": [],
            "pass_rate": 0.0,
            "passes": 0,
            "iterations": run_count,
            "iteration_outputs": [],
            "pre_run_policy": pre_run_policy,
        },
        controls_impacted=[],
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
            "mode": mode_normalized,
            "iterations": run_count,
            "live_session_id": live_session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    dsl = deepcopy(simulation.dsl_json)
    controls = list(dsl.get("maps_to_controls") or [])
    maturity_before = _snapshot_control_maturity_scores(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=controls,
    )
    enforcement_before = _snapshot_enforcement_strength(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=controls,
    )

    iteration_outputs: list[dict[str, Any]] = []
    all_failed_assertions: list[str] = []
    all_evidence_nodes: list[str] = []
    all_linked_events: list[str] = []
    all_step_trace_ids: list[str] = []
    all_non_executable_steps: list[dict[str, Any]] = []
    all_triggered_controls: list[str] = []
    all_observed_decisions: list[str] = []
    outcome_counts = {"pass": 0, "fail": 0, "partial": 0, "not_executable": 0}
    pass_count = 0
    support_matrix = build_execution_support_matrix_orchestrator(dsl)
    execution_status = overall_execution_status_orchestrator(support_matrix)

    for idx in range(run_count):
        try:
            out = _execute_simulation_iteration(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                dsl=dsl,
                inputs_used=inputs_used,
                actor_user_id=actor_user_id,
                run_id=run.id,
                simulation_id=simulation.id,
                iteration_index=idx,
                stochastic_mode=mode_normalized == "stochastic",
                live_session_id=live_session_id,
            )
        except Exception as exc:
            publish_simulation_update(
                tenant_id=tenant_id,
                event_type="simulation.run.failed",
                payload={
                    "run_id": run.id,
                    "simulation_id": simulation.id,
                    "ai_system_id": ai_system_id,
                    "live_session_id": live_session_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": str(exc),
                },
            )
            raise
        iteration_outputs.append(
            {
                "iteration": idx + 1,
                "result": out["result"],
                "failed_assertions": out["failed_assertions"],
                "enforcement_events_linked": out["enforcement_events_linked"],
                "evidence_nodes_created": out["evidence_nodes_created"],
                "step_outputs": out["step_outputs"],
                "step_trace_ids": out.get("step_trace_ids", []),
                "non_executable_steps": out.get("non_executable_steps", []),
                "expected_controls": out.get("expected_controls", []),
                "triggered_controls": out.get("triggered_controls", []),
                "missed_controls": out.get("missed_controls", []),
                "severity": out.get("severity", "low"),
                "evaluator_reasoning": out.get("evaluator_reasoning", ""),
                "confidence": out.get("confidence", 0.0),
                "observed_decisions": out.get("observed_decisions", []),
            }
        )

        if out["result"] == "pass":
            pass_count += 1
        outcome_key = str(out.get("result") or "").strip().lower()
        if outcome_key in outcome_counts:
            outcome_counts[outcome_key] += 1

        all_failed_assertions.extend(out["failed_assertions"])
        all_evidence_nodes.extend(out["evidence_nodes_created"])
        all_linked_events.extend(out["enforcement_events_linked"])
        all_step_trace_ids.extend([str(item).strip() for item in (out.get("step_trace_ids") or []) if str(item).strip()])
        all_non_executable_steps.extend(list(out.get("non_executable_steps") or []))
        all_triggered_controls.extend([str(item).strip() for item in (out.get("triggered_controls") or []) if str(item).strip()])
        all_observed_decisions.extend([str(item).strip() for item in (out.get("observed_decisions") or []) if str(item).strip()])

    pass_rate = _clamp01(pass_count / float(run_count))
    evidence_requirements = dict(dsl.get("evidence_emission_requirements") or {})
    evidence_requirement_failures = _evaluate_evidence_emission_requirements(
        db,
        tenant_id=tenant_id,
        evidence_node_ids=all_evidence_nodes,
        requirements=evidence_requirements,
    )
    final_outcome = evaluate_final_outcome(
        outcome_counts=outcome_counts,
        evidence_requirement_failures=evidence_requirement_failures,
        run_count=run_count,
    )

    result = "pass" if final_outcome == "pass" else "fail"

    if mode_normalized == "stochastic":
        contribution_value = round((pass_rate * 2.0) - 1.0, 4)
    else:
        contribution_value = 1.0 if result == "pass" else -1.0
    contributions = [{"control_id": cid, "contribution": contribution_value} for cid in controls]

    failures = _unique_preserve_order(all_failed_assertions + evidence_requirement_failures)
    evidence_node_ids = _unique_preserve_order([n for n in all_evidence_nodes if n])
    linked_events = _unique_preserve_order([e for e in all_linked_events if e])
    step_trace_ids = _unique_preserve_order([item for item in all_step_trace_ids if item])
    expected_controls = _unique_preserve_order([str(item).strip() for item in controls if str(item).strip()])
    triggered_controls = _unique_preserve_order([item for item in all_triggered_controls if item])
    missed_controls = [control_id for control_id in expected_controls if control_id not in set(triggered_controls)]
    expected_decision = str((dsl.get("expected_control_behavior") or {}).get("expected_decision") or "").strip().lower() or None
    actual_decision = _dominant_decision(all_observed_decisions)
    decision_match = _decision_matches_expected(expected=expected_decision, actual=actual_decision)
    severity = "low"
    if final_outcome == "fail":
        severity = "high"
    elif final_outcome == "partial":
        severity = "med"
    elif final_outcome == "not_executable":
        severity = "med"
    confidence = {"pass": 1.0, "fail": 1.0, "partial": 0.75, "not_executable": 0.35}.get(final_outcome, 0.5)
    evaluator_reasoning = {
        "pass": "Observed execution satisfied all assertions and evidence requirements.",
        "fail": "Observed execution did not satisfy assertions or required evidence emission.",
        "partial": "Execution completed only partially across supported surfaces or had mixed outcomes.",
        "not_executable": "Execution is unavailable for required step types on current deployment surfaces.",
    }.get(final_outcome, "Simulation run evaluated.")
    simulation_crq = compute_simulation_crq(
        simulation_run_id=run.id,
        control_ids=expected_controls,
        category=str(simulation.category or "governance"),
        severity=severity,
        final_outcome=final_outcome,
        pass_rate=pass_rate,
        iterations=run_count,
    )

    failure_reason_machine = ""
    failure_reason_human = ""
    if expected_decision and not decision_match and final_outcome in {"pass", "partial"}:
        final_outcome = "fail"
        result = "fail"
        failures = _unique_preserve_order([*failures, f"expected_decision_mismatch({expected_decision}!={actual_decision})"])
        missed_controls = _unique_preserve_order([*missed_controls, *expected_controls])
        severity = "high"
        failure_reason_machine = "expected_decision_mismatch"
        failure_reason_human = (
            f"Observed decision '{actual_decision}' did not satisfy expected decision '{expected_decision}'."
        )

    run.results = {
        "result": result,
        "final_outcome": final_outcome,
        "failed_assertions": failures,
        "failures": failures,
        "enforcement_events_linked": linked_events,
        "evidence_nodes_created": evidence_node_ids,
        "evidence_node_ids": evidence_node_ids,
        "pass_rate": pass_rate,
        "passes": pass_count,
        "iterations": run_count,
        "control_maturity_delta": [],
        "enforcement_strictness_delta": [],
        "expected_controls": expected_controls,
        "triggered_controls": triggered_controls,
        "missed_controls": missed_controls,
        "severity": severity,
        "expected_decision": expected_decision,
        "actual_decision": actual_decision,
        "decision_match": decision_match,
        "evaluator_reasoning": evaluator_reasoning,
        "confidence": confidence,
        "execution_status": execution_status,
        "execution_support_matrix": support_matrix,
        "enforcement_summary": {
            "observed_decisions": _unique_preserve_order([item for item in all_observed_decisions if item]),
            "linked_events_count": len(linked_events),
            "evidence_node_count": len(evidence_node_ids),
        },
        "step_trace_ids": step_trace_ids,
        "non_executable_steps": all_non_executable_steps,
        "iteration_outputs": iteration_outputs,
        "pre_run_policy": pre_run_policy,
        "crq": simulation_crq,
        "risk_if_exploited": simulation_crq.get("risk_if_exploited"),
        "likelihood": simulation_crq.get("likelihood"),
        "annualized_loss_expectancy": simulation_crq.get("annualized_loss_expectancy"),
        "risk_impact": simulation_crq.get("outcome_impact"),
        "risk_reduction_if_control_passes": simulation_crq.get("risk_reduction"),
        "residual_risk_if_control_fails": simulation_crq.get("annualized_loss_expectancy"),
        "control_impact_score": simulation_crq.get("decision_score", {}).get("priority_score"),
        "framework_mappings": list(dsl.get("framework_mappings") or []),
        "failure_reason_machine": failure_reason_machine or (failures[0] if failures else ""),
        "failure_reason_human": failure_reason_human or evaluator_reasoning,
        "target_surface": str(dsl.get("target_surface") or "unknown"),
    }
    run.controls_impacted = contributions
    run.finished_at = datetime.now(timezone.utc)

    if final_outcome == "fail":
        previous_failures = _count_failed_simulation_runs(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            simulation_id=simulation.id,
            exclude_run_id=run.id,
        )
        repeated_failures = int(previous_failures) + 1
        high_risk_failure = _is_high_risk_simulation_failure(ai_system=ai_system, dsl=dsl)
        critical_failure = bool(high_risk_failure and pass_rate < 1.0)
        policy_escalation_level = 1
        if critical_failure:
            policy_escalation_level = 2
        if repeated_failures >= 3:
            policy_escalation_level = max(policy_escalation_level, 3)
        maturity_penalty = 0.1
        if critical_failure:
            maturity_penalty = 0.2
        if repeated_failures >= 3:
            maturity_penalty = max(maturity_penalty, 0.25)

        _apply_failure_penalty_with_delta(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_ids=controls,
            reason=f"simulation_fail:{simulation.id}",
            delta=maturity_penalty,
        )
        policy_feedback_updated_versions = tighten_enforcement_for_failed_controls(
            db,
            tenant_id=tenant_id,
            control_ids=controls,
            reason=f"simulation_fail:{simulation.id}",
            escalation_level=policy_escalation_level,
            ai_system_id=ai_system_id,
        )

        deployment_block = {"blocked": False}
        if critical_failure and repeated_failures >= 3:
            deployment_block = _apply_simulation_failure_deployment_block(
                db,
                tenant_id=tenant_id,
                ai_system=ai_system,
                simulation_id=simulation.id,
                run_id=run.id,
                repeated_failures=repeated_failures,
                related_control_ids=controls,
                actor_user_id=actor_user_id,
            )
            evidence_node_id = str(deployment_block.get("evidence_node_id") or "").strip()
            if evidence_node_id:
                evidence_node_ids = _unique_preserve_order([*evidence_node_ids, evidence_node_id])

        if critical_failure:
            try:
                critical_signal = ingest_monitoring_signal(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=ai_system_id,
                    signal_type="simulation.critical_failure",
                    severity=("critical" if repeated_failures >= 3 else "high"),
                    payload={
                        "source_surface": "monitoring",
                        "source": "control_validation",
                        "reason_code": "critical_simulation_failure",
                        "simulation_id": simulation.id,
                        "simulation_run_id": run.id,
                        "repeated_failures": repeated_failures,
                        "pass_rate": pass_rate,
                        "related_control_ids": controls,
                        "critical_failure": True,
                        "policy_feedback": {
                            "escalation_level": policy_escalation_level,
                            "updated_policy_version_ids": policy_feedback_updated_versions,
                        },
                        "block_deployment": bool(deployment_block.get("blocked")),
                    },
                    actor_user_id=actor_user_id,
                    create_default_drift_alert=True,
                    drift_title=f"Critical simulation failure: {simulation.name}",
                    related_control_ids=controls,
                    forward_to_runtime_intelligence=True,
                )
                critical_signal_node_ids = [
                    str(node_id).strip()
                    for node_id in (dict(critical_signal.payload or {}).get("evidence_node_ids") or [])
                    if str(node_id).strip()
                ]
                evidence_node_ids = _unique_preserve_order([*evidence_node_ids, *critical_signal_node_ids])
            except Exception as exc:  # pragma: no cover - monitoring linkage must remain non-blocking
                log_structured(
                    "simulation_critical_failure_signal_failed",
                    module="simulation_service",
                    tenant_id=tenant_id,
                    simulation_id=simulation.id,
                    simulation_run_id=run.id,
                    error=str(exc),
                )

        updated_results = dict(run.results or {})
        updated_results["failure_context"] = {
            "repeated_failures": repeated_failures,
            "high_risk_failure": high_risk_failure,
            "critical_failure": critical_failure,
            "maturity_penalty": round(float(maturity_penalty), 6),
            "policy_feedback": {
                "escalation_level": policy_escalation_level,
                "updated_policy_version_ids": list(policy_feedback_updated_versions or []),
            },
            "deployment_block": dict(deployment_block or {}),
        }
        updated_results["evidence_nodes_created"] = evidence_node_ids
        updated_results["evidence_node_ids"] = evidence_node_ids
        run.results = updated_results
        try:
            from app.services.remediation import propose_remediation_from_simulation_failure

            propose_remediation_from_simulation_failure(
                db,
                run=run,
                context={
                    "finding_type": "simulation_failure",
                    "reason_code": "simulation_failure",
                    "related_control_ids": controls,
                    "simulation_id": simulation.id,
                    "occurrence_count": repeated_failures,
                    "critical_failure": critical_failure,
                    "high_business_impact": bool(critical_failure and repeated_failures >= 3),
                    "block_deployment": bool(deployment_block.get("blocked")),
                    "policy_feedback_escalation_level": policy_escalation_level,
                    "policy_feedback_updated_versions": list(policy_feedback_updated_versions or []),
                },
            )
        except Exception as exc:  # pragma: no cover - remediation must not block simulation execution
            log_structured(
                "simulation_remediation_proposal_failed",
                module="simulation_service",
                tenant_id=tenant_id,
                simulation_id=simulation.id,
                simulation_run_id=run.id,
                error=str(exc),
            )

    recalculate_control_maturity(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=controls,
        reason=f"simulation_run:{simulation.id}:{result}:{pass_rate:.4f}",
    )
    _apply_control_success_criteria(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=controls,
        pass_rate=pass_rate,
        simulation_id=simulation.id,
        actor_user_id=actor_user_id,
    )

    maturity_after = _snapshot_control_maturity_scores(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=controls,
    )
    enforcement_after = _snapshot_enforcement_strength(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=controls,
    )

    final_results = dict(run.results or {})
    final_results["control_maturity_delta"] = _compute_control_maturity_delta(
        before_scores=maturity_before,
        after_scores=maturity_after,
        control_ids=controls,
    )
    final_results["enforcement_strictness_delta"] = _compute_enforcement_strictness_delta(
        before_snapshot=enforcement_before,
        after_snapshot=enforcement_after,
    )
    evidence_bundle = write_run_evidence_bundle(
        simulation_id=simulation.id,
        simulation_run_id=run.id,
        payload={
            "simulation_run_id": run.id,
            "tenant_id": tenant_id,
            "simulation_id": simulation.id,
            "ai_system_id": ai_system_id,
            "mode": mode_normalized,
            "final_outcome": final_results.get("final_outcome"),
            "execution_status": final_results.get("execution_status"),
            "execution_support_matrix": list(final_results.get("execution_support_matrix") or []),
            "results": final_results,
            "inputs_used": dict(inputs_used or {}),
            "iteration_outputs": list(final_results.get("iteration_outputs") or []),
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    final_results["evidence_bundle"] = evidence_bundle
    final_results["evidence_bundle_path"] = evidence_bundle.get("relative_path")
    final_results["evidence_bundle_sha256"] = evidence_bundle.get("sha256")
    run.results = final_results
    publish_simulation_update(
        tenant_id=tenant_id,
        event_type="simulation.run.completed",
        payload={
            "run_id": run.id,
            "simulation_id": simulation.id,
            "ai_system_id": ai_system_id,
            "live_session_id": live_session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "final_outcome": final_results.get("final_outcome"),
            "result": final_results.get("result"),
            "execution_status": final_results.get("execution_status"),
            "expected_controls": final_results.get("expected_controls"),
            "triggered_controls": final_results.get("triggered_controls"),
            "missed_controls": final_results.get("missed_controls"),
            "actual_decision": final_results.get("actual_decision"),
            "expected_decision": final_results.get("expected_decision"),
            "control_impact_score": final_results.get("control_impact_score"),
            "evidence_bundle_path": final_results.get("evidence_bundle_path"),
            "risk_if_exploited": final_results.get("risk_if_exploited"),
            "annualized_loss_expectancy": final_results.get("annualized_loss_expectancy"),
            "risk_reduction_if_control_passes": final_results.get("risk_reduction_if_control_passes"),
            "residual_risk_if_control_fails": final_results.get("residual_risk_if_control_fails"),
            "likelihood": final_results.get("likelihood"),
            "crq": final_results.get("crq"),
            "financials": final_results.get("financials"),
            "baseline_ale": (dict(final_results.get("crq") or {})).get("baseline_ale"),
            "current_ale": (dict(final_results.get("crq") or {})).get("current_ale"),
        },
    )

    db.flush()
    return run


def get_simulation_run_trace(
    db: Session,
    *,
    tenant_id: str,
    run_id: str,
) -> dict[str, Any]:
    run = db.scalar(
        select(SimulationRun).where(
            SimulationRun.id == run_id,
            SimulationRun.tenant_id == tenant_id,
        )
    )
    if run is None:
        raise ValueError("Simulation run not found")

    simulation = db.scalar(
        select(SimulationDefinition).where(
            SimulationDefinition.id == run.simulation_id,
            SimulationDefinition.tenant_id == tenant_id,
        )
    )
    if simulation is None:
        raise ValueError("Simulation definition not found for run")

    steps = db.scalars(
        select(SimulationExecutionStep)
        .where(
            SimulationExecutionStep.tenant_id == tenant_id,
            SimulationExecutionStep.simulation_run_id == run.id,
        )
        .order_by(
            SimulationExecutionStep.iteration_index.asc(),
            SimulationExecutionStep.step_order.asc(),
            SimulationExecutionStep.created_at.asc(),
        )
    ).all()
    step_rows = [_serialize_execution_step(row) for row in steps]
    support_matrix = list(
        (run.results or {}).get("execution_support_matrix")
        or build_execution_support_matrix_orchestrator(dict(simulation.dsl_json or {}))
    )
    execution_status = str((run.results or {}).get("execution_status") or overall_execution_status_orchestrator(support_matrix))
    final_outcome = str((run.results or {}).get("final_outcome") or (run.results or {}).get("result") or "fail")

    status_counts: dict[str, int] = {}
    for row in step_rows:
        key = str(row.get("status") or "unknown")
        status_counts[key] = int(status_counts.get(key, 0)) + 1

    return {
        "simulation_run_id": run.id,
        "simulation_id": run.simulation_id,
        "ai_system_id": run.ai_system_id,
        "mode": run.mode,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "final_outcome": final_outcome,
        "execution_status": execution_status,
        "support_matrix": support_matrix,
        "steps": step_rows,
        "summary": {
            "step_count": len(step_rows),
            "status_counts": status_counts,
            "expected_controls": list((run.results or {}).get("expected_controls") or []),
            "triggered_controls": list((run.results or {}).get("triggered_controls") or []),
            "missed_controls": list((run.results or {}).get("missed_controls") or []),
            "severity": str((run.results or {}).get("severity") or "low"),
            "confidence": float((run.results or {}).get("confidence") or 0.0),
            "evaluator_reasoning": str((run.results or {}).get("evaluator_reasoning") or ""),
        },
    }
