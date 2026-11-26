"""Run a catalogue scenario through the existing simulation framework and verify what it recorded.

``simulation_catalog_runners`` says, per scenario, which control to drive with which payload and what must come
back. This module does the database side:

1. ``provision_simulation_world`` creates the synthetic identities a scenario needs inside the tenant (agent
   identities with short-lived capability tokens - one valid, one revoked, one expired, one for a suspended agent, one
   whose owner attestation lapsed - and an AI system still awaiting governance approval). Raw tokens are random per
   provisioning and returned to the caller only; ``retire_simulation_world`` revokes them afterwards.
2. ``compile_catalog_dsl`` turns the runner into a simulation DSL (steps, decision assertion, evidence-marker
   assertions, evidence-emission requirement) validated by ``simulation_contract_service``.
3. ``run_catalog_scenario`` persists the definition and runs it with ``simulation_service.run_simulation``, then
   ``verify_catalog_run`` checks the outcome and the evidence: the decision class, every evidence node recorded for
   the tenant, the enforcement events linked, and the run's evidence bundle on disk hashing to the SHA-256 the run
   recorded.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.simulation import SimulationDefinition, SimulationRun
from app.services.ai_iam_service import token_hash
from app.services.simulation_catalog_runners import (
    DECISION_CLASSES,
    SIMULATION_CATEGORY,
    STATUS_EXECUTABLE,
    STATUS_EXPECTED_GAP,
    TARGET_MODULE,
    ScenarioRunner,
    runner_for,
)
from app.services.simulation_contract_service import validate_and_normalize_simulation_dsl
from app.services.simulation_orchestrator import build_execution_support_matrix, overall_execution_status
from app.services.simulation_orchestrator.executor import _simulation_artifacts_root
from app.services.simulation_service import run_simulation


WORLD_TOKEN_PREFIX = "hawk-sim-"
WORLD_AGENT_PREFIX = "hawk-sim-"
_WORLD_ACTIONS = ["api_call", "email_send", "db_query", "tool_execution", "tool.run", "tool.read", "tool.email_send", "crm.read"]
_WORLD_TOKEN_SCOPES = ["tool.run", "tool.read", "tool.email_send", "crm.read"]
_WORLD_TOOLS = ["crm_lookup", "email_sender", "openai_api"]
_WORLD_SYSTEMS = ["crm.internal", "api.openai.com", "mail.internal"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def provision_simulation_world(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    issued_by_user_id: str | None,
    token_minutes: int = 30,
) -> dict[str, str]:
    """Create the synthetic identities catalogue scenarios use; return the step inputs (ids and raw tokens)."""

    now = _now()
    inputs: dict[str, str] = {}

    def agent(key: str, **overrides: Any) -> AgentIdentity:
        row = AgentIdentity(
            tenant_id=tenant_id,
            name=f"{WORLD_AGENT_PREFIX}{key}-agent",
            description="Synthetic identity for attack simulation; holds no real authority.",
            max_chain_depth=2,
            capability_inheritance=False,
            action_scope=list(_WORLD_ACTIONS),
            tool_registry=list(_WORLD_TOOLS),
            external_system_access=list(_WORLD_SYSTEMS),
            **overrides,
        )
        db.add(row)
        db.flush()
        inputs[f"agent_{key}"] = row.id
        return row

    def token(key: str, owner: AgentIdentity, **overrides: Any) -> None:
        raw = WORLD_TOKEN_PREFIX + secrets.token_urlsafe(24)
        db.add(
            CapabilityToken(
                tenant_id=tenant_id,
                agent_identity_id=owner.id,
                ai_system_id=overrides.pop("ai_system_id", ai_system_id),
                token_hash=token_hash(raw),
                scopes=list(_WORLD_TOKEN_SCOPES),
                expires_at=overrides.pop("expires_at", now + timedelta(minutes=token_minutes)),
                chain_depth=2,
                issued_by_user_id=issued_by_user_id,
                **overrides,
            )
        )
        inputs[f"token_{key}"] = raw

    primary = agent("primary")
    token("primary", primary)
    token("revoked", primary, revoked_at=now - timedelta(minutes=5))
    token("expired", primary, expires_at=now - timedelta(minutes=5))
    peer = agent("peer")
    token("peer", peer)
    suspended = agent("suspended", status="suspended")
    token("suspended", suspended)
    stale = agent("stale", owner_attestation_expiry=now - timedelta(days=1))
    token("stale", stale)

    proposed = AISystem(
        tenant_id=tenant_id,
        name=f"{WORLD_AGENT_PREFIX}proposed-system",
        description="Synthetic AI system awaiting governance approval (attack simulation).",
        risk_tier="HIGH",
        status="active",
        metadata_json={"governance_state": "PROPOSED", "lifecycle_state": "PROPOSED", "simulation_world": True},
    )
    db.add(proposed)
    db.flush()
    inputs["proposed_ai_system_id"] = proposed.id
    # A valid token of the primary agent, bound to the AI system that still awaits governance approval.
    token("proposed", primary, ai_system_id=proposed.id)
    return inputs


def retire_simulation_world(db: Session, *, tenant_id: str, inputs: dict[str, str]) -> int:
    """Revoke every capability token the world minted; returns how many were revoked."""

    hashes = [token_hash(value) for key, value in inputs.items() if key.startswith("token_") and value]
    if not hashes:
        return 0
    rows = db.scalars(
        select(CapabilityToken).where(CapabilityToken.tenant_id == tenant_id, CapabilityToken.token_hash.in_(hashes))
    ).all()
    now = _now()
    for row in rows:
        if row.revoked_at is None:
            row.revoked_at = now
    db.flush()
    return len(rows)


def _generated_inputs(runner: ScenarioRunner) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, (unit, length) in runner.generated_inputs.items():
        repeats = int(length) // max(1, len(unit)) + 1
        out[name] = (unit * repeats)[: int(length)]
    return out


def _framework_mappings(entry_controls: list[str], frameworks: list[dict[str, Any]]) -> list[dict[str, str]]:
    primary = entry_controls[0] if entry_controls else "POLICY_ENFORCEMENT_CONTROL"
    out = []
    for item in frameworks:
        framework = str(item.get("framework") or "").strip()
        if framework:
            out.append({"framework": framework, "reference": str(item.get("reference") or "N/A"), "control_id": primary})
    return out


def compile_catalog_dsl(
    runner: ScenarioRunner,
    *,
    tenant_id: str,
    catalog_entry: dict[str, Any],
) -> dict[str, Any]:
    """The runner as a simulation DSL for ``run_simulation``."""

    if not runner.has_runner:
        raise ValueError(f"{runner.simulation_id} has no runner ({runner.status})")
    category = SIMULATION_CATEGORY[runner.category]
    controls = [str(item).strip() for item in (catalog_entry.get("control_ids") or []) if str(item).strip()]
    steps = []
    for index, step in enumerate(runner.steps, start=1):
        steps.append({"step_id": f"s{index}", "kind": step.kind, "payload_template": dict(step.payload), "variable_bindings": {}})
    decisive = f"s{len(runner.steps)}"
    decision_field = f"{decisive}.{runner.steps[-1].decision_field}"
    assertions: list[dict[str, Any]] = []
    on_fail = {"result": "fail", "evidence_signal_type": "simulation.assertion.failed", "severity": "high"}
    if runner.observed_decision == "none":
        assertions.append({"assertion_id": "a1", "check": {"field": f"{decisive}.signal_id", "operator": "exists", "value": True}, "on_fail": on_fail})
    else:
        assertions.append({"assertion_id": "a1", "check": {"field": decision_field, "operator": "in", "value": list(runner.asserted_decisions)}, "on_fail": on_fail})
    for index, step in enumerate(runner.steps[:-1], start=1):
        # Every step of a multi-step scenario (repeated uploads) must meet the outcome too.
        assertions.append(
            {
                "assertion_id": f"a1.s{index}",
                "check": {"field": f"s{index}.{step.decision_field}", "operator": "in", "value": list(runner.asserted_decisions)},
                "on_fail": on_fail,
            }
        )
    for index, marker in enumerate(runner.markers, start=2):
        assertions.append({"assertion_id": f"a{index}", "check": {"field": decisive, "operator": "contains", "value": marker}, "on_fail": on_fail})
    expected_decision = runner.expected_decision
    candidates = ", ".join(DECISION_CLASSES.get(expected_decision, (expected_decision,)))
    dsl: dict[str, Any] = {
        "id": runner.simulation_id,
        "tenant_id": tenant_id,
        "name": str(catalog_entry.get("name") or runner.simulation_id),
        "category": category,
        "target_module": TARGET_MODULE[category],
        "target_surface": runner.target_surface,
        "required_executor": runner.required_executor,
        "version": "1.0.0",
        "severity": {"medium": "med"}.get(runner.severity, runner.severity if runner.severity in {"low", "med", "high", "critical"} else "med"),
        "description": str(catalog_entry.get("description") or ""),
        "preconditions": [str(item) for item in (catalog_entry.get("preconditions") or [])],
        "attack_steps": [{"order": idx + 1, "action": str(action)} for idx, action in enumerate(catalog_entry.get("attack_steps") or [])],
        "expected_control_behavior": {
            "expected_controls": controls,
            "expected_decision": expected_decision,
            "expected_risk_level": str((catalog_entry.get("expected_control_behavior") or {}).get("expected_risk_level") or ""),
        },
        "framework_mappings": _framework_mappings(controls, list(catalog_entry.get("framework_mappings") or [])),
        "evidence_requirements": ["runtime_event", "policy_decision", "simulation_result"],
        "remediation_template_refs": [str(item) for item in (catalog_entry.get("remediation_template_refs") or [])],
        "safety": {"requires_sandbox": True, "max_runtime_seconds": 120, "no_external_network": True},
        "inputs_schema": {"fields": [{"name": name, "type": "string", "required": True} for name in runner.world_inputs]},
        "steps": steps,
        "assertions": assertions,
        "maps_to_controls": controls or ["POLICY_ENFORCEMENT_CONTROL"],
        "expected_outcomes": {
            "pass_conditions": [f"Decision in {candidates}", *[f"Control output contains {marker}" for marker in runner.markers]],
            "fail_conditions": ["Expected control behaviour was not observed"],
        },
        "evidence_emission_requirements": {"required_signal_types": [], "min_evidence_nodes": 1, "require_audit_log": True},
        "safe_testing_boundaries": {"allowed_data_classes": ["synthetic"], "disallow_production_data": True},
    }
    dsl["executable_status"] = overall_execution_status(build_execution_support_matrix(dsl))
    return validate_and_normalize_simulation_dsl(
        dsl_json=dsl,
        tenant_id=tenant_id,
        simulation_id=runner.simulation_id,
        name=dsl["name"],
        category=category,
        target_module=dsl["target_module"],
        version="1.0.0",
    )


def ensure_catalog_definition(db: Session, *, tenant_id: str, runner: ScenarioRunner, catalog_entry: dict[str, Any]) -> SimulationDefinition:
    dsl = compile_catalog_dsl(runner, tenant_id=tenant_id, catalog_entry=catalog_entry)
    existing = [
        row
        for row in db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()
        if str((row.dsl_json or {}).get("id") or "") == runner.simulation_id
    ]
    if existing:
        row = existing[0]
        row.dsl_json = dsl
        row.name = dsl["name"]
        row.category = dsl["category"]
        row.target_module = dsl["target_module"]
        row.version = "1.0.0"
    else:
        row = SimulationDefinition(
            tenant_id=tenant_id,
            name=dsl["name"],
            category=dsl["category"],
            target_module=dsl["target_module"],
            version="1.0.0",
            dsl_json=dsl,
        )
        db.add(row)
    db.flush()
    return row


@dataclass
class CatalogScenarioOutcome:
    simulation_id: str
    status: str
    run_id: str
    final_outcome: str
    actual_decision: str
    expected_decision: str
    evidence_node_ids: list[str]
    evidence_bundle_path: str | None
    observed_reasons: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_catalog_run(db: Session, *, tenant_id: str, runner: ScenarioRunner, run: SimulationRun) -> list[str]:
    """What is wrong with this run, as a list of problems (empty when it is what the runner promises)."""

    results = dict(run.results or {})
    problems: list[str] = []
    outcome = str(results.get("final_outcome") or "")
    actual = str(results.get("actual_decision") or "").strip().lower()
    failures = [str(item) for item in (results.get("failed_assertions") or [])]
    allowed = set(runner.asserted_decisions)

    if str(results.get("execution_status") or "") != "executable_now":
        problems.append(f"execution_status={results.get('execution_status')} (expected executable_now)")
    if (results.get("pre_run_policy") or {}).get("status") != "approved_to_run":
        problems.append(f"pre_run_policy={(results.get('pre_run_policy') or {}).get('status')}")
    if runner.observed_decision == "none":
        if actual not in {"", "unknown"}:
            problems.append(f"actual_decision={actual} (expected no enforcement decision)")
    elif actual not in allowed:
        problems.append(f"actual_decision={actual} (expected one of {sorted(allowed)})")

    if runner.status == STATUS_EXECUTABLE:
        if outcome != "pass":
            problems.append(f"final_outcome={outcome} failures={failures}")
        evidence_ids = [str(item) for item in (results.get("evidence_node_ids") or []) if str(item).strip()]
        if not evidence_ids:
            problems.append("no evidence nodes recorded")
        else:
            stored = set(
                db.scalars(
                    select(EvidenceNode.id).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id.in_(evidence_ids))
                ).all()
            )
            missing = [item for item in evidence_ids if item not in stored]
            if missing:
                problems.append(f"evidence nodes not stored for the tenant: {missing}")
        if not results.get("enforcement_events_linked"):
            problems.append("no enforcement event linked")
    elif runner.status == STATUS_EXPECTED_GAP:
        # The gap must show up as what it is: the run fails on the catalogue's expected decision, nothing else.
        if outcome != "fail":
            problems.append(f"final_outcome={outcome} (an expected gap must fail against the catalogue expectation)")
        own_failures = [item for item in failures if not item.startswith("expected_decision_mismatch") and not item.startswith("evidence_nodes_below_minimum")]
        if own_failures:
            problems.append(f"runner assertions failed: {own_failures}")
        if not any(item.startswith("expected_decision_mismatch") for item in failures) and runner.observed_decision != "none":
            problems.append("expected_decision_mismatch not recorded")

    bundle_path = str(results.get("evidence_bundle_path") or "")
    bundle_sha = str(results.get("evidence_bundle_sha256") or "")
    if not bundle_path or not bundle_sha:
        problems.append("no evidence bundle recorded")
    else:
        file_path = Path(_simulation_artifacts_root()) / bundle_path
        if not file_path.is_file():
            problems.append(f"evidence bundle missing on disk: {bundle_path}")
        elif hashlib.sha256(file_path.read_bytes()).hexdigest() != bundle_sha:
            problems.append("evidence bundle hash does not match the recorded SHA-256")
    return problems


def _observed_reasons(results: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for iteration in results.get("iteration_outputs") or []:
        for output in dict(iteration.get("step_outputs") or {}).values():
            if not isinstance(output, dict):
                continue
            for key in ("reason", "reason_code"):
                value = str(output.get(key) or "").strip()
                if value and value not in reasons:
                    reasons.append(value)
            for value in output.get("reason_codes") or []:
                if str(value).strip() and str(value) not in reasons:
                    reasons.append(str(value))
            for guardian in output.get("guardian_results") or []:
                if isinstance(guardian, dict) and str(guardian.get("decision") or "allow") != "allow":
                    name = str(guardian.get("guardian_id") or "")
                    if name and name not in reasons:
                        reasons.append(name)
    return reasons


def run_catalog_scenario(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    simulation_id: str,
    actor_user_id: str | None,
    world_inputs: dict[str, str],
    catalog_entry: dict[str, Any],
    approval_granted: bool = False,
) -> CatalogScenarioOutcome:
    """Run one catalogue scenario. ``approval_granted`` is the operator's approval the simulation policy asks for
    before high-severity scenarios run (simulation_policy_service.pre_run_check); without it such a run is refused."""
    runner = runner_for(simulation_id)
    if not runner.has_runner:
        raise ValueError(f"{simulation_id} is {runner.status}: {'; '.join(runner.environment_requirements) or runner.gap_reason}")
    definition = ensure_catalog_definition(db, tenant_id=tenant_id, runner=runner, catalog_entry=catalog_entry)
    inputs = {name: world_inputs[name] for name in runner.world_inputs}
    inputs.update(_generated_inputs(runner))
    run = run_simulation(
        db,
        tenant_id=tenant_id,
        simulation=definition,
        ai_system_id=ai_system_id,
        mode="deterministic",
        stochastic_runs=1,
        inputs_used=inputs,
        actor_user_id=actor_user_id,
        execution_mode="manual",
        execution_environment="sandbox",
        approval_granted=approval_granted,
    )
    results = dict(run.results or {})
    if inputs and any(len(str(value)) > 4096 for value in inputs.values()):
        # Keep generated bulk input (context bloat) out of the stored run row; the evidence bundle keeps its hash.
        run.inputs_used = {name: (value if len(str(value)) <= 4096 else {"sha256": hashlib.sha256(str(value).encode()).hexdigest(), "characters": len(str(value))}) for name, value in inputs.items()}
    problems = verify_catalog_run(db, tenant_id=tenant_id, runner=runner, run=run)
    return CatalogScenarioOutcome(
        simulation_id=simulation_id,
        status=runner.status,
        run_id=run.id,
        final_outcome=str(results.get("final_outcome") or ""),
        actual_decision=str(results.get("actual_decision") or ""),
        expected_decision=runner.expected_decision,
        evidence_node_ids=[str(item) for item in (results.get("evidence_node_ids") or [])],
        evidence_bundle_path=results.get("evidence_bundle_path"),
        observed_reasons=_observed_reasons(results),
        problems=problems,
    )
