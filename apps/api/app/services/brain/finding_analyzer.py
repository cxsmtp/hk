from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.maturity import ControlMaturity
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.db.models.snapshot import AuditorSnapshot
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node


STRICTNESS_PROFILE_RANK = {
    "baseline": 0,
    "moderate": 1,
    "strict": 2,
    "maximum": 3,
    "blocked": 4,
}
RISK_TIER_STRICTNESS_PROFILE = {
    "LOW": "baseline",
    "MEDIUM": "moderate",
    "HIGH": "strict",
    "CRITICAL": "maximum",
    "RESTRICTED": "maximum",
    "PROHIBITED": "blocked",
}


def _unique_strings(values: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = str(raw or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _as_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


class FindingAnalysisCitation(BaseModel):
    type: Literal["evidence_node", "snapshot"]
    id: str
    note: str | None = None
    ts: str | None = None


class FindingAnalysisStep(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str


class FindingAnalysisResult(BaseModel):
    answer: str
    summary: str
    why_it_matters: str
    controls: list[str]
    frameworks: list[str]
    recommended_action: str
    proposed_next_steps: list[FindingAnalysisStep]
    citations: list[FindingAnalysisCitation]
    confidence: float
    missing_evidence: list[str] = Field(default_factory=list)
    proposed_actions: list[FindingAnalysisStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_refusal_contract(self) -> "FindingAnalysisResult":
        refusal = self.answer == "INSUFFICIENT EVIDENCE"
        if refusal:
            if not self.proposed_actions:
                raise ValueError("Refusal response must include proposed_actions.")
        return self


def _strictness_profile(ai_system: AISystem | None) -> str:
    if ai_system is None:
        return "baseline"
    metadata = ai_system.metadata_json if isinstance(ai_system.metadata_json, dict) else {}
    explicit = str(metadata.get("enforcement_profile") or "").strip().lower()
    if explicit in STRICTNESS_PROFILE_RANK:
        return explicit
    return RISK_TIER_STRICTNESS_PROFILE.get(str(ai_system.risk_tier or "").strip().upper(), "baseline")


def _governance_state(ai_system: AISystem | None) -> str:
    if ai_system is None:
        return "UNKNOWN"
    metadata = ai_system.metadata_json if isinstance(ai_system.metadata_json, dict) else {}
    explicit = str(metadata.get("governance_state") or "").strip().upper()
    if explicit:
        return explicit
    return "UNKNOWN"


def _controls_and_frameworks(
    db: Session,
    *,
    tenant_id: str,
    control_ids: list[str],
) -> tuple[list[Control], list[str]]:
    if not control_ids:
        return [], []
    rows = db.scalars(
        select(Control).where(
            Control.id.in_(control_ids),
            Control.tenant_id == tenant_id,
        )
    ).all()
    frameworks: list[str] = []
    for row in rows:
        for item in (row.mapped_framework_refs or []):
            if isinstance(item, dict):
                framework = str(item.get("framework") or "").strip()
                if framework:
                    frameworks.append(framework)
    return rows, _unique_strings(frameworks)


def _recent_simulation_failures(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    control_ids: list[str],
    limit: int = 50,
) -> tuple[int, list[str]]:
    if not ai_system_id:
        return 0, []
    runs = db.scalars(
        select(SimulationRun)
        .where(
            SimulationRun.tenant_id == tenant_id,
            SimulationRun.ai_system_id == ai_system_id,
        )
        .order_by(SimulationRun.started_at.desc())
        .limit(limit)
    ).all()
    failures = 0
    failed_run_ids: list[str] = []
    control_set = set(control_ids)
    for run in runs:
        result = str((run.results or {}).get("result") or "fail").strip().lower()
        if result == "pass":
            continue
        if control_set:
            mapped = set(str(item.get("control_id")) for item in (run.controls_impacted or []) if isinstance(item, dict))
            result_delta = set(
                str(item.get("control_id"))
                for item in ((run.results or {}).get("control_maturity_delta") or [])
                if isinstance(item, dict)
            )
            if not mapped.intersection(control_set) and not result_delta.intersection(control_set):
                continue
        failures += 1
        failed_run_ids.append(run.id)
    return failures, failed_run_ids


def _maturity_score(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    control_ids: list[str],
) -> float | None:
    if not ai_system_id or not control_ids:
        return None
    rows = db.scalars(
        select(ControlMaturity).where(
            ControlMaturity.tenant_id == tenant_id,
            ControlMaturity.ai_system_id == ai_system_id,
            ControlMaturity.control_id.in_(control_ids),
        )
    ).all()
    if not rows:
        return None
    total = sum(float(row.maturity_score or 0.0) for row in rows)
    return round(total / float(len(rows)), 4)


def _collect_citations(
    *,
    evidence_nodes: list[EvidenceNode],
    snapshots: list[AuditorSnapshot],
) -> list[FindingAnalysisCitation]:
    citations: list[FindingAnalysisCitation] = []
    for row in evidence_nodes:
        citations.append(
            FindingAnalysisCitation(
                type="evidence_node",
                id=row.id,
                note=row.signal_type or row.label,
                ts=_as_iso(row.created_at),
            )
        )
    for row in snapshots:
        citations.append(
            FindingAnalysisCitation(
                type="snapshot",
                id=row.id,
                note=row.trigger_type,
                ts=_as_iso(row.created_at),
            )
        )
    return citations


def _policy_label(
    db: Session,
    *,
    tenant_id: str,
    policy_version_id: str | None,
) -> str:
    if not policy_version_id:
        return "none"
    version = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == tenant_id,
        )
    )
    if version is None:
        return policy_version_id
    pack = db.scalar(
        select(PolicyPack).where(
            PolicyPack.id == version.pack_id,
            PolicyPack.tenant_id == tenant_id,
        )
    )
    if pack is None:
        return f"{version.version} ({version.id})"
    return f"{pack.name} {version.version} ({version.id})"


def _proposed_steps(
    *,
    ai_system_id: str | None,
    control_ids: list[str],
    policy_version_id: str | None,
    degraded: bool,
) -> list[FindingAnalysisStep]:
    steps: list[FindingAnalysisStep] = []
    if policy_version_id:
        steps.append(
            FindingAnalysisStep(
                tool="policies.get_guardian_matrix",
                args={"policy_version_id": policy_version_id},
                reason="Review active guardian enforcement mapped to this finding.",
            )
        )
    if ai_system_id:
        steps.append(
            FindingAnalysisStep(
                tool="enforcement.list_events",
                args={"filters": {"ai_system_id": ai_system_id}, "limit": 20, "cursor": "0"},
                reason="Confirm recent enforcement behavior for the affected AI system.",
            )
        )
    for control_id in control_ids[:2]:
        steps.append(
            FindingAnalysisStep(
                tool="simulations.list_for_control",
                args={"control_id": control_id, "ai_system_id": ai_system_id},
                reason="Inspect recent validation coverage and outcomes for impacted controls.",
            )
        )
        if degraded and ai_system_id:
            steps.append(
                FindingAnalysisStep(
                    tool="simulations.run",
                    args={"simulation_id": "", "ai_system_id": ai_system_id},
                    reason=f"Run targeted validation for control {control_id} using an approved simulation id.",
                )
            )
    if ai_system_id:
        steps.append(
            FindingAnalysisStep(
                tool="auditor.create_snapshot",
                args={"framework": "NIST-AI-RMF", "period": {"days": 30}, "ai_system_id": ai_system_id},
                reason="Generate current audit proof pack for this finding context.",
            )
        )
    return steps


def analyze_finding(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
    actor_user_id: str | None,
    correlation_id: str | None,
) -> FindingAnalysisResult:
    finding = db.scalar(
        select(Finding).where(
            Finding.finding_id == finding_id,
            Finding.tenant_id == tenant_id,
        )
    )
    if finding is None:
        raise ValueError("Finding not found for tenant")

    ai_system = None
    if finding.ai_system_id:
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.id == finding.ai_system_id,
                AISystem.tenant_id == tenant_id,
            )
        )

    evidence_ids = _unique_strings(list(finding.evidence_node_ids or []))
    evidence_nodes = (
        db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id.in_(evidence_ids),
            )
        ).all()
        if evidence_ids
        else []
    )
    evidence_nodes = sorted(evidence_nodes, key=lambda row: (row.created_at, row.id), reverse=True)[:20]

    snapshots = db.scalars(
        select(AuditorSnapshot)
        .where(
            AuditorSnapshot.tenant_id == tenant_id,
            AuditorSnapshot.ai_system_id == finding.ai_system_id if finding.ai_system_id else AuditorSnapshot.ai_system_id.is_(None),
        )
        .order_by(AuditorSnapshot.created_at.desc())
        .limit(5)
    ).all()

    control_ids = _unique_strings(list(finding.related_control_ids or []))
    controls, frameworks = _controls_and_frameworks(
        db,
        tenant_id=tenant_id,
        control_ids=control_ids,
    )

    strictness_profile = _strictness_profile(ai_system)
    strictness_rank = STRICTNESS_PROFILE_RANK.get(strictness_profile, 0)
    risk_tier = str(ai_system.risk_tier or "UNKNOWN").strip().upper() if ai_system else "UNKNOWN"
    governance_status = _governance_state(ai_system)
    recent_failures, failed_run_ids = _recent_simulation_failures(
        db,
        tenant_id=tenant_id,
        ai_system_id=finding.ai_system_id,
        control_ids=control_ids,
    )
    maturity_score = _maturity_score(
        db,
        tenant_id=tenant_id,
        ai_system_id=finding.ai_system_id,
        control_ids=control_ids,
    )
    policy_label = _policy_label(
        db,
        tenant_id=tenant_id,
        policy_version_id=finding.policy_version_id,
    )

    citations = _collect_citations(evidence_nodes=evidence_nodes, snapshots=snapshots)
    missing_evidence: list[str] = []
    if not evidence_nodes:
        missing_evidence.append("No evidence nodes are linked to the finding.")
    if not control_ids:
        missing_evidence.append("Finding has no related controls.")
    if finding.ai_system_id and ai_system is None:
        missing_evidence.append("Linked AI system is missing from tenant scope.")

    if missing_evidence:
        proposed_actions = _proposed_steps(
            ai_system_id=finding.ai_system_id,
            control_ids=control_ids,
            policy_version_id=finding.policy_version_id,
            degraded=True,
        )
        out = FindingAnalysisResult(
            answer="INSUFFICIENT EVIDENCE",
            summary="INSUFFICIENT EVIDENCE",
            why_it_matters="Required governance and control-state evidence is missing, so Brain cannot produce a defensible recommendation.",
            controls=control_ids,
            frameworks=frameworks,
            recommended_action="Collect missing evidence before taking remediation actions.",
            proposed_next_steps=proposed_actions,
            citations=[],
            confidence=0.0,
            missing_evidence=missing_evidence,
            proposed_actions=proposed_actions,
        )
    else:
        degraded = bool(
            recent_failures >= 2
            or (maturity_score is not None and maturity_score < 0.6)
            or governance_status != "APPROVED"
        )
        if governance_status != "APPROVED":
            recommended_action = (
                "Pause high-risk operations for this AI system and restore governance approval before further execution."
            )
        elif degraded and strictness_rank < 2:
            recommended_action = (
                "Tighten enforcement strictness and run targeted validation simulations on impacted controls."
            )
        elif degraded:
            recommended_action = (
                "Run immediate control validation and remediation for impacted controls, then reassess maturity before closure."
            )
        else:
            recommended_action = (
                "Maintain current enforcement posture and continue scheduled validation and monitoring for the finding scope."
            )

        proposed_next_steps = _proposed_steps(
            ai_system_id=finding.ai_system_id,
            control_ids=control_ids,
            policy_version_id=finding.policy_version_id,
            degraded=degraded,
        )
        summary = (
            f"Finding {finding.finding_id} ({finding.finding_type}, severity={finding.severity}) "
            f"is mapped to {len(control_ids)} controls with governance={governance_status}, "
            f"risk_tier={risk_tier}, strictness={strictness_profile}, recent_sim_failures={recent_failures}, "
            f"maturity_score={maturity_score if maturity_score is not None else 'n/a'}."
        )
        why = (
            f"Policy context {policy_label} and live validation state show "
            f"{'degraded control assurance' if degraded else 'stable control assurance'}, "
            f"which changes remediation urgency and enforcement actions."
        )
        confidence = min(1.0, round(0.35 + (0.1 * len(evidence_nodes)) + (0.05 * len(snapshots)), 4))
        out = FindingAnalysisResult(
            answer="ANALYZED",
            summary=summary,
            why_it_matters=why,
            controls=control_ids,
            frameworks=frameworks,
            recommended_action=recommended_action,
            proposed_next_steps=proposed_next_steps,
            citations=citations,
            confidence=confidence,
            missing_evidence=[],
            proposed_actions=[],
        )

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="brain.findings.analyze",
        resource_type="finding",
        resource_id=finding.finding_id,
        payload={
            "answer": out.answer,
            "risk_tier": risk_tier,
            "governance_status": governance_status,
            "enforcement_strictness": strictness_profile,
            "recent_simulation_failures": recent_failures,
            "maturity_score": maturity_score,
            "citation_ids": [row.id for row in out.citations],
            "missing_evidence": out.missing_evidence,
        },
        correlation_id=correlation_id,
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="brain_finding_analysis",
        signal_type="brain.findings.analyze",
        label=f"Brain finding analysis {finding.finding_id}",
        payload={
            "finding_id": finding.finding_id,
            "answer": out.answer,
            "risk_tier": risk_tier,
            "governance_status": governance_status,
            "enforcement_strictness": strictness_profile,
            "recent_simulation_failures": recent_failures,
            "failed_simulation_run_ids": failed_run_ids,
            "maturity_score": maturity_score,
            "policy_version_id": finding.policy_version_id,
            "audit_log_id": audit.id,
            "citations": [row.model_dump() for row in out.citations],
        },
        correlation_id=correlation_id,
    )
    return out
