from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.knowledge_base import (
    KBControl,
    KBControlGuardianMap,
    KBControlSimMap,
    KBDoc,
    KBFramework,
    KBGuardianContract,
    KBSimulationTemplate,
)


_TOKEN_RE = re.compile(r"[a-zA-Z0-9_.-]+")


@dataclass(frozen=True)
class _ScoredRow:
    id: str
    score: float


def _tokenize(value: str) -> set[str]:
    return {match.group(0).lower() for match in _TOKEN_RE.finditer(value or "")}


def _text_score(question_tokens: set[str], *parts: str) -> float:
    haystack_tokens = _tokenize(" ".join(parts))
    if not question_tokens or not haystack_tokens:
        return 0.0
    overlap = question_tokens.intersection(haystack_tokens)
    if not overlap:
        return 0.0
    return round(len(overlap) / max(1.0, len(question_tokens)), 6)


def _strength_weight(enforcement_strength: str) -> float:
    normalized = str(enforcement_strength or "").strip().lower()
    if normalized == "maximum":
        return 1.5
    if normalized == "strict":
        return 1.0
    return 0.5


def _frequency_weight(required_frequency: str) -> float:
    normalized = str(required_frequency or "").strip().lower()
    if normalized == "daily":
        return 1.2
    if normalized == "weekly":
        return 1.0
    if normalized == "on_change":
        return 0.8
    return 0.6


def _framework_filter_ids(db: Session, frameworks_in_scope: list[str] | None) -> set[str] | None:
    if not frameworks_in_scope:
        return None
    values = {item.strip().lower() for item in frameworks_in_scope if item and item.strip()}
    if not values:
        return None

    frameworks = db.scalars(select(KBFramework)).all()
    selected: set[str] = set()
    for framework in frameworks:
        if framework.id.lower() in values or framework.name.lower() in values:
            selected.add(framework.id)
    return selected if selected else set()


def retrieve_knowledge_bundle(
    db: Session,
    *,
    question: str,
    tenant_id: str,
    ai_system_id: str | None = None,
    frameworks_in_scope: list[str] | None = None,
    max_controls: int = 12,
    max_guardians: int = 8,
    max_sim_templates: int = 8,
    max_docs: int = 8,
) -> dict[str, Any]:
    _ = tenant_id
    _ = ai_system_id

    question_tokens = _tokenize(question)
    framework_ids = _framework_filter_ids(db, frameworks_in_scope)

    controls_query = select(KBControl)
    if framework_ids is not None:
        if not framework_ids:
            controls: list[KBControl] = []
        else:
            controls = db.scalars(controls_query.where(KBControl.framework_id.in_(framework_ids))).all()
    else:
        controls = db.scalars(controls_query).all()

    scored_controls: list[tuple[KBControl, float]] = []
    for control in controls:
        tags = control.applicability_tags if isinstance(control.applicability_tags, list) else []
        tag_blob = " ".join(str(tag) for tag in tags)
        base_score = _text_score(question_tokens, control.id, control.title, control.objective, tag_blob)
        if control.requirement_level == "MUST":
            base_score += 0.2
        if frameworks_in_scope and framework_ids and control.framework_id in framework_ids:
            base_score += 0.1
        scored_controls.append((control, round(base_score, 6)))

    scored_controls.sort(key=lambda row: (-row[1], row[0].id))
    top_controls = scored_controls[: max(1, max_controls)]
    top_control_ids = [control.id for control, _score in top_controls]

    guardian_map_rows = (
        db.scalars(select(KBControlGuardianMap).where(KBControlGuardianMap.control_id.in_(top_control_ids)))
        if top_control_ids
        else []
    )
    guardian_maps = list(guardian_map_rows) if top_control_ids else []
    guardian_ids = {row.guardian_contract_id for row in guardian_maps}

    guardians = (
        db.scalars(select(KBGuardianContract).where(KBGuardianContract.id.in_(guardian_ids))).all()
        if guardian_ids
        else []
    )
    control_score_by_id = {control.id: score for control, score in top_controls}

    scored_guardians: list[_ScoredRow] = []
    for guardian in guardians:
        related_maps = [row for row in guardian_maps if row.guardian_contract_id == guardian.id]
        weighted = 0.0
        for mapping in related_maps:
            weighted = max(
                weighted,
                control_score_by_id.get(mapping.control_id, 0.0) + _strength_weight(mapping.enforcement_strength),
            )
        weighted += _text_score(question_tokens, guardian.name, guardian.intent)
        scored_guardians.append(_ScoredRow(id=guardian.id, score=round(weighted, 6)))
    scored_guardians.sort(key=lambda row: (-row.score, row.id))

    sim_map_rows = (
        db.scalars(select(KBControlSimMap).where(KBControlSimMap.control_id.in_(top_control_ids))) if top_control_ids else []
    )
    sim_maps = list(sim_map_rows) if top_control_ids else []
    sim_ids = {row.simulation_template_id for row in sim_maps}
    sim_templates = (
        db.scalars(select(KBSimulationTemplate).where(KBSimulationTemplate.id.in_(sim_ids))).all()
        if sim_ids
        else []
    )

    scored_templates: list[_ScoredRow] = []
    for template in sim_templates:
        related_maps = [row for row in sim_maps if row.simulation_template_id == template.id]
        weighted = 0.0
        for mapping in related_maps:
            weighted = max(
                weighted,
                control_score_by_id.get(mapping.control_id, 0.0) + _frequency_weight(mapping.required_frequency),
            )
        weighted += _text_score(question_tokens, template.name, template.category)
        scored_templates.append(_ScoredRow(id=template.id, score=round(weighted, 6)))
    scored_templates.sort(key=lambda row: (-row.score, row.id))

    docs_query = select(KBDoc).where(KBDoc.source_type == "authored")
    if framework_ids is not None:
        if not framework_ids:
            docs: list[KBDoc] = []
        else:
            docs = db.scalars(docs_query.where(KBDoc.framework_id.in_(framework_ids))).all()
    else:
        docs = db.scalars(docs_query).all()

    scored_docs: list[_ScoredRow] = []
    for doc in docs:
        score = _text_score(question_tokens, doc.title, doc.body)
        scored_docs.append(_ScoredRow(id=doc.id, score=round(score, 6)))
    scored_docs.sort(key=lambda row: (-row.score, row.id))

    evidence_hooks = [
        {
            "tool": "evidence.query",
            "args": {
                "time_range": {},
                "filters": {
                    "node_type": "control_evidence",
                    "control_ids": top_control_ids[:5],
                },
                "limit": 50,
                "cursor": "0",
            },
        }
    ]
    if ai_system_id:
        evidence_hooks.append(
            {
                "tool": "enforcement.list_events",
                "args": {
                    "filters": {"ai_system_id": ai_system_id},
                    "limit": 50,
                    "cursor": "0",
                },
            }
        )

    return {
        "top_controls": [
            {
                "control_id": control.id,
                "framework_id": control.framework_id,
                "score": score,
            }
            for control, score in top_controls
        ],
        "top_guardian_contracts": [
            {
                "guardian_contract_id": row.id,
                "score": row.score,
            }
            for row in scored_guardians[: max(1, max_guardians)]
        ],
        "top_sim_templates": [
            {
                "simulation_template_id": row.id,
                "score": row.score,
            }
            for row in scored_templates[: max(1, max_sim_templates)]
        ],
        "top_docs": [
            {
                "doc_id": row.id,
                "source_type": "authored",
                "score": row.score,
            }
            for row in scored_docs[: max(1, max_docs)]
        ],
        "evidence_hooks": evidence_hooks,
    }
