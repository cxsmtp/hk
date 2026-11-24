from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.brain import BrainArbitration, BrainModelCall, BrainPlanRecord, BrainSession, BrainToolCall


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_brain_session(db: Session, *, tenant_id: str, user_id: str) -> BrainSession:
    row = BrainSession(
        tenant_id=tenant_id,
        user_id=user_id,
    )
    db.add(row)
    db.flush()
    return row


def save_brain_plan(
    db: Session,
    *,
    session_id: str,
    question: str,
    plan_json: dict[str, Any],
) -> BrainPlanRecord:
    row = BrainPlanRecord(
        session_id=session_id,
        question=question,
        plan_json=plan_json,
    )
    db.add(row)
    db.flush()
    return row


def update_brain_plan_json(
    db: Session,
    *,
    plan: BrainPlanRecord,
    plan_json: dict[str, Any],
) -> BrainPlanRecord:
    plan.plan_json = plan_json
    db.flush()
    return plan


def get_brain_plan_for_tenant(db: Session, *, tenant_id: str, plan_id: str) -> BrainPlanRecord | None:
    return db.scalar(
        select(BrainPlanRecord)
        .join(BrainSession, BrainSession.id == BrainPlanRecord.session_id)
        .where(
            BrainPlanRecord.id == plan_id,
            BrainSession.tenant_id == tenant_id,
        )
    )


def save_tool_call_start(
    db: Session,
    *,
    plan_id: str,
    tool_name: str,
    args_json: dict[str, Any],
) -> BrainToolCall:
    now = _utcnow()
    row = BrainToolCall(
        plan_id=plan_id,
        tool_name=tool_name,
        args_json=args_json,
        result_json={},
        status="fail",
        started_at=now,
        finished_at=now,
        error=None,
    )
    db.add(row)
    db.flush()
    return row


def save_tool_call_finish(
    db: Session,
    *,
    tool_call: BrainToolCall,
    status: str,
    result_json: dict[str, Any],
    error: str | None = None,
) -> BrainToolCall:
    tool_call.status = status
    tool_call.result_json = result_json
    tool_call.error = error
    tool_call.finished_at = _utcnow()
    db.flush()
    return tool_call


def save_model_call(
    db: Session,
    *,
    plan_id: str,
    task_type: str,
    provider: str,
    prompt_hash: str,
    output_hash: str,
    output_json: dict[str, Any],
) -> BrainModelCall:
    row = BrainModelCall(
        plan_id=plan_id,
        task_type=task_type,
        provider=provider,
        prompt_hash=prompt_hash,
        output_hash=output_hash,
        output_json=output_json,
    )
    db.add(row)
    db.flush()
    return row


def save_arbitration(
    db: Session,
    *,
    plan_id: str,
    task_type: str,
    winner: str | None,
    dissenters_json: list[str],
    reason_codes_json: list[str],
) -> BrainArbitration:
    row = BrainArbitration(
        plan_id=plan_id,
        task_type=task_type,
        winner=winner,
        dissenters_json=dissenters_json,
        reason_codes_json=reason_codes_json,
    )
    db.add(row)
    db.flush()
    return row
