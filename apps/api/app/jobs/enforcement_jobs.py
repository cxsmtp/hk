from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app.db.models.enforcement import EnforcementEvent
from app.db.models.policy import ApprovalRequest
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.ai_system_approval_service import expire_due, is_ai_system_approval_request
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.job_run_service import tracked_scheduled_job


TIMEOUT_DECISIONS = {"block", "warn"}


def _normalize_timeout_decision(value: str | None) -> str:
    candidate = (value or "block").strip().lower()
    if candidate in TIMEOUT_DECISIONS:
        return candidate
    return "block"


@celery_app.task(name="app.jobs.enforcement_jobs.resolve_timed_out_approvals")
def resolve_timed_out_approvals(tenant_id: str | None = None, batch_limit: int = 200) -> dict:
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        query = select(ApprovalRequest).where(ApprovalRequest.status == "pending")
        if tenant_id:
            query = query.where(ApprovalRequest.tenant_id == tenant_id)

        pending = db.scalars(query.order_by(ApprovalRequest.created_at.asc())).all()

        resolved_ids: list[str] = []
        for req in pending:
            if is_ai_system_approval_request(req):
                # Expired by expire_ai_system_approvals, which also puts the AI system back as it was.
                continue
            created_at = req.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)

            deadline = created_at + timedelta(minutes=int(req.sla_minutes))
            if deadline > now:
                continue

            timeout_decision = _normalize_timeout_decision(req.default_if_timeout)
            transition = db.execute(
                update(ApprovalRequest)
                .where(
                    ApprovalRequest.id == req.id,
                    ApprovalRequest.status == "pending",
                )
                .values(
                    status="timed_out",
                    decision=f"timeout_{timeout_decision}",
                    decided_at=now,
                    decided_by=None,
                )
                .execution_options(synchronize_session=False)
            )
            if transition.rowcount != 1:
                continue
            db.flush()
            db.refresh(req)

            timeout_node_id: str | None = None
            if req.enforcement_event_id:
                event = db.scalar(
                    select(EnforcementEvent).where(
                        EnforcementEvent.id == req.enforcement_event_id,
                        EnforcementEvent.tenant_id == req.tenant_id,
                    )
                )
                if event:
                    event.final_decision = timeout_decision
                    actions = dict(event.final_actions or {})
                    actions["approval_timeout"] = {
                        "approval_request_id": req.id,
                        "default_if_timeout": timeout_decision,
                        "resolved_at": now.isoformat(),
                    }
                    event.final_actions = actions

                    timeout_node = create_evidence_node(
                        db,
                        tenant_id=req.tenant_id,
                        node_type="approval_timeout",
                        signal_type="approval.timeout.auto_resolved",
                        label=f"Approval timeout {req.id}",
                        payload={
                            "approval_request_id": req.id,
                            "enforcement_event_id": event.id,
                            "decision": timeout_decision,
                        },
                    )
                    timeout_node_id = timeout_node.id

                    existing_nodes = list(event.evidence_nodes_created or [])
                    if existing_nodes:
                        try:
                            link_evidence_nodes(
                                db,
                                tenant_id=req.tenant_id,
                                from_node_id=existing_nodes[0],
                                to_node_id=timeout_node.id,
                                edge_type="resolved",
                                payload={"approval_request_id": req.id},
                            )
                        except ValueError:
                            pass

                    existing_nodes.append(timeout_node.id)
                    event.evidence_nodes_created = existing_nodes

            write_audit_log(
                db,
                tenant_id=req.tenant_id,
                actor_user_id=None,
                actor_type="system",
                action="approval.timeout.auto_resolve",
                resource_type="approval_request",
                resource_id=req.id,
                payload={
                    "decision": timeout_decision,
                    "enforcement_event_id": req.enforcement_event_id,
                    "timeout_evidence_node_id": timeout_node_id,
                },
            )

            resolved_ids.append(req.id)
            if len(resolved_ids) >= batch_limit:
                break

        db.commit()
        return {
            "tenant_id": tenant_id,
            "resolved_count": len(resolved_ids),
            "resolved_approval_ids": resolved_ids,
        }
    finally:
        db.close()


@celery_app.task(name="app.jobs.enforcement_jobs.run_sla_timeout_checks")
def run_sla_timeout_checks() -> dict:
    with tracked_scheduled_job("approval_sla_timeout", tenant_id=None):
        return resolve_timed_out_approvals(tenant_id=None, batch_limit=500)


@celery_app.task(name="app.jobs.enforcement_jobs.expire_ai_system_approvals")
def expire_ai_system_approvals(tenant_id: str | None = None, batch_limit: int = 500) -> dict:
    """Time-bound AI system approvals whose time is up, and approval requests that waited too long: the systems go to
    pending re-approval (or back to where they were), each with an audit entry and evidence
    (app/services/ai_system_approval_service.py)."""

    with tracked_scheduled_job("ai_system_approval_expiry", tenant_id=tenant_id):
        db = SessionLocal()
        try:
            result = expire_due(db, tenant_id=tenant_id, batch_limit=batch_limit)
            db.commit()
            return {"tenant_id": tenant_id, **result}
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


@celery_app.task(name="app.jobs.enforcement_jobs.ocr_extract_text")
def ocr_extract_text(
    *,
    file_name: str | None = None,
    mime_type: str | None = None,
    content_b64: str | None = None,
) -> str:
    if not content_b64:
        return ""
    import base64

    from app.services.sensitive_data_detection_service import extract_text_from_binary_for_ocr_task

    try:
        content = base64.b64decode(content_b64.encode("utf-8"), validate=False)
    except Exception:
        return ""

    return extract_text_from_binary_for_ocr_task(
        file_name=file_name,
        mime_type=mime_type,
        content_bytes=content,
    )
