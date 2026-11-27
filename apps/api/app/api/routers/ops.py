from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope
from app.core.config import settings
from app.core.observability import (
    banking_runtime_metrics,
    latency_tracker,
)
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.job_run import ScheduledJobRun
from app.db.models.policy import ApprovalRequest
from app.db.session import get_db
from app.services.self_recovery import DIAGNOSTICS_URL, job_reference, plain_job_failure


router = APIRouter(prefix="/ops", tags=["ops"])


class ScheduledJobRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_name: str
    tenant_id: str | None = None
    started_at: datetime
    finished_at: datetime
    status: str
    error_message: str | None = None
    #: For a job of the whole installation that failed: its reference (the diagnostics bundle lists it) and where an
    #: owner or admin downloads the bundle. Its error's text is never shown here.
    reference: str | None = None
    diagnostics_url: str | None = None


def job_run_view(run: ScheduledJobRun) -> ScheduledJobRunResponse:
    """One run as every tenant sees it: a job of the whole installation that failed says when and its reference, in
    plain words; its error (which can name other tenants, hosts or internals) stays in the diagnostics bundle."""

    item = ScheduledJobRunResponse.model_validate(run)
    if run.tenant_id is None and str(run.status) != "success":
        return item.model_copy(update={"error_message": plain_job_failure(run), "reference": job_reference(run.id), "diagnostics_url": DIAGNOSTICS_URL})
    return item


class JobStatusItemResponse(BaseModel):
    job_name: str
    runs: list[ScheduledJobRunResponse]


class PathLatencyResponse(BaseModel):
    count: int
    p50_ms: float | None = None
    p95_ms: float | None = None
    p99_ms: float | None = None


class OutcomePathLatencyResponse(PathLatencyResponse):
    max_ms: float | None = None
    error_rate: float
    timeout_count: int


class CeleryQueueDepthResponse(BaseModel):
    queues: dict[str, int | None]
    error: str | None = None


class OpsMetricsResponse(BaseModel):
    generated_at: datetime
    gateway_latency: dict[str, PathLatencyResponse]
    banking_runtime: "BankingRuntimeMetricsResponse"
    approvals_queue_depth: int
    celery_queue_depth: CeleryQueueDepthResponse


class BankingRuntimeMetricsResponse(BaseModel):
    window_seconds: int
    actions_per_second: float
    decisions_per_second: float
    blocked_per_second: float
    approval_rate: float
    event_counts: dict[str, int]
    latency: dict[str, OutcomePathLatencyResponse]
    transport_latency: dict[str, OutcomePathLatencyResponse]


def _read_celery_queue_depth() -> CeleryQueueDepthResponse:
    queue_names = ("celery", "auditor", "monitoring")
    default_map: dict[str, int | None] = {name: None for name in queue_names}
    redis_client: Redis | None = None
    try:
        redis_client = Redis.from_url(settings.celery_broker_url)
        queues = {name: int(redis_client.llen(name)) for name in queue_names}
        return CeleryQueueDepthResponse(queues=queues, error=None)
    except (RedisError, ValueError) as exc:
        return CeleryQueueDepthResponse(queues=default_map, error=str(exc))
    finally:
        if redis_client is not None:
            redis_client.close()


@router.get("/jobs/status", response_model=ListEnvelope[JobStatusItemResponse])
def list_job_status(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    limit_per_job: int = Query(default=5, ge=1, le=50),
    ctx: TenantContext = Depends(require_permission("monitoring.review")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(ScheduledJobRun)
        .where(or_(ScheduledJobRun.tenant_id == ctx.tenant.id, ScheduledJobRun.tenant_id.is_(None)))
        .order_by(ScheduledJobRun.started_at.desc())
        .limit(1000)
    ).all()

    grouped: dict[str, list[ScheduledJobRun]] = {}
    for row in rows:
        bucket = grouped.setdefault(row.job_name, [])
        if len(bucket) < limit_per_job:
            bucket.append(row)

    items = [
        JobStatusItemResponse(
            job_name=job_name,
            runs=[job_run_view(run) for run in runs],
        )
        for job_name, runs in sorted(grouped.items())
    ]
    start = (page - 1) * page_size
    end = start + page_size
    return ListEnvelope[JobStatusItemResponse](
        items=items[start:end],
        total=len(items),
        page=page,
        page_size=page_size,
    )


@router.get("/metrics", response_model=OpsMetricsResponse)
def ops_metrics(
    ctx: TenantContext = Depends(require_permission("monitoring.review")),
    db: Session = Depends(get_db),
):
    pending_approvals = db.scalar(
        select(func.count())
        .select_from(ApprovalRequest)
        .where(
            ApprovalRequest.tenant_id == ctx.tenant.id,
            ApprovalRequest.status == "pending",
        )
    )
    latency_summary = latency_tracker.gateway_summary()
    gateway_latency = {
        path: PathLatencyResponse(**summary)
        for path, summary in latency_summary.items()
    }
    banking_snapshot = banking_runtime_metrics.snapshot(ctx.tenant.id)
    banking_runtime_latency = {
        path: OutcomePathLatencyResponse(**summary)
        for path, summary in dict(banking_snapshot["latency"]).items()
    }
    banking_transport_latency = {
        transport: OutcomePathLatencyResponse(**summary)
        for transport, summary in dict(
            banking_snapshot["transport_latency"]
        ).items()
    }
    banking_runtime = BankingRuntimeMetricsResponse(
        **{
            key: value
            for key, value in banking_snapshot.items()
            if key not in {"latency", "transport_latency"}
        },
        latency=banking_runtime_latency,
        transport_latency=banking_transport_latency,
    )
    return OpsMetricsResponse(
        generated_at=datetime.now(timezone.utc),
        gateway_latency=gateway_latency,
        banking_runtime=banking_runtime,
        approvals_queue_depth=int(pending_approvals or 0),
        celery_queue_depth=_read_celery_queue_depth(),
    )
