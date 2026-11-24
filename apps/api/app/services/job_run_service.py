from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from app.db.models.job_run import ScheduledJobRun
from app.db.session import SessionLocal


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def write_scheduled_job_run(
    *,
    job_name: str,
    status: str,
    started_at: datetime,
    finished_at: datetime,
    tenant_id: str | None = None,
    error_message: str | None = None,
) -> ScheduledJobRun:
    db = SessionLocal()
    try:
        row = ScheduledJobRun(
            job_name=job_name,
            tenant_id=tenant_id,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            error_message=error_message,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()


def write_dead_letter_job_run(
    *,
    job_name: str,
    tenant_id: str | None = None,
    error_message: str | None = None,
) -> ScheduledJobRun:
    now = _utcnow()
    return write_scheduled_job_run(
        job_name=job_name,
        tenant_id=tenant_id,
        started_at=now,
        finished_at=now,
        status="dead_letter",
        error_message=(error_message or "")[:4000] or None,
    )


@contextmanager
def tracked_scheduled_job(job_name: str, tenant_id: str | None = None) -> Iterator[None]:
    started_at = _utcnow()
    try:
        yield
    except Exception as exc:
        write_scheduled_job_run(
            job_name=job_name,
            tenant_id=tenant_id,
            started_at=started_at,
            finished_at=_utcnow(),
            status="fail",
            error_message=str(exc)[:4000],
        )
        raise
    else:
        write_scheduled_job_run(
            job_name=job_name,
            tenant_id=tenant_id,
            started_at=started_at,
            finished_at=_utcnow(),
            status="success",
            error_message=None,
        )
