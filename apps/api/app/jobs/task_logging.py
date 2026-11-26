"""Celery tasks in the log (app/core/log_config.py): a line when a task starts, finishes, is retried or fails, with its
name, id, how long it took and how many retries so far; and every line logged during a task carries its task_id,
task_name, tenant_id (when the task was given one) and the request_id of the API request that queued it.

Connected by app/jobs/celery_app.py. Never the task's arguments: only a tenant id taken from them.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from celery.signals import before_task_publish, task_failure, task_postrun, task_prerun, task_retry

from app.core.log_config import bind_log_context, get_log_context, reset_log_context, safe_id

logger = logging.getLogger("app.jobs.tasks")

#: The message header that carries the queuing request's id to the worker.
REQUEST_ID_HEADER = "hawk_request_id"

_running: dict[str, tuple[float, Any]] = {}
_running_lock = threading.Lock()


def _tenant_of(kwargs: Any) -> str | None:
    if isinstance(kwargs, dict):
        value = kwargs.get("tenant_id")
        if isinstance(value, str):
            return safe_id(value)
    return None


def _retries(task: Any) -> int:
    try:
        return int(getattr(getattr(task, "request", None), "retries", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _duration_ms(task_id: str | None) -> float | None:
    with _running_lock:
        entry = _running.get(str(task_id))
    if entry is None:
        return None
    return round((time.perf_counter() - entry[0]) * 1000.0, 2)


@before_task_publish.connect
def _on_publish(headers: dict | None = None, **_: Any) -> None:
    """A task queued during an API request (or another task) carries that request's id to the worker."""

    request_id = get_log_context().get("request_id")
    if request_id and isinstance(headers, dict):
        headers.setdefault(REQUEST_ID_HEADER, request_id)


@task_prerun.connect
def _on_prerun(task_id: str | None = None, task: Any = None, args: Any = None, kwargs: Any = None, **_: Any) -> None:
    del args
    request = getattr(task, "request", None)
    request_id = safe_id(getattr(request, REQUEST_ID_HEADER, None))
    name = getattr(task, "name", None) or "unknown"
    token = bind_log_context(task_id=task_id, task_name=name, request_id=request_id, tenant_id=_tenant_of(kwargs))
    with _running_lock:
        _running[str(task_id)] = (time.perf_counter(), token)
    logger.info("Task started: %s", name, extra={"retries": _retries(task)})


@task_retry.connect
def _on_retry(sender: Any = None, request: Any = None, reason: Any = None, **_: Any) -> None:
    name = getattr(sender, "name", None) or "unknown"
    task_id = getattr(request, "id", None)
    retries = int(getattr(request, "retries", 0) or 0)
    logger.warning(
        "Task will be retried: %s (%s)",
        name,
        type(reason).__name__ if isinstance(reason, BaseException) else "retry",
        extra={"retries": retries, "duration_ms": _duration_ms(task_id)},
    )


@task_failure.connect
def _on_failure(sender: Any = None, task_id: str | None = None, exception: BaseException | None = None, **_: Any) -> None:
    name = getattr(sender, "name", None) or "unknown"
    exc_info = (type(exception), exception, exception.__traceback__) if isinstance(exception, BaseException) else None
    logger.error(
        "Task failed: %s",
        name,
        exc_info=exc_info,
        extra={"retries": _retries(sender), "duration_ms": _duration_ms(task_id)},
    )


@task_postrun.connect
def _on_postrun(task_id: str | None = None, task: Any = None, state: str | None = None, **_: Any) -> None:
    with _running_lock:
        entry = _running.pop(str(task_id), None)
    duration_ms = round((time.perf_counter() - entry[0]) * 1000.0, 2) if entry else None
    try:
        # Failures and retries have their own lines (above).
        if state not in {"FAILURE", "RETRY"}:
            logger.info(
                "Task finished: %s",
                getattr(task, "name", None) or "unknown",
                extra={"state": state or "unknown", "retries": _retries(task), "duration_ms": duration_ms},
            )
    finally:
        if entry is not None:
            reset_log_context(entry[1])
