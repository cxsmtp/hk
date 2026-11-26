from __future__ import annotations

import os
import time
import math
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from redis import Redis
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import get_correlation_id
from app.services.snapshot_service import ensure_artifact_storage_writable
from app.services.production_hardening import (
    ComponentHandshake,
    build_component_registration,
    compatibility_contract_from_settings,
)


CELERY_WORKER_HEARTBEAT_KEY = "control_plane:celery:worker_heartbeat"
CELERY_BEAT_HEARTBEAT_KEY = "control_plane:celery:beat_heartbeat"
CELERY_WORKER_COMPONENT_KEY = "control_plane:components:worker"
CELERY_BEAT_COMPONENT_KEY = "control_plane:components:celery_beat"
MIGRATIONS_RELATIVE_PATH = Path("app/db/migrations/alembic.ini")


@dataclass
class ControlPlaneCheckResult:
    ok: bool
    status: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "status": self.status, "detail": self.detail}


@dataclass
class ControlPlaneHealthReport:
    healthy: bool
    strict_mode: bool
    required_checks: list[str]
    checks: dict[str, ControlPlaneCheckResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "strict_mode": self.strict_mode,
            "required_checks": self.required_checks,
            "checks": {name: check.to_dict() for name, check in self.checks.items()},
        }

    def failing_required_checks(self) -> list[str]:
        return [name for name in self.required_checks if not self.checks[name].ok]


def _test_profile() -> str:
    return (os.getenv("TEST_PROFILE") or "").strip().lower()


def _skip_external_checks(strict_mode: bool) -> bool:
    return (not strict_mode) and _test_profile() == "unit"


def _heartbeat_max_age_seconds() -> int:
    configured = int(settings.control_plane_heartbeat_max_age_seconds)
    return max(configured, 1)


def _heartbeat_ttl_seconds() -> int:
    return max(_heartbeat_max_age_seconds() * 3, 120)


def _alembic_ini_path() -> Path:
    api_root = Path(__file__).resolve().parents[2]
    return api_root / MIGRATIONS_RELATIVE_PATH


def _redis_client() -> Redis:
    return Redis.from_url(
        settings.redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
        decode_responses=True,
    )


logger = logging.getLogger(__name__)


def _failed(what: str, exc: BaseException) -> str:
    """A failed check's detail, as the health page shows it: what failed and the kind of error, with the request id
    to find the whole message in the server log (a driver's message can name hosts, users, paths and statements)."""

    request_id = get_correlation_id() or ""
    logger.warning("Control plane check failed: %s", what, exc_info=exc, extra={"request_id": request_id, "reason_code": "control_plane_check_failed"})
    return f"{what} ({exc.__class__.__name__}{f'; request id {request_id}' if request_id else ''})"


def _check_database_connectivity(db: Session) -> ControlPlaneCheckResult:
    try:
        db.execute(text("SELECT 1"))
        return ControlPlaneCheckResult(ok=True, status="ok", detail="database reachable")
    except SQLAlchemyError as exc:
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail=_failed("database connectivity failed", exc))


def _check_migrations_applied(db: Session, *, strict_mode: bool) -> ControlPlaneCheckResult:
    if _test_profile() == "unit" and not strict_mode:
        return ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail="migration check skipped in unit profile",
        )

    alembic_ini = _alembic_ini_path()
    if not alembic_ini.exists():
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail="missing alembic config")

    try:
        connection = db.connection()
        context = MigrationContext.configure(connection)
        current_heads = set(context.get_current_heads())
    except SQLAlchemyError as exc:
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail=_failed("migration query failed", exc))
    except Exception as exc:
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail=_failed("migration context failed", exc))

    if not current_heads:
        return ControlPlaneCheckResult(ok=False, status="out_of_date", detail="no applied migrations found")

    try:
        config = Config(str(alembic_ini))
        script = ScriptDirectory.from_config(config)
        expected_heads = set(script.get_heads())
    except Exception as exc:
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail=_failed("migration head load failed", exc))

    if expected_heads != current_heads:
        return ControlPlaneCheckResult(
            ok=False,
            status="out_of_date",
            detail=f"migration heads mismatch expected={sorted(expected_heads)} current={sorted(current_heads)}",
        )

    return ControlPlaneCheckResult(ok=True, status="ok", detail="migrations at head")


def _check_redis_connectivity(*, strict_mode: bool) -> tuple[ControlPlaneCheckResult, Redis | None]:
    if _skip_external_checks(strict_mode):
        return (
            ControlPlaneCheckResult(ok=True, status="skipped", detail="redis check skipped in unit profile"),
            None,
        )

    try:
        client = _redis_client()
        if bool(client.ping()):
            return ControlPlaneCheckResult(ok=True, status="ok", detail="redis reachable"), client
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail="redis ping returned false"), client
    except Exception as exc:
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail=_failed("redis connectivity failed", exc)), None


def _check_celery_heartbeat(
    *,
    redis_client: Redis | None,
    key: str,
    actor: str,
    strict_mode: bool,
) -> ControlPlaneCheckResult:
    if _skip_external_checks(strict_mode):
        return ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail=f"{actor} heartbeat check skipped in unit profile",
        )

    if redis_client is None:
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail=f"{actor} heartbeat unavailable: redis unavailable")

    raw_value = redis_client.get(key)
    if raw_value is None:
        return ControlPlaneCheckResult(ok=False, status="stale", detail=f"{actor} heartbeat missing")

    try:
        beat_seconds = float(raw_value)
    except (TypeError, ValueError):
        return ControlPlaneCheckResult(ok=False, status="stale", detail=f"{actor} heartbeat malformed")

    now_seconds = time.time()
    if not math.isfinite(beat_seconds) or beat_seconds > now_seconds:
        return ControlPlaneCheckResult(ok=False, status="stale", detail=f"{actor} heartbeat future or malformed")

    age_seconds = now_seconds - beat_seconds
    max_age = _heartbeat_max_age_seconds()
    if age_seconds > max_age:
        return ControlPlaneCheckResult(
            ok=False,
            status="stale",
            detail=f"{actor} heartbeat stale age={round(age_seconds, 3)}s max_age={max_age}s",
        )

    return ControlPlaneCheckResult(
        ok=True,
        status="ok",
        detail=f"{actor} heartbeat age={round(age_seconds, 3)}s",
    )


def _check_component_registration(
    *,
    redis_client: Redis | None,
    key: str,
    expected_component_type: str,
    strict_mode: bool,
) -> ControlPlaneCheckResult:
    if _skip_external_checks(strict_mode):
        return ControlPlaneCheckResult(True, "skipped", f"{expected_component_type} compatibility skipped in unit profile")
    if redis_client is None:
        return ControlPlaneCheckResult(False, "unavailable", f"{expected_component_type} registration unavailable")
    raw_value = redis_client.get(key)
    if not raw_value:
        return ControlPlaneCheckResult(False, "stale", f"{expected_component_type} registration missing")
    try:
        payload = json.loads(raw_value)
    except (TypeError, json.JSONDecodeError):
        return ControlPlaneCheckResult(False, "incompatible", f"{expected_component_type} registration malformed")
    if not isinstance(payload, dict) or payload.get("schema_version") != "phase9/1.0":
        return ControlPlaneCheckResult(False, "incompatible", f"{expected_component_type} registration schema incompatible")
    if payload.get("component_type") != expected_component_type:
        return ControlPlaneCheckResult(False, "incompatible", f"{expected_component_type} registration type mismatch")
    try:
        handshake = ComponentHandshake(
            component_type=str(payload.get("component_type") or ""),
            component_version=str(payload.get("component_version") or ""),
            protocol_version=str(payload.get("protocol_version") or ""),
            deployment_id=str(payload.get("deployment_id") or ""),
            capability_version=str(payload.get("capability_version") or ""),
        )
        result = compatibility_contract_from_settings(settings).evaluate(handshake)
    except ValueError:
        return ControlPlaneCheckResult(False, "incompatible", f"{expected_component_type} compatibility contract invalid")
    if not result.accepted or not result.capability_verified:
        return ControlPlaneCheckResult(False, "incompatible", f"{expected_component_type} {result.reason_code}")
    return ControlPlaneCheckResult(True, "ok", f"{expected_component_type} version compatible")


def evaluate_component_runtime_health(
    *,
    heartbeat_key: str,
    component_key: str,
    component_type: str,
) -> ControlPlaneCheckResult:
    """Require both a fresh heartbeat and compatible component identity."""

    try:
        client = _redis_client()
        if not bool(client.ping()):
            return ControlPlaneCheckResult(False, "unavailable", "redis ping returned false")
    except Exception:
        return ControlPlaneCheckResult(False, "unavailable", "redis unavailable")

    heartbeat = _check_celery_heartbeat(
        redis_client=client,
        key=heartbeat_key,
        actor=component_type,
        strict_mode=True,
    )
    if not heartbeat.ok:
        return heartbeat
    registration = _check_component_registration(
        redis_client=client,
        key=component_key,
        expected_component_type=component_type,
        strict_mode=True,
    )
    if not registration.ok:
        return registration
    return ControlPlaneCheckResult(True, "ok", f"{component_type} heartbeat fresh and compatible")


def _check_artifact_storage() -> ControlPlaneCheckResult:
    try:
        ensure_artifact_storage_writable()
        return ControlPlaneCheckResult(ok=True, status="ok", detail="artifact storage writable")
    except Exception as exc:
        return ControlPlaneCheckResult(ok=False, status="unavailable", detail=_failed("artifact storage unavailable", exc))


def evaluate_control_plane_health(db: Session) -> ControlPlaneHealthReport:
    strict_mode = bool(settings.control_plane_strict_dependency_checks)

    checks: dict[str, ControlPlaneCheckResult] = {}
    checks["database"] = _check_database_connectivity(db)
    checks["artifact_storage"] = _check_artifact_storage()

    if strict_mode:
        checks["migrations"] = _check_migrations_applied(db, strict_mode=strict_mode)

        redis_check, redis_client = _check_redis_connectivity(strict_mode=strict_mode)
        checks["redis"] = redis_check
        checks["celery_worker"] = _check_celery_heartbeat(
            redis_client=redis_client,
            key=CELERY_WORKER_HEARTBEAT_KEY,
            actor="celery_worker",
            strict_mode=strict_mode,
        )
        checks["celery_beat"] = _check_celery_heartbeat(
            redis_client=redis_client,
            key=CELERY_BEAT_HEARTBEAT_KEY,
            actor="celery_beat",
            strict_mode=strict_mode,
        )
        checks["celery_worker_component"] = _check_component_registration(
            redis_client=redis_client,
            key=CELERY_WORKER_COMPONENT_KEY,
            expected_component_type="worker",
            strict_mode=strict_mode,
        )
        checks["celery_beat_component"] = _check_component_registration(
            redis_client=redis_client,
            key=CELERY_BEAT_COMPONENT_KEY,
            expected_component_type="celery_beat",
            strict_mode=strict_mode,
        )
    else:
        checks["migrations"] = ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail="migration check skipped in non-strict mode",
        )
        checks["redis"] = ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail="redis check skipped in non-strict mode",
        )
        checks["celery_worker"] = ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail="celery worker heartbeat skipped in non-strict mode",
        )
        checks["celery_beat"] = ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail="celery beat heartbeat skipped in non-strict mode",
        )
        checks["celery_worker_component"] = ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail="celery worker compatibility skipped in non-strict mode",
        )
        checks["celery_beat_component"] = ControlPlaneCheckResult(
            ok=True,
            status="skipped",
            detail="celery beat compatibility skipped in non-strict mode",
        )

    required_checks = (
        [
            "database",
            "migrations",
            "redis",
            "celery_worker",
            "celery_beat",
            "celery_worker_component",
            "celery_beat_component",
            "artifact_storage",
        ]
        if strict_mode
        else ["database", "artifact_storage"]
    )
    healthy = all(checks[name].ok for name in required_checks)

    return ControlPlaneHealthReport(
        healthy=healthy,
        strict_mode=strict_mode,
        required_checks=required_checks,
        checks=checks,
    )


def control_plane_module_status(report: ControlPlaneHealthReport) -> dict[str, str]:
    governance_ok = report.checks["database"].ok and report.checks["migrations"].ok
    governance_status = "ok" if governance_ok else "unavailable"
    if report.healthy:
        enforcement_status = "ok"
        iam_status = "ok"
        auditor_status = "ok"
    else:
        enforcement_status = "blocked_fail_secure"
        iam_status = "blocked_fail_secure"
        auditor_status = "queued_fail_secure"
    return {
        "governance_status": governance_status,
        "enforcement_status": enforcement_status,
        "iam_status": iam_status,
        "auditor_status": auditor_status,
    }


def write_worker_heartbeat() -> None:
    try:
        client = _redis_client()
        ttl = _heartbeat_ttl_seconds()
        client.setex(CELERY_WORKER_HEARTBEAT_KEY, ttl, str(time.time()))
        registration = build_component_registration(settings)
        if registration["component_type"] != "worker":
            raise ValueError("worker service identity mismatch")
        client.setex(CELERY_WORKER_COMPONENT_KEY, ttl, json.dumps(registration, sort_keys=True, separators=(",", ":")))
    except Exception:
        return


def write_beat_heartbeat() -> None:
    try:
        client = _redis_client()
        ttl = _heartbeat_ttl_seconds()
        client.setex(CELERY_BEAT_HEARTBEAT_KEY, ttl, str(time.time()))
        registration = build_component_registration(settings)
        if registration["component_type"] != "celery_beat":
            raise ValueError("beat service identity mismatch")
        client.setex(CELERY_BEAT_COMPONENT_KEY, ttl, json.dumps(registration, sort_keys=True, separators=(",", ":")))
    except Exception:
        return
