from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import threading

from celery.exceptions import MaxRetriesExceededError
from celery.utils.time import get_exponential_backoff_interval
from billiard.exceptions import SoftTimeLimitExceeded
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.discovery_canonical import DiscoveryScanAssignment
from app.db.models.endpoint_metadata_inventory import (
    EndpointMetadataInventoryRun,
)
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.hmair.collector_registry import CollectorRegistry
from app.services.hmair.collectors.path_native import (
    register_controlled_breadth_collectors,
    register_h4_profile_collectors,
    register_path_native_collectors,
)
from app.services.hmair.collector_sdk import (
    CollectorTerminalOutcome,
    DiscoveryTargetView,
    collect_assignment_observations,
)
from app.services.hmair.deep_scan_contracts import (
    DeepScanCoverageState,
    DeepScanObservationMode,
    DeepScanReadinessState,
    DeepScanStoredProfile,
    parse_persisted_deep_scan_profile,
)
from app.services.hmair.deep_scan_source_service import (
    CONNECTOR_TARGET_TYPES,
    collect_browser_source_batch,
    collect_connector_source_observations,
    collect_mcp_runtime_source_batch,
)
from app.services.hmair.endpoint_metadata_inventory_service import (
    create_endpoint_metadata_inventory_run,
    reconcile_endpoint_metadata_inventory_runs,
)
from app.services.hmair.contracts import (
    CollectorDeclaration,
    CollectorRunStatus,
    DiscoveryObservationInput,
)
from app.services.hmair.evidence_fusion_service import fuse_scan_observations
from app.services.hmair.observation_service import ingest_observation
from app.services.hmair.scan_service import (
    claim_assignment_batch,
    finalize_assignment,
    finalize_scan,
    get_collector,
    get_scan,
    get_target,
    record_deep_scan_source_coverage,
    release_unpublished_assignment_claims,
    start_assignment,
)


collector_registry = CollectorRegistry()
register_path_native_collectors(collector_registry, enabled=True)
register_controlled_breadth_collectors(collector_registry, enabled=True)
register_h4_profile_collectors(collector_registry, enabled=True)
_SDK_COLLECT_ASSIGNMENT_OBSERVATIONS = collect_assignment_observations

_FINAL_SCAN_STATUSES = frozenset(
    {"partially_complete", "complete", "failed", "cancelled"}
)
_TERMINAL_ASSIGNMENT_STATUSES = frozenset(
    {
        "complete",
        "failed",
        "cancelled",
        "unsupported",
        "permission_denied",
        "rate_limited",
        "stale",
        "empty",
    }
)


def _apply_scan_scope_exclusions(
    target: DiscoveryTargetView,
    scan: object,
) -> DiscoveryTargetView:
    """Narrow one frozen target with the scan request's bounded exclusions."""

    scope = getattr(scan, "scope_json", None)
    raw = scope.get("exclusions") if isinstance(scope, Mapping) else None
    if raw is None:
        return target
    if not isinstance(raw, (list, tuple)):
        raise RuntimeError("scan exclusions are invalid")
    exclusions = tuple(
        sorted(
            {
                item.strip()
                for item in (*target.exclusions, *raw)
                if isinstance(item, str) and item.strip()
            }
        )
    )
    if len(exclusions) > 256 or any(len(item) > 128 for item in exclusions):
        raise RuntimeError("scan exclusions are invalid")
    return target.model_copy(update={"exclusions": exclusions})
_SURFACE_FLAGS = {
    "endpoint_group": "hmair_endpoint",
    "browser_tenant": "hmair_browser",
    "mcp_environment": "hmair_mcp_runtime",
    "llm_gateway": "hmair_mcp_runtime",
    "runtime_environment": "hmair_mcp_runtime",
    "cloud_subscription": "hmair_cloud",
    "cloud_project": "hmair_cloud",
    "kubernetes_cluster": "hmair_cloud",
    "saas_tenant": "hmair_saas",
    "ai_provider_account": "hmair_saas",
    "identity_tenant": "hmair_identity",
    "repository": "hmair_repository",
    "repository_org": "hmair_repository",
    "network_range": "hmair_network",
    "dns_domain": "hmair_network",
    "api_gateway": "hmair_network",
    "database_platform": "hmair_database",
}
_RETRY_BACKOFF_MAX = 120
_ASSIGNMENT_SOFT_TIME_LIMIT_SECONDS = 600
_ASSIGNMENT_TIME_LIMIT_SECONDS = 660
_DEEP_SCAN_ENDPOINT_EXPIRY_MINUTES = 30
_DEEP_SCAN_ENDPOINT_TARGET = "endpoint_group"
_DEEP_SCAN_BROWSER_TARGET = "browser_tenant"
_DEEP_SCAN_RUNTIME_TARGETS = frozenset(
    {"mcp_environment", "llm_gateway", "runtime_environment"}
)
_DEEP_SCAN_CONNECTOR_TARGETS = frozenset(CONNECTOR_TARGET_TYPES.values())
_execution_locks_guard = threading.Lock()
_execution_locks: dict[tuple[str, str], tuple[threading.Lock, int]] = {}


def _flag_enabled(name: str) -> bool:
    return getattr(settings, name, False) is True


def require_hmair_job_enabled(scan: object) -> None:
    del scan
    if not _flag_enabled("hmair_core"):
        raise RuntimeError("HMAIR core is disabled")
    if not _flag_enabled("hmair_active_scan"):
        raise RuntimeError("HMAIR active scan is disabled")
    if not any(_flag_enabled(flag) for flag in _SURFACE_FLAGS.values()):
        raise RuntimeError("HMAIR discovery surfaces are disabled")


def require_hmair_collector_enabled(
    declaration: CollectorDeclaration,
    target: DiscoveryTargetView,
) -> None:
    if type(declaration) is not CollectorDeclaration:
        raise RuntimeError("HMAIR collector declaration is invalid")
    if type(target) is not DiscoveryTargetView:
        raise RuntimeError("HMAIR discovery target is invalid")
    if not _flag_enabled("hmair_core"):
        raise RuntimeError("HMAIR core is disabled")
    surface_flag = _SURFACE_FLAGS.get(str(target.target_type))
    if surface_flag is None or not _flag_enabled(surface_flag):
        raise RuntimeError("HMAIR collector surface is disabled")
    supported_targets = getattr(declaration, "supported_targets", None)
    if (
        supported_targets is not None
        and target.target_type not in supported_targets
    ):
        raise RuntimeError("HMAIR collector does not support target surface")
    active_capabilities = getattr(declaration, "active_capabilities", ())
    if active_capabilities and (
        not _flag_enabled("hmair_active_scan")
        or not target.active_scan_allowed
    ):
        raise RuntimeError("HMAIR active collection is disabled")


def require_hmair_deep_scan_source_enabled(target: DiscoveryTargetView) -> None:
    """Require the explicit runtime gates for a Production Deep Scan source.

    A Deep Scan is an active control-plane request even when an admitted
    source only returns metadata.  Connector-backed sources additionally need
    their separate source bridge flag; a surface flag alone must never make a
    customer connector eligible.
    """

    if type(target) is not DiscoveryTargetView:
        raise RuntimeError("HMAIR discovery target is invalid")
    if not _flag_enabled("hmair_core"):
        raise RuntimeError("HMAIR core is disabled")
    if not _flag_enabled("hmair_active_scan"):
        raise RuntimeError("HMAIR active scan is disabled")
    if str(target.target_type) in _DEEP_SCAN_CONNECTOR_TARGETS and not _flag_enabled(
        "hmair_connector_sources"
    ):
        raise RuntimeError("HMAIR connector source bridge is disabled")


def _deep_scan_profile(scan: object) -> DeepScanStoredProfile | None:
    scope = getattr(scan, "scope_json", None)
    if not isinstance(scope, Mapping):
        return None
    raw_profile = scope.get("deep_scan")
    if raw_profile is None:
        return None
    if not isinstance(raw_profile, Mapping) or raw_profile.get("version") != "v1":
        raise RuntimeError("Deep Scan profile is invalid")
    try:
        return parse_persisted_deep_scan_profile(raw_profile)
    except ValueError as exc:
        raise RuntimeError("Deep Scan profile is invalid") from exc


def _deep_scan_source(
    *,
    profile: DeepScanStoredProfile,
    target_id: str,
    collector_id: str,
) -> object:
    source = next(
        (
            item
            for item in profile.sources
            if item.target_id == target_id and item.collector_id == collector_id
        ),
        None,
    )
    if source is None:
        raise RuntimeError("Deep Scan assignment is not present in the frozen profile")
    if (
        source.state is not DeepScanReadinessState.READY
        or source.observation_mode is not DeepScanObservationMode.AUTHORITATIVE
        or source.expected_count is None
    ):
        raise RuntimeError("Deep Scan source is not ready")
    return source


def _deep_scan_outcome_coverage_state(
    outcome: CollectorTerminalOutcome,
) -> DeepScanCoverageState:
    """Map terminal source outcomes without upgrading a source to complete."""

    mapping = {
        "empty": DeepScanCoverageState.EMPTY,
        "stale": DeepScanCoverageState.STALE,
        "unsupported": DeepScanCoverageState.UNSUPPORTED,
    }
    return mapping.get(str(outcome.status), DeepScanCoverageState.FAILED)


def _deep_scan_outcome_reason(outcome: CollectorTerminalOutcome) -> str:
    mapping = {
        "empty": "source_empty",
        "stale": "source_stale",
        "unsupported": "source_unsupported",
    }
    return mapping.get(str(outcome.status), "source_failed")


def _deep_scan_observed_at(observations: tuple[object, ...]) -> datetime | None:
    values = [
        value.observed_at
        for value in observations
        if isinstance(getattr(value, "observed_at", None), datetime)
    ]
    if not values:
        return None
    return max(values)


@contextmanager
def _local_assignment_lock(
    tenant_id: str,
    assignment_id: str,
) -> Iterator[None]:
    key = (tenant_id, assignment_id)
    with _execution_locks_guard:
        lock, references = _execution_locks.get(
            key,
            (threading.Lock(), 0),
        )
        _execution_locks[key] = (lock, references + 1)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _execution_locks_guard:
            current_lock, current_references = _execution_locks[key]
            if current_references == 1:
                del _execution_locks[key]
            else:
                _execution_locks[key] = (
                    current_lock,
                    current_references - 1,
                )


def _session_factory_dialect() -> str | None:
    factory_options = getattr(SessionLocal, "kw", None)
    if not isinstance(factory_options, dict):
        return None
    bind = factory_options.get("bind")
    dialect = getattr(bind, "dialect", None)
    name = getattr(dialect, "name", None)
    return name if isinstance(name, str) else None


def _advisory_lock_key(tenant_id: str, assignment_id: str) -> int:
    material = f"{tenant_id}\x00{assignment_id}".encode("utf-8")
    digest = hashlib.sha256(material).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


@contextmanager
def _assignment_execution_lock(
    tenant_id: str,
    assignment_id: str,
) -> Iterator[None]:
    with _local_assignment_lock(tenant_id, assignment_id):
        if _session_factory_dialect() != "postgresql":
            yield
            return
        with SessionLocal() as lock_db:
            try:
                lock_db.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {
                        "lock_key": _advisory_lock_key(
                            tenant_id,
                            assignment_id,
                        )
                    },
                )
                yield
            finally:
                lock_db.rollback()


def _scan_has_active_work(
    db: object,
    *,
    tenant_id: str,
    scan_id: str,
) -> bool:
    count = db.scalar(
        select(func.count())
        .select_from(DiscoveryScanAssignment)
        .where(
            DiscoveryScanAssignment.tenant_id == tenant_id,
            DiscoveryScanAssignment.scan_id == scan_id,
            DiscoveryScanAssignment.status.in_(("pending", "running")),
        )
    )
    return int(count or 0) > 0


def _release_failed_publications(
    *,
    tenant_id: str,
    scan_id: str,
    assignment_ids: tuple[str, ...],
) -> None:
    if not assignment_ids:
        return
    with SessionLocal() as db:
        try:
            release_unpublished_assignment_claims(
                db,
                tenant_id=tenant_id,
                scan_id=scan_id,
                assignment_ids=assignment_ids,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise


def _recover_retry_publications(
    db: object,
    *,
    tenant_id: str,
    scan_id: str,
) -> None:
    assignment_ids = tuple(
        db.scalars(
            select(DiscoveryScanAssignment.assignment_id).where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
                DiscoveryScanAssignment.status == "running",
            )
        )
    )
    release_unpublished_assignment_claims(
        db,
        tenant_id=tenant_id,
        scan_id=scan_id,
        assignment_ids=assignment_ids,
    )


def _dispatch_delivery_requires_recovery(task: object) -> bool:
    if int(getattr(task.request, "retries", 0)) > 0:
        return True
    delivery_info = getattr(task.request, "delivery_info", None)
    return (
        isinstance(delivery_info, Mapping)
        and delivery_info.get("redelivered") is True
    )


@celery_app.task(
    bind=True,
    name="app.jobs.hmair_discovery_jobs.dispatch_scan",
)
def dispatch_scan(self, tenant_id: str, scan_id: str) -> dict[str, object]:
    should_finalize = False
    assignment_keys: list[tuple[str, str, str]] = []
    with SessionLocal() as db:
        try:
            scan = get_scan(db, tenant_id=tenant_id, scan_id=scan_id)
            if scan is None:
                return {
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "status": "not_found",
                }
            if scan.status in _FINAL_SCAN_STATUSES:
                return {
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "status": scan.status,
                }
            require_hmair_job_enabled(scan)
            if _dispatch_delivery_requires_recovery(self):
                _recover_retry_publications(
                    db,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                )
            batch = claim_assignment_batch(
                db,
                tenant_id=tenant_id,
                scan_id=scan_id,
                limit=settings.hmair_max_concurrent_assignments,
            )
            assignment_keys = [
                (item.assignment_id, item.collector_id, item.target_id)
                for item in batch
            ]
            if not assignment_keys:
                should_finalize = not _scan_has_active_work(
                    db,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                )
            db.commit()
        except Exception:
            db.rollback()
            raise

    for index, (assignment_id, collector_id, target_id) in enumerate(
        assignment_keys
    ):
        try:
            run_collector_assignment.delay(
                tenant_id,
                scan_id,
                assignment_id,
                collector_id,
                target_id,
            )
        except Exception:
            try:
                _release_failed_publications(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    assignment_ids=tuple(
                        item[0] for item in assignment_keys[index:]
                    ),
                )
            except Exception:
                raise RuntimeError(
                    "assignment publication recovery failed"
                ) from None
            raise RuntimeError("assignment publication failed") from None
    if should_finalize:
        try:
            finalize_discovery_scan.delay(tenant_id, scan_id)
        except Exception:
            raise RuntimeError("scan finalization publication failed") from None
    return {
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "status": "dispatched",
        "assignments": len(assignment_keys),
    }


def _validate_assignment_identity(
    assignment: object,
    *,
    scan_id: str,
    collector_id: str,
    target_id: str,
) -> None:
    expected = {
        "scan_id": scan_id,
        "collector_id": collector_id,
        "target_id": target_id,
    }
    for field_name, expected_value in expected.items():
        actual_value = getattr(assignment, field_name, expected_value)
        if actual_value != expected_value:
            raise LookupError("scan assignment scope does not match task input")


def _runtime_declaration_matches_persisted(
    *,
    declaration: object,
    persisted_collector: object,
) -> None:
    runtime_type = getattr(declaration, "collector_type", None)
    persisted_type = getattr(persisted_collector, "collector_type", None)
    if runtime_type != persisted_type:
        raise RuntimeError("collector declaration does not match persisted type")
    runtime_version = getattr(declaration, "version", None)
    persisted_version = getattr(persisted_collector, "version", None)
    if (
        runtime_version is not None
        and persisted_version is not None
        and runtime_version != persisted_version
    ):
        raise RuntimeError(
            "collector declaration does not match persisted version"
        )


def _utc_datetime(value: object) -> object:
    if value is not None and (
        value.tzinfo is None or value.utcoffset() is None
    ):
        return value.replace(tzinfo=UTC)
    return value


def _persisted_collector_declaration(
    persisted_collector: object,
) -> CollectorDeclaration:
    return CollectorDeclaration(
        collector_id=persisted_collector.collector_id,
        collector_type=persisted_collector.collector_type,
        version=persisted_collector.version,
        supported_targets=tuple(persisted_collector.supported_targets_json),
        active_capabilities=tuple(
            persisted_collector.active_capabilities_json
        ),
        passive_capabilities=tuple(
            persisted_collector.passive_capabilities_json
        ),
        permissions_required=tuple(
            persisted_collector.permissions_required_json
        ),
        sensitive_data_accessed=tuple(
            persisted_collector.sensitive_data_accessed_json
        ),
        health=persisted_collector.health,
        last_success_at=_utc_datetime(persisted_collector.last_success_at),
        last_failure_at=_utc_datetime(persisted_collector.last_failure_at),
        data_residency=persisted_collector.data_residency,
        control_capability=persisted_collector.control_capability,
        schema_version=persisted_collector.schema_version,
        limitations=tuple(persisted_collector.limitations_json),
        declaration_hash=persisted_collector.declaration_hash,
    )


def _scan_cancellation_check(
    *,
    tenant_id: str,
    scan_id: str,
) -> bool:
    with SessionLocal() as db:
        try:
            scan = get_scan(db, tenant_id=tenant_id, scan_id=scan_id)
            return scan is None or scan.status == "cancelled"
        except Exception:
            db.rollback()
            raise


def _collect_observations(
    *,
    collector: object,
    target: object,
    tenant_id: str,
    scan_id: str,
) -> tuple[object, ...]:
    return collect_assignment_observations(
        collector=collector,
        target=target,
        cancellation_check=lambda: _scan_cancellation_check(
            tenant_id=tenant_id,
            scan_id=scan_id,
        ),
    )


def _execution_observations(
    observations: tuple[object, ...],
    *,
    scan_id: str,
    persisted_collector_id: str,
    target_id: str,
    declaration: object,
    runtime_identity_required: bool,
) -> tuple[object, ...]:
    # Runtime registries always provide an exact typed declaration. Lightweight
    # test or bridge doubles cannot emit trusted SDK observations, so retain
    # their opaque values only for the existing injected ingestion boundary.
    if type(declaration) is not CollectorDeclaration:
        return tuple(observations)

    rebound: list[DiscoveryObservationInput] = []
    for value in observations:
        if type(value) is not DiscoveryObservationInput:
            raise RuntimeError("collector execution failed")
        observation = DiscoveryObservationInput.model_validate(
            value.model_dump(mode="python")
        )
        if (
            (
                runtime_identity_required
                and observation.collector_id != declaration.collector_id
            )
            or observation.collector_type != declaration.collector_type
            or observation.collector_version != declaration.version
            or observation.target_id != target_id
        ):
            raise RuntimeError("collector execution failed")
        material = observation.model_dump(mode="python")
        material.update(
            {
                "scan_id": scan_id,
                "collector_id": persisted_collector_id,
                "target_id": target_id,
            }
        )
        rebound.append(DiscoveryObservationInput.model_validate(material))
    return tuple(rebound)


def _controlled_preflight_error(error: Exception) -> Exception:
    message = str(error)
    if type(error) is LookupError and message in {
        "discovery target was not found",
        "collector was not found",
        "scan was not found",
    }:
        return LookupError(message)
    if type(error) is KeyError and "collector type is not registered" in message:
        return KeyError("collector type is not registered")
    if type(error) is RuntimeError and (
        message.startswith("HMAIR ")
        or message.startswith("collector declaration does not match")
        or message == "collector surface is disabled"
    ):
        return RuntimeError(message)
    return RuntimeError("collector preflight failed")


def _retry_countdown(task: object) -> int:
    retries = max(0, int(getattr(task.request, "retries", 0)))
    return get_exponential_backoff_interval(
        factor=1,
        retries=retries,
        maximum=_RETRY_BACKOFF_MAX,
        full_jitter=True,
    )


def _request_retry(
    task: object,
    *,
    error: Exception,
) -> bool:
    retries = max(0, int(getattr(task.request, "retries", 0)))
    max_retries = int(getattr(task, "max_retries", 5))
    try:
        raise task.retry(
            exc=error,
            countdown=_retry_countdown(task),
            max_retries=max_retries,
        ) from None
    except MaxRetriesExceededError:
        return True
    except Exception as retry_signal:
        # Celery re-raises the supplied exception, rather than
        # MaxRetriesExceededError, when an explicit `exc` is provided.
        if retries >= max_retries and retry_signal is error:
            return True
        raise


def _finalize_expected_outcome(
    *,
    tenant_id: str,
    assignment_id: str,
    outcome: CollectorTerminalOutcome,
) -> None:
    with SessionLocal() as db:
        try:
            finalize_assignment(
                db,
                tenant_id=tenant_id,
                assignment_id=assignment_id,
                status=outcome.status,
                observations_count=0,
                warning=outcome.safe_message,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise


def _persist_assignment_observations(
    *,
    tenant_id: str,
    assignment_id: str,
    observations: tuple[object, ...],
) -> None:
    with SessionLocal() as db:
        try:
            fusion_enabled = _flag_enabled("hmair_fingerprinting")
            persisted_scan_ids: set[str] = set()
            for payload in observations:
                row = ingest_observation(
                    db, tenant_id=tenant_id, payload=payload
                )
                if fusion_enabled:
                    persisted_scan_ids.add(row.scan_id)
            if fusion_enabled and persisted_scan_ids:
                if len(persisted_scan_ids) != 1:
                    raise RuntimeError(
                        "collector batch contains inconsistent scan identity"
                    )
                fuse_scan_observations(
                    db,
                    tenant_id=tenant_id,
                    scan_id=next(iter(persisted_scan_ids)),
                )
            finalize_assignment(
                db,
                tenant_id=tenant_id,
                assignment_id=assignment_id,
                status="complete",
                observations_count=len(observations),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise


def _finalize_exhausted_failure(
    *,
    tenant_id: str,
    assignment_id: str,
) -> None:
    with SessionLocal() as db:
        try:
            finalize_assignment(
                db,
                tenant_id=tenant_id,
                assignment_id=assignment_id,
                status="failed",
                observations_count=0,
                error="collector execution failed",
            )
            db.commit()
        except Exception:
            db.rollback()
            raise


def _finalize_expected_in_execution(
    execution_db: object,
    *,
    tenant_id: str,
    assignment_id: str,
    outcome: CollectorTerminalOutcome,
) -> None:
    if isinstance(execution_db, Session):
        finalize_assignment(
            execution_db,
            tenant_id=tenant_id,
            assignment_id=assignment_id,
            status=outcome.status,
            observations_count=0,
            warning=outcome.safe_message,
        )
        return
    _finalize_expected_outcome(
        tenant_id=tenant_id,
        assignment_id=assignment_id,
        outcome=outcome,
    )


def _persist_in_execution(
    execution_db: object,
    *,
    tenant_id: str,
    assignment_id: str,
    observations: tuple[object, ...],
) -> None:
    if isinstance(execution_db, Session):
        fusion_enabled = _flag_enabled("hmair_fingerprinting")
        persisted_scan_ids: set[str] = set()
        for payload in observations:
            row = ingest_observation(
                execution_db,
                tenant_id=tenant_id,
                payload=payload,
            )
            if fusion_enabled:
                persisted_scan_ids.add(row.scan_id)
        if fusion_enabled and persisted_scan_ids:
            if len(persisted_scan_ids) != 1:
                raise RuntimeError(
                    "collector batch contains inconsistent scan identity"
                )
            fuse_scan_observations(
                execution_db,
                tenant_id=tenant_id,
                scan_id=next(iter(persisted_scan_ids)),
            )
        finalize_assignment(
            execution_db,
            tenant_id=tenant_id,
            assignment_id=assignment_id,
            status="complete",
            observations_count=len(observations),
        )
        return
    _persist_assignment_observations(
        tenant_id=tenant_id,
        assignment_id=assignment_id,
        observations=observations,
    )


def _execute_deep_scan_source_in_execution(
    execution_db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    assignment_id: str,
    collector_id: str,
    target: DiscoveryTargetView,
    scan: object,
) -> tuple[str | None, str | None]:
    """Run one frozen Deep Scan source without falling back to legacy paths.

    The profile is the authority for the exact source tuple.  Browser,
    runtime, and connector bridges ingest only their explicit safe metadata.
    Browser and runtime coverage closes only when signed per-unit receipts
    reconcile the frozen denominator. Endpoint inventory is handed to enrolled
    endpoint identities until its existing signed reconciliation completes.
    """

    profile = _deep_scan_profile(scan)
    if profile is None:
        raise RuntimeError("Deep Scan profile was not found")
    source = _deep_scan_source(
        profile=profile,
        target_id=target.target_id,
        collector_id=collector_id,
    )
    if source.target_type != str(target.target_type):
        raise RuntimeError("Deep Scan source target type changed")
    require_hmair_deep_scan_source_enabled(target)

    if source.target_type == _DEEP_SCAN_ENDPOINT_TARGET:
        summary = create_endpoint_metadata_inventory_run(
            execution_db,
            tenant_id=tenant_id,
            requested_by_user_id=getattr(scan, "requested_by", None),
            request_idempotency_key=(
                f"deep-scan:{scan_id}:{assignment_id}"
            ),
            endpoint_ids=None,
            expires_in_minutes=_DEEP_SCAN_ENDPOINT_EXPIRY_MINUTES,
            parent_scan_id=scan_id,
            parent_assignment_id=assignment_id,
        )
        record_deep_scan_source_coverage(
            execution_db,
            tenant_id=tenant_id,
            scan_id=scan_id,
            assignment_id=assignment_id,
            state=DeepScanCoverageState.PARTIAL,
            observed_count=0,
            evidence_fresh_at=None,
            reason="endpoint_inventory_pending",
        )
        return None, summary.id

    try:
        completion_receipts = ()
        if source.target_type == _DEEP_SCAN_BROWSER_TARGET:
            batch = collect_browser_source_batch(
                execution_db,
                tenant_id=tenant_id,
                scan_id=scan_id,
                target_id=target.target_id,
                collector_id=collector_id,
                window_start=profile.window_start,
                window_end=profile.window_end,
            )
            observations = batch.observations
            completion_receipts = batch.completion_receipts
        elif source.target_type in _DEEP_SCAN_RUNTIME_TARGETS:
            batch = collect_mcp_runtime_source_batch(
                execution_db,
                tenant_id=tenant_id,
                scan_id=scan_id,
                target_id=target.target_id,
                collector_id=collector_id,
                window_start=profile.window_start,
                window_end=profile.window_end,
            )
            observations = batch.observations
            completion_receipts = batch.completion_receipts
        elif source.target_type in _DEEP_SCAN_CONNECTOR_TARGETS:
            reference = target.credentials_reference
            if not isinstance(reference, str) or not reference.startswith(
                "connector:"
            ):
                raise CollectorTerminalOutcome(
                    CollectorRunStatus.UNSUPPORTED,
                    "connector source is not configured for Deep Scan",
                )
            observations = collect_connector_source_observations(
                execution_db,
                tenant_id=tenant_id,
                scan_id=scan_id,
                target_id=target.target_id,
                collector_id=collector_id,
                connector_id=reference.removeprefix("connector:"),
                window_start=profile.window_start,
                window_end=profile.window_end,
            )
        else:
            raise CollectorTerminalOutcome(
                CollectorRunStatus.UNSUPPORTED,
                "Deep Scan source type is not implemented",
            )
    except CollectorTerminalOutcome as outcome:
        record_deep_scan_source_coverage(
            execution_db,
            tenant_id=tenant_id,
            scan_id=scan_id,
            assignment_id=assignment_id,
            state=_deep_scan_outcome_coverage_state(outcome),
            observed_count=0,
            evidence_fresh_at=None,
            reason=_deep_scan_outcome_reason(outcome),
        )
        _finalize_expected_in_execution(
            execution_db,
            tenant_id=tenant_id,
            assignment_id=assignment_id,
            outcome=outcome,
        )
        return str(outcome.status), None

    receipt_count = len(completion_receipts)
    reconciled = (
        bool(completion_receipts)
        and source.expected_count is not None
        and receipt_count == source.expected_count
    )
    record_deep_scan_source_coverage(
        execution_db,
        tenant_id=tenant_id,
        scan_id=scan_id,
        assignment_id=assignment_id,
        state=(
            DeepScanCoverageState.COMPLETE
            if reconciled
            else DeepScanCoverageState.PARTIAL
        ),
        observed_count=(receipt_count if completion_receipts else len(observations)),
        evidence_fresh_at=(
            max(receipt.observed_at for receipt in completion_receipts)
            if completion_receipts
            else _deep_scan_observed_at(observations)
        ),
        reason=(None if reconciled else "source_denominator_not_reconciled"),
        completion_receipts=completion_receipts,
    )
    _persist_in_execution(
        execution_db,
        tenant_id=tenant_id,
        assignment_id=assignment_id,
        observations=observations,
    )
    return "complete", None


def _run_collector_assignment_locked(
    self,
    tenant_id: str,
    scan_id: str,
    assignment_id: str,
    collector_id: str,
    target_id: str,
) -> dict[str, object]:
    terminal_status: str | None = None
    terminal_result_status = "processed"
    preflight_error: Exception | None = None
    execution_failed = False
    continuation_scan_id: str | None = None
    deep_scan_execution = False
    with SessionLocal() as db:
        try:
            assignment = start_assignment(
                db,
                tenant_id=tenant_id,
                assignment_id=assignment_id,
            )
            if assignment is None:
                return {
                    "tenant_id": tenant_id,
                    "assignment_id": assignment_id,
                    "status": "cancelled",
                }
            continuation_scan_id = str(
                getattr(assignment, "scan_id", scan_id)
            )
            _validate_assignment_identity(
                assignment,
                scan_id=scan_id,
                collector_id=collector_id,
                target_id=target_id,
            )
            terminal_status = assignment.status
            if terminal_status == "cancelled":
                terminal_result_status = "cancelled"
            if terminal_status not in _TERMINAL_ASSIGNMENT_STATUSES:
                target = get_target(
                    db,
                    tenant_id=tenant_id,
                    target_id=target_id,
                )
                if target is None:
                    raise LookupError("discovery target was not found")
                persisted_collector = get_collector(
                    db,
                    tenant_id=tenant_id,
                    collector_id=collector_id,
                )
                if persisted_collector is None:
                    raise LookupError("collector was not found")
                execution_scan = get_scan(
                    db,
                    tenant_id=tenant_id,
                    scan_id=continuation_scan_id,
                )
                if execution_scan is None:
                    raise LookupError("scan was not found")
                target = _apply_scan_scope_exclusions(target, execution_scan)
                if execution_scan.dry_run:
                    dry_declaration = _persisted_collector_declaration(
                        persisted_collector
                    )
                    require_hmair_collector_enabled(
                        dry_declaration,
                        target,
                    )
                    finalize_assignment(
                        db,
                        tenant_id=tenant_id,
                        assignment_id=assignment_id,
                        status="complete",
                        observations_count=0,
                    )
                    terminal_status = "complete"
                    db.commit()
                elif execution_scan.status == "cancelled":
                    finalize_assignment(
                        db,
                        tenant_id=tenant_id,
                        assignment_id=assignment_id,
                        status="cancelled",
                        observations_count=0,
                        warning="collector run cancelled",
                    )
                    terminal_status = "cancelled"
                    db.commit()
                else:
                    profile = _deep_scan_profile(execution_scan)
                    if profile is not None:
                        persisted_declaration = _persisted_collector_declaration(
                            persisted_collector
                        )
                        require_hmair_collector_enabled(
                            persisted_declaration,
                            target,
                        )
                        require_hmair_deep_scan_source_enabled(target)
                        _deep_scan_source(
                            profile=profile,
                            target_id=target.target_id,
                            collector_id=collector_id,
                        )
                        deep_scan_execution = True
                    else:
                        collector = collector_registry.get(
                            persisted_collector.collector_type
                        )
                        _runtime_declaration_matches_persisted(
                            declaration=collector.declaration,
                            persisted_collector=persisted_collector,
                        )
                        require_hmair_collector_enabled(
                            collector.declaration,
                            target,
                        )
        except Exception as error:
            db.rollback()
            preflight_error = _controlled_preflight_error(error)

        if (
            preflight_error is None
            and terminal_status not in _TERMINAL_ASSIGNMENT_STATUSES
        ):
            if deep_scan_execution:
                try:
                    terminal_status, _inventory_run_id = (
                        _execute_deep_scan_source_in_execution(
                            db,
                            tenant_id=tenant_id,
                            scan_id=continuation_scan_id,
                            assignment_id=assignment_id,
                            collector_id=collector_id,
                            target=target,
                            scan=execution_scan,
                        )
                    )
                    db.commit()
                except SoftTimeLimitExceeded:
                    db.commit()
                    execution_failed = True
                except Exception:
                    db.rollback()
                    execution_failed = True
            else:
                try:
                    observations = _collect_observations(
                        collector=collector,
                        target=target,
                        tenant_id=tenant_id,
                        scan_id=continuation_scan_id,
                    )
                except CollectorTerminalOutcome as outcome:
                    try:
                        _finalize_expected_in_execution(
                            db,
                            tenant_id=tenant_id,
                            assignment_id=assignment_id,
                            outcome=outcome,
                        )
                        db.commit()
                        terminal_status = str(outcome.status)
                    except Exception:
                        db.rollback()
                        execution_failed = True
                except SoftTimeLimitExceeded:
                    # Leave the durable assignment running for the retry while
                    # promptly ending the row-lock transaction during the soft
                    # timeout grace period. The task retry is always sanitized.
                    db.commit()
                    execution_failed = True
                except Exception:
                    # Preserve the committed/running execution marker for a safe
                    # retry while releasing the row/advisory transaction cleanly.
                    db.commit()
                    execution_failed = True
                else:
                    try:
                        persisted_observations = _execution_observations(
                            observations,
                            scan_id=continuation_scan_id,
                            persisted_collector_id=collector_id,
                            target_id=target_id,
                            declaration=collector.declaration,
                            runtime_identity_required=(
                                collect_assignment_observations
                                is _SDK_COLLECT_ASSIGNMENT_OBSERVATIONS
                            ),
                        )
                        _persist_in_execution(
                            db,
                            tenant_id=tenant_id,
                            assignment_id=assignment_id,
                            observations=persisted_observations,
                        )
                        db.commit()
                    except Exception:
                        db.rollback()
                        execution_failed = True

    if preflight_error is not None:
        exhausted = _request_retry(self, error=preflight_error)
        if exhausted:
            _finalize_exhausted_failure(
                tenant_id=tenant_id,
                assignment_id=assignment_id,
            )
            terminal_status = "failed"

    if execution_failed:
        safe_error = RuntimeError("collector execution failed")
        if _request_retry(self, error=safe_error):
            _finalize_exhausted_failure(
                tenant_id=tenant_id,
                assignment_id=assignment_id,
            )
            terminal_status = "failed"

    if terminal_status in _TERMINAL_ASSIGNMENT_STATUSES:
        result = {
            "tenant_id": tenant_id,
            "assignment_id": assignment_id,
            "status": terminal_result_status,
        }
        try:
            dispatch_scan.delay(tenant_id, continuation_scan_id)
        except Exception:
            safe_error = RuntimeError("scan continuation publication failed")
            if _request_retry(self, error=safe_error):
                raise safe_error from None
        return result

    try:
        dispatch_scan.delay(tenant_id, continuation_scan_id)
    except Exception:
        safe_error = RuntimeError("scan continuation publication failed")
        if _request_retry(self, error=safe_error):
            raise safe_error from None
    return {
        "tenant_id": tenant_id,
        "assignment_id": assignment_id,
        "status": "processed",
    }


@celery_app.task(
    bind=True,
    name="app.jobs.hmair_discovery_jobs.run_collector_assignment",
    soft_time_limit=_ASSIGNMENT_SOFT_TIME_LIMIT_SECONDS,
    time_limit=_ASSIGNMENT_TIME_LIMIT_SECONDS,
)
def run_collector_assignment(
    self,
    tenant_id: str,
    scan_id: str,
    assignment_id: str,
    collector_id: str,
    target_id: str,
) -> dict[str, object]:
    with _assignment_execution_lock(tenant_id, assignment_id):
        return _run_collector_assignment_locked(
            self,
            tenant_id,
            scan_id,
            assignment_id,
            collector_id,
            target_id,
        )


@celery_app.task(name="app.jobs.hmair_discovery_jobs.finalize_discovery_scan")
def finalize_discovery_scan(
    tenant_id: str,
    scan_id: str,
) -> dict[str, object]:
    with SessionLocal() as db:
        try:
            scan = finalize_scan(db, tenant_id=tenant_id, scan_id=scan_id)
            db.commit()
            return {
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "status": scan.status,
                "observations_count": scan.observations_count,
            }
        except Exception:
            db.rollback()
            raise


@celery_app.task(
    name="app.jobs.hmair_discovery_jobs.reconcile_endpoint_metadata_inventory"
)
def reconcile_endpoint_metadata_inventory(tenant_id: str) -> dict[str, object]:
    """Close expired tenant-local endpoint inventory work without scanning."""

    with SessionLocal() as db:
        try:
            summaries = reconcile_endpoint_metadata_inventory_runs(
                db,
                tenant_id=tenant_id,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
    return {
        "tenant_id": tenant_id,
        "status": "reconciled",
        "active_runs": len(summaries),
    }


@celery_app.task(
    name="app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation"
)
def enqueue_endpoint_metadata_inventory_reconciliation() -> dict[str, object]:
    """Queue bounded tenant-local expiry reconciliation for existing work."""

    with SessionLocal() as db:
        tenant_ids = tuple(
            db.scalars(
                select(EndpointMetadataInventoryRun.tenant_id)
                .where(
                    EndpointMetadataInventoryRun.status.in_(("queued", "running")),
                )
                .distinct()
                .order_by(EndpointMetadataInventoryRun.tenant_id)
                .limit(500)
            ).all()
        )
    for tenant_id in tenant_ids:
        reconcile_endpoint_metadata_inventory.delay(tenant_id)
    return {
        "status": "enqueued",
        "enqueued": len(tenant_ids),
        "tenant_ids": list(tenant_ids),
    }


__all__ = [
    "dispatch_scan",
    "enqueue_endpoint_metadata_inventory_reconciliation",
    "finalize_discovery_scan",
    "reconcile_endpoint_metadata_inventory",
    "require_hmair_collector_enabled",
    "require_hmair_job_enabled",
    "run_collector_assignment",
]
