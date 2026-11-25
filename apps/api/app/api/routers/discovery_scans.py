from __future__ import annotations

import base64
import binascii
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryObservation,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.ai_asset import DiscoveryObservationAssetLink
from app.db.models.discovery_intelligence import DiscoveryAssetFinding
from app.db.session import get_db
from app.jobs.hmair_discovery_jobs import dispatch_scan
from app.services.audit_service import write_audit_log
from app.services.hmair.contracts import DiscoveryScanCreate
from app.services.hmair.deep_scan_contracts import (
    DeepScanCoverage,
    DeepScanCoverageState,
    DeepScanLaunchRequest,
    DeepScanPreflightRequest,
    DeepScanPreflightResult,
    DeepScanStoredProfile,
    DeepScanSourceCoverage,
    deep_scan_profile_digest,
    parse_persisted_deep_scan_profile,
    persist_deep_scan_profile,
)
from app.services.hmair.deep_scan_readiness_service import (
    freeze_deep_scan_profile,
    preflight_deep_scan,
)
from app.services.hmair.deep_scan_source_service import CONNECTOR_TARGET_TYPES
from app.services.hmair.enterprise_scan_service import (
    EnterpriseScanBreadth,
    EnterpriseScanDiagnostics,
    build_scan_diagnostics,
    build_scan_result_breadth,
)
from app.services.hmair.retention_service import (
    ScanSummaryCompactionPlan,
    ScanSummaryCompactionResult,
    compact_terminal_scan_summaries,
    plan_terminal_scan_summary_compaction,
)
from app.services.hmair.scan_service import (
    cancel_scan_with_outcome as cancel_scan_with_outcome_record,
    create_scan_with_assignment_pairs_outcome,
    create_scan_with_outcome as create_scan_with_outcome_record,
    get_scan as get_scan_record,
    rescan_with_outcome as rescan_with_outcome_record,
)
from app.services.privacy_sanitizer import redact_sensitive_text


_SAFE_SCAN_ROLES = ["owner", "admin", "auditor", "operator"]
_DEEP_SCAN_ROLES = ["owner", "admin"]
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
_CURSOR_CONTEXT = b"hawk-hmair-scan-cursor-v1\x00"
_ENQUEUE_WARNING = "Discovery dispatch is pending and requires a safe retry."
_OMITTED_WARNING_NOTICE = "Additional warning detail was omitted for privacy."
_OMITTED_ERROR_NOTICE = "Additional error detail was omitted for privacy."
_BODY_FIELDS = frozenset(DiscoveryScanCreate.model_fields)
_DEEP_SCAN_SOURCE_LIMIT = 64

CoverageKey = Literal["confidence", "freshness", "unsupported", "unknown"]
CoverageValue = str | list[str]


class DiscoveryScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    name: str
    scan_type: str
    status: str
    safety_profile: str
    dry_run: bool
    observations_count: int
    warnings: list[str]
    errors: list[str]
    coverage_summary: dict[CoverageKey, CoverageValue]
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None


class DiscoveryScanListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DiscoveryScanResponse]
    total: int
    page: int
    page_size: int
    next_cursor: str | None


class DiscoveryScanEstimateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_ids: tuple[str, ...]
    collector_ids: tuple[str, ...]


class DiscoveryScanEstimateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_count: int
    collector_count: int
    eligible_assignment_count: int
    unsupported_pairs: list[dict[str, str]]
    permission_gaps: list[dict[str, object]]
    required_permissions: list[str]
    safety_profile: str
    exhaustive_claim_permitted: bool
    limitations: list[str]


class DiscoveryScanProgressResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    assignments_total: int
    assignments_by_state: dict[str, int]
    completion_percent: float
    observations_count: int
    assets_linked: int
    findings_open: int
    warnings: list[str]
    errors: list[str]


class DiscoveryScanResultsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    asset_ids: list[str]
    result_truncated: bool
    observations_count: int
    assets_created: int
    assets_updated: int
    assets_unresolved: int
    findings_open: int
    completion_confidence: str
    unsupported_sources: list[str]
    unknown_sources: list[str]
    exhaustive_claim_permitted: bool
    breadth: EnterpriseScanBreadth


class ScanRetentionPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retention_days: int = 90
    batch_size: int = 100


class ScanRetentionExecuteRequest(ScanRetentionPlanRequest):
    plan_digest: str


class DeepScanSourceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    collector_id: str
    target_type: str
    required: bool
    readiness: str
    observation_mode: str
    expected_count: int | None
    last_success_at: datetime | None
    limitations: list[str]


class DeepScanPreflightResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_digest: str
    preflight_digest: str
    mode: str
    sources: list[DeepScanSourceResponse]
    required_gaps: list[str]
    ready_assignment_count: int
    exhaustive_claim_permitted: bool


class DeepScanLaunchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan: DiscoveryScanResponse
    profile_digest: str
    preflight_digest: str
    ready_assignment_count: int
    exhaustive_claim_permitted: bool


class DeepScanCoverageSourceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    collector_id: str
    target_type: str
    required: bool
    readiness: str
    observation_mode: str
    expected_count: int | None
    coverage_state: str
    observed_count: int
    evidence_fresh_at: datetime | None
    limitation: list[str]
    reason: str | None


class DeepScanCoverageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    mode: str
    profile_digest: str
    exhaustive_claim_permitted: bool
    sources: list[DeepScanCoverageSourceResponse]


def _safe_validation_location(error: Mapping[str, object]) -> list[str]:
    raw_location = error.get("loc")
    location = tuple(raw_location) if isinstance(raw_location, (list, tuple)) else ()
    source = location[0] if location and location[0] in {"body", "header", "query"} else None
    if source == "body":
        field = next(
            (
                item
                for item in location[1:]
                if isinstance(item, str) and item in _BODY_FIELDS
            ),
            None,
        )
        return ["body", field] if field is not None else ["body"]
    if source == "header":
        field = next(
            (
                "Idempotency-Key"
                for item in location[1:]
                if isinstance(item, str)
                and item.casefold().replace("_", "-") == "idempotency-key"
            ),
            None,
        )
        return ["header", field] if field is not None else ["header"]
    if source == "query":
        field = next(
            (
                item
                for item in location[1:]
                if isinstance(item, str) and item in {"cursor", "limit"}
            ),
            None,
        )
        return ["query", field] if field is not None else ["query"]
    return ["request"]


class SanitizedHmairRoute(APIRoute):
    """Keep HMAIR validation errors useful without reflecting request input."""

    def get_route_handler(self) -> Callable[[Request], Awaitable[Response]]:
        original_handler = super().get_route_handler()

        async def sanitized_handler(request: Request) -> Response:
            # FastAPI parses request bodies before resolving router-level
            # dependencies. Conceal disabled HMAIR routes before either body
            # parsing or authentication, while retaining the dependency below
            # as defense in depth.
            require_hmair_core()
            try:
                return await original_handler(request)
            except RequestValidationError as error:
                raw_errors = error.errors()
                raw_error = raw_errors[0] if raw_errors else {}
                location = _safe_validation_location(raw_error)
                is_contract_error = (
                    str(raw_error.get("type", "")) == "hmair_contract_invalid"
                    or location[0] == "body"
                )
                return JSONResponse(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    content={
                        "detail": [
                            {
                                "type": (
                                    "hmair_contract_invalid"
                                    if is_contract_error
                                    else "hmair_request_invalid"
                                ),
                                "loc": location,
                                "msg": (
                                    "invalid HMAIR contract"
                                    if is_contract_error
                                    else "invalid HMAIR request"
                                ),
                            }
                        ]
                    },
                )

        return sanitized_handler


def require_hmair_core() -> None:
    if getattr(settings, "hmair_core", False) is not True:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


router = APIRouter(
    prefix="/discovery/scans",
    tags=["discovery"],
    dependencies=[Depends(require_hmair_core)],
    route_class=SanitizedHmairRoute,
)


def _request_invalid(location: list[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=[
            {
                "type": "hmair_request_invalid",
                "loc": location,
                "msg": "invalid HMAIR request",
            }
        ],
    )


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


def _selection_invalid() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail="Selected scan scope is not permitted",
    )


def _flag_enabled(name: str) -> bool:
    return getattr(settings, name, False) is True


def _surface_enabled(target_type: str) -> bool:
    flag = _SURFACE_FLAGS.get(target_type)
    return flag is not None and _flag_enabled(flag)


def _require_active_scan() -> None:
    if not _flag_enabled("hmair_active_scan"):
        raise _not_found()


def _require_deep_scan_source_flags(
    sources: tuple[object, ...],
) -> None:
    """Keep Deep Scan source bridges opt-in even when a surface is enabled."""

    for source in sources:
        target_type = getattr(source, "target_type", None)
        if target_type in set(CONNECTOR_TARGET_TYPES.values()) and not _flag_enabled(
            "hmair_connector_sources"
        ):
            raise _not_found()


def _deep_scan_source_response(source: object) -> DeepScanSourceResponse:
    return DeepScanSourceResponse(
        target_id=str(getattr(source, "target_id")),
        collector_id=str(getattr(source, "collector_id")),
        target_type=str(getattr(source, "target_type")),
        required=bool(getattr(source, "required")),
        readiness=str(getattr(source, "state")),
        observation_mode=str(getattr(source, "observation_mode")),
        expected_count=getattr(source, "expected_count", None),
        last_success_at=getattr(source, "last_success_at", None),
        limitations=list(getattr(source, "limitations", ())),
    )


def _deep_scan_launch_request_digest(payload: DeepScanLaunchRequest) -> str:
    """Use a stable idempotency comparison that excludes profile issuance."""

    return deep_scan_profile_digest(
        {
            "version": "v1",
            "name": payload.name,
            "preflight_digest": payload.preflight_digest,
            "dry_run": payload.dry_run,
        }
    )


def _stored_deep_scan_launch_digest(row: DiscoveryScan) -> str | None:
    scope = row.scope_json
    if not isinstance(scope, Mapping):
        return None
    value = scope.get("deep_scan_launch_request_digest")
    return value if isinstance(value, str) and len(value) == 64 else None


def _deep_scan_profile_from_scan(row: DiscoveryScan) -> DeepScanStoredProfile:
    scope = row.scope_json
    raw = scope.get("deep_scan") if isinstance(scope, Mapping) else None
    if not isinstance(raw, Mapping) or raw.get("version") != "v1":
        raise _not_found()
    try:
        return parse_persisted_deep_scan_profile(raw)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Deep Scan profile is unavailable",
        ) from None


def _deep_scan_preflight_response(
    preflight: DeepScanPreflightResult,
) -> DeepScanPreflightResponse:
    return DeepScanPreflightResponse(
        profile_digest=preflight.profile.digest,
        preflight_digest=preflight.preflight_digest,
        mode=preflight.profile.mode,
        sources=[_deep_scan_source_response(item) for item in preflight.sources],
        required_gaps=list(preflight.required_gaps),
        ready_assignment_count=preflight.ready_assignment_count,
        exhaustive_claim_permitted=preflight.exhaustive_claim_permitted,
    )


def _bounded_idempotency_key(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 128:
        raise _request_invalid(["header", "Idempotency-Key"])
    return normalized


def _bounded_redacted_strings(
    value: object,
    *,
    max_items: int,
    max_chars: int,
    omitted_notice: str,
) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    projected: list[str] = []
    omitted = False
    for item in value:
        if len(projected) >= max_items:
            break
        if type(item) is not str:
            omitted = True
            continue
        clean = item.strip()
        if not clean:
            omitted = True
            continue
        safe = redact_sensitive_text(clean, max_len=max_chars)[:max_chars].strip()
        if not safe:
            omitted = True
            continue
        projected.append(safe)
    if omitted and omitted_notice not in projected:
        if len(projected) >= max_items:
            projected[-1] = omitted_notice
        else:
            projected.append(omitted_notice)
    return projected


def _bounded_safe_strings(
    value: object,
    *,
    max_items: int,
    max_chars: int,
) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    projected: list[str] = []
    for item in value:
        if len(projected) >= max_items:
            break
        if type(item) is not str:
            continue
        clean = item.strip()
        if not clean:
            continue
        privacy_checked = redact_sensitive_text(
            clean,
            max_len=max(1, len(clean)),
        )
        if privacy_checked != clean:
            continue
        projected.append(clean[:max_chars])
    return projected


def _bounded_safe_scalar(value: object, *, max_chars: int) -> str | None:
    if type(value) is not str:
        return None
    clean = value.strip()
    if not clean:
        return None
    privacy_checked = redact_sensitive_text(
        clean,
        max_len=max(1, len(clean)),
    )
    if privacy_checked != clean:
        return None
    return clean[:max_chars]


def _coverage_summary(value: object) -> dict[CoverageKey, CoverageValue]:
    if not isinstance(value, Mapping):
        return {}
    projected: dict[CoverageKey, CoverageValue] = {}
    for key in ("confidence", "freshness"):
        if key not in value:
            continue
        scalar = _bounded_safe_scalar(value[key], max_chars=32)
        if scalar is not None:
            projected[key] = scalar
    for key in ("unsupported", "unknown"):
        if key in value:
            projected[key] = _bounded_safe_strings(
                value[key],
                max_items=64,
                max_chars=128,
            )
    return projected


def _scan_response(row: DiscoveryScan) -> DiscoveryScanResponse:
    return DiscoveryScanResponse(
        scan_id=row.scan_id,
        name=row.name,
        scan_type=row.scan_type,
        status=row.status,
        safety_profile=row.safety_profile,
        dry_run=row.dry_run,
        observations_count=row.observations_count,
        warnings=_bounded_redacted_strings(
            row.warnings_json,
            max_items=64,
            max_chars=500,
            omitted_notice=_OMITTED_WARNING_NOTICE,
        ),
        errors=_bounded_redacted_strings(
            row.errors_json,
            max_items=64,
            max_chars=500,
            omitted_notice=_OMITTED_ERROR_NOTICE,
        ),
        coverage_summary=_coverage_summary(row.coverage_summary_json),
        started_at=row.started_at,
        completed_at=row.completed_at,
        cancelled_at=row.cancelled_at,
    )


def _load_tenant_selections(
    db: Session,
    *,
    tenant_id: str,
    target_ids: tuple[str, ...],
    collector_ids: tuple[str, ...],
) -> tuple[dict[str, DiscoveryTarget], dict[str, DiscoveryCollector]]:
    targets = {
        row.target_id: row
        for row in db.scalars(
            select(DiscoveryTarget).where(
                DiscoveryTarget.tenant_id == tenant_id,
                DiscoveryTarget.target_id.in_(target_ids),
            )
        )
    }
    collectors = {
        row.collector_id: row
        for row in db.scalars(
            select(DiscoveryCollector).where(
                DiscoveryCollector.tenant_id == tenant_id,
                DiscoveryCollector.collector_id.in_(collector_ids),
            )
        )
    }
    if set(targets) != set(target_ids) or set(collectors) != set(collector_ids):
        raise _not_found()
    return targets, collectors


def _validate_scan_selections(
    *,
    targets: Mapping[str, DiscoveryTarget],
    collectors: Mapping[str, DiscoveryCollector],
    assignment_pairs: tuple[tuple[str, str], ...] | None = None,
) -> None:
    for target in targets.values():
        if not _surface_enabled(target.target_type):
            raise _not_found()
        if target.active_scan_allowed is not True:
            raise _selection_invalid()

    pairs = assignment_pairs or tuple(
        (target_id, collector_id)
        for target_id in targets
        for collector_id in collectors
    )
    if not pairs:
        raise _selection_invalid()
    for target_id, collector_id in pairs:
        target = targets.get(target_id)
        collector = collectors.get(collector_id)
        if target is None or collector is None:
            raise _not_found()
        if target.target_type not in set(collector.supported_targets_json or []):
            raise _selection_invalid()
        permitted_methods = set(target.permitted_methods_json or [])
        active_capabilities = set(collector.active_capabilities_json or [])
        if not active_capabilities.issubset(permitted_methods):
            raise _selection_invalid()


def _persist_enqueue_warning(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> DiscoveryScan:
    row = get_scan_record(db, tenant_id=tenant_id, scan_id=scan_id)
    if row is None:
        raise _not_found()
    warnings = list(row.warnings_json or [])
    if _ENQUEUE_WARNING not in warnings:
        warnings.append(_ENQUEUE_WARNING)
        row.warnings_json = warnings
    db.commit()
    return row


def _clear_enqueue_warning(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> DiscoveryScan:
    row = get_scan_record(db, tenant_id=tenant_id, scan_id=scan_id)
    if row is None:
        raise _not_found()
    row.warnings_json = [
        warning
        for warning in (row.warnings_json or [])
        if warning != _ENQUEUE_WARNING
    ]
    db.commit()
    return row


def _dispatch_new_scan(
    db: Session,
    *,
    tenant_id: str,
    scan: DiscoveryScan,
    created: bool,
) -> DiscoveryScan:
    pending_retry = _ENQUEUE_WARNING in list(scan.warnings_json or [])
    if not created and not pending_retry:
        return scan
    try:
        dispatch_scan.delay(tenant_id, scan.scan_id)
    except Exception:  # The broker error may contain credentials; never reflect it.
        return _persist_enqueue_warning(
            db,
            tenant_id=tenant_id,
            scan_id=scan.scan_id,
        )
    if pending_retry:
        return _clear_enqueue_warning(
            db,
            tenant_id=tenant_id,
            scan_id=scan.scan_id,
        )
    return scan


def _cursor_secret() -> bytes:
    return str(settings.secret_key).encode("utf-8")


def _base64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


def _encode_cursor(row: DiscoveryScan) -> str:
    payload = json.dumps(
        {"created_at": row.created_at.isoformat(), "scan_id": row.scan_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(
        _cursor_secret(),
        _CURSOR_CONTEXT + payload,
        hashlib.sha256,
    ).digest()
    return f"v1.{_base64_encode(payload)}.{_base64_encode(signature)}"


def _decode_cursor(value: str) -> tuple[datetime, str]:
    try:
        version, encoded_payload, encoded_signature = value.split(".", 2)
        if version != "v1":
            raise ValueError("unsupported cursor")
        payload = _base64_decode(encoded_payload)
        signature = _base64_decode(encoded_signature)
        expected = hmac.new(
            _cursor_secret(),
            _CURSOR_CONTEXT + payload,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid cursor signature")
        decoded = json.loads(payload)
        if not isinstance(decoded, dict) or set(decoded) != {"created_at", "scan_id"}:
            raise ValueError("invalid cursor payload")
        created_at = datetime.fromisoformat(decoded["created_at"])
        scan_id = decoded["scan_id"]
        if not isinstance(scan_id, str) or not 1 <= len(scan_id) <= 36:
            raise ValueError("invalid cursor scan")
        return created_at, scan_id
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        raise _request_invalid(["query", "cursor"]) from None


@router.post("/estimate", response_model=DiscoveryScanEstimateResponse)
def estimate_scan(
    payload: DiscoveryScanEstimateRequest,
    ctx: TenantContext = Depends(require_permission("discovery.scan")),
    db: Session = Depends(get_db),
) -> DiscoveryScanEstimateResponse:
    if not payload.target_ids or not payload.collector_ids:
        raise _selection_invalid()
    targets, collectors = _load_tenant_selections(
        db,
        tenant_id=ctx.tenant.id,
        target_ids=payload.target_ids,
        collector_ids=payload.collector_ids,
    )
    unsupported: list[dict[str, str]] = []
    permission_gaps: list[dict[str, object]] = []
    eligible = 0
    required_permissions: set[str] = set()
    for target_id, target in targets.items():
        for collector_id, collector in collectors.items():
            supported = (
                target.target_type in set(collector.supported_targets_json or [])
                and _surface_enabled(target.target_type)
            )
            if not supported:
                unsupported.append(
                    {"target_id": target_id, "collector_id": collector_id}
                )
                continue
            permitted = set(target.permitted_methods_json or [])
            required = set(collector.active_capabilities_json or [])
            required_permissions.update(
                str(item)
                for item in (collector.permissions_required_json or [])
                if type(item) is str and item
            )
            missing = sorted(required - permitted)
            if target.active_scan_allowed is not True or missing:
                permission_gaps.append(
                    {
                        "target_id": target_id,
                        "collector_id": collector_id,
                        "active_scan_allowed": target.active_scan_allowed,
                        "missing_methods": missing,
                    }
                )
                continue
            eligible += 1
    exhaustive = (
        eligible > 0
        and not unsupported
        and not permission_gaps
        and all(row.health == "healthy" for row in collectors.values())
    )
    limitations = [
        "Estimate covers only the selected registered targets and collectors.",
        "No result is an enterprise-wide proof unless a complete authoritative denominator is attached.",
    ]
    if unsupported:
        limitations.append("Some target and collector pairs are unsupported or disabled.")
    if permission_gaps:
        limitations.append("Some selected pairs cannot run with current safety permissions.")
    return DiscoveryScanEstimateResponse(
        target_count=len(targets),
        collector_count=len(collectors),
        eligible_assignment_count=eligible,
        unsupported_pairs=unsupported,
        permission_gaps=permission_gaps,
        required_permissions=sorted(required_permissions),
        safety_profile="read_only",
        exhaustive_claim_permitted=exhaustive,
        limitations=limitations,
    )


@router.post(
    "/deep-scan/preflight",
    response_model=DeepScanPreflightResponse,
)
def preflight_production_deep_scan(
    payload: DeepScanPreflightRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> DeepScanPreflightResponse:
    """Return only current, tenant-scoped Deep Scan readiness metadata."""

    _require_active_scan()
    try:
        preflight = preflight_deep_scan(
            db,
            tenant_id=ctx.tenant.id,
            request=payload,
        )
    except LookupError:
        raise _not_found() from None
    except ValueError:
        raise _request_invalid(["body"]) from None
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=(ctx.user.id if ctx.user is not None else None),
        actor_type="human",
        action="discovery.deep_scan.preflight",
        resource_type="discovery_scan_preflight",
        resource_id=preflight.profile.digest[:36],
        payload={
            "mode": preflight.profile.mode,
            "target_count": len(payload.target_ids),
            "collector_count": len(payload.collector_ids),
            "ready_source_count": preflight.ready_assignment_count,
            "required_gap_count": len(preflight.required_gaps),
        },
    )
    db.commit()
    return _deep_scan_preflight_response(preflight)


@router.post(
    "/deep-scan",
    response_model=DeepScanLaunchResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def launch_production_deep_scan(
    payload: DeepScanLaunchRequest,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=1,
        max_length=128,
    ),
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> DeepScanLaunchResponse:
    """Freeze a current profile and launch only its exact ready source pairs."""

    _require_active_scan()
    request_key = _bounded_idempotency_key(idempotency_key)
    launch_digest = _deep_scan_launch_request_digest(payload)
    existing = db.scalar(
        select(DiscoveryScan).where(
            DiscoveryScan.tenant_id == ctx.tenant.id,
            DiscoveryScan.request_idempotency_key == request_key,
        )
    )
    if existing is not None:
        if _stored_deep_scan_launch_digest(existing) != launch_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency key conflicts with an existing request",
            )
        profile = _deep_scan_profile_from_scan(existing)
        return DeepScanLaunchResponse(
            scan=_scan_response(existing),
            profile_digest=profile.digest,
            preflight_digest=payload.preflight_digest,
            ready_assignment_count=sum(
                source.state.value == "ready" for source in profile.sources
            ),
            # A repeated launch response is not completion evidence. The
            # coverage endpoint is the only place a completed claim can be
            # evaluated, and P0 intentionally has no enterprise scope closure.
            exhaustive_claim_permitted=False,
        )

    try:
        preflight = preflight_deep_scan(
            db,
            tenant_id=ctx.tenant.id,
            request=payload.preflight,
        )
    except LookupError:
        raise _not_found() from None
    except ValueError:
        raise _request_invalid(["body"]) from None
    if payload.preflight_digest != preflight.preflight_digest:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Deep Scan prerequisites changed; run preflight again",
        )
    if (
        payload.preflight.requested_mode == "full_enterprise"
        and not preflight.exhaustive_claim_permitted
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Full enterprise Deep Scan requires complete authoritative coverage readiness",
        )
    ready_sources = tuple(
        source
        for source in preflight.sources
        if source.state.value == "ready"
    )
    if not ready_sources:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No selected Deep Scan sources are currently ready",
        )
    _require_deep_scan_source_flags(ready_sources)
    target_ids = tuple(source.target_id for source in ready_sources)
    collector_ids = tuple(
        dict.fromkeys(source.collector_id for source in ready_sources)
    )
    targets, collectors = _load_tenant_selections(
        db,
        tenant_id=ctx.tenant.id,
        target_ids=target_ids,
        collector_ids=collector_ids,
    )
    assignment_pairs = tuple(
        (source.target_id, source.collector_id) for source in ready_sources
    )
    _validate_scan_selections(
        targets=targets,
        collectors=collectors,
        assignment_pairs=assignment_pairs,
    )
    profile = freeze_deep_scan_profile(
        preflight=preflight,
        request=payload.preflight,
    )
    scan_payload = DiscoveryScanCreate(
        name=payload.name,
        scan_type=(
            "full_enterprise"
            if payload.preflight.requested_mode == "full_enterprise"
            else "targeted"
        ),
        scope={
            "deep_scan": persist_deep_scan_profile(profile).model_dump(mode="json"),
            "deep_scan_preflight_digest": preflight.preflight_digest,
            "deep_scan_launch_request_digest": launch_digest,
            "deep_scan_preflight_exhaustive_claim_permitted": (
                preflight.exhaustive_claim_permitted
            ),
        },
        target_ids=target_ids,
        collector_ids=collector_ids,
        safety_profile="metadata_only",
        dry_run=payload.dry_run,
    )
    try:
        with db.begin_nested():
            outcome = create_scan_with_assignment_pairs_outcome(
                db,
                tenant_id=ctx.tenant.id,
                requested_by=ctx.user.id if ctx.user is not None else None,
                request_idempotency_key=request_key,
                payload=scan_payload,
                assignment_pairs=assignment_pairs,
            )
            if outcome.created:
                write_audit_log(
                    db,
                    tenant_id=ctx.tenant.id,
                    actor_user_id=(ctx.user.id if ctx.user is not None else None),
                    actor_type="human",
                    action="discovery.deep_scan.launch",
                    resource_type="discovery_scan",
                    resource_id=outcome.scan.scan_id,
                    payload={
                        "mode": profile.mode,
                        "ready_source_count": len(ready_sources),
                        "dry_run": payload.dry_run,
                    },
                )
        db.commit()
    except LookupError:
        db.rollback()
        raise _not_found() from None
    except ValueError:
        db.rollback()
        winner = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == ctx.tenant.id,
                DiscoveryScan.request_idempotency_key == request_key,
            )
        )
        if winner is not None and _stored_deep_scan_launch_digest(winner) == launch_digest:
            outcome_scan = winner
            outcome_created = False
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency key conflicts with an existing request",
            ) from None
    except Exception:
        db.rollback()
        raise
    else:
        outcome_scan = outcome.scan
        outcome_created = outcome.created
    scan = _dispatch_new_scan(
        db,
        tenant_id=ctx.tenant.id,
        scan=outcome_scan,
        created=outcome_created,
    )
    return DeepScanLaunchResponse(
        scan=_scan_response(scan),
        profile_digest=profile.digest,
        preflight_digest=preflight.preflight_digest,
        ready_assignment_count=len(ready_sources),
        exhaustive_claim_permitted=preflight.exhaustive_claim_permitted,
    )


@router.post("", response_model=DiscoveryScanResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    payload: DiscoveryScanCreate,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=1,
        max_length=128,
    ),
    ctx: TenantContext = Depends(require_permission("discovery.scan")),
    db: Session = Depends(get_db),
) -> DiscoveryScanResponse:
    _require_active_scan()
    request_key = _bounded_idempotency_key(idempotency_key)
    targets, collectors = _load_tenant_selections(
        db,
        tenant_id=ctx.tenant.id,
        target_ids=payload.target_ids,
        collector_ids=payload.collector_ids,
    )
    _validate_scan_selections(targets=targets, collectors=collectors)
    try:
        with db.begin_nested():
            outcome = create_scan_with_outcome_record(
                db,
                tenant_id=ctx.tenant.id,
                requested_by=ctx.user.id if ctx.user is not None else None,
                request_idempotency_key=request_key,
                payload=payload,
            )
            if outcome.created:
                write_audit_log(
                    db,
                    tenant_id=ctx.tenant.id,
                    actor_user_id=(ctx.user.id if ctx.user is not None else None),
                    actor_type="human",
                    action="discovery.scan.create",
                    resource_type="discovery_scan",
                    resource_id=outcome.scan.scan_id,
                    payload={
                        "scan_type": outcome.scan.scan_type,
                        "safety_profile": outcome.scan.safety_profile,
                        "dry_run": outcome.scan.dry_run,
                        "exclusion_count": len(
                            (outcome.scan.scope_json or {}).get("exclusions", [])
                        ),
                    },
                )
        db.commit()
    except LookupError:
        db.rollback()
        raise _not_found() from None
    except ValueError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Idempotency key conflicts with an existing request",
        ) from None
    except Exception:
        db.rollback()
        raise
    scan = _dispatch_new_scan(
        db,
        tenant_id=ctx.tenant.id,
        scan=outcome.scan,
        created=outcome.created,
    )
    return _scan_response(scan)


@router.get("", response_model=DiscoveryScanListResponse)
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=255),
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DiscoveryScanListResponse:
    total = int(
        db.scalar(
            select(func.count(DiscoveryScan.scan_id)).where(
                DiscoveryScan.tenant_id == ctx.tenant.id
            )
        )
        or 0
    )
    query = select(DiscoveryScan).where(DiscoveryScan.tenant_id == ctx.tenant.id)
    if cursor is not None:
        cursor_created_at, cursor_scan_id = _decode_cursor(cursor)
        query = query.where(
            or_(
                DiscoveryScan.created_at < cursor_created_at,
                and_(
                    DiscoveryScan.created_at == cursor_created_at,
                    DiscoveryScan.scan_id < cursor_scan_id,
                ),
            )
        )
    rows = list(
        db.scalars(
            query.order_by(
                DiscoveryScan.created_at.desc(),
                DiscoveryScan.scan_id.desc(),
            ).limit(limit + 1)
        )
    )
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    return DiscoveryScanListResponse(
        items=[_scan_response(row) for row in page_rows],
        total=total,
        page=1,
        page_size=limit,
        next_cursor=(
            _encode_cursor(page_rows[-1])
            if has_more and page_rows
            else None
        ),
    )


@router.post("/retention/plan", response_model=ScanSummaryCompactionPlan)
def plan_scan_summary_retention(
    payload: ScanRetentionPlanRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> ScanSummaryCompactionPlan:
    try:
        return plan_terminal_scan_summary_compaction(
            db,
            tenant_id=ctx.tenant.id,
            now=datetime.now(timezone.utc),
            retention_days=payload.retention_days,
            batch_size=payload.batch_size,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None


@router.post("/retention/compact", response_model=ScanSummaryCompactionResult)
def compact_scan_summaries(
    payload: ScanRetentionExecuteRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> ScanSummaryCompactionResult:
    try:
        with db.begin_nested():
            result = compact_terminal_scan_summaries(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=ctx.user.id if ctx.user is not None else None,
                now=datetime.now(timezone.utc),
                retention_days=payload.retention_days,
                batch_size=payload.batch_size,
                plan_digest=payload.plan_digest,
            )
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from None
    except Exception:
        db.rollback()
        raise


@router.get("/{scan_id}/coverage", response_model=DeepScanCoverageResponse)
def get_deep_scan_coverage(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DeepScanCoverageResponse:
    """Return bounded coverage facts for a frozen Deep Scan profile only."""

    row = get_scan_record(db, tenant_id=ctx.tenant.id, scan_id=scan_id)
    if row is None:
        raise _not_found()
    profile = _deep_scan_profile_from_scan(row)
    raw_summary = row.coverage_summary_json
    raw_deep = (
        raw_summary.get("deep_scan") if isinstance(raw_summary, Mapping) else None
    )
    raw_sources = raw_deep.get("sources") if isinstance(raw_deep, Mapping) else ()
    coverage_by_source: dict[tuple[str, str], DeepScanSourceCoverage] = {}
    if isinstance(raw_sources, (list, tuple)):
        for raw_source in raw_sources[:_DEEP_SCAN_SOURCE_LIMIT]:
            try:
                source = DeepScanSourceCoverage.model_validate(raw_source)
            except ValueError:
                continue
            coverage_by_source[(source.target_id, source.collector_id)] = source
    exhaustive = bool(
        row.status == "complete"
        and isinstance(raw_deep, Mapping)
        and raw_deep.get("exhaustive_claim_permitted") is True
    )
    sources: list[DeepScanCoverageSourceResponse] = []
    for profile_source in profile.sources:
        coverage = coverage_by_source.get(
            (profile_source.target_id, profile_source.collector_id)
        )
        sources.append(
            DeepScanCoverageSourceResponse(
                target_id=profile_source.target_id,
                collector_id=profile_source.collector_id,
                target_type=profile_source.target_type,
                required=profile_source.required,
                readiness=profile_source.state.value,
                observation_mode=profile_source.observation_mode.value,
                expected_count=profile_source.expected_count,
                coverage_state=(
                    coverage.state.value
                    if coverage is not None
                    else DeepScanCoverageState.UNKNOWN.value
                ),
                observed_count=(coverage.observed_count if coverage is not None else 0),
                evidence_fresh_at=(
                    coverage.evidence_fresh_at if coverage is not None else None
                ),
                limitation=list(profile_source.limitations),
                reason=(coverage.reason if coverage is not None else None),
            )
        )
    return DeepScanCoverageResponse(
        scan_id=row.scan_id,
        status=row.status,
        mode=profile.mode,
        profile_digest=profile.digest,
        exhaustive_claim_permitted=exhaustive,
        sources=sources,
    )


@router.get("/{scan_id}", response_model=DiscoveryScanResponse)
def get_scan(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DiscoveryScanResponse:
    row = get_scan_record(db, tenant_id=ctx.tenant.id, scan_id=scan_id)
    if row is None:
        raise _not_found()
    return _scan_response(row)


def _scan_asset_ids(
    db: Session, *, tenant_id: str, scan_id: str, limit: int = 10_000
) -> tuple[list[str], bool]:
    bounded_limit = max(1, min(limit, 10_000))
    rows = list(
        db.scalars(
            select(DiscoveryObservationAssetLink.asset_id)
            .join(
                DiscoveryObservation,
                and_(
                    DiscoveryObservation.tenant_id
                    == DiscoveryObservationAssetLink.tenant_id,
                    DiscoveryObservation.observation_id
                    == DiscoveryObservationAssetLink.observation_id,
                ),
            )
            .where(
                DiscoveryObservationAssetLink.tenant_id == tenant_id,
                DiscoveryObservation.scan_id == scan_id,
            )
            .distinct()
            .order_by(DiscoveryObservationAssetLink.asset_id)
            .limit(bounded_limit + 1)
        )
    )
    return rows[:bounded_limit], len(rows) > bounded_limit


@router.get("/{scan_id}/progress", response_model=DiscoveryScanProgressResponse)
def get_scan_progress(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DiscoveryScanProgressResponse:
    row = get_scan_record(db, tenant_id=ctx.tenant.id, scan_id=scan_id)
    if row is None:
        raise _not_found()
    assignments_by_state = {
        str(state): int(count)
        for state, count in db.execute(
            select(DiscoveryScanAssignment.status, func.count())
            .where(
                DiscoveryScanAssignment.tenant_id == ctx.tenant.id,
                DiscoveryScanAssignment.scan_id == scan_id,
            )
            .group_by(DiscoveryScanAssignment.status)
        )
    }
    total = sum(assignments_by_state.values())
    terminal = sum(
        assignments_by_state.get(state, 0)
        for state in (
            "complete", "failed", "cancelled", "unsupported",
            "permission_denied", "rate_limited", "stale",
        )
    )
    asset_ids, _ = _scan_asset_ids(
        db, tenant_id=ctx.tenant.id, scan_id=scan_id
    )
    findings_open = 0
    if asset_ids:
        findings_open = int(
            db.scalar(
                select(func.count(DiscoveryAssetFinding.finding_id)).where(
                    DiscoveryAssetFinding.tenant_id == ctx.tenant.id,
                    DiscoveryAssetFinding.asset_id.in_(asset_ids),
                    DiscoveryAssetFinding.status.in_(["open", "reviewing"]),
                )
            )
            or 0
        )
    return DiscoveryScanProgressResponse(
        scan_id=row.scan_id,
        status=row.status,
        assignments_total=total,
        assignments_by_state=assignments_by_state,
        completion_percent=(round(100.0 * terminal / total, 2) if total else 0.0),
        observations_count=row.observations_count,
        assets_linked=len(asset_ids),
        findings_open=findings_open,
        warnings=_bounded_redacted_strings(
            row.warnings_json,
            max_items=64,
            max_chars=500,
            omitted_notice=_OMITTED_WARNING_NOTICE,
        ),
        errors=_bounded_redacted_strings(
            row.errors_json,
            max_items=64,
            max_chars=500,
            omitted_notice=_OMITTED_ERROR_NOTICE,
        ),
    )


@router.get("/{scan_id}/diagnostics", response_model=EnterpriseScanDiagnostics)
def get_scan_diagnostics(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> EnterpriseScanDiagnostics:
    try:
        return build_scan_diagnostics(
            db,
            tenant_id=ctx.tenant.id,
            scan_id=scan_id,
        )
    except LookupError:
        raise _not_found() from None


@router.get("/{scan_id}/results", response_model=DiscoveryScanResultsResponse)
def get_scan_results(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DiscoveryScanResultsResponse:
    row = get_scan_record(db, tenant_id=ctx.tenant.id, scan_id=scan_id)
    if row is None:
        raise _not_found()
    asset_ids, result_truncated = _scan_asset_ids(
        db, tenant_id=ctx.tenant.id, scan_id=scan_id
    )
    findings_open = 0
    if asset_ids:
        findings_open = int(
            db.scalar(
                select(func.count(DiscoveryAssetFinding.finding_id)).where(
                    DiscoveryAssetFinding.tenant_id == ctx.tenant.id,
                    DiscoveryAssetFinding.asset_id.in_(asset_ids),
                    DiscoveryAssetFinding.status.in_(["open", "reviewing"]),
                )
            )
            or 0
        )
    coverage = _coverage_summary(row.coverage_summary_json)
    unsupported = list(coverage.get("unsupported", []))
    unknown = list(coverage.get("unknown", []))
    raw_coverage = (
        row.coverage_summary_json
        if isinstance(row.coverage_summary_json, Mapping)
        else {}
    )
    raw_deep_scan = raw_coverage.get("deep_scan")
    if isinstance(raw_deep_scan, Mapping):
        exhaustive = (
            row.status == "complete"
            and raw_deep_scan.get("exhaustive_claim_permitted") is True
        )
    else:
        exhaustive = (
            row.status == "complete"
            and raw_coverage.get("denominator_complete") is True
            and not unsupported
            and not unknown
        )
    confidence = str(coverage.get("confidence") or "unknown")
    return DiscoveryScanResultsResponse(
        scan_id=row.scan_id,
        status=row.status,
        asset_ids=asset_ids,
        result_truncated=result_truncated,
        observations_count=row.observations_count,
        assets_created=row.assets_created,
        assets_updated=row.assets_updated,
        assets_unresolved=row.assets_unresolved,
        findings_open=findings_open,
        completion_confidence=confidence,
        unsupported_sources=unsupported,
        unknown_sources=unknown,
        exhaustive_claim_permitted=exhaustive,
        breadth=build_scan_result_breadth(
            db,
            tenant_id=ctx.tenant.id,
            scan_id=scan_id,
            asset_ids=asset_ids,
        ),
    )


@router.post("/{scan_id}/cancel", response_model=DiscoveryScanResponse)
def cancel_scan(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.scan")),
    db: Session = Depends(get_db),
) -> DiscoveryScanResponse:
    try:
        with db.begin_nested():
            outcome = cancel_scan_with_outcome_record(
                db,
                tenant_id=ctx.tenant.id,
                scan_id=scan_id,
            )
            if outcome.changed:
                write_audit_log(
                    db,
                    tenant_id=ctx.tenant.id,
                    actor_user_id=(ctx.user.id if ctx.user is not None else None),
                    actor_type="human",
                    action="discovery.scan.cancel",
                    resource_type="discovery_scan",
                    resource_id=outcome.scan.scan_id,
                    payload={"status": "cancelled"},
                )
        db.commit()
    except LookupError:
        db.rollback()
        raise _not_found() from None
    except ValueError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan state does not allow cancellation",
        ) from None
    except Exception:
        db.rollback()
        raise
    return _scan_response(outcome.scan)


@router.post(
    "/{scan_id}/rescan",
    response_model=DiscoveryScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def rescan(
    scan_id: str,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=1,
        max_length=128,
    ),
    ctx: TenantContext = Depends(require_permission("discovery.scan")),
    db: Session = Depends(get_db),
) -> DiscoveryScanResponse:
    _require_active_scan()
    request_key = _bounded_idempotency_key(idempotency_key)
    source = get_scan_record(db, tenant_id=ctx.tenant.id, scan_id=scan_id)
    if source is None:
        raise _not_found()
    target_ids = tuple(
        db.scalars(
            select(DiscoveryScanTarget.target_id).where(
                DiscoveryScanTarget.tenant_id == ctx.tenant.id,
                DiscoveryScanTarget.scan_id == scan_id,
            )
        )
    )
    assignments = tuple(
        db.scalars(
            select(DiscoveryScanAssignment).where(
                DiscoveryScanAssignment.tenant_id == ctx.tenant.id,
                DiscoveryScanAssignment.scan_id == scan_id,
            )
        )
    )
    collector_ids = tuple(sorted({row.collector_id for row in assignments}))
    if not target_ids or not collector_ids or not assignments:
        raise _not_found()
    targets, collectors = _load_tenant_selections(
        db,
        tenant_id=ctx.tenant.id,
        target_ids=target_ids,
        collector_ids=collector_ids,
    )
    _validate_scan_selections(
        targets=targets,
        collectors=collectors,
        assignment_pairs=tuple(
            (assignment.target_id, assignment.collector_id)
            for assignment in assignments
        ),
    )
    try:
        with db.begin_nested():
            outcome = rescan_with_outcome_record(
                db,
                tenant_id=ctx.tenant.id,
                scan_id=scan_id,
                requested_by=ctx.user.id if ctx.user is not None else None,
                request_idempotency_key=request_key,
            )
            if outcome.created:
                write_audit_log(
                    db,
                    tenant_id=ctx.tenant.id,
                    actor_user_id=(ctx.user.id if ctx.user is not None else None),
                    actor_type="human",
                    action="discovery.scan.rescan",
                    resource_type="discovery_scan",
                    resource_id=outcome.scan.scan_id,
                    payload={
                        "source_scan_id": scan_id,
                        "scan_type": outcome.scan.scan_type,
                        "safety_profile": outcome.scan.safety_profile,
                        "dry_run": outcome.scan.dry_run,
                    },
                )
        db.commit()
    except LookupError:
        db.rollback()
        raise _not_found() from None
    except ValueError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Idempotency key conflicts with an existing request",
        ) from None
    except Exception:
        db.rollback()
        raise
    row = _dispatch_new_scan(
        db,
        tenant_id=ctx.tenant.id,
        scan=outcome.scan,
        created=outcome.created,
    )
    return _scan_response(row)


__all__ = ["router"]
