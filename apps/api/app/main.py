from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import time
from uuid import uuid4

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import SQLAlchemyError

from app.api.routers import account_boundary, action_integrity, activity_audit, agui, agents, ai_discovery, ai_iam, ai_orchestration, ai_systems, ai_tools_usage, audit, auditor, auth, banking_transaction_integrity, brain, checkmarx, continuous_assurance, control_coverage, coverage, dashboard, deployments, discovery, discovery_adv, discovery_assets, discovery_capabilities, discovery_collectors, discovery_ecosystems, discovery_erg, discovery_exposure, discovery_scans, discovery_source_connections, discovery_surface_sources, discovery_targets, endpoint_agent, enforcement, executive_mcp, executive_remote_mcp, extension, external_risk, findings, gateway, guardian_contracts_v2, investigations, kb, llm_gateway, maturity_curve, monitoring, native_controls, onprem, ops, policies, policy_pack_platform, runtime, runtime_control, runtime_intelligence, scans, shadow_ai, simulation_policies, simulations, surface_coverage, system, trust_center, user_visibility
from app.api.routers import claude_enterprise
from app.core.config import configured_secret_sources, settings
from app.core.observability import (
    gateway_latency_paths,
    latency_tracker,
    log_structured,
    reset_correlation_id,
    set_correlation_id,
)
from app.db.session import SessionLocal
from app.services.audit_service import write_audit_log
from app.services.schema_health_service import evaluate_schema_health
from app.services.production_hardening import (
    ComponentHandshake,
    ProductionCheck,
    ProductionReadinessReport,
    compatibility_contract_from_settings,
    summarize_readiness,
    validate_production_configuration,
)
from app.services.snapshot_service import ensure_artifact_storage_writable


def _safe_internal_error_message(exc: Exception) -> str:
    text = " ".join(str(exc).split())
    return text[:500]


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _assert_production_readiness_or_fail_startup()
    _assert_schema_integrity_or_fail_startup()
    yield


_production_topology = settings.deployment_topology == "single_node_compose"
app = FastAPI(
    title=settings.app_name,
    version=settings.component_version,
    lifespan=lifespan,
    docs_url=None if _production_topology else "/docs",
    redoc_url=None if _production_topology else "/redoc",
    openapi_url=None if _production_topology else "/openapi.json",
)


@app.exception_handler(RequestValidationError)
async def redacted_request_validation_error(_request, exc: RequestValidationError):
    """Return useful validation locations without reflecting submitted values."""

    details = []
    for error in exc.errors():
        details.append(
            {
                key: error[key]
                for key in ("type", "loc", "msg", "url")
                if key in error
            }
        )
    return JSONResponse(status_code=422, content={"detail": details})

_EXTENSION_ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://", "edge-extension://")


def _split_csv(value: str | None) -> list[str]:
    return [item.strip().rstrip("/") for item in str(value or "").split(",") if item.strip()]


def _is_wildcard_origin(origin: str) -> bool:
    normalized = str(origin or "").strip().rstrip("/")
    if normalized == "*":
        return True
    return any(normalized == f"{prefix}*" for prefix in _EXTENSION_ORIGIN_PREFIXES)


def _build_cors_allowed_origins(
    *,
    web_origin: str | None = None,
    cors_origins: str | None = None,
    extension_cors_origins: str | None = None,
) -> list[str]:
    """Build an explicit CORS allowlist.

    CORS uses credentials, so wildcard web origins and wildcard extension origins
    are intentionally ignored. Managed browser deployments must pin the exact
    extension ID using EXTENSION_CORS_ORIGINS=chrome-extension://<id>.
    """

    origins = {
        str(web_origin if web_origin is not None else settings.web_origin).strip().rstrip("/"),
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    }
    origins.update(_split_csv(cors_origins if cors_origins is not None else settings.cors_origins))
    origins.update(
        _split_csv(
            extension_cors_origins
            if extension_cors_origins is not None
            else settings.extension_cors_origins
        )
    )
    return sorted(origin for origin in origins if origin and not _is_wildcard_origin(origin))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_build_cors_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        host.strip()
        for host in str(settings.trusted_hosts or "").split(",")
        if host.strip()
    ],
)


def _strict_schema_mode_enabled() -> bool:
    return bool(settings.pilot_mode) or str(settings.env or "").strip().lower() in {"pilot", "prod", "production"}


def _assert_schema_integrity_or_fail_startup() -> None:
    if not _strict_schema_mode_enabled():
        return

    with SessionLocal() as db:
        report = evaluate_schema_health(db)
    if report.healthy:
        return

    missing_tables = ", ".join(report.missing_tables) if report.missing_tables else "-"
    missing_columns = ", ".join(report.missing_columns) if report.missing_columns else "-"
    pending = ", ".join(report.pending_migrations) if report.pending_migrations else "-"
    details = (
        "Schema integrity check failed in strict mode. "
        f"missing_tables=[{missing_tables}] "
        f"missing_columns=[{missing_columns}] "
        f"pending_migrations=[{pending}]"
    )
    raise RuntimeError(details)


def _api_readiness_report() -> ProductionReadinessReport:
    checks: dict[str, ProductionCheck] = {}
    if _production_topology:
        configuration = validate_production_configuration(
            settings,
            secret_sources=configured_secret_sources(),
        )
        checks["configuration"] = ProductionCheck(
            ok=configuration.ready,
            critical=True,
            status="ok" if configuration.ready else "invalid",
            detail=(
                "production configuration valid"
                if configuration.ready
                else "configuration rejected:" + ",".join(configuration.reason_codes)
            ),
        )
    else:
        checks["configuration"] = ProductionCheck(
            ok=True,
            critical=True,
            status="development",
            detail="production contract not selected",
        )

    try:
        contract = compatibility_contract_from_settings(settings)
        compatibility = contract.evaluate(
            ComponentHandshake(
                component_type=settings.component_type,
                component_version=settings.component_version,
                protocol_version=settings.component_protocol_version,
                deployment_id=settings.deployment_id,
                capability_version="phase9/1.0",
            )
        )
        checks["component_compatibility"] = ProductionCheck(
            ok=compatibility.accepted and compatibility.capability_verified,
            critical=True,
            status=compatibility.status,
            detail=compatibility.reason_code,
        )
    except ValueError as exc:
        checks["component_compatibility"] = ProductionCheck(
            ok=False,
            critical=True,
            status="incompatible",
            detail=str(exc),
        )

    try:
        with SessionLocal() as db:
            schema = evaluate_schema_health(db)
        checks["database_schema"] = ProductionCheck(
            ok=schema.healthy,
            critical=True,
            status="ok" if schema.healthy else "out_of_date",
            detail="schema at repository head" if schema.healthy else "database schema is incompatible",
        )
    except Exception:  # noqa: BLE001
        checks["database_schema"] = ProductionCheck(
            ok=False,
            critical=True,
            status="unavailable",
            detail="database/schema readiness check failed",
        )

    try:
        ensure_artifact_storage_writable()
        checks["artifact_storage"] = ProductionCheck(True, True, "ok", "artifact storage writable")
    except Exception:  # noqa: BLE001
        checks["artifact_storage"] = ProductionCheck(False, True, "unavailable", "artifact storage unavailable")
    return summarize_readiness(checks)


def _assert_production_readiness_or_fail_startup() -> None:
    if not _production_topology:
        return
    report = _api_readiness_report()
    if not report.ready:
        failed = [name for name, check in report.checks.items() if check.critical and not check.ok]
        raise RuntimeError("Production startup preflight failed: " + ",".join(sorted(failed)))


@app.middleware("http")
async def correlation_and_request_logging_middleware(request, call_next):
    correlation_id = request.headers.get("x-correlation-id") or str(uuid4())
    token = set_correlation_id(correlation_id)
    request.state.correlation_id = correlation_id
    started = time.perf_counter()
    status_code = 500
    response = None
    try:
        try:
            response = await call_next(request)
        except SQLAlchemyError as exc:
            if not request.url.path.startswith("/gateway/"):
                status_code = 500
                log_structured(
                    "http_database_error",
                    level="error",
                    correlation_id=correlation_id,
                    method=request.method,
                    path=request.url.path,
                    error_type=exc.__class__.__name__,
                    error_message=_safe_internal_error_message(exc),
                    tenant_id=request.headers.get("x-tenant-id"),
                )
                response = JSONResponse(
                    status_code=500,
                    content={
                        "detail": {
                            "code": "database_error",
                            "message": "Database operation failed. Use the correlation_id to investigate server logs.",
                            "correlation_id": correlation_id,
                        }
                    },
                )
                status_code = response.status_code
                response.headers["X-Correlation-Id"] = correlation_id
                return response

            status_code = 503
            tenant_id = request.headers.get("x-tenant-id")
            audit_id = None
            if tenant_id:
                try:
                    with SessionLocal() as audit_db:
                        audit = write_audit_log(
                            audit_db,
                            tenant_id=tenant_id,
                            actor_user_id=None,
                            actor_type="system",
                            action=f"{request.url.path.replace('/', '.').strip('.')}.fail_closed",
                            resource_type="tenant",
                            resource_id=tenant_id,
                            payload={
                                "reason": "database_unavailable",
                                "error": str(exc),
                                "final_decision": "block",
                            },
                        )
                        audit_db.commit()
                        audit_id = audit.id
                except SQLAlchemyError:
                    audit_id = None

            response = JSONResponse(
                status_code=503,
                content={
                    "code": "enforcement_fail_closed",
                    "message": "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
                    "final_decision": "block",
                    "audit_log_id": audit_id,
                },
            )
        except Exception as exc:  # noqa: BLE001
            status_code = 500
            event_name = "http_unhandled_error"
            error_message = None
            response_code = "internal_error"
            response_message = "Request failed. Use the correlation_id to investigate server logs."
            if request.url.path == "/endpoint-agent/decision/mcp/tools/scan":
                event_name = "endpoint_mcp_tool_scan_unhandled_error"
                error_message = _safe_internal_error_message(exc)
                response_code = "mcp_tool_scan_failed"
                response_message = "MCP tool scan failed. Use the correlation_id to investigate server logs."
            elif request.url.path.startswith("/native-controls/callbacks/"):
                # Callback payloads never enter this message; only the bounded,
                # sanitized exception reason is retained for operator diagnosis.
                event_name = "native_control_callback_unhandled_error"
                error_message = _safe_internal_error_message(exc)
            log_structured(
                event_name,
                level="error",
                correlation_id=correlation_id,
                method=request.method,
                path=request.url.path,
                error_type=exc.__class__.__name__,
                **({"error_message": error_message} if error_message else {}),
                tenant_id=request.headers.get("x-tenant-id"),
            )
            response = JSONResponse(
                status_code=500,
                content={
                    "detail": {
                        "code": response_code,
                        "message": response_message,
                        "correlation_id": correlation_id,
                    }
                },
            )
            status_code = response.status_code
            response.headers["X-Correlation-Id"] = correlation_id
            return response
        if response is not None:
            status_code = response.status_code
            response.headers["X-Correlation-Id"] = correlation_id
    finally:
        latency_ms = (time.perf_counter() - started) * 1000.0
        path = request.url.path
        if path in gateway_latency_paths:
            latency_tracker.observe(path, latency_ms)
        log_structured(
            "http_request",
            correlation_id=correlation_id,
            method=request.method,
            path=path,
            status_code=status_code,
            latency_ms=round(latency_ms, 4),
            tenant_id=request.headers.get("x-tenant-id"),
        )
        reset_correlation_id(token)
    return response


@app.middleware("http")
async def production_security_headers_and_size_middleware(request, call_next):
    maximum_bytes = int(settings.max_request_body_bytes)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
        if length < 0 or length > maximum_bytes:
            return JSONResponse(status_code=413, content={"detail": "Request body exceeds configured limit."})
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        bounded_body = bytearray()
        async for chunk in request.stream():
            if len(bounded_body) + len(chunk) > maximum_bytes:
                return JSONResponse(status_code=413, content={"detail": "Request body exceeds configured limit."})
            bounded_body.extend(chunk)
        request._body = bytes(bounded_body)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/health/live")
def health_live():
    return {"status": "alive", "service": "api"}


@app.get("/health/ready")
def health_ready():
    report = _api_readiness_report()
    return JSONResponse(status_code=200 if report.ready else 503, content=report.to_dict())


@app.get("/health")
def health():
    strict_schema = _strict_schema_mode_enabled()
    try:
        with SessionLocal() as db:
            schema_report = evaluate_schema_health(db)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "api",
                "strict_schema": strict_schema,
                "schema_healthy": False,
                "error": f"schema_health_failed:{exc}",
            },
        )

    if strict_schema and not schema_report.healthy:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "api",
                "strict_schema": strict_schema,
                "schema": schema_report.to_dict(),
            },
        )

    return {
        "status": "ok" if schema_report.healthy else "degraded",
        "service": "api",
        "strict_schema": strict_schema,
        "schema_healthy": schema_report.healthy,
    }


@app.get("/health/schema")
def health_schema():
    try:
        with SessionLocal() as db:
            report = evaluate_schema_health(db)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            status_code=503,
            content={
                "healthy": False,
                "migration_current_heads": [],
                "migration_expected_heads": [],
                "pending_migrations": [],
                "missing_tables": [],
                "missing_columns": [],
                "notes": [f"schema_health_failed:{exc}"],
            },
        )

    return JSONResponse(
        status_code=200 if report.healthy else 503,
        content=report.to_dict(),
    )


app.include_router(auth.router)
app.include_router(account_boundary.router)
app.include_router(action_integrity.router)
app.include_router(investigations.router)
app.include_router(brain.router)
app.include_router(ai_orchestration.router)
app.include_router(agui.router)
app.include_router(kb.router)
app.include_router(ai_systems.router)
app.include_router(ai_tools_usage.router)
app.include_router(executive_mcp.router)
app.include_router(executive_remote_mcp.router)
app.include_router(executive_remote_mcp.compatibility_router)
app.include_router(policies.router)
app.include_router(gateway.router)
app.include_router(llm_gateway.router)
app.include_router(llm_gateway.openai_compatible_router)
app.include_router(guardian_contracts_v2.router)
app.include_router(dashboard.router)
app.include_router(coverage.router)
app.include_router(control_coverage.router)
app.include_router(maturity_curve.router)
app.include_router(policy_pack_platform.router)
app.include_router(continuous_assurance.router)
app.include_router(native_controls.router)
app.include_router(claude_enterprise.router)
app.include_router(deployments.router)
app.include_router(discovery.router)
app.include_router(discovery_adv.router)
app.include_router(discovery_assets.router)
app.include_router(discovery_capabilities.router)
app.include_router(discovery_ecosystems.router)
app.include_router(discovery_erg.router)
app.include_router(discovery_exposure.router)
app.include_router(discovery_scans.router)
app.include_router(discovery_surface_sources.router)
app.include_router(discovery_source_connections.router)
app.include_router(discovery_collectors.router)
app.include_router(discovery_targets.router)
app.include_router(extension.router)
app.include_router(endpoint_agent.router)
app.include_router(activity_audit.router)
app.include_router(user_visibility.router)
app.include_router(ai_discovery.router)
app.include_router(findings.router)
app.include_router(enforcement.router)
app.include_router(ai_iam.router)
app.include_router(agents.router)
app.include_router(monitoring.router)
app.include_router(external_risk.router)
app.include_router(checkmarx.router)
app.include_router(runtime.router)
app.include_router(runtime_control.router)
app.include_router(banking_transaction_integrity.router)
app.include_router(runtime_intelligence.router)
app.include_router(scans.router)
app.include_router(shadow_ai.router)
app.include_router(surface_coverage.router)
app.include_router(onprem.router)
app.include_router(simulations.router)
app.include_router(simulation_policies.router)
app.include_router(auditor.router)
app.include_router(audit.router)
app.include_router(trust_center.router)
app.include_router(ops.router)
app.include_router(system.router)
