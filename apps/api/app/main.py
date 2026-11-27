from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import logging
import time
from uuid import uuid4

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import SQLAlchemyError

from app.api.routers import account_boundary, action_integrity, activity_audit, agui, agents, ai_discovery, ai_iam, ai_orchestration, ai_systems, ai_tools_usage, audit, auditor, auth, banking_transaction_integrity, brain, checkmarx, continuous_assurance, control_coverage, coverage, dashboard, deployments, discovery, discovery_adv, discovery_assets, discovery_capabilities, discovery_collectors, discovery_ecosystems, discovery_erg, discovery_exposure, discovery_scans, discovery_source_connections, discovery_surface_sources, discovery_targets, endpoint_agent, enforcement, executive_mcp, executive_remote_mcp, extension, external_risk, findings, gateway, guardian_contracts_v2, investigations, kb, llm_gateway, maturity_curve, monitoring, native_controls, onprem, ops, policies, policy_pack_platform, runtime, runtime_control, runtime_intelligence, scans, shadow_ai, simulation_policies, simulations, surface_coverage, system, trust_center, user_visibility
from app.api.routers import access, backups, claude_enterprise, compliance, diagnostics, evidence_signing, hands_off, https, iam, licence, network, records, settings_console, sign_in, support, updates
from app.api.routers import ai_system_approvals, detection
from app.core.access_gate import AccessRequired, access_required_response
from app.core.config import configured_secret_sources, settings
from app.core.licence_gate import licence_gate
from app.core.log_config import (
    bind_log_context,
    configure_logging,
    get_log_context,
    reset_log_context,
    safe_id,
)
from app.core.observability import (
    gateway_latency_paths,
    get_correlation_id,
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
from app.services import activation_service, backup_service, error_counter, first_run_service, https_runtime, network_proxy, terms_service, user_activity
from app.services.pg_tools import InstanceLock, is_postgres
from app.services.integrity import service as integrity_service
from app.services.updates.companion import acknowledge_start
from app.version import APP_VERSION, PACKAGE_VERSION

# Logs (app/core/log_config.py): JSON lines on stdout (LOG_FORMAT, LOG_LEVEL), uvicorn's own access line off.
configure_logging()
logger = logging.getLogger(__name__)


def _safe_internal_error_message(exc: Exception) -> str:
    text = " ".join(str(exc).split())
    return text[:500]


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _assert_production_readiness_or_fail_startup()
    _assert_schema_integrity_or_fail_startup()
    # Backups (app/services/backup_service.py): new or existing installation is decided once, before anything of this
    # start is written (app/cli/prestart.py has normally done it already), and this process holds its share of the
    # instance lock, so a restore refuses while it runs.
    if is_postgres(settings.database_url):
        backup_service.decide_once()
    instance_lock = InstanceLock(settings.database_url, name="api").acquire()
    # The licence (app/services/activation_service.py): the installation's ID, and its 3-day trial from this first start.
    try:
        activation_service.start_installation(SessionLocal, log=lambda line: print(line, flush=True))
    except Exception as error:  # noqa: BLE001 - a database not migrated yet: the first request does it
        print(f"! [licence] The installation's licence could not be read yet: {error}", flush=True)
    _prepare_access_at_start()
    # Network & proxy (app/services/network_proxy.py): the proxy saved under Settings, or the container's HTTPS_PROXY,
    # and the trusted certificates, for every outbound client of this process. Not in tests (their own environment).
    if str(settings.env).lower() != "test":
        network_proxy.apply_to_environment()
    # HTTPS (app/services/https_runtime.py): a certificate that cannot be used stops the start here, never falling
    # back to plain http; the front proxy is handed what Settings → HTTPS chose.
    https_runtime.start()
    # Updates (app/services/updates/companion.py): the updater waits for this after starting a new version; software
    # integrity (app/services/integrity/): the running files and their signature, checked a few seconds after start.
    if is_postgres(settings.database_url):
        acknowledge_start(PACKAGE_VERSION)
        integrity_service.start_in_background()
        # Self-recovery (app/services/self_recovery.py) runs here too when the worker or the scheduler stopped.
        from app.services import self_recovery

        self_recovery.start_guard()
    print(f"Hawk AI {APP_VERSION} running", flush=True)
    try:
        yield
    finally:
        https_runtime.stop()
        _last_words()
        instance_lock.release()


#: The whole stop fits in the 15 s deploy/compose.yaml gives (stop_grace_period) before the container is killed.
STOP_BUDGET_SECONDS = 12.0


def _last_words() -> None:
    """Before the API stops (SIGTERM from `docker compose stop` or `down`, or Ctrl+C): a backup, and an email to the
    administrators at most every LAST_WORDS_EVERY_HOURS (CxMissionZero's "last words", src/server.js)."""

    import os
    import time

    # Only a deployed Hawk AI (PostgreSQL): not a test run or a laptop on SQLite.
    if not is_postgres(settings.database_url):
        return
    try:
        budget = float(os.environ.get("SHUTDOWN_BUDGET_SECONDS") or STOP_BUDGET_SECONDS)
    except ValueError:
        budget = STOP_BUDGET_SECONDS
    try:
        outcome = backup_service.last_words("the service was stopped", time.monotonic() + budget)
        backup = outcome.get("backup") or {}
        if backup.get("ok"):
            print(f"[backup] Before stopping: {backup.get('file')}", flush=True)
    except Exception as error:  # noqa: BLE001 - a stop is never held up by its backup
        print(f"! [backup] Before stopping: {error}", flush=True)


def _prepare_access_at_start() -> None:
    """At start-up, as CxMissionZero does: ACCEPT_TERMS=<email> accepts the terms of use for the organisation and
    everyone (refusing to start if it is not an email address), then, with FIRST_RUN_ACCESS on (deploy/compose.yaml),
    the first administrator is made on an empty database (app/services/first_run_service.py)."""

    import os

    accept_terms = str(os.environ.get("ACCEPT_TERMS") or "").strip()
    if accept_terms:
        with SessionLocal() as db:
            try:
                recorded = terms_service.accept_from_environment(db, accept_terms)
            except ValueError as error:
                raise RuntimeError(str(error)) from error
            if recorded:
                terms = terms_service.current()
                write_audit_log(
                    db,
                    tenant_id=None,
                    actor_user_id=None,
                    actor_type="system",
                    action="terms.accepted",
                    resource_type="terms",
                    resource_id=terms.hash,
                    payload={
                        "reason": f"Terms of use v{terms.version} accepted for the organisation and everyone using this installation by {accept_terms} (ACCEPT_TERMS).",
                        "terms": {"version": terms.version, "hash": terms.hash, "via": "ACCEPT_TERMS"},
                    },
                )
                print(f"[terms] Terms of use v{terms.version} accepted for the organisation by {accept_terms} (ACCEPT_TERMS).", flush=True)
            db.commit()
    if settings.first_run_access:
        first_run_service.prepare_access(SessionLocal)
    # RESET_TWO_STEP=<email>: two-step sign-in taken off once for that person (/settings/guide/people-and-access).
    reset_two_step = os.environ.get("RESET_TWO_STEP")
    try:
        with SessionLocal() as db:
            sign_in.reset_two_step_from_environment(db, reset_two_step, log=lambda line: print(line, flush=True))
            db.commit()
    except Exception as error:  # noqa: BLE001 - a database not migrated yet must not stop the start
        if reset_two_step:
            print(f"! [access] RESET_TWO_STEP could not be used: {error}", flush=True)


_production_topology = settings.deployment_topology == "single_node_compose"
app = FastAPI(
    title=settings.app_name,
    version=settings.component_version,
    lifespan=lifespan,
    docs_url=None if _production_topology else "/docs",
    redoc_url=None if _production_topology else "/redoc",
    openapi_url=None if _production_topology else "/openapi.json",
)


# A temporary password to change, or terms of use to accept, first (app/core/access_gate.py).
app.add_exception_handler(AccessRequired, access_required_response)


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

async def user_activity_middleware(request, call_next):
    """The user activity log (app/services/user_activity.py, CxMissionZero's src/activity-log.js): every signed-in
    request that changes something, and the downloads and exports, once answered. Field names only, never values.
    Registered first, so it runs innermost: the body it looks at is the one the size check let through."""

    method = request.method.upper()
    fields: list[str] = []
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        content_type = request.headers.get("content-type", "")
        try:
            length = int(request.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if "json" in content_type.lower() and 0 < length <= 256 * 1024:
            fields = user_activity.body_fields(await request.body(), content_type)
    started = time.perf_counter()
    response = await call_next(request)
    actor = getattr(request.state, "activity_actor", None)
    route = getattr(request.scope.get("route"), "path", "") or ""
    if actor and route and user_activity.should_record(method, route):
        entry = {
            **actor,
            "ip": request.client.host if request.client else "",
            "kind": "action",
            "action": user_activity.describe(method, route),
            "target": user_activity.target_of(request.path_params),
            "fields": fields,
            "method": method,
            "route": route,
            "status": response.status_code,
            "ms": (time.perf_counter() - started) * 1000,
        }
        await run_in_threadpool(_record_activity, entry)
    return response


def _record_activity(entry: dict) -> None:
    # A session of its own, never the request's: what the request did is committed or not on its own terms.
    try:
        with user_activity.session_factory() as db:
            user_activity.record(db, entry)
            db.commit()
    except Exception:  # noqa: BLE001 - the activity log never fails a request
        pass


app.middleware("http")(user_activity_middleware)

# The licence gate (app/core/licence_gate.py): registered before CORS, so CORS wraps it and the console can read the
# 503 that says Hawk AI has been deactivated.
app.middleware("http")(licence_gate)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_build_cors_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # The detached evidence signature of an export (app/services/evidence_signing.py), for a console on another origin.
    expose_headers=["X-Hawk-Evidence-Signature", "X-Hawk-Evidence-Signature-Status"],
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
    # The request id (app/core/log_config.py): the caller's X-Request-ID or X-Correlation-Id when it is a plain,
    # short identifier, otherwise a new one. It is the correlation id written with the audit records, comes back in
    # X-Request-ID and X-Correlation-Id, and is on every log line of this request.
    correlation_id = (
        safe_id(request.headers.get("x-request-id"))
        or safe_id(request.headers.get("x-correlation-id"))
        or str(uuid4())
    )
    token = set_correlation_id(correlation_id)
    log_token = bind_log_context(request_id=correlation_id)
    request.state.correlation_id = correlation_id
    started = time.perf_counter()
    status_code = 500
    response = None
    try:
        try:
            response = await call_next(request)
        except SQLAlchemyError as exc:
            # Counted for the self-check (more than 30 errors in 15 minutes, app/services/error_counter.py).
            await run_in_threadpool(error_counter.note)
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
                    exc_info=exc,
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
                response.headers["X-Request-ID"] = correlation_id
                return response

            status_code = 503
            tenant_id = request.headers.get("x-tenant-id")
            access_logger.warning(
                "Gateway request blocked (fail closed): the database is unavailable",
                extra={"error_type": exc.__class__.__name__},
            )
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
            await run_in_threadpool(error_counter.note)
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
                exc_info=exc,
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
            response.headers["X-Request-ID"] = correlation_id
            return response
        if response is not None:
            status_code = response.status_code
            response.headers["X-Correlation-Id"] = correlation_id
            response.headers["X-Request-ID"] = correlation_id
    finally:
        latency_ms = (time.perf_counter() - started) * 1000.0
        path = request.url.path
        if path in gateway_latency_paths:
            latency_tracker.observe(path, latency_ms)
        _log_access(request, status_code=status_code, latency_ms=latency_ms)
        reset_log_context(log_token)
        reset_correlation_id(token)
    return response


access_logger = logging.getLogger("app.access")


def _log_access(request, *, status_code: int, latency_ms: float) -> None:
    """One line per request: the route as declared (/ai-systems/{ai_system_id}, never the ids in the path), the
    status, how long it took, the tenant and person when known, and the client's address (uvicorn's --proxy-headers
    already put the front proxy's X-Forwarded-For there). Never a header, query string or body."""

    try:
        route = getattr(request.scope.get("route"), "path", None)
        actor = getattr(request.state, "activity_actor", None) or {}
        context = get_log_context()
        fields = {
            "method": request.method,
            "route": route or None,
            "status": status_code,
            "duration_ms": round(latency_ms, 2),
            "client_ip": request.client.host if request.client else None,
            "tenant_id": actor.get("tenant_id") or context.get("tenant_id") or safe_id(request.headers.get("x-tenant-id")),
            "user_id": actor.get("user_id") or context.get("user_id"),
        }
        if not route:
            # No route matched (404s, scans): the path, without its query string, shortened.
            fields["path"] = request.url.path[:200]
        level = logging.ERROR if status_code >= 500 else logging.INFO
        access_logger.log(
            level,
            "%s %s %s %.1fms",
            request.method,
            route or fields["path"],
            status_code,
            latency_ms,
            extra={key: value for key, value in fields.items() if value is not None},
        )
    except Exception:  # noqa: BLE001 - the access line never fails a request
        pass


@app.middleware("http")
async def production_security_headers_and_size_middleware(request, call_next):
    maximum_bytes = int(settings.max_request_body_bytes)
    # A backup restored from Settings → Backups & health: up to 200 MB (app/api/routers/backups.py), as CxMissionZero.
    restore_upload = request.method == "POST" and request.url.path == "/backups/restore"
    if restore_upload:
        maximum_bytes = backups.MAX_RESTORE_UPLOAD_BYTES
    too_large = (
        {"error": backups.TOO_LARGE, "detail": backups.TOO_LARGE} if restore_upload else {"detail": "Request body exceeds configured limit."}
    )
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
        if length < 0 or length > maximum_bytes:
            return JSONResponse(status_code=413, content=too_large)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        bounded_body = bytearray()
        async for chunk in request.stream():
            if len(bounded_body) + len(chunk) > maximum_bytes:
                return JSONResponse(status_code=413, content=too_large)
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


def _health_failure(exc: Exception) -> str:
    """What an unauthenticated health answer says about a failure: its kind and the request id, never the database's
    own message (it can name the host, the user and the statement). The whole error is in the server log."""

    request_id = get_correlation_id() or ""
    logger.warning("Schema health check failed", exc_info=exc, extra={"request_id": request_id, "reason_code": "schema_health_failed"})
    return f"schema_health_failed:{exc.__class__.__name__}" + (f" (request id {request_id})" if request_id else "")


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
                "error": _health_failure(exc),
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
        "version": APP_VERSION,
        "strict_schema": strict_schema,
        "schema_healthy": schema_report.healthy,
        "detection": _detection_health(),
        "clock": _clock_health(),
    }


def _clock_health() -> dict:
    """Is the host's clock synchronised by NTP (CERT-In's directions, DESC ISR; Settings → Compliance)? Read from the
    kernel only, so this stays instant: true, false, or null where it cannot be read."""
    try:
        from app.services.compliance_service import kernel_clock

        return {"synchronized": kernel_clock()["synchronized"]}
    except Exception as exc:  # noqa: BLE001 - health must answer
        return {"synchronized": None, "error": type(exc).__name__}


def _detection_health() -> dict:
    """DLP / injection detection coverage, without loading a model: named entities run only when a spaCy model is
    installed in the image; without one they degrade to patterns, and this says so."""
    try:
        from app.services.detection.injection_rules import RULESET_VERSION
        from app.services.sensitive_data_detection_service import ner_status

        ner = ner_status()
        return {"offline": True, "ner_available": ner["available"], "ner_model": ner["model"], "injection_rules": RULESET_VERSION}
    except Exception as exc:  # noqa: BLE001 - health must answer
        return {"offline": True, "error": type(exc).__name__}


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
                "notes": [_health_failure(exc)],
            },
        )

    return JSONResponse(
        status_code=200 if report.healthy else 503,
        content=report.to_dict(),
    )


app.include_router(auth.router)
app.include_router(sign_in.router)
app.include_router(iam.router)
app.include_router(licence.router)
app.include_router(https.router)
app.include_router(backups.router)
app.include_router(updates.router)
app.include_router(diagnostics.router)
app.include_router(records.router)
app.include_router(evidence_signing.router)
app.include_router(support.router)
app.include_router(detection.router)
app.include_router(network.router)
app.include_router(hands_off.router)
app.include_router(settings_console.router)
app.include_router(compliance.router)
app.include_router(access.router)
app.include_router(account_boundary.router)
app.include_router(action_integrity.router)
app.include_router(investigations.router)
app.include_router(brain.router)
app.include_router(ai_orchestration.router)
app.include_router(agui.router)
app.include_router(kb.router)
app.include_router(ai_systems.router)
app.include_router(ai_system_approvals.router)
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
