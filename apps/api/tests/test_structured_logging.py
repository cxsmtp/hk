"""Structured logging (app/core/log_config.py): the JSON line, the request id, the access line, the Celery context and
the redaction that keeps every secret out of the log."""

from __future__ import annotations

import json
import logging
import sys
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core import log_config
from app.core.log_config import (
    JsonFormatter,
    RecentErrorsHandler,
    TextFormatter,
    bind_log_context,
    get_log_context,
    mask_email,
    redact_text,
    reset_log_context,
    safe_id,
    update_log_context,
)


SECRETS = [
    "s3cr3t-Pa55w0rd!",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2lnbmF0dXJlLXZhbHVl",
    "sk-live-abcdefghijklmnop",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "session=abc123cookievalue",
    "connector-client-secret-value",
    "please summarise the confidential merger memo",
]


def _record(message: str = "hello", *args, level: int = logging.INFO, name: str = "app.test", exc_info=None, **extra) -> logging.LogRecord:
    logger = logging.getLogger(name)
    record = logger.makeRecord(name, level, __file__, 10, message, args, exc_info, extra=extra or None)
    return record


@pytest.fixture(autouse=True)
def _context_factory():
    log_config.install_context_factory()
    yield


# ---- The JSON line ---------------------------------------------------------------------------------------------------


def test_json_formatter_writes_one_object_with_utc_timestamp_level_logger_message_and_fields():
    token = bind_log_context(request_id="req-1", tenant_id="tenant-a")
    try:
        record = _record("Backup written: %s", "backup-1.tar", route="/x/{id}", duration_ms=12.5)
    finally:
        reset_log_context(token)
    line = JsonFormatter(service="api").format(record)
    assert "\n" not in line
    payload = json.loads(line)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "app.test"
    assert payload["message"] == "Backup written: backup-1.tar"
    assert payload["service"] == "api"
    assert payload["timestamp"].endswith("Z") and "T" in payload["timestamp"]
    assert payload["request_id"] == "req-1" and payload["tenant_id"] == "tenant-a"
    assert payload["route"] == "/x/{id}" and payload["duration_ms"] == 12.5


def test_json_formatter_carries_the_traceback_and_reserved_names_do_not_overwrite_the_line():
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        record = _record("Task failed", level=logging.ERROR, exc_info=sys.exc_info(), level_hint="x")
    record.__dict__["logger"] = "forged"
    payload = json.loads(JsonFormatter().format(record))
    assert payload["exc_type"] == "RuntimeError"
    assert "boom" in payload["exc_info"] and "Traceback" in payload["exc_info"]
    assert payload["logger"] == "app.test" and payload["field_logger"] == "forged"


def test_log_structured_events_become_fields_of_the_line():
    from app.core import observability

    record = _record(json.dumps({"event": "gateway_fail_closed", "route_key": "gateway.mcp.authorize", "correlation_id": "c-1"}), name="app.request")
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "gateway_fail_closed"
    assert payload["route_key"] == "gateway.mcp.authorize"
    assert payload["request_id"] == "c-1"
    assert observability.request_logger.name == "app.request"


def test_text_formatter_is_one_readable_line():
    line = TextFormatter().format(_record("Signed in", user_id="u-1"))
    assert " INFO " in line and "app.test" in line and "Signed in" in line and "user_id=u-1" in line


# ---- Redaction -------------------------------------------------------------------------------------------------------


def test_secrets_in_messages_never_reach_the_line():
    message = (
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123 "
        f"password={SECRETS[0]} token {SECRETS[1]} key {SECRETS[2]} gh {SECRETS[3]} "
        "url https://idp.example.com/cb?code=abcdef123456&state=ok "
        "{'client_secret': 'connector-client-secret-value'}"
    )
    for formatter in (JsonFormatter(), TextFormatter()):
        line = formatter.format(_record(message))
        for secret in SECRETS[:4] + ["abcdefghijklmnopqrstuvwxyz0123", "abcdef123456", "connector-client-secret-value"]:
            assert secret not in line, (secret, line)
    assert "state=ok" in redact_text("https://idp.example.com/cb?code=abcdef123456&state=ok")


def test_cookie_header_is_redacted():
    assert "abc123cookievalue" not in redact_text(f"Cookie: {SECRETS[4]}; theme=dark")


def test_secret_and_raw_material_fields_are_redacted_whatever_their_shape():
    record = _record(
        "Connector saved",
        password=SECRETS[0],
        access_token=SECRETS[1],
        api_key=SECRETS[2],
        headers={"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz", "Cookie": SECRETS[4]},
        connector_secrets={"client_secret": SECRETS[5]},
        prompt=SECRETS[6],
        raw_prompt=SECRETS[6],
        details={"refresh_token": "rt-123456789", "nested": {"secret": "x-secret-value"}},
        token_count=12,
        connector_id="conn-1",
    )
    line = JsonFormatter().format(record)
    for secret in [*SECRETS, "abcdefghijklmnopqrstuvwxyz", "rt-123456789", "x-secret-value"]:
        assert secret not in line, secret
    payload = json.loads(line)
    assert payload["password"] == "[redacted]"
    assert payload["prompt"] == "[omitted]"
    assert payload["token_count"] == 12 and payload["connector_id"] == "conn-1"


def test_secrets_in_exception_text_are_redacted():
    try:
        raise ValueError(f"upstream refused api_key={SECRETS[2]} with Authorization: Bearer abcdefghijklmnopqrstu")
    except ValueError:
        record = _record("Connector pull failed", level=logging.WARNING, exc_info=sys.exc_info())
    for formatter in (JsonFormatter(), TextFormatter()):
        line = formatter.format(record)
        assert SECRETS[2] not in line and "abcdefghijklmnopqrstu" not in line


def test_emails_are_masked_for_log_lines():
    assert mask_email("jane.doe@example.com") == "j***@example.com"
    assert mask_email("user-123") == "user-123"


# ---- Context ---------------------------------------------------------------------------------------------------------


def test_context_is_bound_updated_and_reset():
    assert get_log_context() == {}
    token = bind_log_context(request_id="r-1", tenant_id=None)
    update_log_context(tenant_id="t-1", user_id="")
    assert get_log_context() == {"request_id": "r-1", "tenant_id": "t-1"}
    reset_log_context(token)
    assert get_log_context() == {}
    update_log_context(tenant_id="ignored")  # nothing bound: nothing happens
    assert get_log_context() == {}


@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ("abc-123", True),
        ("6f1c2d3e-0000-4000-8000-000000000000", True),
        ("trace.id:1_2", True),
        ("", False),
        ("has space", False),
        ("line\nbreak", False),
        ('{"json": 1}', False),
        ("x" * 129, False),
        ("-leading-dash", False),
    ],
)
def test_only_plain_short_request_ids_are_accepted(value, accepted):
    assert (safe_id(value) == value) is accepted


# ---- The request id and the access line ------------------------------------------------------------------------------


@pytest.fixture()
def client():
    from app.main import app

    with_client = TestClient(app, raise_server_exceptions=False)
    yield with_client
    with_client.close()


def _access_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "app.access"]


def test_a_safe_incoming_request_id_is_kept_and_returned(client, caplog):
    with caplog.at_level(logging.INFO, logger="app.access"):
        response = client.get("/health/live", headers={"X-Request-ID": "support-ticket-42"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "support-ticket-42"
    assert response.headers["X-Correlation-Id"] == "support-ticket-42"
    records = _access_records(caplog)
    assert len(records) == 1
    assert records[0].hawk_context["request_id"] == "support-ticket-42"
    assert records[0].route == "/health/live" and records[0].status == 200 and records[0].method == "GET"
    assert isinstance(records[0].duration_ms, float)


def test_the_correlation_header_still_works(client):
    response = client.get("/health/live", headers={"X-Correlation-Id": "corr-test-id-001"})
    assert response.headers["X-Correlation-Id"] == "corr-test-id-001"
    assert response.headers["X-Request-ID"] == "corr-test-id-001"


@pytest.mark.parametrize("bad", ["two words", "x" * 300, "<script>", "a\tb"])
def test_an_unsafe_incoming_request_id_is_replaced(client, bad):
    response = client.get("/health/live", headers={"X-Request-ID": bad, "X-Correlation-Id": bad})
    returned = response.headers["X-Request-ID"]
    assert returned != bad and safe_id(returned) == returned
    assert response.headers["X-Correlation-Id"] == returned


def test_a_request_without_an_id_gets_one(client):
    first = client.get("/health/live").headers["X-Request-ID"]
    second = client.get("/health/live").headers["X-Request-ID"]
    assert first and second and first != second


def test_the_access_line_has_the_route_template_not_the_ids(client, caplog):
    with caplog.at_level(logging.INFO, logger="app.access"):
        client.get("/ai-systems/9b7e4f0a-secret-looking-id", headers={"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz", "X-Tenant-ID": "tenant-1"})
    records = _access_records(caplog)
    assert len(records) == 1
    record = records[0]
    assert record.route == "/ai-systems/{ai_system_id}"
    assert record.status == 401
    assert record.tenant_id == "tenant-1"
    line = JsonFormatter().format(record)
    assert "9b7e4f0a-secret-looking-id" not in line
    assert "abcdefghijklmnopqrstuvwxyz" not in line
    assert json.loads(line)["message"].startswith("GET /ai-systems/{ai_system_id} 401 ")


def test_an_unmatched_path_is_logged_without_its_query(client, caplog):
    with caplog.at_level(logging.INFO, logger="app.access"):
        client.get("/no-such-route?token=abcdef")
    record = _access_records(caplog)[0]
    assert getattr(record, "route", None) is None
    assert record.path == "/no-such-route" and record.status == 404
    assert "abcdef" not in JsonFormatter().format(record)


def test_an_unhandled_error_is_logged_with_the_request_id_and_returned_to_the_caller(caplog):
    from fastapi import APIRouter

    from app.main import app

    router = APIRouter()

    @router.get("/tests/logging/boom")
    def boom():
        raise RuntimeError("password=hunter2-should-not-appear")

    app.include_router(router)
    try:
        with caplog.at_level(logging.INFO):
            response = TestClient(app, raise_server_exceptions=False).get("/tests/logging/boom", headers={"X-Request-ID": "boom-1"})
    finally:
        app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", "") != "/tests/logging/boom"]
    assert response.status_code == 500
    assert response.json()["detail"]["correlation_id"] == "boom-1"
    assert response.headers["X-Request-ID"] == "boom-1"
    errors = [r for r in caplog.records if r.name == "app.request" and r.levelno == logging.ERROR]
    assert errors and errors[0].exc_info is not None
    line = JsonFormatter().format(errors[0])
    payload = json.loads(line)
    assert payload["message"] == "http_unhandled_error" and payload["request_id"] == "boom-1"
    assert "hunter2-should-not-appear" not in line
    access = [r for r in caplog.records if r.name == "app.access"]
    assert access and access[0].status == 500 and access[0].route == "/tests/logging/boom"


# ---- Celery ----------------------------------------------------------------------------------------------------------


def _task(name: str = "app.jobs.example", **request):
    return SimpleNamespace(name=name, request=SimpleNamespace(retries=request.pop("retries", 0), **request))


def test_a_task_logs_its_start_and_finish_and_its_lines_carry_the_task_context(caplog):
    from app.jobs import task_logging

    task = _task(hawk_request_id="req-from-api", retries=1)
    with caplog.at_level(logging.INFO):
        task_logging._on_prerun(task_id="task-1", task=task, args=(), kwargs={"tenant_id": "tenant-9", "prompt": "never logged"})
        logging.getLogger("app.services.example").info("working")
        task_logging._on_postrun(task_id="task-1", task=task, state="SUCCESS")
    assert get_log_context() == {}
    lines = [r for r in caplog.records if r.name in {"app.jobs.tasks", "app.services.example"}]
    assert [r.getMessage() for r in lines] == ["Task started: app.jobs.example", "working", "Task finished: app.jobs.example"]
    for record in lines:
        assert record.hawk_context == {"task_id": "task-1", "task_name": "app.jobs.example", "request_id": "req-from-api", "tenant_id": "tenant-9"}
    finished = lines[-1]
    assert finished.state == "SUCCESS" and finished.retries == 1 and finished.duration_ms >= 0
    assert "never logged" not in "".join(JsonFormatter().format(r) for r in lines)


def test_a_failed_task_logs_an_error_with_its_traceback_and_no_finish_line(caplog):
    from app.jobs import task_logging

    task = _task("app.jobs.failing")
    with caplog.at_level(logging.INFO, logger="app.jobs.tasks"):
        task_logging._on_prerun(task_id="task-2", task=task, args=(), kwargs={})
        try:
            raise ConnectionError("broker gone")
        except ConnectionError as error:
            task_logging._on_failure(sender=task, task_id="task-2", exception=error)
        task_logging._on_retry(sender=task, request=SimpleNamespace(id="task-2", retries=2), reason=TimeoutError("slow"))
        task_logging._on_postrun(task_id="task-2", task=task, state="FAILURE")
    messages = [(r.levelname, r.getMessage()) for r in caplog.records if r.name == "app.jobs.tasks"]
    assert messages == [
        ("INFO", "Task started: app.jobs.failing"),
        ("ERROR", "Task failed: app.jobs.failing"),
        ("WARNING", "Task will be retried: app.jobs.failing (TimeoutError)"),
    ]
    failed = [r for r in caplog.records if r.getMessage() == "Task failed: app.jobs.failing"][0]
    assert failed.exc_info[0] is ConnectionError and failed.hawk_context["task_id"] == "task-2"
    assert get_log_context() == {}


def test_a_task_queued_during_a_request_carries_its_request_id():
    from app.jobs import task_logging

    headers: dict = {}
    task_logging._on_publish(headers=headers)
    assert headers == {}
    token = bind_log_context(request_id="req-7")
    try:
        task_logging._on_publish(headers=headers)
    finally:
        reset_log_context(token)
    assert headers == {task_logging.REQUEST_ID_HEADER: "req-7"}


def test_an_unsafe_request_id_from_a_message_is_ignored(caplog):
    from app.jobs import task_logging

    task = _task(hawk_request_id="bad id\nforged")
    with caplog.at_level(logging.INFO, logger="app.jobs.tasks"):
        task_logging._on_prerun(task_id="task-3", task=task, args=(), kwargs={"tenant_id": "t 1"})
        task_logging._on_postrun(task_id="task-3", task=task, state="SUCCESS")
    assert "request_id" not in caplog.records[0].hawk_context and "tenant_id" not in caplog.records[0].hawk_context


# ---- Set-up, audit lines, the last errors ------------------------------------------------------------------------


def test_configure_logging_writes_json_to_stdout_and_turns_uvicorns_access_line_off(capsys):
    root = logging.getLogger()
    saved = (list(root.handlers), root.level)
    access = logging.getLogger("uvicorn.access")
    saved_access = (list(access.handlers), access.propagate, access.disabled)
    trace = logging.getLogger("celery.app.trace")
    saved_trace = trace.level
    try:
        log_config.configure_logging(service="worker", level="INFO", fmt="json", force=True)
        logging.getLogger("app.services.example").info("Restore applied", extra={"password": "hunter2"})
        logging.getLogger("app.services.example").debug("not at INFO")
        out = capsys.readouterr().out.strip().splitlines()
        assert access.disabled is True
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])
        access.handlers[:], access.propagate, access.disabled = saved_access
        trace.setLevel(saved_trace)
        logging.captureWarnings(False)
    lines = [json.loads(line) for line in out if line.startswith("{")]
    assert len(lines) == 1
    assert lines[0]["message"] == "Restore applied" and lines[0]["service"] == "worker" and lines[0]["password"] == "[redacted]"


def test_audit_records_make_a_log_line_without_their_payload(caplog):
    from app.services import audit_service

    with caplog.at_level(logging.DEBUG, logger="app.audit"):
        audit_service._log_audit_entry(
            tenant_id="t-1",
            actor_user_id="u-1",
            actor_type="human",
            action="iam.person.added",
            resource_type="iam",
            resource_id="new.person@example.com",
            payload={"outcome": "changed", "password": "hunter2", "reason": "secret reason"},
        )
        audit_service._log_audit_entry(
            tenant_id=None, actor_user_id=None, actor_type="system", action="licence.activation_code.refused", resource_type="activation_code", resource_id="-", payload={}
        )
        audit_service._log_audit_entry(
            tenant_id="t-1", actor_user_id=None, actor_type="system", action="gateway.mcp.authorize", resource_type="ai_system", resource_id="a-1", payload={}
        )
    records = caplog.records
    assert [r.levelname for r in records] == ["INFO", "WARNING", "DEBUG"]
    line = JsonFormatter().format(records[0])
    payload = json.loads(line)
    assert payload["audit_action"] == "iam.person.added" and payload["outcome"] == "changed"
    assert payload["resource_id"] == "n***@example.com"
    assert "hunter2" not in line and "secret reason" not in line


def test_the_last_error_lines_are_kept_for_the_troubleshooting_report():
    handler = RecentErrorsHandler(capacity=3)
    for n in range(5):
        handler.handle(_record(f"failure {n} for jane@example.com", level=logging.ERROR))
    handler.handle(_record("just info"))
    lines = handler.lines(10)
    assert [line["message"] for line in lines] == ["failure 2 for [email]", "failure 3 for [email]", "failure 4 for [email]"]


def test_the_troubleshooting_report_lists_the_last_errors(monkeypatch):
    from app.services import self_check

    monkeypatch.setattr(self_check, "recent_error_lines", lambda limit=20: [{"message": "boom"}])
    fake = SimpleNamespace(version="1.0.0", now=lambda: __import__("datetime").datetime(2026, 11, 26, tzinfo=__import__("datetime").timezone.utc), watchdog=SimpleNamespace(problems=lambda: [], events=lambda n: []))
    report = self_check.SelfCheck.troubleshooting_log(fake, {"key": "k", "title": "t"})
    assert report["recentErrors"] == [{"message": "boom"}]
