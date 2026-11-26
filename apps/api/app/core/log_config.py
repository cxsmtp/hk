"""One logging set-up for the API, the Celery worker and beat: one line per event on stdout.

LOG_FORMAT=json (deploy/compose.yaml) writes one JSON object a line, for Docker's log files and whatever reads them:

    {"timestamp": "2026-11-26T09:14:03.512Z", "level": "INFO", "logger": "app.access", "message": "GET /ai-systems/{ai_system_id} 200 12.4ms",
     "service": "api", "request_id": "6f1c…", "tenant_id": "…", "user_id": "…", "method": "GET",
     "route": "/ai-systems/{ai_system_id}", "status": 200, "duration_ms": 12.4, "client_ip": "10.0.0.7"}

LOG_FORMAT=text writes the same, easier to read on a laptop. LOG_LEVEL sets the level (INFO by default).

Context: what happens during a request or a Celery task carries its request_id / task_id / tenant_id / user_id with
no help from the code that logs (``bind_log_context``; app/main.py and app/jobs/task_logging.py bind them).

Never a secret: every line goes through ``redact_text`` / ``redact_fields`` (Authorization and Cookie headers, bearer
tokens, JWTs, passwords, API keys, connector secrets, prompt text), which reuse app/services/privacy_sanitizer.py.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from collections import deque
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Any

from app.services.privacy_sanitizer import (
    BEARER_RE,
    EMAIL_RE,
    SECRET_ASSIGNMENT_RE,
    SENSITIVE_KEYWORDS,
    TOKEN_KEYS,
    _is_raw_material_key,
    _normalized_key,
    redact_sensitive_text,
)

# ---------------------------------------------------------------------------------------------------------------------
# Context: request_id, task_id, tenant_id, user_id on every line
# ---------------------------------------------------------------------------------------------------------------------

_log_context: ContextVar[dict[str, Any] | None] = ContextVar("hawk_log_context", default=None)

#: A request id we accept from the caller (X-Request-ID / X-Correlation-Id): short, plain characters only, so it can
#: never forge a log line or carry anything but an identifier.
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def safe_id(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if SAFE_ID_RE.fullmatch(text) else None


def bind_log_context(**fields: Any) -> Token[dict[str, Any] | None]:
    """Start a new context (a request, a task) on top of the current one. Returns the token for reset_log_context."""

    current = _log_context.get() or {}
    merged = {**current, **{key: value for key, value in fields.items() if value is not None and value != ""}}
    return _log_context.set(merged)


def reset_log_context(token: Token[dict[str, Any] | None]) -> None:
    try:
        _log_context.reset(token)
    except ValueError:  # reset in another context (a signal handler on another thread): start afresh there
        _log_context.set(None)


def update_log_context(**fields: Any) -> None:
    """Add to the context already bound (the tenant and user, once a request's dependencies know them). The context is
    shared with the copies FastAPI's thread pool makes of it, so what a dependency adds is seen by the request's
    access line and by the endpoint's own lines."""

    current = _log_context.get()
    if current is None:
        return
    for key, value in fields.items():
        if value is not None and value != "":
            current[key] = value


def get_log_context() -> dict[str, Any]:
    return dict(_log_context.get() or {})


# ---------------------------------------------------------------------------------------------------------------------
# Redaction: never a secret in a log line
# ---------------------------------------------------------------------------------------------------------------------

REDACTED = "[redacted]"
OMITTED = "[omitted]"

_HEADER_RE = re.compile(
    r"(?i)\b((?:proxy-)?authorization|(?:set-)?cookie|x-api-key|api-key|x-auth-token)(\"?'?\s*[:=]\s*)([^\r\n]+)"
)
_QUOTED_SECRET_RE = re.compile(
    r"(?i)([\"']?(?:password|passwd|secret|client_secret|token|access_token|refresh_token|api[_-]?key|authorization|cookie)[\"']?\s*[:=]\s*)([\"'])(.*?)\2"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_URL_SECRET_PARAM_RE = re.compile(
    r"(?i)([?&](?:token|access_token|refresh_token|id_token|code|key|api_key|apikey|password|secret|sig|signature|ticket)=)[^&\s\"']+"
)
_KNOWN_KEY_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9_-]{8,})"
)
_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
    "credential",
    "recovery_code",
    "otp",
    "totp",
    "mfa_code",
    "signature",
)
# Numbers that only describe a secret (how many tokens, when it expires) are kept.
_HARMLESS_SUFFIXES = ("_count", "_tokens", "_ttl", "_seconds", "_expires_at", "_at", "_id", "_ids", "_type", "_kind")

MAX_MESSAGE_CHARS = 8000
MAX_FIELD_CHARS = 2000


def redact_text(value: Any, *, max_len: int = MAX_MESSAGE_CHARS) -> str:
    """A message (or an exception's text) with every secret replaced. Names, ids, dates and addresses are kept."""

    text = str(value if value is not None else "")
    if not text:
        return text
    text = _HEADER_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    text = _QUOTED_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}", text)
    text = BEARER_RE.sub("Bearer [token]", text)
    text = _JWT_RE.sub("[jwt]", text)
    text = _URL_SECRET_PARAM_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _KNOWN_KEY_RE.sub("[secret]", text)
    text = SECRET_ASSIGNMENT_RE.sub("[secret]", text)
    if len(text) > max_len:
        return f"{text[:max_len]}...[truncated]"
    return text


def _secret_key(key: str) -> bool:
    normalized = _normalized_key(key)
    if normalized in TOKEN_KEYS:
        return True
    if normalized.endswith(_HARMLESS_SUFFIXES):
        return False
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _raw_material_key(key: str) -> bool:
    normalized = _normalized_key(key)
    return _is_raw_material_key(normalized) or normalized in SENSITIVE_KEYWORDS or normalized in {
        "body",
        "content",
        "messages",
        "payload",
        "headers",
        "completion",
    }


def mask_email(value: Any) -> str:
    """An email address for a log line: the first letter and the domain (j***@example.com), never the whole address."""

    def mask(match: re.Match[str]) -> str:
        local, _, domain = match.group(0).partition("@")
        return f"{local[:1]}***@{domain}"

    return EMAIL_RE.sub(mask, str(value or ""))


def redact_value(key: str, value: Any, *, depth: int = 0) -> Any:
    if _secret_key(key):
        return REDACTED
    if _raw_material_key(key):
        return OMITTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= 4:
        return "[omitted:max_depth]"
    if isinstance(value, dict):
        return {str(k): redact_value(str(k), v, depth=depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(key, item, depth=depth + 1) for item in list(value)[:50]]
    return redact_text(value, max_len=MAX_FIELD_CHARS)


def redact_fields(fields: dict[str, Any]) -> dict[str, Any]:
    return {str(key): redact_value(str(key), value) for key, value in fields.items()}


# ---------------------------------------------------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------------------------------------------------

#: What every LogRecord has; anything else on a record came from ``extra=`` and is written as a field.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None)).keys()
    | {"message", "asctime", "hawk_context", "taskName"}
)
_RESERVED = {"timestamp", "level", "logger", "message", "service", "exc_type", "exc_info", "stack_info"}


def _utc_iso(created: float) -> str:
    return datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _record_fields(record: logging.LogRecord) -> tuple[str, dict[str, Any]]:
    """The message and the fields of one record: its context, then its ``extra=``, every one redacted."""

    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 - a bad format string still gives a line
        message = f"{record.msg!r} {record.args!r}"
    fields: dict[str, Any] = {}
    context = getattr(record, "hawk_context", None)
    if isinstance(context, dict):
        fields.update(context)
    for key, value in record.__dict__.items():
        if key not in _STANDARD_ATTRS and not key.startswith("_"):
            fields[key] = value
    # app/core/observability.py's log_structured writes one JSON object as the message: its fields become the line's.
    if record.name == "app.request" and message.startswith("{") and message.endswith("}"):
        try:
            structured = json.loads(message)
        except ValueError:
            structured = None
        if isinstance(structured, dict):
            event = structured.pop("event", None)
            structured.pop("level", None)
            if structured.get("correlation_id") and "request_id" not in fields:
                fields["request_id"] = structured["correlation_id"]
            fields.update(structured)
            message = str(event or "")
    safe_fields = {}
    for key, value in redact_fields(fields).items():
        safe_fields[f"field_{key}" if key in _RESERVED else key] = value
    return redact_text(message), safe_fields


class JsonFormatter(logging.Formatter):
    """One JSON object a line: timestamp (UTC, ISO 8601), level, logger, message, service, then the context fields."""

    def __init__(self, *, service: str | None = None) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        message, fields = _record_fields(record)
        payload: dict[str, Any] = {
            "timestamp": _utc_iso(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        if self.service:
            payload["service"] = self.service
        payload.update(fields)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc_type"] = record.exc_info[0].__name__
            payload["exc_info"] = redact_text(self.formatException(record.exc_info), max_len=16000)
        elif record.exc_text:
            payload["exc_info"] = redact_text(record.exc_text, max_len=16000)
        if record.stack_info:
            payload["stack_info"] = redact_text(self.formatStack(record.stack_info), max_len=16000)
        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """For a laptop: ``2026-11-26T09:14:03.512Z INFO  app.access  GET /x 200 12.4ms  request_id=… route=…``."""

    def format(self, record: logging.LogRecord) -> str:
        message, fields = _record_fields(record)
        extra = " ".join(f"{key}={json.dumps(value, default=str, ensure_ascii=False) if not isinstance(value, str) or ' ' in value else value}" for key, value in fields.items())
        line = f"{_utc_iso(record.created)} {record.levelname:<7} {record.name}  {message}"
        if extra:
            line = f"{line}  {extra}"
        if record.exc_info and record.exc_info[0] is not None:
            line = f"{line}\n{redact_text(self.formatException(record.exc_info), max_len=16000)}"
        if record.stack_info:
            line = f"{line}\n{redact_text(self.formatStack(record.stack_info), max_len=16000)}"
        return line


class StdoutHandler(logging.StreamHandler):
    """Writes to whatever sys.stdout is at the time (never a stream that was closed or swapped since)."""

    _hawk_handler = True

    def __init__(self) -> None:
        super().__init__(sys.stdout)

    @property  # type: ignore[override]
    def stream(self):  # noqa: ANN201
        return sys.stdout

    @stream.setter
    def stream(self, _value) -> None:  # noqa: ANN001
        pass


# ---------------------------------------------------------------------------------------------------------------------
# The last errors, for the troubleshooting report (app/services/self_check.py)
# ---------------------------------------------------------------------------------------------------------------------


class RecentErrorsHandler(logging.Handler):
    """The last ERROR lines of this process, kept in memory (no personal data: emails and phone numbers removed)."""

    _hawk_handler = True

    def __init__(self, capacity: int = 50) -> None:
        super().__init__(level=logging.ERROR)
        self._lines: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lines_lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno < self.level:
            return
        try:
            message, fields = _record_fields(record)
            line = {
                "at": _utc_iso(record.created),
                "level": record.levelname,
                "logger": record.name,
                "message": redact_sensitive_text(message, max_len=300),
            }
            for key in ("request_id", "task_id", "task_name", "error_type"):
                if fields.get(key):
                    line[key] = str(fields[key])[:128]
            if record.exc_info and record.exc_info[0] is not None:
                line["error_type"] = record.exc_info[0].__name__
            with self._lines_lock:
                self._lines.append(line)
        except Exception:  # noqa: BLE001 - keeping a copy never breaks logging
            pass

    def lines(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lines_lock:
            items = list(self._lines)
        return items[-limit:] if limit > 0 else []


recent_errors = RecentErrorsHandler()


def recent_error_lines(limit: int = 20) -> list[dict[str, Any]]:
    return recent_errors.lines(limit)


# ---------------------------------------------------------------------------------------------------------------------
# Set-up
# ---------------------------------------------------------------------------------------------------------------------

_base_factory = logging.getLogRecordFactory()
_factory_installed = False
_configure_lock = threading.Lock()


def _record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = _base_factory(*args, **kwargs)
    context = _log_context.get()
    if context:
        record.hawk_context = dict(context)
    return record


def install_context_factory() -> None:
    """Every record made from now on carries the current context (also those pytest's caplog sees)."""

    global _factory_installed, _base_factory
    if _factory_installed:
        return
    _base_factory = logging.getLogRecordFactory()
    logging.setLogRecordFactory(_record_factory)
    _factory_installed = True


def _under_tests() -> bool:
    from app.core.config import settings

    return str(settings.env or "").strip().lower() == "test" or bool(os.getenv("TEST_PROFILE")) or "pytest" in sys.modules


def build_handler(*, fmt: str, service: str | None) -> logging.Handler:
    handler = StdoutHandler()
    handler.setFormatter(JsonFormatter(service=service) if fmt == "json" else TextFormatter())
    return handler


def configure_logging(*, service: str | None = None, level: str | None = None, fmt: str | None = None, force: bool = False) -> None:
    """Set logging up once per process: the API (app/main.py), the worker and beat (app/jobs/celery_app.py).

    Under the tests only the context factory is installed (pytest keeps its own handlers), unless ``force``."""

    from app.core.config import settings

    install_context_factory()
    if _under_tests() and not force:
        return
    service = service or str(settings.component_type or "api")
    level_name = (level or settings.log_level or "INFO").upper()
    fmt = (fmt or settings.log_format or "json").lower()
    with _configure_lock:
        root = logging.getLogger()
        for handler in list(root.handlers):
            root.removeHandler(handler)
        root.addHandler(build_handler(fmt=fmt, service=service))
        root.addHandler(recent_errors)
        root.setLevel(getattr(logging, level_name, logging.INFO))

        # Uvicorn: its lines through the same handler, and its own access line off (app/main.py writes one per
        # request, with the route and the request id).
        for name in ("uvicorn", "uvicorn.error"):
            uvicorn_logger = logging.getLogger(name)
            uvicorn_logger.handlers.clear()
            uvicorn_logger.propagate = True
        access = logging.getLogger("uvicorn.access")
        access.handlers.clear()
        access.propagate = False
        access.disabled = True

        # Celery: our own start / finish / failure lines (app/jobs/task_logging.py) replace its per-task ones.
        for name in ("celery", "celery.task", "celery.worker", "celery.beat", "celery.app.trace", "celery.worker.strategy"):
            celery_logger = logging.getLogger(name)
            celery_logger.handlers.clear()
            celery_logger.propagate = True
        logging.getLogger("celery.app.trace").setLevel(logging.CRITICAL)
        logging.getLogger("celery.worker.strategy").setLevel(logging.WARNING)

        # Libraries that would otherwise fill the log at INFO.
        for name in ("httpx", "httpcore", "urllib3", "multipart", "passlib", "asyncio"):
            logging.getLogger(name).setLevel(max(logging.WARNING, root.level))
        logging.captureWarnings(True)
