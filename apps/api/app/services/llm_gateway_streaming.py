"""Governed SSE streaming for gateway chat completions.

The buffered gateway pipeline stays the single source of truth: a streamed call
runs the same ``gateway_chat_complete`` code, with the provider delegate
swapped for a relay that reads the upstream stream. While text arrives the
relay releases only a scanned prefix and always holds back a sliding window,
so a violation that spans chunk boundaries is seen before any part of it is
sent. The held-back tail is released only after the full post-response
decision has been made and persisted.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import queue
import re
import threading
import time
from typing import Any, Callable, Iterator
from uuid import uuid4

import anyio
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import StreamingResponse
from starlette.types import Receive, Scope, Send

from app.core.config import settings
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError
from app.services.llm_gateway_secure.gateway import ProviderStageError, scan_stream_window
from app.services.llm_gateway_secure.schemas import SecureCallContext
from app.services.privacy_sanitizer import (
    BEARER_RE,
    CC_RE,
    EMAIL_RE,
    PHONE_RE,
    SECRET_ASSIGNMENT_RE,
    redact_sensitive_text,
)
from app.services.sensitive_data_detection_service import detect_sensitive_data

# Longer than any single sensitive pattern the output guards match, so a match
# is always complete inside the scanned region before its first char is sent.
STREAM_WINDOW_CHARS = 256
# Scan in batches: each scan runs the full detector, so per-token scans would
# multiply its cost by the token count.
STREAM_RELEASE_STEP_CHARS = 128
STREAM_MAX_OUTPUT_CHARS = 200_000
STREAM_TOTAL_TIMEOUT_SECS = 300.0
STREAM_QUEUE_MAX_ITEMS = 64
_QUEUE_POLL_SECS = 0.25
_REDACTION_SPAN_PATTERNS: tuple[re.Pattern[str], ...] = (
    BEARER_RE,
    SECRET_ASSIGNMENT_RE,
    EMAIL_RE,
    PHONE_RE,
    CC_RE,
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _redact(text: str) -> str:
    return redact_sensitive_text(text, max_len=max(1, len(text))) if text else ""


_SPACE_RE = re.compile(r"\s")


def _after_last_space(text: str, start: int, end: int) -> int:
    """Index just after the last whitespace in ``text[start:end]``, else ``end``."""
    for index in range(end - 1, start - 1, -1):
        if text[index].isspace():
            return index + 1
    return end


def _first_space(text: str, start: int, end: int) -> int | None:
    match = _SPACE_RE.search(text, start, end)
    return match.start() if match else None


def _redaction_safe_cut(text: str, start: int, cut: int) -> int:
    """Move ``cut`` before any redaction match that straddles it, so a value is
    never split between two independently redacted segments."""
    for _ in range(8):
        moved = cut
        for pattern in _REDACTION_SPAN_PATTERNS:
            for match in pattern.finditer(text, start):
                if match.start() < moved < match.end():
                    moved = match.start()
        if moved == cut:
            return cut
        cut = moved
    return cut


class StreamRelay:
    """Reads the upstream stream inside the provider seam and releases scanned text."""

    def __init__(
        self,
        *,
        emit: Callable[[str], bool],
        cancel_event: threading.Event,
        on_started: Callable[[], None],
        window_chars: int = STREAM_WINDOW_CHARS,
        release_step_chars: int = STREAM_RELEASE_STEP_CHARS,
        max_output_chars: int = STREAM_MAX_OUTPUT_CHARS,
        total_timeout_secs: float = STREAM_TOTAL_TIMEOUT_SECS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._emit = emit
        self._cancel = cancel_event
        self._on_started = on_started
        self.window_chars = max(1, int(window_chars))
        self.release_step_chars = max(1, int(release_step_chars))
        self.max_output_chars = max(1, int(max_output_chars))
        self.total_timeout_secs = float(total_timeout_secs)
        self._clock = clock
        self._secure_context: SecureCallContext | None = None
        self._output_guardian: Callable[[str], dict[str, Any]] | None = None
        self._hold_all = True
        self._parts: list[str] = []
        self._released_raw = 0
        self._released: list[str] = []
        self.model: str | None = None
        self.started = False
        self.chunks_received = 0
        self.truncated = False
        self.termination = "not_started"
        self.violation: dict[str, str] | None = None
        self.usage: dict[str, Any] | None = None

    def wrap(
        self,
        delegate: Any,
        *,
        secure_context: SecureCallContext,
        output_guardian: Callable[[str], dict[str, Any]],
        hold_all: bool,
    ) -> "_RelayDelegate":
        self._secure_context = secure_context
        self._output_guardian = output_guardian
        # Reversibly masked output is restored only after the final decision,
        # so nothing may be released early in that mode.
        self._hold_all = bool(hold_all)
        self.model = str(getattr(delegate, "model", "") or "") or None
        return _RelayDelegate(self, delegate)

    @property
    def released_text(self) -> str:
        return "".join(self._released)

    def _text(self) -> str:
        if len(self._parts) > 1:
            self._parts = ["".join(self._parts)]
        return self._parts[0] if self._parts else ""

    def _set_usage(self, usage: dict[str, Any]) -> None:
        self.usage = {key: value for key, value in usage.items() if isinstance(value, int)}

    def _stop(self, *, decision: str, reason: str) -> None:
        self.violation = {"decision": decision, "reason": reason}
        self.termination = "policy_violation"

    def run(self, delegate: Any, *, system_prompt: str, user_prompt: str) -> str:
        stream_fn = getattr(delegate, "stream_text", None)
        if callable(stream_fn):
            upstream: Iterator[str] = iter(
                stream_fn(system_prompt, user_prompt, usage_sink=self._set_usage)
            )
        else:
            upstream = iter([delegate.generate_text(system_prompt=system_prompt, user_prompt=user_prompt)])
        started_at = self._clock()
        try:
            for delta in upstream:
                if not isinstance(delta, str):
                    raise RuntimeError("provider stream yielded a non-text delta")
                if not self.started:
                    self.started = True
                    self.termination = "streaming"
                    self._on_started()
                self.chunks_received += 1
                if self._cancel.is_set():
                    self.termination = "client_disconnected"
                    break
                if self._clock() - started_at > self.total_timeout_secs:
                    raise TimeoutError("provider stream exceeded its total deadline")
                remaining = self.max_output_chars - len(self._text())
                if len(delta) > remaining:
                    self._parts.append(delta[: max(0, remaining)])
                    self.truncated = True
                    self.termination = "max_output_reached"
                    break
                self._parts.append(delta)
                self._release_scanned_prefix()
                if self.violation is not None or self._cancel.is_set():
                    if self.violation is None:
                        self.termination = "client_disconnected"
                    break
            else:
                self.termination = "completed"
        finally:
            close = getattr(upstream, "close", None)
            if callable(close):
                close()
        text = self._text()
        if self.termination == "completed" and not text.strip():
            raise RuntimeError("LLM stream content is empty")
        return text

    def _release_scanned_prefix(self) -> None:
        if self._hold_all or self.violation is not None:
            return
        if self._secure_context is None or self._output_guardian is None:
            self._stop(decision="block", reason="stream_guard_unconfigured")
            return
        text = self._text()
        if len(text) - self._released_raw < self.window_chars + self.release_step_chars:
            return
        # Window edges sit on word boundaries: a word cut in half (e.g. "st"
        # from "step") reads like a street suffix to the address detector.
        cut = _after_last_space(text, self._released_raw, len(text) - self.window_chars)
        context_start = max(0, self._released_raw - self.window_chars)
        if context_start > 0:
            first_space = _first_space(text, context_start, self._released_raw)
            if first_space is not None:
                context_start = first_space + 1
        region_end = _after_last_space(text, cut, len(text))
        if region_end - cut < self.window_chars // 2:
            # One huge token at the tail: scan all of it rather than trim it.
            region_end = len(text)
        region = text[context_start:region_end]
        guard, controlled_region = scan_stream_window(context=self._secure_context, text=region)
        if not guard.passed:
            violations = list(guard.details.get("violations") or [])
            self._stop(decision="block", reason=str(violations[0] if violations else guard.reason))
            return
        guardian = self._output_guardian(controlled_region)
        guardian_decision = str(guardian.get("decision") or "block")
        if guardian_decision != "allow":
            self._stop(decision=guardian_decision, reason=str(guardian.get("reason") or "output_guardian"))
            return
        if guard.details.get("redaction_applied") is True:
            cut = _redaction_safe_cut(text, context_start, cut)
            if cut <= self._released_raw:
                return
            before = _redact(text[context_start : self._released_raw])
            after = _redact(text[context_start:cut])
            if not after.startswith(before):
                self._stop(decision="block", reason="stream_redaction_boundary_unverified")
                return
            segment = after[len(before) :]
            if detect_sensitive_data(
                text_inputs=[segment],
                correlation_id="secure-gateway-stream-redaction-verification",
            ).get("contains_sensitive"):
                self._stop(decision="block", reason="post_call_sensitive_output_redaction_unverified")
                return
        else:
            segment = text[self._released_raw : cut]
        self._released_raw = cut
        self._released.append(segment)
        if segment and not self._emit(segment):
            self.termination = "client_disconnected"

    def trace_facts(self) -> dict[str, Any]:
        text = self._text()
        released = self.released_text
        return {
            "transport": "sse",
            "window_chars": self.window_chars,
            "held_until_decision": self._hold_all,
            "chunks_received": self.chunks_received,
            "chars_received": len(text),
            "received_hash": _sha256(text),
            "chars_released_before_decision": len(released),
            "released_before_decision_hash": _sha256(released),
            "termination": self.termination,
            "truncated": self.truncated,
            "violation": dict(self.violation) if self.violation else None,
            "usage": dict(self.usage) if self.usage else None,
        }


class _RelayDelegate:
    """Provider stand-in handed to the secure gateway's final execution seam."""

    def __init__(self, relay: StreamRelay, inner: Any) -> None:
        self._relay = relay
        self._inner = inner
        self.model = getattr(inner, "model", None)

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        return self._relay.run(self._inner, system_prompt=system_prompt, user_prompt=user_prompt)

    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict[str, Any]) -> dict[str, Any]:
        del system_prompt, user_prompt, json_schema
        raise ProviderStageError()


def _stream_error_body(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, (ProviderStageError, RuntimeError, TimeoutError)):
        code, kind, message = "provider_execution_failed", "provider_error", "Model provider execution failed."
    elif isinstance(exc, GovernanceViolationError):
        code, kind, message = "governance_context_blocked", "hawk_policy_error", "Governance context blocked this request."
    elif isinstance(exc, GovernanceFailSecureError):
        code, kind, message = "governance_fail_secure", "hawk_policy_error", "Governance fail-secure blocked this request."
    elif isinstance(exc, SQLAlchemyError):
        code, kind, message = (
            "enforcement_fail_closed",
            "hawk_policy_error",
            "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
        )
    else:
        code, kind, message = "stream_failed", "hawk_error", "Governed stream failed."
    return {
        "error": {"message": message, "type": kind, "param": None, "code": code},
        "hawk": {"response_control_coverage": "unknown"},
    }


def _sse(payload: dict[str, Any] | str) -> str:
    data = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"), default=str)
    return f"data: {data}\n\n"


class GatewayChatStream:
    """Runs one governed chat call on a worker thread and relays it as SSE.

    The worker owns the request's DB session from ``start`` until it ends; the
    route thread only waits, and the response joins the worker before the
    session dependency is torn down.
    """

    def __init__(
        self,
        *,
        db: Any,
        run: Callable[[StreamRelay], dict[str, Any]],
        envelope: Callable[[dict[str, Any]], dict[str, Any]],
        model_hint: str | None = None,
        relay_options: dict[str, Any] | None = None,
    ) -> None:
        self._db = db
        self._run = run
        self._envelope = envelope
        self._queue: queue.Queue[tuple[str, str | None]] = queue.Queue(maxsize=STREAM_QUEUE_MAX_ITEMS)
        self._cancel = threading.Event()
        self._decided = threading.Event()
        self._thread: threading.Thread | None = None
        self.relay = StreamRelay(
            emit=self._emit_delta,
            cancel_event=self._cancel,
            on_started=self._decided.set,
            **(relay_options or {}),
        )
        self.result: dict[str, Any] | None = None
        self.error: BaseException | None = None
        self.stream_id = f"chatcmpl-{uuid4().hex}"
        self.created = int(time.time())
        self._model_hint = model_hint

    # -- worker side -------------------------------------------------------
    def start(self) -> None:
        context = contextvars.copy_context()
        self._thread = threading.Thread(
            target=context.run,
            args=(self._work,),
            name="hawk-llm-gateway-stream",
            daemon=True,
        )
        self._thread.start()

    def _work(self) -> None:
        try:
            result = self._run(self.relay)
            if self.relay.started:
                self._db.commit()
            self.result = result
        except BaseException as exc:  # surfaced to the route or the SSE consumer
            if self.relay.started:
                try:
                    self._db.rollback()
                except SQLAlchemyError:
                    pass
            self.error = exc
        finally:
            self._decided.set()
            if self.relay.started:
                self._put(("end", None))

    def _put(self, item: tuple[str, str | None]) -> bool:
        # Bounded queue: a slow client blocks the worker, which stops reading
        # upstream and lets TCP flow control push back on the provider.
        while not self._cancel.is_set():
            try:
                self._queue.put(item, timeout=_QUEUE_POLL_SECS)
                return True
            except queue.Full:
                continue
        return False

    def _emit_delta(self, text: str) -> bool:
        return self._put(("delta", text))

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    # -- route side --------------------------------------------------------
    def wait_until_streaming_or_done(self) -> bool:
        """Block until upstream text arrived (True) or the call finished without streaming (False)."""
        self._decided.wait()
        if self.relay.started:
            return True
        self.join()
        return False

    def unstreamed_result(self) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise RuntimeError("governed stream produced no result")
        return self.result

    # -- SSE consumer --------------------------------------------------------
    def _get(self) -> tuple[str, str | None] | None:
        try:
            return self._queue.get(timeout=_QUEUE_POLL_SECS)
        except queue.Empty:
            return None

    def _chunk(
        self,
        delta: dict[str, Any],
        *,
        finish_reason: str | None = None,
        model: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "id": self.stream_id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": model or self.relay.model or self._model_hint,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }
        if extra:
            payload.update(extra)
        return _sse(payload)

    async def events(self) -> Any:
        try:
            yield self._chunk({"role": "assistant", "content": ""})
            while True:
                item = await anyio.to_thread.run_sync(self._get, abandon_on_cancel=True)
                if item is None:
                    continue
                kind, text = item
                if kind == "delta":
                    yield self._chunk({"content": text})
                    continue
                break
            for frame in self._final_frames():
                yield frame
        finally:
            self.cancel()

    def _final_frames(self) -> Iterator[str]:
        if self.error is not None or self.result is None:
            yield _sse(_stream_error_body(self.error or RuntimeError("missing result")))
            yield _sse("[DONE]")
            return
        result = self.result
        hawk = self._envelope(result)
        decision = str(result.get("final_decision") or "").lower()
        blocked = (
            decision == "block"
            or result.get("control_mode") == "inline_prevented"
            or self.relay.violation is not None
        )
        completion = str(result.get("completion") or "")
        released = self.relay.released_text
        model = str(result.get("model") or "") or None
        if not blocked and decision in {"allow", "warn"} and completion.startswith(released):
            remainder = completion[len(released) :]
            if remainder:
                yield self._chunk({"content": remainder}, model=model)
            finish_reason = "length" if self.relay.truncated else "stop"
        else:
            finish_reason = "content_filter"
            hawk = {
                **hawk,
                "error": {
                    "code": "hawk_policy_block",
                    "reason_code": self._reason_code(result),
                    "message": "Hawk restricted this model response before client return.",
                },
            }
        yield self._chunk(
            {},
            finish_reason=finish_reason,
            model=model,
            extra={"usage": self.relay.usage, "hawk": hawk},
        )
        yield _sse("[DONE]")

    def _reason_code(self, result: dict[str, Any]) -> str:
        if self.relay.violation is not None:
            return self.relay.violation["reason"]
        for item in reversed(list(result.get("guardian_results") or [])):
            if isinstance(item, dict) and str(item.get("decision") or "allow") != "allow":
                return str(item.get("reason") or item.get("guardian_id") or "policy")
        decision = str(result.get("final_decision") or "")
        return "stream_output_divergence" if decision in {"allow", "warn"} else decision or "policy"


class GatewaySSEResponse(StreamingResponse):
    """SSE response that cancels upstream and waits for the worker on exit."""

    def __init__(self, stream: GatewayChatStream) -> None:
        super().__init__(
            stream.events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
        self._hawk_stream = stream

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            # Covers client disconnect: stop reading upstream, then let the
            # worker persist its records before the DB session is closed.
            self._hawk_stream.cancel()
            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(
                    self._hawk_stream.join,
                    float(settings.llm_timeout_secs) + 5.0,
                )
