from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class GeminiHookProcessResult:
    stdout: str
    stderr: str
    exit_code: int


_PRE_ACTION_EVENTS = frozenset({"before_tool", "before_agent", "before_model"})


def _single_line(value: object, *, maximum: int = 4_096) -> str:
    text = str(value or "")[:maximum]
    if any(character in text for character in ("\n", "\r", "\x00")):
        raise ValueError("gemini_hook_output_control_character")
    return text


def render_gemini_hook_result(
    output: Mapping[str, Any],
    *,
    diagnostic: str = "",
    block_transport: str = "json",
) -> GeminiHookProcessResult:
    """Render Gemini's strict command-hook stdout/stderr/exit contract."""

    if not isinstance(output, Mapping):
        raise ValueError("gemini_hook_output_must_be_object")
    payload = dict(output)
    for key, value in payload.items():
        if not isinstance(key, str) or not key:
            raise ValueError("gemini_hook_output_key_invalid")
        if isinstance(value, str):
            _single_line(value)
    transport = str(block_transport or "json").strip().lower()
    if transport not in {"json", "exit_2"}:
        raise ValueError("gemini_hook_output_block_transport_invalid")
    denied = str(payload.get("decision") or "").strip().lower() in {"deny", "block"}
    if denied and transport == "exit_2":
        reason = _single_line(payload.get("reason") or "Blocked by Hawk policy")
        return GeminiHookProcessResult(stdout="", stderr=reason, exit_code=2)
    try:
        stdout = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("gemini_hook_output_not_json") from exc
    if "\n" in stdout or "\r" in stdout or "\x00" in stdout:
        raise ValueError("gemini_hook_output_control_character")
    return GeminiHookProcessResult(
        stdout=stdout,
        stderr=_single_line(diagnostic),
        exit_code=0,
    )


def render_gemini_runtime_result(
    event: str,
    output: Mapping[str, Any],
    *,
    diagnostic: str = "",
    block_transport: str = "json",
) -> GeminiHookProcessResult:
    """Prevent serializer defects or hostile reason text from becoming fail-open stdout."""

    try:
        return render_gemini_hook_result(
            output,
            diagnostic=diagnostic,
            block_transport=block_transport,
        )
    except ValueError:
        reason = "Hawk native output validation failed"
        if str(event or "").strip().lower() in _PRE_ACTION_EVENTS:
            return render_gemini_hook_result(
                {"decision": "deny", "reason": reason},
                block_transport="exit_2",
            )
        return render_gemini_hook_result({}, diagnostic=reason)
