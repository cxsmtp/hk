"""Audio-capture inference.

Precise per-process microphone attribution on macOS is gated behind private APIs
and TCC, so this collector is deliberately honest: it flags *known* recorder /
notetaker processes as likely-capturing (a strong, low-false-positive heuristic)
and leaves absolute proof of mic access to an optional MDM helper. It never asserts
capture it cannot substantiate.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import re

from ..catalog import NOTETAKER_CATALOG, NotetakerCategory, process_hint_matches
from .base import ProcessInfo, run_cmd

_RECORDER_HINTS = tuple(
    hint
    for sig in NOTETAKER_CATALOG
    if sig.category in (NotetakerCategory.LOCAL_RECORDER, NotetakerCategory.MEETING_BOT)
    for hint in sig.process_hints
)


@dataclass
class AudioCandidate:
    pid: int
    process_name: str
    basis: str  # e.g. "known_recorder", "macos_coreaudio_client", "windows_audio_session"


def likely_capturing(processes: list[ProcessInfo]) -> list[AudioCandidate]:
    out: list[AudioCandidate] = []
    for proc in processes:
        process_value = f"{proc.name} {proc.cmdline}"
        if process_hint_matches(process_value, _RECORDER_HINTS):
            out.append(AudioCandidate(pid=proc.pid, process_name=proc.name, basis="known_recorder"))
    return out


def _known_recorder_name(value: str) -> bool:
    return process_hint_matches(value, _RECORDER_HINTS)


def _parse_pid_and_name(line: str) -> tuple[int, str] | None:
    """Extract process name and PID from common tabular command output.

    The endpoint agent intentionally does not require privileged/private audio
    APIs in the pilot. These parsers consume evidence from optional fleet helpers
    or OS commands and only promote known notetaker processes.
    """
    parts = line.strip().split()
    if len(parts) < 2:
        return None

    # Common shapes:
    #   Granola 4242 ayush CoreAudio
    #   4242 Granola True
    #   6161 fathom True
    if parts[0].isdigit():
        pid = int(parts[0])
        name = parts[1]
        return pid, name
    if parts[1].isdigit():
        pid = int(parts[1])
        name = parts[0]
        return pid, name

    match = re.search(r"\bpid[:=]\s*(\d+)\b", line, flags=re.IGNORECASE)
    if not match:
        return None
    pid = int(match.group(1))
    name_match = re.search(r"\b(?:process|processname|name)[:=]\s*([^,\s]+)", line, flags=re.IGNORECASE)
    if not name_match:
        return None
    return pid, name_match.group(1)


def _dedupe(candidates: list[AudioCandidate]) -> list[AudioCandidate]:
    seen: set[tuple[int, str, str]] = set()
    out: list[AudioCandidate] = []
    for candidate in candidates:
        key = (candidate.pid, candidate.process_name.lower(), candidate.basis)
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
    return out


def parse_macos_audio_clients(output: str) -> list[AudioCandidate]:
    """Parse macOS CoreAudio-style process evidence into known notetaker candidates.

    This function does not prove microphone content was captured; it only records
    that a known notetaker process appeared in audio-client evidence. That makes
    the resulting telemetry useful without overstating the control surface.
    """
    candidates: list[AudioCandidate] = []
    for line in output.splitlines():
        low = line.lower()
        if not line.strip() or "command" in low and "pid" in low:
            continue
        if "audio" not in low and "coreaudio" not in low:
            continue
        parsed = _parse_pid_and_name(line)
        if parsed is None:
            continue
        pid, name = parsed
        if _known_recorder_name(name):
            candidates.append(AudioCandidate(pid=pid, process_name=name, basis="macos_coreaudio_client"))
    return _dedupe(candidates)


def parse_windows_audio_sessions(output: str) -> list[AudioCandidate]:
    """Parse Windows audio-session helper output into known notetaker candidates."""
    candidates: list[AudioCandidate] = []
    for line in output.splitlines():
        low = line.lower()
        if not line.strip() or "processid" in low and "processname" in low:
            continue
        if any(marker in low for marker in ("false", "notrecording", "inactive")):
            continue
        parsed = _parse_pid_and_name(line)
        if parsed is None:
            continue
        pid, name = parsed
        if _known_recorder_name(name):
            candidates.append(AudioCandidate(pid=pid, process_name=name, basis="windows_audio_session"))
    return _dedupe(candidates)


def collect_platform_audio_candidates(
    processes: list[ProcessInfo],
    *,
    os_type: str,
    command_runner=run_cmd,
) -> list[AudioCandidate]:
    """Return endpoint audio candidates from process and OS-specific evidence.

    The collector is intentionally best-effort. It never records audio content
    and never treats a generic meeting app as a notetaker; only catalog-matched
    recorder/notetaker processes are promoted.
    """
    candidates = likely_capturing(processes)
    os_low = os_type.lower()
    if os_low in {"windows", "win32", "nt"}:
        raw = command_runner(["hawk-windows-audio-sessions.exe", "--format", "text"], timeout=4.0)
        if not raw:
            raw = command_runner(["hawk-windows-audio-sessions", "--format", "text"], timeout=4.0)
        if not raw:
            script = resources.files("hawk_endpoint_agent.resources").joinpath("windows_audio_sessions.ps1")
            raw = command_runner(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                    "--format",
                    "text",
                ],
                timeout=6.0,
            )
        candidates.extend(parse_windows_audio_sessions(raw))
    return _dedupe(candidates)
