"""Meeting-context collector.

Determines whether a conferencing app is currently running, which raises the risk
weight of a co-resident notetaker. Presence of a meeting app is a heuristic, not a
guarantee a call is live; the backend decision accounts for that.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..catalog import is_meeting_context
from .base import Connection, ProcessInfo


@dataclass
class MeetingContext:
    active: bool
    signals: list[str]


def detect_meeting(processes: list[ProcessInfo], connections: list[Connection]) -> MeetingContext:
    process_names = [p.name for p in processes] + [p.cmdline for p in processes]
    domains = [c.remote_host for c in connections]
    active = is_meeting_context(process_names, domains)
    signals: list[str] = []
    for name in process_names:
        low = name.lower()
        for hint in ("zoom", "teams", "webex", "meet"):
            if hint in low and hint not in signals:
                signals.append(hint)
    return MeetingContext(active=active, signals=signals)
