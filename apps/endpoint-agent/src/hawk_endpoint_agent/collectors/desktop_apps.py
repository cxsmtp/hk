"""Native desktop AI-app inventory.

Identifies AI-capable native applications running on the endpoint (assistant apps,
AI IDEs/terminals, local model runners) so their AI usage is covered by the agent
without a browser extension. Reference data, extended by backend policy; matching
is on the app/process name to keep false positives low.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..chatgpt_desktop import ChatGPTInstallationObservation, observe_chatgpt_processes
from .base import ProcessInfo

# process-name substring (lowercased) -> human label. Local model runners are
# flagged too since they represent on-device inference that bypasses SaaS controls.
DESKTOP_AI_APPS: dict[str, str] = {
    "claude": "Claude Desktop",
    "chatgpt": "ChatGPT Desktop",
    "cursor": "Cursor (AI IDE)",
    "perplexity": "Perplexity Desktop",
    "raycast": "Raycast AI",
    "warp": "Warp (AI terminal)",
    "ollama": "Ollama (local models)",
    "lm studio": "LM Studio (local models)",
    "lmstudio": "LM Studio (local models)",
    "jan.ai": "Jan (local models)",
    "copilot": "GitHub/MS Copilot",
    "cody": "Sourcegraph Cody",
    "continue": "Continue (AI IDE)",
}


@dataclass
class DesktopAIApp:
    pid: int
    process_name: str
    label: str
    local_model_runner: bool
    composite_context: dict[str, Any] | None = None


_LOCAL_RUNNERS = ("ollama", "lm studio", "lmstudio", "jan.ai")


def detect_desktop_ai_apps(
    processes: list[ProcessInfo],
    *,
    chatgpt_installation: ChatGPTInstallationObservation | None = None,
) -> list[DesktopAIApp]:
    out: list[DesktopAIApp] = []
    seen: set[tuple[int, str]] = set()
    for proc in processes:
        haystack = f"{proc.name} {proc.cmdline}".lower()
        for hint, label in DESKTOP_AI_APPS.items():
            if hint in haystack:
                key = (proc.pid, label)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    DesktopAIApp(
                        pid=proc.pid,
                        process_name=proc.name,
                        label=label,
                        local_model_runner=any(runner in hint for runner in _LOCAL_RUNNERS),
                    )
                )
    if chatgpt_installation is not None:
        contexts = {row.process_id: row.as_dict() for row in observe_chatgpt_processes(processes, chatgpt_installation)}
        for app in out:
            if app.label == "ChatGPT Desktop" and app.pid in contexts:
                app.composite_context = contexts[app.pid]
    return out
