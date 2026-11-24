"""Network egress control — block a notetaker SaaS from phoning home.

Blocking egress requires root (a pf anchor or a hosts-file entry). When the agent
is not privileged, it returns ``external_required`` together with the exact rule it
would apply, so an orchestrator/MDM can enforce it out of band. When privileged and
explicitly enabled, it applies reversible hosts-file null-routes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

_HOSTS_PATH = "/etc/hosts"
_MARKER = "# hawk-endpoint-agent"


@dataclass
class NetworkActionResult:
    performed: bool
    mode: str                          # "blocked" | "external_required" | "disabled"
    domains: list[str] = field(default_factory=list)
    detail: str = ""


class NetworkControl:
    def __init__(self, *, enabled: bool) -> None:
        self._enabled = enabled

    def _is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def capability(self) -> dict[str, object]:
        return {"can_block_egress": self._enabled and self._is_root(), "method": "hosts_null_route", "reversible": True}

    def block_domains(self, domains: list[str]) -> NetworkActionResult:
        domains = sorted({d.strip().lower() for d in domains if d.strip()})
        if not domains:
            return NetworkActionResult(False, "disabled", detail="no domains supplied")
        if not (self._enabled and self._is_root()):
            return NetworkActionResult(
                False,
                "external_required",
                domains,
                "egress block requires root + policy enablement; rule prepared for MDM/orchestrator",
            )
        try:
            existing = ""
            if os.path.exists(_HOSTS_PATH):
                with open(_HOSTS_PATH, encoding="utf-8") as handle:
                    existing = handle.read()
            new_lines = [
                f"127.0.0.1 {domain} {_MARKER}"
                for domain in domains
                if f" {domain} {_MARKER}" not in existing
            ]
            if new_lines:
                with open(_HOSTS_PATH, "a", encoding="utf-8") as handle:
                    handle.write("\n" + "\n".join(new_lines) + "\n")
            return NetworkActionResult(True, "blocked", domains)
        except OSError as exc:
            return NetworkActionResult(False, "external_required", domains, f"hosts write failed: {exc}")
