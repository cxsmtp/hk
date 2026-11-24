from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any


_SCHEMA_VERSION = "hawk.claude-code.acceptance-registry/1.0"
_SEMANTIC_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_DEFAULT_PATH = _REPOSITORY_ROOT / "docs/evidence/claude-code-acceptance-registry.json"


@dataclass(frozen=True, slots=True)
class ClaudeAcceptanceEntry:
    provider_version: str
    adapter_version: str
    report_sha256: str
    evidence_artifact: str
    evidence_timestamp: str
    tested_events: tuple[str, ...]
    accepted_capabilities: tuple[str, ...]
    measured_callback_p95_ms: float
    reviewed: bool
    review_status: str


@dataclass(frozen=True, slots=True)
class ClaudeAcceptanceRegistry:
    entries: tuple[ClaudeAcceptanceEntry, ...]

    def accepted_versions(self, *, adapter_version: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    row.provider_version
                    for row in self.entries
                    if row.adapter_version == adapter_version and row.reviewed
                },
                key=lambda value: tuple(int(part) for part in value.split("-", 1)[0].split(".")),
            )
        )

    def entry(
        self,
        provider_version: str,
        *,
        adapter_version: str,
    ) -> ClaudeAcceptanceEntry | None:
        return next(
            (
                row
                for row in self.entries
                if row.provider_version == provider_version
                and row.adapter_version == adapter_version
                and row.reviewed
            ),
            None,
        )

    def assurance(self, provider_version: str, *, adapter_version: str) -> str:
        return (
            "exact_verified"
            if self.entry(provider_version, adapter_version=adapter_version) is not None
            else "unsupported"
        )


def _artifact_matches(row: dict[str, Any], *, repository_root: Path) -> bool:
    artifact = str(row.get("evidence_artifact") or "")
    if not artifact or Path(artifact).is_absolute() or ".." in Path(artifact).parts:
        return False
    path = repository_root / artifact
    if not path.is_file() or path.is_symlink():
        return False
    expected = str(row.get("report_sha256") or "")
    return hashlib.sha256(path.read_bytes()).hexdigest() == expected


def _decode_entry(row: object, *, repository_root: Path) -> ClaudeAcceptanceEntry | None:
    if not isinstance(row, dict):
        return None
    provider_version = str(row.get("provider_version") or "")
    adapter_version = str(row.get("adapter_version") or "")
    report_sha256 = str(row.get("report_sha256") or "")
    evidence_timestamp = str(row.get("evidence_timestamp") or "")
    tested_events = row.get("tested_events")
    accepted_capabilities = row.get("accepted_capabilities")
    try:
        parsed_timestamp = datetime.fromisoformat(evidence_timestamp.replace("Z", "+00:00"))
        measured_p95 = float(row.get("measured_callback_p95_ms"))
    except (TypeError, ValueError):
        return None
    if (
        row.get("provider") != "anthropic"
        or row.get("product") != "claude_code"
        or not _SEMANTIC_VERSION.fullmatch(provider_version)
        or not _SEMANTIC_VERSION.fullmatch(adapter_version)
        or not _SHA256.fullmatch(report_sha256)
        or parsed_timestamp.tzinfo is None
        or not isinstance(tested_events, list)
        or not tested_events
        or not all(isinstance(value, str) and value for value in tested_events)
        or not isinstance(accepted_capabilities, list)
        or not accepted_capabilities
        or not all(isinstance(value, str) and value for value in accepted_capabilities)
        or not 0 <= measured_p95 < 4_000
        or row.get("reviewed") is not True
        or row.get("review_status") != "reviewed_by_acceptance_gate"
        or not _artifact_matches(row, repository_root=repository_root)
    ):
        return None
    return ClaudeAcceptanceEntry(
        provider_version=provider_version,
        adapter_version=adapter_version,
        report_sha256=report_sha256,
        evidence_artifact=str(row["evidence_artifact"]),
        evidence_timestamp=evidence_timestamp,
        tested_events=tuple(dict.fromkeys(tested_events)),
        accepted_capabilities=tuple(dict.fromkeys(accepted_capabilities)),
        measured_callback_p95_ms=measured_p95,
        reviewed=True,
        review_status="reviewed_by_acceptance_gate",
    )


def load_claude_acceptance_registry(
    path: Path | str | None = None,
) -> ClaudeAcceptanceRegistry:
    registry_path = Path(path).expanduser().resolve() if path else _DEFAULT_PATH
    repository_root = _REPOSITORY_ROOT if path is None else registry_path.parents[2]
    if not registry_path.is_file() or registry_path.is_symlink():
        return ClaudeAcceptanceRegistry(entries=())
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ClaudeAcceptanceRegistry(entries=())
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        return ClaudeAcceptanceRegistry(entries=())
    rows = payload.get("entries") if isinstance(payload.get("entries"), list) else []
    entries = tuple(
        decoded
        for row in rows
        if (decoded := _decode_entry(row, repository_root=repository_root)) is not None
    )
    return ClaudeAcceptanceRegistry(entries=entries)
