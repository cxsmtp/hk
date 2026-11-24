from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any


_SCHEMA_VERSION = "gemini-cli-acceptance-registry/1.0"
_SEMANTIC_VERSION = re.compile(r"^\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_DEFAULT_PATH = _REPOSITORY_ROOT / "docs/evidence/gemini-cli-acceptance-registry.json"


@dataclass(frozen=True, slots=True)
class GeminiAcceptanceEntry:
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
    production_eligible: bool


@dataclass(frozen=True, slots=True)
class GeminiAcceptanceRegistry:
    entries: tuple[GeminiAcceptanceEntry, ...]

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

    def entry(self, provider_version: str, *, adapter_version: str) -> GeminiAcceptanceEntry | None:
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
        return "exact_verified" if self.entry(provider_version, adapter_version=adapter_version) else "unsupported"


def _artifact_payload(row: dict[str, Any], *, repository_root: Path) -> dict[str, Any] | None:
    artifact = str(row.get("evidence_artifact") or "")
    if not artifact or Path(artifact).is_absolute() or ".." in Path(artifact).parts:
        return None
    path = repository_root / artifact
    if not path.is_file() or path.is_symlink():
        return None
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != str(row.get("report_sha256") or ""):
        return None
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _decode_entry(row: object, *, repository_root: Path) -> GeminiAcceptanceEntry | None:
    if not isinstance(row, dict):
        return None
    tested_events = row.get("tested_events")
    capabilities = row.get("accepted_capabilities")
    try:
        timestamp = datetime.fromisoformat(str(row.get("evidence_timestamp") or "").replace("Z", "+00:00"))
        measured_p95 = float(row.get("measured_callback_p95_ms"))
    except (TypeError, ValueError):
        return None
    provider_version = str(row.get("provider_version") or "")
    adapter_version = str(row.get("adapter_version") or "")
    report_sha256 = str(row.get("report_sha256") or "")
    artifact = _artifact_payload(row, repository_root=repository_root)
    if (
        row.get("provider") != "google"
        or row.get("product") != "gemini_cli"
        or not _SEMANTIC_VERSION.fullmatch(provider_version)
        or not _SEMANTIC_VERSION.fullmatch(adapter_version)
        or not _SHA256.fullmatch(report_sha256)
        or timestamp.tzinfo is None
        or not isinstance(tested_events, list)
        or not tested_events
        or not all(isinstance(value, str) and value for value in tested_events)
        or not isinstance(capabilities, list)
        or not capabilities
        or not all(isinstance(value, str) and value for value in capabilities)
        or not 0 <= measured_p95 < 4_000
        or row.get("reviewed") is not True
        or row.get("review_status") != "reviewed_by_acceptance_gate"
        or artifact is None
        or artifact.get("provider") != "google"
        or artifact.get("product") != "gemini_cli"
        or artifact.get("provider_version") != provider_version
        or artifact.get("adapter_version") != adapter_version
        or not set(tested_events).issubset(set(artifact.get("tested_events") or []))
        or not set(capabilities).issubset(set(artifact.get("accepted_capabilities") or []))
    ):
        return None
    return GeminiAcceptanceEntry(
        provider_version=provider_version,
        adapter_version=adapter_version,
        report_sha256=report_sha256,
        evidence_artifact=str(row["evidence_artifact"]),
        evidence_timestamp=str(row["evidence_timestamp"]),
        tested_events=tuple(dict.fromkeys(tested_events)),
        accepted_capabilities=tuple(dict.fromkeys(capabilities)),
        measured_callback_p95_ms=measured_p95,
        reviewed=True,
        review_status="reviewed_by_acceptance_gate",
        production_eligible=(
            artifact.get("passed") is True and artifact.get("maturity") == "production"
        ),
    )


def load_gemini_acceptance_registry(path: Path | str | None = None) -> GeminiAcceptanceRegistry:
    registry_path = Path(path).expanduser().resolve() if path else _DEFAULT_PATH
    repository_root = _REPOSITORY_ROOT if path is None else registry_path.parents[2]
    if not registry_path.is_file() or registry_path.is_symlink():
        return GeminiAcceptanceRegistry(entries=())
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return GeminiAcceptanceRegistry(entries=())
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        return GeminiAcceptanceRegistry(entries=())
    rows = payload.get("entries") if isinstance(payload.get("entries"), list) else []
    return GeminiAcceptanceRegistry(
        entries=tuple(
            decoded
            for row in rows
            if (decoded := _decode_entry(row, repository_root=repository_root)) is not None
        )
    )
