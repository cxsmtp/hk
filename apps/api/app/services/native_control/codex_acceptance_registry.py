from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any


_SCHEMA_VERSION = "hawk.codex.acceptance-registry/1.0"
_REPORT_SCHEMA_VERSION = "hawk.codex.acceptance-result/1.0"
_SEMANTIC_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
_DEFAULT_PATH = _REPOSITORY_ROOT / "docs/evidence/codex-acceptance-registry.json"
_REQUIRED_TESTED_EVENTS = frozenset({"session_start", "before_model"})
_REQUIRED_CAPABILITIES = frozenset({"discovery", "identity", "prompt_control"})


@dataclass(frozen=True, slots=True)
class CodexAcceptanceEntry:
    provider_version: str
    adapter_version: str
    binary_sha256: str
    report_sha256: str
    evidence_artifact: str
    evidence_timestamp: str
    platform: str
    tested_events: tuple[str, ...]
    accepted_capabilities: tuple[str, ...]
    measured_callback_p95_ms: float
    reviewed: bool
    review_status: str
    production_eligible: bool


@dataclass(frozen=True, slots=True)
class CodexAcceptanceRegistry:
    entries: tuple[CodexAcceptanceEntry, ...]

    def accepted_versions(self, *, adapter_version: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    row.provider_version
                    for row in self.entries
                    if row.adapter_version == adapter_version
                    and row.reviewed
                    and row.production_eligible
                },
                key=lambda value: tuple(int(part) for part in value.split("-", 1)[0].split(".")),
            )
        )

    def entry(
        self,
        provider_version: str,
        *,
        adapter_version: str,
    ) -> CodexAcceptanceEntry | None:
        return next(
            (
                row
                for row in self.entries
                if row.provider_version == provider_version
                and row.adapter_version == adapter_version
                and row.reviewed
                and row.production_eligible
            ),
            None,
        )

    def assurance(self, provider_version: str, *, adapter_version: str) -> str:
        return (
            "exact_verified"
            if self.entry(provider_version, adapter_version=adapter_version) is not None
            else "unsupported"
        )


def _artifact_path(row: dict[str, Any], *, repository_root: Path) -> Path | None:
    artifact = str(row.get("evidence_artifact") or "")
    relative = Path(artifact)
    if not artifact or relative.is_absolute() or ".." in relative.parts:
        return None
    try:
        root = repository_root.resolve(strict=True)
        path = root / relative
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    if path != resolved or not resolved.is_relative_to(root) or not resolved.is_file():
        return None
    expected = str(row.get("report_sha256") or "")
    if not _SHA256.fullmatch(expected):
        return None
    return resolved if hashlib.sha256(resolved.read_bytes()).hexdigest() == expected else None


def _artifact_contract_matches(
    row: dict[str, Any],
    *,
    repository_root: Path,
) -> bool:
    path = _artifact_path(row, repository_root=repository_root)
    if path is None:
        return False
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(report, dict):
        return False
    result = report.get("result")
    scope = report.get("scope")
    return bool(
        report.get("schema_version") == _REPORT_SCHEMA_VERSION
        and report.get("classification")
        == "real_binary_isolated_hardware_signed_callback_acceptance"
        and report.get("provider") == "openai"
        and report.get("product") == "codex"
        and report.get("provider_version") == row.get("provider_version")
        and report.get("adapter_version") == row.get("adapter_version")
        and report.get("binary_sha256") == row.get("binary_sha256")
        and report.get("evidence_timestamp") == row.get("evidence_timestamp")
        and report.get("platform") == row.get("platform")
        and isinstance(scope, dict)
        and scope.get("provider_adapter_contract_verified") is True
        and scope.get("tenant_deployment_accepted") is False
        and scope.get("live_backend_signature_verified") is False
        and scope.get("synthetic_fixture") is False
        and isinstance(result, dict)
        and result.get("passed") is True
        and result.get("actual_binary_executed") is True
        and result.get("binary_hash_verified") is True
        and result.get("exact_version_verified") is True
        and result.get("version_command_succeeded") is True
        and result.get("hardware_backed_key") is True
        and result.get("hardware_key_provider") == "macos_secure_enclave"
        and _SHA256.fullmatch(str(result.get("key_thumbprint") or "")) is not None
        and result.get("signature_algorithm") == "ES256"
        and result.get("allow_callback_observed") is True
        and result.get("allow_signature_verified") is True
        and result.get("prompt_hook_observed") is True
        and result.get("block_signature_verified") is True
        and result.get("prompt_blocked_before_model") is True
        and result.get("raw_prompt_exported") is False
        and result.get("hook_installation_observed") is True
        and result.get("isolated_hook_trust_bypass") is True
        and result.get("model_transport_isolated") is True
        and result.get("model_request_observed") is False
        and set(result.get("tested_events") or ()) == set(row.get("tested_events") or ())
    )


def _decode_entry(row: object, *, repository_root: Path) -> CodexAcceptanceEntry | None:
    if not isinstance(row, dict):
        return None
    provider_version = str(row.get("provider_version") or "")
    adapter_version = str(row.get("adapter_version") or "")
    binary_sha256 = str(row.get("binary_sha256") or "")
    report_sha256 = str(row.get("report_sha256") or "")
    evidence_timestamp = str(row.get("evidence_timestamp") or "")
    platform = str(row.get("platform") or "")
    tested_events = row.get("tested_events")
    accepted_capabilities = row.get("accepted_capabilities")
    try:
        parsed_timestamp = datetime.fromisoformat(evidence_timestamp.replace("Z", "+00:00"))
        measured_p95 = float(row.get("measured_callback_p95_ms"))
    except (TypeError, ValueError):
        return None
    if (
        row.get("provider") != "openai"
        or row.get("product") != "codex"
        or not _SEMANTIC_VERSION.fullmatch(provider_version)
        or not _SEMANTIC_VERSION.fullmatch(adapter_version)
        or not _SHA256.fullmatch(binary_sha256)
        or not _SHA256.fullmatch(report_sha256)
        or parsed_timestamp.tzinfo is None
        or not platform
        or not isinstance(tested_events, list)
        or len(tested_events) != len(_REQUIRED_TESTED_EVENTS)
        or set(tested_events) != _REQUIRED_TESTED_EVENTS
        or not all(isinstance(value, str) and value for value in tested_events)
        or not isinstance(accepted_capabilities, list)
        or len(accepted_capabilities) != len(_REQUIRED_CAPABILITIES)
        or set(accepted_capabilities) != _REQUIRED_CAPABILITIES
        or not all(isinstance(value, str) and value for value in accepted_capabilities)
        or not 0 <= measured_p95 < 4_000
        or row.get("reviewed") is not True
        or row.get("review_status") != "reviewed_by_acceptance_gate"
        or row.get("production_eligible") is not True
        or not _artifact_contract_matches(row, repository_root=repository_root)
    ):
        return None
    return CodexAcceptanceEntry(
        provider_version=provider_version,
        adapter_version=adapter_version,
        binary_sha256=binary_sha256,
        report_sha256=report_sha256,
        evidence_artifact=str(row["evidence_artifact"]),
        evidence_timestamp=evidence_timestamp,
        platform=platform,
        tested_events=tuple(dict.fromkeys(tested_events)),
        accepted_capabilities=tuple(dict.fromkeys(accepted_capabilities)),
        measured_callback_p95_ms=measured_p95,
        reviewed=True,
        review_status="reviewed_by_acceptance_gate",
        production_eligible=True,
    )


def load_codex_acceptance_registry(
    path: Path | str | None = None,
) -> CodexAcceptanceRegistry:
    registry_candidate = Path(path).expanduser() if path else _DEFAULT_PATH
    if registry_candidate.is_symlink():
        return CodexAcceptanceRegistry(entries=())
    try:
        registry_path = registry_candidate.resolve(strict=True)
    except OSError:
        return CodexAcceptanceRegistry(entries=())
    repository_root = _REPOSITORY_ROOT if path is None else registry_path.parents[2]
    if not registry_path.is_file():
        return CodexAcceptanceRegistry(entries=())
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return CodexAcceptanceRegistry(entries=())
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA_VERSION:
        return CodexAcceptanceRegistry(entries=())
    rows = payload.get("entries") if isinstance(payload.get("entries"), list) else []
    entries = tuple(
        decoded
        for row in rows
        if (decoded := _decode_entry(row, repository_root=repository_root)) is not None
    )
    identities = {(row.provider_version, row.adapter_version) for row in entries}
    if len(identities) != len(entries):
        return CodexAcceptanceRegistry(entries=())
    return CodexAcceptanceRegistry(entries=entries)
