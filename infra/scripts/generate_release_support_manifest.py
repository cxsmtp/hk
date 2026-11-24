#!/usr/bin/env python3
"""Generate deterministic, evidence-bound native release support artifacts."""

from __future__ import annotations

import argparse
from datetime import date, datetime
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
API_ROOT = REPOSITORY_ROOT / "apps" / "api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))


REGISTRY_FILES = {
    "claude": "docs/evidence/claude-code-acceptance-registry.json",
    "codex": "docs/evidence/codex-acceptance-registry.json",
    "gemini": "docs/evidence/gemini-cli-acceptance-registry.json",
    "cursor": "docs/evidence/cursor-acceptance-registry.json",
}
LOADER_NAMES = {
    "claude": ("app.services.native_control.claude_acceptance_registry", "load_claude_acceptance_registry"),
    "codex": ("app.services.native_control.codex_acceptance_registry", "load_codex_acceptance_registry"),
    "gemini": ("app.services.native_control.gemini_acceptance_registry", "load_gemini_acceptance_registry"),
    "cursor": ("app.services.native_control.cursor_acceptance_registry", "load_cursor_acceptance_registry"),
}
REGISTRY_SCHEMA_VERSIONS = {
    "claude": "hawk.claude-code.acceptance-registry/1.0",
    "codex": "hawk.codex.acceptance-registry/1.0",
    "gemini": "gemini-cli-acceptance-registry/1.0",
    "cursor": "hawk.cursor.acceptance-registry/1.0",
}
REGISTRY_IDENTITIES = {
    "claude": ("anthropic", "claude_code"),
    "codex": ("openai", "codex"),
    "gemini": ("google", "gemini_cli"),
    "cursor": ("cursor", "cursor"),
}
REQUIRED_FLAGS = (
    "native_control_framework",
    "native_control_adapter_framework",
    "native_control_reference_adapters",
    "native_control_adapter_enforcement",
    "native_control_monitor",
    "native_control_enforce",
    "native_control_anthropic",
    "native_control_openai",
    "native_control_google",
    "native_control_cursor",
)
ENTERPRISE_TARGETS = (
    "Entra ID",
    "Okta",
    "Splunk",
    "Rapid7",
    "Securonix",
    "Elastic",
    "Microsoft Sentinel",
)
SCHEMA_VERSION = "hawk.release-support-manifest/1.0"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _read_payload(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_authoritative_entries(kind: str, registry_path: Path) -> tuple[Any, ...]:
    module_name, loader_name = LOADER_NAMES[kind]
    module = __import__(module_name, fromlist=[loader_name])
    loader = getattr(module, loader_name)
    registry = loader(registry_path)
    return tuple(registry.entries)


def _identity(kind: str, row: dict[str, Any]) -> tuple[str, str]:
    return (
        str(row.get("provider_version") or ""),
        str(row.get("adapter_version") or row.get("desktop_version") or ""),
    )


def _entry_identity(kind: str, entry: Any) -> tuple[str, str]:
    adapter_version = getattr(entry, "adapter_version", "")
    return (str(getattr(entry, "provider_version", "")), str(adapter_version))


def _entry_matches_raw(kind: str, entry: Any, row: dict[str, Any]) -> bool:
    provider, product = REGISTRY_IDENTITIES[kind]
    entry_reviewed = getattr(entry, "reviewed", True)
    entry_review_status = getattr(entry, "review_status", "reviewed_by_acceptance_gate")
    common_matches = (
        row.get("provider") == provider,
        row.get("product") == product,
        row.get("provider_version") == getattr(entry, "provider_version", None),
        row.get("adapter_version") == getattr(entry, "adapter_version", None),
        row.get("evidence_artifact") == getattr(entry, "evidence_artifact", None),
        row.get("report_sha256") == getattr(entry, "report_sha256", None),
        row.get("evidence_timestamp") == getattr(entry, "evidence_timestamp", None),
        tuple(row.get("tested_events") or ()) == tuple(getattr(entry, "tested_events", ())),
        tuple(row.get("accepted_capabilities") or ()) == tuple(getattr(entry, "accepted_capabilities", ())),
        row.get("measured_callback_p95_ms") == getattr(entry, "measured_callback_p95_ms", None),
        row.get("reviewed") is entry_reviewed,
        row.get("review_status") == entry_review_status,
    )
    if not all(common_matches):
        return False
    if kind == "cursor":
        return (
            row.get("desktop_version") == getattr(entry, "desktop_version", None)
            and row.get("desktop_commit") == getattr(entry, "desktop_commit", None)
        )
    if kind == "codex":
        return (
            row.get("binary_sha256") == getattr(entry, "binary_sha256", None)
            and row.get("platform") == getattr(entry, "platform", None)
            and row.get("production_eligible") is getattr(entry, "production_eligible", None)
        )
    return True


def _raw_status(
    *,
    kind: str,
    registry_root: Path,
    row: object,
    accepted: dict[tuple[str, str], list[Any]],
) -> tuple[str, dict[str, Any]]:
    if not isinstance(row, dict):
        return "registry_invalid", {"reason": "row_not_object"}
    artifact_name = str(row.get("evidence_artifact") or "")
    if not artifact_name:
        return "registry_invalid", {"reason": "evidence_artifact_missing"}
    artifact_relative_path = Path(artifact_name)
    if artifact_relative_path.is_absolute() or ".." in artifact_relative_path.parts:
        return "registry_invalid", {"reason": "artifact_path_must_be_relative"}
    artifact_path = registry_root / artifact_relative_path
    if not artifact_path.is_file() or artifact_path.is_symlink():
        return "artifact_missing", {"artifact": artifact_name}
    actual_digest = _sha256(artifact_path)
    declared_digest = str(row.get("report_sha256") or "")
    if actual_digest != declared_digest:
        return "hash_mismatch", {
            "artifact": artifact_name,
            "declared_sha256": declared_digest,
            "actual_sha256": actual_digest,
        }
    candidates = accepted.get(_identity(kind, row), [])
    if len(candidates) != 1:
        return "registry_invalid", {"reason": "duplicate_or_ambiguous_identity"}
    if not _entry_matches_raw(kind, candidates[0], row):
        return "registry_invalid", {"reason": "authoritative_entry_mismatch"}
    return "accepted", {"artifact": artifact_name, "actual_sha256": actual_digest}


def _expiry_status(row: dict[str, Any], as_of: date) -> tuple[str, str | None]:
    raw_expiry = row.get("expires_at") or row.get("expiry") or row.get("valid_until")
    if raw_expiry in (None, ""):
        return "expiry_missing", None
    try:
        expiry = datetime.fromisoformat(str(raw_expiry).replace("Z", "+00:00")).date()
    except ValueError:
        return "registry_invalid", str(raw_expiry)
    return ("stale" if as_of > expiry else "fresh"), str(raw_expiry)


def _flag_defaults() -> dict[str, bool]:
    from app.core.config import Settings

    return {
        name: bool(Settings.model_fields[name].default)
        for name in REQUIRED_FLAGS
    }


def _source_permits_production(entry: Any) -> bool:
    return getattr(entry, "production_eligible", False) is True


def _normalize_entry(
    *,
    kind: str,
    entry: Any,
    row: dict[str, Any],
    registry_path: Path,
    registry_digest: str,
    artifact_path: Path,
    artifact_digest: str,
    as_of: date,
    repository_root: Path,
) -> dict[str, Any]:
    artifact_payload = _read_payload(artifact_path) or {}
    expiry_status, expires_at = _expiry_status(row, as_of)
    statuses = [expiry_status]
    source_permits = _source_permits_production(entry)
    production_eligible = source_permits and expiry_status == "fresh"
    result = {
        "provider": str(row.get("provider") or ""),
        "product": str(row.get("product") or ""),
        "provider_version": str(getattr(entry, "provider_version", row.get("provider_version", ""))),
        "adapter_version": str(getattr(entry, "adapter_version", row.get("adapter_version", ""))),
        "binary_sha256": str(getattr(entry, "binary_sha256", row.get("binary_sha256", ""))),
        "capabilities": sorted(str(value) for value in getattr(entry, "accepted_capabilities", ())),
        "tested_events": sorted(str(value) for value in getattr(entry, "tested_events", ())),
        "evidence_timestamp": str(getattr(entry, "evidence_timestamp", row.get("evidence_timestamp", ""))),
        "expires_at": expires_at,
        "statuses": statuses,
        "production_eligible": bool(production_eligible),
        "source_production_permitted": bool(source_permits),
        "source_registry": {"path": _relative(registry_path, repository_root), "sha256": registry_digest},
        "evidence_artifact": {
            "path": _relative(artifact_path, repository_root),
            "declared_sha256": str(row.get("report_sha256") or ""),
            "sha256": artifact_digest,
        },
    }
    return result


def build_manifest(
    repository_root: Path,
    as_of: date,
    *,
    registry_paths: dict[str, Path] | None = None,
) -> dict[str, Any]:
    repository_root = Path(repository_root).resolve()
    paths = registry_paths or {
        kind: repository_root / relative
        for kind, relative in REGISTRY_FILES.items()
    }
    diagnostics: list[dict[str, Any]] = []
    accepted_rows: list[dict[str, Any]] = []

    for kind in sorted(REGISTRY_FILES):
        registry_path = Path(paths[kind]).resolve()
        payload = _read_payload(registry_path)
        if payload is None:
            diagnostics.append({"registry": kind, "row_index": None, "status": "registry_invalid", "reason": "registry_missing_or_invalid_json"})
            raw_rows = []
        elif payload.get("schema_version") != REGISTRY_SCHEMA_VERSIONS[kind]:
            diagnostics.append({"registry": kind, "row_index": None, "status": "registry_invalid", "reason": "schema_version_mismatch"})
            raw_rows = []
        elif not isinstance(payload.get("entries"), list):
            diagnostics.append({"registry": kind, "row_index": None, "status": "registry_invalid", "reason": "entries_not_list"})
            raw_rows = []
        else:
            raw_rows = payload["entries"]
        try:
            entries = _load_authoritative_entries(kind, registry_path)
        except Exception as exc:  # loader failures are evidence, not silent omissions
            entries = ()
            diagnostics.append({"registry": kind, "row_index": None, "status": "registry_invalid", "reason": str(exc)})
        accepted: dict[tuple[str, str], list[Any]] = {}
        for entry in entries:
            accepted.setdefault(_entry_identity(kind, entry), []).append(entry)
        registry_root = registry_path.parents[2]
        registry_digest = _sha256(registry_path) if registry_path.is_file() else None
        for index, raw_row in enumerate(raw_rows):
            status, details = _raw_status(kind=kind, registry_root=registry_root, row=raw_row, accepted=accepted)
            if status != "accepted":
                diagnostics.append({"registry": kind, "row_index": index, "status": status, **details})
                continue
            assert isinstance(raw_row, dict)
            artifact_path = registry_root / str(raw_row["evidence_artifact"])
            entry = accepted[_identity(kind, raw_row)][0]
            accepted_rows.append(
                _normalize_entry(
                    kind=kind,
                    entry=entry,
                    row=raw_row,
                    registry_path=registry_path,
                    registry_digest=str(registry_digest),
                    artifact_path=artifact_path,
                    artifact_digest=_sha256(artifact_path),
                    as_of=as_of,
                    repository_root=repository_root,
                )
            )

    """Keep each accepted evidence row separate so capabilities never bleed across versions."""
    native_adapters = []
    for row in accepted_rows:
        row["provider_versions"] = [row["provider_version"]]
        row["evidence"] = [dict(row)]
        native_adapters.append(row)

    enterprise_targets = [
        {
            "target": target,
            "status": "planned_unverified",
            "implementation_evidenced": False,
            "tenant_acceptance_evidenced": False,
        }
        for target in ENTERPRISE_TARGETS
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "as_of": as_of.isoformat(),
        "scope": "bounded native adapter release-support inventory",
        "native_adapters": sorted(native_adapters, key=lambda row: (row["provider"], row["product"], row["adapter_version"])),
        "diagnostics": sorted(diagnostics, key=lambda row: (str(row["registry"]), str(row["row_index"]), row["status"])),
        "required_flags": _flag_defaults(),
        "enterprise_targets": enterprise_targets,
        "enterprise_targets_note": "Generic and Sentinel serialization helpers are not full SIEM delivery integrations; these targets remain planned until implementation and tenant acceptance evidence exists.",
    }


def render_json(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_markdown(manifest: dict[str, Any]) -> str:
    lines = [
        "# Release support matrix",
        "",
        f"As of **{manifest['as_of']}** · scope: {manifest['scope']}",
        "",
        "This matrix is repository evidence for the bounded native-adapter inventory. It is not coverage of all platform routes or a current-tenant acceptance claim.",
        "",
        "## Native adapter evidence",
        "",
        "| Provider | Product | Adapter | Provider versions | Capabilities | Statuses | Production eligible |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in manifest["native_adapters"]:
        lines.append(
            f"| {row['provider']} | {row['product']} | {row['adapter_version']} | {', '.join(row['provider_versions'])} | {', '.join(row['capabilities'])} | {', '.join(row['statuses'])} | {str(row['production_eligible']).lower()} |"
        )
        for evidence in row["evidence"]:
            lines.append(
                f"| ↳ evidence | `{evidence['provider_version']}` | artifact `{evidence['evidence_artifact']['path']}` | registry `{evidence['source_registry']['sha256']}` | artifact `{evidence['evidence_artifact']['sha256']}` | expires `{evidence['expires_at'] or 'missing'}` | {str(evidence['production_eligible']).lower()} |"
            )
    lines.extend(
        [
            "",
            "## Required flag defaults",
            "",
            "| Flag | Declared default |",
            "|---|---|",
        ]
    )
    lines.extend(f"| `{name}` | `{str(value).lower()}` |" for name, value in manifest["required_flags"].items())
    lines.extend(
        [
            "",
            "## Enterprise targets",
            "",
            "| Target | Status | Implementation evidenced | Tenant acceptance evidenced |",
            "|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| {row['target']} | {row['status']} | false | false |"
        for row in manifest["enterprise_targets"]
    )
    lines.extend(["", manifest["enterprise_targets_note"], "", "## Diagnostics", ""])
    if manifest["diagnostics"]:
        lines.extend(
            f"- `{item['registry']}` row `{item['row_index']}`: **{item['status']}** ({item.get('reason') or item.get('artifact') or 'see JSON'})"
            for item in manifest["diagnostics"]
        )
    else:
        lines.append("- None.")
    return "\n".join(lines) + "\n"


def write_outputs(manifest: dict[str, Any], json_path: Path, markdown_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(render_json(manifest), encoding="utf-8")
    markdown_path.write_text(render_markdown(manifest), encoding="utf-8")


def check_outputs(manifest: dict[str, Any], json_path: Path, markdown_path: Path) -> bool:
    expected_json = render_json(manifest)
    expected_markdown = render_markdown(manifest)
    return (
        json_path.is_file()
        and markdown_path.is_file()
        and json_path.read_text(encoding="utf-8") == expected_json
        and markdown_path.read_text(encoding="utf-8") == expected_markdown
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as-of", required=True, help="evaluation date in YYYY-MM-DD format")
    parser.add_argument("--output-json", type=Path, default=REPOSITORY_ROOT / "artifacts/platform-audit-2026-09-23/release-support-manifest.json")
    parser.add_argument("--output-markdown", type=Path, default=REPOSITORY_ROOT / "artifacts/platform-audit-2026-09-23/release-support-matrix.md")
    parser.add_argument("--check", action="store_true", help="fail if generated outputs differ")
    args = parser.parse_args(argv)
    try:
        as_of = date.fromisoformat(args.as_of)
    except ValueError as exc:
        parser.error(f"--as-of must be YYYY-MM-DD: {exc}")
    manifest = build_manifest(REPOSITORY_ROOT, as_of)
    if args.check:
        if check_outputs(manifest, args.output_json, args.output_markdown):
            return 0
        print("release support manifest drift detected", file=sys.stderr)
        return 1
    write_outputs(manifest, args.output_json, args.output_markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
