"""Explicit, one-shot HMAIR metadata snapshot for an enrolled lab endpoint.

The module only projects the existing read-only metadata scanner output. It
does not widen local collection, persist a local copy, or start automatically
with the endpoint agent.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import re
from typing import Any
from uuid import UUID, uuid4

from .config import AgentConfig
from .hawk_client import HawkClient
from .metadata_scanner import SCHEMA_VERSION, collect_platform_endpoint_metadata


_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+ -]{0,127}$")
_SAFE_SNAPSHOT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SEMANTIC_VERSION_RE = re.compile(
    r"^\d{1,3}(?:\.\d{1,5}){1,3}(?:[-+][A-Za-z0-9.-]{1,32})?$"
)
_PHONE_LIKE_DOTTED_VALUE_RE = re.compile(
    r"^(?:\d{1,3}\.)?\d{2,3}\.\d{3}\.\d{4}$"
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?:\bsk-[A-Za-z0-9_-]{4,}|\bbearer\s+|\bapi[_ -]?key\b|\bpassword\b)",
    re.IGNORECASE,
)
_PRIVACY_KEYS = (
    "raw_file_contents_collected",
    "prompts_collected",
    "browser_history_collected",
    "cookies_collected",
    "secrets_or_tokens_collected",
    "account_identifiers_collected",
    "persistent_state_written",
)


class HMAIRSnapshotError(ValueError):
    """The local scanner output cannot be safely submitted to HMAIR."""


def _safe_text(value: object, *, field: str, max_length: int = 128) -> str:
    if type(value) is not str:
        raise HMAIRSnapshotError(f"invalid {field}")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > max_length
        or _SAFE_TEXT.fullmatch(normalized) is None
        or _SENSITIVE_VALUE_RE.search(normalized) is not None
    ):
        raise HMAIRSnapshotError(f"invalid {field}")
    return normalized


def _safe_version(value: object, *, field: str, max_length: int = 64) -> str:
    """Keep a bounded semantic version; redact ambiguous numeric strings."""

    normalized = _safe_text(value, field=field, max_length=max_length)
    if _PHONE_LIKE_DOTTED_VALUE_RE.fullmatch(normalized):
        return "unknown"
    return normalized if _SEMANTIC_VERSION_RE.fullmatch(normalized) else "unknown"


def _safe_list(value: object, *, field: str, max_items: int) -> list[object]:
    if not isinstance(value, list) or len(value) > max_items:
        raise HMAIRSnapshotError(f"invalid {field}")
    return value


def _safe_product(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise HMAIRSnapshotError("invalid product")
    account = value.get("account")
    if not isinstance(account, Mapping):
        raise HMAIRSnapshotError("invalid product account")
    account_status = account.get("status")
    identifiers_collected = account.get("identifiers_collected")
    if account_status != "unknown" or identifiers_collected is not False:
        raise HMAIRSnapshotError("unsafe product account metadata")
    presence = value.get("presence")
    approval_status = value.get("approval_status")
    if presence not in {"present", "unknown"} or approval_status != "unknown":
        raise HMAIRSnapshotError("invalid product state")
    evidence_types = _safe_list(
        value.get("evidence_types"), field="product evidence types", max_items=16
    )
    return {
        "id": _safe_text(value.get("id"), field="product id", max_length=64),
        "name": _safe_text(value.get("name"), field="product name"),
        "provider": _safe_text(
            value.get("provider"), field="product provider", max_length=64
        ),
        "category": _safe_text(
            value.get("category"), field="product category", max_length=64
        ),
        "presence": presence,
        "version": _safe_version(
            value.get("version"), field="product version", max_length=64
        ),
        "evidence_types": [
            _safe_text(item, field="product evidence type", max_length=64)
            for item in evidence_types
        ],
        "approval_status": "unknown",
        "account": {
            "status": "unknown",
            "identifiers_collected": False,
        },
    }


def _safe_extension(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise HMAIRSnapshotError("invalid extension")
    category = value.get("category")
    presence = value.get("presence")
    if category not in {"ide", "browser"} or presence not in {"present", "unknown"}:
        raise HMAIRSnapshotError("invalid extension state")
    if value.get("approval_status") != "unknown":
        raise HMAIRSnapshotError("invalid extension approval state")
    return {
        "id": _safe_text(value.get("id"), field="extension id", max_length=64),
        "name": _safe_text(value.get("name"), field="extension name"),
        "provider": _safe_text(
            value.get("provider"), field="extension provider", max_length=64
        ),
        "host": _safe_text(value.get("host"), field="extension host", max_length=64),
        "category": category,
        "presence": presence,
        "version": _safe_version(
            value.get("version"), field="extension version", max_length=64
        ),
        "approval_status": "unknown",
    }


def _safe_extensions(values: list[object]) -> list[dict[str, object]]:
    """Collapse duplicate host/extension identities into one stable fact."""

    by_identity: dict[tuple[str, str], dict[str, object]] = {}
    for raw in values:
        candidate = _safe_extension(raw)
        identity = (str(candidate["host"]), str(candidate["id"]))
        existing = by_identity.get(identity)
        if existing is None:
            by_identity[identity] = candidate
            continue
        if existing == candidate:
            continue
        selected = min(
            (existing, candidate),
            key=lambda item: tuple(
                str(item[field])
                for field in ("name", "provider", "category", "presence", "version")
            ),
        )
        by_identity[identity] = {**selected, "version": "unknown"}
    return [by_identity[key] for key in sorted(by_identity)]


def _optional_metadata(value: object, *, field: str, max_length: int) -> str | None:
    if value is None:
        return None
    return _safe_text(value, field=field, max_length=max_length)


def _safe_configuration(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise HMAIRSnapshotError("invalid configuration")
    if value.get("kind") != "mcp_agent_configuration" or value.get("status") != "present":
        raise HMAIRSnapshotError("invalid configuration state")
    metadata = value.get("metadata")
    if not isinstance(metadata, Mapping):
        raise HMAIRSnapshotError("invalid configuration metadata")
    mcp_names = _safe_list(
        metadata.get("mcp_server_names", []),
        field="mcp server names",
        max_items=32,
    )
    safe_metadata: dict[str, object] = {
        "mcp_server_names": [
            _safe_text(item, field="mcp server name") for item in mcp_names
        ]
    }
    for field, max_length in (
        ("model", 128),
        ("model_provider", 64),
        ("approval_policy", 64),
        ("sandbox_mode", 64),
    ):
        safe_value = _optional_metadata(
            metadata.get(field), field=field, max_length=max_length
        )
        if safe_value is not None:
            safe_metadata[field] = safe_value
    return {
        "product_id": _safe_text(
            value.get("product_id"), field="configuration product id", max_length=64
        ),
        "kind": "mcp_agent_configuration",
        "source": _safe_text(
            value.get("source"), field="configuration source", max_length=64
        ),
        "status": "present",
        "metadata": safe_metadata,
    }


def _safe_error(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise HMAIRSnapshotError("invalid scanner error")
    return {
        "source": _safe_text(value.get("source"), field="scanner error source", max_length=64),
        "code": _safe_text(value.get("code"), field="scanner error code", max_length=64),
    }


def build_hmair_snapshot_payload(
    report: Mapping[str, object],
    *,
    snapshot_id: str | None = None,
    collected_at: datetime | None = None,
    inventory_assignment_id: str | None = None,
) -> dict[str, object]:
    """Copy only allowlisted metadata from the local scanner report."""

    if not isinstance(report, Mapping):
        raise HMAIRSnapshotError("invalid metadata scanner report")
    if report.get("schema_version") != SCHEMA_VERSION:
        raise HMAIRSnapshotError("unexpected metadata scanner schema")
    status = report.get("status")
    if status not in {"completed", "error"}:
        raise HMAIRSnapshotError("invalid metadata scanner status")
    if report.get("collection_mode") != "one_shot_read_only" or report.get("network_used") is not False:
        raise HMAIRSnapshotError("unsafe metadata scanner mode")
    privacy = report.get("privacy")
    if not isinstance(privacy, Mapping) or any(
        privacy.get(key) is not False for key in _PRIVACY_KEYS
    ):
        raise HMAIRSnapshotError("metadata scanner privacy declaration is invalid")
    material_snapshot_id = snapshot_id or str(uuid4())
    if _SAFE_SNAPSHOT_ID.fullmatch(material_snapshot_id) is None:
        raise HMAIRSnapshotError("invalid snapshot id")
    observed_at = collected_at or datetime.now(timezone.utc)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise HMAIRSnapshotError("snapshot timestamp must include a timezone")
    products = _safe_list(report.get("products"), field="products", max_items=32)
    extensions = _safe_list(report.get("extensions"), field="extensions", max_items=64)
    configurations = _safe_list(
        report.get("configurations"), field="configurations", max_items=32
    )
    errors = _safe_list(report.get("errors"), field="errors", max_items=64)
    payload: dict[str, object] = {
        "snapshot_id": material_snapshot_id,
        "schema_version": SCHEMA_VERSION,
        "collected_at": observed_at.astimezone(timezone.utc).isoformat(),
        "collection_mode": "one_shot_read_only",
        "status": status,
        "network_used": False,
        "products": [_safe_product(item) for item in products],
        "extensions": _safe_extensions(extensions),
        "configurations": [_safe_configuration(item) for item in configurations],
        "errors": [_safe_error(item) for item in errors],
        "privacy": {key: False for key in _PRIVACY_KEYS},
    }
    if inventory_assignment_id is not None:
        if type(inventory_assignment_id) is not str:
            raise HMAIRSnapshotError("invalid inventory assignment")
        try:
            payload["inventory_assignment_id"] = str(UUID(inventory_assignment_id))
        except (ValueError, AttributeError) as exc:
            raise HMAIRSnapshotError("invalid inventory assignment") from exc
    return payload


def run_hmair_discovery_snapshot(
    config: AgentConfig,
    *,
    client: Any | None = None,
    scanner: Callable[[], Mapping[str, object]] = collect_platform_endpoint_metadata,
    snapshot_id: str | None = None,
    collected_at: datetime | None = None,
    inventory_assignment_id: str | None = None,
) -> dict[str, object]:
    """Run exactly one local scanner invocation and return a bounded receipt."""

    payload = build_hmair_snapshot_payload(
        scanner(),
        snapshot_id=snapshot_id,
        collected_at=collected_at,
        inventory_assignment_id=inventory_assignment_id,
    )
    response = (client or HawkClient(config)).report_hmair_snapshot(payload)
    if not isinstance(response, Mapping):
        raise HMAIRSnapshotError("invalid HMAIR snapshot receipt")
    required = (
        "scan_id",
        "status",
        "observations_count",
        "endpoint_denominator",
        "limitations",
    )
    if any(key not in response for key in required):
        raise HMAIRSnapshotError("invalid HMAIR snapshot receipt")
    scan_id = response["scan_id"]
    status = response["status"]
    observations_count = response["observations_count"]
    endpoint_denominator = response["endpoint_denominator"]
    limitations = response["limitations"]
    if (
        type(scan_id) is not str
        or not scan_id.strip()
        or status not in {"complete", "completed"}
        or type(observations_count) is not int
        or observations_count < 0
        or endpoint_denominator != 1
        or not isinstance(limitations, list)
        or not all(isinstance(item, str) and item for item in limitations)
    ):
        raise HMAIRSnapshotError("invalid HMAIR snapshot receipt")
    return {
        "scan_id": scan_id,
        "status": status,
        "observations_count": observations_count,
        "endpoint_denominator": 1,
        "limitations": list(limitations),
    }


__all__ = [
    "HMAIRSnapshotError",
    "build_hmair_snapshot_payload",
    "run_hmair_discovery_snapshot",
]
