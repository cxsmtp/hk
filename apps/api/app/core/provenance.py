from __future__ import annotations

import hashlib
import json
import re
from typing import Annotated, Any

from pydantic import AfterValidator, Field


OPAQUE_PROVENANCE_ID_PATTERN_TEXT = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
OPAQUE_PROVENANCE_ID_PATTERN = re.compile(OPAQUE_PROVENANCE_ID_PATTERN_TEXT)
UNKNOWN_PROVENANCE_PREFIX = "unknown:"
UNKNOWN_PROVENANCE_SENTINEL_PATTERN = re.compile(
    r"^unknown:[0-9A-Fa-f]{56}$"
)


def is_unknown_provenance_sentinel(value: Any) -> bool:
    return (
        isinstance(value, str)
        and UNKNOWN_PROVENANCE_SENTINEL_PATTERN.fullmatch(value) is not None
    )


def _has_reserved_unknown_prefix(value: Any) -> bool:
    return isinstance(value, str) and value.lower().startswith(
        UNKNOWN_PROVENANCE_PREFIX
    )


def validate_authoritative_provenance_id(
    value: Any,
    *,
    field_name: str,
) -> str:
    if (
        not isinstance(value, str)
        or _has_reserved_unknown_prefix(value)
        or not OPAQUE_PROVENANCE_ID_PATTERN.fullmatch(value)
    ):
        raise ValueError(f"{field_name} must be a safe opaque identifier")
    return value


def _validate_provenance_model_value(value: str) -> str:
    return validate_authoritative_provenance_id(
        value,
        field_name="provenance identifier",
    )


OpaqueProvenanceId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=OPAQUE_PROVENANCE_ID_PATTERN_TEXT,
    ),
    AfterValidator(_validate_provenance_model_value),
]


def is_authoritative_provenance_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and not _has_reserved_unknown_prefix(value)
        and OPAQUE_PROVENANCE_ID_PATTERN.fullmatch(value) is not None
    )


def _canonical_untrusted_value(value: Any) -> bytes:
    type_name = f"{type(value).__module__}.{type(value).__qualname__}"
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        serialized = repr(value)
    return f"{type_name}\0{serialized}".encode("utf-8", errors="backslashreplace")


def _domain_separated_digest(
    *,
    tenant_id: str,
    domain: str,
    field_name: str,
    value: Any,
) -> str:
    digest = hashlib.sha256()
    for component in (
        b"hawk-runtime-provenance-v1",
        str(tenant_id).encode("utf-8", errors="backslashreplace"),
        str(domain).encode("utf-8", errors="backslashreplace"),
        str(field_name).encode("ascii"),
        _canonical_untrusted_value(value),
    ):
        digest.update(len(component).to_bytes(8, "big"))
        digest.update(component)
    return digest.hexdigest()


def project_runtime_provenance_id(
    value: Any,
    *,
    tenant_id: str,
    domain: str,
    field_name: str,
) -> dict[str, Any]:
    if value is None:
        return {
            "status": "missing",
            "projection": None,
            "authoritative": False,
        }
    if is_unknown_provenance_sentinel(value):
        return {
            "status": "unknown",
            "projection": value,
            "authoritative": False,
        }
    if is_authoritative_provenance_id(value):
        return {
            "status": "valid",
            "projection": value,
            "authoritative": True,
        }
    digest = _domain_separated_digest(
        tenant_id=tenant_id,
        domain=domain,
        field_name=field_name,
        value=value,
    )
    return {
        "status": "invalid",
        "projection": f"unknown:{digest[:56]}",
        "authoritative": False,
    }
