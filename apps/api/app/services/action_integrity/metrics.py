"""Tenant-scoped metrics derived from durable authority records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping


def count_by_state(records: Iterable[Mapping[str, object]], *, tenant_id: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for record in records:
        if record.get("tenant_id") == tenant_id:
            state = str(record.get("state", "UNKNOWN"))
            result[state] = result.get(state, 0) + 1
    return result
