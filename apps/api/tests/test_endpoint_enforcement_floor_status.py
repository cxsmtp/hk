from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services.endpoint_agent_service import (
    get_endpoint_floor_status,
    project_endpoint_floor_status,
)


NOW = datetime(2026, 8, 12, 10, 0, tzinfo=UTC)


def _node(endpoint_id: str, floor: dict, *, seconds_ago: int = 0):
    return SimpleNamespace(
        id=f"evidence:{endpoint_id}:{seconds_ago}",
        created_at=NOW - timedelta(seconds=seconds_ago),
        payload={
            "endpoint_id": endpoint_id,
            "hostname": f"{endpoint_id}.example",
            "os_type": "darwin",
            "posture": {"endpoint_enforcement_floor": floor},
        },
    )


def _claim(*, status: str = "inline", evidence: bool = True) -> dict:
    return {
        "status": status,
        "verification": "verified",
        "health": "healthy",
        "evidence_refs": ["runtime:receipt"] if evidence else [],
    }


def _local_policy(*, evidence: bool = True, signature_verified: bool = True) -> dict:
    return {
        "status": "active",
        "freshness": "fresh",
        "policy_version": "policy-v7",
        "signature_verified": signature_verified,
        "evidence_refs": ["runtime:policy-receipt"] if evidence else [],
    }


def test_missing_runtime_evidence_remains_unknown_and_not_covered() -> None:
    claimed = {
        "minimum_floor_satisfied": True,
        "controls": {
            "file_control": _claim(evidence=False),
            "process_control": _claim(evidence=False),
            "network_control": _claim(evidence=False),
            "semantic_proxy": _claim(status="inline", evidence=False),
        },
        "local_policy": _local_policy(),
        "blind_spots": [],
        "reason_codes": [],
    }

    summary = project_endpoint_floor_status([_node("endpoint-1", claimed)], now=NOW)

    endpoint = summary["endpoints"][0]
    assert endpoint["minimum_floor_satisfied"] is False
    assert endpoint["controls"]["file_control"]["status"] == "unknown"
    assert "runtime_evidence_missing:file_control" in endpoint["reason_codes"]
    assert summary["summary"]["protected"] == 0
    assert summary["summary"]["unknown"] == 1


def test_latest_heartbeat_wins_and_verified_floor_requires_all_three_primitives() -> None:
    older = {
        "controls": {
            "file_control": _claim(),
            "process_control": _claim(),
            "network_control": _claim(status="not_covered"),
            "semantic_proxy": _claim(status="unavailable"),
        },
        "local_policy": _local_policy(),
        "blind_spots": ["network_filter_missing"],
        "reason_codes": ["CONTROL_REQUIREMENT_UNSATISFIED:network"],
    }
    latest = {
        "controls": {
            "file_control": _claim(),
            "process_control": _claim(),
            "network_control": _claim(),
            "semantic_proxy": {
                "status": "unavailable",
                "verification": "unverified",
                "health": "unknown",
                "evidence_refs": [],
            },
        },
        "local_policy": _local_policy(),
        "blind_spots": ["http_semantics_unavailable"],
        "reason_codes": [],
    }

    summary = project_endpoint_floor_status(
        [_node("endpoint-1", older, seconds_ago=30), _node("endpoint-1", latest)],
        now=NOW,
    )

    endpoint = summary["endpoints"][0]
    assert endpoint["minimum_floor_satisfied"] is True
    assert endpoint["semantic_control_available"] is False
    assert endpoint["local_policy"]["signature_verified"] is True
    assert endpoint["local_policy"]["policy_version"] == "policy-v7"
    assert endpoint["blind_spots"] == ["http_semantics_unavailable"]
    assert summary["summary"]["protected"] == 1


def test_stale_heartbeat_drops_to_unknown_without_inventing_current_health() -> None:
    floor = {
        "controls": {
            "file_control": _claim(),
            "process_control": _claim(),
            "network_control": _claim(),
            "semantic_proxy": _claim(),
        },
        "local_policy": _local_policy(),
        "blind_spots": [],
        "reason_codes": [],
    }

    summary = project_endpoint_floor_status(
        [_node("endpoint-1", floor, seconds_ago=700)],
        now=NOW,
        heartbeat_ttl_seconds=300,
    )

    endpoint = summary["endpoints"][0]
    assert endpoint["minimum_floor_satisfied"] is False
    assert endpoint["health"] == "stale"
    assert endpoint["controls"]["network_control"]["status"] == "unknown"
    assert endpoint["local_policy"]["freshness"] == "stale"


def test_unsigned_or_unproved_local_policy_prevents_minimum_floor() -> None:
    floor = {
        "controls": {
            "file_control": _claim(),
            "process_control": _claim(),
            "network_control": _claim(),
            "semantic_proxy": _claim(status="unavailable"),
        },
        "local_policy": _local_policy(evidence=False, signature_verified=False),
        "blind_spots": [],
        "reason_codes": [],
    }

    summary = project_endpoint_floor_status([_node("endpoint-1", floor)], now=NOW)

    endpoint = summary["endpoints"][0]
    assert endpoint["minimum_floor_satisfied"] is False
    assert endpoint["local_policy"]["status"] == "unknown"
    assert "runtime_evidence_missing:local_policy" in endpoint["reason_codes"]


def test_tenant_query_is_bounded_and_projects_only_heartbeat_nodes() -> None:
    floor = {
        "controls": {
            "file_control": _claim(),
            "process_control": _claim(),
            "network_control": _claim(),
            "semantic_proxy": _claim(status="unavailable"),
        },
        "local_policy": _local_policy(),
        "blind_spots": [],
        "reason_codes": [],
    }
    db = MagicMock()
    db.scalars.return_value.all.return_value = [_node("endpoint-1", floor)]

    summary = get_endpoint_floor_status(db, tenant_id="tenant-1", now=NOW)

    assert summary["summary"]["protected"] == 1
    statement = db.scalars.call_args.args[0]
    assert "endpoint_agent_heartbeat" in str(statement.compile(compile_kwargs={"literal_binds": True}))
    assert "tenant-1" in str(statement.compile(compile_kwargs={"literal_binds": True}))
