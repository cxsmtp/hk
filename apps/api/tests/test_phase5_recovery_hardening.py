from __future__ import annotations

from pathlib import Path

import pytest

from app.services import control_plane_health_service


class _RedisValue:
    def __init__(self, value: str | None) -> None:
        self.value = value

    def get(self, key: str) -> str | None:
        return self.value


@pytest.mark.parametrize(
    ("raw_value", "expected_status"),
    [
        (None, "stale"),
        ("not-a-timestamp", "stale"),
        ("100.0", "stale"),
        ("301.0", "stale"),
        ("299.0", "ok"),
    ],
)
def test_heartbeat_rejects_missing_malformed_stale_and_future_values(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str | None,
    expected_status: str,
) -> None:
    monkeypatch.setattr(control_plane_health_service.time, "time", lambda: 300.0)
    monkeypatch.setattr(
        control_plane_health_service.settings,
        "control_plane_heartbeat_max_age_seconds",
        2,
    )

    result = control_plane_health_service._check_celery_heartbeat(
        redis_client=_RedisValue(raw_value),
        key="heartbeat",
        actor="worker",
        strict_mode=True,
    )

    assert result.status == expected_status
    assert result.ok is (expected_status == "ok")


def test_compose_and_e2e_require_a_new_valid_timestamp_after_restart() -> None:
    root = Path(__file__).resolve().parents[3]
    compose = (root / "infra/docker-compose.demo.yml").read_text()
    harness = (root / "infra/scripts/run_e2e_harness.sh").read_text()

    assert "heartbeat_is_fresh" in compose
    assert "heartbeat_is_newer_than" in harness


def test_buildx_verifier_keeps_index_platform_attestation_and_config_distinct() -> None:
    root = Path(__file__).resolve().parents[3]
    plan = (root / "docs/PHASE5_SOL_APPROVED_BUILD_PLAN.md").read_text()

    assert 'history_ref="${build_ref##*/}"' in plan
    assert 'docker buildx history inspect "$history_ref" --format json' in plan
    assert "loaded_repo_digests" in plan
    assert "containerimage_digest" in plan
    assert "named = [value for value in repo_digests if re.fullmatch" in plan
    assert "assert named == [f\"hawk-api-demo@{index_digest}\"]" in plan


def test_restart_barrier_checks_timestamp_order_and_configured_freshness() -> None:
    root = Path(__file__).resolve().parents[3]
    harness = (root / "infra/scripts/run_e2e_harness.sh").read_text()
    compose = (root / "infra/docker-compose.demo.yml").read_text()

    assert "value > previous" in harness
    assert "time.time() - value <= max_age" in harness
    assert "CONTROL_PLANE_HEARTBEAT_MAX_AGE_SECONDS" in harness
    assert "CONTROL_PLANE_HEARTBEAT_MAX_AGE_SECONDS" in compose
