from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_production_artifacts_use_ssd_backed_docker_volume_not_host_bind() -> None:
    production = yaml.safe_load(
        (ROOT / "infra/legacy/docker-compose.production.yml").read_text(encoding="utf-8")
    )

    assert production["volumes"]["hawk_artifacts"]["name"] == (
        "${HAWK_ARTIFACT_VOLUME_NAME:-hawk_production_artifacts}"
    )
    for service in ("api", "worker", "celery-beat"):
        assert "hawk_artifacts:/artifacts" in production["services"][service]["volumes"]
