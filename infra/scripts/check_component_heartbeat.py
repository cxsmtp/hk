from __future__ import annotations

import argparse

from app.core.config import settings
from app.services.control_plane_health_service import (
    CELERY_BEAT_COMPONENT_KEY,
    CELERY_BEAT_HEARTBEAT_KEY,
    CELERY_WORKER_COMPONENT_KEY,
    CELERY_WORKER_HEARTBEAT_KEY,
    evaluate_component_runtime_health,
)


COMPONENTS = {
    "worker": (CELERY_WORKER_HEARTBEAT_KEY, CELERY_WORKER_COMPONENT_KEY),
    "celery_beat": (CELERY_BEAT_HEARTBEAT_KEY, CELERY_BEAT_COMPONENT_KEY),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check one Hawk runtime component.")
    parser.add_argument("component_type", choices=sorted(COMPONENTS))
    arguments = parser.parse_args()
    if settings.component_type != arguments.component_type:
        return 1
    heartbeat_key, component_key = COMPONENTS[arguments.component_type]
    result = evaluate_component_runtime_health(
        heartbeat_key=heartbeat_key,
        component_key=component_key,
        component_type=arguments.component_type,
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
