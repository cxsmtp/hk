#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose.test.yml"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[ci-integration] booting test dependencies"
docker compose -f "$COMPOSE_FILE" up -d db redis

echo "[ci-integration] waiting for postgres"
for i in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" exec -T db pg_isready -U postgres -d aicontrol_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 60 ]; then
    echo "[ci-integration] postgres did not become ready in time" >&2
    exit 1
  fi
done

echo "[ci-integration] waiting for redis"
for i in $(seq 1 60); do
  if docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
    break
  fi
  sleep 1
  if [ "$i" -eq 60 ]; then
    echo "[ci-integration] redis did not become ready in time" >&2
    exit 1
  fi
done

echo "[ci-integration] running migrate + seed + integration/fail-secure suites"
docker compose -f "$COMPOSE_FILE" run --rm api bash -lc "
  cd /workspace/apps/api && \
  TEST_PROFILE=integration PYTHONPATH=. alembic -c app/db/migrations/alembic.ini upgrade head && \
  TEST_PROFILE=integration PYTHONPATH=. python /workspace/infra/scripts/seed.py && \
  TEST_PROFILE=integration PYTHONPATH=. pytest -q -m integration tests/integration && \
  TEST_PROFILE=integration PYTHONPATH=. pytest -q \
    tests/test_health.py \
    tests/test_control_plane_health_dependency.py \
    tests/test_fail_secure_mode.py \
    tests/test_fail_secure_critical_routes.py
"

echo "[ci-integration] completed successfully"
