#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose.test.yml"
ARTIFACT_DIR="$ROOT_DIR/artifacts"
SUMMARY_FILE="$ARTIFACT_DIR/e2e_summary.json"
JUNIT_FILE="$ARTIFACT_DIR/e2e_pytest.xml"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$ARTIFACT_DIR"
rm -f "$SUMMARY_FILE" "$JUNIT_FILE"

echo "[test-e2e] booting docker test stack: db redis api worker celery-beat web"
docker compose -f "$COMPOSE_FILE" up -d db redis api worker celery-beat web

HEARTBEAT_RESTART_EPOCH="$(date +%s)"

heartbeat_is_newer_than() {
  local heartbeat_key="$1"
  local previous_epoch="$2"
  local raw_value
  raw_value="$(docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli --raw GET "$heartbeat_key" 2>/dev/null || true)"
  python3 - "$raw_value" "$previous_epoch" <<'PY'
import math
import sys
import time

try:
    value = float(sys.argv[1])
    previous = float(sys.argv[2])
except ValueError:
    raise SystemExit(1)

max_age = float(__import__("os").environ.get("CONTROL_PLANE_HEARTBEAT_MAX_AGE_SECONDS", "120"))
raise SystemExit(0 if math.isfinite(value) and value > previous and value <= time.time() and time.time() - value <= max_age else 1)
PY
}

echo "[test-e2e] waiting for postgres"
for i in $(seq 1 90); do
  if docker compose -f "$COMPOSE_FILE" exec -T db pg_isready -U postgres -d aicontrol_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 90 ]; then
    echo "[test-e2e] postgres did not become ready in time" >&2
    exit 1
  fi
done

echo "[test-e2e] waiting for redis"
for i in $(seq 1 90); do
  if docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
    break
  fi
  sleep 1
  if [ "$i" -eq 90 ]; then
    echo "[test-e2e] redis did not become ready in time" >&2
    exit 1
  fi
done

echo "[test-e2e] waiting for api health"
for i in $(seq 1 120); do
  if curl -fsS "http://localhost:8000/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 120 ]; then
    echo "[test-e2e] api did not become healthy in time" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=200 api >&2 || true
    exit 1
  fi
done

echo "[test-e2e] waiting for worker heartbeat"
for i in $(seq 1 120); do
  if heartbeat_is_newer_than control_plane:celery:worker_heartbeat "$HEARTBEAT_RESTART_EPOCH"; then
    break
  fi
  sleep 1
  if [ "$i" -eq 120 ]; then
    echo "[test-e2e] worker heartbeat did not appear in time" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=200 worker >&2 || true
    exit 1
  fi
done

echo "[test-e2e] waiting for beat heartbeat"
for i in $(seq 1 120); do
  if heartbeat_is_newer_than control_plane:celery:beat_heartbeat "$HEARTBEAT_RESTART_EPOCH"; then
    break
  fi
  sleep 1
  if [ "$i" -eq 120 ]; then
    echo "[test-e2e] beat heartbeat did not appear in time" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=200 celery-beat >&2 || true
    exit 1
  fi
done

echo "[test-e2e] waiting for web login route"
for i in $(seq 1 180); do
  status="$(curl -s -o /dev/null -w '%{http_code}' 'http://localhost:3000/login' || true)"
  if [ "$status" = "200" ] || [ "$status" = "307" ] || [ "$status" = "308" ]; then
    break
  fi
  sleep 1
  if [ "$i" -eq 180 ]; then
    echo "[test-e2e] web did not become ready in time (status=$status)" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=200 web >&2 || true
    exit 1
  fi
done

echo "[test-e2e] running deterministic e2e tests"
set +e
docker compose -f "$COMPOSE_FILE" exec -T api bash -lc "
  cd /workspace/apps/api && \
  TEST_PROFILE=integration PYTHONPATH=. E2E_SUMMARY_PATH=/workspace/artifacts/e2e_summary.json \
  pytest -q -m integration tests/integration/test_control_plane_e2e_harness.py \
  --junitxml=/workspace/artifacts/e2e_pytest.xml
"
PYTEST_EXIT_CODE=$?
set -e

echo "[test-e2e] generating summary report"
python3 "$ROOT_DIR/infra/scripts/e2e_summary_report.py" \
  --summary "$SUMMARY_FILE" \
  --junit "$JUNIT_FILE" \
  --pytest-exit-code "$PYTEST_EXIT_CODE"

if [ "$PYTEST_EXIT_CODE" -ne 0 ]; then
  exit "$PYTEST_EXIT_CODE"
fi

echo "[test-e2e] completed successfully"
