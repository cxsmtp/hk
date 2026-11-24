#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/infra/docker-compose.yml"

export POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-15432}"

echo "[startup] bringing up deterministic platform stack"
docker compose -f "$COMPOSE_FILE" up -d --build db redis migrate-seed api worker celery-beat web

echo "[startup] waiting for API health"
for i in $(seq 1 120); do
  if curl -fsS "http://localhost:8000/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 120 ]; then
    echo "[startup] API did not become healthy in time" >&2
    exit 1
  fi
done

echo "[startup] waiting for Web health"
for i in $(seq 1 120); do
  if curl -fsS "http://localhost:3000" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" -eq 120 ]; then
    echo "[startup] Web did not become healthy in time" >&2
    exit 1
  fi
done

echo "[startup] stack is healthy"
echo "  API: http://localhost:8000/health"
echo "  Web: http://localhost:3000"
