#!/usr/bin/env bash
set -euo pipefail

HAWK_PRODUCTION_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAWK_PRODUCTION_REPO_ROOT="$(cd "$HAWK_PRODUCTION_SCRIPT_DIR/../.." && pwd)"

export HAWK_ENV_FILE="${HAWK_ENV_FILE:-$HAWK_PRODUCTION_REPO_ROOT/.env.production}"
export HAWK_APP_ENV_FILE="${HAWK_APP_ENV_FILE:-../.env.production}"
export HAWK_PROJECT_NAME="${HAWK_PROJECT_NAME:-hawk-production}"
export HAWK_POSTGRES_VOLUME="${HAWK_POSTGRES_VOLUME:-hawk_production_postgres_data}"
export HAWK_POSTGRES_VOLUME_NAME="${HAWK_POSTGRES_VOLUME_NAME:-hawk_production_postgres_data}"
export HAWK_REDIS_VOLUME_NAME="${HAWK_REDIS_VOLUME_NAME:-hawk_production_redis_data}"
export HAWK_RUNTIME_VOLUME_NAME="${HAWK_RUNTIME_VOLUME_NAME:-hawk_production_runtime_state}"
export HAWK_COMPOSE_FILES="${HAWK_COMPOSE_FILES:-$HAWK_PRODUCTION_REPO_ROOT/infra/docker-compose.demo.yml:$HAWK_PRODUCTION_REPO_ROOT/infra/docker-compose.production.yml}"

exec "$HAWK_PRODUCTION_SCRIPT_DIR/hawk_demo_stack.sh" "$@"
