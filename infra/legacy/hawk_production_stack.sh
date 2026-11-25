#!/usr/bin/env bash
# Legacy: the production stack layered on the demo compose file (infra/docker-compose.demo.yml +
# infra/legacy/docker-compose.production.yml). Superseded by deploy/compose.yaml and deploy/install.sh
# (deploy/README.md); kept for installations that still run it.
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
export HAWK_COMPOSE_FILES="${HAWK_COMPOSE_FILES:-$HAWK_PRODUCTION_REPO_ROOT/infra/docker-compose.demo.yml:$HAWK_PRODUCTION_REPO_ROOT/infra/legacy/docker-compose.production.yml}"

exec "$HAWK_PRODUCTION_REPO_ROOT/infra/scripts/hawk_demo_stack.sh" "$@"
