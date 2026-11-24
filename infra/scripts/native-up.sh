#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/native-demo-env.sh"

REPO_ROOT="$(native_demo_repo_root)"
native_demo_load_env "$REPO_ROOT"

mkdir -p "$NATIVE_LOG_DIR" "$NATIVE_PID_DIR"

PG_ISREADY="$(native_demo_resolve_binary pg_isready "$NATIVE_POSTGRES_BIN" || true)"
PSQL="$(native_demo_resolve_binary psql "$NATIVE_POSTGRES_BIN" || true)"
CREATEDB="$(native_demo_resolve_binary createdb "$NATIVE_POSTGRES_BIN" || true)"
REDIS_CLI="$(native_demo_resolve_binary redis-cli "$NATIVE_REDIS_BIN" || true)"

missing=()
for cmd in curl npm node; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done
if [[ "${NATIVE_DEMO_USE_DOCKER_DATA_SERVICES:-false}" != "true" ]]; then
  [[ -n "$PG_ISREADY" ]] || missing+=("pg_isready")
  [[ -n "$PSQL" ]] || missing+=("psql")
  [[ -n "$CREATEDB" ]] || missing+=("createdb")
  [[ -n "$REDIS_CLI" ]] || missing+=("redis-cli")
fi
if ! command -v "$NATIVE_PYTHON" >/dev/null 2>&1; then
  missing+=("$NATIVE_PYTHON")
fi
if (( ${#missing[@]} > 0 )); then
  native_demo_print_missing "${missing[@]}"
fi

native_demo_check_app_port_available_or_owned 3443 "$NATIVE_PID_DIR/gateway.pid"
native_demo_check_app_port_available_or_owned 8000 "$NATIVE_PID_DIR/api.pid"
native_demo_check_app_port_available_or_owned 3000 "$NATIVE_PID_DIR/web.pid"

echo "Checking host PostgreSQL and Redis..."
echo "Native data services:"
echo "  PostgreSQL: $NATIVE_POSTGRES_HOST:$NATIVE_POSTGRES_PORT/$NATIVE_POSTGRES_DB as $NATIVE_POSTGRES_USER"
echo "  Redis:      $NATIVE_REDIS_HOST:$NATIVE_REDIS_PORT/$NATIVE_REDIS_DB"
echo "  API URL:    $API_BASE_URL"
echo "  Web URL:    $WEB_ORIGIN"
if [[ "$DATABASE_URL" == *"@db:"* || "$DATABASE_URL" == *"//db:"* || "$REDIS_URL" == *"//redis:"* ]]; then
  echo "Refusing to start native demo: Docker database settings are still present in the effective environment." >&2
  echo "  DATABASE_URL=$DATABASE_URL" >&2
  echo "  REDIS_URL=$REDIS_URL" >&2
  exit 1
fi
if [[ "${NATIVE_DEMO_USE_DOCKER_DATA_SERVICES:-false}" == "true" ]]; then
  echo "Using Docker only for PostgreSQL/Redis data services."
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker CLI is required for hybrid data-services mode." >&2
    exit 1
  fi
  docker compose -f "$REPO_ROOT/infra/docker-compose.yml" up -d db redis
  sleep 3
else
  if ! PGPASSWORD="$NATIVE_POSTGRES_PASSWORD" "$PG_ISREADY" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" >/dev/null 2>&1; then
  echo "PostgreSQL is not ready at $NATIVE_POSTGRES_HOST:$NATIVE_POSTGRES_PORT for user $NATIVE_POSTGRES_USER." >&2
  echo "Start a user-owned local database with: infra/scripts/native-postgres-user.sh" >&2
  echo "If your local user/password differs, copy infra/local-native.env.example to .env.local-native and edit it." >&2
  exit 1
  fi

  if ! "$REDIS_CLI" -h "$NATIVE_REDIS_HOST" -p "$NATIVE_REDIS_PORT" ping >/dev/null 2>&1; then
  echo "Redis is not ready at $NATIVE_REDIS_HOST:$NATIVE_REDIS_PORT." >&2
  echo "Start a user-owned local Redis with: infra/scripts/native-redis-user.sh" >&2
  exit 1
  fi
fi

if [[ "${NATIVE_DEMO_USE_DOCKER_DATA_SERVICES:-false}" != "true" ]] && ! PGPASSWORD="$NATIVE_POSTGRES_PASSWORD" "$PSQL" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" -d "$NATIVE_POSTGRES_DB" -c "select 1" >/dev/null 2>&1; then
  echo "Database $NATIVE_POSTGRES_DB does not exist or is not reachable; attempting to create it..."
  PGPASSWORD="$NATIVE_POSTGRES_PASSWORD" "$CREATEDB" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" "$NATIVE_POSTGRES_DB"
fi

if [[ ! -d "$REPO_ROOT/apps/web/node_modules" ]]; then
  echo "Web dependencies are missing. Run this once:" >&2
  echo "  cd \"$REPO_ROOT/apps/web\" && npm install" >&2
  exit 1
fi

echo "Applying database migrations and seed data..."
"$NATIVE_PYTHON" "$REPO_ROOT/infra/scripts/run_migrations.py"
"$NATIVE_PYTHON" "$REPO_ROOT/infra/scripts/seed.py"

start_process() {
  local name="$1"
  local component_type="$2"
  local working_dir="$3"
  local pid_file="$NATIVE_PID_DIR/$name.pid"
  local log_file="$NATIVE_LOG_DIR/$name.log"
  shift 3

  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" >/dev/null 2>&1; then
      echo "$name already running (pid $old_pid)"
      return 0
    fi
  fi

  echo "Starting $name..."
  (
    cd "$working_dir"
    COMPONENT_TYPE="$component_type" nohup "$@" </dev/null >"$log_file" 2>&1 &
    echo "$!" > "$pid_file"
    disown "$!" 2>/dev/null || true
  )
  sleep 1
  local new_pid
  new_pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -z "$new_pid" ]] || ! kill -0 "$new_pid" >/dev/null 2>&1; then
    echo "$name exited during startup. Last log lines:" >&2
    if [[ -s "$log_file" ]]; then
      tail -n 80 "$log_file" >&2 || true
    else
      echo "  $log_file is empty." >&2
    fi
    return 1
  fi
}

start_process api api "$REPO_ROOT/apps/api" "$NATIVE_PYTHON" -m uvicorn app.main:app --app-dir "$REPO_ROOT/apps/api" --host 127.0.0.1 --port 8000
start_process worker worker "$REPO_ROOT/apps/api" "$NATIVE_PYTHON" -m celery -A app.jobs.celery_app.celery_app worker --loglevel=info -Q default,monitoring,auditor,discovery
start_process scheduler celery_beat "$REPO_ROOT/apps/api" "$NATIVE_PYTHON" -m celery -A app.jobs.celery_app.celery_app beat --loglevel=info
start_process web web "$REPO_ROOT/apps/web" npm run dev:webpack -- --hostname 127.0.0.1 --port 3000
if command -v caddy >/dev/null 2>&1; then
  start_process gateway gateway "$REPO_ROOT" caddy run --config "$REPO_ROOT/infra/Caddyfile.local-native" --adapter caddyfile
else
  start_process gateway gateway "$REPO_ROOT" node "$REPO_ROOT/infra/scripts/native-gateway.mjs"
fi

wait_for_http() {
  local label="$1"
  local url="$2"
  shift 2
  local attempt
  for attempt in {1..30}; do
    if curl --silent --show-error --fail --connect-timeout 2 --max-time 5 "$@" "$url" >/dev/null 2>&1; then
      echo "✓ $label"
      return 0
    fi
    sleep 1
  done
  echo "✗ $label did not become ready after 30 attempts: $url" >&2
  return 1
}

wait_for_http "API strict readiness" "http://127.0.0.1:8000/health/ready" || {
  echo "API startup failed; inspect $NATIVE_LOG_DIR/api.log" >&2
  exit 1
}
wait_for_http "Web direct route" "http://127.0.0.1:3000/" || {
  echo "Web startup failed; inspect $NATIVE_LOG_DIR/web.log" >&2
  exit 1
}
wait_for_http "Gateway strict readiness" "https://hawk.localhost:3443/api/health/ready" --insecure --resolve hawk.localhost:3443:127.0.0.1 || {
  echo "Gateway startup failed; inspect $NATIVE_LOG_DIR/gateway.log" >&2
  exit 1
}

echo ""
echo "Native local demo processes are starting."
echo "Run health check:"
echo "  infra/scripts/native-health.sh"
echo ""
echo "Demo URL:"
echo "  https://hawk.localhost:3443"
