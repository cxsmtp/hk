#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/native-demo-env.sh"

REPO_ROOT="$(native_demo_repo_root)"
native_demo_load_env "$REPO_ROOT"

mkdir -p "$NATIVE_LOG_DIR" "$NATIVE_PID_DIR"

preflight() {
  local missing=()
  local command_name
  for command_name in curl lsof nohup; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  command -v "$NATIVE_PYTHON" >/dev/null 2>&1 || missing+=("$NATIVE_PYTHON")
  if ! command -v caddy >/dev/null 2>&1 && ! command -v node >/dev/null 2>&1; then
    missing+=("caddy or node")
  fi
  PG_ISREADY="$(native_demo_resolve_binary pg_isready "$NATIVE_POSTGRES_BIN" || true)"
  [[ -n "$PG_ISREADY" ]] || missing+=("pg_isready")
  if (( ${#missing[@]} > 0 )); then
    native_demo_print_missing "${missing[@]}"
  fi
  if ! "$PG_ISREADY" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" >/dev/null 2>&1; then
    echo "PostgreSQL is not reachable at $NATIVE_POSTGRES_HOST:$NATIVE_POSTGRES_PORT; start or recover it before starting the API." >&2
    return 1
  fi
}

port_owner() {
  local port="$1"
  native_demo_port_owner "$port" || true
}

wait_for() {
  local label="$1"
  local url="$2"
  shift 2
  local attempt body_file status
  body_file="$(mktemp)"
  for attempt in {1..30}; do
    if status="$(curl --silent --show-error --connect-timeout 2 --max-time 5 -o "$body_file" -w '%{http_code}' "$@" "$url" 2>/dev/null)"; then
      if [[ "$status" == 2[0-9][0-9] ]]; then
        rm -f "$body_file"
        echo "✓ $label"
        return 0
      fi
      echo "✗ $label (HTTP $status)" >&2
      head -c 2048 "$body_file" >&2
      echo "" >&2
      rm -f "$body_file"
      return 1
    fi
    sleep 1
  done
  rm -f "$body_file"
  echo "✗ $label"
  return 1
}

start_api() {
  local owner
  owner="$(port_owner 8000)"
  if [[ -n "$owner" ]]; then
    echo "API already listening on 8000 ($owner)"
    return 0
  fi

  echo "Starting native API on http://127.0.0.1:8000 ..."
  cd "$REPO_ROOT/apps/api"
  COMPONENT_TYPE=api nohup "$NATIVE_PYTHON" -m uvicorn app.main:app \
    --app-dir "$REPO_ROOT/apps/api" \
    --host 127.0.0.1 \
    --port 8000 \
    </dev/null >"$NATIVE_LOG_DIR/api.log" 2>&1 &
  echo "$!" > "$NATIVE_PID_DIR/api.pid"
}

start_gateway() {
  local owner
  owner="$(port_owner 3443)"
  if [[ -n "$owner" ]]; then
    echo "Gateway already listening on 3443 ($owner)"
    return 0
  fi

  if command -v caddy >/dev/null 2>&1; then
    echo "Starting native HTTPS gateway with Caddy on https://hawk.localhost:3443 ..."
    cd "$REPO_ROOT"
    nohup caddy run --config "$REPO_ROOT/infra/Caddyfile.local-native" --adapter caddyfile \
      </dev/null >"$NATIVE_LOG_DIR/gateway.log" 2>&1 &
    echo "$!" > "$NATIVE_PID_DIR/gateway.pid"
  else
    echo "Starting native HTTPS gateway with Node on https://hawk.localhost:3443 ..."
    cd "$REPO_ROOT"
    nohup node "$REPO_ROOT/infra/scripts/native-gateway.mjs" \
      </dev/null >"$NATIVE_LOG_DIR/gateway.log" 2>&1 &
    echo "$!" > "$NATIVE_PID_DIR/gateway.pid"
  fi
}

preflight
start_api
wait_for "API strict readiness" "http://127.0.0.1:8000/health/ready" || {
  echo ""
  echo "API failed to become healthy. Recent API log:"
  tail -n 80 "$NATIVE_LOG_DIR/api.log" || true
  exit 1
}

start_gateway
wait_for "Gateway strict readiness" "https://hawk.localhost:3443/api/health/ready" --insecure --resolve hawk.localhost:3443:127.0.0.1 || {
  echo ""
  echo "Gateway failed to become healthy. Recent gateway log:"
  tail -n 80 "$NATIVE_LOG_DIR/gateway.log" || true
  exit 1
}

echo ""
echo "Native platform is ready:"
echo "  UI:  https://hawk.localhost:3443"
echo "  API: http://127.0.0.1:8000"
echo "  Logs: $NATIVE_LOG_DIR"
