#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/native-demo-env.sh"

REPO_ROOT="$(native_demo_repo_root)"
native_demo_load_env "$REPO_ROOT"

mkdir -p "$NATIVE_LOG_DIR" "$NATIVE_PID_DIR"

PG_ISREADY="$(native_demo_resolve_binary pg_isready "$NATIVE_POSTGRES_BIN" || true)"
REDIS_CLI="$(native_demo_resolve_binary redis-cli "$NATIVE_REDIS_BIN" || true)"

status=0
CURL_TIMEOUT=(--connect-timeout 2 --max-time 5)

show_port_owner() {
  local port="$1"
  local label="$2"
  local owner
  owner="$(native_demo_port_owner "$port" || true)"
  if [[ -n "$owner" ]]; then
    echo "• $label port $port owner: $owner"
  else
    echo "• $label port $port owner: none"
  fi
}

show_port_owner 3443 "Gateway"
show_port_owner 8000 "API"
show_port_owner 3000 "Web"
show_port_owner "$NATIVE_POSTGRES_PORT" "PostgreSQL"
show_port_owner "$NATIVE_REDIS_PORT" "Redis"
echo ""

check() {
  local label="$1"
  shift
  if "$@" >/tmp/native-demo-check.out 2>/tmp/native-demo-check.err; then
    echo "✓ $label"
  else
    status=1
    echo "✗ $label"
    sed -n '1,8p' /tmp/native-demo-check.err >&2 || true
    sed -n '1,8p' /tmp/native-demo-check.out >&2 || true
  fi
}

if [[ -n "$PG_ISREADY" ]]; then
  check "PostgreSQL reachable" env PGPASSWORD="$NATIVE_POSTGRES_PASSWORD" "$PG_ISREADY" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER"
else
  status=1
  echo "✗ PostgreSQL reachable"
  echo "pg_isready not found. Expected it on PATH or in $NATIVE_POSTGRES_BIN." >&2
fi

if [[ -n "$REDIS_CLI" ]]; then
  check "Redis reachable" "$REDIS_CLI" -h "$NATIVE_REDIS_HOST" -p "$NATIVE_REDIS_PORT" ping
else
  status=1
  echo "✗ Redis reachable"
  echo "redis-cli not found. Expected it on PATH or in $NATIVE_REDIS_BIN." >&2
fi
check "API direct health" curl "${CURL_TIMEOUT[@]}" --fail --silent --show-error http://127.0.0.1:8000/health
check "API strict readiness" curl "${CURL_TIMEOUT[@]}" --fail --silent --show-error http://127.0.0.1:8000/health/ready
check "Web direct route" curl "${CURL_TIMEOUT[@]}" --fail --silent --show-error http://127.0.0.1:3000/
check "Gateway API health" curl "${CURL_TIMEOUT[@]}" --insecure --fail --silent --show-error --resolve hawk.localhost:3443:127.0.0.1 https://hawk.localhost:3443/api/health
check "Gateway strict readiness" curl "${CURL_TIMEOUT[@]}" --insecure --fail --silent --show-error --resolve hawk.localhost:3443:127.0.0.1 https://hawk.localhost:3443/api/health/ready
check "Gateway command center" curl "${CURL_TIMEOUT[@]}" --insecure --fail --silent --show-error --resolve hawk.localhost:3443:127.0.0.1 -H "Accept: text/html" https://hawk.localhost:3443/dashboard/command-center

echo ""
echo "Logs: $NATIVE_LOG_DIR"
if (( status != 0 )); then
  echo ""
  echo "Recent log tails:"
  for log in "$NATIVE_LOG_DIR"/*.log; do
    [[ -f "$log" ]] || continue
    echo "--- ${log##*/} ---"
    tail -n 12 "$log" || true
  done
fi

exit "$status"
