#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/native-demo-env.sh"

REPO_ROOT="$(native_demo_repo_root)"
native_demo_load_env "$REPO_ROOT"

if [[ ! -d "$NATIVE_PID_DIR" ]]; then
  echo "No native demo PID directory found."
  exit 0
fi

for name in gateway caddy web scheduler worker api; do
  pid_file="$NATIVE_PID_DIR/$name.pid"
  [[ -f "$pid_file" ]] || continue
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    echo "Stopping $name (pid $pid)..."
    kill "$pid" >/dev/null 2>&1 || true
  fi
  rm -f "$pid_file"
done

redis_pid_file="$NATIVE_PID_DIR/redis.pid"
if [[ -f "$redis_pid_file" ]]; then
  redis_pid="$(cat "$redis_pid_file" 2>/dev/null || true)"
  if [[ -n "$redis_pid" ]] && kill -0 "$redis_pid" >/dev/null 2>&1; then
    echo "Stopping user-owned Redis (pid $redis_pid)..."
    kill "$redis_pid" >/dev/null 2>&1 || true
  fi
  rm -f "$redis_pid_file"
fi

PG_CTL="$(native_demo_resolve_binary pg_ctl "$NATIVE_POSTGRES_BIN" || true)"
NATIVE_POSTGRES_DATA_DIR="${NATIVE_POSTGRES_DATA_DIR:-/private/tmp/hawk-native-demo/postgres-data}"
if [[ -n "$PG_CTL" ]] && [[ -f "$NATIVE_POSTGRES_DATA_DIR/PG_VERSION" ]]; then
  if "$PG_CTL" -D "$NATIVE_POSTGRES_DATA_DIR" status >/dev/null 2>&1; then
    echo "Stopping user-owned PostgreSQL..."
    "$PG_CTL" -D "$NATIVE_POSTGRES_DATA_DIR" stop -m fast >/dev/null 2>&1 || true
  fi
fi

echo "Native local demo processes stopped."
