#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/native-demo-env.sh"

REPO_ROOT="$(native_demo_repo_root)"
native_demo_load_env "$REPO_ROOT"

export NATIVE_REDIS_PORT="${NATIVE_REDIS_PORT:-6379}"
export NATIVE_REDIS_DATA_DIR="${NATIVE_REDIS_DATA_DIR:-"${HOME}/Library/Application Support/Hawk/Redis/data"}"

mkdir -p "$NATIVE_LOG_DIR" "$NATIVE_PID_DIR" "$NATIVE_REDIS_DATA_DIR"

REDIS_SERVER="$(native_demo_resolve_binary redis-server "$NATIVE_REDIS_BIN" || true)"
REDIS_CLI="$(native_demo_resolve_binary redis-cli "$NATIVE_REDIS_BIN" || true)"

redis_ready() {
  if [[ -n "$REDIS_CLI" ]]; then
    [[ "$("$REDIS_CLI" -h "$NATIVE_REDIS_HOST" -p "$NATIVE_REDIS_PORT" ping 2>/dev/null)" == "PONG" ]]
    return
  fi

  "$NATIVE_PYTHON" - "$NATIVE_REDIS_HOST" "$NATIVE_REDIS_PORT" >/dev/null 2>&1 <<'PY'
import socket
import sys

try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(b"*1\r\n$4\r\nPING\r\n")
        response = connection.makefile("rb").readline(8)
    if response != b"+PONG\r\n":
        raise SystemExit(1)
except (OSError, ValueError):
    raise SystemExit(1)
PY
}

if redis_ready; then
  echo "User-owned Redis is already ready at $NATIVE_REDIS_HOST:$NATIVE_REDIS_PORT."
  exit 0
fi

missing=()
[[ -n "$REDIS_SERVER" ]] || missing+=("redis-server")
if [[ -z "$REDIS_CLI" ]] && ! command -v "$NATIVE_PYTHON" >/dev/null 2>&1; then
  missing+=("$NATIVE_PYTHON")
fi
if (( ${#missing[@]} > 0 )); then
  native_demo_print_missing "${missing[@]}"
fi

echo "Starting user-owned Redis at $NATIVE_REDIS_HOST:$NATIVE_REDIS_PORT..."
"$REDIS_SERVER" \
  --bind "$NATIVE_REDIS_HOST" \
  --port "$NATIVE_REDIS_PORT" \
  --dir "$NATIVE_REDIS_DATA_DIR" \
  --daemonize yes \
  --pidfile "$NATIVE_PID_DIR/redis.pid" \
  --logfile "$NATIVE_LOG_DIR/redis.log"

for _ in {1..40}; do
  if redis_ready; then
    echo "Redis ready: $NATIVE_REDIS_HOST:$NATIVE_REDIS_PORT"
    exit 0
  fi
  sleep 0.25
done

echo "User-owned Redis did not become ready. Recent log:" >&2
tail -n 40 "$NATIVE_LOG_DIR/redis.log" >&2 || true
exit 1
