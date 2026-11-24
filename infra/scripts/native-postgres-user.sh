#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/native-demo-env.sh"

REPO_ROOT="$(native_demo_repo_root)"
native_demo_load_env "$REPO_ROOT"

export NATIVE_POSTGRES_PORT="${NATIVE_POSTGRES_PORT:-55432}"
export NATIVE_POSTGRES_USER="${NATIVE_POSTGRES_USER:-$(id -un)}"
export NATIVE_POSTGRES_PASSWORD="${NATIVE_POSTGRES_PASSWORD:-}"
export NATIVE_POSTGRES_DATA_DIR="${NATIVE_POSTGRES_DATA_DIR:-/private/tmp/hawk-native-demo/postgres-data}"

mkdir -p "$NATIVE_LOG_DIR" "$NATIVE_PID_DIR" "$NATIVE_POSTGRES_DATA_DIR"

PG_CTL="$(native_demo_resolve_binary pg_ctl "$NATIVE_POSTGRES_BIN" || true)"
INITDB="$(native_demo_resolve_binary initdb "$NATIVE_POSTGRES_BIN" || true)"
PSQL="$(native_demo_resolve_binary psql "$NATIVE_POSTGRES_BIN" || true)"
CREATEDB="$(native_demo_resolve_binary createdb "$NATIVE_POSTGRES_BIN" || true)"
PG_ISREADY="$(native_demo_resolve_binary pg_isready "$NATIVE_POSTGRES_BIN" || true)"

missing=()
for pair in "pg_ctl:$PG_CTL" "initdb:$INITDB" "psql:$PSQL" "createdb:$CREATEDB" "pg_isready:$PG_ISREADY"; do
  name="${pair%%:*}"
  value="${pair#*:}"
  [[ -n "$value" ]] || missing+=("$name")
done
if (( ${#missing[@]} > 0 )); then
  native_demo_print_missing "${missing[@]}"
fi

if [[ ! -f "$NATIVE_POSTGRES_DATA_DIR/PG_VERSION" ]]; then
  if [[ -n "$(find "$NATIVE_POSTGRES_DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "PostgreSQL data directory has contents but no PG_VERSION: $NATIVE_POSTGRES_DATA_DIR" >&2
    echo "Preserving it unchanged. Choose a new empty NATIVE_POSTGRES_DATA_DIR, or inspect and recover the existing directory." >&2
    exit 1
  fi
  echo "Initializing user-owned PostgreSQL data directory at $NATIVE_POSTGRES_DATA_DIR"
  "$INITDB" \
    -D "$NATIVE_POSTGRES_DATA_DIR" \
    --auth=trust \
    --username="$NATIVE_POSTGRES_USER" \
    -c dynamic_shared_memory_type=posix \
    >"$NATIVE_LOG_DIR/postgres-initdb.log" 2>&1
fi

if "$PG_ISREADY" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" >/dev/null 2>&1; then
  echo "User-owned PostgreSQL is already ready at $NATIVE_POSTGRES_HOST:$NATIVE_POSTGRES_PORT."
else
  echo "Starting user-owned PostgreSQL at $NATIVE_POSTGRES_HOST:$NATIVE_POSTGRES_PORT..."
  "$PG_CTL" \
    -D "$NATIVE_POSTGRES_DATA_DIR" \
    -l "$NATIVE_LOG_DIR/postgres.log" \
    -o "-h $NATIVE_POSTGRES_HOST -p $NATIVE_POSTGRES_PORT" \
    start
fi

for _ in {1..40}; do
  if "$PG_ISREADY" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if ! "$PG_ISREADY" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" >/dev/null 2>&1; then
  echo "User-owned PostgreSQL did not become ready. Recent log:" >&2
  tail -n 40 "$NATIVE_LOG_DIR/postgres.log" >&2 || true
  exit 1
fi

if ! "$PSQL" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" -d "$NATIVE_POSTGRES_DB" -c "select 1" >/dev/null 2>&1; then
  echo "Creating local demo database $NATIVE_POSTGRES_DB..."
  "$CREATEDB" -h "$NATIVE_POSTGRES_HOST" -p "$NATIVE_POSTGRES_PORT" -U "$NATIVE_POSTGRES_USER" "$NATIVE_POSTGRES_DB"
fi

echo "PostgreSQL ready: $NATIVE_POSTGRES_HOST:$NATIVE_POSTGRES_PORT/$NATIVE_POSTGRES_DB"
