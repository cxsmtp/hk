#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export NATIVE_POSTGRES_HOST="${NATIVE_POSTGRES_HOST:-127.0.0.1}"
export NATIVE_POSTGRES_PORT=55432
export NATIVE_POSTGRES_DB="${NATIVE_POSTGRES_DB:-aicontrol}"
export NATIVE_POSTGRES_USER="${NATIVE_POSTGRES_USER:-$(id -un)}"
export NATIVE_POSTGRES_PASSWORD="${NATIVE_POSTGRES_PASSWORD:-}"
export NATIVE_POSTGRES_BIN="${NATIVE_POSTGRES_BIN:-/Library/PostgreSQL/18/bin}"
export NATIVE_POSTGRES_DATA_DIR="${NATIVE_POSTGRES_DATA_DIR:-/private/tmp/hawk-native-demo/postgres-data}"

export NATIVE_REDIS_HOST="${NATIVE_REDIS_HOST:-127.0.0.1}"
export NATIVE_REDIS_PORT="${NATIVE_REDIS_PORT:-6379}"
export NATIVE_REDIS_BIN="${NATIVE_REDIS_BIN:-/tmp/redis-stable/src}"
export NATIVE_REDIS_DATA_DIR="${NATIVE_REDIS_DATA_DIR:-"${HOME}/Library/Application Support/Hawk/Redis/data"}"

mkdir -p "$SCRIPT_DIR/../artifacts/native-runtime"
{
  printf 'NATIVE_POSTGRES_HOST=%q\n' "$NATIVE_POSTGRES_HOST"
  printf 'NATIVE_POSTGRES_PORT=%q\n' "$NATIVE_POSTGRES_PORT"
  printf 'NATIVE_POSTGRES_DB=%q\n' "$NATIVE_POSTGRES_DB"
  printf 'NATIVE_POSTGRES_USER=%q\n' "$NATIVE_POSTGRES_USER"
  printf 'NATIVE_POSTGRES_PASSWORD=%q\n' "$NATIVE_POSTGRES_PASSWORD"
  printf 'NATIVE_POSTGRES_BIN=%q\n' "$NATIVE_POSTGRES_BIN"
  printf 'NATIVE_POSTGRES_DATA_DIR=%q\n' "$NATIVE_POSTGRES_DATA_DIR"
  printf 'NATIVE_REDIS_HOST=%q\n' "$NATIVE_REDIS_HOST"
  printf 'NATIVE_REDIS_PORT=%q\n' "$NATIVE_REDIS_PORT"
  printf 'NATIVE_REDIS_BIN=%q\n' "$NATIVE_REDIS_BIN"
  printf 'NATIVE_REDIS_DATA_DIR=%q\n' "$NATIVE_REDIS_DATA_DIR"
} > "$SCRIPT_DIR/../artifacts/native-runtime/native-active.env"

"$SCRIPT_DIR/native-postgres-user.sh"
"$SCRIPT_DIR/native-redis-user.sh"
"$SCRIPT_DIR/native-up.sh"
