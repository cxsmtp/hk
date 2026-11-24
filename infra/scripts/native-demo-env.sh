#!/usr/bin/env bash
set -euo pipefail

native_demo_repo_root() {
  local script_dir
  if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  elif [[ -f "$PWD/infra/scripts/native-demo-env.sh" ]]; then
    # Allow operators to source this helper from zsh after `cd` into the repo.
    # Bash entrypoint scripts still use BASH_SOURCE; this fallback only prevents
    # an interactive shell from dropping into confusing continuation prompts.
    script_dir="$PWD/infra/scripts"
  else
    echo "native_demo_repo_root: run from the repository root or use bash infra/scripts/<script>.sh" >&2
    return 1
  fi
  cd "$script_dir/../.." && pwd
}

native_demo_load_env() {
  local repo_root="$1"

  if [[ -f "$repo_root/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$repo_root/.env"
    set +a
  fi

  if [[ -f "$repo_root/.env.local-native" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$repo_root/.env.local-native"
    set +a
  fi

  if [[ -f "$repo_root/infra/artifacts/native-runtime/native-active.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$repo_root/infra/artifacts/native-runtime/native-active.env"
    set +a
  fi

  if [[ "${AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT:-}" == "{5043d9f6-b79e-4621-bf27-9d3dc7bb0483:[runtime_control]}" ]]; then
    export AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT='{"5043d9f6-b79e-4621-bf27-9d3dc7bb0483":["runtime_control"]}'
  fi

  export NATIVE_POSTGRES_HOST="${NATIVE_POSTGRES_HOST:-127.0.0.1}"
  export NATIVE_POSTGRES_PORT="${NATIVE_POSTGRES_PORT:-55432}"
  export NATIVE_POSTGRES_DB="${NATIVE_POSTGRES_DB:-aicontrol}"
  export NATIVE_POSTGRES_USER="${NATIVE_POSTGRES_USER:-$(id -un)}"
  export NATIVE_POSTGRES_PASSWORD="${NATIVE_POSTGRES_PASSWORD:-}"
  export NATIVE_POSTGRES_BIN="${NATIVE_POSTGRES_BIN:-/Library/PostgreSQL/18/bin}"

  export NATIVE_REDIS_HOST="${NATIVE_REDIS_HOST:-127.0.0.1}"
  export NATIVE_REDIS_PORT="${NATIVE_REDIS_PORT:-6379}"
  export NATIVE_REDIS_DB="${NATIVE_REDIS_DB:-0}"
  export NATIVE_REDIS_BIN="${NATIVE_REDIS_BIN:-/tmp/redis-stable/src}"

  if [[ "${NATIVE_DEMO_USE_DOCKER_DATA_SERVICES:-false}" == "true" ]]; then
    export NATIVE_POSTGRES_PORT="${NATIVE_POSTGRES_PORT:-15432}"
  fi

  # Native demo mode must be hermetic.  The repository .env is intentionally
  # Docker-oriented (db:5432 / redis:6379), so never allow those values—or any
  # other pre-existing DATABASE_URL/REDIS_URL from the parent shell—to win in
  # the native path unless an operator explicitly opts out.
  if [[ "${NATIVE_DEMO_FORCE_LOCAL_DATA_SERVICES:-true}" == "true" && "${NATIVE_DEMO_USE_DOCKER_DATA_SERVICES:-false}" != "true" ]]; then
    unset DATABASE_URL TEST_DATABASE_URL REDIS_URL TEST_REDIS_URL CELERY_BROKER_URL CELERY_RESULT_BACKEND
  else
    if [[ "${DATABASE_URL:-}" == *"@db:"* || "${DATABASE_URL:-}" == *"//db:"* ]]; then
      unset DATABASE_URL
    fi
    if [[ "${TEST_DATABASE_URL:-}" == *"@db:"* || "${TEST_DATABASE_URL:-}" == *"//db:"* ]]; then
      unset TEST_DATABASE_URL
    fi
    if [[ "${REDIS_URL:-}" == *"//redis:"* ]]; then
      unset REDIS_URL
    fi
    if [[ "${TEST_REDIS_URL:-}" == *"//redis:"* ]]; then
      unset TEST_REDIS_URL
    fi
    if [[ "${CELERY_BROKER_URL:-}" == *"//redis:"* ]]; then
      unset CELERY_BROKER_URL
    fi
    if [[ "${CELERY_RESULT_BACKEND:-}" == *"//redis:"* ]]; then
      unset CELERY_RESULT_BACKEND
    fi
  fi

  if [[ -n "$NATIVE_POSTGRES_PASSWORD" ]]; then
    export NATIVE_DATABASE_URL="postgresql+psycopg2://${NATIVE_POSTGRES_USER}:${NATIVE_POSTGRES_PASSWORD}@${NATIVE_POSTGRES_HOST}:${NATIVE_POSTGRES_PORT}/${NATIVE_POSTGRES_DB}"
  else
    export NATIVE_DATABASE_URL="postgresql+psycopg2://${NATIVE_POSTGRES_USER}@${NATIVE_POSTGRES_HOST}:${NATIVE_POSTGRES_PORT}/${NATIVE_POSTGRES_DB}"
  fi
  export DATABASE_URL="${DATABASE_URL:-$NATIVE_DATABASE_URL}"
  export TEST_DATABASE_URL="${TEST_DATABASE_URL:-$DATABASE_URL}"
  export REDIS_URL="${REDIS_URL:-redis://${NATIVE_REDIS_HOST}:${NATIVE_REDIS_PORT}/${NATIVE_REDIS_DB}}"
  export TEST_REDIS_URL="${TEST_REDIS_URL:-$REDIS_URL}"
  export CELERY_BROKER_URL="${CELERY_BROKER_URL:-redis://${NATIVE_REDIS_HOST}:${NATIVE_REDIS_PORT}/1}"
  export CELERY_RESULT_BACKEND="${CELERY_RESULT_BACKEND:-redis://${NATIVE_REDIS_HOST}:${NATIVE_REDIS_PORT}/2}"

  if [[ "${NATIVE_DEMO_FORCE_LOCAL_DATA_SERVICES:-true}" == "true" ]]; then
    unset API_BASE_URL WEB_ORIGIN FRONTEND_URL NEXT_PUBLIC_API_URL
  fi
  export API_BASE_URL="${API_BASE_URL:-https://hawk.localhost:3443/api}"
  export WEB_ORIGIN="${WEB_ORIGIN:-https://hawk.localhost:3443}"
  export FRONTEND_URL="${FRONTEND_URL:-https://hawk.localhost:3443}"
  export NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-https://hawk.localhost:3443/api}"
  export CORS_ORIGINS="${CORS_ORIGINS:-https://hawk.localhost:3443,https://api.hawk.localhost:3443,http://127.0.0.1:3000,http://localhost:3000}"

  export SECRET_KEY="${SECRET_KEY:-local-native-demo-secret-key-change-before-any-real-pilot}"
  export SECRET_KEY_LOCK_ENABLED="${SECRET_KEY_LOCK_ENABLED:-false}"
  export SECRET_KEY_LOCK_PEPPER="${SECRET_KEY_LOCK_PEPPER:-local-native-demo-lock-pepper}"
  export CONNECTOR_SECRETS_KEY="${CONNECTOR_SECRETS_KEY:-local-native-demo-connector-key}"
  export CONNECTOR_SECRETS_KDF_SALT="${CONNECTOR_SECRETS_KDF_SALT:-local-native-demo-connector-salt}"
  export ONPREM_BUNDLE_SIGNING_SECRET="${ONPREM_BUNDLE_SIGNING_SECRET:-local-native-demo-onprem-signing-secret}"

  # Native demo mode should expose the discovery control plane routes so the UI
  # can show real readiness, selected-source gaps, and bounded monitor-only scan
  # results.  These defaults do not create authoritative enterprise coverage;
  # unsupported sources still remain explicit gaps in the API responses.
  export HMAIR_CORE="${HMAIR_CORE:-true}"
  export HMAIR_ACTIVE_SCAN="${HMAIR_ACTIVE_SCAN:-true}"
  export HMAIR_ENDPOINT="${HMAIR_ENDPOINT:-true}"
  export HMAIR_BROWSER="${HMAIR_BROWSER:-true}"
  export HMAIR_MCP_RUNTIME="${HMAIR_MCP_RUNTIME:-true}"
  export HMAIR_REPOSITORY="${HMAIR_REPOSITORY:-true}"
  export HMAIR_FINGERPRINTING="${HMAIR_FINGERPRINTING:-true}"
  export HMAIR_USAGE_ATTRIBUTION="${HMAIR_USAGE_ATTRIBUTION:-true}"
  export HMAIR_SHADOW_AI="${HMAIR_SHADOW_AI:-true}"
  export HMAIR_REACHABILITY="${HMAIR_REACHABILITY:-true}"
  export HMAIR_CONNECTOR_SOURCES="${HMAIR_CONNECTOR_SOURCES:-true}"
  export HMAIR_GITHUB_CLOUD_SOURCE="${HMAIR_GITHUB_CLOUD_SOURCE:-true}"
  export HMAIR_GITHUB_GHES_SOURCE="${HMAIR_GITHUB_GHES_SOURCE:-true}"

  export PYTHONPATH="$repo_root/apps/api:$repo_root/packages${PYTHONPATH:+:$PYTHONPATH}"
  export ARTIFACT_DIR="${ARTIFACT_DIR:-$repo_root/artifacts}"
  export ARTIFACTS_DIR="${ARTIFACTS_DIR:-$repo_root/infra/artifacts}"
  export NATIVE_RUNTIME_DIR="${NATIVE_RUNTIME_DIR:-$repo_root/infra/artifacts/native-runtime}"
  export NATIVE_LOG_DIR="$NATIVE_RUNTIME_DIR/logs"
  export NATIVE_PID_DIR="$NATIVE_RUNTIME_DIR/pids"

  if [[ -x "$repo_root/apps/api/.venv/bin/python" ]]; then
    export NATIVE_PYTHON="$repo_root/apps/api/.venv/bin/python"
  elif [[ -x "$repo_root/.venv/bin/python" ]]; then
    export NATIVE_PYTHON="$repo_root/.venv/bin/python"
  else
    export NATIVE_PYTHON="${NATIVE_PYTHON:-python3}"
  fi
}

native_demo_print_missing() {
  local missing=("$@")
  if (( ${#missing[@]} == 0 )); then
    return 0
  fi

  echo "Missing local dependency/dependencies: ${missing[*]}" >&2
  echo "" >&2
  echo "Install the missing host services/tools, then rerun:" >&2
  echo "  brew install postgresql@16 redis caddy node python@3.12" >&2
  echo "  brew services start postgresql@16" >&2
  echo "  brew services start redis" >&2
  return 1
}

native_demo_port_owner() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $1 " pid=" $2}'
}

native_demo_check_port_available_or_owned() {
  local port="$1"
  local expected_pid_file="$2"
  local owner
  owner="$(native_demo_port_owner "$port" || true)"
  if [[ -z "$owner" ]]; then
    return 0
  fi

  if [[ -f "$expected_pid_file" ]]; then
    local expected_pid
    expected_pid="$(cat "$expected_pid_file" 2>/dev/null || true)"
    if [[ -n "$expected_pid" ]] && [[ "$owner" == *"pid=$expected_pid"* ]]; then
      return 0
    fi
  fi

  echo "Port $port is already in use by $owner." >&2
  if [[ "$owner" == com.docke* ]]; then
    echo "Docker Desktop is still holding this demo port. Quit Docker Desktop before running the native stack." >&2
  fi
  return 1
}

native_demo_check_app_port_available_or_owned() {
  local port="$1"
  local expected_pid_file="$2"
  native_demo_check_port_available_or_owned "$port" "$expected_pid_file"
}

native_demo_resolve_binary() {
  local name="$1"
  local fallback_dir="$2"
  local resolved
  resolved="$(command -v "$name" 2>/dev/null || true)"
  if [[ -n "$resolved" ]]; then
    echo "$resolved"
    return 0
  fi
  if [[ -x "$fallback_dir/$name" ]]; then
    echo "$fallback_dir/$name"
    return 0
  fi
  return 1
}
