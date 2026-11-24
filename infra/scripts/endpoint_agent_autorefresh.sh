#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DEFAULT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ROOT="${ROOT:-$ROOT_DEFAULT}"
API_URL="${API_URL:-http://127.0.0.1:8000}"
LOGIN_EMAIL="${LOGIN_EMAIL:-owner@acme.ai}"
LOGIN_PASSWORD="${LOGIN_PASSWORD:-Password123!}"
APP_NAME="${APP_NAME:-Local Agent UI}"
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-20}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-20}"
REQUEST_RETRIES="${REQUEST_RETRIES:-3}"
ALLOW_LOCAL_HTTP_API="${ALLOW_LOCAL_HTTP_API:-1}"
GATEWAY_ROUTED="${GATEWAY_ROUTED:-1}"
VERBOSE="${VERBOSE:-1}"
USER_ID_OVERRIDE="${USER_ID_OVERRIDE:-}"
RUN_ONCE="${RUN_ONCE:-0}"
REAUTH_RETRY_SECONDS="${REAUTH_RETRY_SECONDS:-5}"
LOGIN_TIMEOUT_SECONDS="${LOGIN_TIMEOUT_SECONDS:-10}"

AGENT_SCRIPT="${ROOT}/infra/scripts/endpoint_agent.py"
VENV_PYTHON="${ROOT}/apps/api/.venv/bin/python3"

if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
    PYTHON_BIN="$VIRTUAL_ENV/bin/python"
  elif [[ -x "${ROOT}/.venv/bin/python" ]]; then
    PYTHON_BIN="${ROOT}/.venv/bin/python"
  elif [[ -x "$VENV_PYTHON" ]]; then
    PYTHON_BIN="$VENV_PYTHON"
  else
    PYTHON_BIN="python3"
  fi
fi

if [[ ! -f "$AGENT_SCRIPT" ]]; then
  echo "[fatal] endpoint agent script not found at: $AGENT_SCRIPT" >&2
  exit 1
fi

now_ts() {
  date +"%Y-%m-%d %H:%M:%S"
}

normalize_interval() {
  local raw="$1"
  if [[ ! "$raw" =~ ^[0-9]+$ ]]; then
    echo "20"
    return
  fi
  if (( raw < 5 )); then
    echo "5"
    return
  fi
  echo "$raw"
}

HEARTBEAT_INTERVAL="$(normalize_interval "$HEARTBEAT_INTERVAL")"

reauth() {
  local auth_json=""
  auth_json="$(curl -sS --connect-timeout 3 --max-time "${LOGIN_TIMEOUT_SECONDS}" -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${LOGIN_EMAIL}\",\"password\":\"${LOGIN_PASSWORD}\"}")" || return 1

  ACCESS_TOKEN="$("$PYTHON_BIN" -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' <<< "$auth_json")"
  TENANT_ID="$("$PYTHON_BIN" -c 'import json,sys; print(json.load(sys.stdin).get("selected_tenant_id",""))' <<< "$auth_json")"
  USER_ID="$("$PYTHON_BIN" -c 'import json,sys; u=(json.load(sys.stdin).get("user") or {}); print(u.get("id",""))' <<< "$auth_json")"

  if [[ -z "$ACCESS_TOKEN" || -z "$TENANT_ID" ]]; then
    return 1
  fi

  if [[ -n "$USER_ID_OVERRIDE" ]]; then
    USER_ID="$USER_ID_OVERRIDE"
  fi

  export ACCESS_TOKEN TENANT_ID USER_ID
  return 0
}

run_heartbeat_once() {
  local cmd=("$PYTHON_BIN" "$AGENT_SCRIPT"
    "--api-url" "$API_URL"
    "--tenant-id" "$TENANT_ID"
    "--token" "$ACCESS_TOKEN"
    "--request-timeout" "$REQUEST_TIMEOUT"
    "--request-retries" "$REQUEST_RETRIES")

  if [[ -n "$USER_ID" ]]; then
    cmd+=("--user-id" "$USER_ID")
  fi
  if [[ "$ALLOW_LOCAL_HTTP_API" == "1" ]]; then
    cmd+=("--allow-local-http-api")
  fi
  if [[ "$VERBOSE" == "1" ]]; then
    cmd+=("--verbose")
  fi

  cmd+=("heartbeat" "--once" "--interval" "$HEARTBEAT_INTERVAL" "--app" "$APP_NAME")
  if [[ "$GATEWAY_ROUTED" == "1" ]]; then
    cmd+=("--gateway-routed")
  else
    cmd+=("--no-gateway-routed")
  fi

  "${cmd[@]}"
}

echo "[info] $(now_ts) starting endpoint auto-refresh heartbeat loop"
echo "[info] api=${API_URL} email=${LOGIN_EMAIL} app=${APP_NAME} interval=${HEARTBEAT_INTERVAL}s"

while true; do
  if ! reauth; then
    echo "[warn] $(now_ts) login failed; retrying in ${REAUTH_RETRY_SECONDS}s" >&2
    sleep "$REAUTH_RETRY_SECONDS"
    continue
  fi

  if run_heartbeat_once; then
    echo "[info] $(now_ts) heartbeat sent"
  else
    echo "[warn] $(now_ts) heartbeat send failed (will retry next cycle)" >&2
  fi

  if [[ "$RUN_ONCE" == "1" ]]; then
    echo "[info] $(now_ts) run-once completed"
    exit 0
  fi

  sleep "$HEARTBEAT_INTERVAL"
done
