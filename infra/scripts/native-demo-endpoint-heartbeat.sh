#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HAWK_EXEC_API="${HAWK_EXEC_API:-http://127.0.0.1:8000}"

if [[ -z "${HAWK_EXEC_EMAIL:-}" ]]; then
  read -r -p "Hawk owner/admin email: " HAWK_EXEC_EMAIL
fi
if [[ -z "${HAWK_EXEC_PASSWORD:-}" ]]; then
  read -r -s -p "Hawk password: " HAWK_EXEC_PASSWORD
  echo
fi

login_json="$(
  printf '{"email":"%s","password":"%s"}' "$HAWK_EXEC_EMAIL" "$HAWK_EXEC_PASSWORD" |
    curl --silent --show-error --fail-with-body \
      -H 'Content-Type: application/json' \
      --data-binary @- \
      "$HAWK_EXEC_API/auth/login"
)"

tenant_id="$(
  printf '%s' "$login_json" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["selected_tenant_id"])'
)"
token="$(
  printf '%s' "$login_json" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
)"

device_id="$(hostname | tr -c 'A-Za-z0-9._:-' '-')-local-native-demo"

python3 "$REPO_ROOT/infra/scripts/endpoint_agent.py" \
  --api-url "$HAWK_EXEC_API" \
  --tenant-id "$tenant_id" \
  --token "$token" \
  --user-id "$HAWK_EXEC_EMAIL" \
  --device-id "$device_id" \
  --location "local-native-demo" \
  --allow-local-http-api \
  --verbose \
  heartbeat \
  --once

echo ""
echo "Endpoint heartbeat submitted for $device_id"
