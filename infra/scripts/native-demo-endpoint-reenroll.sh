#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

HAWK_EXEC_API="${HAWK_EXEC_API:-http://127.0.0.1:8000}"
HAWK_EXEC_GATEWAY_API="${HAWK_EXEC_GATEWAY_API:-https://hawk.localhost:3443}"
HAWK_AGENT_ROOT="${HAWK_AGENT_ROOT:-$HOME/Library/Application Support/Hawk/EndpointAgent}"
HAWK_AGENT_RUNTIME="${HAWK_AGENT_RUNTIME:-$HAWK_AGENT_ROOT/runtime/bin/hawk-endpoint-agent}"
HAWK_AGENT_CONFIG="${HAWK_AGENT_CONFIG:-$HAWK_AGENT_ROOT/state/endpoint-agent.json}"
HAWK_IDENTITY_HELPER="${HAWK_IDENTITY_HELPER:-$HAWK_AGENT_ROOT/bin/hawk-device-identity}"

if [[ ! -x "$HAWK_AGENT_RUNTIME" ]]; then
  echo "Endpoint agent binary not found: $HAWK_AGENT_RUNTIME" >&2
  exit 1
fi

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

endpoint_id="${HAWK_ENDPOINT_ID:-}"
if [[ -z "$endpoint_id" && -f "$HAWK_AGENT_CONFIG" ]]; then
  endpoint_id="$(
    python3 - "$HAWK_AGENT_CONFIG" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        print((json.load(f).get("endpoint_id") or "").strip())
except Exception:
    print("")
PY
  )"
fi
if [[ -z "$endpoint_id" ]]; then
  endpoint_id="$(hostname | tr -c 'A-Za-z0-9._:-' '-')-local-native-demo"
fi

ai_system_id="${HAWK_AI_SYSTEM_ID:-}"
if [[ -z "$ai_system_id" ]]; then
  ai_system_id="$(
    curl --silent --show-error --fail-with-body \
      -H "Authorization: Bearer $token" \
      -H "X-Tenant-ID: $tenant_id" \
      "$HAWK_EXEC_API/ai-systems?page_size=100" |
      python3 -c '
import json, sys
data = json.load(sys.stdin)
items = data.get("items") or []
preferred = [
    item for item in items
    if str(item.get("asset_type") or "").lower() in {"endpoint", "desktop", "workstation"}
    or "endpoint" in str(item.get("name") or "").lower()
]
chosen = (preferred or items or [{}])[0]
print(chosen.get("id") or "")
'
  )"
fi

if [[ -z "$ai_system_id" ]]; then
  ai_system_id="$(
    curl --silent --show-error --fail-with-body \
      -X POST \
      -H "Authorization: Bearer $token" \
      -H "X-Tenant-ID: $tenant_id" \
      -H 'Content-Type: application/json' \
      --data '{
        "name": "Local native demo endpoint",
        "description": "Default AI system for the local native endpoint, browser, Claude, Codex, and GitHub MCP demo.",
        "risk_tier": "MEDIUM",
        "asset_type": "endpoint",
        "provider": "local",
        "deployment_surface": "Endpoint",
        "status_classification": "approved",
        "supported_clients": ["Chrome", "Claude Desktop", "Claude Code", "Codex Desktop", "Codex CLI"],
        "connected_tools": ["GitHub MCP", "Executive MCP"],
        "connected_data_sources": ["managed_browser", "endpoint_agent", "mcp_gateway"],
        "permissions": ["endpoint:heartbeat:write", "endpoint:discovery:write", "endpoint:decision:execute"]
      }' \
      "$HAWK_EXEC_API/ai-systems" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
  )"
fi

set +e
authorization_json="$(
  curl --silent --show-error --fail-with-body \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H "X-Tenant-ID: $tenant_id" \
    -H 'Content-Type: application/json' \
    --data '{}' \
    "$HAWK_EXEC_API/endpoint-agent/identities/$endpoint_id/reenroll-authorizations" 2>&1
)"
authorization_status=$?
set -e

if [[ "$authorization_status" -ne 0 ]]; then
  authorization_json="$(
    curl --silent --show-error --fail-with-body \
      -X POST \
      -H "Authorization: Bearer $token" \
      -H "X-Tenant-ID: $tenant_id" \
      -H 'Content-Type: application/json' \
      --data "{\"endpoint_id\":\"$endpoint_id\"}" \
      "$HAWK_EXEC_API/endpoint-agent/enrollment-authorizations"
  )"
fi

bundle_json="$(
  printf '%s' "$authorization_json" |
    python3 -c '
import json, sys
data = json.load(sys.stdin)
print(json.dumps({
    "authorization_id": data["authorization_id"],
    "enrollment_code": data["enrollment_code"],
    "enrollment_nonce": data["enrollment_nonce"],
}))
'
)"

printf '%s' "$bundle_json" |
  "$HAWK_AGENT_RUNTIME" \
    --config "$HAWK_AGENT_CONFIG" \
    --enroll \
    --enrollment-bundle-stdin \
    --api-url "$HAWK_EXEC_GATEWAY_API" \
    --tenant-id "$tenant_id" \
    --endpoint-id "$endpoint_id" \
    --ai-system-id "$ai_system_id" \
    --identity-helper "$HAWK_IDENTITY_HELPER" \
    --mode monitor \
    --security-profile bank \
    --key-provider macos_secure_enclave

"$HAWK_AGENT_RUNTIME" \
  --config "$HAWK_AGENT_CONFIG" \
  --verify-device-identity

"$HAWK_AGENT_RUNTIME" \
  --config "$HAWK_AGENT_CONFIG" \
  --hmair-discovery-snapshot || true

echo ""
echo "Endpoint re-enrollment completed."
echo "Tenant: $tenant_id"
echo "Endpoint: $endpoint_id"
echo "AI system: $ai_system_id"
echo "Endpoint API base in config: $HAWK_EXEC_GATEWAY_API"
echo ""
echo "Next: restart Claude Desktop / Codex Desktop, then retry the governed MCP prompts."
