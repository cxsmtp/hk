#!/usr/bin/env bash
set -euo pipefail
umask 077

HAWK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAWK_REPO_ROOT="$(cd "$HAWK_SCRIPT_DIR/../.." && pwd)"
HAWK_STACK="$HAWK_SCRIPT_DIR/hawk_demo_stack.sh"
HAWK_ENV_FILE="$HAWK_REPO_ROOT/.env"
HAWK_API="${HAWK_API:-http://127.0.0.1:8000}"
HAWK_DEMO_EMAIL="${HAWK_DEMO_EMAIL:-owner@acme.ai}"
HAWK_ROOT="$HOME/Library/Application Support/Hawk/EndpointAgent"
HAWK_RUNTIME="$HAWK_ROOT/runtime"
HAWK_PY="$HAWK_RUNTIME/venv/bin/python"
HAWK_HOOK="$HAWK_RUNTIME/bin/hawk-native-hook"
HAWK_IDENTITY="$HAWK_RUNTIME/bin/hawk-device-identity"
HAWK_EXPECTED_IDENTITY="$HAWK_ROOT/bin/hawk-device-identity"
HAWK_KEY_TAG="com.hawk.endpoint-agent.device-key"
HAWK_CLAUDE_BINARY="$HOME/.local/bin/claude"
HAWK_CLAUDE_VERIFIED_BINARY="$HOME/.local/share/claude/versions/2.1.183"
HAWK_CLAUDE_SETTINGS="$HOME/.claude/settings.json"
HAWK_STATE_DIR="$HOME/.hawk/native-control"
HAWK_STATE_FILE="$HAWK_STATE_DIR/claude-demo-enrollment.json"
HAWK_CONFIG="$HAWK_STATE_DIR/claude-code.json"
HAWK_ENV_TEMP=""
HAWK_SETTINGS_TEMP=""

hawk_cleanup() {
  unset HAWK_DEMO_PASSWORD HAWK_LOGIN HAWK_TOKEN HAWK_PUBLIC_KEY HAWK_IDENTITY_JSON
  if [[ -n "${HAWK_ENV_TEMP:-}" && -f "$HAWK_ENV_TEMP" ]]; then
    /bin/rm -f "$HAWK_ENV_TEMP"
  fi
  if [[ -n "${HAWK_SETTINGS_TEMP:-}" && -f "$HAWK_SETTINGS_TEMP" ]]; then
    /bin/rm -f "$HAWK_SETTINGS_TEMP"
  fi
}
trap hawk_cleanup EXIT

hawk_require_file() {
  local HAWK_PATH="$1"
  local HAWK_LABEL="$2"
  if [[ ! -f "$HAWK_PATH" || -L "$HAWK_PATH" ]]; then
    echo "$HAWK_LABEL is missing or unsafe: $HAWK_PATH" >&2
    exit 1
  fi
}

hawk_require_executable() {
  local HAWK_PATH="$1"
  local HAWK_LABEL="$2"
  if [[ ! -x "$HAWK_PATH" ]]; then
    echo "$HAWK_LABEL is missing or unsafe: $HAWK_PATH" >&2
    exit 1
  fi
}

for HAWK_COMMAND in curl jq uuidgen awk stat; do
  if ! command -v "$HAWK_COMMAND" >/dev/null 2>&1; then
    echo "Required command is missing: $HAWK_COMMAND" >&2
    exit 1
  fi
done

hawk_require_file "$HAWK_ENV_FILE" "Hawk Docker environment"
hawk_require_executable "$HAWK_STACK" "Hawk Docker launcher"
hawk_require_executable "$HAWK_PY" "Hawk private Python runtime"
hawk_require_executable "$HAWK_HOOK" "Hawk native-hook launcher"
hawk_require_executable "$HAWK_IDENTITY" "Hawk Secure Enclave helper"
hawk_require_executable "$HAWK_CLAUDE_VERIFIED_BINARY" "Verified Claude Code 2.1.183 binary"

if [[ -e "$HAWK_CLAUDE_BINARY" || -L "$HAWK_CLAUDE_BINARY" ]]; then
  if [[ ! -L "$HAWK_CLAUDE_BINARY" ]]; then
    echo "Claude Code launcher is not a symlink; refusing to replace it." >&2
    exit 1
  fi
else
  /bin/mkdir -p "$(dirname "$HAWK_CLAUDE_BINARY")"
fi
/bin/ln -sfn "$HAWK_CLAUDE_VERIFIED_BINARY" "$HAWK_CLAUDE_BINARY"
hawk_require_executable "$HAWK_CLAUDE_BINARY" "Pinned Claude Code launcher"

if [[ -e "$HAWK_EXPECTED_IDENTITY" || -L "$HAWK_EXPECTED_IDENTITY" ]]; then
  if [[ ! -x "$HAWK_EXPECTED_IDENTITY" ]] || ! /usr/bin/cmp -s "$HAWK_EXPECTED_IDENTITY" "$HAWK_IDENTITY"; then
    echo "Existing Secure Enclave helper path does not match the installed Hawk helper." >&2
    exit 1
  fi
else
  /bin/mkdir -p "$HAWK_ROOT/bin"
  /bin/ln -s "$HAWK_IDENTITY" "$HAWK_EXPECTED_IDENTITY"
fi

if [[ -z "${HAWK_DEMO_PASSWORD:-}" ]]; then
  if [[ ! -t 0 ]]; then
    echo "HAWK_DEMO_PASSWORD is required when standard input is not a terminal." >&2
    exit 1
  fi
  read -r -s -p "Hawk demo password for $HAWK_DEMO_EMAIL: " HAWK_DEMO_PASSWORD
  printf '\n'
fi

"$HAWK_STACK" prepare
"$HAWK_STACK" up
curl -fsS --max-time 5 "$HAWK_API/health" |
  jq -e '.status == "ok" and .schema_healthy == true' >/dev/null

export PYTHONPATH="$HAWK_RUNTIME/app"
HAWK_VALIDATION="$("$HAWK_PY" -m hawk_endpoint_agent.native_control.cli \
  validate-claude --binary "$HAWK_CLAUDE_VERIFIED_BINARY")"
printf '%s\n' "$HAWK_VALIDATION" |
  jq -e '.passed == true and .provider_version == "2.1.183" and .runtime_binding_version == "2.1.183"' >/dev/null
printf '%s\n' "$HAWK_VALIDATION" |
  jq '{passed, provider_version, runtime_binding_version, measured_callback_p95_ms, failures}'

HAWK_LOGIN="$(curl -sS --fail-with-body \
  -H "Content-Type: application/json" \
  --data "$(jq -nc --arg email "$HAWK_DEMO_EMAIL" --arg password "$HAWK_DEMO_PASSWORD" \
    '{email:$email,password:$password}')" \
  "$HAWK_API/auth/login")"
HAWK_TOKEN="$(printf '%s' "$HAWK_LOGIN" | jq -er '.access_token')"
HAWK_TENANT_ID="$(printf '%s' "$HAWK_LOGIN" | jq -er '.selected_tenant_id')"

HAWK_ADAPTER="$(curl -sS --fail-with-body \
  -H "Authorization: Bearer $HAWK_TOKEN" \
  -H "X-Tenant-ID: $HAWK_TENANT_ID" \
  "$HAWK_API/native-controls/adapters")"
printf '%s\n' "$HAWK_ADAPTER" |
  jq -e '.items[] | select(
    .adapter_id == "anthropic.claude-code.command-hooks" and
    .adapter_version == "1.2.0" and
    .verification_status == "verified" and
    .production_eligible == true
  )' >/dev/null

HAWK_IDENTITY_JSON="$("$HAWK_IDENTITY" ensure "$HAWK_KEY_TAG")"
printf '%s\n' "$HAWK_IDENTITY_JSON" |
  jq -e '.ok == true and .hardware_backed == true and ((.public_key_pem // "") | length > 100)' >/dev/null
HAWK_PUBLIC_KEY="$(printf '%s' "$HAWK_IDENTITY_JSON" | jq -er '.public_key_pem')"

/bin/mkdir -p "$HAWK_STATE_DIR"
/bin/chmod 700 "$HAWK_STATE_DIR"

HAWK_INTEGRATION_ID=""
HAWK_CREDENTIAL_ID=""
HAWK_CREDENTIAL_REGISTERED="false"
if [[ -f "$HAWK_STATE_FILE" && ! -L "$HAWK_STATE_FILE" ]]; then
  HAWK_STATE_TENANT="$(jq -er '.tenant_id' "$HAWK_STATE_FILE")"
  if [[ "$HAWK_STATE_TENANT" != "$HAWK_TENANT_ID" ]]; then
    echo "Existing Claude enrollment belongs to another tenant; refusing to overwrite it." >&2
    exit 1
  fi
  HAWK_INTEGRATION_ID="$(jq -er '.integration_id' "$HAWK_STATE_FILE")"
  HAWK_CREDENTIAL_ID="$(jq -er '.credential_id' "$HAWK_STATE_FILE")"
  HAWK_CREDENTIAL_REGISTERED="$(jq -er '.credential_registered' "$HAWK_STATE_FILE")"
  curl -sS --fail-with-body \
    -H "Authorization: Bearer $HAWK_TOKEN" \
    -H "X-Tenant-ID: $HAWK_TENANT_ID" \
    "$HAWK_API/control-points/$HAWK_INTEGRATION_ID" >/dev/null
else
  HAWK_POLICY_UNTIL="$(date -u -v+7d '+%Y-%m-%dT%H:%M:%SZ')"
  HAWK_INTEGRATION="$(curl -sS --fail-with-body \
    -X POST \
    -H "Authorization: Bearer $HAWK_TOKEN" \
    -H "X-Tenant-ID: $HAWK_TENANT_ID" \
    -H "Content-Type: application/json" \
    --data "$(jq -nc --arg fresh "$HAWK_POLICY_UNTIL" '{
      provider:"anthropic",
      product:"claude_code",
      method:"native_hook",
      instance_key:"claude-code-local-2-1-183",
      display_name:"Claude Code - governed Mac",
      environment:"production",
      deployment_family:"endpoint",
      provider_version:"2.1.183",
      adapter_version:"1.2.0",
      policy_version:"airtel-demo-claude-v1",
      policy_fresh_until:$fresh,
      degradation_mode:"fail_closed"
    }')" \
    "$HAWK_API/native-controls/integrations")"
  HAWK_INTEGRATION_ID="$(printf '%s' "$HAWK_INTEGRATION" | jq -er '.id')"
  HAWK_CREDENTIAL_ID="claude-mac-$(uuidgen | tr '[:upper:]' '[:lower:]')"
fi

hawk_write_state() {
  local HAWK_REGISTERED="$1"
  local HAWK_STATE_TEMP
  HAWK_STATE_TEMP="$(mktemp "$HAWK_STATE_DIR/.claude-demo-enrollment.XXXXXX")"
  HAWK_STATE_PAYLOAD="$(jq -nc \
    --arg tenant "$HAWK_TENANT_ID" \
    --arg integration "$HAWK_INTEGRATION_ID" \
    --arg credential "$HAWK_CREDENTIAL_ID" \
    --argjson registered "$HAWK_REGISTERED" \
    '{
      schema_version:1,
      tenant_id:$tenant,
      integration_id:$integration,
      credential_id:$credential,
      credential_epoch:1,
      credential_registered:$registered,
      provider:"anthropic",
      product:"claude_code",
      provider_version:"2.1.183",
      adapter_version:"1.2.0"
    }')"
  printf '%s\n' "$HAWK_STATE_PAYLOAD" > "$HAWK_STATE_TEMP"
  /bin/chmod 600 "$HAWK_STATE_TEMP"
  /bin/mv "$HAWK_STATE_TEMP" "$HAWK_STATE_FILE"
}

if [[ ! -f "$HAWK_STATE_FILE" ]]; then
  hawk_write_state false
fi

if [[ "$HAWK_CREDENTIAL_REGISTERED" != "true" ]]; then
  HAWK_CREDENTIAL_UNTIL="$(date -u -v+30d '+%Y-%m-%dT%H:%M:%SZ')"
  curl -sS --fail-with-body \
    -X POST \
    -H "Authorization: Bearer $HAWK_TOKEN" \
    -H "X-Tenant-ID: $HAWK_TENANT_ID" \
    -H "Content-Type: application/json" \
    --data "$(jq -nc \
      --arg credential "$HAWK_CREDENTIAL_ID" \
      --arg public_key "$HAWK_PUBLIC_KEY" \
      --arg expires "$HAWK_CREDENTIAL_UNTIL" '{
        credential_id:$credential,
        credential_epoch:1,
        public_key_pem:$public_key,
        environment:"production",
        allowed_event_types:[
          "before_tool","permission_request","after_tool","after_tool_failure",
          "before_model","session_start","session_end","config_change",
          "subagent_context_start","subagent_context_stop"
        ],
        expires_at:$expires
      }')" \
    "$HAWK_API/native-controls/integrations/$HAWK_INTEGRATION_ID/credentials" >/dev/null
  HAWK_CREDENTIAL_REGISTERED="true"
  hawk_write_state true
fi

unset HAWK_LOGIN HAWK_TOKEN HAWK_PUBLIC_KEY HAWK_IDENTITY_JSON HAWK_DEMO_PASSWORD

HAWK_CURRENT_ROUTES="$(awk '
  index($0, "NATIVE_CONTROL_ROUTE_BINDINGS_JSON=") == 1 {
    print substr($0, length("NATIVE_CONTROL_ROUTE_BINDINGS_JSON=") + 1)
    found=1
    exit
  }
  END { if (!found) print "{}" }
' "$HAWK_ENV_FILE")"
HAWK_ROUTE_JSON="$(printf '%s' "$HAWK_CURRENT_ROUTES" | jq -ce \
  --arg tenant "$HAWK_TENANT_ID" \
  --arg integration "$HAWK_INTEGRATION_ID" '
  .[$tenant].runtime_control = {
    integration_instance_ids:[$integration],
    provider:"anthropic",
    provider_version:"2.1.183",
    adapter_version:"1.2.0",
    product:"claude_code"
  }')"
HAWK_ENV_TEMP="$(mktemp "$HAWK_REPO_ROOT/.env.hawk.XXXXXX")"
awk -v value="$HAWK_ROUTE_JSON" '
  index($0, "NATIVE_CONTROL_ROUTE_BINDINGS_JSON=") == 1 {
    print "NATIVE_CONTROL_ROUTE_BINDINGS_JSON=" value
    found=1
    next
  }
  { print }
  END {
    if (!found) print "NATIVE_CONTROL_ROUTE_BINDINGS_JSON=" value
  }
' "$HAWK_ENV_FILE" > "$HAWK_ENV_TEMP"
HAWK_ENV_MODE="$(stat -f '%Lp' "$HAWK_ENV_FILE")"
/bin/chmod "$HAWK_ENV_MODE" "$HAWK_ENV_TEMP"
/bin/mv "$HAWK_ENV_TEMP" "$HAWK_ENV_FILE"
HAWK_ENV_TEMP=""

if [[ -f "$HAWK_CLAUDE_SETTINGS" && ! -L "$HAWK_CLAUDE_SETTINGS" ]]; then
  HAWK_BACKUP_TIME="$(date -u '+%Y%m%dT%H%M%SZ')"
  HAWK_CLAUDE_BACKUP="$HAWK_CLAUDE_SETTINGS.hawk-backup-$HAWK_BACKUP_TIME"
  /bin/cp -p "$HAWK_CLAUDE_SETTINGS" "$HAWK_CLAUDE_BACKUP"
  /bin/chmod 600 "$HAWK_CLAUDE_BACKUP"
fi

HAWK_INSTALL_RESULT="$("$HAWK_PY" -m hawk_endpoint_agent.native_control.cli install \
  --provider claude_code \
  --scope user \
  --helper "$HAWK_HOOK" \
  --config "$HAWK_CONFIG" \
  --api-url "$HAWK_API" \
  --tenant-id "$HAWK_TENANT_ID" \
  --integration-id "$HAWK_INTEGRATION_ID" \
  --credential-id "$HAWK_CREDENTIAL_ID" \
  --credential-epoch 1 \
  --provider-family anthropic \
  --product claude_code \
  --provider-version 2.1.183 \
  --adapter-version 1.2.0 \
  --environment production \
  --key-provider macos_secure_enclave \
  --security-profile development \
  --kms-key-reference "secure-enclave://$HAWK_KEY_TAG")"
printf '%s\n' "$HAWK_INSTALL_RESULT" | jq '{provider, settings_path, changed, events}'

HAWK_SETTINGS_TEMP="$(mktemp "$HOME/.claude/.settings.hawk.XXXXXX")"
jq '.env = ((.env // {}) + {"DISABLE_AUTOUPDATER":"1","DISABLE_UPDATES":"1"})' \
  "$HAWK_CLAUDE_SETTINGS" > "$HAWK_SETTINGS_TEMP"
/bin/chmod 600 "$HAWK_SETTINGS_TEMP"
/bin/mv "$HAWK_SETTINGS_TEMP" "$HAWK_CLAUDE_SETTINGS"
HAWK_SETTINGS_TEMP=""

"$HAWK_STACK" up

HAWK_HOOK_SUMMARY="$(jq '{
  hook_events:(.hooks | keys),
  hawk_hook_count:([.hooks[] | .[] | select(tostring | contains("--hawk-managed-hook"))] | length)
}' "$HAWK_CLAUDE_SETTINGS")"
printf '%s\n' "$HAWK_HOOK_SUMMARY"
printf 'HAWK_TENANT_ID=%s\n' "$HAWK_TENANT_ID"
printf 'HAWK_INTEGRATION_ID=%s\n' "$HAWK_INTEGRATION_ID"
printf 'HAWK_CREDENTIAL_ID=%s\n' "$HAWK_CREDENTIAL_ID"
printf 'HAWK_ENROLLMENT_STATE=%s\n' "$HAWK_STATE_FILE"
printf 'HAWK_CLAUDE_VERSION=%s\n' "$("$HAWK_CLAUDE_BINARY" --version)"
printf 'NEXT=Run one harmless Claude Code read to emit the first signed callback.\n'
