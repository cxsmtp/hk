#!/usr/bin/env bash
set -euo pipefail

# This installer accepts enrollment authorization material only from inherited
# standard input. It is never accepted in arguments, environment variables,
# files, launchd configuration, or shell variables.
HAWK_API_URL="${HAWK_AGENT_API_URL:-}"
HAWK_TENANT_ID="${HAWK_AGENT_TENANT_ID:-}"
HAWK_EXTENSION_ID_VALUE="${HAWK_EXTENSION_ID:-}"
HAWK_AI_SYSTEM_ID=""
HAWK_ENDPOINT_MODE="monitor"
HAWK_SECURITY_PROFILE="bank"
HAWK_CODESIGN_IDENTITY=""
HAWK_DEVICE_KEY_TAG="com.hawk.endpoint-agent.device-key"
HAWK_WHEELHOUSE="${HAWK_AGENT_WHEELHOUSE:-}"
HAWK_REQUIREMENTS_LOCK="${HAWK_AGENT_REQUIREMENTS_LOCK:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url) HAWK_API_URL="$2"; shift 2 ;;
    --tenant-id) HAWK_TENANT_ID="$2"; shift 2 ;;
    --ai-system-id) HAWK_AI_SYSTEM_ID="$2"; shift 2 ;;
    --extension-id) HAWK_EXTENSION_ID_VALUE="$2"; shift 2 ;;
    --mode) HAWK_ENDPOINT_MODE="$2"; shift 2 ;;
    --security-profile) HAWK_SECURITY_PROFILE="$2"; shift 2 ;;
    --codesign-identity) HAWK_CODESIGN_IDENTITY="$2"; shift 2 ;;
    --device-key-tag) HAWK_DEVICE_KEY_TAG="$2"; shift 2 ;;
    --wheelhouse) HAWK_WHEELHOUSE="$2"; shift 2 ;;
    --requirements-lock) HAWK_REQUIREMENTS_LOCK="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$HAWK_API_URL" || -z "$HAWK_TENANT_ID" || -z "$HAWK_AI_SYSTEM_ID" ]]; then
  echo "--api-url, --tenant-id, and --ai-system-id are required" >&2
  exit 2
fi
if [[ "$HAWK_ENDPOINT_MODE" != "monitor" && "$HAWK_ENDPOINT_MODE" != "enforce" ]]; then
  echo "--mode must be monitor or enforce" >&2
  exit 2
fi
if [[ "$HAWK_SECURITY_PROFILE" != "bank" && "$HAWK_SECURITY_PROFILE" != "development" ]]; then
  echo "--security-profile must be bank or development" >&2
  exit 2
fi
if [[ "$HAWK_SECURITY_PROFILE" == "bank" && "$HAWK_API_URL" != https://* ]]; then
  echo "bank security profile requires an HTTPS Hawk API URL" >&2
  exit 2
fi
if [[ "$HAWK_SECURITY_PROFILE" == "bank" && -z "$HAWK_CODESIGN_IDENTITY" ]]; then
  echo "bank security profile requires --codesign-identity for the native helper" >&2
  echo "For local ad-hoc testing, rerun with --security-profile development." >&2
  exit 2
fi
if [[ "$HAWK_SECURITY_PROFILE" == "bank" ]]; then
  if [[ -z "$HAWK_WHEELHOUSE" || -z "$HAWK_REQUIREMENTS_LOCK" ]]; then
    echo "bank security profile requires an offline wheelhouse and hashed requirements lock" >&2
    exit 2
  fi
  if [[ ! -d "$HAWK_WHEELHOUSE" || -L "$HAWK_WHEELHOUSE" || \
        ! -f "$HAWK_REQUIREMENTS_LOCK" || -L "$HAWK_REQUIREMENTS_LOCK" ]]; then
    echo "bank offline dependency bundle is missing or unsafe" >&2
    exit 2
  fi
fi
if [[ -n "$HAWK_EXTENSION_ID_VALUE" && ! "$HAWK_EXTENSION_ID_VALUE" =~ ^[a-p]{32}$ ]]; then
  echo "--extension-id must be a 32-character Chrome extension ID" >&2
  exit 2
fi
if [[ ! "$HAWK_DEVICE_KEY_TAG" =~ ^[A-Za-z0-9._-]{1,200}$ ]]; then
  echo "--device-key-tag must contain only letters, digits, dot, underscore, or hyphen" >&2
  exit 2
fi

HAWK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAWK_PACKAGE_ROOT="$(cd "$HAWK_SCRIPT_DIR/.." && pwd)"
HAWK_ROOT="$HOME/Library/Application Support/Hawk/EndpointAgent"
HAWK_RUNTIME="$HAWK_ROOT/runtime"
HAWK_STATE="$HAWK_ROOT/state"
HAWK_BOOTSTRAP="$HAWK_ROOT/bootstrap"
HAWK_LOGS="$HAWK_ROOT/logs"
HAWK_CONFIG="$HAWK_STATE/endpoint-agent.json"
HAWK_IDENTITY_HELPER="$HAWK_RUNTIME/bin/hawk-device-identity"
HAWK_PLIST="$HOME/Library/LaunchAgents/com.hawk.endpoint-agent.plist"
HAWK_NATIVE_HOST_NAME="com.hawk.endpoint_agent"
HAWK_NATIVE_HOST_WRAPPER="$HAWK_STATE/hawk-bridge"
HAWK_NATIVE_HOST_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
HAWK_NATIVE_HOST_MANIFEST="$HAWK_NATIVE_HOST_DIR/$HAWK_NATIVE_HOST_NAME.json"

# Stop the exact legacy/current service before touching runtime files. If any
# secure-upgrade step fails, the old token-bearing process stays stopped.
launchctl bootout "gui/$(id -u)/com.hawk.endpoint-agent" 2>/dev/null || true

# Remove only obsolete regular bootstrap files. Never read their values and
# never follow a symlink outside the Hawk installation root.
for HAWK_LEGACY_NAME in "agent-token" "operator-token" "tenant-id"; do
  HAWK_LEGACY_FILE="$HAWK_BOOTSTRAP/$HAWK_LEGACY_NAME"
  if [[ -f "$HAWK_LEGACY_FILE" && ! -L "$HAWK_LEGACY_FILE" ]]; then
    /bin/rm -f "$HAWK_LEGACY_FILE"
  fi
done

if [[ -t 0 ]]; then
  echo "Paste the one-time Hawk enrollment JSON, then press Control-D." >&2
fi

# Compile the fixed native source locally. Development explicitly accepts the
# ad-hoc signature produced by the build helper; bank mode replaces it with a
# hardened Developer ID signature and verifies that a Team ID is present.
HAWK_BUILT_HELPER="$("$HAWK_PACKAGE_ROOT/scripts/build_macos_identity_helper.sh")"
if [[ "$HAWK_SECURITY_PROFILE" == "bank" ]]; then
  /usr/bin/codesign --force --options runtime --timestamp \
    --sign "$HAWK_CODESIGN_IDENTITY" "$HAWK_BUILT_HELPER"
  HAWK_SIGNATURE_INFO="$(/usr/bin/codesign -dv --verbose=4 "$HAWK_BUILT_HELPER" 2>&1)"
  if [[ "$HAWK_SIGNATURE_INFO" == *"Signature=adhoc"* || \
        "$HAWK_SIGNATURE_INFO" == *"TeamIdentifier=not set"* || \
        "$HAWK_SIGNATURE_INFO" != *"TeamIdentifier="* ]]; then
    echo "bank helper signing verification failed" >&2
    exit 1
  fi
fi

mkdir -p "$HAWK_RUNTIME" "$HAWK_STATE" "$HAWK_LOGS" "$HOME/Library/LaunchAgents"
python3 -m venv "$HAWK_RUNTIME/venv"
if [[ "$HAWK_SECURITY_PROFILE" == "bank" ]]; then
  "$HAWK_RUNTIME/venv/bin/python" -m pip install \
    --disable-pip-version-check --no-input --no-cache-dir \
    --no-index --find-links "$HAWK_WHEELHOUSE" --require-hashes \
    -r "$HAWK_REQUIREMENTS_LOCK"
else
  "$HAWK_RUNTIME/venv/bin/python" -m pip install \
    --disable-pip-version-check --no-input --no-cache-dir "cryptography>=42"
fi
mkdir -p "$HAWK_RUNTIME/app" "$HAWK_RUNTIME/bin"
/usr/bin/rsync -a --delete --exclude '._*' \
  "$HAWK_PACKAGE_ROOT/src/hawk_endpoint_agent/" \
  "$HAWK_RUNTIME/app/hawk_endpoint_agent/"
/usr/bin/install -m 0755 "$HAWK_PACKAGE_ROOT/scripts/hawk-endpoint-agent-wrapper.sh" \
  "$HAWK_RUNTIME/bin/hawk-endpoint-agent"
/usr/bin/install -m 0755 "$HAWK_PACKAGE_ROOT/scripts/hawk-endpoint-control-wrapper.sh" \
  "$HAWK_RUNTIME/bin/hawk-endpoint-control"
/usr/bin/install -m 0755 "$HAWK_PACKAGE_ROOT/scripts/hawk-native-hook-wrapper.sh" \
  "$HAWK_RUNTIME/bin/hawk-native-hook"
/usr/bin/install -m 0755 "$HAWK_BUILT_HELPER" "$HAWK_IDENTITY_HELPER"

export PYTHONPATH="$HAWK_RUNTIME/app"

HAWK_ENROLL=(
  "$HAWK_RUNTIME/bin/hawk-endpoint-agent"
  --enroll
  --enrollment-bundle-stdin
  --api-url "$HAWK_API_URL"
  --tenant-id "$HAWK_TENANT_ID"
  --ai-system-id "$HAWK_AI_SYSTEM_ID"
  --config "$HAWK_CONFIG"
  --mode "$HAWK_ENDPOINT_MODE"
  --security-profile "$HAWK_SECURITY_PROFILE"
  --key-provider macos_secure_enclave
  --identity-helper "$HAWK_IDENTITY_HELPER"
  --device-key-tag "$HAWK_DEVICE_KEY_TAG"
  --install-service
  --enable-proxy
  --log-dir "$HAWK_LOGS"
  --python-path "$HAWK_RUNTIME/app"
)
if [[ "$HAWK_SECURITY_PROFILE" == "development" ]]; then
  HAWK_ENROLL+=(--allow-development-local-control)
fi
if [[ -n "$HAWK_EXTENSION_ID_VALUE" ]]; then
  HAWK_ENROLL+=(--install-bridge --extension-id "$HAWK_EXTENSION_ID_VALUE")
fi

# Standard input is inherited directly by the enrollment process. Do not add a
# pipe, temporary file, variable capture, or command-line value here.
"${HAWK_ENROLL[@]}"
chmod 600 "$HAWK_CONFIG"

# Enrollment is not considered installed until a separate Python process can
# reopen the configured hardware key, match the backend pin, sign a fresh
# challenge, and verify it locally. Any failure leaves launchd stopped.
"$HAWK_RUNTIME/bin/hawk-endpoint-agent" --config "$HAWK_CONFIG" --verify-device-identity

if [[ -n "$HAWK_EXTENSION_ID_VALUE" ]]; then
  # Chrome launches this process with no Hawk environment. Pin the native host
  # to the private runtime, copied package, and this installation's config.
  printf '#!/usr/bin/env bash\nexport HAWK_AGENT_CONFIG=%q\nexport PYTHONPATH=%q\nexec %q -m hawk_endpoint_agent.bridge "$@"\n' \
    "$HAWK_CONFIG" "$HAWK_RUNTIME/app" "$HAWK_RUNTIME/venv/bin/python" \
    > "$HAWK_NATIVE_HOST_WRAPPER"
  chmod 755 "$HAWK_NATIVE_HOST_WRAPPER"
  if [[ ! -f "$HAWK_NATIVE_HOST_MANIFEST" || -L "$HAWK_NATIVE_HOST_MANIFEST" ]]; then
    echo "Chrome native-messaging manifest was not installed safely" >&2
    exit 1
  fi
  chmod 644 "$HAWK_NATIVE_HOST_MANIFEST"
fi

launchctl bootstrap "gui/$(id -u)" "$HAWK_PLIST"
launchctl kickstart -k "gui/$(id -u)/com.hawk.endpoint-agent"

sleep 1
"$HAWK_RUNTIME/bin/hawk-endpoint-control" --config "$HAWK_CONFIG" status

echo "Installed Hawk Endpoint Inline Control in $HAWK_ROOT"
echo "Security profile: $HAWK_SECURITY_PROFILE"
echo "Mode: $HAWK_ENDPOINT_MODE"
echo "Control command: $HAWK_RUNTIME/bin/hawk-endpoint-control --config $HAWK_CONFIG"
