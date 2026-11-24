#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
  "$SCRIPT_DIR/native-stop.sh" >/dev/null 2>&1 || true
}
trap cleanup INT TERM

"$SCRIPT_DIR/native-up-user-services.sh"

echo ""
echo "Native demo is running. Keep this Terminal window open."
echo "Open https://hawk.localhost:3443"
echo "Press Control-C here to stop the local demo stack."
echo "If this launcher exits unexpectedly, services are left running; use infra/scripts/native-stop.sh to stop them."
echo ""

for attempt in {1..12}; do
  if "$SCRIPT_DIR/native-health.sh"; then
    break
  fi
  if [[ "$attempt" == "12" ]]; then
    echo "Native demo started, but health is not fully green yet. Keep this window open and rerun infra/scripts/native-health.sh from another Terminal."
    break
  fi
  echo "Waiting for local services to become healthy..."
  sleep 5
done

tail -F \
  "$SCRIPT_DIR/../artifacts/native-runtime/logs/api.log" \
  "$SCRIPT_DIR/../artifacts/native-runtime/logs/web.log" \
  "$SCRIPT_DIR/../artifacts/native-runtime/logs/gateway.log"
