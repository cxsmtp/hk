#!/usr/bin/env bash
set -euo pipefail

HAWK_PURGE="0"
if [[ "${1:-}" == "--purge-data" ]]; then
  HAWK_PURGE="1"
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--purge-data]" >&2
  exit 2
fi

HAWK_ROOT="$HOME/Library/Application Support/Hawk/EndpointAgent"
HAWK_RUNTIME="$HAWK_ROOT/runtime"
HAWK_STATE="$HAWK_ROOT/state"
HAWK_PLIST="$HOME/Library/LaunchAgents/com.hawk.endpoint-agent.plist"
HAWK_TRASH="$HOME/.Trash"
HAWK_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

launchctl bootout "gui/$(id -u)/com.hawk.endpoint-agent" 2>/dev/null || true
mkdir -p "$HAWK_TRASH"

if [[ -f "$HAWK_PLIST" ]]; then
  mv "$HAWK_PLIST" "$HAWK_TRASH/com.hawk.endpoint-agent.plist.$HAWK_STAMP"
fi
if [[ -d "$HAWK_RUNTIME" ]]; then
  mv "$HAWK_RUNTIME" "$HAWK_TRASH/Hawk-EndpointAgent-runtime-$HAWK_STAMP"
fi
if [[ "$HAWK_PURGE" == "1" ]] && [[ -d "$HAWK_STATE" ]]; then
  mv "$HAWK_STATE" "$HAWK_TRASH/Hawk-EndpointAgent-state-$HAWK_STAMP"
  echo "Endpoint state moved to Trash."
else
  echo "Endpoint state preserved at $HAWK_STATE"
fi

echo "Hawk Endpoint Inline Control was unloaded; removed material is recoverable from Trash."
