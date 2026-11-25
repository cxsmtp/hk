#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0 2>/dev/null || true

HAWK_WRAPPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAWK_RUNTIME="$(cd "$HAWK_WRAPPER_DIR/.." && pwd)"
export PYTHONPATH="$HAWK_RUNTIME/app"
exec "$HAWK_RUNTIME/venv/bin/python" -m hawk_endpoint_agent.operator_cli "$@"
