#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

declare -a STEPS=(
  "test-unit"
  "test-integration"
  "test-enterprise"
  "test-report"
)

FAILED=0
PASSED=0

for STEP in "${STEPS[@]}"; do
  echo
  echo "=== [full-suite] running: $STEP ==="
  if make "$STEP"; then
    PASSED=$((PASSED + 1))
    echo "=== [full-suite] $STEP: PASS ==="
  else
    FAILED=$((FAILED + 1))
    echo "=== [full-suite] $STEP: FAIL ==="
  fi
done

echo
echo "===== Full Suite Summary ====="
echo "total: ${#STEPS[@]}"
echo "passed: $PASSED"
echo "failed: $FAILED"

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
