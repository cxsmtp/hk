#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -z "${TEST_PYTHON:-}" ]]; then
  if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
    TEST_PYTHON="$VIRTUAL_ENV/bin/python"
  fi
  for candidate in "$REPO_ROOT/.venv/bin/python" "$REPO_ROOT/apps/api/.venv/bin/python"; do
    [[ -n "${TEST_PYTHON:-}" ]] && break
    if [[ -x "$candidate" ]]; then TEST_PYTHON="$candidate"; break; fi
  done
  TEST_PYTHON="${TEST_PYTHON:-$(command -v python3 || true)}"
fi
if [[ ! -x "$TEST_PYTHON" ]]; then
  echo "Create the API development virtual environment before running these tests." >&2
  exit 1
fi

echo "Synthetic Claude Enterprise tests only; no MDM, proxy, certificate, or CrowdStrike changes."
(
  cd "$REPO_ROOT/apps/endpoint-agent"
  PYTHONPATH=src "$TEST_PYTHON" -m pytest -q tests/test_claude_enterprise_boundary.py
)
(
  cd "$REPO_ROOT/apps/api"
  "$TEST_PYTHON" -m pytest -q tests/test_claude_enterprise_inference.py
)
