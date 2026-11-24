#!/usr/bin/env bash
# Run one local test service in the foreground. No credentials are printed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/native-demo-env.sh"
REPO_ROOT="$(native_demo_repo_root)"
native_demo_load_env "$REPO_ROOT"
export ARTIFACT_DIR="$REPO_ROOT/artifacts"
# Alembic's script_location is relative to the API directory.
cd "$REPO_ROOT/apps/api"
case "${1:-}" in
  api)
    export COMPONENT_TYPE=api
    export OPENAI_API_KEY=ollama-local
    export OPENAI_BASE_URL=https://api.hawk.localhost:11435/v1
    export OPENAI_MODEL=qwen3.5:9b LLM_MODEL=qwen3.5:9b
    export LLM_TIMEOUT_SECS=180 LLM_MAX_TOKENS=4096
    export SSL_CERT_FILE="$REPO_ROOT/infra/tls/local/hawk-local.crt"
    exec "$NATIVE_PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port 8001
    ;;
  worker)
    export COMPONENT_TYPE=worker
    exec "$NATIVE_PYTHON" -m celery -A app.jobs.celery_app.celery_app worker --pool=solo --concurrency=1 --loglevel=warning -Q default,monitoring,auditor,discovery --hostname=hawk-local-test@%h
    ;;
  beat)
    export COMPONENT_TYPE=celery_beat
    exec "$NATIVE_PYTHON" -m celery -A app.jobs.celery_app.celery_app beat --loglevel=warning --schedule="$REPO_ROOT/infra/artifacts/native-runtime/llm-test-celerybeat"
    ;;
  *) echo "Usage: bash infra/scripts/local-llm-test-service.sh {api|worker|beat}" >&2; exit 2 ;;
esac
