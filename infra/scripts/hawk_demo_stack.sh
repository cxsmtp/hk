#!/usr/bin/env bash
set -euo pipefail

HAWK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAWK_REPO_ROOT="$(cd "$HAWK_SCRIPT_DIR/../.." && pwd)"
HAWK_COMPOSE_FILES="${HAWK_COMPOSE_FILES:-$HAWK_REPO_ROOT/infra/docker-compose.demo.yml}"
HAWK_ENV_FILE="${HAWK_ENV_FILE:-$HAWK_REPO_ROOT/.env}"
HAWK_PROJECT_NAME="${HAWK_PROJECT_NAME:-hawk-demo}"
HAWK_POSTGRES_VOLUME="${HAWK_POSTGRES_VOLUME:-hawk_demo_postgres_data}"

if [[ ! -f "$HAWK_ENV_FILE" ]]; then
  echo "Hawk root .env is missing: $HAWK_ENV_FILE" >&2
  exit 1
fi

hawk_compose() {
  local HAWK_COMPOSE_ARGS=(--project-name "$HAWK_PROJECT_NAME" --env-file "$HAWK_ENV_FILE")
  local HAWK_COMPOSE_ENTRY
  local HAWK_COMPOSE_LIST=()
  IFS=':' read -r -a HAWK_COMPOSE_LIST <<< "$HAWK_COMPOSE_FILES"
  for HAWK_COMPOSE_ENTRY in "${HAWK_COMPOSE_LIST[@]}"; do
    if [[ ! -f "$HAWK_COMPOSE_ENTRY" ]]; then
      echo "Hawk Compose file is missing: $HAWK_COMPOSE_ENTRY" >&2
      exit 1
    fi
    HAWK_COMPOSE_ARGS+=(-f "$HAWK_COMPOSE_ENTRY")
  done
  docker compose "${HAWK_COMPOSE_ARGS[@]}" "$@"
}

hawk_env_value() {
  local HAWK_ENV_KEY="$1"
  awk -v key="$HAWK_ENV_KEY" '
    index($0, key "=") == 1 {
      print substr($0, length(key) + 2)
      found = 1
      exit
    }
    END { if (!found) exit 1 }
  ' "$HAWK_ENV_FILE"
}

hawk_require_secret() {
  local HAWK_ENV_KEY="$1"
  local HAWK_DEFAULT_VALUE="$2"
  local HAWK_MIN_LENGTH="$3"
  local HAWK_SECRET_VALUE
  HAWK_SECRET_VALUE="$(hawk_secret_value "$HAWK_ENV_KEY")"
  if [[ "$HAWK_SECRET_VALUE" == "$HAWK_DEFAULT_VALUE" || ${#HAWK_SECRET_VALUE} -lt $HAWK_MIN_LENGTH ]]; then
    echo "Refusing to start with an absent, short, or documented default secret: $HAWK_ENV_KEY" >&2
    exit 1
  fi
}

hawk_secret_value() {
  local HAWK_SECRET_KEY="$1"
  local HAWK_DIRECT_VALUE=""
  local HAWK_FILE_VALUE=""
  HAWK_DIRECT_VALUE="$(hawk_env_value "$HAWK_SECRET_KEY" 2>/dev/null || true)"
  HAWK_FILE_VALUE="$(hawk_env_value "${HAWK_SECRET_KEY}_FILE" 2>/dev/null || true)"
  if [[ -n "$HAWK_DIRECT_VALUE" && -n "$HAWK_FILE_VALUE" ]]; then
    echo "Refusing both $HAWK_SECRET_KEY and ${HAWK_SECRET_KEY}_FILE." >&2
    exit 1
  fi
  if [[ -n "$HAWK_DIRECT_VALUE" ]]; then
    printf '%s' "$HAWK_DIRECT_VALUE"
    return
  fi
  if [[ -z "$HAWK_FILE_VALUE" || "$HAWK_FILE_VALUE" != /* || ! -f "$HAWK_FILE_VALUE" || -L "$HAWK_FILE_VALUE" ]]; then
    echo "Required Hawk secret reference is missing or unsafe: ${HAWK_SECRET_KEY}_FILE" >&2
    exit 1
  fi
  local HAWK_SECRET_SIZE
  HAWK_SECRET_SIZE="$(wc -c < "$HAWK_FILE_VALUE" | tr -d ' ')"
  if [[ "$HAWK_SECRET_SIZE" -le 0 || "$HAWK_SECRET_SIZE" -gt 65536 ]]; then
    echo "Hawk secret file size is invalid: ${HAWK_SECRET_KEY}_FILE" >&2
    exit 1
  fi
  if [[ -n "$(find "$HAWK_FILE_VALUE" -prune -perm -0022 -print)" ]]; then
    echo "Hawk secret file must not be group/world writable: ${HAWK_SECRET_KEY}_FILE" >&2
    exit 1
  fi
  tr -d '\r\n' < "$HAWK_FILE_VALUE"
}

hawk_require_distinct_secrets() {
  local HAWK_SECRET_KEYS=(
    "POSTGRES_PASSWORD"
    "SECRET_KEY"
    "SECRET_KEY_LOCK_PEPPER"
    "CONNECTOR_SECRETS_KEY"
    "CONNECTOR_SECRETS_KDF_SALT"
    "ENFORCEMENT_PAYLOADS_KEY"
    "ONPREM_BUNDLE_SIGNING_SECRET"
  )
  local HAWK_SECRET_VALUES=()
  local HAWK_SECRET_KEY
  local HAWK_LEFT_INDEX
  local HAWK_RIGHT_INDEX
  for HAWK_SECRET_KEY in "${HAWK_SECRET_KEYS[@]}"; do
    HAWK_SECRET_VALUES+=("$(hawk_secret_value "$HAWK_SECRET_KEY")")
  done
  for ((HAWK_LEFT_INDEX = 0; HAWK_LEFT_INDEX < ${#HAWK_SECRET_KEYS[@]}; HAWK_LEFT_INDEX++)); do
    for ((HAWK_RIGHT_INDEX = HAWK_LEFT_INDEX + 1; HAWK_RIGHT_INDEX < ${#HAWK_SECRET_KEYS[@]}; HAWK_RIGHT_INDEX++)); do
      if [[ "${HAWK_SECRET_VALUES[$HAWK_LEFT_INDEX]}" == "${HAWK_SECRET_VALUES[$HAWK_RIGHT_INDEX]}" ]]; then
        echo "Refusing to reuse secret material across ${HAWK_SECRET_KEYS[$HAWK_LEFT_INDEX]} and ${HAWK_SECRET_KEYS[$HAWK_RIGHT_INDEX]}" >&2
        exit 1
      fi
    done
  done
}

hawk_validate_config() {
  hawk_require_secret "POSTGRES_PASSWORD" "postgres" 24
  hawk_require_secret "SECRET_KEY" "change-me-super-secret" 32
  hawk_require_secret "SECRET_KEY_LOCK_PEPPER" "replace-with-distinct-lock-pepper" 32
  hawk_require_secret "CONNECTOR_SECRETS_KEY" "replace-with-32-byte-random-value" 32
  hawk_require_secret "CONNECTOR_SECRETS_KDF_SALT" "replace-with-distinct-kdf-salt" 32
  hawk_require_secret "ENFORCEMENT_PAYLOADS_KEY" "replace-with-distinct-payload-key" 32
  hawk_require_secret "ONPREM_BUNDLE_SIGNING_SECRET" "replace-with-distinct-signing-secret" 32
  hawk_require_distinct_secrets
  if [[ "$(hawk_env_value "DEPLOYMENT_TOPOLOGY" 2>/dev/null || true)" == "single_node_compose" ]]; then
    hawk_require_secret "DATABASE_URL" "" 24
    hawk_require_secret "REDIS_URL" "" 20
    hawk_require_secret "CELERY_BROKER_URL" "" 20
    hawk_require_secret "CELERY_RESULT_BACKEND" "" 20
  fi
  hawk_compose config --quiet
}

hawk_assert_volume_ownership() {
  if ! docker volume inspect "$HAWK_POSTGRES_VOLUME" >/dev/null 2>&1; then
    return
  fi
  local HAWK_VOLUME_PROJECT
  local HAWK_VOLUME_KEY
  HAWK_VOLUME_PROJECT="$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$HAWK_POSTGRES_VOLUME")"
  HAWK_VOLUME_KEY="$(docker volume inspect --format '{{ index .Labels "com.docker.compose.volume" }}' "$HAWK_POSTGRES_VOLUME")"
  if [[ "$HAWK_VOLUME_PROJECT" != "$HAWK_PROJECT_NAME" || "$HAWK_VOLUME_KEY" != "hawk_demo_postgres_data" ]]; then
    echo "Refusing to reuse unverified Docker volume: $HAWK_POSTGRES_VOLUME" >&2
    exit 1
  fi
}

hawk_stage_build_context() {
  if ! command -v rsync >/dev/null 2>&1; then
    echo "rsync is required to create the sanitized Hawk Docker build context." >&2
    exit 1
  fi
  local HAWK_TEMP_ROOT="${TMPDIR:-/tmp}"
  HAWK_BUILD_CONTEXT="${HAWK_TEMP_ROOT%/}/hawk-demo-build-context"
  case "$HAWK_BUILD_CONTEXT" in
    */hawk-demo-build-context) ;;
    *)
      echo "Refusing unexpected Hawk build-context path: $HAWK_BUILD_CONTEXT" >&2
      exit 1
      ;;
  esac
  mkdir -p \
    "$HAWK_BUILD_CONTEXT/apps/api" \
    "$HAWK_BUILD_CONTEXT/apps/web" \
    "$HAWK_BUILD_CONTEXT/docs/evidence" \
    "$HAWK_BUILD_CONTEXT/packages" \
    "$HAWK_BUILD_CONTEXT/infra/scripts"
  export COPYFILE_DISABLE=1
  local HAWK_RSYNC_ARGS=(
    -a
    --delete
    --delete-excluded
    --exclude="._*"
    --exclude="__pycache__"
    --exclude="*.pyc"
    --exclude=".pytest_cache"
    --exclude=".env*"
    --exclude="*.db*"
    --exclude="*.sqlite*"
    --exclude="*.dump"
    --exclude=".DS_Store"
    --exclude=".coverage"
    --exclude=".appledouble-*"
    --exclude="tsconfig.tsbuildinfo"
  )
  rsync "${HAWK_RSYNC_ARGS[@]}" \
    --exclude=".venv" \
    --exclude=".runtime" \
    --exclude="artifacts" \
    --exclude="tests" \
    "$HAWK_REPO_ROOT/apps/api/" "$HAWK_BUILD_CONTEXT/apps/api/"
  rsync "${HAWK_RSYNC_ARGS[@]}" \
    --exclude="node_modules" \
    --exclude=".next*" \
    --exclude="tests" \
    "$HAWK_REPO_ROOT/apps/web/" "$HAWK_BUILD_CONTEXT/apps/web/"
  rsync "${HAWK_RSYNC_ARGS[@]}" \
    --exclude="node_modules" \
    "$HAWK_REPO_ROOT/packages/" "$HAWK_BUILD_CONTEXT/packages/"
  rsync "${HAWK_RSYNC_ARGS[@]}" \
    "$HAWK_REPO_ROOT/docs/evidence/" "$HAWK_BUILD_CONTEXT/docs/evidence/"
  rsync "${HAWK_RSYNC_ARGS[@]}" \
    "$HAWK_REPO_ROOT/infra/scripts/" "$HAWK_BUILD_CONTEXT/infra/scripts/"
  rsync -a \
    "$HAWK_REPO_ROOT/infra/Dockerfile.api" \
    "$HAWK_REPO_ROOT/infra/Dockerfile.web.demo" \
    "$HAWK_REPO_ROOT/infra/Dockerfile.local-production-gateway" \
    "$HAWK_REPO_ROOT/infra/Caddyfile.local-production" \
    "$HAWK_BUILD_CONTEXT/infra/"
  export HAWK_BUILD_CONTEXT
}

HAWK_ACTION="${1:-status}"
case "$HAWK_ACTION" in
  validate)
    hawk_validate_config
    ;;
  stage)
    hawk_validate_config
    hawk_stage_build_context
    echo "$HAWK_BUILD_CONTEXT"
    ;;
  build)
    hawk_validate_config
    hawk_stage_build_context
    hawk_compose build
    ;;
  prepare)
    hawk_validate_config
    hawk_assert_volume_ownership
    hawk_stage_build_context
    hawk_compose build
    hawk_compose up -d db redis
    hawk_compose run --rm --no-deps migrate
    hawk_compose run --rm --no-deps seed-demo
    ;;
  up)
    hawk_validate_config
    hawk_assert_volume_ownership
    hawk_compose up -d --wait --wait-timeout 180 api worker celery-beat web
    ;;
  status)
    hawk_compose ps
    ;;
  recover)
    hawk_validate_config
    hawk_assert_volume_ownership
    hawk_compose restart api worker celery-beat web
    hawk_compose up -d --wait --wait-timeout 180 api worker celery-beat web
    ;;
  backup)
    hawk_validate_config
    hawk_assert_volume_ownership
    HAWK_BACKUP_DIR="$HAWK_REPO_ROOT/infra/artifacts/backups"
    mkdir -p "$HAWK_BACKUP_DIR"
    chmod 700 "$HAWK_BACKUP_DIR"
    HAWK_BACKUP_TIME="$(date -u +%Y%m%dT%H%M%SZ)"
    HAWK_BACKUP_PATH="$HAWK_BACKUP_DIR/hawk-demo-$HAWK_BACKUP_TIME.dump"
    HAWK_BACKUP_TEMP="$HAWK_BACKUP_PATH.partial"
    hawk_compose exec -T db sh -lc 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$HAWK_BACKUP_TEMP"
    if [[ ! -s "$HAWK_BACKUP_TEMP" ]]; then
      echo "PostgreSQL backup is empty; retained for diagnosis: $HAWK_BACKUP_TEMP" >&2
      exit 1
    fi
    chmod 600 "$HAWK_BACKUP_TEMP"
    mv "$HAWK_BACKUP_TEMP" "$HAWK_BACKUP_PATH"
    echo "$HAWK_BACKUP_PATH"
    ;;
  restore-verify)
    hawk_validate_config
    hawk_assert_volume_ownership
    HAWK_BACKUP_DIR="$HAWK_REPO_ROOT/infra/artifacts/backups"
    HAWK_BACKUP_PATH="${2:-}"
    if [[ -z "$HAWK_BACKUP_PATH" ]]; then
      HAWK_BACKUP_PATH="$(find "$HAWK_BACKUP_DIR" -maxdepth 1 -type f -name 'hawk-demo-*.dump' -print | sort | tail -n 1)"
    fi
    case "$HAWK_BACKUP_PATH" in
      "$HAWK_BACKUP_DIR"/hawk-demo-*.dump) ;;
      *) echo "Restore verification accepts only Hawk backups under $HAWK_BACKUP_DIR" >&2; exit 1 ;;
    esac
    if [[ ! -s "$HAWK_BACKUP_PATH" ]]; then
      echo "Restore verification backup is missing or empty." >&2
      exit 1
    fi
    HAWK_RESTORE_DB="hawk_restore_verify_$(date -u +%Y%m%d%H%M%S)_$$"
    HAWK_POSTGRES_USER="$(hawk_env_value POSTGRES_USER)"
    (
      trap 'hawk_compose exec -T db dropdb -U "$HAWK_POSTGRES_USER" --if-exists "$HAWK_RESTORE_DB" >/dev/null 2>&1 || true' EXIT
      hawk_compose exec -T db createdb -U "$HAWK_POSTGRES_USER" "$HAWK_RESTORE_DB"
      hawk_compose exec -T db pg_restore -U "$HAWK_POSTGRES_USER" --exit-on-error --no-owner --no-privileges -d "$HAWK_RESTORE_DB" < "$HAWK_BACKUP_PATH"
      hawk_compose exec -T db psql -U "$HAWK_POSTGRES_USER" -d "$HAWK_RESTORE_DB" -v ON_ERROR_STOP=1 -Atc \
        "SELECT 'revision=' || version_num FROM alembic_version; SELECT 'tenants=' || count(*) FROM tenants; SELECT 'evidence=' || count(*) FROM evidence_nodes;"
    )
    ;;
  bootstrap-admin)
    hawk_validate_config
    if [[ "$#" -ne 5 ]]; then
      echo "Usage: $0 bootstrap-admin <email> <full-name> <tenant-name> <tenant-slug>" >&2
      exit 2
    fi
    IFS= read -r -s -p "Initial administrator password: " HAWK_INITIAL_ADMIN_PASSWORD
    echo
    IFS= read -r -s -p "Confirm initial administrator password: " HAWK_INITIAL_ADMIN_PASSWORD_CONFIRM
    echo
    if [[ "$HAWK_INITIAL_ADMIN_PASSWORD" != "$HAWK_INITIAL_ADMIN_PASSWORD_CONFIRM" ]]; then
      unset HAWK_INITIAL_ADMIN_PASSWORD HAWK_INITIAL_ADMIN_PASSWORD_CONFIRM
      echo "Initial administrator passwords do not match." >&2
      exit 1
    fi
    printf '%s\n' "$HAWK_INITIAL_ADMIN_PASSWORD" | hawk_compose exec -T api \
      python /workspace/infra/scripts/production_bootstrap.py \
      --create-initial-admin \
      --password-stdin \
      --email "$2" \
      --full-name "$3" \
      --tenant-name "$4" \
      --tenant-slug "$5"
    unset HAWK_INITIAL_ADMIN_PASSWORD HAWK_INITIAL_ADMIN_PASSWORD_CONFIRM
    ;;
  logs)
    shift || true
    hawk_compose logs --tail=200 "$@"
    ;;
  down)
    hawk_compose down --remove-orphans
    ;;
  *)
    echo "Usage: $0 {validate|stage|build|prepare|up|status|recover|backup|restore-verify [backup]|bootstrap-admin <email> <full-name> <tenant-name> <tenant-slug>|logs|down}" >&2
    exit 2
    ;;
esac
