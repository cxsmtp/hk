#!/usr/bin/env bash
# Hawk AI on one Linux machine, with one command (deploy/README.md):
#
#   sudo deploy/install.sh
#
# 1. checks Docker and its compose plugin;
# 2. creates the data folder (0700) and, the first time only, its secrets (0600 files);
# 3. builds the images and starts everything: docker compose up -d;
# 4. waits until the API answers /health/ready;
# 5. prints the first administrator's sign-in from the API's log (once: the first start only).
#
# Running it again is safe: existing secrets, settings (deploy/.env) and data are never replaced or wiped. It brings
# the running stack up to this checkout (use it to update after `git pull`).
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"
WAIT_SECONDS="${HAWK_WAIT_SECONDS:-600}"

say() { printf '%s\n' "$*"; }
fail() { printf '! %s\n' "$*" >&2; exit 1; }

# Secrets are made readable by the uid of the container that uses them, which needs root.
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo --preserve-env=HAWK_DATA_DIR,HAWK_WAIT_SECONDS,HAWK_BUILD_CA_FILE bash "$0" "$@"
  fi
  fail "Run this as root (sudo deploy/install.sh)."
fi

# --- 1. Docker and compose ------------------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker is not installed. On Ubuntu: curl -fsSL https://get.docker.com | sh   then run this again."
fi
if ! docker compose version >/dev/null 2>&1; then
  fail "The Docker compose plugin is missing. On Ubuntu: apt-get install -y docker-compose-plugin   then run this again."
fi
if ! docker info >/dev/null 2>&1; then
  fail "Docker is installed but not running. Start it (systemctl start docker), then run this again."
fi

# --- 2. Settings, data folder and secrets ----------------------------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  data_dir="${HAWK_DATA_DIR:-/var/lib/hawk-ai}"
  sed "s|^HAWK_DATA_DIR=.*|HAWK_DATA_DIR=${data_dir}|" "$DEPLOY_DIR/.env.example" > "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  say "Settings written to $ENV_FILE (edit it to change the address or port, then run this again)."
fi
HAWK_DATA_DIR="$(sed -n 's/^HAWK_DATA_DIR=//p' "$ENV_FILE" | tail -n 1)"
[ -n "$HAWK_DATA_DIR" ] || fail "HAWK_DATA_DIR is empty in $ENV_FILE."
case "$HAWK_DATA_DIR" in
  /*) ;;
  *) fail "HAWK_DATA_DIR in $ENV_FILE must be an absolute path." ;;
esac
case "$HAWK_DATA_DIR/" in
  "$REPO_DIR"/*) say "! The data folder $HAWK_DATA_DIR is inside this checkout: keep it elsewhere, so it is never committed or copied with the code." ;;
esac

SECRETS="$HAWK_DATA_DIR/secrets"
umask 077
mkdir -p "$SECRETS" "$HAWK_DATA_DIR/certs"
chmod 0700 "$HAWK_DATA_DIR" "$SECRETS" "$HAWK_DATA_DIR/certs"
# Certificates given to the deployment (TLS_CERT_FILE…, docs/https-and-hosting.md): readable by the API (uid 1000) only.
chown -R 1000:1000 "$HAWK_DATA_DIR/certs"

random() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }

# write_secret NAME VALUE OWNER: only when the file is not there yet (never regenerated).
created=0
write_secret() {
  local file="$SECRETS/$1"
  if [ ! -s "$file" ]; then
    printf '%s' "$2" > "$file"
    created=$((created + 1))
  fi
  chown "$3" "$file"
  chmod 0600 "$file"
}
read_secret() { cat "$SECRETS/$1"; }

# Owners: PostgreSQL and Redis run as uid 999 in their images; the Hawk containers as uid 1000.
write_secret postgres_password "$(random 48)" 999:999
write_secret redis_password "$(random 48)" 999:999
pg="$(read_secret postgres_password)"
rd="$(read_secret redis_password)"
write_secret database_url "postgresql+psycopg2://hawk:${pg}@postgres:5432/hawk" 1000:1000
write_secret redis_url "redis://:${rd}@redis:6379/0" 1000:1000
write_secret celery_broker_url "redis://:${rd}@redis:6379/1" 1000:1000
write_secret celery_result_backend "redis://:${rd}@redis:6379/2" 1000:1000
for name in secret_key secret_key_lock_pepper connector_secrets_key connector_secrets_kdf_salt enforcement_payloads_key onprem_bundle_signing_secret; do
  write_secret "$name" "$(random 64)" 1000:1000
done
unset pg rd
if [ "$created" -gt 0 ]; then
  say "Created $created secret(s) in $SECRETS (folder 0700, files 0600). Back this folder up with the database."
else
  say "Secrets in $SECRETS kept as they are."
fi

# --- 3. Start -----------------------------------------------------------------------------------------------------
compose() { docker compose --project-directory "$DEPLOY_DIR" -f "$DEPLOY_DIR/compose.yaml" --env-file "$ENV_FILE" "$@"; }
say "Building and starting Hawk AI (the first build takes several minutes)..."
compose up -d --build --remove-orphans

# --- 4. Wait for the API ------------------------------------------------------------------------------------------
say "Waiting for the API to be ready (/health/ready)..."
deadline=$((SECONDS + WAIT_SECONDS))
until compose exec -T api python -m app.cli.healthcheck /health/ready >/dev/null 2>&1; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    compose ps || true
    compose logs --tail 40 api || true
    fail "The API was not ready after ${WAIT_SECONDS} s. See: docker compose -f $DEPLOY_DIR/compose.yaml logs api"
  fi
  sleep 5
done

# --- 5. The first administrator ------------------------------------------------------------------------------------
port="$(sed -n 's/^PORT=//p' "$ENV_FILE" | tail -n 1)"
host="$(sed -n 's/^HAWK_HOST=//p' "$ENV_FILE" | tail -n 1)"
public="$(sed -n 's/^PUBLIC_URL=//p' "$ENV_FILE" | tail -n 1)"
url="${public:-https://${host:-localhost}:${port:-3000}}"

log="$(compose logs --no-log-prefix --no-color api 2>/dev/null || true)"
rule="$(printf '=%.0s' $(seq 1 64))"
# The last 64-character "=" banner in the log, while its password is still the one to use (its file is removed when
# the administrator chooses their own).
banner=""
if compose exec -T api test -f /data/first-admin-password.txt >/dev/null 2>&1; then
  banner="$(printf '%s\n' "$log" | awk -v rule="$rule" '$0 == rule {inside = !inside; block = block $0 "\n"; if (!inside) {last = block; block = ""}; next} inside {block = block $0 "\n"} END {printf "%s", last}')"
fi
setup="$(printf '%s\n' "$log" | grep -A1 'create the first administrator with this setup code' | tail -n 1 || true)"
existing="$(printf '%s\n' "$log" | grep '\[access\] Users already set up' | tail -n 1 || true)"

say ""
say "Hawk AI is running: $url"
if [ -n "$banner" ]; then
  printf '\n%s\n' "$banner"
elif [ -n "$setup" ]; then
  say "  No users yet. Open Hawk AI and create the first administrator with this setup code:"
  say "$setup"
elif [ -n "$existing" ]; then
  say "$existing"
  say "  (docker compose -f $DEPLOY_DIR/compose.yaml exec api python -m app.cli.reset_admin)"
else
  say "No email and password in the log? The database already has people from an earlier install. Set a new"
  say "temporary password for the administrator; it prints the email and password to sign in with:"
  say "  docker compose -f $DEPLOY_DIR/compose.yaml exec api python -m app.cli.reset_admin"
fi
say ""
if printf '%s\n' "$log" | grep -q 'Self-signed certificate'; then
  say "The browser warns once about the certificate (\"Your connection is not private\": Advanced, then continue)."
  say "Your own certificate, or a free one from Let's Encrypt: Settings → HTTPS, or deploy/README.md (HTTPS)."
fi
