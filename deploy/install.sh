#!/usr/bin/env bash
# Hawk AI on one Linux machine, with one command (/settings/guide/install):
#
#   sudo deploy/install.sh
#
# 1. checks Docker and its compose plugin;
# 2. creates the data folder (0700) and, the first time only, its secrets (0600 files); on a first install it asks for
#    the address people type (HAWK_HOST, or give it: HAWK_HOST=hawk.example.com sudo deploy/install.sh);
# 3. pulls the published images (HAWK_RELEASE in deploy/.env: latest, stable or a version, this checkout's version on a
#    first install, with the updater that updates from Settings → Updates), or builds them from this checkout
#    (HAWK_BUILD=1, an empty HAWK_RELEASE on a server already installed, or when the download fails on a first
#    install), writes into deploy/.env what compose runs (so `docker compose up -d` and `run` use the same images),
#    and starts everything: docker compose up -d;
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
    exec sudo --preserve-env=HAWK_DATA_DIR,HAWK_WAIT_SECONDS,HAWK_BUILD_CA_FILE,HAWK_RELEASE,HAWK_BUILD,HAWK_HOST bash "$0" "$@"
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
  say "Settings written to $ENV_FILE (change any of them later, then run this again)."
fi

setting() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
# set_setting NAME VALUE: NAME=VALUE in deploy/.env, in place of the line that is there (else added at the end). The
# file keeps its owner and mode.
set_setting() {
  local tmp
  tmp="$(mktemp "$ENV_FILE.XXXXXX")"
  awk -v k="$1" -v v="$2" 'index($0, k "=") == 1 { if (!done) print k "=" v; done = 1; next } { print } END { if (!done) print k "=" v }' "$ENV_FILE" > "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

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
# A first install: no secrets yet (they are made once, below).
first_install=0
[ -s "$SECRETS/postgres_password" ] || first_install=1

# The address people type (HAWK_HOST). Given as HAWK_HOST=… sudo deploy/install.sh, it is written to deploy/.env. On a
# first install still on the default, asked here when someone is at the keyboard; otherwise deploy/.env says.
this_address() {
  local ip
  ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')"
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$ip" ] || ip="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
  printf '%s' "${ip:-localhost}"
}
valid_host() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'; }
use_host() {
  set_setting HAWK_HOST "$1"
  case "$1" in
    localhost|127.*) ;;
    *)
      # Other machines can reach it only when it listens on more than this machine's own address.
      if [ "$(setting BIND_ADDRESS)" = "127.0.0.1" ]; then
        set_setting BIND_ADDRESS 0.0.0.0
        say "  It answers other machines too: BIND_ADDRESS=0.0.0.0 in $ENV_FILE (allow port $(setting PORT) in the firewall)."
      fi
      ;;
  esac
  say "Address: https://$1:$(setting PORT) (HAWK_HOST in $ENV_FILE)."
}
if [ -n "${HAWK_HOST:-}" ]; then
  valid_host "$HAWK_HOST" || fail "HAWK_HOST=$HAWK_HOST is not a name or an address."
  [ "$(setting HAWK_HOST)" = "$HAWK_HOST" ] || use_host "$HAWK_HOST"
elif [ "$first_install" = 1 ] && [ -t 0 ] && { [ -z "$(setting HAWK_HOST)" ] || [ "$(setting HAWK_HOST)" = localhost ]; }; then
  suggested="$(this_address)"
  say "Which name or address will people type in their browser to reach Hawk AI?"
  say "  (Enter for $suggested; localhost keeps it to this machine only.)"
  answer=""
  for _ in 1 2 3; do
    read -r -p "  Address [$suggested]: " answer || answer=""
    answer="${answer:-$suggested}"
    valid_host "$answer" && break
    say "  $answer is not a name or an address (letters, digits, dots and dashes)."
    answer=""
  done
  use_host "${answer:-$suggested}"
fi
umask 077
mkdir -p "$SECRETS" "$HAWK_DATA_DIR/certs"
chmod 0700 "$HAWK_DATA_DIR" "$SECRETS" "$HAWK_DATA_DIR/certs"
# Certificates given to the deployment (TLS_CERT_FILE…, /settings/guide/https): readable by the API (uid 1000) only.
chown -R 1000:1000 "$HAWK_DATA_DIR/certs"
# Backups (/settings/guide/backups): BACKUP_DIR, else the data folder's backups/; written by the API and the worker.
BACKUP_DIR_HOST="$(sed -n 's/^BACKUP_DIR=//p' "$ENV_FILE" | tail -n 1)"
BACKUP_DIR_HOST="${BACKUP_DIR_HOST:-$HAWK_DATA_DIR/backups}"
case "$BACKUP_DIR_HOST" in
  /*) ;;
  *) fail "BACKUP_DIR in $ENV_FILE must be an absolute path." ;;
esac
mkdir -p "$BACKUP_DIR_HOST"
chown 1000:1000 "$BACKUP_DIR_HOST"
chmod 0700 "$BACKUP_DIR_HOST"
# Updates (/settings/guide/updates): the folder the API and the worker (uid 1000) share with the updater (root, no capabilities).
mkdir -p "$HAWK_DATA_DIR/updater"
chown 0:1000 "$HAWK_DATA_DIR/updater"
chmod 0770 "$HAWK_DATA_DIR/updater"

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

# PostgreSQL's TLS certificate (deploy/compose.yaml: ssl=on, and deploy/postgres-hba.conf refuses connections without
# TLS). Self-signed and for the name `postgres` only: the connection never leaves this machine's internal network.
# Made once, with this machine's openssl, else with the openssl in the PostgreSQL image itself.
if [ ! -s "$SECRETS/postgres_tls.key" ] || [ ! -s "$SECRETS/postgres_tls.crt" ]; then
  tls_args=(req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=postgres" -addext "subjectAltName=DNS:postgres" -keyout postgres_tls.key -out postgres_tls.crt)
  if command -v openssl >/dev/null 2>&1; then
    (cd "$SECRETS" && openssl "${tls_args[@]}" >/dev/null 2>&1) || fail "Could not make PostgreSQL's TLS certificate with openssl."
  else
    pg_image="$(sed -n 's/^    image: \(postgres:[^ ]*\)$/\1/p' "$DEPLOY_DIR/compose.yaml" | head -n 1)"
    docker run --rm --user 0:0 --network none --entrypoint openssl -v "$SECRETS:/out" -w /out "$pg_image" "${tls_args[@]}" >/dev/null 2>&1 \
      || fail "Could not make PostgreSQL's TLS certificate (install openssl, then run this again)."
  fi
  created=$((created + 2))
fi
chown 999:999 "$SECRETS/postgres_tls.key" "$SECRETS/postgres_tls.crt"
chmod 0600 "$SECRETS/postgres_tls.key"
chmod 0644 "$SECRETS/postgres_tls.crt"

if [ "$created" -gt 0 ]; then
  say "Created $created secret(s) in $SECRETS (folder 0700, files 0600). Back this folder up with the database."
else
  say "Secrets in $SECRETS kept as they are."
fi

# --- This machine against the CIS Linux benchmark (reported, never changed) -------------------------------------------
# A few items an auditor asks about first. Written to ${HAWK_DATA_DIR}/updater/host-check.json, which the API reads:
# Settings → Backups & health shows them under the self-check (/settings/guide/self-check-and-help).
host_checks=()
host_check() { # id pass|warn "what" "detail"
  host_checks+=("$(printf '{"id": "%s", "status": "%s", "title": "%s", "detail": "%s"}' "$1" "$2" "$3" "$4")")
  printf '  %-5s %s: %s\n' "$2" "$3" "$4"
}
active() { command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$1" 2>/dev/null; }
enabled() { command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet "$1" 2>/dev/null; }
check_host() {
  say "This machine (CIS Linux benchmark items, reported only; nothing is changed):"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    host_check firewall pass "Firewall" "ufw is active. Docker's published ports bypass ufw: BIND_ADDRESS limits them."
  elif active firewalld || active nftables; then
    host_check firewall pass "Firewall" "firewalld or nftables is active."
  else
    host_check firewall warn "Firewall" "No host firewall is active (ufw, firewalld or nftables). Allow only SSH and the Hawk AI ports."
  fi
  sshd_config=""
  if command -v sshd >/dev/null 2>&1; then sshd_config="$(sshd -T 2>/dev/null || true)"; fi
  if [ -z "$sshd_config" ]; then
    host_check ssh-root pass "SSH root sign-in" "No SSH server is running here."
    host_check ssh-passwords pass "SSH passwords" "No SSH server is running here."
  else
    root_login="$(printf '%s\n' "$sshd_config" | awk '$1 == "permitrootlogin" {print $2}')"
    if [ "$root_login" = "no" ]; then
      host_check ssh-root pass "SSH root sign-in" "PermitRootLogin no."
    else
      host_check ssh-root warn "SSH root sign-in" "PermitRootLogin is ${root_login:-unset}: set PermitRootLogin no in /etc/ssh/sshd_config."
    fi
    if [ "$(printf '%s\n' "$sshd_config" | awk '$1 == "passwordauthentication" {print $2}')" = "no" ]; then
      host_check ssh-passwords pass "SSH passwords" "PasswordAuthentication no: keys only."
    else
      host_check ssh-passwords warn "SSH passwords" "SSH accepts passwords: set PasswordAuthentication no and use keys."
    fi
  fi
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -Eq 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
    host_check updates pass "Automatic security updates" "unattended-upgrades is on."
  elif enabled dnf-automatic.timer || enabled dnf-automatic-install.timer; then
    host_check updates pass "Automatic security updates" "dnf-automatic is on."
  else
    host_check updates warn "Automatic security updates" "Not on: apt-get install unattended-upgrades (Debian, Ubuntu) or dnf-automatic (RHEL)."
  fi
  if command -v timedatectl >/dev/null 2>&1 && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then
    host_check time-sync pass "Time synchronisation" "The clock is synchronised (NTP)."
  elif active chronyd || active chrony || active systemd-timesyncd || active ntp || active ntpd; then
    host_check time-sync pass "Time synchronisation" "A time service is running."
  else
    host_check time-sync warn "Time synchronisation" "No time service found: logs and evidence need the right time (chrony or systemd-timesyncd)."
  fi
  if command -v lsblk >/dev/null 2>&1 && lsblk -rno TYPE 2>/dev/null | grep -qx crypt; then
    host_check disk-encryption pass "Disk encryption" "An encrypted volume (LUKS) is in use."
  else
    host_check disk-encryption warn "Disk encryption" "No LUKS volume found. A cloud disk may be encrypted by its provider: check there, and keep HAWK_DATA_DIR and BACKUP_DIR on encrypted disks."
  fi
  if active auditd; then
    host_check auditd pass "Audit daemon" "auditd is running."
  else
    host_check auditd warn "Audit daemon" "auditd is not running: apt-get install auditd (Debian, Ubuntu) or dnf install audit (RHEL)."
  fi
  local joined
  joined="$(IFS=,; printf '%s' "${host_checks[*]}")"
  printf '{"checkedAt": "%s", "by": "deploy/install.sh", "checks": [%s]}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$joined" > "$HAWK_DATA_DIR/updater/host-check.json"
  chown 0:1000 "$HAWK_DATA_DIR/updater/host-check.json"
  chmod 0640 "$HAWK_DATA_DIR/updater/host-check.json"
}
check_host || say "! The checks of this machine did not finish; installing anyway."

# --- 3. Start -----------------------------------------------------------------------------------------------------
compose() { docker compose --project-directory "$DEPLOY_DIR" -f "$DEPLOY_DIR/compose.yaml" --env-file "$ENV_FILE" "$@"; }

# What compose runs is kept in deploy/.env itself, so a plain `docker compose -f deploy/compose.yaml up -d` (or `run`)
# starts the same version as this script and never builds: the images (by digest), the updater's profile and the
# socket's group. The updater sets the images again after each update or rollback from Settings → Updates.
MANAGED_KEYS="HAWK_API_IMAGE HAWK_WEB_IMAGE HAWK_PROXY_IMAGE HAWK_UPDATER_IMAGE COMPOSE_PROFILES HAWK_DOCKER_GID"
MANAGED_NOTE="# --- Kept by deploy/install.sh and the updater: what compose runs. Do not edit: change HAWK_RELEASE instead. ---"
keep_managed() {
  local name
  grep -qxF "$MANAGED_NOTE" "$ENV_FILE" || printf '\n%s\n' "$MANAGED_NOTE" >> "$ENV_FILE"
  for name in $MANAGED_KEYS; do
    set_setting "$name" "${!name:-}"
  done
}
# Building from this folder: compose's defaults (hawk-*:local), so any earlier published images are cleared.
clear_managed() {
  local name
  for name in $MANAGED_KEYS; do
    if grep -q "^$name=" "$ENV_FILE"; then set_setting "$name" ""; fi
  done
}
# The image a tag points at now, by digest (repository@sha256:…), else the reference as it is.
by_digest() {
  local repo="${1%@*}"
  repo="${repo%:*}"
  docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$1" 2>/dev/null | grep -m 1 "^${repo}@sha256:" || printf '%s' "$1"
}

release="$(setting HAWK_RELEASE)"
release="${HAWK_RELEASE:-$release}"
# A first install with no HAWK_RELEASE runs the published images of this folder's version (VERSION), unless
# HAWK_BUILD=1 asks to build them from the folder. Later runs keep what deploy/.env says.
defaulted=0
if [ -z "$release" ] && [ "$first_install" = 1 ] && [ "${HAWK_BUILD:-}" != 1 ]; then
  checkout_version="$(tr -d ' \r\n' < "$REPO_DIR/VERSION" 2>/dev/null || true)"
  if printf '%s' "$checkout_version" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$'; then
    release="$checkout_version"
    defaulted=1
    say "Using the published images of Hawk AI $release (this folder's version). To build them from this folder instead: HAWK_BUILD=1 sudo deploy/install.sh"
  fi
fi
[ "${HAWK_BUILD:-}" = 1 ] && release=""

if [ -n "$release" ]; then
  # The published images (/settings/guide/updates): <UPDATE_IMAGE>-api, -web, -proxy and -updater at HAWK_RELEASE, and the
  # updater that updates and rolls back from Settings → Updates. After an update from that page the images it chose are
  # kept (the page's choice wins, as for HTTPS): delete ${HAWK_DATA_DIR}/updater/images.env to go back to HAWK_RELEASE.
  case "$release" in
    latest|stable) ;;
    *) printf '%s' "$release" | grep -Eq '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$' || fail "HAWK_RELEASE in $ENV_FILE is latest, stable or a version such as 0.2.0." ;;
  esac
  prefix="$(setting UPDATE_IMAGE)"
  prefix="${prefix:-ghcr.io/cxsmtp/hk}"
  export HAWK_API_IMAGE="$prefix-api:$release" HAWK_WEB_IMAGE="$prefix-web:$release" HAWK_PROXY_IMAGE="$prefix-proxy:$release" HAWK_UPDATER_IMAGE="$prefix-updater:$release"
  pins="$HAWK_DATA_DIR/updater/images.env"
  if [ -f "$pins" ]; then
    for name in HAWK_API_IMAGE HAWK_WEB_IMAGE HAWK_PROXY_IMAGE; do
      value="$(sed -n "s/^$name=//p" "$pins" | tail -n 1)"
      if printf '%s' "$value" | grep -Eq "^${prefix//./\\.}-(api|web|proxy)@sha256:[0-9a-f]{64}$"; then
        export "$name=$value"
      fi
    done
    say "Keeping the version chosen under Settings → Updates ($(sed -n 's/^HAWK_RUNNING_VERSION=//p' "$pins" | tail -n 1)); delete $pins to use HAWK_RELEASE=$release."
  fi
  export COMPOSE_PROFILES="" HAWK_DOCKER_GID=""
  if [ "$(setting HAWK_UPDATER)" != "off" ]; then
    export COMPOSE_PROFILES=updates
    # The updater runs as uid 1000 and reaches the Docker socket through the socket's group only.
    HAWK_DOCKER_GID="$(stat -c %g /var/run/docker.sock 2>/dev/null || echo 0)"
    export HAWK_DOCKER_GID
  fi
  say "Downloading and starting Hawk AI ($release)..."
  if ! pull_log="$(compose pull --quiet 2>&1)"; then
    printf '%s\n' "$pull_log" | tail -n 5 >&2
    if [ "$defaulted" = 1 ]; then
      say "! The published images of Hawk AI $release could not be downloaded (above). Building them from this folder instead: this takes several minutes."
      release=""
    else
      fail "The published images of Hawk AI $release could not be downloaded (above). Check that this machine reaches $prefix (ghcr.io) over HTTPS, or empty HAWK_RELEASE in $ENV_FILE to build the images from this folder."
    fi
  fi
fi

if [ -n "$release" ]; then
  set_setting HAWK_RELEASE "$release"
  # Exactly the images just downloaded, by digest: a tag that moves later never changes what runs.
  for name in HAWK_API_IMAGE HAWK_WEB_IMAGE HAWK_PROXY_IMAGE HAWK_UPDATER_IMAGE; do
    export "$name=$(by_digest "${!name}")"
  done
  # The api, worker, beat and migrate containers are on two networks (deploy/compose.yaml); an updater made before
  # that could not put them back after an update. Such an updater is not started: update with this script instead.
  if [ "${COMPOSE_PROFILES:-}" = updates ] && [ "$(docker image inspect -f '{{ index .Config.Labels "org.cxsmtp.hawk.updater.networks" }}' "$HAWK_UPDATER_IMAGE" 2>/dev/null)" != "many" ]; then
    say "! The updater in $release predates this folder's compose.yaml: Settings → Updates is off; update with deploy/install.sh."
    COMPOSE_PROFILES=updates compose rm --stop --force updater >/dev/null 2>&1 || true
    export COMPOSE_PROFILES=""
  fi
  keep_managed
  if [ "${COMPOSE_PROFILES:-}" = updates ]; then
    # The updater rewrites the images in deploy/.env after an update: the file is the socket group's too, whose
    # members already control Docker (and so this machine). Without the updater it stays root's alone.
    chown "0:$HAWK_DOCKER_GID" "$ENV_FILE"
    chmod 0660 "$ENV_FILE"
  else
    chown 0:0 "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
  fi
  compose up -d --no-build --remove-orphans
else
  unset HAWK_API_IMAGE HAWK_WEB_IMAGE HAWK_PROXY_IMAGE HAWK_UPDATER_IMAGE
  export COMPOSE_PROFILES=""
  clear_managed
  chown 0:0 "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  say "Building and starting Hawk AI (the first build takes several minutes)..."
  compose up -d --build --remove-orphans
fi

# --- 4. Wait for the API ------------------------------------------------------------------------------------------
# Self-recovery while installing (/settings/guide/troubleshooting#not-ready): when the API is not ready in time, the
# logs say why; one fix is tried for what they say, then it waits once more. What happened is kept in the updater
# folder (install-status.json, install.log), which the API's self-recovery reads and the diagnostics bundle carries.
INSTALL_NOTES="$HAWK_DATA_DIR/updater"
install_status() {
  mkdir -p "$INSTALL_NOTES"
  printf '{"at":"%s","state":"%s","reason":"%s","action":"%s","release":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$3" "${release:-source}" > "$INSTALL_NOTES/install-status.json.tmp"
  chmod 0644 "$INSTALL_NOTES/install-status.json.tmp"
  mv "$INSTALL_NOTES/install-status.json.tmp" "$INSTALL_NOTES/install-status.json"
  cat "$INSTALL_NOTES/install-status.json" >> "$INSTALL_NOTES/install.log"
}
install_log() {
  # The services' own lines are already redacted by Hawk AI's logging (app/core/log_config.py); the last 2000 are kept.
  { printf '=== %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; compose ps 2>&1 || true; compose logs --no-color --tail 60 migrate api 2>&1 || true; } >> "$INSTALL_NOTES/install.log"
  tail -n 2000 "$INSTALL_NOTES/install.log" > "$INSTALL_NOTES/install.log.tmp" && mv "$INSTALL_NOTES/install.log.tmp" "$INSTALL_NOTES/install.log"
  chmod 0644 "$INSTALL_NOTES/install.log"
}
wait_ready() {
  local deadline=$((SECONDS + $1))
  until compose exec -T api python -m app.cli.healthcheck /health/ready >/dev/null 2>&1; do
    [ "$SECONDS" -ge "$deadline" ] && return 1
    sleep 5
  done
}
diagnose() {
  local logs
  logs="$(compose logs --no-color --tail 200 migrate api postgres 2>&1 || true)"
  if printf '%s' "$logs" | grep -qi 'no space left on device'; then echo disk-full
  elif compose ps -a migrate 2>/dev/null | grep -qiE 'exited \([1-9]'; then echo migrate-failed
  elif printf '%s' "$logs" | grep -qiE 'could not connect to server|connection refused|the database system is starting up'; then echo database-not-ready
  else echo api-not-ready
  fi
}
recover() {
  local up_flags="--build"
  [ -n "$release" ] && up_flags="--no-build"
  case "$1" in
    disk-full) docker image prune -f >/dev/null 2>&1 || true; docker builder prune -f >/dev/null 2>&1 || true; echo "removed unused images and build cache" ;;
    migrate-failed) compose up -d --force-recreate --no-deps migrate >/dev/null 2>&1 || true; compose up -d $up_flags >/dev/null 2>&1 || true; echo "ran the migrations again" ;;
    database-not-ready) compose restart postgres >/dev/null 2>&1 || true; compose up -d $up_flags >/dev/null 2>&1 || true; echo "restarted the database" ;;
    *) compose restart api >/dev/null 2>&1 || true; echo "restarted the api" ;;
  esac
}

say "Waiting for the API to be ready (/health/ready)..."
if ! wait_ready "$WAIT_SECONDS"; then
  reason="$(diagnose)"
  install_log
  say "! The API was not ready after ${WAIT_SECONDS} s ($reason). Trying to put it right..."
  action="$(recover "$reason")"
  say "  It $action; waiting once more."
  if ! wait_ready "$WAIT_SECONDS"; then
    install_log
    install_status failed "$reason" "$action"
    compose ps || true
    compose logs --tail 40 api || true
    fail "The API was not ready after ${WAIT_SECONDS} s, even after it $action. What happened is in $INSTALL_NOTES/install.log; once the API answers, Settings → Backups & health has the diagnostics bundle to send to the OEM. See: docker compose -f $DEPLOY_DIR/compose.yaml logs api"
  fi
  install_status recovered "$reason" "$action"
  say "  It worked: the API is ready."
else
  install_status ok "" ""
fi

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
  say "Your own certificate, or a free one from Let's Encrypt: Settings → HTTPS, or /settings/guide/https."
fi
