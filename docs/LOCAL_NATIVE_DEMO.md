# Local Native Demo Runbook

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


This profile runs the demo stack without Docker Desktop. It keeps the demo URL
stable at:

```text
https://hawk.localhost:3443
```

The local gateway routes:

- `/api/*` and `api.hawk.localhost` to the native API on `127.0.0.1:8000`
- all other routes to the native web app on `127.0.0.1:3000`

The gateway uses Caddy when it is installed. If Caddy is not installed, the
native profile falls back to a small local Node HTTPS gateway in
`infra/scripts/native-gateway.mjs`.

## Why use this for tomorrow’s demo?

Docker Desktop has been the unstable part of the local setup. The native profile
removes Docker from the live demo path while preserving the same browser URL and
product behavior.

## One-time prerequisites

Install and start host services:

```bash
brew install postgresql@16 redis node python@3.12
brew services start postgresql@16
brew services start redis
```

Install app dependencies if they are not already present:

```bash
cd "/path/to/hawk-checkout/apps/web"
npm install
```

For the API, use the existing project Python environment if present. If not,
create one and install the API requirements:

```bash
cd "/path/to/hawk-checkout/apps/api"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

If your local PostgreSQL username/password is not `postgres/postgres`, copy the
native env template and edit it:

```bash
cd "/path/to/hawk-checkout"
cp infra/local-native.env.example .env.local-native
```

## No Homebrew fallback: hybrid mode

If Homebrew is unavailable, use Docker only for PostgreSQL and Redis, and run
API/web/gateway natively. This avoids Docker image rebuilds and keeps the live
app path lighter, but it still depends on Docker Desktop for the two data
services.

First quit any old full-stack Docker run that is holding the app ports, then run:

```bash
cd "/path/to/hawk-checkout"
infra/scripts/native-up-hybrid.sh
infra/scripts/native-health.sh
```

Hybrid mode uses:

- PostgreSQL on `127.0.0.1:15432`
- Redis on `127.0.0.1:6379`
- API native on `127.0.0.1:8000`
- Web native on `127.0.0.1:3000`
- Gateway native on `https://hawk.localhost:3443`

## Start

Quit Docker Desktop first if it is still holding local ports from a prior run.
The native script will stop early if Docker is still using `3443`, `8000`, or
`3000`.

```bash
cd "/path/to/hawk-checkout"
infra/scripts/native-up.sh
```

## Check

```bash
cd "/path/to/hawk-checkout"
infra/scripts/native-health.sh
```

Open:

```text
https://hawk.localhost:3443
```

## Stop

```bash
cd "/path/to/hawk-checkout"
infra/scripts/native-stop.sh
```

## Logs

```text
infra/artifacts/native-runtime/logs/
```

The health command prints the latest log tails when something is not ready.

## Restoring existing demo data

This native profile does not delete or move Docker data. If you need to copy the
current Docker PostgreSQL data into host PostgreSQL, take a proper backup first,
then restore it into the local `aicontrol` database.

Example outline:

```bash
mkdir -p infra/artifacts/backups
docker exec ai_control_db pg_dump -U postgres -d aicontrol --format=custom > infra/artifacts/backups/aicontrol-native-demo.dump
createdb aicontrol
pg_restore --clean --if-exists -d aicontrol infra/artifacts/backups/aicontrol-native-demo.dump
```

Do this only when Docker is healthy enough to read from the database container.
The native scripts never reset Docker volumes.

## No sudo / no Homebrew / no Docker data-services fallback

Use this on a Mac where PostgreSQL is installed but the current user cannot
start system services with `sudo`, and where Docker Desktop is not reliable.

This mode starts project-owned local services only:

- PostgreSQL from `/Library/PostgreSQL/18/bin` on `127.0.0.1:55432`
- Redis from `/tmp/redis-stable/src` on `127.0.0.1:6379`
- PostgreSQL data under `/private/tmp/hawk-native-demo/postgres-data`
- Redis data under `/private/tmp/hawk-native-demo/redis-data`

The database files are intentionally not placed on the external X10 volume
because macOS AppleDouble metadata files can break PostgreSQL relation-file
creation there.

It does not touch Docker volumes or system PostgreSQL.

```bash
cd "/path/to/hawk-checkout"
infra/scripts/native-demo-serve.sh
```

Keep that Terminal window open during the demo. It is intentionally the parent
process for the local API, web app and gateway.

Stop everything started by this local profile:

```bash
cd "/path/to/hawk-checkout"
infra/scripts/native-stop.sh
```
