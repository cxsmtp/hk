# Run Hawk AI

One Linux machine (a VM is fine) with Docker and its compose plugin. Hawk AI runs as a few containers: a front proxy
(one HTTPS address), the web console, the API, a worker and a scheduler (Celery), PostgreSQL and Redis. Everything it
keeps is in Docker volumes plus one data folder for its secrets.

## Run it

You need Ubuntu (or another Linux) with Docker, and this repository. Each command is a single line.

**Docker** (skip if `docker compose version` already works):

```
curl -fsSL https://get.docker.com | sudo sh
```

**Install and start:**

```
sudo deploy/install.sh
```

It checks Docker, creates the data folder `/var/lib/hawk-ai` (0700) and its secrets (0600 files, generated the first time only), builds the images, starts everything with `docker compose up -d`, waits until the API is ready, and prints the first administrator's email and password, once. Open <https://localhost:3000>, sign in, and choose your own password. An administrator then accepts the terms of use for the organisation; until then Hawk AI is closed. Everyone else accepts them once at their first sign-in.

**The first start's log** (the email and password are printed there too, once):

```
docker compose -f deploy/compose.yaml logs api
```

Until the administrator chooses a password it is also in a file only the API can read:

```
docker compose -f deploy/compose.yaml exec api cat /data/first-admin-password.txt
```

**No email and password in the log?** The database already has people from an earlier install, so nothing new is printed. Set a new temporary password for the administrator; it prints the email and password to sign in with:

```
docker compose -f deploy/compose.yaml exec api python -m app.cli.reset_admin
```

Add an email to reset that person instead. The server keeps running, the person chooses their own password at their next sign-in, and the reset is written to the audit log.

**HTTPS is the default.** With no certificate given, the proxy makes its own, so the browser warns once ("Your connection is not private": **Advanced**, then continue).

**From other machines:** in `deploy/.env` set `BIND_ADDRESS=0.0.0.0` and `HAWK_HOST` to the name or address people type, then run `sudo deploy/install.sh` again.

**Another port** (e.g. 8443): set `PORT=8443` in `deploy/.env`, run `sudo deploy/install.sh` again, and open <https://localhost:8443>.

**Choose the first administrator yourself:** set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `deploy/.env` before the first start (they still choose a new password at first sign-in). Or set `FIRST_ADMIN=setup-code`: the log then prints a setup code instead, and whoever has it creates the first administrator on the sign-in page.

**Automated setups:** `ACCEPT_TERMS=<your email>` in `deploy/.env` accepts the terms of use (TERMS.md) for the organisation and everyone, recorded with that email.

**Building behind a company proxy that inspects HTTPS?** Give the build its CA certificate:

```
sudo HAWK_BUILD_CA_FILE=/path/to/company-ca.pem deploy/install.sh
```

**Update without losing anything:** get the new version, then run the installer again. Secrets, settings and data are kept; the database is migrated before the API starts.

```
git pull
```

```
sudo deploy/install.sh
```

**Stop** (data kept): `docker compose -f deploy/compose.yaml down`. Only `down -v` deletes the volumes, and with them all data.

**Back up** the data folder (`/var/lib/hawk-ai`) and the database together:

```
docker compose -f deploy/compose.yaml exec -T postgres pg_dump -U hawk -Fc hawk > hawk-$(date +%F).dump
```

The first administrator's password file is never in a backup.

## What runs, and how it is hardened

| Service | Image | Notes |
|---|---|---|
| proxy | `infra/Dockerfile.proxy` (Caddy) | the only published port: `${BIND_ADDRESS:-127.0.0.1}:${PORT:-3000}`; `/` is the console, `/api/` the API |
| web | `infra/Dockerfile.web` (target `runtime`) | Next.js, started with node (no npm in the image) |
| api | `infra/Dockerfile.api` (target `runtime`) | makes the first administrator on an empty database |
| worker, beat | the API image | Celery worker and scheduler |
| migrate | the API image | brings the database to this version, then exits |
| postgres, redis | `postgres:16`, `redis:7` | not published |

Every Hawk container (proxy, web, api, worker, beat, migrate) runs as uid 1000 with a read-only file system (only its volumes and a scratch `/tmp` are writable), no Linux capabilities (`cap_drop: ALL`), `no-new-privileges`, at most 512 processes, 15 s to stop, and a health check every 30 s (5 s timeout, 20 s start period, 3 retries). The exceptions: PostgreSQL keeps the five capabilities its entrypoint needs to prepare its data folder (`CHOWN`, `SETUID`, `SETGID`, `FOWNER`, `DAC_OVERRIDE`), a writable file system and 30 s to stop; Redis runs as its own user (uid 999).

Settings are in `deploy/.env` (from `deploy/.env.example`); secrets are in `/var/lib/hawk-ai/secrets` and reach the containers as Docker secrets (`*_FILE`), never as environment variables or in this repository. The version (`VERSION`, shown as `HK-xx.xx.xx`) is bottom-left on every screen and on `/api/health`.
