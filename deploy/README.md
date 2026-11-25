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

**HTTPS is the default.** With no certificate given, Hawk AI makes a self-signed one, so the browser warns once ("Your connection is not private": **Advanced**, then continue). Your own certificate, or a free one from Let's Encrypt: [HTTPS](#https) below.

**From other machines:** in `deploy/.env` set `BIND_ADDRESS=0.0.0.0` and `HAWK_HOST` to the name or address people type, then run `sudo deploy/install.sh` again.

**Another port** (e.g. 8443): set `PORT=8443` in `deploy/.env`, run `sudo deploy/install.sh` again, and open <https://localhost:8443>.

**Choose the first administrator yourself:** set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `deploy/.env` before the first start (they still choose a new password at first sign-in). Or set `FIRST_ADMIN=setup-code`: the log then prints a setup code instead, and whoever has it creates the first administrator on the sign-in page.

**Automated setups:** `ACCEPT_TERMS=<your email>` in `deploy/.env` accepts the terms of use (TERMS.md) for the organisation and everyone, recorded with that email.

**Building behind a company proxy that inspects HTTPS?** Give the build its CA certificate:

```
sudo HAWK_BUILD_CA_FILE=/path/to/company-ca.pem deploy/install.sh
```

**Update without losing anything:** from the console, under **Settings → Updates**, when Hawk AI runs the published images ([Updates](#updates) below). From a checkout: get the new version, then run the installer again. Secrets, settings and data are kept; the database is migrated before the API starts.

```
git pull
```

```
sudo deploy/install.sh
```

**Stop** (data kept): `docker compose -f deploy/compose.yaml down`. Only `down -v` deletes the volumes, and with them all data.

**Backups are automatic:** one a minute after start, then every 24 hours, and one each time the API stops, into `/var/lib/hawk-ai/backups`, encrypted. An owner or admin saves the backup key under **Settings → Backups & health**: [Backups](#backups) below.

## Updates

**Run the published images** (signed by this repository's release workflow) instead of building them: in `deploy/.env` set `HAWK_RELEASE=stable` (the release the maintainer promoted), `latest` (every merged release) or a version such as `0.2.0`, then:

```
sudo deploy/install.sh
```

It pulls `ghcr.io/cxsmtp/hk-api`, `-web`, `-proxy` and `-updater` and starts the **updater**. Owners and admins then update and roll back from **Settings → Updates**: every published version is listed, **Update now** or **Roll back to this** in one click, auto-update (off until turned on) at an hour of the day you choose. Before each update the updater checks the images' signatures and files, takes a backup, migrates the database and starts every service; if Hawk AI is not healthy within 150 s it puts the previous version back by itself, with its database. The whole story, the channels and the variables: [docs/updating.md](../docs/updating.md); what is checked: [docs/integrity.md](../docs/integrity.md).

**Check what runs is what was released:**

```
docker compose -f deploy/compose.yaml exec api python -m app.cli.integrity check --origin
```

## Backups

A backup is one `.hkbackup` file: the whole database (`pg_dump`, custom format) and the API's data folder (the HTTPS choices and certificates), gzipped, with a SHA-256 per file and over the whole set. A damaged backup is refused whole, never half-restored. The backup key itself, the backups, and the first administrator's one-time password file are never in a backup. The application keys the database depends on (connector secrets, signing keys) are.

**When.** One minute after the scheduler starts, then every `BACKUP_INTERVAL_HOURS` (24), and before every version switch from Settings → Updates (the updater's, "Before the update to HK-…"); the newest `BACKUP_KEEP` (14) are kept. By hand: **Back up now** on the Settings page, or:

```
docker compose -f deploy/compose.yaml exec api python -m app.cli.backup
```

**Before stopping.** When the API is stopped (`docker compose stop` or `down`, `install.sh` updating it), it makes one more backup and, with an email server set, emails the administrators (the backup attached only when it is encrypted; at most once every `LAST_WORDS_EVERY_HOURS`, 6). It has the 15 s Docker gives a container to stop: a very large database may not fit, and a forced kill or a power cut cannot be caught, so the scheduled backups are what to rely on.

**Where.** `BACKUP_DIR` in `deploy/.env` (default `/var/lib/hawk-ai/backups`). Put it on another disk or a network share, so losing one disk does not lose both: the Settings page warns while they share one. Then run `sudo deploy/install.sh` again.

**Encrypted by default** (AES-256-GCM, the key from scrypt):

| The server has | Backups are |
|---|---|
| `BACKUP_PASSPHRASE` set | encrypted with that passphrase |
| no passphrase, a new installation | encrypted with **the server's own backup key** |
| no passphrase, an installation from before | not encrypted, until an owner or admin chooses **Turn on backup encryption** (Settings → Backups & health); `BACKUP_ENCRYPTION=off` keeps them plain on purpose |

New or existing is decided once, at the first start. **Save the backup key:** under Settings → Backups & health, **Show backup key**, then **Copy** or **Download as a text file**, keep it away from the server (a password manager, a safe), and confirm **I have saved it**. Until someone does, owners and admins see a notice on every page. Each showing is written to the audit log; the key is never emailed, logged or put in a backup. Without it (or `BACKUP_PASSPHRASE`), a backup cannot be opened on another server.

**The backup mailbox.** With `BACKUP_EMAIL` and an email server (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` in `deploy/.env`), every encrypted backup up to 15 MB is also emailed there, with a subject starting "Hawk AI backup". A plain backup is never emailed.

**Rebuild from the mailbox.** On a new server, before the first start, set in `deploy/.env` the same `BACKUP_EMAIL`, its `BACKUP_EMAIL_PASSWORD`, and `BACKUP_PASSPHRASE` (the old passphrase, or the backup key an admin saved); the mailbox server is `BACKUP_EMAIL_IMAP_HOST` (default `SMTP_HOST`) on `BACKUP_EMAIL_IMAP_PORT` (993; another port must offer STARTTLS). Then `sudo deploy/install.sh`. Before anything else starts, the new server reads the newest 20 emails whose subject starts "Hawk AI backup" (reading only, 90 s at most), restores the newest backup that opens with the passphrase, and writes it to the audit log. It does this only while its database has nobody in it.

## Restore

**Check a backup** (writes nothing; Hawk AI can be running). Backups in `BACKUP_DIR` are `/backups/<file>` inside the containers:

```
docker compose -f deploy/compose.yaml exec api python -m app.cli.restore /backups/hawk-ai-2026-11-25T02-00-00.hkbackup
```

**Restore it.** API, worker and scheduler stop (PostgreSQL stays up), the restore runs in a one-off container of the same image, and Hawk AI starts again:

```
docker compose -f deploy/compose.yaml stop api worker beat
```

```
docker compose -f deploy/compose.yaml run --rm --no-deps api python -m app.cli.restore /backups/hawk-ai-2026-11-25T02-00-00.hkbackup --yes
```

```
docker compose -f deploy/compose.yaml up -d
```

- The database as it was (`database.pgdump`) and every file of the data folder are moved to `replaced-<time>/` in the data folder first, never deleted. The database is replaced in one transaction: a restore that fails leaves it as it was.
- **It refuses while Hawk AI runs.** API, worker and scheduler each hold a share of a PostgreSQL lock while they run; the restore takes it alone, so it says which are running and writes nothing. `--force` skips that check: only when they are certainly stopped.
- **An encrypted backup** opens by itself on the server that made it. From another server, give its key: add `-e BACKUP_PASSPHRASE=<the key>` after `--no-deps` (the key may be typed in lower case, with spaces for the dashes).
- **A backup file from elsewhere:** copy it into `BACKUP_DIR` (`sudo cp hawk-ai-….hkbackup /var/lib/hawk-ai/backups/ && sudo chown 1000:1000 /var/lib/hawk-ai/backups/*.hkbackup`).
- **On a new server** (new secrets), the restore says so and lists the steps that put the old server's application keys in place, so the restored database can read what it holds.
- After starting, the database is brought to this version, so a backup from an older version is updated too.

**From the Settings page:** **Restore** checks the backup (up to 200 MB; a larger one is restored as above), asks for its key or passphrase when this server's own does not open it, and stages it. It is applied the next time Hawk AI starts, before anything else runs: `docker compose -f deploy/compose.yaml stop api worker beat`, then `docker compose -f deploy/compose.yaml up -d`. While api, worker or scheduler still run it stays staged, and the log says so.

## HTTPS

**No certificate from your organisation? One setting.** With a DNS name pointing at the server and ports 80 and 443 open to the internet, set these in `deploy/.env`, then run `sudo deploy/install.sh` again:

```
BIND_ADDRESS=0.0.0.0
PORT=443
HTTP_REDIRECT_PORT=80
HAWK_HOST=hawk.company.com
LETSENCRYPT_DOMAIN=hawk.company.com
LETSENCRYPT_EMAIL=appsec@company.com
```

Hawk AI gets a free Let's Encrypt certificate, switches to HTTPS only, and renews it by itself. Setting `LETSENCRYPT_DOMAIN` means you accept the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/). It is also one button under Settings → HTTPS. More: [docs/https-and-hosting.md](../docs/https-and-hosting.md#b-free-certificate-from-lets-encrypt-public-name).

**From the Settings page (recommended with your organisation's certificate).** An owner or admin moves a running Hawk AI to HTTPS under **Settings → HTTPS**, with no new command and no restart:

1. **Certificate.** Upload the files from IT (certificate, chain, key, or one `.pfx`). It is checked the way a browser would before anything changes: the key, the chain, the names people use, the dates. No certificate yet? **Create a request (CSR)** for IT there; the key stays on the server.
2. **Turn on HTTPS next to http** (**HTTP and HTTPS**). HTTPS answers on `PORT`, plain http on `HTTP_REDIRECT_PORT`. Nobody is cut off.
3. **Test it.** Open the https address, and check your browser accepts it.
4. **Switch to HTTPS only,** from the page open over HTTPS. Plain http then redirects to https.
5. **Harden:** HSTS (start with a day), and TLS 1.3 only if you want.

**Replacing a certificate** (a renewal, or another one) works the same way: upload it, it is checked, and it goes into use at once. The previous one is kept, to put back in one click. **Locked out?** This brings http back next to HTTPS within 5 seconds (and turns HSTS off):

```
docker compose -f deploy/compose.yaml exec api python -m app.cli.https both
```

**From `deploy/.env`** instead: Hawk AI starts with `HTTPS=on` (HTTPS only, self-signed until a certificate is given). `HTTPS=off` starts with plain http, `HTTPS=both` with both. Once an owner or admin changes it on the Settings page, the page's choice is kept across restarts and updates. Ways to give the certificate (each time, run `sudo deploy/install.sh` again afterwards):

In everything below, replace `hawk.company.com` with your server's name.

**A. Your company's certificate.** Put `server.crt` (with its chain) and `server.key` in `/var/lib/hawk-ai/certs`, readable by the API only:

```
sudo cp server.crt server.key /var/lib/hawk-ai/certs/
```

```
sudo chown 1000:1000 /var/lib/hawk-ai/certs/server.crt /var/lib/hawk-ai/certs/server.key && sudo chmod 0600 /var/lib/hawk-ai/certs/server.key
```

then in `deploy/.env`:

```
TLS_CERT_FILE=/certs/server.crt
TLS_KEY_FILE=/certs/server.key
HAWK_HOST=hawk.company.com
BIND_ADDRESS=0.0.0.0
PORT=443
HTTP_REDIRECT_PORT=80
```

- **With a `.pfx` instead:** replace the two `TLS_CERT_FILE` / `TLS_KEY_FILE` lines with `TLS_PFX_FILE=/certs/server.pfx` and `TLS_PFX_PASSPHRASE=…` (an encrypted key: `TLS_KEY_PASSPHRASE=…`).
- **Port 80** (`HTTP_REDIRECT_PORT`) only sends `http://` visitors to `https://` (or serves Hawk AI while http is on next to HTTPS).
- **Renewals:** copy the renewed files over the old ones. It switches over within 5 minutes, with no restart.

**B. Free certificate from Let's Encrypt** (public name): `LETSENCRYPT_DOMAIN`, above. `LETSENCRYPT_STAGING=1` tries Let's Encrypt's staging service first, `LETSENCRYPT_SKIP_CHECK=1` skips the check that the name reaches this server (when the server cannot reach its own public name although the internet can), and `ACME_DIRECTORY_URL` uses another ACME certificate authority.

**C. Self-signed** (try it out): what Hawk AI does when no certificate is given. `TLS_HOSTNAMES` adds names to it:

```
TLS_HOSTNAMES=hawk.company.com
```

**Check it worked**
- `docker compose -f deploy/compose.yaml logs api` shows `[https] HTTPS only…`, and the certificate's name and expiry date. Self-signed also logs a warning: fine to try it out, not for everyday use. A certificate that does not fit its key, or a wrong `.pfx` password, stops the start with the reason, and the proxy serves nothing: it never falls back to plain http.
- The browser shows the padlock at `https://hawk.company.com`.

**Behind a load balancer of yours** that sends `X-Forwarded-For` / `-Proto`: set `TRUST_PROXY` to its address or network (e.g. `TRUST_PROXY=10.20.0.15`), else those headers are not believed. All the options, and a checklist for hosting it safely: [docs/https-and-hosting.md](../docs/https-and-hosting.md).

## What runs, and how it is hardened

| Service | Image | Notes |
|---|---|---|
| proxy | `infra/Dockerfile.proxy` (Caddy) | the only published ports: `${BIND_ADDRESS:-127.0.0.1}:${PORT:-3000}` (HTTPS) and `:${HTTP_REDIRECT_PORT:-80}` (plain http); `/` is the console, `/api/` the API; its configuration is written by the API (Settings → HTTPS) |
| web | `infra/Dockerfile.web` (target `runtime`) | Next.js, started with node (no npm in the image) |
| api | `infra/Dockerfile.api` (target `runtime`) | makes the first administrator on an empty database |
| worker, beat | the API image | Celery worker and scheduler; the worker makes the scheduled backups (it has `pg_dump`) |
| migrate | the API image | applies a staged restore (or, on a new server, one from the backup mailbox), brings the database to this version, then exits |
| postgres, redis | `postgres:16`, `redis:7` | not published |

Every Hawk container (proxy, web, api, worker, beat, migrate) runs as uid 1000 with a read-only file system (only its volumes and a scratch `/tmp` are writable), no Linux capabilities (`cap_drop: ALL`), `no-new-privileges`, at most 512 processes, 15 s to stop, and a health check every 30 s (5 s timeout, 20 s start period, 3 retries). The exceptions: PostgreSQL keeps the five capabilities its entrypoint needs to prepare its data folder (`CHOWN`, `SETUID`, `SETGID`, `FOWNER`, `DAC_OVERRIDE`), a writable file system and 30 s to stop; Redis runs as its own user (uid 999).

Settings are in `deploy/.env` (from `deploy/.env.example`); secrets are in `/var/lib/hawk-ai/secrets` and reach the containers as Docker secrets (`*_FILE`), never as environment variables or in this repository. The version (`VERSION`, shown as `HK-xx.xx.xx`) is bottom-left on every screen and on `/api/health`.
