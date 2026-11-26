import type { GuideTopic } from "../types";

/** deploy/install.sh, deploy/.env.example, deploy/compose.yaml and app/services/first_run_service.py. */
export const install: GuideTopic = {
  slug: "install",
  title: "Install on one Linux machine",
  summary: "What the machine needs, the one command that installs Hawk AI, the settings in deploy/.env and the first administrator's sign-in.",
  sections: [
    {
      id: "what-you-need",
      title: "What you need",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "list",
          items: [
            "A Linux machine (a virtual machine is fine) with **Docker** and its **compose plugin**, and Docker running. The installer checks all three and says how to put each right: on Ubuntu `curl -fsSL https://get.docker.com | sh` installs Docker, `apt-get install -y docker-compose-plugin` the compose plugin, and `systemctl start docker` starts it.",
            "Root access: the installer runs as root (it asks for `sudo` by itself), because it gives each secret file to the user of the container that reads it.",
            "A copy of the Hawk AI folder (the one that holds `deploy/`) on that machine. Commands in this guide are typed in that folder.",
            "Two free ports: `PORT` (3000) for HTTPS and `HTTP_REDIRECT_PORT` (80) for plain http, which is redirected to HTTPS and where Let's Encrypt checks the name.",
            "Internet access to download the images (with `HAWK_RELEASE`), or to build them from the folder (without it). Published images exist for amd64 and arm64.",
          ],
        },
        {
          kind: "p",
          text: "Hawk AI does not check the machine's memory or processors itself. It runs these services: proxy (the one address people use), web (the console), api, worker and beat (background work), postgres and redis, a short migrate step at every start and, with the published images, the updater.",
        },
      ],
    },
    {
      id: "run-the-installer",
      title: "Run the installer",
      who: "Whoever runs the server",
      blocks: [
        { kind: "code", caption: "In the Hawk AI folder:", lines: ["sudo deploy/install.sh"] },
        {
          kind: "steps",
          items: [
            "It checks Docker and its compose plugin.",
            "The first time, it copies `deploy/.env.example` to `deploy/.env` (readable by root only) and fills in `HAWK_DATA_DIR`. It never overwrites `deploy/.env` afterwards.",
            "It creates the data folder (`HAWK_DATA_DIR`, default `/var/lib/hawk-ai`) and, the first time only, the secrets in its `secrets` folder: the database and Redis passwords and the application keys. Back this folder up with the database.",
            "It builds the images from the folder, or downloads the published ones when `HAWK_RELEASE` is set, and starts everything.",
            "It waits until the API answers `/health/ready` (at most 600 seconds; `HAWK_WAIT_SECONDS` changes that), then prints the address and the first administrator's sign-in.",
          ],
        },
        {
          kind: "note",
          tone: "info",
          text: "Building behind a company proxy that inspects HTTPS? Give its CA certificate to the build in `HAWK_BUILD_CA_FILE`, for example `HAWK_BUILD_CA_FILE=/path/to/ca.pem deploy/install.sh` typed as a normal user: the installer asks for sudo by itself and keeps that setting.",
        },
      ],
    },
    {
      id: "settings",
      title: "The settings in deploy/.env",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "Change a setting in `deploy/.env`, then run `sudo deploy/install.sh` again: it brings the running services up to date. Empty means the default.",
        },
        {
          kind: "table",
          head: ["Setting", "Default", "What it does"],
          rows: [
            ["`HAWK_DATA_DIR`", "`/var/lib/hawk-ai`", "Where the secrets and certificates live, outside the Hawk AI folder. Must be an absolute path."],
            ["`BIND_ADDRESS`", "`127.0.0.1`", "Which address of this machine answers. The default answers this machine only: set `0.0.0.0` (or one interface's address) to serve other machines."],
            ["`PORT`", "`3000`", "The HTTPS port people use. `443` for the usual https address."],
            ["`HAWK_HOST`", "`localhost`", "The name or address people type in their browser."],
            ["`PUBLIC_URL`", "empty", "The full address, when it is not `https://HAWK_HOST:PORT` (for example behind another proxy on port 443). Links in emails point here."],
            ["`HTTP_REDIRECT_PORT`", "`80`", "Plain http, redirected to HTTPS while HTTPS only. Let's Encrypt needs 80; set another port if 80 is taken."],
            ["`HTTPS`", "`on`", "The starting point only: `on` (HTTPS only), `off` (plain http) or `both`. Once changed under Settings → HTTPS, the page's choice wins."],
            ["`TZ`", "`UTC`", "Time zone for scheduled work, such as `Asia/Dubai`."],
            ["`BACKUP_DIR`", "`HAWK_DATA_DIR`/backups", "Where backups go. Better on another disk or a network share. Must be an absolute path."],
            ["`HAWK_RELEASE`", "empty", "Empty: build the images from this folder. `latest`, `stable` or a version such as `0.2.0`: run the published images, with the updater, so owners and admins update from Settings → Updates."],
            ["`ADMIN_EMAIL`", "`admin@hawk.local`", "The first administrator's email. With `ADMIN_PASSWORD` too, that is their first password instead of a generated one."],
            ["`FIRST_ADMIN`", "empty", "`setup-code`: print a setup code in the log instead, and create the first administrator on the sign-in page."],
            ["`ACCEPT_TERMS`", "empty", "An email: the person deploying accepts the terms of use for the organisation and everyone, on record."],
            ["`ORGANISATION_NAME`", "empty", "The organisation's name (otherwise the administrator gives it when accepting the terms)."],
            ["`CELERY_WORKER_CONCURRENCY`", "`4`", "How many background jobs the worker runs at once."],
          ],
        },
        {
          kind: "p",
          text: "The other settings (HTTPS certificates, backups, email, updates, the self-check, the proxy) are described on their own pages of this guide.",
        },
        {
          kind: "table",
          head: ["Setting", "Default", "What it does"],
          rows: [
            ["`HAWK_API_MEMORY`", "`2g`", "The most memory the api may use. Each service has its own cap: `HAWK_WORKER_MEMORY` (`3g`), `HAWK_POSTGRES_MEMORY` (`2g`), `HAWK_MIGRATE_MEMORY` (`2g`), `HAWK_WEB_MEMORY` (`1g`), `HAWK_REDIS_MEMORY` (`1g`), `HAWK_PROXY_MEMORY` (`512m`), `HAWK_BEAT_MEMORY` (`512m`), `HAWK_UPDATER_MEMORY` (`256m`). Raise one if its service is stopped for lack of memory (`docker compose -f deploy/compose.yaml ps` shows it restarting)."],
          ],
        },
      ],
    },
    {
      id: "hardening",
      title: "How the installation is protected",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "The installer sets every service up to the CIS Docker Benchmark, with nothing to do on your side:",
        },
        {
          kind: "list",
          items: [
            "Every service runs as a fixed user that is not root, with no Linux capabilities, no way to gain privileges, a read-only file system (only its data and a scratch folder can be written), a memory cap, a CPU share, at most 512 processes, a health check and a restart policy. Logs are rotated.",
            "Only the proxy answers on the network (`BIND_ADDRESS`, `PORT`, `HTTP_REDIRECT_PORT`). PostgreSQL and Redis are on an internal network of their own: only the api, worker, beat and migrate services reach them, and they reach nothing outside this machine.",
            "PostgreSQL accepts only SCRAM-SHA-256 passwords, over TLS (with a certificate the installer makes for it, in the `secrets` folder), and logs every connection and disconnection, schema changes and slow statements: `docker compose -f deploy/compose.yaml logs postgres`.",
            "Redis needs its password, and the commands that would wipe, reconfigure or list the whole store are switched off.",
            "PostgreSQL, Redis and every image Hawk AI is built on are pinned to an exact, checked version. Each published image carries a list of its components (an SBOM) and is scanned for known vulnerabilities before it is published.",
            "The updater is the one service with access to Docker, which it needs to replace the others: it has no network at all, runs as an ordinary user in the Docker socket's group, and acts only on what an owner or admin asks from Settings → Updates.",
          ],
        },
        {
          kind: "p",
          text: "At each run the installer also checks the machine itself (firewall, SSH, automatic security updates, time, disk encryption, the audit daemon) and prints Pass or Check for each; [Settings → Backups & health](/settings/backups) shows the same list under the self-check. It changes nothing on the machine.",
        },
      ],
    },
    {
      id: "first-administrator",
      title: "The first administrator's sign-in",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "On an empty database the API creates the first administrator, `admin@hawk.local` (or `ADMIN_EMAIL`), with a generated password of four groups of five characters, and prints it once in its log between two lines of 64 `=` signs. The installer shows that banner at the end:",
        },
        {
          kind: "code",
          lines: [
            "================================================================",
            "  First start: an administrator was created. Sign in with:",
            "      Email:    admin@hawk.local",
            "      Password: xxxxx-xxxxx-xxxxx-xxxxx",
            "  You choose your own password at first sign-in. This is shown only once;",
            "  until then it is also in /data/first-admin-password.txt.",
            "  Lost it? Run: python -m app.cli.reset_admin  (with Docker: docker compose exec api python -m app.cli.reset_admin)",
            "================================================================",
          ],
          caption: "An example: your password is different.",
        },
        {
          kind: "list",
          items: [
            "Until the administrator chooses their own password, it is also kept in `/data/first-admin-password.txt` inside the api container (readable by the API only); the file goes once they do.",
            "The banner scrolled away? See the log again with `docker compose -f deploy/compose.yaml logs api`, or set a new temporary password (see [First sign-in](/settings/guide/first-sign-in#lost-admin-password)).",
            "With `FIRST_ADMIN=setup-code` nobody is created: the log shows a setup code, and whoever has it creates the first administrator on the sign-in page, once.",
            "On a database that already has people, the log names an administrator and the command to reset their password instead.",
          ],
        },
      ],
    },
    {
      id: "run-again",
      title: "Running the installer again",
      blocks: [
        {
          kind: "p",
          text: "Running `sudo deploy/install.sh` again is safe: existing secrets, settings (`deploy/.env`) and data are never replaced or wiped. Run it after changing `deploy/.env`, and to update a Hawk AI built from the folder (after `git pull`).",
        },
        {
          kind: "note",
          tone: "warn",
          text: "Everything Hawk AI keeps is in Docker volumes and in `HAWK_DATA_DIR`. `docker compose -f deploy/compose.yaml down` keeps the volumes; `docker compose -f deploy/compose.yaml down -v` deletes them, with every record. Never use `-v` unless you mean to start from nothing.",
        },
      ],
    },
  ],
};
