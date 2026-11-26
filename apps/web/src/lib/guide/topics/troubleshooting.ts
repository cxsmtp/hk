import type { GuideTopic } from "../types";

/** app/main.py (health), app/services/https_proxy.py (/api), app/api/routers/updates.py (the report), deploy/install.sh. */
export const troubleshooting: GuideTopic = {
  slug: "troubleshooting",
  title: "Troubleshooting",
  summary: "Health addresses, the logs, the troubleshooting report, and the usual problems with what to do about each.",
  sections: [
    {
      id: "health",
      title: "Is it running?",
      blocks: [
        {
          kind: "p",
          text: "The API answers under `/api` on Hawk AI's address. These need no sign-in and stay open even when the licence has ended:",
        },
        {
          kind: "table",
          head: ["Address", "What it says"],
          rows: [
            ["`/api/health/live`", "The API process answers."],
            ["`/api/health/ready`", "Ready for work: 200, or 503 with what is not ready. The installer waits for this one."],
            ["`/api/health`", "\"ok\" or \"degraded\", the version, and whether the database is up to date."],
            ["`/api/health/schema`", "The database's migrations: what is missing, if anything."],
          ],
        },
        {
          kind: "p",
          text: "On the server, `docker compose -f deploy/compose.yaml ps` lists every service and whether it is healthy.",
        },
      ],
    },
    {
      id: "logs",
      title: "The logs",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "code",
          lines: [
            "docker compose -f deploy/compose.yaml logs api",
            "docker compose -f deploy/compose.yaml logs --tail 100 worker",
            "docker compose -f deploy/compose.yaml logs -f proxy",
          ],
          caption: "One service's log; its last 100 lines; follow it as it grows (Ctrl C stops). The services are proxy, web, api, worker, beat, migrate, postgres, redis and, with published images, updater.",
        },
        {
          kind: "p",
          text: "Lines starting with `!` are problems Hawk AI noticed and says what to do about.",
        },
      ],
    },
    {
      id: "report",
      title: "The troubleshooting report",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "**Download troubleshooting report** on [Settings → Updates](/settings/updates) saves a JSON file with the versions, the updater and its recent events, the integrity check, the disk, the HTTPS mode, the last backup and the time zone: no secrets, keys or customer data. Send it to whoever helps you. (The same button on Settings → Backups & health is not working yet.)",
        },
      ],
    },
    {
      id: "port-80-busy",
      title: "Port 80 is taken on this machine",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "Hawk AI cannot start its proxy while another program uses `HTTP_REDIRECT_PORT` (80). Set another port in `deploy/.env`, for example `HTTP_REDIRECT_PORT=8080`, and run `sudo deploy/install.sh` again. Let's Encrypt then cannot check the name: it needs port 80.",
        },
      ],
    },
    {
      id: "certificate-warning",
      title: "The browser warns about the certificate",
      blocks: [
        {
          kind: "p",
          text: "Hawk AI is using its self-signed certificate. Put your own in place or get one from Let's Encrypt ([HTTPS](/settings/guide/https)). A warning with your own certificate usually means a missing intermediate certificate or a name it does not cover: Settings → HTTPS says which when you **Check it**.",
        },
      ],
    },
    {
      id: "https-locked-out",
      title: "Locked out after an HTTPS change",
      who: "Whoever runs the server",
      blocks: [
        { kind: "code", lines: ["docker compose -f deploy/compose.yaml exec api python -m app.cli.https both"] },
        {
          kind: "p",
          text: "Plain http works again within 5 seconds, next to HTTPS; fix the certificate on Settings → HTTPS ([more](/settings/guide/https#locked-out)).",
        },
      ],
    },
    {
      id: "lost-password",
      title: "Nobody can sign in as an administrator",
      who: "Whoever runs the server",
      blocks: [
        { kind: "code", lines: ["docker compose -f deploy/compose.yaml exec api python -m app.cli.reset_admin"] },
        {
          kind: "p",
          text: "It prints a new temporary password and takes two-step sign-in off ([more](/settings/guide/first-sign-in#lost-admin-password)). A single person locked after five wrong passwords: wait 15 minutes, or **Unlock** them under [Settings → People](/settings/people).",
        },
      ],
    },
    {
      id: "licence-ended",
      title: "Every page says the product has been deactivated",
      blocks: [
        {
          kind: "p",
          text: "The licence has ended. Nothing is deleted: enter a product activation code on that page and everything comes back ([Licence](/settings/guide/licence)).",
        },
      ],
    },
    {
      id: "not-ready",
      title: "The installer says the API was not ready",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "It waited 600 seconds (`HAWK_WAIT_SECONDS`) and printed the last 40 lines of the API's log. Read them, or `docker compose -f deploy/compose.yaml logs api` and `docker compose -f deploy/compose.yaml logs migrate`. A first build takes several minutes; on a slow machine, run the installer again with a longer `HAWK_WAIT_SECONDS`.",
        },
      ],
    },
    {
      id: "other-problems",
      title: "Other common problems",
      blocks: [
        {
          kind: "table",
          head: ["What you see", "What to do"],
          rows: [
            ["No email arrives (password links, Get help, hands-off).", "The email server is not tested with the settings in force: **Test connection** on Settings → Email (SMTP)."],
            ["A proxy change on Settings → Network & proxy did nothing.", "Restart: `docker compose -f deploy/compose.yaml restart api worker beat`."],
            ["Software integrity says \"Not confirmed yet\".", "The server cannot reach `api.github.com`: allow it, or set `INTEGRITY_OFFLINE=allow` ([Updates](/settings/guide/updates#integrity))."],
            ["A notice at the top of every page says the backup key is not saved, or backups are not encrypted.", "Save the key, or turn encryption on, on Settings → Backups & health ([Backups](/settings/guide/backups#backup-key))."],
            ["Other machines cannot open Hawk AI.", "`BIND_ADDRESS` is `127.0.0.1` by default: set `0.0.0.0` and `HAWK_HOST` in `deploy/.env`, then `sudo deploy/install.sh`."],
          ],
        },
      ],
    },
  ],
};
