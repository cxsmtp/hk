import type { GuideTopic } from "../types";

/** app/main.py (health), app/services/https_proxy.py (/api), app/api/routers/updates.py (the report),
 * app/services/self_recovery.py and app/services/diagnostics_bundle.py (self-recovery, the bundle), deploy/install.sh. */
export const troubleshooting: GuideTopic = {
  slug: "troubleshooting",
  title: "Troubleshooting",
  summary: "Health addresses, the logs, self-recovery, the diagnostics bundle for the OEM, and the usual problems with what to do about each.",
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
          text: "**Download troubleshooting report** on [Settings → Updates](/settings/updates) or [Settings → Backups & health](/settings/backups) saves a JSON file with the versions, the updater and its recent events, the integrity check, the disk, the HTTPS mode, the last backup and the time zone: no secrets, keys or customer data. For the OEM, the diagnostics bundle (below) has much more.",
        },
      ],
    },
    {
      id: "self-recovery",
      title: "Self-recovery",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "Every `SELF_RECOVERY_EVERY_SECONDS` (300) Hawk AI reads its error log (the API's, the worker's and the scheduler's), its failed background jobs, the updater's events and the installer's result, recognises the failures it knows and puts them right. Each fix has a limit; a pause that doubles between attempts; and a circuit breaker, so a kind of fix that keeps failing is left alone for a while. When the attempts run out, or the failure is one Hawk AI does not know, it stops trying, marks it **Needs OEM help** and prepares the diagnostics bundle. Everything it does is in its history on [Settings → Backups & health](/settings/backups) and in the audit log (Updates & system).",
        },
        {
          kind: "table",
          head: ["What it recognises", "What it does", "At most"],
          rows: [
            ["A background job failed.", "Runs it again, waiting longer each time (a job that needs its own schedule is waited for).", "3 times in 6 hours"],
            ["A lock was left behind: an update request no updater took, a database session idle in a transaction.", "Clears it.", "2 times an hour"],
            ["The database or Redis connection dropped.", "Empties the connection pool and connects again.", "3 times an hour"],
            ["The worker or the scheduler stopped answering.", "Asks the updater to restart that service alone.", "2 times in 6 hours"],
            ["The disk is almost full.", "Removes old error logs, half-written files and older prepared bundles; never a backup.", "2 times in 6 hours"],
            ["The database schema looks out of date.", "Runs the migration check again.", "2 times in 6 hours"],
            ["An update failed, or the new version is unhealthy.", "Goes back to the version before through the updater, then checks it is running and healthy within 30 minutes.", "once per version"],
            ["The installer reported a problem.", "Checks Hawk AI is running and healthy now.", "3 times a day"],
            ["Errors it does not recognise (the same one 3 times in 30 minutes).", "Nothing: Needs OEM help at once.", "—"],
          ],
        },
        {
          kind: "p",
          text: "When the worker or the scheduler is down, the API runs self-recovery itself. **Try again** next to an issue that needed help gives it its attempts back, once the OEM has advised.",
        },
      ],
    },
    {
      id: "diagnostics-bundle",
      title: "The diagnostics bundle for the OEM",
      who: "Owners and admins",
      blocks: [
        {
          kind: "steps",
          items: [
            "Open [Settings → Backups & health](/settings/backups) and find **Self-recovery**.",
            "**Download diagnostics bundle**: one `.tar.gz` file. When an issue needed help, **Bundle prepared** is the one Hawk AI made at that moment.",
            "Send it to the OEM with the reference shown (`REC-…`, or `JOB-…` for a background job).",
          ],
        },
        {
          kind: "p",
          text: "It holds the recent errors, the failed jobs, the update and rollback history, the self-check's and self-recovery's events, the installer's log, the versions, health (database, Redis, worker, scheduler, disk, schema) and the settings in force, with every secret, key and password replaced by `[redacted]`: no prompt text or customer data. `manifest.json` lists every file with its SHA-256 and `manifest.sig.json` signs it with the server's evidence key (`keys.json` has the public keys), so the OEM can check it came from this server unchanged.",
        },
        {
          kind: "note",
          tone: "info",
          text: "The owners and admins of the first organisation set up on the server get the whole installation's bundle. Those of another organisation get their own organisation's only, and see the installation's problems as a line with a time and a reference, never their text. Every download is in the audit log.",
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
          text: "It waited 600 seconds (`HAWK_WAIT_SECONDS`), read the logs and tried one fix on its own: the migrations again when they failed, unused images and build cache removed when the disk was full, the database restarted when it did not answer, or the API restarted; then it waited once more. If that did not help it printed the last 40 lines of the API's log and saved what happened in the updater folder (`install-status.json`, `install.log`), which self-recovery reads and the diagnostics bundle carries. Read them, or `docker compose -f deploy/compose.yaml logs api` and `docker compose -f deploy/compose.yaml logs migrate`. A first build takes several minutes; on a slow machine, run the installer again with a longer `HAWK_WAIT_SECONDS`.",
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
