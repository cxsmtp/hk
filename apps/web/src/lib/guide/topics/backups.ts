import type { GuideTopic } from "../types";

/**
 * app/services/backup_service.py, app/services/backup_key.py, app/cli/backup.py, app/cli/restore.py,
 * app/api/routers/backups.py, Settings → Backups & health, deploy/.env.example, deploy/compose.yaml.
 */
export const backups: GuideTopic = {
  slug: "backups",
  title: "Backups and restore",
  summary: "When backups are made and how many are kept, the backup key you must save, the backup mailbox, and restoring from the command line or from the console.",
  sections: [
    {
      id: "what-and-when",
      title: "What is backed up, and when",
      blocks: [
        {
          kind: "p",
          text: "A backup is one `.hkbackup` file with the whole database (people, password hashes, activation, connector secrets, the audit log) and the API's data folder (HTTPS choices and certificate keys, settings, the evidence signing key). The backup key and the first administrator's password file are never in a backup.",
        },
        {
          kind: "table",
          head: ["Setting", "Default", "What it does"],
          rows: [
            ["`BACKUP_DIR`", "`HAWK_DATA_DIR`/backups", "Where backups go on this machine. Put it on another disk or a network share, so losing one disk does not lose both. The containers see it as `/backups`."],
            ["`BACKUP_INTERVAL_HOURS`", "`24`", "How often one is made: the first a minute after start, then every so many hours. `0` turns the schedule off."],
            ["`BACKUP_KEEP`", "`14`", "How many are kept; older ones are removed."],
          ],
        },
        {
          kind: "list",
          items: [
            "By hand: **Back up now** on [Settings → Backups & health](/settings/backups) (owners and admins), or on the server `docker compose -f deploy/compose.yaml exec api python -m app.cli.backup`.",
            "Also before every update, and when the API stops for a reason nobody asked for (then the administrators get a \"Hawk AI stopped\" email, at most one every `LAST_WORDS_EVERY_HOURS`, 6).",
            "Each backup on the page can be downloaded.",
          ],
        },
      ],
    },
    {
      id: "backup-key",
      title: "The backup key: save it",
      who: "Owners and admins",
      blocks: [
        {
          kind: "note",
          tone: "warn",
          text: "Backups are encrypted, and a backup opens only with its key. If the server is lost and nobody kept the key, its backups cannot be opened anywhere. Save the key somewhere other than this server, today.",
        },
        {
          kind: "steps",
          items: [
            "Open [Settings → Backups & health](/settings/backups) and **Show backup key**: eight groups of four letters and digits.",
            "Copy it or **Download as a text file**, and keep it somewhere other than this server (a password manager, a safe).",
            "Confirm you saved it. Until someone does, the page says \"Nobody has confirmed saving this key yet.\"",
          ],
        },
        {
          kind: "list",
          items: [
            "A new installation makes its backup key at its first start and encrypts every backup with it. An installation that existed before keeps its backups plain until an owner or admin turns encryption on there; backups made before stay as they were.",
            "The key is never emailed and never inside a backup.",
            "`BACKUP_PASSPHRASE` in `deploy/.env`, when set, wins: every backup is encrypted with that passphrase instead. Keep it away from this server too: it is needed to restore.",
            "`BACKUP_ENCRYPTION=off` keeps backups plain on purpose (a passphrase still wins). Plain backups hold password hashes, connector keys and certificate keys in the clear.",
          ],
        },
      ],
    },
    {
      id: "backup-mailbox",
      title: "The backup mailbox",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "With `BACKUP_EMAIL` set, every encrypted backup up to 15 MB is emailed to that mailbox (plain backups are never emailed). A new, empty server started with the same `BACKUP_EMAIL`, `BACKUP_EMAIL_PASSWORD` and `BACKUP_PASSPHRASE` (the passphrase, or the saved backup key) finds the newest backup there and restores itself at its first start.",
        },
        {
          kind: "table",
          head: ["Setting", "Default", "What it does"],
          rows: [
            ["`BACKUP_EMAIL`", "empty", "The mailbox backups are sent to."],
            ["`BACKUP_EMAIL_PASSWORD`", "empty", "Its password, for reading it back (IMAP)."],
            ["`BACKUP_EMAIL_IMAP_HOST`", "`SMTP_HOST`", "The mailbox's server."],
            ["`BACKUP_EMAIL_IMAP_PORT`", "`993`", "Its port; another port must offer STARTTLS."],
            ["`BACKUP_EMAIL_USER`", "`BACKUP_EMAIL`", "The account, when not the address itself."],
          ],
        },
        {
          kind: "p",
          text: "It needs an email server ([Email](/settings/guide/email)).",
        },
      ],
    },
    {
      id: "restore-command-line",
      title: "Restore on the server",
      who: "Whoever runs the server",
      blocks: [
        {
          kind: "p",
          text: "Copy the backup into `BACKUP_DIR` on the server (the containers see it under `/backups`). First check it: this only reads the backup and says what it holds, and can run while Hawk AI runs.",
        },
        {
          kind: "code",
          lines: ["docker compose -f deploy/compose.yaml exec api python -m app.cli.restore /backups/<file>.hkbackup"],
        },
        {
          kind: "p",
          text: "Then stop the api, worker and beat (PostgreSQL stays up), restore with `--yes` from a one-off container, and start again:",
        },
        {
          kind: "code",
          lines: [
            "docker compose -f deploy/compose.yaml stop api worker beat",
            "docker compose -f deploy/compose.yaml run --rm --no-deps api python -m app.cli.restore /backups/<file>.hkbackup --yes",
            "sudo deploy/install.sh",
          ],
        },
        {
          kind: "list",
          items: [
            "Nothing is deleted: the database as it was and every file of the data folder are moved to `replaced-<time>/` in the data folder first.",
            "The restore refuses while any of api, worker or beat still runs. `--force` restores anyway: only when Hawk AI is certainly not running.",
            "A backup this same server made opens by itself. One from another server opens with that server's backup key or its `BACKUP_PASSPHRASE`, given like this:",
          ],
        },
        {
          kind: "code",
          lines: ["docker compose -f deploy/compose.yaml run --rm --no-deps -e BACKUP_PASSPHRASE=<the key> api python -m app.cli.restore /backups/<file>.hkbackup"],
        },
      ],
    },
    {
      id: "restore-console",
      title: "Restore from the console",
      who: "Owners and admins",
      blocks: [
        {
          kind: "steps",
          items: [
            "On [Settings → Backups & health](/settings/backups), under **Restore**, choose a `.hkbackup` file (200 MB at most; larger ones are restored on the server) and its passphrase or backup key if it came from another server.",
            "**Check and restore** shows when it was made and what it holds, and asks before going on.",
            "It is then staged: it is applied at the next start, before anything else runs. Restart the services on the server: `docker compose -f deploy/compose.yaml stop api worker beat`, then `sudo deploy/install.sh`: it starts the same version again (built from the folder or downloaded with `HAWK_RELEASE`) and waits until it is ready.",
            "Changed your mind before the restart? **Cancel it** on the same page.",
          ],
        },
      ],
    },
    {
      id: "ready-for-production",
      title: "Ready for production?",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "The bottom of [Settings → Backups & health](/settings/backups) lists what to put right before the server is opened to more people, each with where to fix it. Looking changes nothing.",
        },
        {
          kind: "list",
          items: [
            "A backup in the last day.",
            "Backups kept away from the data (`BACKUP_DIR` on another disk).",
            "Backups sealed with a passphrase or key.",
            "A restore tried: try one of your backups on a second copy of the server, so the first time is not the day it is needed.",
            "A certificate browsers trust.",
            "Email is set up.",
            "Room on the disk (more than 1 GB free).",
            "More than one Admin.",
          ],
        },
      ],
    },
  ],
};
