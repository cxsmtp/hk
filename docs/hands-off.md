# Hands-off and self-healing

Some teams don't want one more tool to look after. For them, Hawk AI can be set up once and then left alone. It checks itself every few minutes, puts right what it can, tells the administrators when it cannot, sends a short status each week, and takes requests from that email. Nobody has to sign in.

Ported from CxMissionZero's hands-off mode and watchdog (its docs/hands-off.md, src/watchdog.js, src/routes/hands-off.js), with the console pages in FTR Command Center's settings look. Where Hawk AI differs, this page says so.

## Set it up once

Open **Settings → Hands-off** (owners and admins). The page first shows whether the email server is tested (Settings → Sign-in) and the server address is set (`PUBLIC_URL`). The server address is what makes the email buttons work. Then answer three questions:

1. **What should Hawk AI do on its own?** Email a short status every week.
2. **Who?** Who gets the weekly status.
3. **When?** The day and hour of the weekly status, in the server's time (`TZ`).

Select **Turn on hands-off**. **Send the status now** sends one straight away. **Turn off hands-off** stops the weekly status and the reading of replies; the self-check keeps running.

CxMissionZero asks four questions: the others are about its reminders to developers (which findings, who, how often), which Hawk AI does not have.

## Steer it by email

The weekly status gives the automatic runs of the last 7 days (and how many failed), the last backup, the version (and a newer one if there is), and the health of the server. It has buttons:

| Button | What it does |
| --- | --- |
| **Run the checks now** | Runs the monitoring checks (the 15-minute cycle) now. |
| **Pause for 7 days** / **Resume** | Stops the weekly status until then, or starts it again. |
| **Stop sending me this** | Takes you off the status list. |

Each button opens a page that asks once more ("Yes, do it"). A mail scanner that opens every link in an email therefore never changes anything. Each button works for the person it was sent to, for 30 days, and only if that person is still on the status list or an owner or admin. A changed or expired link does nothing. The page needs no sign-in; the link's secret is after `#`, so it is never sent to a server or in a Referer.

**Replies.** Tick **Also read replies** and Hawk AI reads the mailbox it sends from, using the email server's account (`SMTP_USER`, `SMTP_PASS`) over IMAP. The mailbox server defaults to `SMTP_HOST`, on port 993. The password is only ever sent over an encrypted connection: on port 993 from the start, on any other port (such as 143) only after the server offers STARTTLS. A server that does not is never sent the password, and after three failed reads in a row the self-check says how to fix it. A reply acts when it starts with one word:

| Word | What it does |
| --- | --- |
| `PAUSE` (or `PAUSE 14`) | Pause the weekly status for 7 days (or the number of days given, up to 90). |
| `RESUME` | Resume after a pause. |
| `RUN` | Run the monitoring checks that are due now. |
| `STATUS` | Email me the status now. |
| `STOP` | Stop sending me the status. |
| `SOLVED` | Close the support case the email is about (owners and admins of its tenant). |

In CxMissionZero, pausing also stops its reminders and `RUN` sends them; Hawk AI's monitoring is never paused by email.

Hawk AI only acts on a reply that is safe to act on:

- **From the right address.** The reply comes from the address the email was sent to. The subject carries a short reference made from that address (`[HKR-…]`), so a reply from anyone else, even with the same subject, is ignored.
- **The person's own words.** Only the first line above the quoted message counts.
- **Never an automatic message.** Auto-replies, out-of-office messages and bounces are never answered, so mail cannot loop.

Hawk AI only reads unread mail (25 at a time), marks it read, keeps only the sender, the subject and the text (64 KB at most), and never opens attachments. It answers each request with one line saying what it did. Every request is in the audit log.

## It looks after itself

Every 5 minutes (`WATCHDOG_EVERY_SECONDS`) the worker checks Hawk AI:

| Check | How |
| --- | --- |
| **Checkmarx One** | Each enabled Checkmarx One connector signs in with its own key and asks for one project. |
| **Email server** | Once set up and tested: it connects and signs in, but sends nothing. |
| **Automatic runs** | Did the last two runs fail? Scheduled backups, the monitoring checks (every 15 minutes, hourly, daily) and the daily snapshot pack. |
| **Errors** | More than 30 errors nobody caught in 15 minutes, in the API and the worker together (counted in Redis). |
| **Reading replies** | Three failed reads in a row, when replies are read. |
| **Database, Redis, worker, scheduler** | The database answers, Redis answers, and the worker's and the scheduler's heartbeats are fresh (what Hawk AI needs that CxMissionZero does not have). |

A retried run counts as a run: a monitoring check that Celery retries after a failure records each attempt.

**What it puts right on its own** (each repair is tried once while a problem lasts):

| Repair | When |
| --- | --- |
| **Put back the last working connection** | A Checkmarx One connector changed since it last worked, and does not work now. Its last working settings (kept in `connection-guard.json` in the data folder, the secrets as encrypted as in the database) come back, and the audit log says so. |
| **Sign in to Checkmarx One again** | A Checkmarx One connection fails. |
| **Try the mail server again after a pause** | The mail server fails: 10 seconds, then once more. |
| **Go back to the previous version** | A version that came in less than a day ago broke what worked before, and the version before it passed a whole check. This happens once per version, and only when the updater looks after the services (CxMissionZero: only under its launcher); it asks the updater to install the previous version, as **Roll back to this** under Settings → Updates does. It never happens for an outage on the far side: when Checkmarx One or the mail server answers 5xx or 429, times out or cannot be reached, going back a version cannot help, so the version stays and the problem says it is on that side. A refused key (401) or a refused permission (403) after an update still counts. |

The email server is set in `deploy/.env`, not on a page, so there is no "last working" mail setting to put back.

**Who it tells.** Owners and admins: of the tenant concerned (a Checkmarx One connector), or of every tenant for a problem of the server itself. Nothing is emailed before the email server is set up and tested.

| When | Email |
| --- | --- |
| A problem is seen on two checks in a row | **Hawk AI needs attention** |
| A repair fixes a problem it had told you about | **Hawk AI fixed itself** |
| The problem clears | **Hawk AI is working again** |
| It goes back to the previous version | **Hawk AI went back to HK-…** |

When the email server itself is the problem, these emails cannot go out. The pages show the problem anyway.

**A support case, raised by itself.** This happens when all of the following are true:

- the problem lasts three checks;
- **auto-update** is on (Settings → Updates);
- the last update check reached the internet (in the last two days).

Hawk AI then raises a support case (SUP-…, under **Get help**, from **Hawk AI (automatic)**, high priority), in the tenant concerned (the first tenant for the server's own problems). It emails the owners and admins asking them to forward the email to the maintainer, `MAINTAINER_EMAIL`. Hawk AI never sends anything outside your network by itself. `MAINTAINER_EMAIL` has no default: set it in `deploy/.env` to the address the person who supplied Hawk AI gave you.

The email carries the troubleshooting log: the problem, what was tried, the open problems and the self-check's last 30 events, with no personal data, keys or findings. To close the case, use **Mark as solved**, or reply `SOLVED`. One case is raised per problem while it lasts. When the problem clears, the case says so, and stays open until an administrator closes it.

**Where to see it.** Settings → Hands-off and Settings → Backups & health show the self-check: what is wrong now, when the last check ran, and the last events. **Check now** runs a check straight away.

## Settings

| Setting | Where | Default |
| --- | --- | --- |
| Weekly status: who, day, hour | Settings → Hands-off | Nobody; Monday 08:00 |
| Read replies, mailbox server and port | Settings → Hands-off | Off; `SMTP_HOST`, 993 |
| Where automatic cases are forwarded | `MAINTAINER_EMAIL` | none |
| How often the self-check runs | `WATCHDOG_EVERY_SECONDS` | 300 |
| How often replies are read | `INBOX_EVERY_SECONDS` | 120 |

The self-check's notes are kept in `watchdog.json`, the hands-off settings in `hands-off.json` and the last working connections in `connection-guard.json`, all in the data folder (`HAWK_DATA_DIR`), which is in every backup.
