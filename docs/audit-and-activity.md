# Audit log, user activity and connector API activity

Ported from CxMissionZero's src/audit-log.js, src/activity-log.js and docs/audit-and-backup.md, with the console pages of FTR Command Center (Records → Audit log, CxOne API audit).

## The audit log: tamper-evident

Every entry of Hawk AI's audit log (`audit_logs`) carries its place in a chain: one chain per organisation, and one (`system`) for entries that belong to none. Each entry has a sequence number and a MAC: an HMAC-SHA256 over the previous entry's MAC and the entry itself, keyed by `audit.key` in the data folder (made at the first entry: 32 random bytes, readable by the server only). Editing, removing or reordering any entry breaks the chain from that point on.

- **Append-only.** The database refuses to change or delete an entry (triggers since migration 0002), and so does the application.
- **Several writers.** The api and the worker both write; each append advances the chain's head row (`audit_chain_heads`) under that row's lock, so two entries are never numbered alike, whichever process writes them.
- **Check the log is intact** (Records → Audit log, `/settings/audit`; `GET /audit/log/verify`) walks the organisation's chain and names every broken entry: contents changed after it was written, entries missing or reordered, entries removed from the end. On the server, `docker compose -f deploy/compose.yaml exec api python -m app.cli.audit_verify` checks every chain. Entries written before the chain began (before migration 0097) are counted and said, not checked.
- **Exports.** CSV for spreadsheets (a cell that would start a formula, `= + - @`, is prefixed with `'`), and JSON Lines with every entry's MAC and the previous MAC, complete and checkable, for a SIEM. Both are in the audit log themselves.
- **The key is backed up.** `audit.key` lives in the data folder, so every backup carries it beside the database it signs (`data/audit.key`; encrypted with the rest when backups are encrypted), and a restore brings both back together. A key file that is there but cut short is never replaced by a new key: the server stops writing audit entries and says what to do. Losing the key does not lose the log, only the means to check it.
- **Refusals from people not signed in** are listed only so many a minute, so nobody can fill the disk with them: refused requests 10 a minute per address and 40 in all; product activation codes 10 and 40; sign-ins (passwords, two-step codes, password resets, single sign-on) 30 and 120. The rest are counted, and one entry says how many were left out.

Who reads it: the organisation's owners, admins and auditors.

## The user activity log

What people do in the console, one row each (`user_activity`): who (email, name, role), when, from where (IP), what (the action, the item), the **names** of the fields a change touched (never their values: no passwords, keys or text are kept), and how it ended (status, time taken). Every signed-in request that changes something is recorded, and the downloads and exports. Not chained (the audit log is the chained record). Rows older than a year are not shown and are removed, and an organisation keeps at most 200,000 rows (about CxMissionZero's two 20 MB files). `GET /activity/log` lists it, filtered by person, text, kind and dates; `GET /activity/log/export.csv` exports it.

## Connector API activity

Records → Connector API activity (`/settings/connector-activity`) lists every call Hawk AI's connectors made to the services they read: when, the connector, the host, the method and path (without its query, which may carry a token; long opaque path segments shown as …), the status, the time taken and a short error. Never a header, a body or a query string. The last 30 days are summed up (calls, average time, calls that did not succeed, connectors, services); calls are kept 90 days. Recorded where the connectors make their calls (the credentialed egress, the hosted discovery sources' client, the AWS connector's calls, the Microsoft Graph, Google Workspace and Zoom actions), in a session of its own so that recording never fails a call.
