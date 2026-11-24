# Deployment Hardening: 50-User Local Pilot

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


This checklist keeps Hawk as a local AI Action Control Plane pilot while making the operational risks explicit.

## Data Residency

For the local pilot, browser extension telemetry goes to the configured Hawk API URL. The API stores data in the local PostgreSQL database from `DATABASE_URL` and writes local evidence/artifact files under the configured evidence/artifact roots. No external Hawk cloud service is required by this setup.

Do not use SQLite for a 50-user pilot.

## Required `.env` Settings

```env
ENV=pilot
PILOT_MODE=true
DATABASE_URL=postgresql+psycopg2://postgres:REPLACE@127.0.0.1:5432/hawk_pilot
SECRET_KEY=<32+ byte random value>
SECRET_KEY_LOCK_ENABLED=true

API_BASE_URL=http://<api-host-ip>:8000
WEB_ORIGIN=http://<ui-host-ip>:3000
CORS_ORIGINS=http://<ui-host-ip>:3000,http://localhost:3000,http://127.0.0.1:3000
EXTENSION_CORS_ORIGINS=chrome-extension://<installed-extension-id>

DISK_ENCRYPTION_CONFIRMED=true
API_NETWORK_RESTRICTION_CONFIRMED=true
BACKUP_CONFIGURED=true
EVIDENCE_RETENTION_DAYS=90
REPORT_RETENTION_DAYS=90
INCOGNITO_POLICY=disabled
```

Use `REQUIRE_HTTPS_FOR_PILOT=true` once the API is behind HTTPS.

For the current local pilot where the API runs on the Windows laptop and the UI is opened on the Mac as `http://localhost:3000`, use:

```env
API_BASE_URL=http://192.168.102.35:8000
WEB_ORIGIN=http://localhost:3000
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
EXTENSION_CORS_ORIGINS=chrome-extension://<installed-extension-id>
```

Get the extension ID from `chrome://extensions` after loading the pilot package. If the same package is loaded into Edge or Brave, add each browser's extension origin to `EXTENSION_CORS_ORIGINS` as a comma-separated list. Do not use wildcard extension origins for the 50-user pilot.

## Host Controls

Check disk encryption:

```bash
fdesetup status
```

Windows:

```powershell
manage-bde -status
```

Restrict the API port to the internal pilot network only. On Windows, run PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "Hawk API 8000 Pilot LAN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000 -RemoteAddress <pilot-subnet-cidr>
```

## Managed Browser Extension Policy

The pilot extension must be deployed in managed mode. The browser policy should provide:

```json
{
  "api_base_url": "http://<api-host-ip>:8000",
  "tenant_id": "<tenant-id>",
  "policy_locked": true,
  "enterprise_managed": true,
  "browser": "chrome"
}
```

When `policy_locked=true`, users cannot edit the backend URL or tenant ID in the extension options page, and password auto-persistence is disabled.

## Extension Package Validation

Build and validate the shareable pilot package:

```bash
cd /Volumes/X10\ Pro/New\ project/repo/extension
HAWK_MANAGED_API_BASE_URL="http://192.168.102.35:8000" \
HAWK_MANAGED_TENANT_ID="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb" \
HAWK_MANAGED_BROWSER="chrome" \
npm run package:pilot
```

The packager runs `validate:pilot-package` and fails if source maps, TypeScript source files, dev directories, AppleDouble metadata, or `sourceMappingURL` markers are present.

When `HAWK_MANAGED_API_BASE_URL` and `HAWK_MANAGED_TENANT_ID` are provided, the package also includes `pilot-managed-policy.json` with:

- `api_base_url`
- `tenant_id`
- `policy_locked=true`
- `enterprise_managed=true`
- browser/incognito policy hints

Use that file as the source for Chrome/Edge managed storage policy. The file is included for operator handoff; enforcement still depends on deploying it through managed browser policy or MDM.

## Full Readiness Gate

Before sharing the extension with pilot users, run the repo-level readiness gate against the exact API `.env` and the exact packaged extension folder you plan to distribute:

```bash
cd /Volumes/X10\ Pro/New\ project/repo
python3 scripts/pilot_deployment_readiness.py \
  --api-env apps/api/.env \
  --extension-dir "../hawk-extension-pilot-0.1.8-REPLACE_HASH" \
  --expected-api-url "http://192.168.102.35:8000" \
  --expected-web-origin "http://localhost:3000" \
  --expected-tenant-id "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb"
```

Use `--expected-web-origin "http://<mac-ui-ip>:3000"` only when pilot users open the UI from another machine over the LAN. If the UI is only opened on the Mac running Next.js, `http://localhost:3000` is the correct origin.

For a fully hardened HTTPS deployment, add:

```bash
--require-https
```

Windows API machine example after copying the repo/API transfer folder:

```powershell
cd C:\Users\Ayushmaan\Desktop\api-machine-transfer
.\apps\api\.venv\Scripts\python.exe .\scripts\pilot_deployment_readiness.py `
  --api-env .\apps\api\.env `
  --extension-dir .\hawk-extension-pilot-0.1.8-REPLACE_HASH `
  --expected-api-url "http://192.168.102.35:8000" `
  --expected-web-origin "http://localhost:3000" `
  --expected-tenant-id "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb"
```

The gate fails on:

- SQLite or missing PostgreSQL configuration
- demo mode enabled
- weak or unlocked `SECRET_KEY`
- missing API/UI URL alignment
- missing disk encryption, network restriction, backup, retention, or incognito attestations
- sensitive raw prompt logging enabled
- missing Redis/Celery configuration
- extension packages containing source maps, TypeScript source, dev folders, AppleDouble metadata, or source map markers
- extension packages containing `.env`, private key, certificate, or nested zip artifacts
- extension packages with weak/missing build hashes
- managed policy mismatch for API URL or tenant ID

HTTP deployments are allowed only as a degraded closed-lab state. For CISO-facing rollout, prefer HTTPS and run the gate with `--require-https`.

## API URL and Tenant Alignment

For 50-user pilots, the extension heartbeat must report the same API URL and tenant ID that the API expects:

- `api_base_url` / `backendUrl` must match `API_BASE_URL`
- `tenant_id` / `tenantId` must match the active pilot tenant

Pilot Health reads the latest `/extension/status` heartbeat and flags:

- `extension_api_url_match=failed` when a deployed extension is still pointed at an old IP/port
- `extension_tenant_match=failed` when the user signed into, or was managed into, the wrong tenant
- `warning` when the extension is too old to report these fields

If either check fails, update the managed browser policy or extension options, sync/reload the extension, then run a fresh extension health report. Do not expand the pilot while any user heartbeat points at a stale API URL or tenant.

## Backups

macOS/Linux:

```bash
cd /Volumes/X10\ Pro/New\ project/repo
DATABASE_URL="postgresql+psycopg2://postgres:REPLACE@127.0.0.1:5432/hawk_pilot" ./scripts/backup_postgres.sh
```

Windows:

```powershell
cd C:\Users\Ayushmaan\Desktop\api-machine-transfer\apps\api
$env:DATABASE_URL = "postgresql+psycopg2://postgres:REPLACE@127.0.0.1:5432/hawk_pilot"
.\scripts\backup_postgres.ps1
```

Store backups on encrypted storage with restricted access.

## Retention

Dry run:

```bash
python3 scripts/prune_pilot_artifacts.py --root ./evidence --root ./artifacts --days 90
```

Execute:

```bash
python3 scripts/prune_pilot_artifacts.py --root ./evidence --root ./artifacts --days 90 --execute
```

## Pilot Health

`GET /dashboard/pilot-health` now includes `deployment_hardening`. It reports:

- PostgreSQL usage
- SECRET_KEY strength and lock status
- HTTPS warning/requirement
- disk encryption attestation
- API firewall attestation
- backup attestation
- evidence/report retention
- incognito policy
- managed extension mode
- policy lock status
- extension version/build hash
- extension API URL and tenant alignment
- password rotation or SSO status

Manual items remain `manual_required` until the operator attests them through environment settings.
