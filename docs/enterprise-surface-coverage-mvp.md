# Enterprise Surface Coverage MVP


This document describes the unified control-plane ingestion implemented for SaaS, endpoint/desktop, browser, and developer-tool events.

## Objective
All AI interactions are ingested into one enforcement path:

`surface event -> Hawk Gateway runtime normalization -> control engine + AI IAM -> enforcement decision -> activity/audit trace`

## New API Surface

### Unified multi-surface ingestion
- `POST /surface-coverage/events`
- `POST /surface-coverage/events/batch`

### SaaS wrappers
- `POST /surface-coverage/saas/slack/events`
- `POST /surface-coverage/saas/o365/events`
- `POST /surface-coverage/saas/google-workspace/events`

### SaaS raw adapters (connector-native payloads)
- `POST /surface-coverage/saas/slack/events/raw`
- `POST /surface-coverage/saas/o365/events/raw`
- `POST /surface-coverage/saas/google-workspace/events/raw`

### Endpoint / dev-tool ingestion
- `POST /surface-coverage/endpoint/events`
- `POST /surface-coverage/endpoint/heartbeat`
- `POST /surface-coverage/dev-tools/events`

### Unified identity and alert trace
- `GET /surface-coverage/identity/{user_id}`
- `GET /surface-coverage/alerts`
- `GET /surface-coverage/alerts/{alert_id}`

## Canonical Event Response
Each ingested event returns:
- `user_id`
- `app`
- `device_id`
- `prompt_or_content` (redacted preview)
- `sensitivity_score`
- `ai_usage_detected`
- `policy_triggered`
- `decision` (`allow|warn|block`)
- `timestamp`
- plus trace IDs (`runtime_event_id`, `audit_action_id`, `alert_id`)

## Unified Enforcement Guarantees in MVP

1. Surface normalization to one runtime path.
2. Sensitivity detection/classification on every event.
3. Transport policy checks (fail-closed signals):
   - TLS requirement checks
   - mTLS-required checks
   - sensitive query-string key checks
4. Endpoint/dev-tool no-bypass rule:
   - AI usage with `gateway_routed=false` -> blocked with `gateway_bypass_detected`.
5. Full audit timeline linkage via activity/audit service.

## Connector-to-Control-Plane Forwarding
Connector monitoring signals that represent AI usage (e.g. `saas.*.ai_usage`) are now forwarded to the same unified surface control service.

Result:
- connector evidence and drift path remain intact,
- plus the same runtime control/evaluation path is executed,
- and payload linkage is stored under `payload.surface_control_plane`.

## Deployment Modes

### 1) SaaS-only mode
- Use connector pulls and/or raw SaaS adapter endpoints.
- No endpoint agent required.

### 2) SaaS + browser mode
- Add browser extension telemetry.
- Use same policy/control plane outputs and alert center.

### 3) Full POC mode (SaaS + browser + endpoint/dev-tool)
- Feed endpoint heartbeats and endpoint/dev-tool events.
- Mark AI API calls with `gateway_routed=true` when proxied through gateway.

## SailPoint Integration Modes

### IdentityNow (existing)
- `provider_key=sailpoint`
- `config.api_variant=identitynow_v3` (default)
- uses OAuth client credentials (`client_id` + `client_secret`)

### IdentityIQ SCIM (new)
- `provider_key=sailpoint`
- `config.api_variant=iiq_scim`
- `config.base_url=https://<host>/identityiq/scim/v2`
- supports auth:
  - `username + password` (basic auth), or
  - `username + api_key` (basic auth), or
  - token/api key as bearer

Pulled entities in IIQ SCIM mode:
- identities (`/Users`)
- roles (`/Roles`)
- entitlements (`/Entitlements`)
- accounts (`/Accounts`)
- events/task results (`/TaskResults`)

## Example: Slack raw event

```json
{
  "type": "event_callback",
  "team_id": "T123",
  "event_id": "Ev01",
  "event": {
    "type": "message",
    "user": "user-123",
    "text": "Use ChatGPT to summarize this roadmap",
    "channel": "C123"
  }
}
```

## Example: Endpoint heartbeat

```json
{
  "user_id": "user-123",
  "device_id": "macbook-001",
  "hostname": "macbook-001.local",
  "os_type": "mac",
  "os_version": "14.7",
  "running_apps": ["Slack Desktop", "VS Code", "Codex CLI"],
  "gateway_routed": true
}
```

## Current Scope / Honest Gaps

Implemented now:
- unified ingestion + enforcement APIs,
- SaaS wrappers and raw adapters,
- endpoint heartbeat/event ingestion,
- identity graph/timeline and alert trace APIs,
- connector AI-usage forwarding into unified control path,
- endpoint deployment scripts:
  - `infra/scripts/endpoint_agent.py` (daemon-ready heartbeat + dev-tool emit),
  - `infra/scripts/endpoint_proxy_guard.py` (proxy guard + system proxy apply/clear),
  - `infra/scripts/connector_bootstrap.py` (Slack/Microsoft bootstrap automation).

Still intentionally not in this pass:
- signed native endpoint binaries/daemon installers (MSI/PKG) with fleet MDM packaging,
- kernel/driver-level transparent interception.

The current implementation remains deployable for enterprise POC in days while preserving fail-closed policy checks.
