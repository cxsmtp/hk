# Microsoft Graph Enterprise Coverage


## Scope
Hawk AI Microsoft ecosystem coverage now supports:
- `entra_id` connector (identity + audit)
- `microsoft_365` connector (Teams/SharePoint/audit/AI usage indicators)
- `outlook` connector (mailbox activity + AI usage indicators)
- `teams` connector (chat/channel message telemetry)
- `onedrive_sharepoint` connector (file access + sharing posture)
- `office_apps` connector (Word/Excel/PowerPoint Copilot usage indicators)
- `microsoft_defender` connector (security alerts/incidents ingestion)
- `azure_openai` connector (Azure OpenAI usage + gateway routing posture checks)
- `power_platform` connector (Power Apps / Power Automate governance signals)

All ingestion feeds into the existing unified control plane path:
`connector pull -> monitoring signal -> runtime intelligence -> surface control plane -> findings/alerts/audit`.

## Least-Privilege Permission Modes
Use connector `config.permission_mode`:
- `poc_safe` (default)
- `standard`
- `full_enterprise`

API helpers:
- `GET /monitoring/connectors/microsoft/permission-modes`
- `POST /monitoring/connectors/microsoft/resolve-scopes`
- `POST /monitoring/connectors/microsoft/admin-consent-url`
- `GET /monitoring/connectors/microsoft/app-registration-template`
- `POST /monitoring/connectors/bootstrap/microsoft` (one-call bootstrap + optional connector create)
- `POST /monitoring/connectors/bootstrap/slack` (one-call Slack bootstrap + optional connector create)

Microsoft surface ingestion endpoints (unified control path):
- `POST /surface-coverage/microsoft/outlook/events`
- `POST /surface-coverage/microsoft/teams/events`
- `POST /surface-coverage/microsoft/onedrive-sharepoint/events`
- `POST /surface-coverage/microsoft/office-copilot/events`
- `POST /surface-coverage/microsoft/azure-openai/events`

Azure OpenAI routing behavior:
- if `gateway_routed=true`, endpoint is normalized to Hawk Gateway (`https://hawk-gateway.company.com/azure-openai` by default or custom `metadata.gateway_endpoint`)
- upstream Azure endpoint is retained as metadata (`upstream_api_endpoint`) for traceability

## Secure Defaults
- HTTPS is required for Graph base URL and token URL.
- Query-string secret material is rejected.
- OAuth client credentials are supported for Graph:
  - `tenant_id`
  - `client_id`
  - `client_secret`
- Access-token mode is still supported when provided explicitly.
- Client assertion / certificate-backed OAuth credentials are supported for enterprise keyless secret posture.

## Data Minimization
Microsoft connector pulls run metadata-first by default:
- `config.metadata_only_ingestion=true` by default
- content-like fields are redacted from normalized records unless explicitly enabled via `content_scanning_enabled=true`.

## Connector Creation Behavior
When creating a Microsoft connector, Hawk auto-applies:
- `permission_mode` default `poc_safe`
- `app_registration_mode=single_tenant`
- `oauth_flow=client_credentials`
- `base_url=https://graph.microsoft.com/v1.0` (if omitted)
- metadata in `connector.metadata_json.microsoft_graph`:
  - resolved scopes
  - security profile
  - metadata-only setting
  - optional admin consent URL (when `tenant_id`, `client_id`, and `redirect_uri` are supplied)

## Bootstrap Automation
- `POST /monitoring/connectors/bootstrap/microsoft`:
  - validates provider and permission mode
  - resolves required/selected scopes
  - returns admin consent URL
  - optionally creates the connector securely
- `POST /monitoring/connectors/bootstrap/slack`:
  - returns Slack install URL with selected scopes
  - optionally creates connector with encrypted secret payload
- CLI helper:
  - `infra/scripts/connector_bootstrap.py`
  - supports non-interactive Slack/Microsoft bootstrap + optional immediate pull.

## Demo Checklist
1. `GET /monitoring/connectors/microsoft/permission-modes`
2. `POST /monitoring/connectors/microsoft/resolve-scopes` with `provider_key=microsoft_365`, `permission_mode=standard`
3. Create `microsoft_365` connector with `tenant_id/client_id/client_secret/redirect_uri`
4. `POST /monitoring/connectors/{id}/pull`
5. Validate generated monitoring signals + findings + drift alerts in Control Plane
