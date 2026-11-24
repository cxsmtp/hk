# On-Prem Gateway Stub

Minimal on-prem gateway process for:

- policy sync from cloud control plane
- local policy cache
- signed evidence bundle creation
- signed bundle upload to cloud ingest endpoint

## Run

```bash
cd apps/api
uvicorn app.onprem_gateway.main:app --host 127.0.0.1 --port 8081
```

## Required env vars

- `ONPREM_CLOUD_BASE_URL` (example: `http://localhost:8000`)
- `ONPREM_BEARER_TOKEN`
- `ONPREM_TENANT_ID`
- `ONPREM_GATEWAY_ID` (optional, default `onprem-gateway-stub`)
- `ONPREM_SIGNING_SECRET` (required, minimum 32 characters, must match cloud `ONPREM_BUNDLE_SIGNING_SECRET`; no development default is accepted)
- `ONPREM_LOCAL_AUTH_TOKEN` (required, minimum 32 characters; protects every local control and evidence route)
- `ONPREM_POLICY_CACHE_PATH` (optional, default `./onprem_cache/policy_sync.json`)
- `ONPREM_HTTP_TIMEOUT_SECONDS` (optional, default `30`)
- `ONPREM_RETRY_MAX_ATTEMPTS` (optional, default `3`)
- `ONPREM_RETRY_BACKOFF_SECONDS` (optional, default `0.5`)

## Local endpoints

- `POST /policy/sync`
- `GET /policy/cache`
- `POST /evidence/bundle`
- `POST /evidence/upload`

`GET /health` is intentionally unauthenticated and returns no tenant or secret data.
All other routes require `Authorization: Bearer <ONPREM_LOCAL_AUTH_TOKEN>`.
Keep the helper bound to loopback. Binding to a LAN interface is an explicit
deployment decision and requires host firewall restrictions plus TLS termination.
