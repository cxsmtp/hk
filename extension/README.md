# Hawk AI Browser Extension (Manifest V3)

This extension provides:
- AI domain/tool discovery
- Lightweight prompt input checks in-page
- Clipboard and file-upload policy hooks (browser layer)
- `allow | warn | block | hold` control flow
- Hold adjudication delegated to backend
- Telemetry emission to backend with `correlation_id`
- Explicit extension health/status reporting to backend

Backend remains authoritative for policy and evidence decisions.

## Files
- `manifest.json`: MV3 manifest with least-privilege permissions and strict CSP
- `src/service-worker.ts`: policy sync orchestration, telemetry flush, message hub
- `src/content-script.ts`: domain detection, input interception, hold/warn/block UX
- `src/interactions/data-transfer-hooks.ts`: clipboard + file-upload hooks
- `src/policy-sync.ts`: fetch/cache policy + DNR dynamic block rules
- `src/telemetry.ts`: telemetry queue + interaction eval calls
- `src/interactions/input-guard.ts`: lightweight input checks + submit interception
- `src/interactions/output-guard.ts`: output flagging stub
- `src/ui/banner.ts`: warn/hold banners
- `src/ui/interstitial.ts`: block interstitial
- `options.html`, `src/options.ts`: extension configuration UI

## Build
```bash
cd extension
npm install
npm run build
```

Build output is generated in `extension/dist`.

## Load unpacked (Chrome/Edge)
1. Open `chrome://extensions` or `edge://extensions`
2. Enable Developer mode
3. Click **Load unpacked**
4. Select the `extension` folder (not `extension/dist`)

## Configure
Open extension options and set:
- Backend URL (default `http://localhost:8000`)
- Tenant ID
- Access token + refresh token (recommended), or use **Sign In & Fill Session**
- Optional: keep encrypted login in extension storage for automatic session recovery when token refresh fails
- Browser type

Then click **Sync Policy Now**.

## Runtime flow
1. Service worker syncs policy at startup and every 5 minutes (`/extension/policy-sync`)
2. Content script classifies current AI domain:
   - approved / warn / blocked / unknown
3. Extension emits telemetry (`/telemetry/browser`)
4. On prompt submission, input guard runs local checks:
   - sensitive patterns
   - blocked keywords
   - high-risk terms
   - domain policy mismatch
5. For `hold`, extension calls backend adjudication (`/telemetry/browser/interaction-eval`)
6. Backend response drives final action:
   - allow (resume submit)
   - warn (banner + continue/cancel)
   - block (interstitial)
7. Service worker reports extension health/status to backend (`/extension/status`)

## Security constraints
- No secrets hardcoded in extension code
- No remote hosted code
- Strict extension CSP
- Token provided via options, expected short-lived
- Optional credential recovery stores login password encrypted at rest in extension local storage (AES-GCM derived from runtime id)
- All telemetry includes `correlation_id`
- Telemetry attribution includes tenant, policy version, browser profile, and extension version

## E2E demo checklist
1. Visit approved AI domain -> `ai_domain_visit` telemetry
2. Visit blocked domain -> interstitial
3. Visit unknown domain in supported list -> `unknown_ai_detected`
4. Submit prompt with sensitive content -> blocked/warned
5. Submit ambiguous prompt -> `hold_for_backend` -> backend adjudication -> final decision
6. Confirm extension health report arrives in backend

## Playwright E2E
The Playwright suite is deterministic and does not depend on live external AI sites:
- it loads the unpacked extension in Chromium
- spins a local mock backend implementing:
  - `GET /extension/policy-sync`
  - `POST /telemetry/browser`
  - `POST /telemetry/browser/interaction-eval`
  - `POST /extension/status`
- fulfills AI host pages with synthetic HTML so content-script interception is testable

Run:
```bash
cd extension
npm ci
npm run build
npm run test:e2e -- tests/e2e/browser-extension.spec.ts
```

The mock sign-in fixture supplies a synthetic actor email, matching the identity
stored by normal sign-in. Telemetry intentionally requires a tenant, backend and
actor; tests must not disable that scope guard. The suite verifies the actor email
on emitted telemetry as well as the existing policy, correlation and denial checks.

Validated on 23 October 2026 with locked Playwright 1.58.2 and the official
`mcr.microsoft.com/playwright:v1.58.2-noble` image (digest
`sha256:6446946a1d9fd62d9ae501312a2d76a43ee688542b21622056a372959b65d63d`).
After locked install and build in a disposable checkout, the test container used
`--network none`, Xvfb and no mounted credentials. Its command was:

```bash
xvfb-run -a ./node_modules/.bin/playwright test tests/e2e/browser-extension.spec.ts
```

All ten tests passed without skips. This is mock-backend browser coverage, not
validation of live provider accounts or the live-backend suite below.

### Live Backend E2E (Discovery/Findings/Runtime/Auditor assertions)
This suite loads the unpacked extension in Chromium and validates backend state end-to-end.

Prereqs:
- API running at `http://localhost:8000`
- working auth/register endpoints

Run:
```bash
cd extension
npm run build
EXT_E2E_LIVE_BACKEND=1 npm run test:e2e -- tests/e2e/browser-extension.live.spec.ts
```

Optional env overrides:
- `EXT_E2E_BACKEND_URL` (default `http://localhost:8000`)
- `EXT_E2E_HEADED=0` to run headless mode
- `EXT_E2E_APPROVED_ORIGIN`, `EXT_E2E_BLOCKED_ORIGIN`, `EXT_E2E_UNKNOWN_ORIGIN`, `EXT_E2E_PROMPT_ORIGIN`

Artifacts:
- Per-test JSON debug bundle with raw telemetry payloads and backend correlation IDs
- screenshots
- HAR capture
- Written under Playwright `test-results/`
