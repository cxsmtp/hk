# Hawk AI

Hawk AI is an enterprise AI visibility, governance and action-control platform. Its scope spans how people and software use AI, which models and tools participate, and what enterprise actions follow. It is broader than prompt filtering or agent security alone. The intended control path is:

**User → AI application or agent → model → tool / MCP → API → enterprise action → evidence**

Discovery identifies activity and deployment surfaces; policy and authorization determine what should be permitted; integrations can observe or enforce at supported points; evidence records what was observed, decided and actually executed. Observation is not proof of blocking, and a policy decision is not proof that a downstream action was prevented. Coverage must be demonstrated for each adapter, transport and deployment mode.


## Deployment surfaces and code map

The table identifies source evidence and intended responsibilities. **No surface has end-to-end enforcement verified yet.**

| Surface | Responsibility and existing source evidence | Current verification boundary |
|---|---|---|
| Browser extension | Browser AI discovery, application adapters, interaction context and policy evaluation. `extension/src/` includes app adapters, context state, policy-evaluation client, endpoint bridge and UI. | Entrypoints, manifest, options and policy sync; strict typecheck, 143 unit tests, build and 10 mock-backend browser tests pass. Live-provider browser flows remain unverified. |
| Endpoint | Device discovery and local policy/control integration. `apps/endpoint-agent/` includes policy, endpoint-floor and native-control code; package declares operator, metadata-scan and hook commands. | Source and locked dependency setup; 871 software tests and eight subtests pass, with four installed-provider tests explicitly unrun. OS-specific installation/enrollment remains unverified. Do not install certificates, change proxy settings or enroll devices as a setup shortcut. |
| Agent/runtime/native hooks | Integration points for agent and native desktop activity. `apps/endpoint-agent/src/hawk_endpoint_agent/native_control/`, `apps/desktop-guard/`, extension runtime discovery and API native-control services. | Endpoint software and 39 desktop-guard tests pass. Installed hooks, provider versions and OS permissions remain separately unverified; software fixtures do not establish live control coverage. |
| LLM gateway | Model/provider interaction and governance. `apps/api/app/services/llm_gateway_secure/`, gateway discovery adapter, SDK contracts and API services. | Current source and integration fixtures. Live provider authentication, streaming and enforcement need configured target acceptance; synthetic integration does not establish those. |
| MCP gateway | Tool authorization/context and result inspection. `packages/hawk-mcp-proxy/` declares a local stdio proxy; API `services/mcp/` and approval/discovery services contain related contracts. | 216 passed / 0 failed (CLI entry and manual-terminal README now; short TMPDIR resolves Unix socket path limit). Local stdio is the package's declared transport. Remote HTTP is a separate surface to verify where implemented; it is not claimed operational from stdio evidence. |
| SaaS/API integrations | Discovery and governance across connected enterprise systems. API collectors include Microsoft Copilot, Azure Foundry, SDK, local proxy and other sources under `apps/api/app/services/`. | Adapter files show integration work, not verified connected accounts or complete control coverage. Permissions and credentials require owner configuration. |
| API and evidence | Shared policies, identity/context, discovery, decisions and evidence models/services under `apps/api/app/`; regression tests in `apps/api/tests/`. | Native, Docker and GitHub integration pass, including strict readiness and PostgreSQL acceptance. The full-unit result is tracked by the linked exact application-commit run; live external integrations and production settings are not certified. |
| Web console | Enterprise control-plane UI under `apps/web/src/`, with UI tests in `apps/web/tests/`. | Next production build passes 53 pages; 272 UI tests plus native/Docker login and eight-route browser checks pass. This is not exhaustive live-provider feature acceptance. |
| SDK and shared contracts | `packages/hawk-sdk/` client/types and `packages/shared/schemas/` for applications, gateways and integrations. | SDK build and 35 tests pass. Endpoint client source. |

MCP gateway, LLM gateway, browser extension, hooks and GitHub control remain explicit development priorities. Completing new MVP capabilities is separate from restoring and testing the currently implemented platform. Planned capabilities must stay labeled planned until implementation and tests support a stronger claim.

## Install

On one Linux machine with Docker: `sudo deploy/install.sh`. It generates the secrets, starts the stack and prints the first administrator's sign-in. See [deploy/README.md](deploy/README.md). With the published, signed images (`HAWK_RELEASE` in `deploy/.env`), owners and admins update and roll back from Settings → Updates ([docs/updating.md](docs/updating.md), [docs/integrity.md](docs/integrity.md)); Hawk AI checks and repairs itself every 5 minutes and can be left hands-off ([docs/hands-off.md](docs/hands-off.md)); every release is in [CHANGELOG.md](CHANGELOG.md).

## Local development

Prerequisites: Git, Node.js 20+/npm, Python 3.11+, PostgreSQL 16 and Redis 7 (or Docker). See [native local setup](docs/development/native-local.md) and [Docker/cloud setup](docs/development/cloud-development.md).

```sh
# JavaScript components (repeat in extension, packages/hawk-sdk, packages/hawk-mcp-proxy)
cd apps/web && npm ci --ignore-scripts --no-audit --no-fund

# API
python3 -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r apps/api/requirements.lock

# Endpoint agent (separate environment)
(cd apps/endpoint-agent && uv sync --locked --extra dev --extra fast)
```

## Build and test commands

| Directory | Commands |
|---|---|
| `apps/web` | `npm run build`; `npm run test:ui`; `npm run lint` |
| `extension` | `npx tsc --noEmit -p tsconfig.json`; `npm test`; `npm run build` |
| `packages/hawk-sdk` | `npm run build`; `npm test` |
| `packages/hawk-mcp-proxy` | `npm test` |
| `apps/api` | `make test-unit` (from repository root) |
| `apps/endpoint-agent` | see [its README](apps/endpoint-agent/README.md) |
| `apps/desktop-guard` | `PYTHONPATH=src python -m pytest tests` |

## Secrets

Never commit `.env` files, credentials, private keys, logs or databases. Supply secrets through files or a secret manager per deployment.

## License

Proprietary. Copyright (c) 2026 Bhawani Singh. All rights reserved. See [LICENSE](LICENSE).
