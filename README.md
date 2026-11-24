# Hawk AI

Hawk AI is an enterprise AI visibility, governance and action-control platform. Its scope spans how people and software use AI, which models and tools participate, and what enterprise actions follow. It is broader than prompt filtering or agent security alone. The intended control path is:

**User → AI application or agent → model → tool / MCP → API → enterprise action → evidence**

Discovery identifies activity and deployment surfaces; policy and authorization determine what should be permitted; integrations can observe or enforce at supported points; evidence records what was observed, decided and actually executed. Observation is not proof of blocking, and a policy decision is not proof that a downstream action was prevented. Coverage must be demonstrated for each adapter, transport and deployment mode.

## Current repository status

The selected current-worktree baseline is restored for collaboration: 857 initial files, 1,214 later source/document restorations and 17 original dependency/configuration files have provenance receipts. Historical-only capability variants are preserved and explicitly unresolved; they are not silently merged or represented as implemented. Full platform acceptance is **not yet complete**.

Verified setup and execution evidence:

- Web: fresh locked install, 53-page production build and 272 UI tests pass. Native and isolated Docker browser tests pass fixture login and eight routes without JavaScript errors or API 5xx.
- API: native, Docker and GitHub integration pass all 10 tests, including four PostgreSQL acceptance cases, migrations, seeds, actual API/worker/beat readiness and strict health. Synthetic signing/configuration checks pass; these are not production credentials.
- Extension: strict typecheck, 143 unit tests and build pass. All 10 deterministic browser tests pass with external networking disabled after correcting the mock login identity. SDK build/35 tests and MCP proxy/216 tests pass. All five branches pass component and import checks at application commit `8cf2a93`.
- Python dependencies: the original 27 API direct pins now have complete uv and pip hash locks. Fresh API and endpoint environments install cleanly and pass compatibility checks, 36 connector tests and 66 endpoint tests. The locked Linux Docker candidate also builds and passes all 10 integration tests.
- Full API units: **5,076 passed, zero failed, four deselected** on Python 3.11 from an untouched archive of `245f772`. Its API tree is identical to `5ee8398`. The incomplete TLS fixture is corrected; all 45 destination-policy tests also pass on Python 3.11 Linux and Python 3.12 macOS. GitHub jobs for the published fixes did not start because of an account billing/spending restriction. See [the validation record](docs/collaboration/validation-2026-10-23.md).
- Endpoint software: 871 tests and eight subtests pass locally and in the macOS 26/Xcode 26.6 CI environment; four installed-provider acceptance tests are explicitly deselected and unverified. Desktop guard software: 39 tests pass from the same untouched application commit.

The endpoint identity/transport repair (`d4fc192`) and bounded risk-escalation ID repair were explicitly approved and tested. The separate simulation transaction-recovery patch is held outside published source. Unit-profile defaults disable HMAIR/CIE feature flags and strict dependency checks; enabled integration behavior is exercised separately. Live provider accounts, target OS installation/enrollment, hardware signing, release upgrade/rollback and production deployment remain distinct acceptance gates. See [source accounting](docs/collaboration/source-accounting.md) and [cloud setup](docs/collaboration/cloud-development.md).

## Deployment surfaces and code map

The table identifies source evidence and intended responsibilities. **No surface has end-to-end enforcement verified in this collaboration checkout yet.**

| Surface | Responsibility and existing source evidence | Current verification boundary |
|---|---|---|
| Browser extension | Browser AI discovery, application adapters, interaction context and policy evaluation. `extension/src/` includes app adapters, context state, policy-evaluation client, endpoint bridge and UI. | Entrypoints, manifest, options and policy sync restored; strict typecheck, 143 unit tests, build and 10 mock-backend browser tests pass. Live-provider browser flows remain unverified. |
| Endpoint | Device discovery and local policy/control integration. `apps/endpoint-agent/` includes policy, endpoint-floor and native-control code; package declares operator, metadata-scan and hook commands. | Source and locked dependency setup restored; 871 software tests and eight subtests pass, with four installed-provider tests explicitly unrun. OS-specific installation/enrollment remains unverified. Do not install certificates, change proxy settings or enroll devices as a setup shortcut. |
| Agent/runtime/native hooks | Integration points for agent and native desktop activity. `apps/endpoint-agent/src/hawk_endpoint_agent/native_control/`, `apps/desktop-guard/`, extension runtime discovery and API native-control services. | Endpoint software and 39 desktop-guard tests pass. Installed hooks, provider versions and OS permissions remain separately unverified; software fixtures do not establish live control coverage. |
| LLM gateway | Model/provider interaction and governance. `apps/api/app/services/llm_gateway_secure/`, gateway discovery adapter, SDK contracts and API services. | Current source and integration fixtures restored. Live provider authentication, streaming and enforcement need configured target acceptance; synthetic integration does not establish those. |
| MCP gateway | Tool authorization/context and result inspection. `packages/hawk-mcp-proxy/` declares a local stdio proxy; API `services/mcp/` and approval/discovery services contain related contracts. | 216 passed / 0 failed (CLI entry and manual-terminal README now restored; short TMPDIR resolves Unix socket path limit). Local stdio is the package's declared transport. Remote HTTP is a separate surface to verify where implemented; it is not claimed operational from stdio evidence. |
| SaaS/API integrations | Discovery and governance across connected enterprise systems. API collectors include Microsoft Copilot, Azure Foundry, SDK, local proxy and other sources under `apps/api/app/services/`. | Adapter files show integration work, not verified connected accounts or complete control coverage. Permissions and credentials require owner configuration. |
| GitHub repository control | Product capability for repository access/action governance. API models and migrations include GitHub repository access/runtime controls; a GitHub Enterprise source connector exists. | Partial/unverified product work. This repository's Git collaboration setup is distinct from Hawk's GitHub control feature. |
| API and evidence | Shared policies, identity/context, discovery, decisions and evidence models/services under `apps/api/app/`; regression tests in `apps/api/tests/`. | Native, Docker and GitHub integration pass, including strict readiness and PostgreSQL acceptance. The full-unit result is tracked by the linked exact application-commit run; live external integrations and production settings are not certified. |
| Web console | Enterprise control-plane UI under `apps/web/src/`, with UI tests in `apps/web/tests/`. | Next production build passes 53 pages; 272 UI tests plus native/Docker login and eight-route browser checks pass. This is not exhaustive live-provider feature acceptance. |
| SDK and shared contracts | `packages/hawk-sdk/` client/types and `packages/shared/schemas/` for applications, gateways and integrations. | SDK build and 35 tests pass. Endpoint client source restored. |

MCP gateway, LLM gateway, browser extension, hooks and GitHub control remain explicit development priorities. Completing new MVP capabilities is separate from restoring and testing the currently implemented platform. Planned capabilities must stay labeled planned until implementation and tests support a stronger claim.

## Collaboration branches

| Branch | Work lane |
|---|---|
| `main` | Reviewed shared baseline |
| `development/mcp-gateway` | MCP proxy/gateway, tool contracts and API integration |
| `development/llm-gateway` | Model/provider gateway, policy and SDK integration |
| `development/browser-extension` | Browser adapters, interactions, extension UI and endpoint bridge |
| `development/hooks` | Endpoint, runtime and native desktop hooks across supported operating systems |

These branches currently share the same baseline. Use short-lived feature branches and pull requests into the relevant lane, then integrate reviewed changes into `main`. Keep shared API, UI, SDK and contract changes coordinated across lanes; branches do not imply that components are independently deployable.

## Local development

Native-local collaborators: follow [the Docker-free bootstrap](docs/collaboration/native-local.md) for locked installs, private PostgreSQL 16/Redis 7 data, migrations/seeds, API/web/worker/beat startup and integration/browser checks. Docker setup remains a separate path in [cloud-development.md](docs/collaboration/cloud-development.md). Earlier host API/web evidence used Docker data services and is hybrid. An untouched archive of published `5ee8398` passed all 10 integration tests, all 272 web tests, the web build and fixture login/eight routes with native PostgreSQL 16/Redis 7; no Docker or source overlays were used.

Prerequisites: Git, Node.js/npm and Python 3.11 or newer. The initial checks used Node 20.20.2, npm 10.8.2 and Python 3.12.9 on macOS. These are observed local versions, not a complete supported-platform matrix. Endpoint packaging must be validated on its target OS/architecture.

Clone this private repository using your individually authorized GitHub identity. Obtain access from the owner; do not share tokens. Start with the provenance check:

```sh
python3 tools/collaboration/check_import.py
```

Install each JavaScript component from its existing lockfile, initially without lifecycle scripts:

```sh
cd apps/web                     # repeat in extension, packages/hawk-sdk, packages/hawk-mcp-proxy
npm ci --ignore-scripts --no-audit --no-fund
```

Review any required lifecycle scripts before enabling them. A successful install does not establish that the app builds or runs. Preserve the lockfiles; do not guess replacement dependencies.

For isolated Python setup, after source/configuration recovery:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r apps/api/requirements.lock
# Separate endpoint environment, using uv 0.11.6 or a compatible release:
(cd apps/endpoint-agent && uv sync --locked --extra dev --extra fast)
```

API requirements installation passed with binary wheels from PyPI in an isolated virtual environment. Disposable PostgreSQL/Redis CI starts API, worker and beat successfully; strict readiness and compatibility checks pass. The complete local API unit profile passed with 5,076 passed, zero failed and four deselected; latest hosted CI remains blocked by GitHub billing, and live-provider acceptance remains unverified. `apps/api/pyproject.toml` mirrors the 27 existing direct requirements; `uv.lock` resolves their full graph and `requirements.lock` exports pinned versions with artifact hashes for pip and CI. The endpoint lock pins its development dependency graph while its package metadata retains supported version ranges. Both locks installed into fresh isolated Python 3.12 environments; target-platform builds and OS acceptance remain separate. Database, queue, identity/provider and other service settings must come from reviewed configuration contracts. Do not connect tests to production services or run migrations against an existing database.

## Build and test commands

Run from the listed directory. Commands and failures are tracked explicitly; this table is not a passing certification.

| Directory | Commands | Latest observed result |
|---|---|---|
| Repository root | `python3 tools/collaboration/check_import.py` | Pass: source/dependency hashes and Python parsing; reviewed modifications retain original provenance. |
| `apps/web` | `npm run build`; `npm run test:ui`; after a successful build, `npm start` | Build passes. UI Node tests: 272 passed; missing validation route and banking reference restored. Native and Docker fixture login plus eight navigation routes passed without JavaScript errors or API 5xx. Live-provider feature acceptance remains separate. |
| `extension` | `npx tsc --noEmit -p tsconfig.json`; `npm test`; `npm run build` | Typecheck, 143 unit tests and build pass. All 10 mock-backend browser tests pass in isolated headed Chromium with external networking disabled; live-backend/provider E2E remains unrun. |
| `packages/hawk-sdk` | `npm run build`; `npm test` | Build passes; 35 tests pass. |
| `packages/hawk-mcp-proxy` | `npm test` | 216 passed / 0 failed (short TMPDIR resolves Unix socket path limit). |
| `apps/api` | Use the documented unit profile and [native bootstrap](docs/collaboration/native-local.md) for isolated startup/integration. | Full local Python 3.11 units: 5,076 passed / 0 failed / 4 deselected. Exact published native setup: 10 integration tests, all four PostgreSQL acceptance cases, migrations/seeds, API/worker/beat and strict readiness pass. Hosted CI for the final fixes is blocked before execution by account billing. |
| `apps/endpoint-agent` | Follow the frozen software-suite command in [its README](apps/endpoint-agent/README.md). | 871 tests and eight subtests pass; four installed-provider tests are explicitly deselected. Live binary/OS, enrollment and native-hook acceptance remain unrun. |
| `apps/desktop-guard` | `PYTHONPATH=src python -m pytest tests` in the endpoint development environment on macOS | 39 software/native-signature-verifier tests pass; input/window/API dependencies are mocked. No live desktop-provider acceptance claim. |

Full acceptance requires a clean install, API startup and relevant API regressions, UI build and operation, and the existing platform's feature flows across deployment surfaces. Record externally dependent or OS-specific checks separately; do not infer them from unit tests.

## SDLC, CI/CD and DevSecOps

Read [CONTRIBUTING.md](CONTRIBUTING.md) before a change. Each pull request should explain behavior, source lineage, dependencies, configuration/migration impact, tests, remaining limits and rollback. Review the exact diff and secret/configuration handling. Preserve compatibility across API, SDK, UI, gateway and hook contracts.

The workflows use pinned actions, read-only repository permissions and no persisted Git credentials. Import integrity checks provenance and Python syntax. Component checks install the existing npm lockfiles and run web build/UI tests, extension typecheck/tests/build, SDK build/tests and MCP proxy tests. All five branches passed these checks on `8cf2a93`.

API Tests separates the full SQLite unit profile from disposable PostgreSQL 16/Redis 7 integration with migrations, seeded fixtures, API/worker/beat and four PostgreSQL acceptance tests. Its protected `/private/tmp` fixture is provisioned on disposable Linux runners; the application validator is unchanged. Unit execution reports the whole batch rather than stopping after the first failure. [The published native-setup API run](https://github.com/dang070298/hhaawwkk--aaii/actions/runs/39908855560) records the hosted billing block before any step ran. The complete local result and its exact source are recorded in [validation-2026-10-23.md](docs/collaboration/validation-2026-10-23.md); a local pass is not a hosted-CI pass.

Endpoint software checks use the frozen lock, macOS 26/Xcode 26.6, a fresh home/temp directory and the virtual environment for child scripts. Tests retain expiry, signature, identity and fail-closed assertions. Four installed-provider tests are explicitly excluded because they require separate configured target acceptance. Check [all workflows](https://github.com/dang070298/hhaawwkk--aaii/actions) for branch-specific terminal results. These checks do not exercise live provider accounts or installed OS controls.

Required reviews, branch protections, dependency/security scanning and release environments are not established merely by this README. Repository settings, new access grants, cloud credentials/OIDC trust and production releases require the owner's appropriate approval. CD is not configured. Follow [cloud-development.md](docs/collaboration/cloud-development.md) to validate a clean cloud checkout, isolated service dependencies, migrations, deployment and rollback before release automation.

## Secrets and known limitations

Never commit local `.env` files, credentials, private keys, logs, databases, preservation archives, dependency directories or unscreened Git history. Use approved environment/secret injection per deployment. Supply only reviewed nonsecret configuration examples. Secret-bearing preservation archives require encrypted storage with the owner entering the password privately; this repository is not an archive destination.

The selected current-worktree source and document disposition is complete. Secret/private runtime material and generated artifacts remain excluded with reasons. The owner chose to preserve 49 historical-only paths as unresolved variants; they are not proven omissions from this baseline and their migrations are not merged automatically. The imported source manifest stays immutable; reviewed changes record both original and updated hashes.

Known product findings, unsupported integrations and unfinished MVP work must remain visible during collaboration. Passing builds will be necessary but will not by themselves prove that enterprise actions are correctly authorized, enforced and evidenced.
