# Cloud development and release setup

For a fully native local stack, use [native-local.md](native-local.md). That path runs PostgreSQL, Redis, API, worker/beat and web without Docker. The Docker instructions below remain a separate deployment/test option.

The repository uses relative source paths and does not depend on the owner's local preservation mount. GitHub's clean Linux checkouts pass web, extension, SDK and MCP checks; API integration passes with disposable PostgreSQL and Redis. Full API unit acceptance is still tracked separately.

Complete these concrete setup prerequisites before calling the baseline runnable:

1. Existing dependency manifests and npm locks for API, endpoint, web, extension, MCP proxy and SDK packages are now recorded in `dependency-manifest.json`. The selected current-worktree source/dependency and document dispositions are complete; review any new lifecycle/install scripts before enabling them. API `uv.lock` pins the complete graph derived from the unchanged 27 direct requirements; hash-exported `requirements.lock` is used by pip, CI and the Docker wheel builder. Endpoint `uv.lock` pins its development and optional-extra resolutions. Do not recreate guessed dependencies from imports.
2. Create documented nonsecret configuration examples from the reviewed configuration contract. Inject credentials through approved environment/secret mechanisms; never copy a local .env.
3. In a clean isolated environment, install exact locked dependencies and run each lane's documented unit/build checks plus shared API/contract tests. Record failures and unrun tests honestly.
4. The Component checks workflow now runs the verified web, extension, SDK and MCP commands from their existing locks. Check its exact-commit results; live browser/OS/provider acceptance remains separate. Keep import integrity distinct from application checks.
5. Select the cloud provider and deployment environment with the owner; review infrastructure and migrations, then configure protected environments, credentials or OIDC trust with explicit approval. Run deployment and rollback checks before enabling automatic releases.

Import integrity performs source hash and Python parsing checks. API Tests now defines unit and integration jobs; native isolated integration passed all 10 tests on 22 October with the endpoint repair and harness/setup corrections; GitHub integration passes at `755a23b`, and exact `bf6a536` Docker integration and combined browser/API checks passed. Application changes and dependency changes require their own rerun; a previous pass is not transferred silently. CD, cloud credentials, protected environments and deployment are not configured; no successful deployment is claimed. This is a tracked setup gap, not a product-feature prerequisite.

## Disposable integration environment

The same `tools/collaboration/run_api_integration.py` runs in GitHub Actions and the Docker test image. It requires fresh PostgreSQL 16 and Redis 7 services, migrates both `hawk_collaboration_test` and `aicontrol_phase5_acceptance`, seeds fixtures, starts its own API/worker/beat processes, waits for strict readiness and real heartbeats, and runs every integration-marked test. All four PostgreSQL acceptance tests must execute without skips. Signing/encryption values are ephemeral test values, not deployment credentials.

With an already-running Docker engine, use a new unique project for each run:

```sh
make test-integration TEST_PROJECT=hawk-acceptance-$(date -u +%Y%m%d%H%M%S)
```

Keep the printed project name for inspection. This Compose file publishes no host ports and uses no native directories, fixed container names or existing data volumes. The API `test` build target retains pytest; the default `runtime` target still removes test packages. Results remain in the project's `test-results` volume. `make test-integration-down TEST_PROJECT=<same-project>` stops only that project and preserves its volumes. The runner refuses reused databases, so use a fresh project for the next run. Do not run the legacy `infra/docker-compose.test.yml` against native services.

For native execution, supply explicitly disposable PostgreSQL 16/Redis 7 instances on separate loopback ports, set `HAWK_DISPOSABLE_TEST_ENV=1`, `DATABASE_URL` (database name `hawk_collaboration_test`) and `REDIS_URL`, then run the same Python runner using the API virtual environment. `--check-config` validates the target settings without connecting. Native PostgreSQL ports 5432/55432 and Redis 6379 are rejected outside GitHub Actions. The runner never reads a local `.env`, inherits production secrets, stops existing services, or migrates a non-test database.

Static runner/configuration checks and Compose parsing pass. The Docker API test image built successfully. Earlier host-native Python 3.12 execution with Docker-hosted isolated PostgreSQL 16 and Redis 7 passed migrations, seeds, real API/worker/beat readiness, strict health and all 10 integration tests, including all four PostgreSQL acceptance tests. Exact `bf6a536` Docker runtime passed the same 10 tests. Its web image and combined synthetic login/eight-route browser check also passed with no JavaScript errors or API 5xx. The dependency-lock candidate built successfully for Python 3.11 Linux; its new isolated integration run also passed all 10 tests. This uses ephemeral test keys and proves no production credential or external-provider setup.

## Updating Python locks

Use the declared requirements as the dependency authority; do not infer packages
from imports. API direct pins in `requirements.txt` and `pyproject.toml` must agree.
With uv 0.11.6 (the validated resolver), from `apps/api`:

```sh
uv lock
uv export --locked --format requirements.txt --no-header --no-annotate --no-emit-project --no-dev --output-file requirements.lock
uv sync --locked
```

Review all lock changes, public registry URLs, artifact hashes and supported
Python markers. Test a fresh locked environment, then CI and the Docker test
image. The wheel builder verifies downloaded artifact hashes; runtime installation
uses only that verified offline wheel set. Locally built wheels can have different
hashes from upstream source archives, so runtime does not compare wheel bytes to
source-archive hashes. For endpoint development, use `uv sync --locked --extra dev
--extra fast` in `apps/endpoint-agent`; Windows packaging requires its own Windows
target validation. Keep generated environments and egg-info out of Git.
