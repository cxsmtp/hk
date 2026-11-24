# Native local development and acceptance

This path runs PostgreSQL, Redis, API, Celery worker/beat and the web console as
local processes. Docker and Podman are not used. Start from a clean checkout of
the selected collaboration branch. The commands below use synthetic development
fixtures, fresh private data and loopback-only ports; they do not enroll devices,
configure external providers, change trust stores or operate on an existing Hawk
database.

The older `infra/scripts/native-*.sh` scripts and `docs/LOCAL_NATIVE_DEMO.md` are
preserved source. They can load an existing `.env`, select existing databases and
machine-specific paths. Use the isolated bootstrap below for a new collaborator
checkout. Earlier host API/web checks with Docker database services are **hybrid**
evidence, not fully native evidence.

## Prerequisites and locked installation

Use Python 3.11 or 3.12, uv 0.11.6, Node 20/npm 10, PostgreSQL **16** and Redis
**7**. macOS endpoint/native compiler tests additionally need the Xcode/SDK listed
in `apps/endpoint-agent/README.md`; other operating systems have separate native
acceptance requirements. Install PostgreSQL and Redis through their official
platform instructions or verified source packages. The bootstrap checks actual
binary versions and rejects another major version rather than silently changing
the migration/test contract. It never installs or starts a system service.

- PostgreSQL distributions/source: <https://www.postgresql.org/download/>
- Redis source installation: <https://redis.io/docs/latest/operate/oss_and_stack/install/archive/install-redis/install-redis-from-source/>

From the repository root, install the declared locks:

```sh
uv sync --locked --python 3.12 --project apps/api
uv sync --locked --python 3.12 --project apps/endpoint-agent --extra dev --extra fast
npm --prefix apps/web ci --ignore-scripts --no-audit --no-fund
npm --prefix extension ci --ignore-scripts --no-audit --no-fund
npm --prefix packages/hawk-sdk ci --ignore-scripts --no-audit --no-fund
npm --prefix packages/hawk-mcp-proxy ci --ignore-scripts --no-audit --no-fund
```

These commands use the committed dependency graphs. They do not copy the owner's
virtual environments, node_modules or credentials. For the optional browser check,
install the Chromium revision declared by the extension's existing Playwright lock:

```sh
(cd extension && npx --no-install playwright install chromium)
```

Alternatively provide an already-installed compatible Chromium executable with
`--browser-executable`; a fresh automation profile is used. No personal browser
profile or installed extensions are loaded.

## Configuration and read-only preflight

`infra/native-local.example.json` contains only paths, never passwords. Copy it
to a local ignored location if overrides are needed. Set `postgres_bin` to the
directory containing PostgreSQL 16's `postgres`, `initdb`, `createdb` and
`pg_isready`, and `redis_bin` to the directory containing Redis 7's `redis-server`.
Null means discover through PATH. There are no `/Volumes`, owner-home, Homebrew,
Postgres.app or `/Library/PostgreSQL` assumptions in the bootstrap.

```sh
mkdir -p .runtime
apps/api/.venv/bin/python tools/collaboration/native_local.py \
  --config infra/native-local.example.json --check
```

CLI paths override the template, for example `--postgres-bin /path/to/pg16/bin`.
The state directory must not already exist, and its parent must be a canonical
directory without symlink aliases. Preflight reads versions and checks prerequisites
without creating data, connecting to services or applying migrations.

## Run and verify the whole local stack

```sh
apps/api/.venv/bin/python tools/collaboration/native_local.py \
  --config infra/native-local.example.json --browser-smoke
```

The bootstrap creates a private state directory, initializes a new PostgreSQL 16
cluster with a random test-only SCRAM password, starts PostgreSQL and Redis on
unused loopback ports, pins the database clock convention to UTC, and verifies that their data directories belong to this
invocation. It then runs the same committed integration runner as CI:

PostgreSQL uses TCP with SCRAM authentication and no Unix socket pathname, so a
long checkout/state path does not exceed macOS's Unix socket length limit. The
browser executable is resolved before the runner isolates HOME, avoiding loss of
the caller's already-installed Playwright cache.

1. Refuse reused/non-test databases; create the two named disposable test databases.
2. Apply the current 92-revision migration lineage and both seed scripts.
3. Start API, worker and beat with explicit Redis URLs, correct component identities,
   strict dependency checks and fail-secure behavior.
4. Verify readiness, actual worker/beat heartbeats, component compatibility and
   strict control-plane health.
5. Run all integration-marked tests, requiring all four PostgreSQL acceptance
   cases without skips.
6. Run web UI tests, build the web console for the actual local API URL, start it
   on loopback, and test synthetic login plus eight documented routes in a fresh
   browser, rejecting JavaScript errors and API 5xx responses.

`--web` runs the web build/unit/readiness checks without browser automation.
Without either flag, the command verifies native data services and API integration.
This does not replace the full API unit suite or installed-provider acceptance.
All subprocess exit codes are checked. Logs, JSON results and the optional browser
screenshot remain in the private state directory; secrets are not printed or
committed. The runner stops only processes it started and preserves their data.

Add `--serve` to keep the verified development stack running after acceptance:

```sh
apps/api/.venv/bin/python tools/collaboration/native_local.py \
  --config infra/native-local.example.json --web --serve
```

The command prints the actual API and web URLs after readiness. Ctrl-C performs
owned-process cleanup; it never restarts an existing API, kills a port owner or
deletes a volume. Choose a new state directory for each invocation, such as
`--state-dir .runtime/native-run-002`. Existing runs are deliberately not migrated
or seeded again. Preserve any data you need before owner-directed removal.

## Configuration, encryption and TLS boundaries

The integration runner generates ephemeral signing/encryption values, enables
the secret-key lock, and keeps artifacts under its private state directory.
These values are for synthetic local fixtures. Do not import real provider
credentials, customer data or production signing keys into this development run.
Production storage/key-provider configuration requires its own deployment review.

The isolated browser/API route uses explicit **HTTP on 127.0.0.1**; it makes no
HTTPS or certificate-trust claim. Outbound application HTTPS verification remains
enabled. No `--insecure`, certificate installation, global trust change or proxy
change is part of this bootstrap. If a target feature requires the existing HTTPS
gateway or installed native hooks, configure and validate that target separately
through its documented owner-approved setup. Do not use an insecure health probe
as evidence of valid TLS.

## Other component and regression checks

Use the root README and component READMEs for full API units, extension strict
types/build/143 tests, SDK build/tests, MCP tests and endpoint/native-hook tests.
The four installed-provider endpoint acceptance cases require actual configured
targets and remain separate from software fixture tests. Live LLM providers,
enterprise SaaS permissions, OS enrollment and production KMS/HSM signing are not
proven by the isolated local stack.

The current-worktree source baseline includes these local scripts, manifests,
locks, migrations, seed inputs and templates alongside Docker setup. Historical
capability variants remain explicitly preserved/unresolved per the owner's scope
decision; they are not silently represented as implemented in this baseline.

## Recorded validation

An untouched archive of published commit `5ee839812ff8917208f48d2d81bfa65a81e7264a`
passed fresh locked API/web/extension installs on 23 October,
all 10 integration tests (including all four PostgreSQL acceptance cases), both
migration/seed targets, strict health and real worker/beat heartbeats, 272 web tests,
the production build, and synthetic login/eight browser routes. PostgreSQL 16.15
and Redis 7.4.11 ran as native processes; Docker was not used. A state path longer
than the macOS Unix-socket limit was tested using TCP-only PostgreSQL.

The first candidate attempt inherited the machine database timezone and failed three
integration assertions. The fresh UTC-configured cluster passed all 10 unchanged
tests. Keep UTC explicit; this is not evidence of arbitrary database timezone
compatibility. Live provider and installed OS-control acceptance remain unverified.

The complete local Python 3.11 API unit run also passed 5,076 tests with four
deselected; its API source tree is identical to this native setup commit. See
[the validation record](validation-2026-10-23.md) for exact sources and the separate
hosted-CI billing blocker. The browser run used an explicit installed Chrome
executable. Default Playwright-cache resolution has been implemented and missing
browsers fail preflight, but default-cache runtime acceptance was not executed.
