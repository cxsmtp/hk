# Hawk production single-node Compose operations

## Supported topology

Phase 9 supports one topology: a single Docker Engine host running the existing PostgreSQL, Redis, migration, bootstrap, API, Celery worker, Celery beat, and Next.js services. API and web ports remain bound to loopback. A customer-managed TLS reverse proxy must expose the configured HTTPS origins and must enforce request-size and connection-rate limits. This run does not claim Kubernetes, multi-node, multi-region, private-cloud, or zero-downtime support.

## Prerequisites

- Docker Engine with Compose v2 and sufficient host storage for two persistent volumes.
- Customer-managed TLS termination with fixed API and web hostnames.
- A restricted host directory containing the required secret files.
- PostgreSQL and Redis URLs in secret files, with distinct Redis logical databases for API/cache, broker, and result state.
- An external identity/bootstrap procedure for the first tenant administrator. Production startup never creates the demo tenant or default credentials.

## Required secret references

Copy `.env.production.example` to `.env.production`; do not commit it. Every `*_FILE` value must be an absolute path to a regular, non-symlink file that is not group/world writable. Values are mounted as Compose secrets. The application loads only an explicit secret allowlist, rejects dual environment/file sources, and exposes only source metadata. Keep signing-key versions needed to verify historical receipts during rotation.

## Deploy and start

1. Review `.env.production` and the secret directory permissions.
2. Run `./infra/scripts/hawk_production_stack.sh validate`.
3. Run `./infra/scripts/hawk_production_stack.sh prepare` for the first deployment or approved migration.
4. Run `./infra/scripts/hawk_production_stack.sh up`.
5. Confirm `./infra/scripts/hawk_production_stack.sh status` reports every long-running service healthy.

For a new empty database only, create the first owner with
`./infra/scripts/hawk_production_stack.sh bootstrap-admin owner@example.com "Owner Name" "Tenant Name" tenant-slug`.
The password is accepted twice through hidden standard input, never through an argument or environment variable.
The operation obtains a database lock, is audited, and permanently refuses to run once any tenant or user exists.
Production self-registration remains disabled.

## Startup preflight

The API refuses the supported production topology unless production mode, deployment identity/location, PostgreSQL, HTTPS public origins, explicit CORS, strict dependency checks, fail-secure governance, secret-key locking, component versions, and required secret-file references are valid. A running process is not sufficient readiness evidence.

## Migration

`prepare` runs `infra/scripts/run_migrations.py`. The runner obtains a PostgreSQL advisory lock, applies the repository Alembic chain to `head`, and releases the lock. Historical migrations are not rewritten. Back up before upgrades. Never stamp a revision without establishing its effects.

## Readiness

Use `/health/live` only for process liveness. Use `/health/ready` for API production readiness and `/system/control-plane-health` with an authenticated owner/admin/auditor session for full worker, beat, Redis, migration, and artifact-storage state. A stale worker or beat is ineligible and degrades the control plane even when the API process remains live.

## Backup

Run `./infra/scripts/hawk_production_stack.sh backup`. The wrapper creates a mode-0600 PostgreSQL custom-format dump under `infra/artifacts/backups`. The operator is responsible for encrypting and copying that file to an approved backup system; a local dump alone is not disaster recovery.

## Restore verification

Run `./infra/scripts/hawk_production_stack.sh restore-verify /absolute/repo/path/infra/artifacts/backups/hawk-demo-<timestamp>.dump`. Hawk restores only into a generated disposable `hawk_restore_verify_*` database, checks Alembic revision plus tenant/evidence row access, and drops the disposable database. It never overwrites the active database.

## Upgrade

1. Create a backup and run restore verification.
2. Review configuration and component-version changes.
3. Build images with `hawk_production_stack.sh build`.
4. Run `prepare`, then `up`.
5. Verify readiness, worker/beat freshness, schema head, and UI login.
6. Confirm no terminal/dead-letter jobs or receipt-signing failures appeared.

## Rollback limitations

Application images may be rolled back only when the older version declares compatibility with the deployed schema and receipt formats. Alembic downgrades are not an automatic production rollback. If a migration is irreversible, restore a verified backup into a separately reviewed database and redeploy compatible application images. Never delete production volumes as a rollback method.

## Common degraded states

- `migrations: out_of_date`: stop consequential work and apply the reviewed migration chain.
- `celery_worker` or `celery_beat: stale`: restart only the affected service and confirm a newer heartbeat.
- `artifact_storage: unavailable`: restore mount ownership/writability before evidence-producing work.
- component version mismatch: deploy a compatible version; do not mark unknown capabilities verified.
- mandatory control unavailable: Hawk follows the existing explicit fail-secure policy and records degraded evidence/coverage.

## Unsupported deployment modes

Kubernetes, Helm, Terraform-managed cloud infrastructure, active-active/multi-node API or worker clusters, multi-region databases, service meshes, automatic certificate issuance, zero-downtime migration, and automated disaster failover remain unsupported or unverified in Phase 9. Browser, endpoint, runtime, MCP, and connector packages retain their existing individual capability and verification states.
