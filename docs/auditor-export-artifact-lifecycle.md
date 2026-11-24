# Auditor Export Artifact Lifecycle

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


Auditor exports write JSON, CSV, evidence-pack JSON, PDF-ready JSON, and executive PDF files under `ARTIFACT_DIR`.

## Retention Policy

- Default retention is 90 days.
- Cleanup preserves artifacts referenced by snapshots created inside the retention window.
- Files older than the retention window and not protected by a recent snapshot reference are eligible for deletion.
- Snapshot rows remain immutable; cleanup only removes filesystem artifacts.

## Cleanup Command

From the repository root:

```bash
scripts/cleanup_auditor_artifacts --retention-days 90 --dry-run
scripts/cleanup_auditor_artifacts --retention-days 90
```

The command prints JSON with deleted files, retained count, and per-file errors.

## Scheduled Job

Celery task:

```text
app.jobs.auditor_jobs.cleanup_auditor_export_artifacts
```

Recommended schedule: daily, with `retention_days=90`. Use `dry_run=true` during first pilot deployment to confirm the artifact directory and retention behavior.
