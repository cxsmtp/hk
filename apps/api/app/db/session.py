from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _normalize_sqlite_database_url(raw_url: str) -> str:
    """Resolve relative sqlite paths against the API root for stable local runtime behavior."""
    url = make_url(raw_url)
    if url.get_backend_name() != "sqlite":
        return raw_url
    database = str(url.database or "").strip()
    if not database or database == ":memory:":
        return raw_url

    path = Path(database).expanduser()
    if not path.is_absolute():
        api_root = Path(__file__).resolve().parents[2]
        path = (api_root / path).resolve()
        return url.set(database=str(path)).render_as_string(hide_password=False)

    expanded = path.resolve()
    if str(expanded) != database:
        return url.set(database=str(expanded)).render_as_string(hide_password=False)
    return raw_url


database_url = _normalize_sqlite_database_url(settings.database_url)
database_url_obj = make_url(database_url)
is_sqlite = database_url_obj.get_backend_name() == "sqlite"

engine_kwargs: dict[str, object] = {
    "pool_pre_ping": True,
}
if is_sqlite:
    # Improve reliability for concurrent background scan/sync jobs and interactive UI reads.
    sqlite_lock_timeout_seconds = max(1, int(settings.sqlite_lock_timeout_seconds or 8))
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": sqlite_lock_timeout_seconds}

engine = create_engine(database_url, **engine_kwargs)

if is_sqlite:
    sqlite_busy_timeout_ms = max(1000, int(settings.sqlite_busy_timeout_ms or 8000))
    sqlite_performance_indexes = (
        "CREATE INDEX IF NOT EXISTS idx_signal_tenant_created_at ON monitoring_signals (tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_remediation_tenant_created_at ON remediation_actions (tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_runtime_recos_tenant_created_at ON runtime_governance_recommendations (tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_findings_tenant_updated_at ON findings (tenant_id, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_sim_run_tenant_started_at ON simulation_runs (tenant_id, started_at)",
        "CREATE INDEX IF NOT EXISTS idx_approval_tenant_created_at ON approval_requests (tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_snapshot_tenant_created_at ON auditor_snapshots (tenant_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_drift_tenant_updated_at ON drift_alerts (tenant_id, updated_at)",
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute(f"PRAGMA busy_timeout={sqlite_busy_timeout_ms};")

            # Self-heal older local pilot databases that missed runtime-linkage migration 0037.
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
                has_findings = cursor.fetchone() is not None
                if has_findings:
                    cursor.execute("PRAGMA table_info(findings)")
                    finding_columns = {str(row[1]) for row in cursor.fetchall() if len(row) > 1}
                    if "agent_id" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN agent_id VARCHAR(64)")
                    if "machine_id" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN machine_id VARCHAR(128)")
                    if "user_email" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN user_email VARCHAR(320)")
                    if "browser_type" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN browser_type VARCHAR(32)")
                    if "application" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN application VARCHAR(255)")
                    if "decision" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN decision VARCHAR(32)")
                    if "policy_id" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN policy_id VARCHAR(64)")
                    if "evidence_status" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN evidence_status VARCHAR(16) NOT NULL DEFAULT 'complete'")
                    if "related_runtime_event_id" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN related_runtime_event_id VARCHAR(64)")
                    if "related_event_ids" not in finding_columns:
                        cursor.execute("ALTER TABLE findings ADD COLUMN related_event_ids JSON NOT NULL DEFAULT '[]'")
                    cursor.execute(
                        "CREATE INDEX IF NOT EXISTS idx_findings_tenant_agent ON findings (tenant_id, agent_id)"
                    )
                    cursor.execute(
                        "CREATE INDEX IF NOT EXISTS idx_findings_tenant_machine ON findings (tenant_id, machine_id)"
                    )
                    cursor.execute(
                        "CREATE INDEX IF NOT EXISTS idx_findings_tenant_decision ON findings (tenant_id, decision)"
                    )

                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='runtime_events'")
                has_runtime_events = cursor.fetchone() is not None
                if has_runtime_events:
                    cursor.execute("PRAGMA table_info(runtime_events)")
                    runtime_columns = {str(row[1]) for row in cursor.fetchall() if len(row) > 1}
                    if "machine_id" not in runtime_columns:
                        cursor.execute("ALTER TABLE runtime_events ADD COLUMN machine_id VARCHAR(128)")
                    if "browser_type" not in runtime_columns:
                        cursor.execute("ALTER TABLE runtime_events ADD COLUMN browser_type VARCHAR(32)")
                    if "application" not in runtime_columns:
                        cursor.execute("ALTER TABLE runtime_events ADD COLUMN application VARCHAR(255)")
                    if "decision" not in runtime_columns:
                        cursor.execute("ALTER TABLE runtime_events ADD COLUMN decision VARCHAR(32)")
                    cursor.execute(
                        "CREATE INDEX IF NOT EXISTS idx_runtime_events_tenant_decision ON runtime_events (tenant_id, decision)"
                    )
            except Exception:
                # Keep startup resilient; alembic remains source of truth for full schema migration.
                pass

            for ddl in sqlite_performance_indexes:
                try:
                    cursor.execute(ddl)
                except Exception:
                    # Keep startup resilient when optional tables are not present yet.
                    continue
        finally:
            cursor.close()

    def _repair_sqlite_findings_schema() -> None:
        """Best-effort schema repair for local pilot databases with partial migrations."""
        try:
            with engine.begin() as conn:
                has_findings = conn.execute(
                    text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings' LIMIT 1")
                ).scalar()
                if not has_findings:
                    return

                column_rows = conn.execute(text("PRAGMA table_info(findings)")).all()
                finding_columns = {str(row[1]) for row in column_rows if len(row) > 1}

                if "agent_id" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN agent_id VARCHAR(64)"))
                if "machine_id" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN machine_id VARCHAR(128)"))
                if "user_email" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN user_email VARCHAR(320)"))
                if "browser_type" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN browser_type VARCHAR(32)"))
                if "application" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN application VARCHAR(255)"))
                if "decision" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN decision VARCHAR(32)"))
                if "policy_id" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN policy_id VARCHAR(64)"))
                if "evidence_status" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN evidence_status VARCHAR(16) NOT NULL DEFAULT 'complete'"))
                if "related_runtime_event_id" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN related_runtime_event_id VARCHAR(64)"))
                if "related_event_ids" not in finding_columns:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN related_event_ids JSON NOT NULL DEFAULT '[]'"))

                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_tenant_agent ON findings (tenant_id, agent_id)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_tenant_machine ON findings (tenant_id, machine_id)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_tenant_decision ON findings (tenant_id, decision)"))

                has_runtime_events = conn.execute(
                    text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_events' LIMIT 1")
                ).scalar()
                if has_runtime_events:
                    runtime_rows = conn.execute(text("PRAGMA table_info(runtime_events)")).all()
                    runtime_columns = {str(row[1]) for row in runtime_rows if len(row) > 1}
                    if "machine_id" not in runtime_columns:
                        conn.execute(text("ALTER TABLE runtime_events ADD COLUMN machine_id VARCHAR(128)"))
                    if "browser_type" not in runtime_columns:
                        conn.execute(text("ALTER TABLE runtime_events ADD COLUMN browser_type VARCHAR(32)"))
                    if "application" not in runtime_columns:
                        conn.execute(text("ALTER TABLE runtime_events ADD COLUMN application VARCHAR(255)"))
                    if "decision" not in runtime_columns:
                        conn.execute(text("ALTER TABLE runtime_events ADD COLUMN decision VARCHAR(32)"))
                    conn.execute(
                        text("CREATE INDEX IF NOT EXISTS idx_runtime_events_tenant_decision ON runtime_events (tenant_id, decision)")
                    )
        except Exception:
            # Keep startup resilient; alembic remains the source of truth.
            return

    _repair_sqlite_findings_schema()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
