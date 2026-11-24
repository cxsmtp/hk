from __future__ import annotations

import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.services.schema_health_service import evaluate_schema_health


def test_schema_health_reports_missing_findings_agent_id() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE findings (
                    finding_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT,
                    machine_id TEXT,
                    policy_id TEXT,
                    decision TEXT
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE runtime_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT,
                    machine_id TEXT,
                    browser_type TEXT,
                    application TEXT,
                    decision TEXT
                )
                """
            )
        )
        conn.execute(text("CREATE TABLE policies (id TEXT PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE policy_versions (id TEXT PRIMARY KEY, scope TEXT)"))
        conn.execute(text("CREATE TABLE users (id TEXT PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE devices (id TEXT PRIMARY KEY)"))

    with SessionLocal() as db:
        report = evaluate_schema_health(db)

    assert report.healthy is False
    assert "findings.agent_id" in report.missing_columns
