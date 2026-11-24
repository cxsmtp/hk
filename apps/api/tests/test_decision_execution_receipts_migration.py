from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect
from sqlalchemy.exc import DBAPIError


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = "app/db/migrations/alembic.ini"


def _alembic(database_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = database_url
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", ALEMBIC_CONFIG, *args],
        cwd=API_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result


def test_receipt_migration_upgrade_downgrade_reupgrade_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "receipt-migration.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"

    engine = create_engine(database_url)
    try:
        baseline = MetaData()
        Table("tenants", baseline, Column("id", String(36), primary_key=True))
        Table(
            "evidence_nodes",
            baseline,
            Column("id", String(36), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
        )
        Table(
            "approval_bindings",
            baseline,
            Column("id", String(36), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
        )
        Table(
            "findings",
            baseline,
            Column("finding_id", String(36), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
        )
        Table(
            "evidence_edges",
            baseline,
            Column("id", String(36), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
            Column("from_node_id", String(36), nullable=False),
            Column("to_node_id", String(36), nullable=False),
            Column("edge_type", String(64), nullable=False),
        )
        Table(
            "runtime_events",
            baseline,
            Column("event_id", String(36), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
        )
        Table(
            "ai_actions",
            baseline,
            Column("action_id", String(64), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
        )
        baseline.create_all(engine)
    finally:
        engine.dispose()
    _alembic(database_url, "stamp", "0042_token_system_binding")
    _alembic(database_url, "upgrade", "0043_decision_execution_receipts")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            for table_name in ("evidence_nodes", "evidence_edges"):
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER trg_{table_name}_immutable_update
                    BEFORE UPDATE ON {table_name}
                    FOR EACH ROW BEGIN
                      SELECT RAISE(ABORT, 'immutable_table:{table_name}');
                    END
                    """
                )
                connection.exec_driver_sql(
                    f"""
                    CREATE TRIGGER trg_{table_name}_immutable_delete
                    BEFORE DELETE ON {table_name}
                    FOR EACH ROW BEGIN
                      SELECT RAISE(ABORT, 'immutable_table:{table_name}');
                    END
                    """
                )
    finally:
        engine.dispose()
    _alembic(database_url, "upgrade", "0064_native_control_logical_action_claims")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert {
            "decision_receipts",
            "execution_receipts",
            "execution_integrity_results",
        } <= set(inspector.get_table_names())
        finding_columns = {
            column["name"] for column in inspector.get_columns("findings")
        }
        assert {"canonical_action_id", "execution_attempt_id"} <= finding_columns
        approval_columns = {
            column["name"]: column for column in inspector.get_columns("approval_bindings")
        }
        assert "receipt_material_hash" in approval_columns
        assert approval_columns["receipt_material_hash"]["nullable"] is True
        assert any(
            index.get("name") == "idx_findings_tenant_execution_attempt"
            and index.get("column_names") == ["tenant_id", "execution_attempt_id"]
            for index in inspector.get_indexes("findings")
        )
        decision_columns = {
            column["name"]: column for column in inspector.get_columns("decision_receipts")
        }
        assert {
            "chain_id",
            "transformations",
            "canonical_action_evidence_node_id",
        } <= set(decision_columns)
        assert decision_columns["chain_id"]["nullable"] is False
        assert decision_columns["transformations"]["nullable"] is False
        assert decision_columns["canonical_action_evidence_node_id"]["nullable"] is False
        assert {
            "policy_snapshot_evidence_node_id",
            "evidence_bundle_id",
        } <= set(decision_columns)
        assert decision_columns["policy_snapshot_evidence_node_id"]["nullable"] is True
        assert decision_columns["evidence_bundle_id"]["nullable"] is True
        assert "evidence_bundle_id" in {
            column["name"] for column in inspector.get_columns("runtime_events")
        }
        edge_columns = {
            column["name"]: column for column in inspector.get_columns("evidence_edges")
        }
        assert edge_columns["integrity_key"]["nullable"] is True
        assert any(
            constraint.get("name") == "uq_evidence_edges_canonical_integrity"
            and constraint.get("column_names")
            == ["tenant_id", "from_node_id", "edge_type", "integrity_key"]
            for constraint in inspector.get_unique_constraints("evidence_edges")
        )
        assert any(
            check.get("name") == "ck_evidence_edges_canonical_integrity_key"
            and "bundle_manifest" in str(check.get("sqltext"))
            for check in inspector.get_check_constraints("evidence_edges")
        )
        assert "evidence_bundle_id" in {
            column["name"] for column in inspector.get_columns("ai_actions")
        }
        execution_columns = {
            column["name"]: column for column in inspector.get_columns("execution_receipts")
        }
        assert "execution_attempt_id" in execution_columns
        assert execution_columns["execution_attempt_id"]["nullable"] is False
        assert any(
            constraint.get("name") == "uq_execution_receipts_tenant_decision_attempt"
            and constraint.get("column_names")
            == ["tenant_id", "decision_receipt_id", "execution_attempt_id"]
            for constraint in inspector.get_unique_constraints("execution_receipts")
        )
        integrity_columns = {
            column["name"]: column
            for column in inspector.get_columns("execution_integrity_results")
        }
        assert {
            "signature",
            "signing_key_id",
            "execution_attempt_id",
            "superseded_evidence_node_id",
            "superseded_integrity_body_hash",
            "superseded_integrity_signature",
            "supersession_evidence_node_id",
        } <= set(integrity_columns)
        assert integrity_columns["signature"]["nullable"] is False
        assert integrity_columns["signing_key_id"]["nullable"] is False
        assert integrity_columns["execution_attempt_id"]["nullable"] is False
        assert any(
            constraint.get("name") == "uq_execution_integrity_tenant_decision_attempt"
            and constraint.get("column_names")
            == ["tenant_id", "decision_receipt_id", "execution_attempt_id"]
            for constraint in inspector.get_unique_constraints("execution_integrity_results")
        )
        assert any(
            check.get("name") == "ck_execution_integrity_result_closed"
            and "drift_detected" in str(check.get("sqltext"))
            for check in inspector.get_check_constraints("execution_integrity_results")
        )
        assert any(
            foreign_key.get("name") == "fk_decision_receipt_tenant_canonical_evidence"
            and foreign_key.get("referred_table") == "evidence_nodes"
            and foreign_key.get("constrained_columns")
            == ["tenant_id", "canonical_action_evidence_node_id"]
            for foreign_key in inspector.get_foreign_keys("decision_receipts")
        )
        with engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == (
                "0064_native_control_logical_action_claims"
            )
            native_selection_columns = {
                column[1]: column
                for column in connection.exec_driver_sql(
                    "PRAGMA table_info(native_control_selections)"
                ).all()
            }
            assert native_selection_columns["plan_issued_at"][3] == 1
            assert native_selection_columns["plan_expires_at"][3] == 1
            trigger_names = {
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                ).all()
            }
            assert {
                "trg_evidence_nodes_immutable_update",
                "trg_evidence_edges_immutable_update",
                "trg_native_control_selections_immutable_update",
                "trg_native_control_selections_immutable_delete",
            } <= trigger_names
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO tenants (id) VALUES ('immutable-tenant')"
            )
            connection.exec_driver_sql(
                """
                INSERT INTO native_control_selections (
                    selection_id, tenant_id, action_id, selection_reason,
                    assurance_level, selector_version, matrix_version,
                    policy_version, input_digest, plan_issued_at, plan_expires_at
                ) VALUES (
                    'immutable-selection', 'immutable-tenant', 'immutable-action',
                    'test', 0, 'selector-test', 'matrix-test', 'policy-test',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    '2026-08-20T00:00:00+00:00', '2026-08-20T00:05:00+00:00'
                )
                """
            )
            connection.exec_driver_sql(
                "INSERT INTO evidence_nodes (id, tenant_id) VALUES ('node-a', 'immutable-tenant')"
            )
            connection.exec_driver_sql(
                "INSERT INTO evidence_nodes (id, tenant_id) VALUES ('node-b', 'immutable-tenant')"
            )
            connection.exec_driver_sql(
                """
                INSERT INTO evidence_edges
                    (id, tenant_id, from_node_id, to_node_id, edge_type, integrity_key)
                VALUES
                    ('edge-a', 'immutable-tenant', 'node-a', 'node-b',
                     'bundle_member', 'integrity-a')
                """
            )
        with engine.begin() as connection:
            with pytest.raises(DBAPIError, match="immutable_table:evidence_nodes"):
                connection.exec_driver_sql(
                    "UPDATE evidence_nodes SET tenant_id='immutable-tenant' WHERE id='node-a'"
                )
        with engine.begin() as connection:
            with pytest.raises(DBAPIError, match="immutable_table:evidence_edges"):
                connection.exec_driver_sql(
                    "UPDATE evidence_edges SET integrity_key='other' WHERE id='edge-a'"
                )
        with engine.begin() as connection:
            with pytest.raises(
                DBAPIError,
                match="immutable_table:native_control_selections",
            ):
                connection.exec_driver_sql(
                    "UPDATE native_control_selections SET selection_reason='tampered' "
                    "WHERE selection_id='immutable-selection'"
                )
        with engine.begin() as connection:
            for table_name in ("evidence_nodes", "evidence_edges"):
                connection.exec_driver_sql(
                    f"DROP TRIGGER IF EXISTS trg_{table_name}_immutable_update"
                )
                connection.exec_driver_sql(
                    f"DROP TRIGGER IF EXISTS trg_{table_name}_immutable_delete"
                )
            connection.exec_driver_sql(
                "DROP TRIGGER IF EXISTS trg_native_control_selections_immutable_update"
            )
            connection.exec_driver_sql(
                "DROP TRIGGER IF EXISTS trg_native_control_selections_immutable_delete"
            )
            connection.exec_driver_sql("DELETE FROM evidence_edges WHERE id='edge-a'")
            connection.exec_driver_sql(
                "DELETE FROM evidence_nodes WHERE id IN ('node-a', 'node-b')"
            )
            connection.exec_driver_sql(
                "DELETE FROM native_control_selections "
                "WHERE selection_id='immutable-selection'"
            )
            connection.exec_driver_sql(
                "DELETE FROM tenants WHERE id='immutable-tenant'"
            )
    finally:
        engine.dispose()

    _alembic(database_url, "downgrade", "0042_token_system_binding")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert "decision_receipts" not in inspector.get_table_names()
        assert "canonical_action_id" not in {
            column["name"] for column in inspector.get_columns("findings")
        }
        assert "execution_attempt_id" not in {
            column["name"] for column in inspector.get_columns("findings")
        }
        assert "receipt_material_hash" not in {
            column["name"] for column in inspector.get_columns("approval_bindings")
        }
        assert "evidence_bundle_id" not in {
            column["name"] for column in inspector.get_columns("runtime_events")
        }
        assert "evidence_bundle_id" not in {
            column["name"] for column in inspector.get_columns("ai_actions")
        }
    finally:
        engine.dispose()

    _alembic(database_url, "upgrade", "0064_native_control_logical_action_claims")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert "execution_integrity_results" in inspector.get_table_names()
        assert "execution_attempt_id" in {
            column["name"] for column in inspector.get_columns("execution_receipts")
        }
        assert "execution_attempt_id" in {
            column["name"] for column in inspector.get_columns("execution_integrity_results")
        }
        assert "supersession_evidence_node_id" in {
            column["name"] for column in inspector.get_columns("execution_integrity_results")
        }
        assert "receipt_material_hash" in {
            column["name"] for column in inspector.get_columns("approval_bindings")
        }
        assert "execution_attempt_id" in {
            column["name"] for column in inspector.get_columns("findings")
        }
        with engine.connect() as connection:
                assert connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one() == (
                    "0064_native_control_logical_action_claims"
                )
    finally:
        engine.dispose()
