from __future__ import annotations

from importlib import import_module
from pathlib import Path
import shutil
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DatabaseError, IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.discovery_resolution import DiscoveryResolutionGraphEdge
from app.services.hmair.erg.evidence_resolution_graph import EvidenceResolutionGraph
from app.services.hmair.erg.resolution_history import ResolutionHistory
from app.services.hmair.resolution_graph_service import create_graph_node
from test_phase2_asset_resolution_service import NOW, _seed


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"


def test_0060_migration_follows_cie_and_declares_append_only_erg_schema() -> None:
    migration = import_module(
        "app.db.migrations.versions.0060_evidence_resolution_graph"
    )
    assert migration.revision == "0060_evidence_resolution_graph"
    assert migration.down_revision == "0059_capability_inference_engine"
    assert set(migration.TABLES) == {
        "discovery_hypothesis_evaluations",
        "discovery_hypothesis_evaluation_edges",
        "discovery_collector_quality_snapshots",
        "discovery_observation_quality_snapshots",
        "discovery_ai_ecosystems",
        "discovery_ecosystem_memberships",
        "discovery_ecosystem_resolution_events",
        "discovery_ecosystem_history_members",
    }
    assert migration.IMMUTABLE_TABLES == migration.TABLES


def test_0060_postgresql_graph_edge_extension_uses_direct_alter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = import_module(
        "app.db.migrations.versions.0060_evidence_resolution_graph"
    )

    class RecordingOp:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []

        def get_bind(self) -> SimpleNamespace:
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def batch_alter_table(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("PostgreSQL graph-edge migration must not recreate table")

        def add_column(self, table_name: str, column: object) -> None:
            self.calls.append(("add_column", table_name, column.name))

        def create_foreign_key(
            self,
            name: str,
            source_table: str,
            referent_table: str,
            local_columns: list[str],
            remote_columns: list[str],
            **kwargs: object,
        ) -> None:
            self.calls.append(
                (
                    "create_foreign_key",
                    name,
                    source_table,
                    referent_table,
                    tuple(local_columns),
                    tuple(remote_columns),
                    kwargs.get("ondelete"),
                )
            )

        def create_check_constraint(
            self, name: str, table_name: str, condition: str
        ) -> None:
            self.calls.append(("create_check_constraint", name, table_name, condition))

        def create_unique_constraint(
            self, name: str, table_name: str, columns: list[str]
        ) -> None:
            self.calls.append(
                ("create_unique_constraint", name, table_name, tuple(columns))
            )

        def create_index(
            self, name: str, table_name: str, columns: list[str]
        ) -> None:
            self.calls.append(("create_index", name, table_name, tuple(columns)))

        def execute(self, statement: str) -> None:
            self.calls.append(("execute", statement))

        def drop_table(self, table_name: str) -> None:
            self.calls.append(("drop_table", table_name))

        def alter_column(
            self, table_name: str, column_name: str, **kwargs: object
        ) -> None:
            self.calls.append(("alter_column", table_name, column_name, kwargs["nullable"]))

        def drop_index(self, name: str, **kwargs: object) -> None:
            self.calls.append(("drop_index", name, kwargs["table_name"]))

        def drop_constraint(
            self, name: str, table_name: str, **kwargs: object
        ) -> None:
            self.calls.append(("drop_constraint", name, table_name, kwargs["type_"]))

        def drop_column(self, table_name: str, column_name: str) -> None:
            self.calls.append(("drop_column", table_name, column_name))

    recorder = RecordingOp()
    monkeypatch.setattr(migration, "op", recorder)

    migration._extend_graph_edges()
    migration.downgrade()

    assert (
        "add_column",
        migration.EDGE_TABLE,
        "predecessor_edge_id",
    ) in recorder.calls
    assert (
        "create_foreign_key",
        "fk_discovery_resolution_graph_edge_tenant_predecessor",
        migration.EDGE_TABLE,
        migration.EDGE_TABLE,
        ("tenant_id", "predecessor_edge_id"),
        ("tenant_id", "edge_id"),
        "RESTRICT",
    ) in recorder.calls
    assert (
        "create_unique_constraint",
        "uq_discovery_resolution_graph_edge_tenant_predecessor",
        migration.EDGE_TABLE,
        ("tenant_id", "predecessor_edge_id"),
    ) in recorder.calls
    assert (
        "create_index",
        "idx_discovery_resolution_graph_edge_tenant_predecessor",
        migration.EDGE_TABLE,
        ("tenant_id", "predecessor_edge_id", "edge_id"),
    ) in recorder.calls
    assert any(
        call[0] == "execute" and "base_confidence = confidence" in call[1]
        for call in recorder.calls
    )
    assert {
        ("alter_column", migration.EDGE_TABLE, "source_surface", False),
        ("alter_column", migration.EDGE_TABLE, "base_confidence", False),
        ("alter_column", migration.EDGE_TABLE, "last_validated_at", False),
    } <= set(recorder.calls)
    assert (
        "drop_index",
        "idx_discovery_resolution_graph_edge_tenant_predecessor",
        migration.EDGE_TABLE,
    ) in recorder.calls
    assert (
        "drop_constraint",
        "fk_discovery_resolution_graph_edge_tenant_predecessor",
        migration.EDGE_TABLE,
        "foreignkey",
    ) in recorder.calls
    assert (
        "drop_column",
        migration.EDGE_TABLE,
        "predecessor_edge_id",
    ) in recorder.calls


def test_fresh_upgrade_to_0060_creates_edge_successors_and_immutable_erg(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "erg.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        API_ROOT / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0060_evidence_resolution_graph")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        for table_name in (
            "discovery_hypothesis_evaluations",
            "discovery_hypothesis_evaluation_edges",
            "discovery_collector_quality_snapshots",
            "discovery_observation_quality_snapshots",
            "discovery_ai_ecosystems",
            "discovery_ecosystem_memberships",
            "discovery_ecosystem_resolution_events",
            "discovery_ecosystem_history_members",
        ):
            assert table_name in inspector.get_table_names()
            assert all(
                tuple(index["column_names"])[0] == "tenant_id"
                for index in inspector.get_indexes(table_name)
            )
        edge_columns = {
            item["name"]
            for item in inspector.get_columns("discovery_resolution_graph_edges")
        }
        assert {
            "base_confidence", "relationship_weight", "collector_id", "source_surface",
            "signal_class", "observation_quality_factor", "collector_quality_factor",
            "relationship_rule_id", "decay_policy_id", "last_validated_at",
            "edge_sequence", "predecessor_edge_id",
        } <= edge_columns
        unique_constraints = {
            item["name"]
            for item in inspector.get_unique_constraints(
                "discovery_resolution_graph_edges"
            )
        }
        assert "uq_discovery_resolution_graph_edge_tenant_predecessor" in unique_constraints
        evaluation_columns = {
            item["name"]
            for item in inspector.get_columns("discovery_hypothesis_evaluations")
        }
        assert {"required_anchor_results_json", "idempotency_key"} <= evaluation_columns
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == "0060_evidence_resolution_graph"
            trigger_names = {
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            immutable = {
                name
                for name in trigger_names
                if name.startswith("trg_erg_") and "immutable" in name
            }
            assert len(immutable) == 18
            assert "trg_erg_graph_edge_successor_shape" in trigger_names

        session = Session(engine, autoflush=False, expire_on_commit=False)
        try:
            # The structural assertions above exercise exactly revision 0060.
            # Advance the same database before using today's ORM projection so
            # later additive columns are not accidentally required at 0060.
            command.upgrade(config, "head")
            seed = _seed(session, suffix="erg-migration-runtime")
            event = ResolutionHistory().record_disposition(
                session,
                tenant_id=seed["tenant_id"],
                action="manual_review",
                subject_reference="hypothesis:migration-immutability",
                evidence_node_id=seed["node_id"],
                confidence=0.5,
                operator_id="owner-1",
                operator_role="owner",
                reason="Prove migrated append-only enforcement",
                occurred_at=NOW,
                idempotency_key="migration-immutability-event",
            )
            first_node = create_graph_node(
                session,
                tenant_id=seed["tenant_id"],
                node_class="observation",
                subject_reference="observation:migration-successor",
                idempotency_key="migration-successor-source",
            )
            second_node = create_graph_node(
                session,
                tenant_id=seed["tenant_id"],
                node_class="capability",
                subject_reference="capability:migration-successor",
                idempotency_key="migration-successor-target",
            )
            graph = EvidenceResolutionGraph()
            first = graph.append_edge_evaluation(
                session,
                tenant_id=seed["tenant_id"],
                from_node_id=first_node.graph_node_id,
                to_node_id=second_node.graph_node_id,
                edge_type="supports",
                evidence_node_id=seed["node_id"],
                collector_id=f"collector-erg-migration-runtime",
                base_confidence=0.9,
                relationship_weight=1.0,
                observation_quality=0.9,
                collector_quality=0.9,
                source_surface="endpoint",
                signal_class="capability",
                verification_state="verified",
                freshness="fresh",
                contradiction_state="none",
                first_observed_at=NOW,
                last_observed_at=NOW,
                last_validated_at=NOW,
                relationship_rule_id="capability-support-v1",
                relationship_rule_version="1.0.0",
                idempotency_key="migration-successor-root",
            )
            successor = graph.append_edge_evaluation(
                session,
                tenant_id=seed["tenant_id"],
                from_node_id=first_node.graph_node_id,
                to_node_id=second_node.graph_node_id,
                edge_type="supports",
                evidence_node_id=seed["node_id"],
                collector_id=f"collector-erg-migration-runtime",
                base_confidence=0.8,
                relationship_weight=1.0,
                observation_quality=0.9,
                collector_quality=0.9,
                source_surface="endpoint",
                signal_class="capability",
                verification_state="verified",
                freshness="fresh",
                contradiction_state="none",
                first_observed_at=NOW,
                last_observed_at=NOW,
                last_validated_at=NOW,
                relationship_rule_id="capability-support-v1",
                relationship_rule_version="1.0.0",
                idempotency_key="migration-successor-one",
                predecessor_edge_id=first.edge_id,
            )
            session.commit()

            with engine.begin() as connection, pytest.raises(DatabaseError):
                connection.execute(
                    text(
                        "UPDATE discovery_ecosystem_resolution_events "
                        "SET reason = 'tampered' WHERE resolution_event_id = :event_id"
                    ),
                    {"event_id": event.event_id},
                )

            fork = DiscoveryResolutionGraphEdge(
                edge_id=str(uuid4()),
                tenant_id=successor.tenant_id,
                from_node_id=successor.from_node_id,
                to_node_id=successor.to_node_id,
                edge_type=successor.edge_type,
                evidence_node_id=successor.evidence_node_id,
                collector_id=successor.collector_id,
                source_surface=successor.source_surface,
                signal_class=successor.signal_class,
                base_confidence=successor.base_confidence,
                observation_quality_factor=successor.observation_quality_factor,
                collector_quality_factor=successor.collector_quality_factor,
                confidence=successor.confidence,
                relationship_weight=successor.relationship_weight,
                relationship_rule_id=successor.relationship_rule_id,
                relationship_rule_version=successor.relationship_rule_version,
                decay_policy_id=successor.decay_policy_id,
                decay_policy_version=successor.decay_policy_version,
                verification_state=successor.verification_state,
                freshness=successor.freshness,
                contradiction_state=successor.contradiction_state,
                first_observed_at=successor.first_observed_at,
                last_observed_at=successor.last_observed_at,
                last_validated_at=successor.last_validated_at,
                edge_schema_version=successor.edge_schema_version,
                edge_sequence=successor.edge_sequence,
                predecessor_edge_id=first.edge_id,
                idempotency_key="migration-successor-fork",
                input_digest="f" * 64,
            )
            session.add(fork)
            with pytest.raises(IntegrityError):
                session.commit()
            session.rollback()
        finally:
            session.close()
    finally:
        engine.dispose()
