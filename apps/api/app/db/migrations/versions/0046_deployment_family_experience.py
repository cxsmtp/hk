"""additive deployment-family persistence

Revision ID: 0046_deployment_family_exp
Revises: 0045_control_coverage
"""

from collections.abc import Iterator
from contextlib import contextmanager

from alembic import op
import sqlalchemy as sa


revision = "0046_deployment_family_exp"
down_revision = "0045_control_coverage"
branch_labels = None
depends_on = None


SURFACE_FAMILY_BACKFILL = {
    "browser_extension": "browser",
    "browser_agent": "browser",
    "managed_browser": "browser",
    "browser_automation_control": "browser",
    "endpoint_agent": "endpoint",
    "endpoint_discovery": "endpoint",
    "local_agent_telemetry": "endpoint",
    "desktop_ai_control": "endpoint",
    "local_ai_proxy": "endpoint",
    "local_proxy": "endpoint",
    "ide_companion": "endpoint",
    "developer_endpoint": "endpoint",
    "local_mcp_runtime": "endpoint",
    "cli_agent_runtime": "endpoint",
    "mdm_discovery": "endpoint",
    "llm_gateway": "runtime",
    "mcp_gateway": "runtime",
    "sdk": "runtime",
    "sdk_app_embed": "runtime",
    "runtime_mesh": "runtime",
    "azure_foundry": "runtime",
    "azure_apim": "runtime",
    "kong": "runtime",
    "envoy": "runtime",
    "kubernetes": "runtime",
    "aks": "runtime",
    "container_apps": "runtime",
    "custom_agent_runtime": "runtime",
    "internal_api_authorization": "runtime",
    "microsoft_365": "saas_api",
    "copilot": "saas_api",
    "google_workspace": "saas_api",
    "slack": "saas_api",
    "salesforce": "saas_api",
    "service_now": "saas_api",
    "github": "saas_api",
    "gitlab": "saas_api",
    "saas_connector": "saas_api",
    "saas_ai_connector": "saas_api",
    "oauth_app_connector": "saas_api",
    "siem_connector": "saas_api",
    "webhook": "saas_api",
    "custom_connector": "saas_api",
}

NORMALIZED_COLUMNS = (
    "deployment_family",
    "hosting_mode",
    "provider",
    "region",
    "feature_flag",
    "last_health_check_at",
    "policy_bundle_version",
    "collector_version",
    "control_capability",
    "evidence_capability",
    "containment_capability",
    "bypass_detection_capability",
)


@contextmanager
def _sqlite_batch_recreate_guard() -> Iterator[None]:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        yield
        return

    migration_context = op.get_context()
    with migration_context.autocommit_block():
        foreign_keys_were_enabled = bool(
            bind.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
        )
        bind.exec_driver_sql("PRAGMA foreign_keys=OFF")
        if bind.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 0:
            raise RuntimeError(
                "SQLite foreign-key enforcement could not be paused safely"
            )

    try:
        yield
    except Exception:
        if bind.in_transaction():
            bind.rollback()
        if foreign_keys_were_enabled:
            bind.exec_driver_sql("PRAGMA foreign_keys=ON")
        bind.commit()
        raise
    else:
        if bind.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 0:
            with migration_context.autocommit_block():
                violations = bind.exec_driver_sql(
                    "PRAGMA foreign_key_check"
                ).all()
                if foreign_keys_were_enabled:
                    bind.exec_driver_sql("PRAGMA foreign_keys=ON")
                expected_state = 1 if foreign_keys_were_enabled else 0
                if bind.exec_driver_sql(
                    "PRAGMA foreign_keys"
                ).scalar_one() != expected_state:
                    raise RuntimeError(
                        "SQLite foreign-key enforcement was not restored"
                    )
                if violations:
                    raise RuntimeError(
                        "SQLite foreign-key violations after deployment-surface "
                        f"recreation: {violations[:5]}"
                    )


def upgrade() -> None:
    with _sqlite_batch_recreate_guard():
        _upgrade()


def _upgrade() -> None:
    with op.batch_alter_table("deployment_surfaces") as batch_op:
        batch_op.drop_constraint(
            "ck_deployment_surface_health_status",
            type_="check",
        )
        batch_op.add_column(
            sa.Column(
                "deployment_family",
                sa.String(length=32),
                server_default="unknown",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "hosting_mode",
                sa.String(length=32),
                server_default="unknown",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column("provider", sa.String(length=128), nullable=True)
        )
        batch_op.add_column(
            sa.Column("region", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column("feature_flag", sa.String(length=128), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "last_health_check_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "policy_bundle_version",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "collector_version",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "control_capability",
                sa.String(length=32),
                server_default="unknown",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "evidence_capability",
                sa.String(length=32),
                server_default="unknown",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "containment_capability",
                sa.String(length=32),
                server_default="unknown",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "bypass_detection_capability",
                sa.String(length=32),
                server_default="unknown",
                nullable=False,
            )
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_health_status",
            "health_status IN "
            "('healthy','warning','degraded','offline','stale','unknown')",
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_family",
            "deployment_family IN "
            "('browser','endpoint','runtime','saas_api','unknown')",
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_hosting_mode",
            "hosting_mode IN "
            "('saas','hybrid','private_cloud','on_premises','unknown')",
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_control_capability",
            "control_capability IN "
            "('inline','warn_only','monitor_only','external_required','unknown')",
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_evidence_capability",
            "evidence_capability IN "
            "('complete','partial','metadata_only','none','unknown')",
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_containment_capability",
            "containment_capability IN "
            "('direct','surface_limited','external','none','unknown')",
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_bypass_capability",
            "bypass_detection_capability IN "
            "('supported','unsupported','unknown')",
        )

    surfaces = sa.table(
        "deployment_surfaces",
        sa.column("surface_type", sa.String()),
        sa.column("deployment_family", sa.String()),
    )
    family_case = sa.case(
        *(
            (surfaces.c.surface_type == surface_type, family)
            for surface_type, family in SURFACE_FAMILY_BACKFILL.items()
        ),
        else_="unknown",
    )
    op.execute(
        surfaces.update().values(deployment_family=family_case)
    )

    op.create_index(
        "idx_deployment_surface_tenant_family",
        "deployment_surfaces",
        ["tenant_id", "deployment_family"],
    )
    op.create_index(
        "idx_deployment_surface_tenant_health",
        "deployment_surfaces",
        ["tenant_id", "health_status"],
    )


def downgrade() -> None:
    with _sqlite_batch_recreate_guard():
        _downgrade()


def _downgrade() -> None:
    op.drop_index(
        "idx_deployment_surface_tenant_health",
        table_name="deployment_surfaces",
    )
    op.drop_index(
        "idx_deployment_surface_tenant_family",
        table_name="deployment_surfaces",
    )

    surfaces = sa.table(
        "deployment_surfaces",
        sa.column("health_status", sa.String()),
    )
    op.execute(
        surfaces.update()
        .where(surfaces.c.health_status == "stale")
        .values(health_status="unknown")
    )

    with op.batch_alter_table("deployment_surfaces") as batch_op:
        batch_op.drop_constraint(
            "ck_deployment_surface_bypass_capability",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_deployment_surface_containment_capability",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_deployment_surface_evidence_capability",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_deployment_surface_control_capability",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_deployment_surface_hosting_mode",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_deployment_surface_family",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_deployment_surface_health_status",
            type_="check",
        )
        batch_op.create_check_constraint(
            "ck_deployment_surface_health_status",
            "health_status IN "
            "('healthy','warning','degraded','offline','unknown')",
        )
        for column_name in reversed(NORMALIZED_COLUMNS):
            batch_op.drop_column(column_name)
