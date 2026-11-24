"""Allow stale-but-present control coverage assessments.

Revision ID: 0087_allow_covered_stale_control_coverage
Revises: 0086_expand_audit_resource_reference
"""

from alembic import op
import sqlalchemy as sa


revision = "0087_allow_covered_stale_control_coverage"
down_revision = "0086_expand_audit_resource_reference"
branch_labels = None
depends_on = None


_CONSTRAINT_NAME = "ck_coverage_assessment_state"
_TABLE_NAME = "control_coverage_assessments"
_UPGRADE_STATES = (
    "covered_current",
    "covered_stale",
    "partially_covered",
    "configured_unvalidated",
    "regressed",
    "gap",
    "unsupported",
    "unknown",
    "not_applicable",
)
_DOWNGRADE_STATES = (
    "covered_current",
    "partially_covered",
    "configured_unvalidated",
    "regressed",
    "gap",
    "unsupported",
    "unknown",
    "not_applicable",
)


def _constraint_sql(states: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{state}'" for state in states)
    return f"coverage_state IN ({quoted})"


def _replace_constraint(states: tuple[str, ...]) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    op.drop_constraint(_CONSTRAINT_NAME, _TABLE_NAME, type_="check")
    op.create_check_constraint(
        _CONSTRAINT_NAME,
        _TABLE_NAME,
        _constraint_sql(states),
    )


def upgrade() -> None:
    _replace_constraint(_UPGRADE_STATES)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    stale_count = bind.execute(
        sa.text(
            "SELECT count(*) FROM control_coverage_assessments "
            "WHERE coverage_state = 'covered_stale'"
        )
    ).scalar_one()
    if int(stale_count or 0) > 0:
        raise RuntimeError(
            "Cannot downgrade coverage_state constraint while covered_stale rows exist"
        )
    _replace_constraint(_DOWNGRADE_STATES)
