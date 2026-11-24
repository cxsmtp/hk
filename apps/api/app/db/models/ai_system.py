from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy import ForeignKey, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class AISystem(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_systems"
    __table_args__ = (Index("idx_ai_systems_tenant", "tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


@event.listens_for(Session, "before_flush")
def _sync_risk_propagation_on_ai_system_update(session: Session, flush_context, instances) -> None:
    pending_hooks = session.info.setdefault("risk_propagation_hooks", [])
    processed = session.info.setdefault("risk_propagation_processed", set())
    with session.no_autoflush:
        for obj in list(session.dirty):
            if not isinstance(obj, AISystem):
                continue

            state = inspect(obj)
            if not state.persistent:
                continue

            risk_history = state.attrs.risk_tier.history
            lifecycle_history = state.attrs.status.history
            if not risk_history.has_changes() and not lifecycle_history.has_changes():
                continue

            marker = (
                obj.id,
                tuple(risk_history.deleted),
                tuple(risk_history.added),
                tuple(lifecycle_history.deleted),
                tuple(lifecycle_history.added),
            )
            if marker in processed:
                continue
            processed.add(marker)

            previous_risk_tier = risk_history.deleted[0] if risk_history.deleted else obj.risk_tier
            previous_lifecycle_state = lifecycle_history.deleted[0] if lifecycle_history.deleted else obj.status

            from app.services.risk_propagation_service import apply_risk_propagation

            apply_risk_propagation(
                session,
                ai_system=obj,
                previous_risk_tier=previous_risk_tier,
                previous_lifecycle_state=previous_lifecycle_state,
                hook_sink=pending_hooks,
            )


@event.listens_for(Session, "after_commit")
def _dispatch_risk_propagation_hooks(session: Session) -> None:
    hooks = session.info.pop("risk_propagation_hooks", [])
    session.info.pop("risk_propagation_processed", None)
    if not hooks:
        return

    from app.services.risk_propagation_service import dispatch_risk_propagation_hooks

    dispatch_risk_propagation_hooks(hooks)


@event.listens_for(Session, "after_rollback")
def _clear_risk_propagation_state(session: Session) -> None:
    session.info.pop("risk_propagation_hooks", None)
    session.info.pop("risk_propagation_processed", None)
