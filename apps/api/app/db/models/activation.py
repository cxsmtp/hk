from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ActivationState(Base):
    """This installation's licence: one row, id 1.

    Holds, as JSON (app/services/activation_service.py): ``{installationId, trialStart, identitySeal, licence,
    seenAt, lastAt, trialUsedMs, history}``: the installation ID and when its 3-day trial started (sealed), the
    imported ``.hawkai`` licence (the signed licence itself), the licence's clock and what was imported or refused. It is kept in the database because Hawk runs several processes
    (API workers, Celery worker and beat) that must all see the same codes and the same clock.
    """

    __tablename__ = "activation_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    state: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
