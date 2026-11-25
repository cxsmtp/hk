from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ActivationState(Base):
    """The activation codes accepted on this installation and the licence's clock: one row, id 1.

    Holds, as JSON, what CxMissionZero keeps in DATA_DIR/activation.json: ``{tenants, product, seenAt, history}``
    (app/services/activation_service.py). It is kept in the database because Hawk runs several processes
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
