from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class DetectionSettings(Base):
    """Per-tenant DLP and prompt-injection settings (app/services/detection/profile.py).

    ``config`` holds category toggles, custom dictionaries and the injection thresholds. ``fingerprints`` holds the
    exact-data-match sets as salted HMAC digests only, never the values; ``fingerprint_salt`` is the tenant's own
    random salt for them.
    """

    __tablename__ = "detection_settings"

    tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    fingerprint_salt: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    fingerprints: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    revision: Mapped[int] = mapped_column(nullable=False, default=0)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str] = mapped_column(String(320), nullable=False, default="")
