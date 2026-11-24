from __future__ import annotations

from sqlalchemy import Boolean, CheckConstraint, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("user_visibility_prompt_retention_days >= 0", name="ck_tenant_user_visibility_prompt_retention_days"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    platform_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="enforce")
    user_visibility_full_content_reveal_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    user_visibility_prompt_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
