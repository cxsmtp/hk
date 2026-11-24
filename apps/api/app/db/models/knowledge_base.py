from __future__ import annotations

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class KBFramework(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_framework"
    __table_args__ = (
        Index("idx_kb_framework_name", "name"),
        Index("idx_kb_framework_source", "source_type"),
        CheckConstraint("source_type in ('authored','customer_provided')", name="ck_kb_framework_source_type"),
    )

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBControl(Base):
    __tablename__ = "kb_control"
    __table_args__ = (
        Index("idx_kb_control_framework", "framework_id"),
        Index("idx_kb_control_requirement", "requirement_level"),
        CheckConstraint("requirement_level in ('MUST','SHOULD','MAY')", name="ck_kb_control_requirement_level"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    framework_id: Mapped[str] = mapped_column(ForeignKey("kb_framework.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    requirement_level: Mapped[str] = mapped_column(String(8), nullable=False)
    applicability_tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    maturity_model: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    evidence_requirements: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBCrosswalk(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_crosswalk"
    __table_args__ = (
        Index("idx_kb_crosswalk_from", "from_control_id"),
        Index("idx_kb_crosswalk_to", "to_control_id"),
        CheckConstraint("mapping_type in ('equivalent','partial','supports')", name="ck_kb_crosswalk_mapping_type"),
    )

    from_control_id: Mapped[str] = mapped_column(ForeignKey("kb_control.id", ondelete="CASCADE"), nullable=False)
    to_control_id: Mapped[str] = mapped_column(ForeignKey("kb_control.id", ondelete="CASCADE"), nullable=False)
    mapping_type: Mapped[str] = mapped_column(String(16), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBThreat(Base):
    __tablename__ = "kb_threat"
    __table_args__ = (
        Index("idx_kb_threat_framework_ref", "framework_ref"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    framework_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description_short: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBThreatControlMap(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_threat_control_map"
    __table_args__ = (
        Index("idx_kb_tcm_threat", "threat_id"),
        Index("idx_kb_tcm_control", "control_id"),
        CheckConstraint("coverage in ('detect','prevent','respond')", name="ck_kb_tcm_coverage"),
        CheckConstraint("severity in ('low','med','high','critical')", name="ck_kb_tcm_severity"),
    )

    threat_id: Mapped[str] = mapped_column(ForeignKey("kb_threat.id", ondelete="CASCADE"), nullable=False)
    control_id: Mapped[str] = mapped_column(ForeignKey("kb_control.id", ondelete="CASCADE"), nullable=False)
    coverage: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBSimulationTemplate(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_simulation_template"
    __table_args__ = (
        Index("idx_kb_sim_template_category", "category"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    template_schema: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    safe_boundary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBControlSimMap(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_control_sim_map"
    __table_args__ = (
        Index("idx_kb_csm_control", "control_id"),
        Index("idx_kb_csm_template", "simulation_template_id"),
        CheckConstraint(
            "required_frequency in ('daily','weekly','monthly','on_change')",
            name="ck_kb_csm_frequency",
        ),
    )

    control_id: Mapped[str] = mapped_column(ForeignKey("kb_control.id", ondelete="CASCADE"), nullable=False)
    simulation_template_id: Mapped[str] = mapped_column(
        ForeignKey("kb_simulation_template.id", ondelete="CASCADE"),
        nullable=False,
    )
    required_frequency: Mapped[str] = mapped_column(String(16), nullable=False)
    failure_impact: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBGuardianContract(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_guardian_contract"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    intent: Mapped[str] = mapped_column(Text, nullable=False)
    detection_inputs: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    enforcement_contract: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBControlGuardianMap(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_control_guardian_map"
    __table_args__ = (
        Index("idx_kb_cgm_control", "control_id"),
        Index("idx_kb_cgm_guardian", "guardian_contract_id"),
        CheckConstraint(
            "enforcement_strength in ('baseline','strict','maximum')",
            name="ck_kb_cgm_strength",
        ),
    )

    control_id: Mapped[str] = mapped_column(ForeignKey("kb_control.id", ondelete="CASCADE"), nullable=False)
    guardian_contract_id: Mapped[str] = mapped_column(
        ForeignKey("kb_guardian_contract.id", ondelete="CASCADE"),
        nullable=False,
    )
    enforcement_strength: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBDoc(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_doc"
    __table_args__ = (
        Index("idx_kb_doc_framework", "framework_id"),
        Index("idx_kb_doc_source", "source_type"),
        CheckConstraint("source_type in ('authored','customer_provided')", name="ck_kb_doc_source_type"),
    )

    framework_id: Mapped[str] = mapped_column(ForeignKey("kb_framework.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class KBEmbedding(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "kb_embedding"
    __table_args__ = (
        Index("idx_kb_embedding_doc", "doc_id"),
    )

    doc_id: Mapped[str] = mapped_column(ForeignKey("kb_doc.id", ondelete="CASCADE"), nullable=False)
    embedding_model: Mapped[str] = mapped_column(String(128), nullable=False)
    vector: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
