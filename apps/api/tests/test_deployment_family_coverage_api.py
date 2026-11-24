from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings, settings
from app.core.control_coverage import CoverageDimension
from app.core.security import create_access_token
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    ControlCoverageSnapshot,
    DeploymentSurface,
)
from app.db.models.evidence import DecisionReceipt
from app.db.models.evidence import EvidenceNode, ExecutionReceipt
from app.db.models.activity_audit import AIAction
from app.db.models.policy import ApprovalBinding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.control_coverage.path_projection import (
    ai_action_candidate,
    make_path_key,
    runtime_event_candidate,
)
from app.services.control_coverage.source_resolution import (
    surface_for_action,
    surface_indexes,
)
from app.services.control_coverage.deployment_family_projection import (
    SURFACE_PROJECTION_WATERMARK_KEY,
    deployment_family_surface_projection_digest,
)
from app.services.control_coverage.service import (
    _snapshot_digest,
    calculate_tenant_control_coverage,
)
from app.services import deployment_family_coverage_service as coverage_service
from app.services.receipt_service import (
    create_decision_receipt,
    create_execution_receipt,
)


FAMILY_ORDER = ("browser", "endpoint", "runtime", "saas_api", "unknown")
DIMENSION_ORDER = (
    "discovery",
    "identity",
    "authorization",
    "evidence",
    "containment",
    "bypass_detection",
)


@pytest.fixture()
def coverage_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "deployment_family_coverage.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setitem(settings.__dict__, "deployment_family_experience_enabled", True)
    monkeypatch.setitem(settings.__dict__, "deployment_family_coverage_enabled", True)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, session_factory
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _settings(**overrides: Any) -> Settings:
    values = {
        "secret_key": "deployment-coverage-api-secret",
        "connector_secrets_key": "deployment-coverage-connector-secret",
        "connector_secrets_kdf_salt": "deployment-coverage-kdf-salt",
        "onprem_bundle_signing_secret": "deployment-coverage-onprem-secret",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def _identity(session_factory, *, email: str, role: str = "viewer"):
    with session_factory() as db:
        tenant = Tenant(
            name=f"{email} tenant",
            slug=email.replace("@", "-").replace(".", "-"),
            is_active=True,
        )
        user = User(
            email=email,
            hashed_password="unused",
            full_name=email,
            is_active=True,
        )
        db.add_all((tenant, user))
        db.flush()
        db.add(
            UserTenantRole(
                user_id=user.id,
                tenant_id=tenant.id,
                role=role,
            )
        )
        db.commit()
        tenant_id = tenant.id
        user_id = user.id
    return tenant_id, {
        "Authorization": f"Bearer {create_access_token(user_id, tenant_id=tenant_id, role=role)}",
        "X-Tenant-ID": tenant_id,
    }


def _count_coverage_rows(session_factory) -> tuple[int, int, int]:
    with session_factory() as db:
        return (
            db.scalar(select(func.count()).select_from(ControlCoveragePath)) or 0,
            db.scalar(select(func.count()).select_from(ControlCoverageAssertion)) or 0,
            db.scalar(select(func.count()).select_from(ControlCoverageSnapshot)) or 0,
        )


def _snapshot_relevant_rows(session_factory) -> dict[str, tuple[str, ...]]:
    models = (
        ControlCoveragePath,
        ControlCoverageAssertion,
        ControlCoverageSnapshot,
        DeploymentSurface,
        DecisionReceipt,
        ExecutionReceipt,
        RuntimeEvent,
        AIAction,
        EvidenceNode,
        ApprovalBinding,
    )
    with session_factory() as db:
        return {
            model.__tablename__: tuple(
                sorted(
                    repr(tuple(row))
                    for row in db.execute(
                        select(*model.__table__.columns)
                    ).all()
                )
            )
            for model in models
        }


@contextmanager
def _capture_mutating_sql(session_factory):
    engine = session_factory.kw["bind"]
    statements: list[str] = []

    def before_cursor_execute(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(str(statement).split()).lower()
        if normalized.startswith(("insert ", "update ", "delete ")):
            statements.append(normalized)

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)


def _seed_current_snapshot(
    session_factory,
    *,
    tenant_id: str,
    computed_at: datetime | None = None,
    freshness_status: str = "current",
    surface_health: str = "healthy",
    deployment_state: str = "covered",
    deployment_reason: str = "deployment_surface_active",
    future_observed_dimension: str | None = None,
    future_evaluated_dimension: str | None = None,
    authorization_refs: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    authorization_state: str = "covered",
    authorization_reason: str = "verified_inline_decision",
    evidence_state: str = "covered",
    evidence_reason: str = "verified_execution_evidence",
    discovery_state: str = "covered",
    discovery_reason: str = "verified_discovery_observation",
    identity_state: str = "covered",
    identity_reason: str = "verified_identity_binding",
    bypass_state: str = "covered",
    bypass_reason: str = "bypass_detector_operational",
    event_user_id: str | None = None,
    event_type: str = "tool_call",
    event_metadata: dict[str, object] | None = None,
    surface_profile: dict[str, object] | None = None,
) -> None:
    now = (computed_at or datetime.now(timezone.utc)).replace(microsecond=0)
    with session_factory() as db:
        surface = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="test",
            source_id="runtime-surface",
            name="Runtime surface",
            surface_type="mcp_gateway",
            deployment_mode="inline",
            deployment_family="runtime",
            hosting_mode="hybrid",
            environment="production",
            status="active",
            capability_profile=dict(surface_profile or {}),
            capability_sources=[],
            control_capability="inline",
            evidence_capability="complete",
            containment_capability="direct",
            bypass_detection_capability="supported",
            health_status=surface_health,
            health_reason="current_heartbeat",
            first_seen_at=now - timedelta(days=1),
            last_seen_at=now,
            last_health_check_at=now,
            metadata_json={},
            created_at=now,
            updated_at=now,
        )
        db.add(surface)
        db.flush()
        candidate = runtime_event_candidate(
            RuntimeEvent(
                event_id="event-1",
                tenant_id=tenant_id,
                source_surface="mcp_gateway",
                event_type=event_type,
                user_id=event_user_id,
                metadata_json={
                    **(event_metadata or {}),
                    "deployment_surface_row_id": surface.id,
                },
                created_at=now,
            ),
            deployment_surface=surface,
        )
        path = ControlCoveragePath(
            tenant_id=tenant_id,
            path_key=make_path_key(candidate),
            asset_ref=candidate.asset_ref,
            identity_type=candidate.identity_type,
            identity_ref=candidate.identity_ref,
            runtime_ref=candidate.runtime_ref,
            deployment_surface_id=candidate.deployment_surface_id,
            deployment_surface_ref=candidate.deployment_surface_ref,
            destination_type=candidate.destination_type,
            destination_ref=candidate.destination_ref,
            source_refs=["runtime_event:event-1"],
            first_seen_at=now - timedelta(hours=1),
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(path)
        db.flush()
        assertions = []
        for dimension in CoverageDimension:
            assertion_refs = (
                authorization_refs
                if dimension.value == "authorization"
                and authorization_refs is not None
                else evidence_refs
                if dimension.value == "evidence"
                and evidence_refs is not None
                else ["runtime_event:event-1"]
            )
            row = ControlCoverageAssertion(
                tenant_id=tenant_id,
                path_id=path.id,
                dimension=dimension.value,
                state=(
                    deployment_state
                    if dimension.value == "deployment"
                    else authorization_state
                    if dimension.value == "authorization"
                    else evidence_state
                    if dimension.value == "evidence"
                    else discovery_state
                    if dimension.value == "discovery"
                    else identity_state
                    if dimension.value == "identity"
                    else bypass_state
                    if dimension.value == "bypass"
                    else "covered"
                ),
                reason_code={
                    "discovery": discovery_reason,
                    "identity": identity_reason,
                    "authorization": authorization_reason,
                    "evidence": evidence_reason,
                    "deployment": deployment_reason,
                    "runtime": "runtime_governance_verified",
                    "bypass": bypass_reason,
                }[dimension.value],
                explanation="verified",
                methodology_version="control-coverage/1.0",
                evaluator_version="control-coverage-evaluator/1.0",
                evidence_refs=assertion_refs,
                source_watermark=hashlib.sha256(
                    json.dumps(
                        assertion_refs,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
                observed_at=(
                    now + timedelta(minutes=5)
                    if dimension.value == future_observed_dimension
                    else now
                ),
                evaluated_at=(
                    now + timedelta(minutes=5)
                    if dimension.value == future_evaluated_dimension
                    else now
                ),
                valid_until=now + timedelta(hours=1),
            )
            db.add(row)
            assertions.append(row)
        db.flush()
        watermarks = {
            "runtime_event": "event-1",
            "ai_action": "none",
            "decision_receipt": "none",
            "execution_receipt": "none",
            "deployment_surface": surface.id,
            SURFACE_PROJECTION_WATERMARK_KEY: (
                deployment_family_surface_projection_digest(
                    paths=(path,),
                    surfaces_by_id={surface.id: surface},
                )
            ),
        }
        db.add(
            ControlCoverageSnapshot(
                tenant_id=tenant_id,
                methodology_version="control-coverage/1.0",
                window_start=now - timedelta(days=30),
                window_end=now,
                input_digest=_snapshot_digest(
                    watermarks=watermarks,
                    paths=(path,),
                    assertions=assertions,
                ),
                headline_counts={},
                headline_score=100.0,
                dimension_summaries={},
                input_watermarks=watermarks,
                diagnostics=[],
                freshness_status=freshness_status,
                computed_at=now,
            )
        )
        db.commit()


def _seed_runtime_event(
    session_factory,
    *,
    tenant_id: str,
    event_id: str = "event-1",
    created_at: datetime | None = None,
    user_id: str | None = None,
    event_type: str = "tool_call",
    metadata: dict[str, object] | None = None,
) -> None:
    with session_factory() as db:
        if created_at is None:
            snapshot = db.scalar(
                select(ControlCoverageSnapshot)
                .where(ControlCoverageSnapshot.tenant_id == tenant_id)
                .order_by(ControlCoverageSnapshot.computed_at.desc())
            )
            created_at = (
                snapshot.computed_at
                if snapshot is not None
                else datetime.now(timezone.utc).replace(microsecond=0)
            )
        surface = db.scalar(
            select(DeploymentSurface).where(
                DeploymentSurface.tenant_id == tenant_id
            )
        )
        db.add(
            RuntimeEvent(
                event_id=event_id,
                tenant_id=tenant_id,
                source_surface="mcp_gateway",
                event_type=event_type,
                user_id=user_id,
                metadata_json={
                    **(metadata or {}),
                    **(
                        {"deployment_surface_row_id": surface.id}
                        if surface is not None
                        else {}
                    ),
                },
                created_at=created_at,
            )
        )
        db.commit()


def _foreign_decision_receipt(
    session_factory,
    *,
    tenant_id: str,
    receipt_id: str,
    action_id: str,
) -> None:
    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(
            DecisionReceipt(
                receipt_id=receipt_id,
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id="foreign-chain",
                canonical_action_hash="a" * 64,
                actor_hash="b" * 64,
                authority_hash="c" * 64,
                purpose_hash="d" * 64,
                tool_fingerprint="tool",
                parameter_hash="e" * 64,
                target_resource_hash="f" * 64,
                destination_hash="1" * 64,
                side_effect_class="read",
                approval_binding_hash="2" * 64,
                policy_snapshot_id="policy-1",
                decision="allow",
                control_mode="inline_allowed",
                transformations=[],
                expires_at=now + timedelta(hours=1),
                issued_at=now,
                signature="invalid",
                signing_key_id="missing",
                collector_id="foreign",
                canonical_action_evidence_node_id="missing-node",
                idempotency_key=f"foreign-{receipt_id}",
            )
        )
        db.commit()


def _canonical_action(
    *,
    tenant_id: str,
    action_id: str,
    decision: str = "allow",
    control_mode: str = "inline_allowed",
) -> dict[str, object]:
    return {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "action_id": action_id,
        "tenant_id": tenant_id,
        "chain_id": f"chain-{action_id}",
        "actor": {"identity_id": "user-001", "user_id": "user-001"},
        "authority": {
            "authority_type": "delegated",
            "authority_source": "server-session",
            "permission_scope": ["tool:read"],
            "verified": True,
        },
        "purpose": {
            "declared_purpose": "coverage-test",
            "purpose_status": "verified",
        },
        "action": {
            "action_type": "tool_execution",
            "action_category": "read",
            "tool_name": "accounts.read",
            "tool_version": "1",
            "tool_fingerprint_id": "fingerprint-001",
            "parameter_hash": "parameter-hash-001",
            "target_resource_hash": "target-hash-001",
            "destination_hash": "destination-hash-001",
            "side_effect_class": "read_only",
        },
        "approval": {"approval_binding_hash": "approval-hash-001"},
        "policy": {
            "policy_snapshot_id": "policy-001",
            "decision": decision,
            "control_mode": control_mode,
        },
    }


def _seed_verified_receipt_chain(
    session_factory,
    *,
    tenant_id: str,
    action_id: str,
    issued_at: datetime,
) -> tuple[str, str]:
    with session_factory() as db:
        canonical = _canonical_action(
            tenant_id=tenant_id,
            action_id=action_id,
        )
        decision = create_decision_receipt(
            db,
            tenant_id=tenant_id,
            canonical_action=canonical,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="mcp-gateway",
            settings_obj=settings,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(hours=1),
        )
        execution, _ = create_execution_receipt(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=canonical,
            execution_status="success",
            collector_id="mcp-gateway",
            settings_obj=settings,
            executed_at=issued_at + timedelta(seconds=1),
        )
        db.commit()
        return decision.receipt_id, execution.receipt_id


def _seed_verified_block_decision(
    session_factory,
    *,
    tenant_id: str,
    action_id: str,
    issued_at: datetime,
) -> str:
    with session_factory() as db:
        canonical = _canonical_action(
            tenant_id=tenant_id,
            action_id=action_id,
            decision="block",
            control_mode="inline_prevented",
        )
        decision = create_decision_receipt(
            db,
            tenant_id=tenant_id,
            canonical_action=canonical,
            decision="block",
            control_mode="inline_prevented",
            collector_id="mcp-gateway",
            settings_obj=settings,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(hours=1),
        )
        db.commit()
        return decision.receipt_id


def test_coverage_flag_defaults_off_and_honors_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEPLOYMENT_FAMILY_COVERAGE_ENABLED", raising=False)
    assert _settings().deployment_family_coverage_enabled is False
    monkeypatch.setenv("DEPLOYMENT_FAMILY_COVERAGE_ENABLED", "true")
    assert _settings().deployment_family_coverage_enabled is True


def test_coverage_requires_both_parent_and_coverage_flags(
    coverage_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = coverage_env
    _, headers = _identity(session_factory, email="flags@example.com")

    monkeypatch.setitem(settings.__dict__, "deployment_family_coverage_enabled", False)
    response = client.get("/deployments/coverage", headers=headers)
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}

    response = client.get(
        "/deployments/coverage/not-a-family",
        headers=headers,
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}

    monkeypatch.setitem(settings.__dict__, "deployment_family_coverage_enabled", True)
    monkeypatch.setitem(settings.__dict__, "deployment_family_experience_enabled", False)
    response = client.get("/deployments/coverage", headers=headers)
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_missing_snapshot_is_typed_200_and_get_does_not_materialize(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="empty@example.com")
    before = _count_coverage_rows(session_factory)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["tenant_id"] == tenant_id
    assert payload["methodology"] == "deployment-family-coverage/1.0"
    assert payload["freshness_status"] == "unknown"
    assert payload["confidence_basis"]
    assert [item["family"] for item in payload["items"]] == list(FAMILY_ORDER)
    assert "overall" not in payload
    assert payload["diagnostics"] == ["missing_current_control_coverage_snapshot"]
    assert payload["known_estate_limitation"]
    for family in payload["items"]:
        assert [item["name"] for item in family["dimensions"]] == list(DIMENSION_ORDER)
        assert "overall" not in family
        for dimension in family["dimensions"]:
            assert set(dimension) == {
                "name",
                "status",
                "covered_count",
                "not_covered_count",
                "total_known_eligible_count",
                "unknown_count",
                "excluded_count",
                "percentage_nullable",
                "confidence",
                "methodology",
                "evidence_refs",
                "calculated_at",
            }
    assert _count_coverage_rows(session_factory) == before


def test_safe_references_without_extant_evidence_downgrade_to_unknown(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="current@example.com")
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    before = _count_coverage_rows(session_factory)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    runtime = next(item for item in payload["items"] if item["family"] == "runtime")
    by_name = {item["name"]: item for item in runtime["dimensions"]}
    for dimension in DIMENSION_ORDER:
        assert by_name[dimension]["covered_count"] == 0
        assert by_name[dimension]["unknown_count"] == 1
    assert runtime["overall"]["percentage_nullable"] == 0.0
    assert runtime["overall"]["confidence"] == "unknown"
    assert runtime["overall"]["methodology"] == "deployment-family-coverage/1.0"
    assert runtime["overall"]["calculated_at"] == payload["calculated_at"]
    assert set(runtime["overall"]) == {
        "covered_count",
        "not_covered_count",
        "total_known_eligible_count",
        "unknown_count",
        "excluded_count",
        "percentage_nullable",
        "confidence",
        "confidence_basis",
        "methodology",
        "calculated_at",
    }
    assert "overall" not in payload
    assert _count_coverage_rows(session_factory) == before


def test_real_v1_materialization_db_timestamp_skew_is_not_incoherent(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="real-v1-skew@example.com",
    )
    captured_now = (
        datetime.now(timezone.utc).replace(microsecond=0)
        - timedelta(seconds=2)
    )
    with session_factory() as db:
        db.add(
            RuntimeEvent(
                event_id="real-v1-event",
                tenant_id=tenant_id,
                source_surface="mcp_gateway",
                event_type="tool_call",
                metadata_json={},
                created_at=captured_now,
            )
        )
        db.flush()
        calculation = calculate_tenant_control_coverage(
            db,
            tenant_id=tenant_id,
            now=captured_now,
            window_days=30,
        )
        db.flush()
        assert calculation.paths
        path_updated_at = calculation.paths[0].updated_at
        snapshot_computed_at = calculation.snapshot.computed_at
        if path_updated_at.tzinfo is None:
            path_updated_at = path_updated_at.replace(tzinfo=timezone.utc)
        if snapshot_computed_at.tzinfo is None:
            snapshot_computed_at = snapshot_computed_at.replace(
                tzinfo=timezone.utc
            )
        assert path_updated_at > snapshot_computed_at
        db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert "control_coverage_snapshot_incoherent" not in response.json()[
        "diagnostics"
    ]
    assert sum(
        item["dimensions"][0]["total_known_eligible_count"]
        for item in response.json()["items"]
    ) == 1


def test_extant_source_observation_is_required_for_observation_backed_states(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="observed@example.com")
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    _seed_runtime_event(session_factory, tenant_id=tenant_id)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    by_name = {item["name"]: item for item in runtime["dimensions"]}
    assert by_name["discovery"]["covered_count"] == 1
    for dimension in (
        "identity",
        "authorization",
        "evidence",
        "containment",
        "bypass_detection",
    ):
        assert by_name[dimension]["unknown_count"] == 1
    assert runtime["overall"]["percentage_nullable"] == 16.67


def test_verified_exact_path_receipt_chain_supports_authorization_and_evidence(
    coverage_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="verified-receipts@example.com",
    )
    monkeypatch.setitem(
        settings.__dict__,
        "decision_execution_receipts_enabled",
        True,
    )
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_active_key_id",
        "coverage-key",
    )
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_keys_json",
        '{"coverage-key":"coverage-signing-key-material-00000001"}',
    )
    issued_at = (
        datetime.now(timezone.utc).replace(microsecond=0)
        - timedelta(minutes=1)
    )
    decision_id, execution_id = _seed_verified_receipt_chain(
        session_factory,
        tenant_id=tenant_id,
        action_id="event-1",
        issued_at=issued_at,
    )
    snapshot_at = datetime.now(timezone.utc).replace(microsecond=0)
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        computed_at=snapshot_at,
        authorization_refs=[
            "runtime_event:event-1",
            f"decision_receipt:{decision_id}",
        ],
        evidence_refs=[
            "runtime_event:event-1",
            f"decision_receipt:{decision_id}",
            f"execution_receipt:{execution_id}",
        ],
    )
    _seed_runtime_event(
        session_factory,
        tenant_id=tenant_id,
        created_at=issued_at,
    )

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    by_name = {item["name"]: item for item in runtime["dimensions"]}
    assert by_name["authorization"]["covered_count"] == 1
    assert by_name["evidence"]["covered_count"] == 1
    assert by_name["containment"]["unknown_count"] == 1
    assert runtime["overall"]["percentage_nullable"] == 50.0


def test_observed_monitor_only_and_missing_execution_proofs_are_not_covered(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="observed-gaps@example.com",
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        authorization_state="not_covered",
        authorization_reason="monitor_only_surface",
        evidence_state="not_covered",
        evidence_reason="missing_execution_proof",
        event_metadata={"control_mode": "monitor_only"},
    )
    _seed_runtime_event(
        session_factory,
        tenant_id=tenant_id,
        metadata={"control_mode": "monitor_only"},
    )

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    by_name = {item["name"]: item for item in runtime["dimensions"]}
    assert by_name["authorization"]["not_covered_count"] == 1
    assert by_name["evidence"]["not_covered_count"] == 1


def test_explicit_source_predicates_support_identity_and_discovery_states(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="source-predicates@example.com",
    )
    metadata = {
        "confirmed_unmanaged": True,
        "identity_confirmed_unbound": True,
    }
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        discovery_state="not_covered",
        discovery_reason="confirmed_unmanaged_path",
        identity_state="not_covered",
        identity_reason="missing_identity_binding",
        event_metadata=metadata,
    )
    _seed_runtime_event(
        session_factory,
        tenant_id=tenant_id,
        metadata=metadata,
    )

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    by_name = {item["name"]: item for item in runtime["dimensions"]}
    assert by_name["discovery"]["not_covered_count"] == 1
    assert by_name["identity"]["not_covered_count"] == 1


def test_resolved_source_identity_can_support_identity_covered(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="resolved-source-identity@example.com",
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        event_user_id="user-123",
    )
    _seed_runtime_event(
        session_factory,
        tenant_id=tenant_id,
        user_id="user-123",
    )

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    identity = next(
        item for item in runtime["dimensions"] if item["name"] == "identity"
    )
    assert identity["covered_count"] == 1


def test_monitor_only_assertion_without_monitor_mode_evidence_is_unknown(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="missing-monitor-mode@example.com",
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        authorization_state="not_covered",
        authorization_reason="monitor_only_surface",
    )
    _seed_runtime_event(session_factory, tenant_id=tenant_id)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    authorization = next(
        item for item in runtime["dimensions"] if item["name"] == "authorization"
    )
    assert authorization["not_covered_count"] == 0
    assert authorization["unknown_count"] == 1


@pytest.mark.parametrize("operational", [False, True])
def test_bypass_state_requires_exact_source_detector_predicates(
    coverage_env,
    operational: bool,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email=f"bypass-{operational}@example.com",
    )
    metadata = (
        {
            "hawk_validated_bypass_observation": True,
            "gateway_bypass_detected": True,
            "gateway_routed": False,
            "enforcement_path": "observed_unprotected_route",
            "control_mode": "post_execution",
            "triggered_controls": ["SHADOW_AI_DETECTION"],
            "reason_code": "unprotected_mcp_route_observed",
            "identity_binding_state": "authenticated_self",
        }
        if operational
        else {"bypass_observed": True}
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        bypass_state="covered" if operational else "not_covered",
        bypass_reason="bypass_observed",
        event_metadata=metadata,
    )
    _seed_runtime_event(
        session_factory,
        tenant_id=tenant_id,
        metadata=metadata,
    )

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    bypass = next(
        item
        for item in runtime["dimensions"]
        if item["name"] == "bypass_detection"
    )
    expected = "covered_count" if operational else "not_covered_count"
    assert bypass[expected] == 1


def test_future_assertion_observation_fails_snapshot_coherence(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="future-observed@example.com")
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        future_observed_dimension="discovery",
    )
    _seed_runtime_event(session_factory, tenant_id=tenant_id)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [
        "control_coverage_snapshot_incoherent"
    ]
    assert response.json()["freshness_status"] == "unknown"
    assert all("overall" not in item for item in response.json()["items"])


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    (
        ("future_evaluated", "control_coverage_snapshot_incoherent"),
        (
            "source_watermark_mismatch",
            "control_coverage_assertion_watermark_mismatch",
        ),
        ("window_end_mismatch", "control_coverage_snapshot_incoherent"),
        ("unexpected_watermark", "invalid_control_coverage_watermarks"),
        ("bearer_watermark", "invalid_control_coverage_watermarks"),
        ("url_watermark", "invalid_control_coverage_watermarks"),
        ("newline_watermark", "invalid_control_coverage_watermarks"),
        ("derived_digest_attack", "invalid_control_coverage_watermarks"),
    ),
)
def test_snapshot_mutable_inputs_are_bound_and_fail_typed_unavailable(
    coverage_env,
    mutation: str,
    diagnostic: str,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email=f"{mutation}@example.com",
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        future_evaluated_dimension=(
            "identity" if mutation == "future_evaluated" else None
        ),
    )
    if mutation != "future_evaluated":
        with session_factory() as db:
            if mutation == "source_watermark_mismatch":
                assertion = db.scalar(
                    select(ControlCoverageAssertion).where(
                        ControlCoverageAssertion.tenant_id == tenant_id,
                        ControlCoverageAssertion.dimension == "identity",
                    )
                )
                assert assertion is not None
                assertion.source_watermark = "0" * 64
            elif mutation == "window_end_mismatch":
                snapshot = db.scalar(
                    select(ControlCoverageSnapshot).where(
                        ControlCoverageSnapshot.tenant_id == tenant_id
                    )
                )
                assert snapshot is not None
                snapshot.window_end = snapshot.computed_at - timedelta(seconds=1)
                snapshot.window_start = snapshot.window_start - timedelta(seconds=1)
            else:
                snapshot = db.scalar(
                    select(ControlCoverageSnapshot).where(
                        ControlCoverageSnapshot.tenant_id == tenant_id
                    )
                )
                assert snapshot is not None
                if mutation == "unexpected_watermark":
                    snapshot.input_watermarks = {
                        **snapshot.input_watermarks,
                        "unexpected": {"secret": "must-not-stringify"},
                    }
                elif mutation == "derived_digest_attack":
                    snapshot.input_digest = "Bearer secret-material"
                else:
                    attack = {
                        "bearer_watermark": "Bearer secret-material",
                        "url_watermark": "https://example.invalid/receipt",
                        "newline_watermark": "receipt\ninjected",
                    }[mutation]
                    snapshot.input_watermarks = {
                        **snapshot.input_watermarks,
                        "decision_receipt": attack,
                    }
            db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [diagnostic]
    assert "unexpected" not in response.json()["input_watermarks"]
    assert "must-not-stringify" not in response.text
    assert all("overall" not in item for item in response.json()["items"])


def test_processing_ceiling_returns_typed_unavailable_without_partial_score(
    coverage_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="ceiling@example.com")
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    monkeypatch.setattr(coverage_service, "MAX_PATHS", 0)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [
        "coverage_processing_limit_exceeded"
    ]
    assert all("overall" not in item for item in response.json()["items"])


def test_malformed_assertion_ref_json_fails_typed_without_server_error(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="malformed-refs@example.com",
    )
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    with session_factory() as db:
        assertion = db.scalar(
            select(ControlCoverageAssertion).where(
                ControlCoverageAssertion.tenant_id == tenant_id,
                ControlCoverageAssertion.dimension == "identity",
            )
        )
        assert assertion is not None
        assertion.evidence_refs = [{"not": "a string"}]
        db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [
        "invalid_assertion_evidence_refs"
    ]


def test_foreign_source_observation_cannot_support_target_tenant(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    target_tenant_id, target_headers = _identity(
        session_factory,
        email="source-target@example.com",
    )
    foreign_tenant_id, _ = _identity(
        session_factory,
        email="source-foreign@example.com",
    )
    _seed_current_snapshot(session_factory, tenant_id=target_tenant_id)
    with session_factory() as db:
        target_snapshot = db.scalar(
            select(ControlCoverageSnapshot).where(
                ControlCoverageSnapshot.tenant_id == target_tenant_id
            )
        )
        assert target_snapshot is not None
        target_time = target_snapshot.computed_at
    _seed_runtime_event(
        session_factory,
        tenant_id=foreign_tenant_id,
        created_at=target_time,
    )

    response = client.get("/deployments/coverage", headers=target_headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    for dimension in (
        "discovery",
        "identity",
        "authorization",
        "evidence",
        "bypass_detection",
    ):
        item = next(
            value for value in runtime["dimensions"] if value["name"] == dimension
        )
        assert item["unknown_count"] == 1


def test_post_snapshot_source_mutation_cannot_change_path_identity(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="mutated-source@example.com",
    )
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    _seed_runtime_event(session_factory, tenant_id=tenant_id)
    with session_factory() as db:
        event_row = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == tenant_id,
                RuntimeEvent.event_id == "event-1",
            )
        )
        assert event_row is not None
        event_row.metadata_json = {"tool_name": "mutated-after-snapshot"}
        db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [
        "control_coverage_snapshot_incoherent"
    ]
    assert all("overall" not in item for item in response.json()["items"])


def test_post_snapshot_source_surface_rebinding_cannot_reuse_old_path_surface(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="mutated-source-surface@example.com",
    )
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    _seed_runtime_event(session_factory, tenant_id=tenant_id)
    with session_factory() as db:
        event_row = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == tenant_id,
                RuntimeEvent.event_id == "event-1",
            )
        )
        assert event_row is not None
        event_row.metadata_json = {
            **event_row.metadata_json,
            "deployment_surface_row_id": "post-snapshot-rebinding",
        }
        db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [
        "control_coverage_snapshot_incoherent"
    ]


def test_post_snapshot_path_surface_fk_mutation_fails_closed(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="mutated-path-surface-fk@example.com",
    )
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    _seed_runtime_event(session_factory, tenant_id=tenant_id)
    with session_factory() as db:
        path = db.scalar(
            select(ControlCoveragePath).where(
                ControlCoveragePath.tenant_id == tenant_id
            )
        )
        original = db.scalar(
            select(DeploymentSurface).where(
                DeploymentSurface.tenant_id == tenant_id
            )
        )
        assert path is not None
        assert original is not None
        replacement = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="test",
            source_id="replacement-surface",
            name="Replacement surface",
            surface_type="browser_extension",
            deployment_mode="monitor_only",
            deployment_family="browser",
            hosting_mode="saas",
            environment="production",
            status="active",
            capability_profile={},
            capability_sources=[],
            control_capability="monitor_only",
            evidence_capability="metadata_only",
            containment_capability="none",
            bypass_detection_capability="unsupported",
            health_status="healthy",
            health_reason="current_heartbeat",
            first_seen_at=original.first_seen_at,
            last_seen_at=original.last_seen_at,
            last_health_check_at=original.last_health_check_at,
            metadata_json={},
        )
        db.add(replacement)
        db.flush()
        path.deployment_surface_id = replacement.id
        db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [
        "deployment_family_surface_projection_mismatch"
    ]
    assert all("overall" not in item for item in response.json()["items"])


@pytest.mark.parametrize(
    ("field", "mutated_value"),
    (
        ("deployment_family", "browser"),
        ("containment_capability", "none"),
        ("health_status", "offline"),
        ("capability_profile", {"bypass_detection": "unsupported"}),
    ),
)
def test_post_snapshot_scored_surface_field_mutation_fails_closed(
    coverage_env,
    field: str,
    mutated_value: object,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email=f"mutated-surface-{field}@example.com",
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        surface_profile={"bypass_detection": "supported"},
    )
    _seed_runtime_event(session_factory, tenant_id=tenant_id)
    with session_factory() as db:
        surface = db.scalar(
            select(DeploymentSurface).where(
                DeploymentSurface.tenant_id == tenant_id
            )
        )
        assert surface is not None
        setattr(surface, field, mutated_value)
        db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == [
        "deployment_family_surface_projection_mismatch"
    ]
    assert all("overall" not in item for item in response.json()["items"])


def test_profile_only_supported_bypass_replays_v1_covered(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="profile-only-bypass@example.com",
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        surface_profile={"bypass_detection": "supported"},
        bypass_state="covered",
        bypass_reason="bypass_detector_operational",
    )
    _seed_runtime_event(session_factory, tenant_id=tenant_id)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    bypass = next(
        item
        for item in runtime["dimensions"]
        if item["name"] == "bypass_detection"
    )
    assert bypass["covered_count"] == 1
    assert bypass["unknown_count"] == 0


def test_canonical_action_endpoint_mutation_resolves_new_surface() -> None:
    old_surface = DeploymentSurface(
        id="old-surface",
        tenant_id="tenant-a",
        source_kind="deployment_endpoint",
        source_id="endpoint-old",
        name="Old",
        surface_type="endpoint_agent",
    )
    new_surface = DeploymentSurface(
        id="new-surface",
        tenant_id="tenant-a",
        source_kind="deployment_endpoint",
        source_id="endpoint-new",
        name="New",
        surface_type="endpoint_agent",
    )
    _, by_source = surface_indexes((old_surface, new_surface))
    action = AIAction(
        action_id="action-1",
        tenant_id="tenant-a",
        session_id="session-1",
        endpoint_id="endpoint-old",
        action_type="tool_call",
        enforcement_action="allowed",
        metadata_json={},
    )
    old_candidate = ai_action_candidate(
        action,
        deployment_surface=surface_for_action(
            action,
            by_source=by_source,
        ),
    )

    action.endpoint_id = "endpoint-new"
    new_candidate = ai_action_candidate(
        action,
        deployment_surface=surface_for_action(
            action,
            by_source=by_source,
        ),
    )

    assert old_candidate.deployment_surface_id == "old-surface"
    assert new_candidate.deployment_surface_id == "new-surface"
    assert make_path_key(new_candidate) != make_path_key(old_candidate)


def test_foreign_decision_receipt_cannot_support_authorization(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    target_tenant_id, target_headers = _identity(
        session_factory,
        email="receipt-target@example.com",
    )
    foreign_tenant_id, _ = _identity(
        session_factory,
        email="receipt-foreign@example.com",
    )
    _seed_current_snapshot(
        session_factory,
        tenant_id=target_tenant_id,
        authorization_refs=["decision_receipt:foreign-receipt"],
    )
    _seed_runtime_event(session_factory, tenant_id=target_tenant_id)
    _foreign_decision_receipt(
        session_factory,
        tenant_id=foreign_tenant_id,
        receipt_id="foreign-receipt",
        action_id="event-1",
    )

    response = client.get("/deployments/coverage", headers=target_headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    authorization = next(
        item for item in runtime["dimensions"] if item["name"] == "authorization"
    )
    assert authorization["covered_count"] == 0
    assert authorization["unknown_count"] == 1


def test_both_get_routes_execute_no_mutating_sql_and_preserve_relevant_rows(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="readonly@example.com")
    _seed_current_snapshot(session_factory, tenant_id=tenant_id)
    before = _snapshot_relevant_rows(session_factory)

    with _capture_mutating_sql(session_factory) as mutations:
        collection = client.get("/deployments/coverage", headers=headers)
        detail = client.get(
            "/deployments/coverage/runtime",
            headers=headers,
        )

    assert collection.status_code == 200, collection.text
    assert detail.status_code == 200, detail.text
    assert mutations == []
    assert _snapshot_relevant_rows(session_factory) == before


def test_stale_snapshot_preserves_known_population_as_unknown(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="stale@example.com")
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        computed_at=datetime.now(timezone.utc) - timedelta(minutes=31),
    )

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["diagnostics"] == ["stale_control_coverage_snapshot"]
    assert payload["freshness_status"] == "stale"
    runtime = next(item for item in payload["items"] if item["family"] == "runtime")
    assert runtime["overall"]["percentage_nullable"] == 0.0
    assert runtime["overall"]["confidence"] == "unknown"
    for dimension in runtime["dimensions"]:
        assert dimension["total_known_eligible_count"] == 1
        assert dimension["unknown_count"] == 1
        assert dimension["confidence"] == "unknown"


def test_current_offline_proof_never_grants_direct_containment(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="offline@example.com")
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        surface_health="offline",
        deployment_state="not_covered",
        deployment_reason="surface_offline",
    )
    _seed_runtime_event(session_factory, tenant_id=tenant_id)

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    containment = next(
        item for item in runtime["dimensions"] if item["name"] == "containment"
    )
    assert containment["covered_count"] == 0
    assert containment["not_covered_count"] == 1


def test_block_receipt_cannot_override_not_covered_authorization_assertion(
    coverage_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email="block-with-monitor-auth@example.com",
    )
    monkeypatch.setitem(
        settings.__dict__,
        "decision_execution_receipts_enabled",
        True,
    )
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_active_key_id",
        "coverage-key",
    )
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_keys_json",
        '{"coverage-key":"coverage-signing-key-material-00000001"}',
    )
    issued_at = (
        datetime.now(timezone.utc).replace(microsecond=0)
        - timedelta(minutes=1)
    )
    decision_id = _seed_verified_block_decision(
        session_factory,
        tenant_id=tenant_id,
        action_id="event-1",
        issued_at=issued_at,
    )
    snapshot_at = datetime.now(timezone.utc).replace(microsecond=0)
    _seed_current_snapshot(
        session_factory,
        tenant_id=tenant_id,
        computed_at=snapshot_at,
        authorization_state="not_covered",
        authorization_reason="monitor_only_surface",
        authorization_refs=[
            "runtime_event:event-1",
            f"decision_receipt:{decision_id}",
        ],
        event_metadata={"control_mode": "monitor_only"},
    )
    _seed_runtime_event(
        session_factory,
        tenant_id=tenant_id,
        created_at=issued_at,
        metadata={"control_mode": "monitor_only"},
    )

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    runtime = next(
        item for item in response.json()["items"] if item["family"] == "runtime"
    )
    containment = next(
        item for item in runtime["dimensions"] if item["name"] == "containment"
    )
    assert containment["covered_count"] == 0
    assert containment["unknown_count"] == 1


def test_tenant_isolation_never_projects_another_tenants_snapshot(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    owner_tenant_id, _ = _identity(session_factory, email="owner@example.com")
    _seed_current_snapshot(session_factory, tenant_id=owner_tenant_id)
    viewer_tenant_id, viewer_headers = _identity(
        session_factory,
        email="isolated@example.com",
    )

    response = client.get("/deployments/coverage", headers=viewer_headers)

    assert response.status_code == 200, response.text
    assert response.json()["tenant_id"] == viewer_tenant_id
    assert response.json()["diagnostics"] == [
        "missing_current_control_coverage_snapshot"
    ]


def test_equal_latest_divergent_snapshots_fail_closed_as_conflicting(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(session_factory, email="conflict@example.com")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with session_factory() as db:
        for marker in ("event-a", "event-b"):
            watermarks = {"runtime_event": marker}
            db.add(
                ControlCoverageSnapshot(
                    tenant_id=tenant_id,
                    methodology_version="control-coverage/1.0",
                    window_start=now - timedelta(days=30),
                    window_end=now,
                    input_digest=_snapshot_digest(
                        watermarks=watermarks,
                        paths=(),
                        assertions=(),
                    ),
                    headline_counts={},
                    headline_score=None,
                    dimension_summaries={},
                    input_watermarks=watermarks,
                    diagnostics=[],
                    freshness_status="current",
                    computed_at=now,
                )
            )
        db.commit()

    response = client.get("/deployments/coverage", headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["diagnostics"] == ["snapshot_conflicting"]
    assert all("overall" not in item for item in response.json()["items"])


@pytest.mark.parametrize("family", FAMILY_ORDER)
def test_family_detail_including_empty_and_unknown_is_typed_200(
    coverage_env,
    family: str,
) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _identity(
        session_factory,
        email=f"{family}@example.com",
    )
    response = client.get(f"/deployments/coverage/{family}", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["tenant_id"] == tenant_id
    assert payload["methodology"] == "deployment-family-coverage/1.0"
    assert payload["item"]["family"] == family
    assert "overall" not in payload["item"]


def test_coverage_routes_enforce_auth_viewer_floor_and_window_bounds(
    coverage_env,
) -> None:
    client, session_factory = coverage_env
    _, guest_headers = _identity(
        session_factory,
        email="guest@example.com",
        role="guest",
    )
    assert client.get("/deployments/coverage").status_code == 401
    assert client.get(
        "/deployments/coverage",
        headers=guest_headers,
    ).status_code == 403

    _, viewer_headers = _identity(
        session_factory,
        email="viewer@example.com",
    )
    missing_tenant_headers = dict(viewer_headers)
    missing_tenant_headers.pop("X-Tenant-ID")
    assert client.get(
        "/deployments/coverage",
        headers=missing_tenant_headers,
    ).status_code == 400
    assert client.get(
        "/deployments/coverage?window_days=0",
        headers=viewer_headers,
    ).status_code == 422
    assert client.get(
        "/deployments/coverage?window_days=91",
        headers=viewer_headers,
    ).status_code == 422

    _, admin_headers = _identity(
        session_factory,
        email="admin@example.com",
        role="admin",
    )
    assert client.get(
        "/deployments/coverage",
        headers=admin_headers,
    ).status_code == 200
