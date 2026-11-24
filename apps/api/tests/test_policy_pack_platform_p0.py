from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _database(tmp_path, name: str):
    from app.db import models as _models  # noqa: F401
    from app.db.session import Base

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / name}")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def _tenant_with_entitlement(db, *, label: str):
    from app.db.models.policy_pack_platform import PolicyPackPlatformEntitlement
    from app.db.models.tenant import Tenant
    from app.db.models.user import User, UserTenantRole

    tenant = Tenant(name=label, slug=f"{label.lower().replace(' ', '-')}-{uuid4().hex[:8]}", is_active=True)
    owner = User(email=f"owner-{uuid4().hex[:10]}@example.test", hashed_password="test", full_name="Owner")
    approver = User(email=f"approver-{uuid4().hex[:10]}@example.test", hashed_password="test", full_name="Approver")
    db.add_all([tenant, owner, approver])
    db.flush()
    db.add_all(
        [
            UserTenantRole(tenant_id=tenant.id, user_id=owner.id, role="owner"),
            UserTenantRole(tenant_id=tenant.id, user_id=approver.id, role="admin"),
            PolicyPackPlatformEntitlement(tenant_id=tenant.id, package_tier="enterprise", enabled=True),
        ]
    )
    db.flush()
    return tenant, owner, approver


def _definition(db, *, template_decision: str = "block", surfaces: list[str] | None = None, stable_id: str = "vendor:data"):
    from app.services.policy_pack_platform.service import create_policy_pack_definition

    return create_policy_pack_definition(
        db,
        publisher_tenant_id=None,
        stable_pack_id=stable_id,
        version="1.0.0",
        name="Sensitive data boundary",
        description="Prevent restricted data from crossing an unmanaged AI boundary.",
        vertical="universal",
        department_persona="security",
        pack_family="data_handling",
        maturity_status="verified",
        package_entitlement="secure",
        applicable_jurisdictions=["global"],
        framework_mappings={"NIST": ["AI.RM-2"]},
        templates=[
            {
                "template_id": "restricted-external-transfer",
                "title": "Restricted external transfer",
                "reason": "Restricted data requires a controlled destination.",
                "condition_tree": {
                    "all": [
                        {"field": "data_classification", "operator": "equals", "value": "restricted"},
                        {"field": "destination_class", "operator": "in", "value": ["external", "public"]},
                    ]
                },
                "decision": template_decision,
                "applicable_surfaces": surfaces or ["browser"],
                "required_fields": ["data_classification", "destination_class"],
                "required_control_capabilities": ["pre_execution_block"],
                "default_mode": "monitor",
                "recommended_mature_mode": "enforce",
                "criticality": "high",
                "override_behavior": "customer_override_allowed",
                "exception_rules": {"max_hours": 8},
                "simulation_expectations": {"minimum_sample_count": 1},
                "evidence_requirements": ["decision_receipt"],
                "human_explanation": "Block restricted data transfers to external destinations.",
                "reference_mappings": {"NIST": ["AI.RM-2"]},
            }
        ],
        required_signals=["data_classification", "destination_class"],
        required_control_capabilities=["pre_execution_block"],
        supported_deployment_surfaces=surfaces or ["browser"],
        default_parameters={"approved_destination_classes": ["internal"]},
        customization_schema={"parameters": ["approved_destination_classes"]},
        simulation_required=True,
        default_rollout="MONITORING",
        exception_guidance="Use an exact, time-bound exception.",
        known_blind_spots=["No DOM-level claim without a verified browser control point."],
        owner_publisher="hawk",
        release_notes="Initial controlled release.",
    )


def test_templates_are_typed_and_never_executable(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "pack-typed.sqlite3")
    try:
        with sessions.begin() as db:
            _definition(db)
            from app.services.policy_pack_platform.service import create_policy_pack_definition

            with pytest.raises(ValueError, match="unsupported condition field"):
                create_policy_pack_definition(
                    db,
                    publisher_tenant_id=None,
                    stable_pack_id="vendor:invalid",
                    version="1.0.0",
                    name="Invalid",
                    description="Invalid template",
                    vertical="universal",
                    department_persona="security",
                    pack_family="test",
                    maturity_status="draft",
                    package_entitlement="secure",
                    templates=[
                        {
                            "template_id": "not-code",
                            "title": "Invalid",
                            "reason": "No executable policy fields are allowed.",
                            "condition_tree": {"field": "shell", "operator": "equals", "value": "rm -rf /"},
                            "decision": "block",
                        }
                    ],
                    owner_publisher="hawk",
                )
    finally:
        engine.dispose()


def test_resource_assignment_dimension_normalizes_and_compiles_to_the_generic_resource_ref() -> None:
    from app.services.policy_pack_platform.service import _assignment_condition_tree, _assignment_precedence, _normalize_assignment_targets

    targets = _normalize_assignment_targets({"application": ["github"], "deployment_surface": ["mcp_gateway"], "resource": ["repo-immutable-1"]})
    assert targets["resource"] == ["repo-immutable-1"]
    assert _assignment_precedence(targets) == (5_000, ["specific_overlay"])
    tree = _assignment_condition_tree(tenant_id="tenant-a", targets=targets)
    assert tree == {"all": [
        {"field": "tenant_id", "operator": "equals", "value": "tenant-a"},
        {"field": "application", "operator": "equals", "value": "github"},
        {"field": "source_surface", "operator": "equals", "value": "mcp_gateway"},
        {"field": "resource_ref", "operator": "equals", "value": "repo-immutable-1"},
    ]}
    multiple = _assignment_condition_tree(tenant_id="tenant-a", targets=_normalize_assignment_targets({"resource": ["repo-immutable-1", "repo-immutable-2"]}))
    assert multiple["all"][-1] == {"field": "resource_ref", "operator": "in", "value": ["repo-immutable-1", "repo-immutable-2"]}


def test_resource_ref_is_not_a_public_assignment_dimension() -> None:
    from app.services.policy_pack_platform.service import PolicyPackPlatformError, _normalize_assignment_targets

    with pytest.raises(PolicyPackPlatformError, match="policy_pack_assignment_dimension_invalid"):
        _normalize_assignment_targets({"resource_ref": ["repo-immutable-1"]})


def test_apply_draft_monitor_and_approved_enforce_compile_existing_policy_lineage(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "pack-apply.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner, approver = _tenant_with_entitlement(db, label="Pack Apply")
            definition = _definition(db)
            from app.db.models.control_coverage import DeploymentSurface
            from app.db.models.policy import PolicyPack, PolicyVersion
            from app.services.policy_pack_platform.service import (
                apply_policy_pack,
                simulate_policy_pack,
                transition_policy_pack_instance,
            )

            db.add(
                DeploymentSurface(
                    tenant_id=tenant.id,
                    source_kind="test",
                    source_id="browser-inline",
                    name="Verified browser control",
                    surface_type="browser",
                    deployment_family="browser",
                    status="active",
                    capability_profile={"independent_verification": True},
                    control_capability="inline",
                    evidence_capability="complete",
                    containment_capability="direct",
                    bypass_detection_capability="supported",
                    health_status="healthy",
                    health_reason="accepted",
                )
            )
            db.flush()

            draft = apply_policy_pack(
                db,
                tenant_id=tenant.id,
                definition_id=definition.id,
                assignments=[{"organization": "all"}],
                customer_parameters={},
                local_overrides={},
                disabled_template_ids=[],
                added_customer_templates=[],
                requested_state="DRAFT",
                requested_by_ref=f"user:{owner.id}",
            )
            assert draft.instance.state == "DRAFT"
            runtime_pack = db.get(PolicyPack, draft.instance.runtime_policy_pack_id)
            runtime_version = db.get(PolicyVersion, draft.instance.effective_policy_version_id)
            assert runtime_pack is not None and runtime_pack.status == "draft"
            assert runtime_version is not None
            assert runtime_version.contract_json["policy_pack_platform"]["instance_id"] == draft.instance.id
            assert runtime_version.scope["scoped_rules"][0]["condition_tree"]["all"]

            monitored = transition_policy_pack_instance(
                db,
                tenant_id=tenant.id,
                instance_id=draft.instance.id,
                target_state="MONITORING",
                actor_ref=f"user:{owner.id}",
            )
            monitored_version = db.get(PolicyVersion, monitored.effective_policy_version_id)
            assert monitored.state == "MONITORING"
            assert monitored_version.scope["scoped_rules"][0]["effect"]["decision"] == "warn"

            simulation = simulate_policy_pack(
                db,
                tenant_id=tenant.id,
                instance_id=monitored.id,
                historical_events=[
                    {
                        "actor_user_id": owner.id,
                        "source_surface": "browser",
                        "data_classification": "restricted",
                        "destination_class": "external",
                    }
                ],
            )
            assert simulation.sample_count == 1
            with pytest.raises(ValueError, match="separate authorized approver"):
                transition_policy_pack_instance(
                    db,
                    tenant_id=tenant.id,
                    instance_id=monitored.id,
                    target_state="ENFORCED",
                    actor_ref=f"user:{owner.id}",
                    approver_ref=f"user:{owner.id}",
                )
            enforced = transition_policy_pack_instance(
                db,
                tenant_id=tenant.id,
                instance_id=monitored.id,
                target_state="ENFORCED",
                actor_ref=f"user:{owner.id}",
                approver_ref=f"user:{approver.id}",
            )
            enforced_version = db.get(PolicyVersion, enforced.effective_policy_version_id)
            assert enforced.state == "ENFORCED"
            assert enforced_version.scope["scoped_rules"][0]["effect"]["decision"] == "block"
    finally:
        engine.dispose()


def test_live_scoped_policy_composes_active_policy_versions(tmp_path) -> None:
    """A newer active pack must not mask a matching active baseline policy."""
    engine, sessions = _database(tmp_path, "pack-live-composition.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, _owner, _approver = _tenant_with_entitlement(db, label="Pack Live Composition")
            from app.db.models.policy import PolicyPack, PolicyVersion
            from app.services.policy_scope_service import resolve_scoped_policy_decision

            baseline_pack = PolicyPack(tenant_id=tenant.id, name="Baseline", description="Existing tenant baseline", status="active")
            managed_pack = PolicyPack(tenant_id=tenant.id, name="Managed Pack", description="Newer policy-pack runtime", status="active")
            db.add_all([baseline_pack, managed_pack])
            db.flush()
            baseline_version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=baseline_pack.id,
                version="baseline-1",
                created_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                scope={
                    "scoped_rules": [
                        {
                            "rule_id": "baseline-restricted-external",
                            "enabled": True,
                            "priority": 100,
                            "condition_tree": {
                                "all": [
                                    {"field": "data_classification", "operator": "equals", "value": "restricted"},
                                    {"field": "destination_class", "operator": "equals", "value": "external"},
                                ]
                            },
                            "effect": {"decision": "block", "reason_code": "baseline_restricted_external", "priority": 100},
                        }
                    ]
                },
                enforcement_defaults={"default_decision": "allow"},
                guardian_contracts=[],
                contract_json={"profile": "baseline"},
            )
            newer_managed_version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=managed_pack.id,
                version="managed-1",
                created_at=datetime.now(timezone.utc),
                scope={
                    "scoped_rules": [
                        {
                            "rule_id": "managed-internal-only",
                            "enabled": True,
                            "priority": 200,
                            "condition_tree": {"field": "destination_class", "operator": "equals", "value": "internal"},
                            "effect": {"decision": "warn", "reason_code": "managed_internal_only", "priority": 200},
                        }
                    ]
                },
                enforcement_defaults={"default_decision": "allow"},
                guardian_contracts=[],
                contract_json={"profile": "policy_pack_platform"},
            )
            db.add_all([baseline_version, newer_managed_version])
            db.flush()

            decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context={"data_classification": "restricted", "destination_class": "external"},
            )

            assert decision.decision == "block"
            assert decision.policy_version_id == baseline_version.id
            assert decision.rule_id == "baseline-restricted-external"
    finally:
        engine.dispose()


def test_live_scoped_policy_preserves_newest_legacy_policy_selection(tmp_path) -> None:
    """Platform composition must not change legacy active-policy selection."""
    engine, sessions = _database(tmp_path, "pack-live-legacy-selection.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, _owner, _approver = _tenant_with_entitlement(db, label="Pack Live Legacy Selection")
            from app.db.models.policy import PolicyPack, PolicyVersion
            from app.services.policy_scope_service import resolve_scoped_policy_decision

            older_pack = PolicyPack(tenant_id=tenant.id, name="Older", description="Older legacy policy", status="active")
            newer_pack = PolicyPack(tenant_id=tenant.id, name="Newer", description="Newer legacy policy", status="active")
            db.add_all([older_pack, newer_pack])
            db.flush()
            older_version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=older_pack.id,
                version="older-1",
                created_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                scope={
                    "scoped_rules": [
                        {
                            "rule_id": "older-block",
                            "enabled": True,
                            "priority": 100,
                            "condition_tree": {"field": "destination_class", "operator": "equals", "value": "external"},
                            "effect": {"decision": "block", "reason_code": "older_block", "priority": 100},
                        }
                    ]
                },
                enforcement_defaults={"default_decision": "allow"},
                guardian_contracts=[],
                contract_json={"profile": "legacy"},
            )
            newer_version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=newer_pack.id,
                version="newer-1",
                created_at=datetime.now(timezone.utc),
                scope={
                    "scoped_rules": [
                        {
                            "rule_id": "newer-warn",
                            "enabled": True,
                            "priority": 100,
                            "condition_tree": {"field": "destination_class", "operator": "equals", "value": "external"},
                            "effect": {"decision": "warn", "reason_code": "newer_warn", "priority": 100},
                        }
                    ]
                },
                enforcement_defaults={"default_decision": "allow"},
                guardian_contracts=[],
                contract_json={"profile": "legacy"},
            )
            db.add_all([older_version, newer_version])
            db.flush()

            decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context={"destination_class": "external"},
            )

            assert decision.decision == "warn"
            assert decision.policy_version_id == newer_version.id
            assert decision.rule_id == "newer-warn"
    finally:
        engine.dispose()


def test_live_scoped_policy_honors_active_policy_pack_exception(tmp_path) -> None:
    """An approved, exact-scope exception must reach the live resolver."""
    engine, sessions = _database(tmp_path, "pack-live-exception.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner, approver = _tenant_with_entitlement(db, label="Pack Live Exception")
            definition = _definition(db)
            from app.services.policy_pack_platform.service import (
                apply_policy_pack,
                create_policy_pack_exception,
                transition_policy_pack_instance,
            )
            from app.services.policy_scope_service import resolve_scoped_policy_decision

            applied = apply_policy_pack(
                db,
                tenant_id=tenant.id,
                definition_id=definition.id,
                assignments=[{"organization": "all"}],
                customer_parameters={},
                local_overrides={},
                disabled_template_ids=[],
                added_customer_templates=[],
                requested_state="DRAFT",
                requested_by_ref=f"user:{owner.id}",
            )
            active = transition_policy_pack_instance(
                db,
                tenant_id=tenant.id,
                instance_id=applied.instance.id,
                target_state="MONITORING",
                actor_ref=f"user:{owner.id}",
            )
            exception = create_policy_pack_exception(
                db,
                tenant_id=tenant.id,
                instance_id=active.id,
                scope={
                    "condition_tree": {
                        "all": [
                            {"field": "data_classification", "operator": "equals", "value": "restricted"},
                            {"field": "destination_class", "operator": "equals", "value": "external"},
                        ]
                    }
                },
                reason="Approved customer data exchange",
                requested_by_ref=f"user:{owner.id}",
                approved_by_ref=f"user:{approver.id}",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            )

            decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context={"data_classification": "restricted", "destination_class": "external", "source_surface": "browser"},
            )

            assert decision.decision == "allow"
            assert decision.policy_version_id == active.effective_policy_version_id
            assert decision.rule_id == f"policy_pack_exception:{exception.id}"
    finally:
        engine.dispose()


def test_static_dynamic_and_nested_groups_are_cycle_safe(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "pack-groups.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner, _approver = _tenant_with_entitlement(db, label="Pack Groups")
            from app.db.models.activity_audit import UserRegistry
            from app.db.models.user import User
            from app.services.policy_pack_platform.service import create_policy_pack_group, resolve_group_member_ids

            engineer = User(email=f"engineer-{uuid4().hex[:10]}@example.test", hashed_password="test", full_name="Engineer")
            db.add(engineer)
            db.flush()
            db.add(
                UserRegistry(
                    tenant_id=tenant.id,
                    user_id=engineer.id,
                    display_name="Engineer",
                    email=engineer.email,
                    department="Engineering",
                    role="developer",
                    status="active",
                )
            )
            static = create_policy_pack_group(
                db,
                tenant_id=tenant.id,
                group_key="coding-users",
                name="Coding users",
                group_type="static",
                membership_rule={},
                member_user_ids=[owner.id],
                nested_group_ids=[],
                actor_ref=f"user:{owner.id}",
            )
            dynamic = create_policy_pack_group(
                db,
                tenant_id=tenant.id,
                group_key="engineering",
                name="Engineering",
                group_type="dynamic_attribute",
                membership_rule={"field": "department", "operator": "equals", "value": "engineering"},
                member_user_ids=[],
                nested_group_ids=[static.id],
                actor_ref=f"user:{owner.id}",
            )
            # The explicit cycle must not recurse forever or expand membership beyond the visited set.
            static.nested_group_ids = [dynamic.id]
            members = resolve_group_member_ids(db, tenant_id=tenant.id, group_id=dynamic.id)
            assert members == sorted([engineer.id, owner.id])
    finally:
        engine.dispose()


def test_effective_policy_safety_precedence_and_expired_exception(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "pack-effective.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner, approver = _tenant_with_entitlement(db, label="Pack Effective")
            safety = _definition(db, template_decision="block", stable_id="vendor:safety")
            permissive = _definition(db, template_decision="allow", stable_id="vendor:team")
            from app.db.models.control_coverage import DeploymentSurface
            from app.services.policy_pack_platform.service import (
                apply_policy_pack,
                create_policy_pack_exception,
                resolve_effective_policy_explanation,
                simulate_policy_pack,
                transition_policy_pack_instance,
            )

            db.add(
                DeploymentSurface(
                    tenant_id=tenant.id,
                    source_kind="test",
                    source_id="browser-inline",
                    name="Verified browser control",
                    surface_type="browser",
                    deployment_family="browser",
                    status="active",
                    capability_profile={},
                    control_capability="inline",
                    evidence_capability="complete",
                    containment_capability="direct",
                    bypass_detection_capability="supported",
                    health_status="healthy",
                    health_reason="accepted",
                )
            )
            db.flush()
            events = [{"actor_user_id": owner.id, "source_surface": "browser", "data_classification": "restricted", "destination_class": "external"}]
            safety_instance = apply_policy_pack(
                db, tenant_id=tenant.id, definition_id=safety.id, assignments=[{"organization": "all", "non_overridable": True}],
                customer_parameters={}, local_overrides={}, disabled_template_ids=[], added_customer_templates=[], requested_state="DRAFT", requested_by_ref=f"user:{owner.id}",
            ).instance
            team_instance = apply_policy_pack(
                db, tenant_id=tenant.id, definition_id=permissive.id, assignments=[{"user": owner.id}],
                customer_parameters={}, local_overrides={}, disabled_template_ids=[], added_customer_templates=[], requested_state="DRAFT", requested_by_ref=f"user:{owner.id}",
            ).instance
            for instance in (safety_instance, team_instance):
                transition_policy_pack_instance(db, tenant_id=tenant.id, instance_id=instance.id, target_state="MONITORING", actor_ref=f"user:{owner.id}")
                simulate_policy_pack(db, tenant_id=tenant.id, instance_id=instance.id, historical_events=events)
                transition_policy_pack_instance(
                    db, tenant_id=tenant.id, instance_id=instance.id, target_state="ENFORCED",
                    actor_ref=f"user:{owner.id}", approver_ref=f"user:{approver.id}",
                )
            create_policy_pack_exception(
                db,
                tenant_id=tenant.id,
                instance_id=team_instance.id,
                scope={"condition_tree": {"field": "actor_user_id", "operator": "equals", "value": owner.id}},
                reason="Expired test exception",
                requested_by_ref=f"user:{owner.id}",
                approved_by_ref=f"user:{approver.id}",
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
            explanation = resolve_effective_policy_explanation(db, tenant_id=tenant.id, context=events[0])
            assert explanation["final"]["decision"] == "block"
            assert explanation["final"]["source_pack"] == "vendor:safety"
            assert explanation["final"]["exception"] is None
            from app.services.policy_scope_service import resolve_scoped_policy_decision

            live_decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context=events[0],
            )
            assert live_decision.decision == "block"
            assert live_decision.policy_version_id == safety_instance.effective_policy_version_id
    finally:
        engine.dispose()


def test_three_way_update_preserves_customer_overrides_bulk_assignment_and_tenant_boundaries(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "pack-update.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner, _approver = _tenant_with_entitlement(db, label="Pack Update")
            other, _other_owner, _other_approver = _tenant_with_entitlement(db, label="Pack Other")
            first = _definition(db, template_decision="warn", stable_id="vendor:update")
            from app.services.policy_pack_platform.service import (
                apply_policy_pack,
                bulk_assign_policy_pack_instance,
                compare_policy_pack_update,
                create_policy_pack_definition,
            )

            instance = apply_policy_pack(
                db,
                tenant_id=tenant.id,
                definition_id=first.id,
                assignments=[{"application": "cursor"}],
                customer_parameters={},
                local_overrides={"restricted-external-transfer": {"decision": "require_approval"}},
                disabled_template_ids=[],
                added_customer_templates=[],
                requested_state="DRAFT",
                requested_by_ref=f"user:{owner.id}",
            ).instance
            second = create_policy_pack_definition(
                db,
                publisher_tenant_id=None,
                stable_pack_id="vendor:update",
                version="2.0.0",
                name="Sensitive data boundary",
                description="Updated defaults.",
                vertical="universal",
                department_persona="security",
                pack_family="data_handling",
                maturity_status="verified",
                package_entitlement="secure",
                templates=[
                    {
                        "template_id": "restricted-external-transfer",
                        "title": "Restricted external transfer",
                        "reason": "Updated vendor default.",
                        "condition_tree": {"field": "data_classification", "operator": "equals", "value": "restricted"},
                        "decision": "block",
                    },
                    {
                        "template_id": "unknown-tool",
                        "title": "Unknown tool",
                        "reason": "New vendor template.",
                        "condition_tree": {"field": "tool_trust_state", "operator": "equals", "value": "unknown"},
                        "decision": "require_approval",
                    },
                ],
                owner_publisher="hawk",
            )
            comparison = compare_policy_pack_update(
                db, tenant_id=tenant.id, instance_id=instance.id, new_definition_id=second.id
            )
            assert comparison["requires_resimulation"] is True
            assert comparison["customer_overrides_unchanged"] == ["restricted-external-transfer"]
            assert comparison["new_templates"] == ["unknown-tool"]
            first_bulk = bulk_assign_policy_pack_instance(
                db, tenant_id=tenant.id, instance_id=instance.id, assignments=[{"application": "cursor"}, {"provider": "openai"}], actor_ref=f"user:{owner.id}"
            )
            second_bulk = bulk_assign_policy_pack_instance(
                db, tenant_id=tenant.id, instance_id=instance.id, assignments=[{"provider": "openai"}, {"application": "cursor"}], actor_ref=f"user:{owner.id}"
            )
            assert first_bulk["created"] == 1
            assert second_bulk["created"] == 0
            with pytest.raises(ValueError, match="not_found"):
                bulk_assign_policy_pack_instance(
                    db, tenant_id=other.id, instance_id=instance.id, assignments=[{"application": "cursor"}], actor_ref="user:foreign"
                )
    finally:
        engine.dispose()


def test_policy_pack_platform_api_is_feature_and_role_guarded(tmp_path, monkeypatch) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.routers.policy_pack_platform import router
    from app.core.config import settings
    from app.core.tenant import require_tenant
    from app.db.session import Base, get_db

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'pack-api.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    db = sessions()
    try:
        tenant, owner, _approver = _tenant_with_entitlement(db, label="Pack API")
        definition = _definition(db, template_decision="warn", stable_id="vendor:api")
        definition.framework_mappings = {
            "references": [{"id": "rbi-free-ai-2025", "title": "RBI FREE-AI", "status": "CURRENT_REFERENCE"}],
            "disclaimer": "Informative mapping only.",
        }
        db.commit()
        current = {"ctx": SimpleNamespace(tenant=tenant, user=owner, role="viewer")}
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[require_tenant] = lambda: current["ctx"]
        client = TestClient(app)
        monkeypatch.setattr(settings, "policy_pack_platform_enabled", True, raising=False)
        monkeypatch.setattr(settings, "policy_pack_platform_rollout", f'{{"{tenant.id}": true}}', raising=False)
        assert client.get("/policy-pack-platform/catalog").status_code == 200
        atlas = client.get("/policy-pack-platform/framework-atlas")
        assert atlas.status_code == 200, atlas.text
        rbi_items = [
            item
            for item in atlas.json()["items"]
            if item["framework_id"] == "rbi-free-ai-2025"
        ]
        assert rbi_items
        assert "vendor:api" in rbi_items[0]["policy_pack_stable_ids"]
        payload = {"assignments": [{"organization": "all"}], "requested_state": "DRAFT"}
        assert client.post(f"/policy-pack-platform/definitions/{definition.id}/apply", json=payload).status_code == 403
        current["ctx"] = SimpleNamespace(tenant=tenant, user=owner, role="operator")
        applied = client.post(f"/policy-pack-platform/definitions/{definition.id}/apply", json=payload)
        assert applied.status_code == 201, applied.text
        app.dependency_overrides.clear()
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
