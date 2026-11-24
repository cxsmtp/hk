"""Focused acceptance for the data-only vertical Policy Pack library."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def _database(tmp_path, name: str):
    from app.db import models as _models  # noqa: F401
    from app.db.session import Base

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / name}")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def _tenant_with_entitlement(db):
    from app.db.models.policy_pack_platform import PolicyPackPlatformEntitlement
    from app.db.models.tenant import Tenant
    from app.db.models.user import User, UserTenantRole

    tenant = Tenant(name="Vertical library", slug=f"vertical-library-{uuid4().hex[:8]}", is_active=True)
    owner = User(email=f"owner-{uuid4().hex[:10]}@example.test", hashed_password="test", full_name="Owner")
    db.add_all([tenant, owner])
    db.flush()
    db.add_all(
        [
            UserTenantRole(tenant_id=tenant.id, user_id=owner.id, role="owner"),
            PolicyPackPlatformEntitlement(tenant_id=tenant.id, package_tier="enterprise", enabled=True),
        ]
    )
    db.flush()
    return tenant, owner


def test_vendor_catalog_covers_every_requested_vertical_with_unique_stable_ids() -> None:
    from app.services.policy_pack_platform.vendor_catalog import vendor_policy_pack_specs

    specs = vendor_policy_pack_specs()
    stable_ids = [spec["stable_pack_id"] for spec in specs]
    assert len(stable_ids) == len(set(stable_ids))
    assert {"universal", "bfsi", "insurance", "telecom", "payments", "real_estate"} <= {spec["vertical"] for spec in specs}
    assert {
        "universal": 12,
        "india": 3,
        "bfsi": 15,
        "insurance": 15,
        "telecom": 16,
        "payments": 15,
        "real_estate": 17,
    } == {vertical: sum(spec["vertical"] == vertical for spec in specs) for vertical in {spec["vertical"] for spec in specs}}
    assert {
        "trinya:bfsi-retail",
        "trinya:insurance-underwriting",
        "trinya:telecom-network-engineering",
        "trinya:payments-merchant-onboarding",
        "trinya:real-estate-sales",
        "trinya:india-ai-governance",
        "trinya:india-rbi-free-ai",
        "trinya:india-sebi-ai-governance",
        "trinya:agentic-ai-governance",
    } <= set(stable_ids)
    assert {"uai-001", "uai-018"} <= {template["template_id"] for spec in specs for template in spec["templates"]}
    assert all(spec["framework_mappings"].get("disclaimer") for spec in specs)


def test_catalog_seeds_typed_templates_and_rejects_unknown_reference_status(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-catalog.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, _owner = _tenant_with_entitlement(db)
            from app.db.models.policy_pack_platform import PolicyPackDefinition, PolicyPackTemplate
            from app.services.policy_pack_platform.service import (
                PolicyPackPlatformError,
                create_policy_pack_definition,
                ensure_builtin_policy_pack_catalog,
                list_policy_pack_definitions,
            )

            ensure_builtin_policy_pack_catalog(db)
            definitions = list_policy_pack_definitions(db, tenant_id=tenant.id)
            assert len(definitions) >= 80
            assert {row.vertical for row in definitions} >= {"universal", "india", "bfsi", "insurance", "telecom", "payments", "real_estate"}
            assert db.scalar(select(PolicyPackTemplate).where(PolicyPackTemplate.template_id == "uai-017")) is not None
            assert db.scalar(select(PolicyPackDefinition).where(PolicyPackDefinition.stable_pack_id == "trinya:bfsi-retail")) is not None

            with pytest.raises(PolicyPackPlatformError, match="reference_mapping_status_invalid"):
                create_policy_pack_definition(
                    db,
                    publisher_tenant_id=None,
                    stable_pack_id="trinya:invalid-reference-status",
                    version="1.0.0",
                    name="Invalid reference status",
                    description="Should not persist.",
                    vertical="universal",
                    department_persona="all",
                    pack_family="test",
                    maturity_status="draft",
                    package_entitlement="secure",
                    framework_mappings={"references": [{"id": "example", "title": "Example", "status": "not-a-status"}]},
                    templates=[
                        {
                            "template_id": "blocked-test",
                            "title": "Blocked test",
                            "reason": "Only typed mappings are accepted.",
                            "condition_tree": {"field": "action_class", "operator": "equals", "value": "test"},
                            "decision": "block",
                            "required_fields": ["action_class"],
                            "applicable_surfaces": ["runtime"],
                        }
                    ],
                    supported_deployment_surfaces=["runtime"],
                )
    finally:
        engine.dispose()


def test_india_and_agentic_governance_framework_overlays_are_actionable_without_compliance_claims() -> None:
    from app.services.policy_pack_platform.vendor_catalog import INFORMATIVE_MAPPING_DISCLAIMER, vendor_policy_pack_specs

    specs = {spec["stable_pack_id"]: spec for spec in vendor_policy_pack_specs()}
    expected = {
        "trinya:india-ai-governance": {
            "meity-india-ai-governance-guidelines-2025",
            "dpdp-act-2023",
            "dpdp-rules-2025",
        },
        "trinya:india-rbi-free-ai": {
            "rbi-free-ai-2025",
            "rbi-it-governance-risk-controls-assurance-2023",
            "rbi-it-outsourcing-2023",
        },
        "trinya:india-sebi-ai-governance": {
            "sebi-ai-ml-reporting-2019",
            "sebi-cscrf-2024",
        },
        "trinya:agentic-ai-governance": {
            "imda-agentic-ai-governance-framework-2026",
            "imda-generative-ai-governance-framework-2024",
            "mitre-atlas",
        },
    }
    for stable_pack_id, reference_ids in expected.items():
        pack = specs[stable_pack_id]
        assert pack["pack_family"] == "framework_overlay"
        assert pack["default_rollout"] == "MONITORING"
        assert pack["simulation_required"] is True
        assert pack["framework_mappings"]["disclaimer"] == INFORMATIVE_MAPPING_DISCLAIMER
        assert reference_ids <= {reference["id"] for reference in pack["framework_mappings"]["references"]}
        assert all("certification" not in template["human_explanation"].lower() for template in pack["templates"])
        assert all(template["decision"] != "allow" for template in pack["templates"])


def test_framework_atlas_groups_references_to_actionable_policy_pack_overlays(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "framework-atlas.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, _owner = _tenant_with_entitlement(db)
            from app.services.policy_pack_platform.service import ensure_builtin_policy_pack_catalog, framework_atlas

            ensure_builtin_policy_pack_catalog(db)
            atlas = framework_atlas(db, tenant_id=tenant.id)

            assert atlas["disclaimer"]
            assert atlas["count"] >= 4
            cards = {item["framework_id"]: item for item in atlas["items"]}
            assert "rbi-free-ai-2025" in cards
            assert "meity-india-ai-governance-guidelines-2025" in cards
            assert "imda-agentic-ai-governance-framework-2026" in cards
            assert "trinya:india-rbi-free-ai" in cards["rbi-free-ai-2025"]["policy_pack_stable_ids"]
            assert "trinya:india-ai-governance" in cards["meity-india-ai-governance-guidelines-2025"]["policy_pack_stable_ids"]
            assert "trinya:agentic-ai-governance" in cards["imda-agentic-ai-governance-framework-2026"]["policy_pack_stable_ids"]
            assert cards["rbi-free-ai-2025"]["recommended_action"] == "Preview pack, simulate, then apply in Draft or Monitor."
            assert cards["rbi-free-ai-2025"]["claim_boundary"] == "Informative mapping only; not a compliance certification."
            rbi = cards["rbi-free-ai-2025"]
            assert rbi["jurisdiction"] == "India"
            assert rbi["policy_recommendations"]
            assert rbi["mapped_control_families"]
            assert rbi["control_coverage"]["href"].startswith("/deployment/surface-coverage")
            assert rbi["simulation_links"][0]["href"].startswith("/simulations")
            assert "Decision receipts and execution evidence" in rbi["evidence_requirements"]
            assert "mapped controls" in rbi["compliance_note"].lower()
            assert "certified compliant" in rbi["compliance_note"].lower()
            assert cards["eu-ai-act"]["title"] == "EU AI Act"
            assert cards["mitre-atlas"]["framework_family"] == "Threat and adversarial AI"
    finally:
        engine.dispose()


def test_operator_provisioning_enables_only_requested_tenant_and_seeds_vendor_catalog(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-provisioning.sqlite3")
    try:
        with sessions.begin() as db:
            from app.db.models.policy_pack_platform import PolicyPackPlatformEntitlement
            from app.db.models.tenant import Tenant
            from app.services.policy_pack_platform.service import provision_policy_pack_entitlement

            first = Tenant(name="First tenant", slug=f"first-{uuid4().hex[:8]}", is_active=True)
            second = Tenant(name="Second tenant", slug=f"second-{uuid4().hex[:8]}", is_active=True)
            db.add_all([first, second])
            db.flush()

            entitlement, catalog_count = provision_policy_pack_entitlement(
                db,
                tenant_id=first.id,
                package_tier="secure",
            )

            assert entitlement.tenant_id == first.id
            assert entitlement.enabled is True
            assert entitlement.package_tier == "secure"
            assert catalog_count >= 80
            assert db.scalar(
                select(PolicyPackPlatformEntitlement).where(
                    PolicyPackPlatformEntitlement.tenant_id == second.id
                )
            ) is None
    finally:
        engine.dispose()


def test_vertical_pack_compiles_inherited_and_local_templates_with_source_lineage(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-inheritance.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner = _tenant_with_entitlement(db)
            from app.db.models.policy_pack_platform import PolicyPackDefinition
            from app.services.policy_pack_platform.service import apply_policy_pack, ensure_builtin_policy_pack_catalog

            ensure_builtin_policy_pack_catalog(db)
            retail = db.scalar(select(PolicyPackDefinition).where(PolicyPackDefinition.stable_pack_id == "trinya:bfsi-retail"))
            assert retail is not None
            result = apply_policy_pack(
                db,
                tenant_id=tenant.id,
                definition_id=retail.id,
                assignments=[{"organization": "all", "deployment_surface": ["runtime"]}],
                customer_parameters={},
                local_overrides={},
                disabled_template_ids=[],
                added_customer_templates=[],
                requested_state="DRAFT",
                requested_by_ref=f"user:{owner.id}",
            )
            rules = result.policy_version.scope["scoped_rules"]
            template_lineage = result.policy_version.contract_json["policy_pack_platform"]["template_lineage"]
            assert any(rule["metadata"]["policy_pack_platform"]["template_id"] == "uai-001" for rule in rules)
            assert any(item["source_pack"] == "trinya:universal-baseline" for item in template_lineage)
            assert any(item["source_pack"] == "trinya:bfsi-retail" for item in template_lineage)
            assert result.instance.lineage["definition_lineage"][0]["stable_pack_id"] == "trinya:universal-baseline"
            assert result.instance.lineage["definition_lineage"][-1]["stable_pack_id"] == "trinya:bfsi-retail"
    finally:
        engine.dispose()


def test_inherited_template_customization_is_tenant_scoped_and_no_seeded_high_impact_rule_allows(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-customization.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner = _tenant_with_entitlement(db)
            from app.db.models.policy_pack_platform import PolicyPackDefinition
            from app.services.policy_pack_platform.service import apply_policy_pack, ensure_builtin_policy_pack_catalog

            ensure_builtin_policy_pack_catalog(db)
            retail = db.scalar(select(PolicyPackDefinition).where(PolicyPackDefinition.stable_pack_id == "trinya:bfsi-retail"))
            assert retail is not None
            result = apply_policy_pack(
                db,
                tenant_id=tenant.id,
                definition_id=retail.id,
                assignments=[{"organization": "all"}],
                customer_parameters={},
                local_overrides={"uai-001": {"decision": "warn"}},
                disabled_template_ids=["uai-017"],
                added_customer_templates=[],
                requested_state="DRAFT",
                requested_by_ref=f"user:{owner.id}",
            )
            rules = result.policy_version.scope["scoped_rules"]
            assert not any(rule["metadata"]["policy_pack_platform"]["template_id"] == "uai-017" for rule in rules)
            overridden = next(rule for rule in rules if rule["metadata"]["policy_pack_platform"]["template_id"] == "uai-001")
            assert overridden["effect"]["decision"] == "warn"
            assert overridden["metadata"]["policy_pack_platform"]["customer_override"] is True
    finally:
        engine.dispose()


def test_typed_customer_parameters_bind_only_declared_catalog_condition_values(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-parameters.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner = _tenant_with_entitlement(db)
            from app.db.models.policy_pack_platform import PolicyPackDefinition
            from app.services.policy_pack_platform.service import (
                PolicyPackPlatformError,
                apply_policy_pack,
                ensure_builtin_policy_pack_catalog,
            )

            ensure_builtin_policy_pack_catalog(db)
            retail = db.scalar(select(PolicyPackDefinition).where(PolicyPackDefinition.stable_pack_id == "trinya:bfsi-retail"))
            assert retail is not None
            result = apply_policy_pack(
                db,
                tenant_id=tenant.id,
                definition_id=retail.id,
                assignments=[{"organization": "all"}],
                customer_parameters={"restricted_account_classes": ["partner"]},
                local_overrides={},
                disabled_template_ids=[],
                added_customer_templates=[],
                requested_state="DRAFT",
                requested_by_ref=f"user:{owner.id}",
            )
            uai_rule = next(rule for rule in result.policy_version.scope["scoped_rules"] if rule["metadata"]["policy_pack_platform"]["template_id"] == "uai-001")
            atoms = []

            def collect(tree):
                if "field" in tree:
                    atoms.append(tree)
                for child in tree.get("all", []) + tree.get("any", []):
                    collect(child)
                if isinstance(tree.get("not"), dict):
                    collect(tree["not"])

            collect(uai_rule["condition_tree"])
            assert next(atom for atom in atoms if atom["field"] == "account_class")["value"] == ["partner"]
            with pytest.raises(PolicyPackPlatformError, match="policy_pack_parameter_not_allowed"):
                apply_policy_pack(
                    db,
                    tenant_id=tenant.id,
                    definition_id=retail.id,
                    assignments=[{"organization": "all"}],
                    customer_parameters={"unexpected_parameter": "value"},
                    local_overrides={},
                    disabled_template_ids=[],
                    added_customer_templates=[],
                    requested_state="DRAFT",
                    requested_by_ref=f"user:{owner.id}",
                )
    finally:
        engine.dispose()


def test_parent_publication_does_not_silently_change_an_applied_customer_instance(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-parent-freeze.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner = _tenant_with_entitlement(db)
            from app.db.models.policy_pack_platform import PolicyPackDefinition
            from app.services.policy_pack_platform.service import (
                apply_policy_pack,
                create_policy_pack_definition,
                ensure_builtin_policy_pack_catalog,
                transition_policy_pack_instance,
            )
            from app.services.policy_pack_platform.vendor_catalog import vendor_policy_pack_specs

            ensure_builtin_policy_pack_catalog(db)
            retail = db.scalar(select(PolicyPackDefinition).where(PolicyPackDefinition.stable_pack_id == "trinya:bfsi-retail"))
            assert retail is not None
            applied = apply_policy_pack(
                db,
                tenant_id=tenant.id,
                definition_id=retail.id,
                assignments=[{"organization": "all"}],
                customer_parameters={},
                local_overrides={},
                disabled_template_ids=[],
                added_customer_templates=[],
                requested_state="DRAFT",
                requested_by_ref=f"user:{owner.id}",
            )
            prior_lineage = list(applied.instance.lineage["definition_lineage"])
            baseline = next(spec for spec in vendor_policy_pack_specs() if spec["stable_pack_id"] == "trinya:universal-baseline")
            baseline["version"] = "1.0.1"
            create_policy_pack_definition(db, **baseline)

            transitioned = transition_policy_pack_instance(
                db,
                tenant_id=tenant.id,
                instance_id=applied.instance.id,
                target_state="MONITORING",
                actor_ref=f"user:{owner.id}",
            )
            assert transitioned.lineage["definition_lineage"] == prior_lineage
            assert next(item for item in prior_lineage if item["stable_pack_id"] == "trinya:universal-baseline")["version"] == "1.0.0"
    finally:
        engine.dispose()


def test_inheritance_cycles_are_rejected_before_customer_runtime_compilation(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-inheritance-cycle.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner = _tenant_with_entitlement(db)
            from app.services.policy_pack_platform.service import apply_policy_pack, create_policy_pack_definition

            first = create_policy_pack_definition(
                db,
                publisher_tenant_id=None,
                stable_pack_id="vendor:cycle-first",
                version="1.0.0",
                name="Cycle first",
                description="Invalid inherited graph fixture.",
                vertical="universal",
                department_persona="all",
                pack_family="test",
                maturity_status="draft",
                package_entitlement="secure",
                templates=[],
                inherited_pack_refs=["vendor:cycle-second"],
                supported_deployment_surfaces=["runtime"],
            )
            create_policy_pack_definition(
                db,
                publisher_tenant_id=None,
                stable_pack_id="vendor:cycle-second",
                version="1.0.0",
                name="Cycle second",
                description="Invalid inherited graph fixture.",
                vertical="universal",
                department_persona="all",
                pack_family="test",
                maturity_status="draft",
                package_entitlement="secure",
                templates=[],
                inherited_pack_refs=["vendor:cycle-first"],
                supported_deployment_surfaces=["runtime"],
            )
            with pytest.raises(ValueError, match="policy_pack_inheritance_cycle"):
                apply_policy_pack(
                    db,
                    tenant_id=tenant.id,
                    definition_id=first.id,
                    assignments=[{"organization": "all"}],
                    customer_parameters={},
                    local_overrides={},
                    disabled_template_ids=[],
                    added_customer_templates=[],
                    requested_state="DRAFT",
                    requested_by_ref=f"user:{owner.id}",
                )
    finally:
        engine.dispose()


def test_all_seeded_templates_compile_through_existing_deterministic_validator(tmp_path) -> None:
    engine, sessions = _database(tmp_path, "vertical-validation.sqlite3")
    try:
        with sessions.begin() as db:
            tenant, owner = _tenant_with_entitlement(db)
            from app.db.models.policy_pack_platform import PolicyPackTemplate
            from app.services.policy_pack_platform.service import apply_policy_pack, ensure_builtin_policy_pack_catalog, list_policy_pack_definitions

            ensure_builtin_policy_pack_catalog(db)
            definitions = list_policy_pack_definitions(db, tenant_id=tenant.id)
            for definition in definitions:
                assert all(template.decision != "allow" for template in db.scalars(select(PolicyPackTemplate).where(PolicyPackTemplate.definition_id == definition.id)).all())
                result = apply_policy_pack(
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
                assert result.policy_version.scope["scoped_rules"]
                assert result.policy_version.contract_json["profile"] == "policy_pack_platform"
    finally:
        engine.dispose()
