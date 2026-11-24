from __future__ import annotations

import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def test_authoritative_generic_fallback_evaluates_once_executes_once_and_persists_evidence(
    tmp_path, monkeypatch
) -> None:
    """Exercise the configured server pre-authorization path end to end."""
    from app.core.config import settings
    from app.core.control_engine import authorization as authorization_module
    from app.db.models.action_integrity import (
        ExecutionComparisonV2,
        ExecutionPermitAttemptV2,
        ExecutionPermitV2,
        ExecutionReceiptV2Extension,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.db.models.evidence import ExecutionReceipt
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import (
        install_generic_seam_authority,
        invoke_final_seam,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.action_integrity.stored_authority import (
        append_profile_selection_v1,
        issue_domain_semantic_profile_v1,
    )
    from app.services.native_control.integrity import integration_configuration_fingerprint
    from test_native_control_selection_persistence import NOW, _add_point, _capabilities

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'generic-fallback.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Generic fallback", slug="generic-fallback", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all(
                [
                    TenantPolicyEpoch(tenant_id=tenant_id, epoch=1),
                    TenantActionIntegrityRollout(
                        tenant_id=tenant_id,
                        mode="AUTHORITATIVE",
                        policy_epoch=1,
                    ),
                ]
            )

        provider = LocalSigningKeyProvider(development=True)
        for purpose, key_id, secret in (
            ("domain_profile_signing", "profile", b"p" * 32),
            ("domain_profile_selection_signing", "selection", b"s" * 32),
            ("decision_receipt_signing", "decision", b"d" * 32),
            ("execution_permit_signing", "permit", b"e" * 32),
            ("execution_receipt_signing", "execution-receipt", b"r" * 32),
            ("execution_comparison_signing", "execution-comparison", b"c" * 32),
        ):
            provider.add_key(purpose=purpose, tenant_id=tenant_id, key_id=key_id, secret=secret)

        with session_local.begin() as db:
            point = _add_point(
                db,
                tenant_id,
                name="phase5-runtime-openai",
                method="native_hook",
                capabilities=_capabilities(execution="independent_bound"),
            )
            point.policy_version = "phase5:persisted-rollout"
            point.configuration_fingerprint = integration_configuration_fingerprint(point)
            point.expected_configuration_fingerprint = point.configuration_fingerprint
            profile = issue_domain_semantic_profile_v1(
                db,
                provider=provider,
                tenant_id=tenant_id,
                profile_id="profile:generic",
                version="1",
                status="reviewed",
                content={"scope": "generic-runtime"},
                issued_at=NOW,
                effective_at=NOW,
                expires_at=NOW.replace(hour=9),
            )
            append_profile_selection_v1(
                db,
                provider=provider,
                tenant_id=tenant_id,
                profile=profile,
                policy_epoch=1,
                selected_by_principal_ref="user:owner",
                reason_code="initial",
                issued_at=NOW,
                effective_at=NOW,
                expires_at=NOW.replace(hour=8, minute=30),
            )

        monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
        monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
        monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
        monkeypatch.setattr(
            settings,
            "authorization_kernel_v2_enforce_rollout",
            json.dumps({tenant_id: ["runtime_control"]}),
        )
        monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
        monkeypatch.setattr(settings, "receipt_signing_active_key_id", "phase5-receipt")
        monkeypatch.setattr(
            settings,
            "receipt_signing_keys_json",
            '{"phase5-receipt":"phase5-receipt-material-000001-0123456789"}',
        )
        monkeypatch.setattr(settings, "native_control_framework", True)
        monkeypatch.setattr(settings, "trusted_control_selector", True)
        monkeypatch.setattr(settings, "native_control_enforce", True)
        monkeypatch.setattr(settings, "native_control_openai", True)
        monkeypatch.setattr(
            settings,
            "native_control_route_bindings_json",
            json.dumps(
                {
                    tenant_id: {
                        "runtime_control": [
                            {
                                "integration_instance_ids": [point.id],
                                "provider": "openai",
                                "provider_version": "1.5.0",
                                "adapter_version": "1.0.0",
                                "product": "direct_api",
                            }
                        ]
                    }
                }
            ),
        )

        evaluations = 0
        original_evaluate = authorization_module.apply_trusted_pre_action_rollout

        def count_evaluations(*args, **kwargs):
            nonlocal evaluations
            evaluations += 1
            return original_evaluate(*args, **kwargs)

        monkeypatch.setattr(
            authorization_module,
            "apply_trusted_pre_action_rollout",
            count_evaluations,
        )

        with session_local() as db:
            db.info["phase5_signing_provider"] = provider
            handle = install_generic_seam_authority(
                db,
                tenant_id=tenant_id,
                seam_ref="agui.actual_executor",
                action_id="generic-runtime-action",
                chain_id="generic-runtime-chain",
                actor_principal="user:owner",
                executing_principal="service:agui",
                operation="tool_execution",
                tool_or_service_ref="openai",
                parameter_hash="a" * 64,
                target_ref="resource:generic-runtime",
                now=lambda: NOW,
            )
            assert handle is not None and handle.permit_id and handle.attempt_id
            callback_calls: list[str] = []
            assert invoke_final_seam(
                db,
                seam_ref="agui.actual_executor",
                executor=lambda: callback_calls.append("called") or {"ok": True},
            ) == {"ok": True}
            assert callback_calls == ["called"]
            permit_id = handle.permit_id

        assert evaluations == 1
        with session_local() as db:
            permit = db.get(ExecutionPermitV2, permit_id)
            assert permit is not None and permit.state == "CONSUMED"
            attempt = db.scalar(
                select(ExecutionPermitAttemptV2).where(
                    ExecutionPermitAttemptV2.tenant_id == tenant_id,
                    ExecutionPermitAttemptV2.attempt_id == permit.attempt_id,
                )
            )
            assert attempt is not None
            assert attempt.decision_receipt_id == permit.decision_receipt_id
            assert attempt.execution_permit_id == permit.permit_id
            execution_receipt = db.scalar(
                select(ExecutionReceipt).where(
                    ExecutionReceipt.tenant_id == tenant_id,
                    ExecutionReceipt.execution_attempt_id == permit.attempt_id,
                )
            )
            assert execution_receipt is not None
            assert db.get(ExecutionReceiptV2Extension, execution_receipt.receipt_id) is not None
            assert db.scalar(
                select(ExecutionComparisonV2).where(
                    ExecutionComparisonV2.tenant_id == tenant_id,
                    ExecutionComparisonV2.attempt_id == permit.attempt_id,
                )
            ) is not None
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
