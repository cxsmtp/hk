from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.core.control_engine.authorization import AuthorizationRequest, AuthorizationResponse
from app.db.session import Base, get_db
from app.db.models.evidence import DecisionReceipt, EvidenceNode, ExecutionReceipt
from app.db.models.finding import Finding
from app.db.models.github_repository_access import (
    GitHubRepository,
    GitHubRepositoryRuntimeBinding,
    GitHubSourceOrganization,
)
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.policy_pack_platform import (
    PolicyPackAssignment,
    PolicyPackDefinition,
    PolicyPackInstance,
)
from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_resolution import DiscoveryResolutionGraphNode
from app.db.models.evidence_resolution import DiscoveryAIEcosystem, DiscoveryEcosystemMembership
from app.db.models.discovery_verification import DiscoveryVerificationAssertion
from app.db.models.capability_inference import DiscoveryCapabilityGenome
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlSelection,
    NativeWorkloadCredential,
)
from app.main import app
from app.api.routers import native_controls as native_controls_router
from app.services.native_control.contracts import (
    HealthState,
    IntegrationMode,
    IntegrationState,
    VerificationStatus,
)
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.claude_adapter import ClaudeAdapter
from app.services.native_control.envelope import TrustedControlEnvelope, canonical_envelope_body
from app.services.native_control.metrics import native_control_metrics
from app.services.native_control.service import IntegrationFacts, NativeValidationResult
from app.services.native_control.selection_service import select_and_persist_authorization
from app.services.policy_pack_platform.service import _normalize_assignment_targets


PASSWORD = "Password123!"


@pytest.fixture()
def native_api_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'native-control.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    for flag in (
        "native_control_framework",
        "native_control_adapter_framework",
        "native_control_reference_adapters",
        "control_capability_matrix",
        "trusted_control_selector",
        "native_control_monitor",
        "native_control_enforce",
        "native_control_openai",
        "native_control_qwen",
    ):
        monkeypatch.setitem(settings.__dict__, flag, True)

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
        Base.metadata.drop_all(engine)
        engine.dispose()


def _register(client: TestClient, email: str) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Native Control Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    tenant_id = body["tenants"][0]["id"]
    return tenant_id, {
        "Authorization": f"Bearer {body['access_token']}",
        "X-Tenant-ID": tenant_id,
    }


def test_adapter_catalog_includes_reference_fixtures_and_verified_claude(native_api_env) -> None:
    client, _session_factory = native_api_env
    _tenant_id, headers = _register(client, "native-adapter-catalog@example.com")

    response = client.get("/native-controls/adapters", headers=headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source"] == "hawk_shipped_registry"
    assert {row["maturity"] for row in body["items"]} == {
        "reference",
        "experimental",
        "production",
    }
    cursor = next(row for row in body["items"] if row["adapter_id"] == "cursor.cursor.command-hooks")
    assert cursor["verification_status"] == "experimental"
    assert cursor["provider_version_range"]["exact_verified_versions"] == [
        "2026.08.11-e8db854"
    ]
    assert cursor["production_eligible"] is False
    claude = next(row for row in body["items"] if row["provider_family"] == "anthropic")
    assert claude["product_family"] == "claude_code"
    assert claude["provider_version_range"]["minimum"] == "2.1.183"
    assert claude["provider_version_range"]["maximum"] == "2.1.183"
    assert claude["provider_version_range"]["exact_verified_versions"] == ["2.1.183"]
    assert claude["provider_version_range"]["compatible_versions_require_signed_runtime_validation"] is False
    surface_rows = {row["surface"]: row for row in claude["surface_coverage"]}
    assert surface_rows["code_desktop_local"]["control_method"] == "native_hook"
    assert surface_rows["desktop_chat"]["native_hook_capable"] is False
    assert surface_rows["desktop_chat"]["control_method"] == "mcp_gateway_and_endpoint"
    assert claude["production_eligible"] is True
    assert all(
        row["production_eligible"] is False
        for row in body["items"]
        if row["maturity"] == "reference"
    )


def test_adapter_catalog_includes_reviewed_gemini_evidence(native_api_env) -> None:
    client, _session_factory = native_api_env
    _tenant_id, headers = _register(client, "gemini-adapter-catalog@example.com")

    response = client.get("/native-controls/adapters", headers=headers)

    assert response.status_code == 200, response.text
    gemini = next(
        row
        for row in response.json()["items"]
        if row["adapter_id"] == "google.gemini-cli.command-hooks"
    )
    assert gemini["provider_family"] == "google"
    assert gemini["product_family"] == "gemini_cli"
    assert gemini["provider_version_range"]["exact_verified_versions"] == ["0.54.4", "0.55.1"]
    assert gemini["verification_status"] == "experimental"
    assert gemini["production_eligible"] is False


def test_integration_status_requires_real_contract_bound_acceptance_not_static_adapter_metadata(
    native_api_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory = native_api_env
    _tenant_id, headers = _register(client, "native-static-status@example.com")
    now = datetime.now(timezone.utc)

    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-static-status",
            "display_name": "Claude static status",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert created.status_code == 201, created.text

    with session_factory() as db:
        row = db.get(NativeControlIntegration, created.json()["id"])
        assert row is not None
        row.state = IntegrationState.ENFORCING.value
        row.mode = IntegrationMode.ENFORCE.value
        db.commit()

    now = datetime.now(timezone.utc)
    monkeypatch.setattr(
        native_controls_router,
        "_facts",
        lambda _db, _row: IntegrationFacts(
            state=IntegrationState.ENFORCING,
            mode=IntegrationMode.ENFORCE,
            profile_verification=VerificationStatus.VERIFIED,
            profile_active=True,
            health=HealthState.HEALTHY,
            validation=NativeValidationResult.PASSED,
            validated_at=now,
            validation_valid_until=now + timedelta(minutes=5),
            policy_fresh_until=now + timedelta(minutes=5),
            configuration_integrity_valid=True,
            provider_version_supported=True,
            adapter_version_supported=True,
            route_binding_current=True,
            enforcement_feature_active=True,
            active_workload_identity=True,
            callback_authenticated=True,
            evidence_flowing=True,
            measured_latency_ms=1,
        ),
    )

    status = client.get(
        f"/control-points/{created.json()['id']}", headers=headers
    )

    assert status.status_code == 200, status.text
    assert status.json()["authoritative"] is False


def test_admin_configure_rebinds_a_stale_profile_to_current_reviewed_manifest(
    native_api_env,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "native-profile-rebind@example.com")
    now = datetime.now(timezone.utc)
    claude = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-profile-rebind",
            "display_name": "Claude profile rebind",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert claude.status_code == 201, claude.text
    cursor = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "cursor",
            "product": "cursor",
            "method": "native_hook",
            "instance_key": "stale-unverified-profile",
            "display_name": "Stale profile fixture",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "0.0.0",
            "adapter_version": "1.0.0",
            "policy_version": "policy-stale",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert cursor.status_code == 201, cursor.text
    claude_id = claude.json()["id"]
    with session_factory() as db:
        claude_row = db.get(NativeControlIntegration, claude_id)
        cursor_row = db.get(NativeControlIntegration, cursor.json()["id"])
        assert claude_row is not None
        assert cursor_row is not None
        claude_row.capability_profile_id = cursor_row.capability_profile_id
        claude_row.state = "degraded"
        claude_row.mode = "monitor"
        claude_row.health_state = "degraded"
        db.commit()

    configured = client.post(
        f"/native-controls/integrations/{claude_id}/configure",
        headers=headers,
    )

    assert configured.status_code == 200, configured.text
    assert configured.json()["provider_version_compatible"] is True
    assert configured.json()["adapter_version_compatible"] is True
    with session_factory() as db:
        integration = db.get(NativeControlIntegration, claude_id)
        assert integration is not None
        profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
        assert profile is not None
        assert profile.provider == "anthropic"
        assert profile.product == "claude_code"
        assert profile.verification_status == "verified"
        assert profile.adapter_version == "1.2.0"
        assert profile.tested_min_version == "2.1.183"
        assert profile.tested_max_version == "2.1.183"


def test_openai_product_adapters_are_cataloged_independently(native_api_env) -> None:
    client, _session_factory = native_api_env
    _tenant_id, headers = _register(client, "openai-product-adapter-catalog@example.com")

    response = client.get("/native-controls/adapters", headers=headers)

    assert response.status_code == 200, response.text
    openai_items = {
        row["adapter_id"]: row
        for row in response.json()["items"]
        if row["provider_family"] == "openai"
    }
    assert {
        "openai.agents-sdk.control",
        "openai.codex.native-hooks",
        "openai.direct-api.control",
    } <= set(openai_items)
    assert openai_items["openai.agents-sdk.control"]["provider_version_range"][
        "exact_verified_versions"
    ] == ["0.20.0"]
    assert openai_items["openai.codex.native-hooks"]["production_eligible"] is True
    assert openai_items["openai.codex.native-hooks"]["provider_version_range"][
        "exact_verified_versions"
    ] == ["0.154.0"]
    assert openai_items["openai.direct-api.control"]["enforcement_methods_supported"] == [
        "gateway_inline",
        "api_intercept",
        "tool_loop_intercept",
    ]


def _integration_payload() -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "provider": "openai",
        "product": "direct_api",
        "method": "gateway_inline",
        "instance_key": "production-codex-gateway",
        "display_name": "Production Codex Gateway",
        "environment": "production",
        "deployment_family": "saas_api",
        "provider_version": "hawk-openai-compatible-v1",
        "adapter_version": "1.0.0",
        "policy_version": "policy-7",
        "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
        "degradation_mode": "fail_closed",
    }


def _key_pair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return key, public_pem


def _validation_proof(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    tenant_id: str,
    integration_id: str,
    validation_claims: dict[str, object] | None = None,
    credential_id: str = "workload-production-1",
    credential_epoch: int = 1,
) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    claims: dict[str, object] = {
            "validation_version": "native-control-validation/1.0",
            "safe_synthetic": True,
            "allow_behavior": True,
            "block_behavior": True,
            "evidence_callback": True,
            "post_execution_path": True,
    }
    claims.update(validation_claims or {})
    payload = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    values: dict[str, object] = {
        "event_id": f"validation-{uuid4()}",
        "integration_instance_id": integration_id,
        "tenant_binding": tenant_id,
        "provider": "openai",
        "product": "direct_api",
        "provider_event_id": f"probe-{uuid4()}",
        "provider_event_type": "hawk.validation",
        "provider_version": "hawk-openai-compatible-v1",
        "adapter_version": "1.0.0",
        "issued_at": now,
        "expires_at": now + timedelta(seconds=30),
        "nonce": f"nonce-{uuid4()}",
        "session_id": "validation-session",
        "chain_id": "validation-chain",
        "correlation_id": f"validation-{uuid4()}",
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "canonical_action_hash": None,
        "credential_id": credential_id,
        "credential_epoch": credential_epoch,
        "signature_algorithm": "ES256",
        "signature": "",
    }
    unsigned = TrustedControlEnvelope(**values)
    signature = private_key.sign(canonical_envelope_body(unsigned), ec.ECDSA(hashes.SHA256()))
    envelope = TrustedControlEnvelope(
        **{
            **values,
            "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        }
    )
    return {
        "envelope_base64": base64.b64encode(
            json.dumps(envelope.as_dict(), separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }


def _callback_proof(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    tenant_id: str,
    integration_id: str,
    event: dict[str, object],
    credential_id: str = "workload-production-1",
    credential_epoch: int = 1,
    provider: str = "openai",
    product: str = "direct_api",
    provider_version: str = "hawk-openai-compatible-v1",
    adapter_version: str = "1.0.0",
    provider_event_type: str = "before_tool",
    provider_event_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    # Test callbacks model the two mutually exclusive production schemas:
    # raw provider hook input, or the endpoint's bounded privacy-safe hash
    # envelope.  Never construct the ambiguous legacy hybrid.
    raw_shape_fields = {
        "tool_input",
        "parameters",
        "arguments",
        "cwd",
        "url",
        "path",
        "file_path",
        "tool_use_id",
        "event_type",
        "hook_event_name",
    }
    hash_material_fields = {
        "parameter_hash",
        "target_resource_hash",
        "destination_hash",
    }
    event = dict(event)
    if set(event).intersection(raw_shape_fields):
        for key in hash_material_fields:
            event.pop(key, None)
    elif set(event).intersection(hash_material_fields):
        event["callback_schema"] = "hawk-native-hash-envelope/v1"
        event.setdefault(
            "tool_fingerprint_id",
            hashlib.sha256(
                str(event.get("tool_name") or "unknown").encode("utf-8")
            ).hexdigest(),
        )
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    values: dict[str, object] = {
        "event_id": f"callback-{uuid4()}",
        "integration_instance_id": integration_id,
        "tenant_binding": tenant_id,
        "provider": provider,
        "product": product,
        "provider_event_id": provider_event_id or f"provider-{uuid4()}",
        "provider_event_type": provider_event_type,
        "provider_version": provider_version,
        "adapter_version": adapter_version,
        "issued_at": now,
        "expires_at": now + timedelta(seconds=30),
        "nonce": f"nonce-{uuid4()}",
        "session_id": "native-session",
        "chain_id": "native-chain",
        "correlation_id": correlation_id or f"native-{uuid4()}",
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "canonical_action_hash": None,
        "credential_id": credential_id,
        "credential_epoch": credential_epoch,
        "signature_algorithm": "ES256",
        "signature": "",
    }
    unsigned = TrustedControlEnvelope(**values)
    signature = private_key.sign(canonical_envelope_body(unsigned), ec.ECDSA(hashes.SHA256()))
    envelope = TrustedControlEnvelope(
        **{**values, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")}
    )
    return {
        "envelope_base64": base64.b64encode(
            json.dumps(envelope.as_dict(), separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }


def test_gemini_signed_callbacks_support_the_complete_reviewed_lifecycle(
    native_api_env,
) -> None:
    client, _session_factory = native_api_env
    tenant_id, headers = _register(client, "gemini-callback-lifecycle@example.com")
    now = datetime.now(timezone.utc)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "google",
            "product": "gemini_cli",
            "method": "native_hook",
            "instance_key": "gemini-cli-0-54-4-callbacks",
            "display_name": "Gemini CLI 0.54.4",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "0.54.4",
            "adapter_version": "1.0.0",
            "policy_version": "policy-gemini",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "monitor_only",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    lifecycle_semantics = {
        "before_agent": "pre_agent_turn_control",
        "after_agent": "provider_reported_agent_response",
        "before_tool_selection": "tool_filtering_only",
        "pre_compress": "advisory_compression_context",
        "notification": "provider_notification_observation",
    }
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "gemini-workload-1",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": list(lifecycle_semantics),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text

    for event_type, expected_semantics in lifecycle_semantics.items():
        callback = client.post(
            f"/native-controls/callbacks/{integration_id}",
            json=_callback_proof(
                private_key,
                tenant_id=tenant_id,
                integration_id=integration_id,
                credential_id="gemini-workload-1",
                provider="google",
                product="gemini_cli",
                provider_version="0.54.4",
                adapter_version="1.0.0",
                provider_event_type=event_type,
                event={
                    "action_type": "AGENT_TURN" if event_type == "before_agent" else "SESSION_CONTEXT",
                    "tool_name": event_type,
                    "parameter_hash": "p" * 64,
                    "target_resource": "local",
                    "target_resource_hash": "t" * 64,
                    "destination": "local",
                    "destination_hash": "d" * 64,
                    "persistent_side_effect": False,
                    "data_classifications": [],
                },
            ),
        )

        assert callback.status_code == 200, (event_type, callback.text)
        assert callback.json()["lifecycle_semantics"] == expected_semantics
        # An independently delivered provider-reported post event has no
        # exact Hawk pre-action material to reuse. It is evidence only and
        # must never fabricate an Allow decision.
        assert callback.json()["decision"] == (
            "allow" if event_type == "before_agent" else "unknown"
        )
        assert callback.json()["enforced"] is False


def test_claude_signed_pre_and_post_callbacks_persist_conservative_correlation_evidence(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = native_api_env
    monkeypatch.setitem(settings.__dict__, "decision_execution_receipts_enabled", True)
    monkeypatch.setitem(settings.__dict__, "receipt_signing_active_key_id", "test-receipt-key")
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_keys_json",
        json.dumps({"test-receipt-key": "r" * 32}),
    )
    tenant_id, headers = _register(client, "claude-correlation@example.com")
    authorized_requests: list[AuthorizationRequest] = []
    original_authorize = native_controls_router.authorize_ai_action

    def _counting_authorize(request: AuthorizationRequest):
        authorized_requests.append(request)
        return original_authorize(request)

    monkeypatch.setattr(native_controls_router, "authorize_ai_action", _counting_authorize)
    now = datetime.now(timezone.utc)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-code-2-1-183",
            "display_name": "Claude Code 2.1.183",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    monkeypatch.setitem(
        settings.__dict__,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "runtime_control": {
                        "integration_instance_ids": [integration_id],
                        "provider": "anthropic",
                        "product": "claude_code",
                        "provider_version": "2.1.183",
                        "adapter_version": "1.2.0",
                    }
                }
            }
        ),
    )
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-workload-1",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": [
                "before_tool",
                "before_model",
                "permission_request",
                "after_tool",
                "after_tool_failure",
                "config_change",
            ],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    # The retry proof needs a persisted, route-bound selection.  Lifecycle
    # validation itself is covered separately; this test isolates the callback
    # idempotency contract.
    with session_factory() as db:
        integration = db.get(NativeControlIntegration, integration_id)
        assert integration is not None
        integration.state = IntegrationState.MONITORING.value
        integration.mode = IntegrationMode.MONITOR.value
        db.commit()
    correlation_id = "c" * 64
    provider_event_id = "p" * 64
    common = {
        "action_type": "tool_execution",
        "tool_name": "Bash",
        "tool_class": "local_shell",
        "tool_fingerprint_id": "f" * 64,
        "parameter_hash": "a" * 64,
        "target_resource": "local",
        "target_resource_hash": "t" * 64,
        "destination": "local",
        "destination_hash": "d" * 64,
        "persistent_side_effect": False,
        "side_effect_class": "read_only_or_unknown",
        "prompt_hash": "h" * 64,
        "data_classifications": [],
        "provider_session_hash": "s" * 64,
        "provider_tool_use_hash": provider_event_id,
        "approval_action_hash": "q" * 64,
        "tool_input": {"path": "Desktop/one.txt"},
    }
    native_control_metrics.reset()
    before = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id=provider_event_id,
            correlation_id=correlation_id,
            event=common,
        ),
    )
    assert before.status_code == 200, before.text
    with session_factory() as db:
        first_evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.id == before.json()["evidence_ref"].removeprefix("evidence:")
            )
        )
        first_selection = db.scalar(select(native_controls_router.NativeControlSelection))
        assert first_evidence is not None
        assert first_selection is not None
        first_binding = {
            "selection_id_match": first_evidence.payload.get("native_control_selection_id")
            == first_selection.selection_id,
            "plan_id_match": first_evidence.payload.get("native_control_plan_id")
            == first_selection.control_plan_id,
            "plan_digest_match": first_evidence.payload.get("native_control_plan_digest")
            == first_selection.control_plan_digest,
            "contract_present": bool(first_selection.contract_hashes),
            "receipt": first_evidence.payload.get("decision_receipt_id"),
            "route": first_evidence.payload.get("route_binding_current"),
        }
        assert first_binding == {
            "selection_id_match": True,
            "plan_id_match": True,
            "plan_digest_match": True,
            "contract_present": True,
            "receipt": first_evidence.payload.get("decision_receipt_id"),
            "route": True,
        }
    repeated_before = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id=provider_event_id,
            correlation_id="retry-" + ("c" * 58),
            event=common,
        ),
    )
    assert repeated_before.status_code == 200, repeated_before.text
    assert repeated_before.json()["deduplicated"] is True, first_binding
    assert repeated_before.json()["decision_receipt_id"] == before.json()["decision_receipt_id"]
    assert len(authorized_requests) == 1
    metrics = native_control_metrics.snapshot()
    assert sum(row["value"] for row in metrics["provider_adapter_events_total"]) == 2
    assert sum(row["value"] for row in metrics["provider_adapter_allow_total"]) == 0
    assert sum(row["value"] for row in metrics["provider_adapter_block_total"]) == 0
    assert sum(row["value"] for row in metrics["provider_adapter_would_block_total"]) == 2
    assert sum(row["value"] for row in metrics["provider_adapter_deduplicated_total"]) == 1
    first_prompt = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_model",
            provider_event_id="claude-reused-prompt-session-action-id",
            correlation_id="prompt-one-" + ("c" * 53),
            event={
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Read README.md and return only the first heading",
                "provider_session_hash": "s" * 64,
            },
        ),
    )
    assert first_prompt.status_code == 200, first_prompt.text
    assert first_prompt.json()["deduplication_conflict"] is False
    second_prompt = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_model",
            provider_event_id="claude-reused-prompt-session-action-id",
            correlation_id="prompt-two-" + ("c" * 53),
            event={
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Use Bash to run: rm -rf /tmp/hawk-demo-protected-folder",
                "provider_session_hash": "s" * 64,
            },
        ),
    )
    assert second_prompt.status_code == 200, second_prompt.text
    assert second_prompt.json()["deduplication_conflict"] is False
    assert "provider_event_id_reauthorization_required" not in second_prompt.json()["reason_codes"]
    assert len(authorized_requests) == 3
    conflicting_retry = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id=provider_event_id,
            correlation_id="conflict-" + ("c" * 55),
            event={
                **common,
                "target_resource": "Desktop/two.txt",
                "target_resource_hash": "z" * 64,
                "tool_input": {"path": "Desktop/two.txt"},
            },
        ),
    )
    assert conflicting_retry.status_code == 200, conflicting_retry.text
    assert conflicting_retry.json()["deduplicated"] is False
    assert conflicting_retry.json()["deduplication_conflict"] is True
    assert conflicting_retry.json()["would_decision"] == "block"
    assert len(authorized_requests) == 3
    retry_after_conflict = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id=provider_event_id,
            correlation_id="after-conflict-" + ("c" * 49),
            event=common,
        ),
    )
    assert retry_after_conflict.status_code == 200, retry_after_conflict.text
    assert retry_after_conflict.json()["deduplicated"] is False
    assert retry_after_conflict.json()["deduplication_conflict"] is True
    assert retry_after_conflict.json()["would_decision"] == "block"
    assert "provider_event_id_historical_conflict" in retry_after_conflict.json()["reason_codes"]
    assert len(authorized_requests) == 3
    permission = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="permission_request",
            correlation_id=correlation_id,
            event={
                **common,
                "permission_context_present": True,
                "permission_suggestions_hash": "g" * 64,
            },
        ),
    )
    assert permission.status_code == 200, permission.text
    assert permission.json()["provider_permission_context"] is True
    assert permission.json()["permission_pre_action_correlated"] is False
    assert permission.json()["approval_reauthorization_required"] is True
    assert permission.json()["control_mode"] == "provider_permission_context"
    assert permission.json()["enforced"] is False
    assert permission.json()["would_decision"] == "block"
    assert "provider_event_id_historical_conflict" in permission.json()["reason_codes"]

    changed_permission = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="permission_request",
            correlation_id=correlation_id,
            event={
                **common,
                "approval_action_hash": "m" * 64,
                "tool_input": {"path": "Desktop/two.txt"},
                "permission_context_present": True,
                "permission_suggestions_hash": "g" * 64,
            },
        ),
    )
    assert changed_permission.status_code == 200, changed_permission.text
    assert changed_permission.json()["permission_pre_action_correlated"] is False
    assert changed_permission.json()["approval_reauthorization_required"] is True
    assert changed_permission.json()["would_decision"] == "block"
    missing_tool_permission = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="permission_request",
            correlation_id=correlation_id,
            event={
                **{key: value for key, value in common.items() if key != "tool_name"},
                "permission_context_present": True,
                "permission_suggestions_hash": "g" * 64,
            },
        ),
    )
    assert missing_tool_permission.status_code == 200, missing_tool_permission.text
    assert missing_tool_permission.json()["permission_pre_action_correlated"] is False
    assert missing_tool_permission.json()["approval_reauthorization_required"] is True
    assert missing_tool_permission.json()["would_decision"] == "block"
    lifecycle_mismatch = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            event={**common, "provider_event_type": "after_tool"},
        ),
    )
    assert lifecycle_mismatch.status_code == 422
    assert lifecycle_mismatch.json()["detail"] == "Native callback lifecycle binding mismatch"
    after = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="after_tool",
            provider_event_id=provider_event_id,
            correlation_id=correlation_id,
            event={**common, "response_hash": "r" * 64},
        ),
    )

    assert after.status_code == 200, after.text
    assert after.json()["post_action_correlated"] is False
    assert after.json()["execution_evidence_quality"] == "provider_reported"
    assert after.json()["input_mutation_detected"] is False
    assert after.json()["correlated_pre_action_evidence_ref"] is None
    assert after.json()["execution_receipt_id"] is None
    assert after.json()["execution_integrity_result_id"] is None
    assert "provider_event_id_historical_conflict" in after.json()["reason_codes"]
    failed_after = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="after_tool_failure",
            provider_event_id=provider_event_id,
            correlation_id=correlation_id,
            event={**common, "failure_hash": "x" * 64, "execution_status": "failed"},
        ),
    )
    assert failed_after.status_code == 200, failed_after.text
    assert failed_after.json()["lifecycle_semantics"] == "provider_reported_failure"
    assert failed_after.json()["post_action_correlated"] is False
    assert failed_after.json()["execution_evidence_quality"] == "provider_reported"

    config_change = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-workload-1",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="config_change",
            event={
                **common,
                "action_type": "session_context",
                "config_source": "user_settings",
                "config_file_path_hash": "z" * 64,
            },
        ),
    )
    assert config_change.status_code == 200, config_change.text
    assert config_change.json()["lifecycle_semantics"] == "configuration_integrity_signal"
    assert config_change.json()["execution_evidence_quality"] == "none"
    with session_factory() as db:
        rows = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.correlation_id == correlation_id,
                EvidenceNode.node_type == "native_control_callback",
            )
        ).all()
    assert len(rows) == 6
    post = next(row for row in rows if row.payload["provider_event_type"] == "after_tool")
    permission_evidence = next(
        row
        for row in rows
        if row.payload["provider_event_type"] == "permission_request"
        and row.payload["permission_pre_action_correlated"] is False
    )
    assert post.payload["raw_result_retained"] is False
    assert post.payload["tool_class"] == "local_shell"
    assert post.payload["execution_evidence_quality"] == "provider_reported"
    assert permission_evidence.payload["provider_permission_context"] is True
    assert permission_evidence.payload["execution_evidence_quality"] == "none"


def test_signed_claude_callback_records_the_exact_adapter_dispatch(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "claude-exact-dispatch@example.com")
    now = datetime.now(timezone.utc)
    observed_bindings = []
    enrich = native_controls_router._enrich_native_request_with_discovery_context

    def capture_binding(db, request):
        observed_bindings.append(dict(request.path_evidence["native_control_route_binding"]))
        return enrich(db, request)

    monkeypatch.setattr(native_controls_router, "_enrich_native_request_with_discovery_context", capture_binding)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-exact-dispatch",
            "display_name": "Claude exact dispatch",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-exact-dispatch-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text

    callback = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-exact-dispatch-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            event={
                "action_type": "tool_execution",
                "tool_name": "Read",
                "tool_class": "file_read",
                "parameter_hash": "p" * 64,
                "target_resource": "README.md",
                "target_resource_hash": "t" * 64,
                "destination": "local",
                "destination_hash": "d" * 64,
                "persistent_side_effect": False,
                "data_classifications": [],
            },
        ),
    )

    assert callback.status_code == 200, callback.text
    assert callback.json()["adapter_dispatch"] == "exact"
    assert callback.json()["adapter_enforcement_eligible"] is False
    assert len(observed_bindings) == 1
    assert observed_bindings[0].get("runtime_context_verified") is not True
    assert "lifecycle_stage" not in observed_bindings[0]
    assert callback.json()["adapter_id"] == "anthropic.claude-code.command-hooks"
    with session_factory() as db:
        evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.node_type == "native_control_callback",
            )
        )
    assert evidence is not None
    assert evidence.payload["adapter_dispatch"] == "exact"
    assert evidence.payload["adapter_resolution"] == "exact_match"
    assert evidence.payload["adapter_id"] == "anthropic.claude-code.command-hooks"


def test_single_observed_claude_callback_cannot_mint_real_binary_acceptance(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "claude-real-acceptance@example.com")
    now = datetime.now(timezone.utc)
    for flag in (
        "native_control_anthropic",
        "native_control_adapter_enforcement",
        "authorization_kernel_v2_enabled",
        "authorization_kernel_v2_enforce",
    ):
        monkeypatch.setitem(settings.__dict__, flag, True)
    monkeypatch.setitem(settings.__dict__, "env", "production")
    monkeypatch.setitem(
        settings.__dict__,
        "authorization_kernel_v2_enforce_rollout",
        json.dumps({tenant_id: ["runtime_control"]}),
    )
    monkeypatch.setitem(settings.__dict__, "decision_execution_receipts_enabled", True)
    monkeypatch.setitem(settings.__dict__, "receipt_signing_active_key_id", "test-receipt-key")
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_keys_json",
        json.dumps({"test-receipt-key": "r" * 32}),
    )
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-real-acceptance",
            "display_name": "Claude real acceptance",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
            "trusted_workload_authority": True,
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    monkeypatch.setitem(
        settings.__dict__,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "runtime_control": {
                        "integration_instance_ids": [integration_id],
                        "provider": "anthropic",
                        "product": "claude_code",
                        "provider_version": "2.1.183",
                        "adapter_version": "1.2.0",
                    }
                }
            }
        ),
    )
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-real-acceptance-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text

    observed = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-real-acceptance-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            event={
                "action_type": "tool_execution",
                "tool_name": "Read",
                "tool_class": "file_read",
                "parameter_hash": "p" * 64,
                "target_resource": "README.md",
                "target_resource_hash": "t" * 64,
                "destination": "local",
                "destination_hash": "d" * 64,
                "persistent_side_effect": False,
                "data_classifications": [],
            },
        ),
    )
    assert observed.status_code == 200, observed.text
    assert observed.json()["adapter_dispatch"] == "exact"

    # Production previously contained a legacy reviewed profile for the same
    # Claude manifest version whose fingerprint no longer matched the current
    # reviewed manifest and whose exact adapter contract fields were still
    # unknown. Real-binary acceptance is the audited admin boundary that may
    # re-ratify that profile; ordinary catalog reads must still fail closed.
    with session_factory() as db:
        profile = db.scalar(
            select(ControlCapabilityProfileRecord).where(
                ControlCapabilityProfileRecord.provider == "anthropic",
                ControlCapabilityProfileRecord.product == "claude_code",
                ControlCapabilityProfileRecord.adapter_version == "1.2.0",
            )
        )
        assert profile is not None
        profile.manifest_fingerprint = "0" * 64
        profile.matrix_version = "stale-matrix"
        profile.verification_status = "experimental"
        profile.verification_source = "stale-source"
        profile.verified_at = None
        profile.runtime = "unknown"
        profile.capabilities = {}
        profile.security_properties = {}
        profile.health_requirements = []
        profile.degradation_modes = []
        profile.known_blind_spots = []
        profile.documentation_references = []
        profile.supported_action_classes = []
        profile.supported_control_methods = []
        profile.contract_hash = None
        profile.active = False
        integration = db.get(NativeControlIntegration, integration_id)
        assert integration is not None
        integration.policy_fresh_until = now - timedelta(days=1)
        db.commit()

    accepted = client.post(
        f"/native-controls/integrations/{integration_id}/accept-real-binary",
        headers=headers,
    )
    assert accepted.status_code == 409, accepted.text
    detail = accepted.json()["detail"]
    assert detail["code"] == "real_binary_acceptance_failed"
    assert {
        "signed_allow_receipt_observed",
        "signed_block_receipt_observed",
        "distinct_acceptance_challenges",
        "hardware_endpoint_identity_bound",
        "allow_execution_receipt_observed",
        "attested_allow_target_effect_observed",
        "block_execution_absent",
        "attested_non_execution_observed",
    } <= set(detail["reasons"])

    with session_factory() as db:
        repaired = db.scalar(
            select(ControlCapabilityProfileRecord).where(
                ControlCapabilityProfileRecord.provider == "anthropic",
                ControlCapabilityProfileRecord.product == "claude_code",
                ControlCapabilityProfileRecord.adapter_version == "1.2.0",
            )
        )
        integration = db.get(NativeControlIntegration, integration_id)
        assert repaired is not None
        assert integration is not None
        assert repaired.matrix_version == "stale-matrix"
        assert repaired.verification_status == "experimental"
        assert repaired.verification_source == "stale-source"
        assert repaired.verified_at is None
        assert repaired.runtime == "unknown"
        assert repaired.contract_hash is None
        assert repaired.active is False
        assert native_controls_router._aware(integration.policy_fresh_until) < now

    enforced = client.post(f"/native-controls/integrations/{integration_id}/enforce", headers=headers)
    assert enforced.status_code == 409, enforced.text
    return

    with session_factory() as db:
        integration = db.get(NativeControlIntegration, integration_id)
        assert integration is not None
        integration.state = IntegrationState.DEGRADED.value
        integration.mode = IntegrationMode.MONITOR.value
        integration.health_state = HealthState.DEGRADED.value
        integration.health_reasons = ["simulated_runtime_degradation"]
        db.commit()

        blocked = client.post(
            f"/native-controls/callbacks/{integration_id}",
            json=_callback_proof(
                private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-real-acceptance-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id="claude-destructive-tool-1",
            event={
                "action_type": "tool_execution",
                "tool_name": "Bash",
                "tool_class": "local_shell",
                "tool_fingerprint_id": "f" * 64,
                "parameter_hash": "a" * 64,
                "target_resource": "/tmp/hawk-demo-protected-folder",
                "target_resource_hash": "b" * 64,
                "destination": "local",
                "destination_hash": "c" * 64,
                "persistent_side_effect": True,
                "side_effect_class": "delete",
                "data_classifications": [],
            },
        ),
    )
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["decision"] == "block", blocked.json()
    assert blocked.json()["would_decision"] == "block"
    assert blocked.json()["control_mode"] != "telemetry_only"
    assert blocked.json()["enforced"] is True
    assert blocked.json()["decision_receipt_id"] is None
    assert blocked.json()["evidence_ref"].startswith("evidence:")

    with session_factory() as evidence_db:
        blocked_evidence = evidence_db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.id == blocked.json()["evidence_ref"].removeprefix("evidence:")
            )
        )
        assert blocked_evidence is not None
        assert blocked_evidence.payload["decision"] == "block"

    with session_factory() as db:
        integration = db.get(NativeControlIntegration, integration_id)
        assert integration is not None
        integration.state = IntegrationState.ENFORCING.value
        integration.mode = IntegrationMode.ENFORCE.value
        integration.health_state = HealthState.HEALTHY.value
        integration.health_reasons = []
        db.commit()

    safe_read_reuse = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-real-acceptance-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id="claude-reused-session-action-id",
            event={
                "callback_schema": "hawk-native-hash-envelope/v1",
                "action_type": "file_read",
                "tool_name": "Read",
                "tool_class": "file_read",
                "provider_tool_use_hash": "safe-tool-use",
                "tool_fingerprint_id": "f" * 64,
                "parameter_hash": "1" * 64,
                "target_resource": "/tmp/hawk-demo-protected-folder/readme.txt",
                "target_resource_hash": "2" * 64,
                "destination": "local",
                "destination_hash": "3" * 64,
                "persistent_side_effect": False,
                "side_effect_class": "read",
                "data_classifications": [],
            },
        ),
    )
    assert safe_read_reuse.status_code == 200, safe_read_reuse.text
    assert safe_read_reuse.json()["deduplication_conflict"] is False
    assert "provider_event_id_reauthorization_required" not in safe_read_reuse.json()["reason_codes"]

    destructive_reuse = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-real-acceptance-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id="claude-reused-session-action-id",
            event={
                "callback_schema": "hawk-native-hash-envelope/v1",
                "action_type": "tool_execution",
                "tool_name": "Bash",
                "tool_class": "local_shell",
                "provider_tool_use_hash": "delete-tool-use",
                "tool_fingerprint_id": "f" * 64,
                "parameter_hash": "4" * 64,
                "target_resource": "/tmp/hawk-demo-protected-folder",
                "target_resource_hash": "5" * 64,
                "destination": "local",
                "destination_hash": "6" * 64,
                "persistent_side_effect": True,
                "side_effect_class": "delete",
                "data_classifications": [],
            },
        ),
    )
    assert destructive_reuse.status_code == 200, destructive_reuse.text
    assert destructive_reuse.json()["decision"] == "block", destructive_reuse.json()
    assert destructive_reuse.json()["deduplication_conflict"] is False


def test_failed_codex_acceptance_rolls_back_admin_profile_reratification(
    native_api_env,
) -> None:
    client, session_factory = native_api_env
    _tenant_id, headers = _register(client, "codex-reratification-rollback@example.com")
    now = datetime.now(timezone.utc)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "openai",
            "product": "codex",
            "method": "native_hook",
            "instance_key": "codex-reratification-rollback",
            "display_name": "Codex re-ratification rollback",
            "environment": "development",
            "deployment_family": "endpoint",
            "provider_version": "0.154.0",
            "adapter_version": "1.0.0",
            "policy_version": "policy-codex",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
            "trusted_workload_authority": True,
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]

    with session_factory() as db:
        integration = db.get(NativeControlIntegration, integration_id)
        assert integration is not None
        profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
        assert profile is not None
        profile_id = profile.id
        profile.manifest_fingerprint = "0" * 64
        profile.matrix_version = "stale-matrix"
        profile.runtime = "unknown"
        profile.verification_status = "experimental"
        profile.supported_action_classes = []
        profile.supported_control_methods = []
        profile.contract_hash = None
        profile.active = False
        integration.contract_hash = "f" * 64
        prior_configuration_fingerprint = integration.configuration_fingerprint
        prior_expected_fingerprint = integration.expected_configuration_fingerprint
        db.commit()

    rejected = client.post(
        f"/native-controls/integrations/{integration_id}/accept-real-binary",
        headers=headers,
    )
    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["detail"] == "active_workload_credential_required"

    with session_factory() as db:
        profile = db.get(ControlCapabilityProfileRecord, profile_id)
        integration = db.get(NativeControlIntegration, integration_id)
        assert profile is not None
        assert integration is not None
        assert profile.manifest_fingerprint == "0" * 64
        assert profile.matrix_version == "stale-matrix"
        assert profile.runtime == "unknown"
        assert profile.verification_status == "experimental"
        assert profile.supported_action_classes == []
        assert profile.supported_control_methods == []
        assert profile.contract_hash is None
        assert profile.active is False
        assert integration.contract_hash == "f" * 64
        assert integration.configuration_fingerprint == prior_configuration_fingerprint
        assert integration.expected_configuration_fingerprint == prior_expected_fingerprint


def test_hash_only_exact_allow_reuses_one_decision_and_records_matched_post_execution(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One signed logical action yields one decision and one matched execution."""

    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "native-exact-allow-execution@example.com")
    now = datetime.now(timezone.utc)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-exact-allow-execution",
            "display_name": "Claude exact allow execution",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-exact-allow-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool", "after_tool"],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    monkeypatch.setitem(settings.__dict__, "decision_execution_receipts_enabled", True)
    monkeypatch.setitem(settings.__dict__, "receipt_signing_active_key_id", "test-receipt-key")
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_keys_json",
        json.dumps({"test-receipt-key": "r" * 32}),
    )

    # This fixture proves the exact callback transaction in Monitor. Do not
    # let a separate tenant route-enforcement rollout rewrite the otherwise
    # allowed decision into a selector-requirement denial.
    monkeypatch.setitem(settings.__dict__, "native_control_enforce", False)

    def _allow(request: AuthorizationRequest) -> AuthorizationResponse:
        return AuthorizationResponse(
            decision="allow",
            control_mode="inline_allowed",
            reason="test_allow",
            policy_snapshot_id=request.policy_snapshot_id,
            policy_profile_hash="p" * 64,
            response_hash="r" * 64,
        )

    monkeypatch.setattr(native_controls_router, "authorize_ai_action", _allow)
    provider_event_id = "logical-tool-allow-1"
    correlation_id = "logical-correlation-allow-1"
    action = {
        "callback_schema": "hawk-native-hash-envelope/v1",
        "action_type": "FILE_READ",
        "tool_name": "Read",
        "tool_class": "file_read",
        "tool_fingerprint_id": "f" * 64,
        "parameter_hash": "a" * 64,
        "target_resource": "README.md",
        "target_resource_hash": "b" * 64,
        "destination": "local",
        "destination_hash": "c" * 64,
        "persistent_side_effect": False,
        "side_effect_class": "read_only_or_unknown",
        "provider_tool_use_hash": "u" * 64,
        "approval_action_hash": "h" * 64,
        "data_classifications": [],
    }
    pre = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-exact-allow-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id=provider_event_id,
            correlation_id=correlation_id,
            event=action,
        ),
    )
    assert pre.status_code == 200, pre.text
    assert pre.json()["decision"] == "allow"
    assert pre.json()["would_decision"] == "allow"
    assert pre.json()["decision_receipt_id"]

    retry = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-exact-allow-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            provider_event_id=provider_event_id,
            correlation_id="logical-correlation-retry-allow-1",
            event=action,
        ),
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["deduplicated"] is True, json.dumps(retry.json(), indent=2)
    assert retry.json()["decision_receipt_id"] == pre.json()["decision_receipt_id"]

    # A provider retry is informational: it inherits the prior receipt but
    # deliberately has no fresh selector plan. Exercise the historical
    # same-timestamp ordering where its ID sorts before the authoritative
    # pre-action evidence, so it cannot shadow the bound action during post
    # execution correlation.
    provider_event_hash = hashlib.sha256(provider_event_id.encode("utf-8")).hexdigest()
    with session_factory() as db:
        callback_evidence = list(
            db.scalars(
                select(EvidenceNode)
                .where(
                    EvidenceNode.tenant_id == tenant_id,
                    EvidenceNode.node_type == "native_control_callback",
                    EvidenceNode.payload["provider_event_id_hash"].as_string()
                    == provider_event_hash,
                )
                .order_by(EvidenceNode.created_at.asc(), EvidenceNode.id.asc())
            ).all()
        )
        assert len(callback_evidence) == 2
        bound_evidence = next(
            node for node in callback_evidence if node.payload["deduplicated"] is False
        )
        informational_retry = next(
            node for node in callback_evidence if node.payload["deduplicated"] is True
        )
        informational_retry.created_at = bound_evidence.created_at
        informational_retry.id = "00000000-0000-0000-0000-000000000001"
        db.commit()

    post = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-exact-allow-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="after_tool",
            provider_event_id=provider_event_id,
            correlation_id=correlation_id,
            event={**action, "execution_status": "succeeded"},
        ),
    )
    assert post.status_code == 200, post.text
    assert post.json()["post_action_correlated"] is True, json.dumps(post.json(), indent=2)
    assert post.json()["execution_receipt_id"]
    with session_factory() as db:
        decision_rows = list(
            db.scalars(
                select(DecisionReceipt).where(DecisionReceipt.tenant_id == tenant_id)
            ).all()
        )
        execution_rows = list(
            db.scalars(
                select(ExecutionReceipt).where(ExecutionReceipt.tenant_id == tenant_id)
            ).all()
        )
    assert [row.receipt_id for row in decision_rows] == [pre.json()["decision_receipt_id"]]
    assert len(execution_rows) == 1
    assert execution_rows[0].decision_receipt_id == pre.json()["decision_receipt_id"]


def test_framework_disabled_callback_is_observation_only_in_monitor_and_fails_safe_in_enforce(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A generic compatibility path never creates a policy decision/receipt."""

    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "native-generic-fallback@example.com")
    now = datetime.now(timezone.utc)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-framework-disabled",
            "display_name": "Claude generic fallback fixture",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-framework-disabled-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    monkeypatch.setitem(settings.__dict__, "native_control_adapter_framework", False)

    event = {
        "action_type": "FILE_WRITE",
        "tool_name": "Write",
        "tool_class": "file_write",
        "parameter_hash": "p" * 64,
        "target_resource": "README.md",
        "target_resource_hash": "t" * 64,
        "destination": "local",
        "destination_hash": "d" * 64,
        "persistent_side_effect": True,
        "data_classifications": ["secret"],
    }
    monitor = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-framework-disabled-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            event=event,
        ),
    )
    assert monitor.status_code == 200, monitor.text
    assert monitor.json()["decision"] == "unknown"
    assert monitor.json()["would_decision"] == "unknown"
    assert monitor.json()["control_mode"] == "generic_observation"
    assert monitor.json()["enforced"] is False
    assert monitor.json()["decision_receipt_id"] is None

    with session_factory() as db:
        integration = db.get(NativeControlIntegration, integration_id)
        assert integration is not None
        integration.state = IntegrationState.ENFORCING.value
        integration.mode = IntegrationMode.ENFORCE.value
        integration.health_state = HealthState.HEALTHY.value
        db.commit()

    enforce = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-framework-disabled-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            event=event,
        ),
    )
    assert enforce.status_code == 200, enforce.text
    assert enforce.json()["decision"] == "block"
    assert enforce.json()["would_decision"] == "block"
    assert enforce.json()["control_mode"] == "control_requirement_unsatisfied"
    assert enforce.json()["enforced"] is True
    assert enforce.json()["decision_receipt_id"] is None
    assert "CONTROL_REQUIREMENT_UNSATISFIED" in enforce.json()["reason_codes"]
    with session_factory() as db:
        assert db.scalar(
            select(DecisionReceipt).where(DecisionReceipt.tenant_id == tenant_id)
        ) is None
        assert db.scalar(
            select(NativeControlSelection).where(
                NativeControlSelection.tenant_id == tenant_id
            )
        ) is None


def test_exact_but_enforcement_ineligible_callback_remains_telemetry_only_and_non_authoritative(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "claude-exact-ineligible@example.com")
    now = datetime.now(timezone.utc)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-exact-ineligible",
            "display_name": "Claude exact but ineligible",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-exact-ineligible-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    with session_factory() as db:
        row = db.get(NativeControlIntegration, integration_id)
        assert row is not None
        row.state = IntegrationState.ENFORCING.value
        row.mode = IntegrationMode.ENFORCE.value
        row.health_state = HealthState.HEALTHY.value
        db.commit()

    registry = NativeControlAdapterRegistry(environment="development")
    registry.register(ClaudeAdapter())
    monkeypatch.setattr(native_controls_router, "_foundation_registry", lambda: registry)
    monkeypatch.setitem(settings.__dict__, "native_control_adapter_enforcement", True)
    monkeypatch.setattr(
        native_controls_router,
        "_facts",
        lambda _db, _row: IntegrationFacts(
            state=IntegrationState.ENFORCING,
            mode=IntegrationMode.ENFORCE,
            profile_verification=VerificationStatus.VERIFIED,
            profile_active=True,
            health=HealthState.HEALTHY,
            validation=NativeValidationResult.PASSED,
            validated_at=now,
            validation_valid_until=now + timedelta(minutes=5),
            policy_fresh_until=now + timedelta(minutes=5),
            configuration_integrity_valid=True,
            provider_version_supported=True,
            adapter_version_supported=True,
            route_binding_current=True,
            enforcement_feature_active=True,
            active_workload_identity=True,
            callback_authenticated=True,
            evidence_flowing=True,
            measured_latency_ms=1,
        ),
    )

    callback = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-exact-ineligible-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.183",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            event={
                "action_type": "tool_execution",
                "tool_name": "Write",
                "tool_class": "file_write",
                "parameter_hash": "p" * 64,
                "target_resource": "README.md",
                "target_resource_hash": "t" * 64,
                "destination": "local",
                "destination_hash": "d" * 64,
                "persistent_side_effect": True,
                "data_classifications": [],
            },
        ),
    )

    assert callback.status_code == 200, callback.text
    assert callback.json()["adapter_dispatch"] == "exact"
    assert callback.json()["adapter_resolution"] == "exact_match"
    assert callback.json()["adapter_enforcement_eligible"] is False
    assert callback.json()["decision"] == "block"
    assert callback.json()["would_decision"] == "block"
    assert callback.json()["control_mode"] == "control_requirement_unsatisfied"
    assert callback.json()["enforced"] is True
    assert "CONTROL_REQUIREMENT_UNSATISFIED" in callback.json()["reason_codes"]
    assert callback.json()["decision_receipt_id"] is None
    status = client.get(f"/control-points/{integration_id}", headers=headers)
    assert status.status_code == 200, status.text
    assert status.json()["authoritative"] is False


def test_signed_callback_rejects_an_unverified_newer_known_native_adapter(
    native_api_env,
) -> None:
    client, _session_factory = native_api_env
    tenant_id, headers = _register(client, "claude-newer-adapter@example.com")
    now = datetime.now(timezone.utc)
    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-newer-adapter",
            "display_name": "Claude newer adapter",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.184",
            "adapter_version": "1.2.0",
            "policy_version": "policy-claude",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-newer-adapter-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text

    callback = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="claude-newer-adapter-workload",
            provider="anthropic",
            product="claude_code",
            provider_version="2.1.184",
            adapter_version="1.2.0",
            provider_event_type="before_tool",
            event={
                "action_type": "tool_execution",
                "tool_name": "Write",
                "tool_class": "file_write",
                "parameter_hash": "p" * 64,
                "target_resource": "README.md",
                "target_resource_hash": "t" * 64,
                "destination": "local",
                "destination_hash": "d" * 64,
                "persistent_side_effect": True,
                "data_classifications": [],
            },
        ),
    )

    assert callback.status_code == 409, callback.text
    assert callback.json()["detail"] == (
        "Native callback exact adapter unavailable: provider_version_unverified_newer"
    )


def test_signed_negative_validation_claim_fails_conservatively(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _session_factory = native_api_env
    tenant_id, headers = _register(client, "negative-validation@example.com")
    created = client.post("/native-controls/integrations", headers=headers, json=_integration_payload())
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    monkeypatch.setitem(
        settings.__dict__,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "llm_gateway": {
                        "integration_instance_ids": [integration_id],
                        "provider": "openai",
                        "provider_version": "hawk-openai-compatible-v1",
                        "adapter_version": "1.0.0",
                        "product": "direct_api",
                    }
                }
            }
        ),
    )
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "workload-production-1",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["hawk.validation"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text

    response = client.post(
        f"/native-controls/integrations/{integration_id}/validate",
        headers=headers,
        json=_validation_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            validation_claims={"safe_synthetic": False},
        ),
    )

    assert response.status_code == 200, response.text
    assert response.json()["result"] == "failed"
    assert response.json()["checks"]["safe_synthetic"] is False


def test_provider_matrix_is_typed_and_conservative(native_api_env) -> None:
    client, _session_factory = native_api_env
    _tenant_id, headers = _register(client, "matrix@example.com")

    response = client.get("/control-capabilities/providers", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["matrix_version"].startswith("control-capability-matrix/1.0+")
    assert {row["provider"] for row in payload["providers"]} >= {
        "anthropic",
        "openai",
        "azure",
        "aws",
        "meta",
        "deepseek",
    }
    codex_native = next(
        row
        for row in payload["providers"]
        if row["provider"] == "openai" and row["product"] == "codex" and row["method"] == "native_hook"
    )
    assert codex_native["verification_status"] == "verified"
    assert codex_native["supported_versions"] == ["0.154.0"]
    assert {
        name
        for name, claim in codex_native["capability_matrix"].items()
        if claim["verification_status"] == "verified"
    } == {"discovery", "identity", "prompt_control"}


def test_end_to_end_synthetic_validation_stays_monitor_only_and_never_enforces(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _session_factory = native_api_env
    tenant_id, headers = _register(client, "lifecycle@example.com")
    monkeypatch.setitem(settings.__dict__, "authorization_kernel_v2_enabled", True)
    monkeypatch.setitem(settings.__dict__, "authorization_kernel_v2_enforce", True)
    monkeypatch.setitem(
        settings.__dict__,
        "authorization_kernel_v2_enforce_rollout",
        json.dumps({tenant_id: ["llm_gateway"]}),
    )

    created = client.post("/native-controls/integrations", headers=headers, json=_integration_payload())
    assert created.status_code == 201, created.text
    integration = created.json()
    integration_id = integration["id"]
    monkeypatch.setitem(
        settings.__dict__,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "llm_gateway": {
                        "integration_instance_ids": [integration_id],
                        "provider": "openai",
                        "provider_version": "hawk-openai-compatible-v1",
                        "adapter_version": "1.0.0",
                        "product": "direct_api",
                    }
                }
            }
        ),
    )
    assert integration["tenant_id"] == tenant_id
    assert integration["state"] == "configuring"
    assert integration["mode"] == "discover"

    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "workload-production-1",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_model", "before_tool", "after_tool", "hawk.validation"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    assert "public_key_pem" not in credential.json()
    assert "private" not in credential.text.lower()

    validation = client.post(
        f"/native-controls/integrations/{integration_id}/validate",
        headers=headers,
        json=_validation_proof(private_key, tenant_id=tenant_id, integration_id=integration_id),
    )
    assert validation.status_code == 200, validation.text
    validation_body = validation.json()
    assert validation_body["result"] == "partial"
    assert validation_body["checks"]["live_route_observed"] is False
    assert validation_body["safe_synthetic"] is True

    monitored = client.post(f"/native-controls/integrations/{integration_id}/monitor", headers=headers)
    assert monitored.status_code == 200, monitored.text
    assert monitored.json()["state"] == "monitoring"

    with _session_factory() as db:
        select_and_persist_authorization(
            db,
            request=AuthorizationRequest(
                tenant_id=tenant_id,
                environment="production",
                collector_id="llm-gateway-request",
                action_id=f"live-route-{uuid4()}",
                chain_id="live-route-chain",
                surface="llm_gateway",
                actor={"identity_id": "user-1"},
                authority={
                    "verified": True,
                    "authority_type": "authenticated_user",
                    "authority_source": "tenant_context",
                },
                action={"action_type": "prompt", "risk_level": "low"},
                target={"resource_hash": "route-target", "destination": "internal"},
                discovery_context={
                    "provider": "openai",
                    "product": "direct_api",
                    "provider_version": "hawk-openai-compatible-v1",
                    "adapter_version": "1.0.0",
                    "asset_status": "approved",
                },
                policy_snapshot_id="policy-7",
                policy_profile={
                    "dependencies_healthy": True,
                    "degraded_behavior": "fail_closed",
                },
                path_evidence={
                    "native_control_route_binding": {
                        "verified": True,
                        "source": "hawk_gateway_route",
                        "integration_instance_ids": [integration_id],
                        "allowed_methods": ["gateway_inline"],
                    }
                },
            ),
            now=datetime.now(timezone.utc),
        )
        db.commit()

    revalidation = client.post(
        f"/native-controls/integrations/{integration_id}/validate",
        headers=headers,
        json=_validation_proof(private_key, tenant_id=tenant_id, integration_id=integration_id),
    )
    assert revalidation.status_code == 200, revalidation.text
    assert revalidation.json()["result"] == "passed"
    assert revalidation.json()["checks"]["live_route_observed"] is True
    monitored = client.post(f"/native-controls/integrations/{integration_id}/monitor", headers=headers)
    assert monitored.status_code == 200, monitored.text

    enforced = client.post(f"/native-controls/integrations/{integration_id}/enforce", headers=headers)
    assert enforced.status_code == 409, enforced.text
    assert enforced.json()["detail"] == "real_acceptance_required"

    coverage = client.get(f"/native-controls/integrations/{integration_id}/coverage", headers=headers)
    assert coverage.status_code == 200, coverage.text
    assert coverage.json()["dimensions"]["authorization"] == "unknown"
    assert coverage.json()["known_estate_limitation"]

    health = client.get(f"/control-points/{integration_id}/health", headers=headers)
    assert health.status_code == 200, health.text
    assert health.json()["health_state"] == "healthy"
    assert health.json()["provider_version_compatible"] is True
    assert health.json()["real_acceptance_current"] is False
    assert health.json()["active_for_enforcement"] is False

    blocked_callback = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            event={
                "action_type": "tool_execution",
                "tool_name": "github.create_pull_request",
                "parameter_hash": "p" * 64,
                "target_resource": "github/repository",
                "target_resource_hash": "t" * 64,
                "destination": "github.com",
                "destination_hash": "d" * 64,
                "persistent_side_effect": True,
                "data_classifications": [],
            },
        ),
    )
    assert blocked_callback.status_code == 200, blocked_callback.text
    assert blocked_callback.json()["would_decision"] == "block"
    assert blocked_callback.json()["decision"] == "allow"
    assert blocked_callback.json()["control_mode"] == "telemetry_only"
    assert blocked_callback.json()["enforced"] is False
    assert blocked_callback.json()["evidence_ref"].startswith("evidence:")

    rotated_key, rotated_public_key_pem = _key_pair()
    rotating = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "workload-production-2",
            "credential_epoch": 2,
            "public_key_pem": rotated_public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_model", "before_tool", "after_tool", "hawk.validation"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert rotating.status_code == 201, rotating.text
    assert rotating.json()["status"] == "rotating"
    non_monotonic = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "workload-production-reused",
            "credential_epoch": 1,
            "public_key_pem": rotated_public_key_pem,
            "environment": "production",
            "allowed_event_types": ["hawk.validation"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert non_monotonic.status_code == 409
    rotated_validation = client.post(
        f"/native-controls/integrations/{integration_id}/validate",
        headers=headers,
        json=_validation_proof(
            rotated_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="workload-production-2",
            credential_epoch=2,
        ),
    )
    assert rotated_validation.status_code == 200, rotated_validation.text
    assert rotated_validation.json()["result"] == "passed"
    with _session_factory() as db:
        credentials = {
            row.credential_id: row.status
            for row in db.scalars(
                select(NativeWorkloadCredential).where(
                    NativeWorkloadCredential.integration_instance_id == integration_id
                )
            ).all()
        }
    assert credentials == {
        "workload-production-1": "revoked",
        "workload-production-2": "active",
    }

    revoked = client.post(
        f"/native-controls/integrations/{integration_id}/credentials/workload-production-2/revoke",
        headers=headers,
        json={"reason": "scheduled rotation"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert "public_key_pem" not in revoked.text
    health_after_revoke = client.get(f"/control-points/{integration_id}/health", headers=headers)
    assert health_after_revoke.json()["callback_health"] == "unverified"
    coverage_after_revoke = client.get(
        f"/native-controls/integrations/{integration_id}/coverage", headers=headers
    )
    assert coverage_after_revoke.json()["dimensions"]["authorization"] != "covered"


def test_long_tail_endpoint_runtime_observation_binding_cannot_enter_enforce(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "endpoint-runner@example.com")
    monkeypatch.setitem(settings.__dict__, "authorization_kernel_v2_enabled", True)
    monkeypatch.setitem(settings.__dict__, "authorization_kernel_v2_enforce", True)
    monkeypatch.setitem(
        settings.__dict__,
        "authorization_kernel_v2_enforce_rollout",
        json.dumps({tenant_id: ["runtime_control"]}),
    )
    payload = {
        **_integration_payload(),
        "provider": "alibaba_qwen",
        "product": "self_hosted",
        "method": "endpoint_runtime",
        "instance_key": "endpoint-qwen-runtime",
        "display_name": "Endpoint Qwen Runtime",
        "deployment_family": "endpoint",
        "provider_version": "explicit-hawk-client-binding-v1",
    }
    created = client.post("/native-controls/integrations", headers=headers, json=payload)
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    monkeypatch.setitem(
        settings.__dict__,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "runtime_control": {
                        "integration_instance_ids": [integration_id],
                        "provider": "alibaba_qwen",
                        "provider_version": "explicit-hawk-client-binding-v1",
                        "adapter_version": "1.0.0",
                        "product": "self_hosted",
                    }
                }
            }
        ),
    )
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "endpoint-workload-1",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text

    callback = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="endpoint-workload-1",
            provider="alibaba_qwen",
            product="self_hosted",
            provider_version="explicit-hawk-client-binding-v1",
            event={
                "action_type": "tool_execution",
                "tool_name": "gmail.read",
                "parameter_hash": "p" * 64,
                "target_resource": "gmail/message",
                "target_resource_hash": "t" * 64,
                "destination": "gmail.googleapis.com",
                "destination_hash": "d" * 64,
                "persistent_side_effect": False,
                "data_classifications": [],
            },
        ),
    )
    assert callback.status_code == 200, callback.text
    assert callback.json()["enforced"] is False

    with session_factory() as db:
        select_and_persist_authorization(
            db,
            request=AuthorizationRequest(
                tenant_id=tenant_id,
                environment="production",
                collector_id="endpoint-runtime-request",
                action_id=f"endpoint-route-{uuid4()}",
                chain_id="endpoint-route-chain",
                surface="runtime_control",
                actor={"identity_id": "endpoint-workload-1"},
                authority={
                    "verified": True,
                    "authority_type": "signed_workload_identity",
                    "authority_source": "endpoint_device_key",
                },
                action={"action_type": "tool_execution", "risk_level": "low"},
                target={"resource_hash": "route-target", "destination": "internal"},
                discovery_context={
                    "provider": "alibaba_qwen",
                    "product": "self_hosted",
                    "provider_version": "explicit-hawk-client-binding-v1",
                    "adapter_version": "1.0.0",
                    "asset_status": "approved",
                },
                policy_snapshot_id="policy-7",
                policy_profile={"dependencies_healthy": True, "degraded_behavior": "block"},
                path_evidence={
                    "native_control_route_binding": {
                        "verified": True,
                        "source": "hawk_runtime_route",
                        "integration_instance_ids": [integration_id],
                        "allowed_methods": ["endpoint_runtime"],
                    }
                },
            ),
            now=datetime.now(timezone.utc),
        )
        db.commit()

    before = client.post(f"/native-controls/integrations/{integration_id}/enforce", headers=headers)
    assert before.status_code == 409

    validation = client.post(
        f"/native-controls/integrations/{integration_id}/validate/run",
        headers=headers,
    )
    assert validation.status_code == 200, validation.text
    assert validation.json()["result"] == "failed", validation.text
    assert validation.json()["checks"]["server_probe_supported"] is False
    assert validation.json()["checks"]["callback_authenticated"] is True

    monitored = client.post(f"/native-controls/integrations/{integration_id}/monitor", headers=headers)
    assert monitored.status_code == 409
    assert monitored.json()["detail"] == "revalidation_required"
    enforced = client.post(f"/native-controls/integrations/{integration_id}/enforce", headers=headers)
    assert enforced.status_code == 409
    assert enforced.json()["detail"] == "revalidation_required"


def test_cross_tenant_control_point_is_not_visible(native_api_env) -> None:
    client, _session_factory = native_api_env
    _tenant_one, first_headers = _register(client, "first-tenant@example.com")
    _tenant_two, second_headers = _register(client, "second-tenant@example.com")
    created = client.post("/native-controls/integrations", headers=first_headers, json=_integration_payload())
    assert created.status_code == 201, created.text

    response = client.get(f"/control-points/{created.json()['id']}", headers=second_headers)

    assert response.status_code == 404


def test_signed_callback_replay_is_rejected_at_the_router_and_records_a_finding(
    native_api_env,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "callback-replay@example.com")
    created = client.post("/native-controls/integrations", headers=headers, json=_integration_payload())
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "replay-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    signed_callback = _callback_proof(
        private_key,
        tenant_id=tenant_id,
        integration_id=integration_id,
        credential_id="replay-workload",
        event={
            "action_type": "tool_execution",
            "tool_name": "safe_read",
            "parameter_hash": "p" * 64,
            "target_resource": "README.md",
            "target_resource_hash": "t" * 64,
            "destination": "local",
            "destination_hash": "d" * 64,
            "persistent_side_effect": False,
            "data_classifications": [],
        },
    )

    first = client.post(f"/native-controls/callbacks/{integration_id}", json=signed_callback)
    replay = client.post(f"/native-controls/callbacks/{integration_id}", json=signed_callback)

    assert first.status_code == 200, first.text
    assert replay.status_code == 401, replay.text
    assert replay.json()["detail"] == "Native callback rejected: replay_detected"
    with session_factory() as db:
        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.finding_type == "NATIVE_CONTROL_REPLAY_REJECTED",
            )
        )
    assert finding is not None
    assert finding.application == integration_id


def test_signed_callback_from_another_tenant_cannot_bind_to_the_integration(
    native_api_env,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "callback-owner@example.com")
    other_tenant_id, _other_headers = _register(client, "callback-other@example.com")
    created = client.post("/native-controls/integrations", headers=headers, json=_integration_payload())
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, _public_key_pem = _key_pair()
    foreign_tenant_callback = _callback_proof(
        private_key,
        tenant_id=other_tenant_id,
        integration_id=integration_id,
        event={
            "action_type": "tool_execution",
            "tool_name": "safe_read",
            "parameter_hash": "p" * 64,
            "target_resource": "README.md",
            "target_resource_hash": "t" * 64,
            "destination": "local",
            "destination_hash": "d" * 64,
            "persistent_side_effect": False,
            "data_classifications": [],
        },
    )

    response = client.post(
        f"/native-controls/callbacks/{integration_id}", json=foreign_tenant_callback
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Native callback identity is unavailable"
    with session_factory() as db:
        evidence_count = db.query(EvidenceNode).filter(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.node_type == "native_control_callback",
        ).count()
    assert evidence_count == 0


def test_signed_repository_callback_persists_hash_only_observation_linked_to_evidence(native_api_env) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "repository-observation@example.com")
    created = client.post("/native-controls/integrations", headers=headers, json=_integration_payload())
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "repository-observation-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    root_hash = "1" * 64
    common_hash = "2" * 64
    target_hash = "3" * 64
    callback = client.post(
        f"/native-controls/callbacks/{integration_id}",
        json=_callback_proof(
            private_key,
            tenant_id=tenant_id,
            integration_id=integration_id,
            credential_id="repository-observation-workload",
            event={
                "action_type": "FILE_WRITE",
                "tool_name": "Edit",
                "tool_class": "file_write",
                "parameter_hash": "p" * 64,
                "target_resource": "workspace",
                "target_resource_hash": target_hash,
                "destination": "local",
                "destination_hash": "d" * 64,
                "persistent_side_effect": True,
                "data_classifications": [],
                "repository_control_resolution": "resolved",
                "repository_operation": "EDIT",
                "repository_command_shape": "file_write",
                "repository_command_hash": "c" * 64,
                "repository_destination_hash": "unknown",
                "repository_root_hash": root_hash,
                "repository_common_dir_hash": common_hash,
                "repository_target_hash": target_hash,
            },
        ),
    )

    assert callback.status_code == 200, callback.text
    with session_factory() as db:
        observation = db.scalar(
            select(GitHubRepositoryRuntimeBinding).where(
                GitHubRepositoryRuntimeBinding.tenant_id == tenant_id,
                GitHubRepositoryRuntimeBinding.native_integration_id == integration_id,
                GitHubRepositoryRuntimeBinding.canonical_root_sha256 == root_hash,
                GitHubRepositoryRuntimeBinding.common_dir_sha256 == common_hash,
            )
        )
        evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.id == callback.json()["evidence_ref"].removeprefix("evidence:")
            )
        )
        assert observation is not None
        assert observation.repository_id is None
        assert observation.scope == "EXACT_FOLDER"
        assert observation.state == "OBSERVED"
        assert evidence is not None
        assert observation.signed_evidence_ref == f"evidence:{evidence.id}"
        assert evidence.payload["repository_root_hash"] == root_hash
        assert evidence.payload["repository_common_dir_hash"] == common_hash
        assert evidence.payload["repository_target_hash"] == target_hash
        assert evidence.payload["repository_operation"] == "EDIT"
        assert "path" not in evidence.payload

        now_verified = datetime.now(timezone.utc)
        source = GitHubSourceOrganization(
            tenant_id=tenant_id,
            host="github.com",
            external_organization_id="observation-org",
            login="observation-org",
        )
        db.add(source)
        db.flush()
        repository = GitHubRepository(
            tenant_id=tenant_id,
            source_organization_id=source.id,
            host="github.com",
            external_repository_id="observation-repo",
            full_name="observation-org/private-repo",
            evidence_state="CONFIRMED",
            visibility="PRIVATE",
            lifecycle_state="ACTIVE",
            first_seen_at=now_verified,
            last_seen_at=now_verified,
            last_verified_at=now_verified,
        )
        db.add(repository)
        db.commit()
        observation_id = observation.id
        repository_id = repository.id

    binding_url = (
        f"/control-coverage/source-control/github-repositories/repositories/{repository_id}/runtime-binding"
    )
    injected = client.put(
        binding_url,
        headers=headers,
        json={
            "observation_id": observation_id,
            "expected_governance_version": 0,
            "canonical_root_sha256": root_hash,
            "common_dir_sha256": common_hash,
            "native_integration_id": integration_id,
        },
    )
    assert injected.status_code == 422
    activated_without_current_governance = client.put(
        binding_url,
        headers=headers,
        json={
            "observation_id": observation_id,
            "expected_governance_version": 0,
        },
    )
    assert activated_without_current_governance.status_code == 422
    assert "current confirmed private repository governance" in activated_without_current_governance.json()["detail"]


def test_distinct_repository_reads_without_tool_identity_use_signed_event_identity() -> None:
    identity = native_controls_router._provider_action_identity_hash
    event = {"action_type": "FILE_READ", "provider_session_hash": "s" * 64}
    for additional in ({}, {"prompt_hash": "unknown"}, {"prompt": "incidental context"}):
        read = {**event, **additional}
        first = identity(provider_event=read, provider_event_id="read-one")
        assert first != identity(provider_event=read, provider_event_id="read-two")
        assert first == identity(provider_event=read, provider_event_id="read-one")


def test_verified_tool_identity_precedes_prompt_and_event_identity() -> None:
    identity = native_controls_router._provider_action_identity_hash
    event = {"action_type": "FILE_READ", "provider_tool_use_hash": "t" * 64}
    first = identity(provider_event=event, provider_event_id="before-read")
    assert first == identity(
        provider_event={**event, "prompt": "different incidental material"},
        provider_event_id="after-read",
    )


@pytest.mark.parametrize("semantics", [
    {"action_type": "MODEL_REQUEST"},
    {"action_type": "prompt"},
    {"provider_event_type": "before_model"},
    {"hook_event_name": "UserPromptSubmit"},
    {"hook_event_name": "BeforeModel"},
    {"hook_event_name": "beforeSubmitPrompt"},
])
def test_genuine_prompt_retries_bind_prompt_material(semantics: dict) -> None:
    identity = native_controls_router._provider_action_identity_hash
    for material_key in ("prompt_hash", "prompt", "input", "messages"):
        event = {**semantics, material_key: "first prompt", "provider_session_hash": "s" * 64}
        first = identity(provider_event=event, provider_event_id="prompt-one")
        assert first == identity(provider_event=event, provider_event_id="prompt-retry")
        assert first != identity(
            provider_event={**event, material_key: "second prompt"},
            provider_event_id="prompt-one",
        )


def test_prompt_semantics_without_real_material_use_signed_event_identity() -> None:
    identity = native_controls_router._provider_action_identity_hash
    event = {"action_type": "MODEL_REQUEST", "prompt_hash": "unknown", "provider_session_hash": "s" * 64}
    assert identity(provider_event=event, provider_event_id="prompt-one") != identity(
        provider_event=event, provider_event_id="prompt-two",
    )


def test_claude_exact_repository_read_floor_tracks_authenticated_control_changes(
    native_api_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, session_factory = native_api_env
    tenant_id, headers = _register(client, "claude-repository-floor@example.com")
    now = datetime.now(timezone.utc)
    for flag in (
        "native_control_anthropic",
        "native_control_adapter_enforcement",
        "authorization_kernel_v2_enabled",
        "authorization_kernel_v2_enforce",
    ):
        monkeypatch.setitem(settings.__dict__, flag, True)
    monkeypatch.setitem(settings.__dict__, "env", "production")
    monkeypatch.setitem(
        settings.__dict__,
        "authorization_kernel_v2_enforce_rollout",
        json.dumps({tenant_id: ["runtime_control"]}),
    )
    monkeypatch.setitem(settings.__dict__, "decision_execution_receipts_enabled", True)
    monkeypatch.setitem(settings.__dict__, "receipt_signing_active_key_id", "test-receipt-key")
    monkeypatch.setitem(
        settings.__dict__,
        "receipt_signing_keys_json",
        json.dumps({"test-receipt-key": "r" * 32}),
    )
    monkeypatch.setitem(settings.__dict__, "discovery_context_provider", True)

    created = client.post(
        "/native-controls/integrations",
        headers=headers,
        json={
            "provider": "anthropic",
            "product": "claude_code",
            "method": "native_hook",
            "instance_key": "claude-repository-floor",
            "display_name": "Claude repository floor",
            "environment": "production",
            "deployment_family": "endpoint",
            "provider_version": "2.1.183",
            "adapter_version": "1.2.0",
            "policy_version": "policy-repository-floor",
            "policy_fresh_until": (now + timedelta(hours=1)).isoformat(),
            "degradation_mode": "fail_closed",
            "trusted_workload_authority": True,
        },
    )
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    monkeypatch.setitem(
        settings.__dict__,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "runtime_control": {
                        "integration_instance_ids": [integration_id],
                        "provider": "anthropic",
                        "product": "claude_code",
                        "provider_version": "2.1.183",
                        "adapter_version": "1.2.0",
                    }
                }
            }
        ),
    )
    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "claude-repository-floor-workload",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["before_tool"],
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text

    root_hash, common_hash = "8" * 64, "9" * 64

    # Seed current, signed-governance inputs. The repository approval, runtime
    # binding, and operation controls themselves all go through owner APIs.
    with session_factory() as db:
        source = GitHubSourceOrganization(tenant_id=tenant_id, host="github.com", external_organization_id="floor-org", login="floor-org")
        db.add(source)
        db.flush()
        repository = GitHubRepository(
            tenant_id=tenant_id,
            source_organization_id=source.id,
            host="github.com",
            external_repository_id="floor-repo",
            full_name="floor-org/private-repo",
            evidence_state="CONFIRMED",
            visibility="PRIVATE",
            lifecycle_state="ACTIVE",
            first_seen_at=now,
            last_seen_at=now,
            last_verified_at=now,
        )
        db.add(repository)
        db.flush()
        pack = PolicyPack(id=str(uuid4()), tenant_id=tenant_id, name="Repository floor", description="test", status="active")
        version = PolicyVersion(id=str(uuid4()), tenant_id=tenant_id, pack_id=pack.id, version="1", scope={}, enforcement_defaults={}, guardian_contracts=[], contract_json={})
        definition = PolicyPackDefinition(id=str(uuid4()), publisher_ref="test-repository-floor", stable_pack_id="TEST-REPOSITORY-FLOOR", version="1", name="Repository floor", description="test", state="PUBLISHED")
        instance = PolicyPackInstance(id=str(uuid4()), tenant_id=tenant_id, definition_id=definition.id, source_pack_id="TEST-REPOSITORY-FLOOR", source_pack_version="1", runtime_policy_pack_id=pack.id, effective_policy_version_id=version.id, owner_ref="test-owner", state="ENFORCED")
        assignment = PolicyPackAssignment(
            id=str(uuid4()),
            tenant_id=tenant_id,
            instance_id=instance.id,
            assignment_key="repository-floor",
            targets=_normalize_assignment_targets({
                "application": ["github"],
                "deployment_surface": ["mcp_gateway"],
                "resource": [repository.id],
            }),
            active=True,
        )
        db.add_all((pack, version, definition, instance, assignment))

        asset_id = str(uuid4())
        digest = lambda: hashlib.sha256(uuid4().bytes).hexdigest()
        asset = DiscoveryAIAsset(
            asset_id=asset_id,
            tenant_id=tenant_id,
            asset_type="runtime",
            canonical_name="Claude Code",
            provider="anthropic",
            product="claude_code",
            framework="Read",
            version="2.1.183",
            deployment_family="endpoint",
            technical_surface="runtime",
            environment="production",
            approved_status="approved",
            lifecycle_status="active",
            shadow_ai_status="unknown",
            first_seen_at=now - timedelta(minutes=1),
            last_seen_at=now,
            resolution_confidence=0.95,
            evidence_bundle_id=str(uuid4()),
            projection_version=1,
        )
        graph_node_id = str(uuid4())
        genome_id = str(uuid4())
        ecosystem_id = str(uuid4())
        ecosystem_record_id = str(uuid4())
        db.add_all((
            asset,
            DiscoveryResolutionGraphNode(
                graph_node_id=graph_node_id,
                tenant_id=tenant_id,
                node_class="ai_asset",
                subject_reference=f"discovery_asset:{asset_id}",
                idempotency_key=uuid4().hex,
                input_digest=digest(),
            ),
            DiscoveryCapabilityGenome(
                genome_id=genome_id,
                tenant_id=tenant_id,
                inference_run_id=str(uuid4()),
                subject_reference_hash="e" * 64,
                genome_version=1,
                supersedes_genome_id=None,
                genome_digest=digest(),
                capabilities_json=[],
                dependencies_json=[{"reference": "current"}],
                permissions_json=[],
                reachability_json=[],
                usage_json=[],
                models_json=[],
                providers_json=[],
                runtime_json=[],
                data_json=[],
                marketplace_json=[],
                identity_json=[],
                first_observed_at=now - timedelta(minutes=1),
                last_observed_at=now,
            ),
            DiscoveryAIEcosystem(
                ecosystem_record_id=ecosystem_record_id,
                tenant_id=tenant_id,
                ecosystem_id=ecosystem_id,
                resolution_version=1,
                supersedes_record_id=None,
                canonical_name="Claude Code test ecosystem",
                ecosystem_class="runtime",
                lifecycle_state="active",
                resolution_state="resolved",
                confidence=0.95,
                evidence_quality=0.95,
                capability_genome_id=genome_id,
                first_observed_at=now - timedelta(minutes=1),
                last_observed_at=now,
                last_validated_at=now,
                methodology_id="native-control-test",
                methodology_version="1.0",
                limitations_json=[],
                outstanding_contradictions=0,
                idempotency_key=uuid4().hex,
                input_digest=digest(),
            ),
            DiscoveryEcosystemMembership(
                membership_id=str(uuid4()),
                tenant_id=tenant_id,
                ecosystem_record_id=ecosystem_record_id,
                ecosystem_id=ecosystem_id,
                graph_node_id=graph_node_id,
                member_type="ai_asset",
                membership_state="active",
                membership_sequence=1,
                predecessor_membership_id=None,
                evidence_node_id=str(uuid4()),
                confidence=0.95,
                verification_state="verified",
                first_observed_at=now - timedelta(minutes=1),
                last_observed_at=now,
                limitations_json=[],
                input_digest=digest(),
            ),
            DiscoveryVerificationAssertion(
                assertion_id=str(uuid4()),
                tenant_id=tenant_id,
                ecosystem_id=ecosystem_id,
                ecosystem_record_id=ecosystem_record_id,
                episode_id=str(uuid4()),
                erg_evaluation_id=str(uuid4()),
                policy_record_id=str(uuid4()),
                predecessor_assertion_id=None,
                assertion_sequence=1,
                conclusion="verified",
                required_requirement_count=1,
                required_verified_count=1,
                optional_requirement_count=0,
                optional_verified_count=0,
                source_diversity=1,
                evidence_quality=0.95,
                verification_quality=0.95,
                issued_at=now - timedelta(minutes=1),
                valid_from=now - timedelta(minutes=1),
                valid_until=now + timedelta(hours=1),
                invalidated_at=None,
                methodology_version="1.0",
                limitations_json=[],
                contradictions_json=[],
                idempotency_key=uuid4().hex,
                input_digest=digest(),
            ),
        ))
        db.commit()
        repository_id = repository.id
        assignment_id = assignment.id

    approved = client.put(
        f"/control-coverage/source-control/github-repositories/repositories/{repository_id}/governance",
        headers=headers,
        json={"decision": "APPROVED", "expected_governance_version": 0, "assignment_id": assignment_id},
    )
    assert approved.status_code == 200, approved.text

    def send(provider_event_id: str):
        return client.post(
            f"/native-controls/callbacks/{integration_id}",
            json=_callback_proof(
                private_key,
                tenant_id=tenant_id,
                integration_id=integration_id,
                credential_id="claude-repository-floor-workload",
                provider="anthropic",
                product="claude_code",
                provider_version="2.1.183",
                adapter_version="1.2.0",
                provider_event_type="before_tool",
                provider_event_id=provider_event_id,
                event={
                    "action_type": "FILE_READ",
                    "tool_name": "Read",
                    "tool_class": "file_read",
                    "parameter_hash": "a" * 64,
                    "target_resource": "README.md",
                    "target_resource_hash": "b" * 64,
                    "destination": "local",
                    "destination_hash": "c" * 64,
                    "persistent_side_effect": False,
                    "data_classifications": [],
                    "repository_control_resolution": "resolved",
                    "repository_operation": "READ",
                    "repository_root_hash": root_hash,
                    "repository_common_dir_hash": common_hash,
                    "repository_target_hash": "d" * 64,
                    "repository_destination_hash": "unknown",
                },
            ),
        )

    observed = send("claude-floor-observation")
    assert observed.status_code == 200, observed.text
    assert observed.json()["adapter_dispatch"] == "exact"
    assert observed.json()["decision"] == "allow", observed.json()
    with session_factory() as db:
        observation = db.scalar(select(GitHubRepositoryRuntimeBinding).where(
            GitHubRepositoryRuntimeBinding.tenant_id == tenant_id,
            GitHubRepositoryRuntimeBinding.native_integration_id == integration_id,
            GitHubRepositoryRuntimeBinding.canonical_root_sha256 == root_hash,
            GitHubRepositoryRuntimeBinding.common_dir_sha256 == common_hash,
            GitHubRepositoryRuntimeBinding.repository_id.is_(None),
        ))
        profile = db.scalar(select(ControlCapabilityProfileRecord).where(
            ControlCapabilityProfileRecord.provider == "anthropic",
            ControlCapabilityProfileRecord.product == "claude_code",
            ControlCapabilityProfileRecord.adapter_version == "1.2.0",
        ))
        integration = db.get(NativeControlIntegration, integration_id)
        assert observation is not None
        assert profile is not None
        assert integration is not None
        profile.manifest_fingerprint = "0" * 64
        profile.runtime = "unknown"
        profile.supported_action_classes = []
        profile.supported_control_methods = []
        profile.contract_hash = None
        integration.policy_fresh_until = now - timedelta(days=1)
        observation_id = observation.id
        db.commit()

    bound = client.put(
        f"/control-coverage/source-control/github-repositories/repositories/{repository_id}/runtime-binding",
        headers=headers,
        json={"observation_id": observation_id, "expected_governance_version": 1},
    )
    assert bound.status_code == 200, bound.text
    binding = bound.json()
    assert binding["id"] == observation_id
    assert binding["state"] == "ACTIVE"
    assert binding["repository_id"] == repository_id
    assert binding["native_integration_id"] == integration_id
    assert binding["scope"] == "EXACT_FOLDER"
    assert binding["canonical_root_sha256"] == root_hash
    assert binding["common_dir_sha256"] == common_hash
    all_allowed = {key: "ALLOW" for key in ("READ", "EDIT", "COMMIT", "PULL", "PUSH")}
    controls = client.put(
        f"/control-coverage/source-control/github-repositories/repositories/{repository_id}/operation-controls",
        headers=headers,
        json={"controls": all_allowed, "expected_governance_version": 2},
    )
    assert controls.status_code == 200, controls.text

    accepted = client.post(
        f"/native-controls/integrations/{integration_id}/accept-real-binary",
        headers=headers,
    )
    assert accepted.status_code == 409, accepted.text
    assert accepted.json()["detail"]["code"] == "real_binary_acceptance_failed"
    assert "attested_non_execution_observed" in accepted.json()["detail"]["reasons"]
    enforced = client.post(f"/native-controls/integrations/{integration_id}/enforce", headers=headers)
    assert enforced.status_code == 409, enforced.text
    return

    first = send("claude-floor-allow-1")
    assert first.status_code == 200, first.text
    # Diagnose only this callback's closed control projection, never provider data.
    from app.services.native_control.contracts import CapabilityDimension

    capability_codes = {dimension.value for dimension in CapabilityDimension}
    safe_reason_codes = {
        "CONTROL_REQUIREMENT_UNSATISFIED", "generic_observation_only",
        "repository_control_floor", "repository_operation_blocked",
        "repository_runtime_target_unresolved", "repository_runtime_blocked",
        "blocked_action_type", "missing_active_policies", "asset_status_unknown",
        "tenant_binding_invalid", "provider_product_mismatch",
        "provider_version_unavailable", "provider_version_route_mismatch",
        "provider_version_unsupported", "adapter_version_unavailable",
        "adapter_version_route_mismatch", "adapter_version_unsupported",
        "policy_binding_mode_unverified", "policy_version_mismatch",
        "policy_version_unavailable", "callback_authentication_failed",
        "callback_unauthenticated", "validation_stale",
        "configuration_integrity_invalid", "policy_stale",
        "evidence_flow_unavailable", "active_bypass_detected",
        "latency_requirement_unsatisfied", "latency_budget_exceeded",
        "degradation_mode_unacceptable", "required_lifecycle_event_missing",
        "blocking_semantics_unavailable", "minimum_assurance_unsatisfied",
        "insufficient_post_execution_verification", "not_endpoint_enforcement_floor",
        "profile_unverified", "semantic_control_unsatisfied",
        "mandatory_enforcement_floor_unsatisfied",
    }
    safe_reason_codes.update({
        'deployment_acceptance_action_class_mismatch',
        'deployment_acceptance_adapter_version_mismatch',
        'deployment_acceptance_contract_hash_mismatch',
        'deployment_acceptance_control_method_mismatch',
        'deployment_acceptance_credential_inactive',
        'deployment_acceptance_credential_mismatch',
        'deployment_acceptance_deployment_identity_mismatch',
        'deployment_acceptance_deployment_mismatch',
        'deployment_acceptance_environment_mismatch',
        'deployment_acceptance_evidence_incomplete',
        'deployment_acceptance_lifecycle_mismatch',
        'deployment_acceptance_location_mismatch',
        'deployment_acceptance_model_mismatch',
        'deployment_acceptance_model_provider_mismatch',
        'deployment_acceptance_not_current',
        'deployment_acceptance_outcomes_incomplete',
        'deployment_acceptance_provider_product_mismatch',
        'deployment_acceptance_provider_version_mismatch',
        'deployment_acceptance_route_identity_mismatch',
        'deployment_acceptance_route_mismatch',
        'deployment_acceptance_runtime_mismatch',
        'deployment_acceptance_state_mismatch',
        'deployment_acceptance_synthetic',
        "enterprise_account_context_required", "enterprise_tenant_context_required",
        "provider_event_id_reauthorization_required",
        "action_field_identity_not_visible", "action_field_parameters_not_visible",
        "action_field_target_not_visible", "action_field_destination_not_visible",
        "action_field_result_not_visible",
    })
    safe_reason_codes.update(
        f"{prefix}{code}{suffix}"
        for code in capability_codes
        for prefix, suffix in (
            ("capability_", "_unverified"), ("capability_", "_unsatisfied"),
            ("insufficient_", ""),
        )
    )
    safe_reason_codes.update(f"profile_{state.value}" for state in VerificationStatus)
    safe_reason_codes.update(f"health_{state.value}" for state in HealthState)
    safe_reason_codes.update(
        f"action_field_{field}_not_visible"
        for field in ("action_type", "tool_name", "tool_class", "parameter_hash",
                      "target_resource", "target_resource_hash", "destination",
                      "destination_hash", "persistent_side_effect", "data_classifications")
    )
    callback = first.json()
    diagnostic = {
        "http_status": first.status_code,
        "callback": {key: callback.get(key) for key in (
            "decision", "would_decision", "control_mode", "enforced",
            "adapter_dispatch", "adapter_resolution", "adapter_enforcement_eligible",
        )},
        "reason_codes": sorted(set(callback.get("reason_codes") or []) & safe_reason_codes),
        "selection": "not_found",
    }
    with session_factory() as db:
        current_integration = db.scalar(select(NativeControlIntegration).where(
            NativeControlIntegration.tenant_id == tenant_id,
            NativeControlIntegration.id == integration_id,
        ))
        linked_profile = db.get(
            ControlCapabilityProfileRecord, current_integration.capability_profile_id,
        ) if current_integration is not None and current_integration.capability_profile_id else None
        diagnostic["integration_checks"] = {
            "present": current_integration is not None,
            "enforcing": current_integration is not None and current_integration.state == "enforcing",
            "native_hook": current_integration is not None and current_integration.integration_method == "native_hook",
            "production": current_integration is not None and current_integration.environment == "production",
            "linked_profile_present": linked_profile is not None,
            "linked_profile_active": linked_profile is not None and linked_profile.active is True,
        }
        callback_evidence = db.scalar(select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == str(callback.get("evidence_ref") or "").removeprefix("evidence:"),
            EvidenceNode.node_type == "native_control_callback",
        ))
        selection_id = (
            callback_evidence.payload.get("native_control_selection_id")
            if callback_evidence is not None else None
        )
        selection = db.scalar(select(NativeControlSelection).where(
            NativeControlSelection.tenant_id == tenant_id,
            NativeControlSelection.selection_id == selection_id,
        )) if selection_id else None
        if selection is not None:
            diagnostic["selection"] = {
                "selection_reason": selection.selection_reason if selection.selection_reason in {
                    "strongest_verified_eligible_control_point", "CONTROL_REQUIREMENT_UNSATISFIED",
                } else "other_closed_reason",
                "control_requirement_unsatisfied": selection.control_requirement_unsatisfied,
                "required_capabilities": sorted(set(selection.required_capabilities or []) & capability_codes),
                "satisfied_capabilities": sorted(set(selection.satisfied_capabilities or []) & capability_codes),
                "unsatisfied_capabilities": sorted(set(selection.unsatisfied_capabilities or []) & capability_codes),
                "assurance_level": selection.assurance_level,
                "rejected_candidate_count": len(selection.rejected_candidates or []),
                "runtime_context_checks": {
                    key: (selection.provider_runtime_context or {}).get(key) == expected
                    for key, expected in {
                        "provider": "anthropic", "product": "claude_code",
                        "action_class": "file_read", "runtime_location": "local_endpoint",
                        "provider_version": "2.1.183", "adapter_version": "1.2.0",
                        "control_method": "native_hook", "environment": "production",
                        "lifecycle_stage": "before_tool",
                    }.items()
                },
                "rejected_candidate_reason_codes": sorted({
                    code for candidate in (selection.rejected_candidates or [])
                    for code in candidate.get("reason_codes", []) if code in safe_reason_codes
                }),
            }
    assert callback["decision"] == "allow", json.dumps(diagnostic, sort_keys=True)
    assert first.json()["enforced"] is True

    blocked_controls = dict(all_allowed)
    blocked_controls["READ"] = "BLOCK"
    changed = client.put(
        f"/control-coverage/source-control/github-repositories/repositories/{repository_id}/operation-controls",
        headers=headers,
        json={"controls": blocked_controls, "expected_governance_version": 3},
    )
    assert changed.status_code == 200, changed.text
    middle = send("claude-floor-block-1")
    assert middle.status_code == 200, middle.text
    assert middle.json()["decision"] == "block"
    assert "repository_control_floor" in middle.json()["reason_codes"]
    assert "repository_operation_blocked" in middle.json()["reason_codes"]
    assert middle.json()["enforced"] is True

    restored = client.put(
        f"/control-coverage/source-control/github-repositories/repositories/{repository_id}/operation-controls",
        headers=headers,
        json={"controls": all_allowed, "expected_governance_version": 4},
    )
    assert restored.status_code == 200, restored.text
    last = send("claude-floor-allow-2")
    assert last.status_code == 200, last.text
    assert last.json()["decision"] == "allow"
    assert last.json()["enforced"] is True
    assert last.json()["adapter_dispatch"] == "exact"
    assert first.json()["adapter_dispatch"] == "exact"
    assert middle.json()["adapter_dispatch"] == "exact"
    assert "repository_control_floor" not in first.json()["reason_codes"]
    assert {"repository_control_floor", "repository_operation_blocked"} <= set(middle.json()["reason_codes"])
    assert "repository_control_floor" not in last.json()["reason_codes"]

    with session_factory() as db:
        evidence = list(db.scalars(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.node_type == "native_control_callback")).all())
        phase_ids = {"claude-floor-allow-1", "claude-floor-block-1", "claude-floor-allow-2"}
        phase_hashes = {hashlib.sha256(event_id.encode()).hexdigest() for event_id in phase_ids}
        phase_evidence = [row for row in evidence if row.payload.get("provider_event_id_hash") in phase_hashes]
        assert len(phase_evidence) == 3
        by_hash = {row.payload["provider_event_id_hash"]: row for row in phase_evidence}
        for event_id in phase_ids:
            row = by_hash[hashlib.sha256(event_id.encode()).hexdigest()]
            assert row.signal_type == "authenticated_native_adapter"
            assert row.payload["adapter_dispatch"] == "exact"
            assert row.payload["enforced"] is True
            selection = db.scalar(select(NativeControlSelection).where(
                NativeControlSelection.tenant_id == tenant_id,
                NativeControlSelection.selection_id == row.payload.get("native_control_selection_id"),
            ))
            assert selection is not None
            assert selection.provider_runtime_context["lifecycle_stage"] == "before_tool"
        assert by_hash[hashlib.sha256(b"claude-floor-allow-1").hexdigest()].payload["decision"] == "allow"
        assert by_hash[hashlib.sha256(b"claude-floor-block-1").hexdigest()].payload["decision"] == "block"
        assert by_hash[hashlib.sha256(b"claude-floor-allow-2").hexdigest()].payload["decision"] == "allow"


def test_disabled_framework_returns_not_found(native_api_env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _session_factory = native_api_env
    _tenant_id, headers = _register(client, "disabled-native@example.com")
    monkeypatch.setitem(settings.__dict__, "native_control_framework", False)

    assert client.get("/control-capabilities/providers", headers=headers).status_code == 404
    assert client.get("/control-points", headers=headers).status_code == 404


def test_provider_specific_flag_prevents_enforce_rollout(native_api_env, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _session_factory = native_api_env
    tenant_id, headers = _register(client, "provider-flag@example.com")
    created = client.post("/native-controls/integrations", headers=headers, json=_integration_payload())
    assert created.status_code == 201, created.text
    integration_id = created.json()["id"]
    monkeypatch.setitem(
        settings.__dict__,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "llm_gateway": {
                        "integration_instance_ids": [integration_id],
                        "provider": "openai",
                        "provider_version": "hawk-openai-compatible-v1",
                        "adapter_version": "1.0.0",
                        "product": "direct_api",
                    }
                }
            }
        ),
    )

    private_key, public_key_pem = _key_pair()
    credential = client.post(
        f"/native-controls/integrations/{integration_id}/credentials",
        headers=headers,
        json={
            "credential_id": "workload-production-1",
            "credential_epoch": 1,
            "public_key_pem": public_key_pem,
            "environment": "production",
            "allowed_event_types": ["hawk.validation"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert credential.status_code == 201, credential.text
    validation = client.post(
        f"/native-controls/integrations/{integration_id}/validate",
        headers=headers,
        json=_validation_proof(private_key, tenant_id=tenant_id, integration_id=integration_id),
    )
    assert validation.status_code == 200, validation.text
    assert client.post(f"/native-controls/integrations/{integration_id}/monitor", headers=headers).status_code == 200

    monkeypatch.setitem(settings.__dict__, "native_control_openai", False)
    response = client.post(f"/native-controls/integrations/{integration_id}/enforce", headers=headers)

    assert response.status_code == 404
