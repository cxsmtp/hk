from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def _base_settings(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "_env_file": None,
        "secret_key": "bank-settings-app-secret-key-00000001",
        "connector_secrets_key": "bank-settings-connector-key-00000001",
        "connector_secrets_kdf_salt": "bank-settings-kdf-salt",
        "onprem_bundle_signing_secret": "bank-settings-bundle-key-00000001",
        "canonical_action_binding_key": "bank-settings-canonical-key-00000001",
    }
    values.update(overrides)
    return values


def _enabled_settings(**overrides: object) -> dict[str, object]:
    values = _base_settings(
        authorization_kernel_v2_enabled=True,
        authorization_kernel_shadow_compare_enabled=True,
        authorization_kernel_v2_enforce=True,
        authorization_kernel_v2_enforce_rollout=json.dumps(
            {"tenant-a": ["llm_gateway"]}
        ),
        decision_execution_receipts_enabled=True,
        receipt_signing_active_key_id="bank-receipt-key",
        receipt_signing_keys_json=json.dumps(
            {"bank-receipt-key": "bank-settings-receipt-key-0000000001"}
        ),
        banking_transaction_integrity_enabled=True,
        banking_subject_trust_json=json.dumps(
            {
                "https://bank.example/auth": {
                    "audience": "hawk-bank-foundry",
                    "keys": {
                        "bank-key-1": (
                            "-----BEGIN PUBLIC KEY-----\n"
                            "synthetic-test-public-key\n"
                            "-----END PUBLIC KEY-----"
                        )
                    },
                }
            }
        ),
        banking_subject_pseudonymization_key=(
            "bank-settings-pseudonymization-key-00000001"
        ),
        banking_transaction_policy_profile_json=json.dumps(
            {
                "base_decision": "allow",
                "dependencies_healthy": True,
                "degraded_behavior": "block",
                "policy_snapshot_id": "bank-policy-v1",
                "approved_ai_system_ids": ["foundry-bank-agent"],
                "approved_tools": {
                    "get_account_summary": {
                        "version": "1.0.0",
                        "schema_fingerprint": "a" * 64,
                        "target_binding": {
                            "account_argument": "account_id",
                            "resource": "bank.customer/current/summary",
                            "resource_type": "account",
                            "operation": "read_summary",
                            "customer_source": "signed_subject",
                        },
                    }
                },
                "approved_destinations": ["bank-core.internal"],
                "approved_workload_identities": ["foundry-managed-identity"],
                "approved_workload_identity_types": ["project_managed_identity"],
                "approved_workload_authentication_modes": ["managed_identity"],
                "approved_operation_types": ["read_summary"],
                "allowed_purpose_ids": ["own-account-summary"],
            }
        ),
    )
    values.update(overrides)
    return values


def test_banking_feature_requires_decision_execution_receipts() -> None:
    with pytest.raises(
        ValidationError,
        match="BANKING_TRANSACTION_INTEGRITY_ENABLED requires",
    ):
        Settings(
            **_base_settings(
                banking_transaction_integrity_enabled=True,
                banking_subject_pseudonymization_key=(
                    "bank-settings-pseudonymization-key-00000001"
                ),
            )
        )


def test_banking_feature_accepts_separate_trust_and_policy_material() -> None:
    configured = Settings(**_enabled_settings())

    assert configured.banking_transaction_integrity_enabled is True
    assert configured.banking_subject_pseudonymization_key.startswith("bank-settings-")


@pytest.mark.parametrize(
    "overrides",
    (
        {"banking_subject_pseudonymization_key": "short"},
        {"banking_subject_trust_json": "{}"},
        {"banking_transaction_policy_profile_json": "{}"},
        {
            "banking_transaction_policy_profile_json": json.dumps(
                {"base_decision": "allow"}
            )
        },
        {
            "banking_transaction_policy_profile_json": json.dumps(
                {
                    **json.loads(
                        str(_enabled_settings()["banking_transaction_policy_profile_json"])
                    ),
                    "approved_tools": {
                        "get_account_summary": {
                            "version": "1.0.0",
                            "schema_fingerprint": "a" * 64,
                        }
                    },
                }
            )
        },
        {"banking_subject_trust_json": "not-json"},
    ),
)
def test_banking_feature_rejects_incomplete_trust_configuration(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        Settings(**_enabled_settings(**overrides))
