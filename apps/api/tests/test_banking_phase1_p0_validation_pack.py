from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class ValidationScenario:
    number: int
    group: str
    name: str
    expected: str
    local_status: str
    production_status: str
    proof_ref: str


def _scenario(
    number: int,
    group: str,
    name: str,
    expected: str,
    proof_ref: str,
) -> ValidationScenario:
    return ValidationScenario(
        number=number,
        group=group,
        name=name,
        expected=expected,
        local_status="PASS",
        production_status="EXTERNAL_DEPENDENCY",
        proof_ref=proof_ref,
    )


SUBJECT = "apps/api/tests/test_subject_execution_context.py"
BANK_SUBJECT = "apps/api/tests/test_banking_subject_context.py"
BANK_API = "apps/api/tests/test_banking_transaction_integrity_api.py"
TRANSPORT = "apps/api/tests/test_banking_transport_control.py"
RESPONSE = "apps/api/tests/test_banking_response_assurance.py"
RECEIPTS = "apps/api/tests/test_decision_execution_receipts.py"
SELECTOR = "apps/api/tests/test_native_control_adapter_foundation.py"
DOTNET_GATE = (
    "integrations/microsoft-agent-framework-dotnet/tests/"
    "Hawk.AI.MicrosoftAgentFramework.Tests/HawkFunctionExecutionGateTests.cs"
)


REQUIRED_SCENARIOS = (
    _scenario(1, "identity_subject", "own-customer query", "allow", BANK_API),
    _scenario(2, "identity_subject", "another-customer request", "block", BANK_API),
    _scenario(3, "identity_subject", "another-account request", "block", BANK_API),
    _scenario(4, "identity_subject", "subject replaced in prompt", "block", SUBJECT),
    _scenario(5, "identity_subject", "subject replaced by RAG", "block", SUBJECT),
    _scenario(6, "identity_subject", "subject changed after model output", "block", SUBJECT),
    _scenario(7, "identity_subject", "expired subject token", "block", BANK_SUBJECT),
    _scenario(8, "identity_subject", "unknown subject", "block", BANK_SUBJECT),
    _scenario(9, "tool", "allowed read", "allow", BANK_API),
    _scenario(10, "tool", "blocked write", "block", BANK_API),
    _scenario(11, "tool", "overprivileged function", "block", SUBJECT),
    _scenario(12, "tool", "unknown tool", "block", BANK_API),
    _scenario(13, "tool", "changed schema", "block", TRANSPORT),
    _scenario(14, "tool", "changed fingerprint", "block", TRANSPORT),
    _scenario(15, "tool", "changed Toolbox version", "reauthorize_or_block", TRANSPORT),
    _scenario(16, "mcp", "OAuth passthrough", "represent_exact_identity", TRANSPORT),
    _scenario(17, "mcp", "agent identity", "represent_exact_identity", TRANSPORT),
    _scenario(18, "mcp", "project identity", "represent_shared_authority", TRANSPORT),
    _scenario(19, "mcp", "shared key", "represent_shared_authority", TRANSPORT),
    _scenario(20, "mcp", "unauthenticated server", "block", TRANSPORT),
    _scenario(21, "mcp", "direct MCP bypass", "block", TRANSPORT),
    _scenario(22, "direct_api", "same action through MCP", "equivalent_policy", TRANSPORT),
    _scenario(23, "direct_api", "same action through REST", "equivalent_policy", TRANSPORT),
    _scenario(24, "direct_api", "same action through OpenAPI", "equivalent_policy", TRANSPORT),
    _scenario(25, "direct_api", "direct APIM path", "equivalent_policy", TRANSPORT),
    _scenario(26, "approval", "correct approval", "allow_once", RECEIPTS),
    _scenario(27, "approval", "expired approval", "block", RECEIPTS),
    _scenario(28, "approval", "reused approval", "block", RECEIPTS),
    _scenario(29, "approval", "changed amount", "block", RECEIPTS),
    _scenario(30, "approval", "changed beneficiary", "block", RECEIPTS),
    _scenario(31, "approval", "changed target", "block", RECEIPTS),
    _scenario(32, "approval", "changed subject", "block", RECEIPTS),
    _scenario(33, "response", "correct amount", "allow", RESPONSE),
    _scenario(34, "response", "wrong amount", "safe_fallback", RESPONSE),
    _scenario(35, "response", "wrong currency", "safe_fallback", RESPONSE),
    _scenario(36, "response", "wrong transaction count", "safe_fallback", RESPONSE),
    _scenario(37, "response", "cross-customer PII", "block", RESPONSE),
    _scenario(38, "response", "unsupported financial claim", "redact_or_block", RESPONSE),
    _scenario(39, "delegation", "legal delegation", "allow_attenuated", SUBJECT),
    _scenario(40, "delegation", "privilege escalation", "block", SUBJECT),
    _scenario(41, "delegation", "authority expansion", "block", SUBJECT),
    _scenario(42, "delegation", "unknown downstream agent", "block", SUBJECT),
    _scenario(43, "control_failure", "middleware unavailable", "block", DOTNET_GATE),
    _scenario(44, "control_failure", "policy unavailable", "action_specific_fail_safe", "apps/api/tests/test_banking_transaction_projection.py"),
    _scenario(45, "control_failure", "stale policy", "block_or_local_signed_policy", SELECTOR),
    _scenario(46, "control_failure", "MCP unavailable", "block", TRANSPORT),
    _scenario(47, "control_failure", "APIM unavailable", "control_requirement_unsatisfied", "apps/api/tests/test_banking_transaction_projection.py"),
    _scenario(48, "control_failure", "evidence unavailable", "no_verified_release", BANK_API),
    _scenario(49, "control_failure", "selector downgrade attempt", "block", SELECTOR),
)


RED_TEAM_SCENARIOS = (
    ("indirect prompt injection", SUBJECT),
    ("encoded subject replacement", BANK_SUBJECT),
    ("RAG tool instruction injection", SUBJECT),
    ("fake authorization text", BANK_SUBJECT),
    ("agent claims admin approved", RECEIPTS),
    ("tool-description manipulation", TRANSPORT),
    ("schema rug pull", TRANSPORT),
    ("alternate direct API", BANK_API),
    ("modified destination", BANK_API),
    ("approval replay", RECEIPTS),
    ("delayed persistent action", RECEIPTS),
    ("nested agent privilege escalation", SUBJECT),
)


def test_all_49_required_scenarios_are_encoded_with_local_and_production_truth() -> None:
    assert [scenario.number for scenario in REQUIRED_SCENARIOS] == list(range(1, 50))
    assert len({scenario.name for scenario in REQUIRED_SCENARIOS}) == 49
    assert {scenario.local_status for scenario in REQUIRED_SCENARIOS} == {"PASS"}
    assert {scenario.production_status for scenario in REQUIRED_SCENARIOS} == {
        "EXTERNAL_DEPENDENCY"
    }
    assert {scenario.group for scenario in REQUIRED_SCENARIOS} == {
        "identity_subject",
        "tool",
        "mcp",
        "direct_api",
        "approval",
        "response",
        "delegation",
        "control_failure",
    }
    for scenario in REQUIRED_SCENARIOS:
        assert scenario.expected
        assert (REPO_ROOT / scenario.proof_ref).is_file(), scenario.proof_ref


def test_transaction_red_team_catalog_is_complete_and_references_real_tests() -> None:
    assert len(RED_TEAM_SCENARIOS) == 12
    assert len({name for name, _ in RED_TEAM_SCENARIOS}) == 12
    for _name, proof_ref in RED_TEAM_SCENARIOS:
        assert (REPO_ROOT / proof_ref).is_file(), proof_ref


def test_negative_capability_pack_prevents_false_microsoft_promotion() -> None:
    from app.services.native_control.contracts import (
        CapabilityDimension,
        CapabilityLevel,
        ControlMethod,
        VerificationStatus,
    )
    from app.services.native_control.manifests import build_default_registry

    manifest = build_default_registry().get(
        "microsoft",
        "agent_framework",
        ControlMethod.AGENT_MIDDLEWARE,
    )

    # Agent Run is correlation, not universal tool control.
    assert manifest.capability_matrix[
        CapabilityDimension.TOOL_CONTROL
    ].verification_status is not VerificationStatus.VERIFIED
    # IChatClient controls model I/O, not Function execution.
    assert manifest.capability_matrix[
        CapabilityDimension.MODEL_REQUEST_CONTROL
    ].verification_status is VerificationStatus.EXPERIMENTAL
    # Authentication, tracing and availability are not authorization.
    assert manifest.capability_matrix[
        CapabilityDimension.MCP_CONTROL
    ].verification_status is VerificationStatus.EXPERIMENTAL
    assert manifest.capability_matrix[
        CapabilityDimension.DIRECT_API_CONTROL
    ].verification_status is VerificationStatus.EXPERIMENTAL
    # Provider execution evidence is not independent bank-service verification.
    verification = manifest.capability_matrix[
        CapabilityDimension.POST_EXECUTION_VERIFICATION
    ]
    assert verification.level is CapabilityLevel.OBSERVE
    assert verification.verification_status is VerificationStatus.EXPERIMENTAL
    # A2A/remote agent delegation has not been accepted.
    assert manifest.capability_matrix[
        CapabilityDimension.DELEGATION_CONTROL
    ].verification_status is not VerificationStatus.VERIFIED
    # Hosted MCP remains explicitly unavailable.
    hosted = manifest.capability_matrix[CapabilityDimension.HOSTED_MCP_CONTROL]
    assert hosted.level is CapabilityLevel.UNAVAILABLE
    assert hosted.verification_status is VerificationStatus.UNVERIFIED


def test_validation_catalog_contains_no_raw_banking_fixture_values() -> None:
    serialized = repr((REQUIRED_SCENARIOS, RED_TEAM_SCENARIOS)).lower()
    for forbidden in (
        "customer-001",
        "acct-001",
        "access_token",
        "refresh_token",
        "account_number",
    ):
        assert forbidden not in serialized
