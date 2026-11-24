from __future__ import annotations

import pytest

from app.services.deployment_family_contracts import (
    ContainmentCapability,
    DeploymentFamily,
    DEPLOYMENT_FAMILY_LABELS,
    HostingMode,
    TECHNICAL_SURFACE_FAMILY_MAP,
    deployment_family_for_surface,
    parse_deployment_family,
    parse_hosting_mode,
    translate_containment_capability,
)


EXPECTED_SURFACE_FAMILIES = {
    "browser_extension": DeploymentFamily.BROWSER,
    "browser_agent": DeploymentFamily.BROWSER,
    "managed_browser": DeploymentFamily.BROWSER,
    "browser_automation_control": DeploymentFamily.BROWSER,
    "endpoint_agent": DeploymentFamily.ENDPOINT,
    "endpoint_discovery": DeploymentFamily.ENDPOINT,
    "local_agent_telemetry": DeploymentFamily.ENDPOINT,
    "desktop_ai_control": DeploymentFamily.ENDPOINT,
    "local_ai_proxy": DeploymentFamily.ENDPOINT,
    "local_proxy": DeploymentFamily.ENDPOINT,
    "ide_companion": DeploymentFamily.ENDPOINT,
    "developer_endpoint": DeploymentFamily.ENDPOINT,
    "local_mcp_runtime": DeploymentFamily.ENDPOINT,
    "cli_agent_runtime": DeploymentFamily.ENDPOINT,
    "mdm_discovery": DeploymentFamily.ENDPOINT,
    "llm_gateway": DeploymentFamily.RUNTIME,
    "mcp_gateway": DeploymentFamily.RUNTIME,
    "sdk": DeploymentFamily.RUNTIME,
    "sdk_app_embed": DeploymentFamily.RUNTIME,
    "runtime_mesh": DeploymentFamily.RUNTIME,
    "azure_foundry": DeploymentFamily.RUNTIME,
    "azure_apim": DeploymentFamily.RUNTIME,
    "kong": DeploymentFamily.RUNTIME,
    "envoy": DeploymentFamily.RUNTIME,
    "kubernetes": DeploymentFamily.RUNTIME,
    "aks": DeploymentFamily.RUNTIME,
    "container_apps": DeploymentFamily.RUNTIME,
    "custom_agent_runtime": DeploymentFamily.RUNTIME,
    "internal_api_authorization": DeploymentFamily.RUNTIME,
    "microsoft_365": DeploymentFamily.SAAS_API,
    "copilot": DeploymentFamily.SAAS_API,
    "google_workspace": DeploymentFamily.SAAS_API,
    "slack": DeploymentFamily.SAAS_API,
    "salesforce": DeploymentFamily.SAAS_API,
    "service_now": DeploymentFamily.SAAS_API,
    "github": DeploymentFamily.SAAS_API,
    "gitlab": DeploymentFamily.SAAS_API,
    "saas_connector": DeploymentFamily.SAAS_API,
    "saas_ai_connector": DeploymentFamily.SAAS_API,
    "oauth_app_connector": DeploymentFamily.SAAS_API,
    "siem_connector": DeploymentFamily.SAAS_API,
    "webhook": DeploymentFamily.SAAS_API,
    "custom_connector": DeploymentFamily.SAAS_API,
}


class HostileString(str):
    def __new__(cls, *, target: str) -> "HostileString":
        instance = super().__new__(cls, "attacker_controlled")
        instance.target = target
        return instance

    def __hash__(self) -> int:
        return hash(self.target)

    def __eq__(self, other: object) -> bool:
        del other
        return True


def test_contract_enums_are_closed_to_the_approved_values() -> None:
    assert {member.value for member in DeploymentFamily} == {
        "browser",
        "endpoint",
        "runtime",
        "saas_api",
        "unknown",
    }
    assert {member.value for member in HostingMode} == {
        "saas",
        "hybrid",
        "private_cloud",
        "on_premises",
        "unknown",
    }
    assert {member.value for member in ContainmentCapability} == {
        "direct",
        "surface_limited",
        "external",
        "none",
        "unknown",
    }


def test_customer_labels_are_closed_complete_and_immutable() -> None:
    assert dict(DEPLOYMENT_FAMILY_LABELS) == {
        DeploymentFamily.BROWSER: "Browser",
        DeploymentFamily.ENDPOINT: "Endpoint",
        DeploymentFamily.RUNTIME: "Runtime",
        DeploymentFamily.SAAS_API: "SaaS & APIs",
        DeploymentFamily.UNKNOWN: "Unknown",
    }

    with pytest.raises(TypeError):
        DEPLOYMENT_FAMILY_LABELS[DeploymentFamily.BROWSER] = "Web"  # type: ignore[index]


def test_every_approved_technical_surface_maps_exactly_once() -> None:
    assert dict(TECHNICAL_SURFACE_FAMILY_MAP) == EXPECTED_SURFACE_FAMILIES
    assert {
        surface: deployment_family_for_surface(surface)
        for surface in EXPECTED_SURFACE_FAMILIES
    } == EXPECTED_SURFACE_FAMILIES


def test_unrecognized_or_non_exact_surface_never_receives_a_family() -> None:
    for value in (
        None,
        "",
        "unknown",
        "LLM_GATEWAY",
        " llm_gateway",
        "llm_gateway ",
        "llm-gateway",
        "my_llm_gateway",
        "browser_extension_v2",
        object(),
    ):
        assert deployment_family_for_surface(value) is DeploymentFamily.UNKNOWN


def test_surface_mapping_rejects_hostile_string_subclasses_before_lookup() -> None:
    value = HostileString(target="llm_gateway")

    assert deployment_family_for_surface(value) is DeploymentFamily.UNKNOWN


def test_family_and_hosting_parsers_accept_only_exact_closed_values() -> None:
    assert parse_deployment_family("browser") is DeploymentFamily.BROWSER
    assert parse_deployment_family(DeploymentFamily.RUNTIME) is DeploymentFamily.RUNTIME
    assert parse_hosting_mode("private_cloud") is HostingMode.PRIVATE_CLOUD
    assert parse_hosting_mode(HostingMode.HYBRID) is HostingMode.HYBRID

    for value in (None, "", "Browser", " browser", "air_gapped", object()):
        assert parse_deployment_family(value) is DeploymentFamily.UNKNOWN
    for value in (None, "", "SaaS", "on-premises", "air_gapped", object()):
        assert parse_hosting_mode(value) is HostingMode.UNKNOWN


def test_family_parser_rejects_hostile_string_subclasses_before_lookup() -> None:
    value = HostileString(target="browser")

    assert parse_deployment_family(value) is DeploymentFamily.UNKNOWN


def test_hosting_parser_rejects_hostile_string_subclasses_before_lookup() -> None:
    value = HostileString(target="saas")

    assert parse_hosting_mode(value) is HostingMode.UNKNOWN


def test_verified_native_containment_translates_conservatively() -> None:
    assert translate_containment_capability("end_to_end") is ContainmentCapability.DIRECT
    assert translate_containment_capability("surface") is ContainmentCapability.SURFACE_LIMITED
    assert translate_containment_capability("none") is ContainmentCapability.NONE

    for value in (None, "", "unknown", "END_TO_END", "registration", "simulation", object()):
        assert translate_containment_capability(value) is ContainmentCapability.UNKNOWN


def test_external_containment_requires_both_verified_path_and_evidence() -> None:
    assert (
        translate_containment_capability(
            "external",
            verified_external_action_path=True,
            verified_external_evidence=True,
        )
        is ContainmentCapability.EXTERNAL
    )

    for path_verified, evidence_verified in (
        (False, False),
        (True, False),
        (False, True),
    ):
        assert (
            translate_containment_capability(
                "external",
                verified_external_action_path=path_verified,
                verified_external_evidence=evidence_verified,
            )
            is ContainmentCapability.UNKNOWN
        )


def test_truthy_registration_or_simulation_values_do_not_verify_external_control() -> None:
    assert (
        translate_containment_capability(
            "external",
            verified_external_action_path="registered",  # type: ignore[arg-type]
            verified_external_evidence="simulated",  # type: ignore[arg-type]
        )
        is ContainmentCapability.UNKNOWN
    )


def test_non_string_equality_spoof_cannot_grant_containment() -> None:
    class EqualitySpoof:
        def __eq__(self, other: object) -> bool:
            del other
            return True

    assert (
        translate_containment_capability(
            EqualitySpoof(),
            verified_external_action_path=True,
            verified_external_evidence=True,
        )
        is ContainmentCapability.UNKNOWN
    )
