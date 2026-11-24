from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final, Mapping


class DeploymentFamily(StrEnum):
    BROWSER = "browser"
    ENDPOINT = "endpoint"
    RUNTIME = "runtime"
    SAAS_API = "saas_api"
    UNKNOWN = "unknown"


class HostingMode(StrEnum):
    SAAS = "saas"
    HYBRID = "hybrid"
    PRIVATE_CLOUD = "private_cloud"
    ON_PREMISES = "on_premises"
    UNKNOWN = "unknown"


class ContainmentCapability(StrEnum):
    DIRECT = "direct"
    SURFACE_LIMITED = "surface_limited"
    EXTERNAL = "external"
    NONE = "none"
    UNKNOWN = "unknown"


DEPLOYMENT_FAMILY_LABELS: Final[Mapping[DeploymentFamily, str]] = MappingProxyType(
    {
        DeploymentFamily.BROWSER: "Browser",
        DeploymentFamily.ENDPOINT: "Endpoint",
        DeploymentFamily.RUNTIME: "Runtime",
        DeploymentFamily.SAAS_API: "SaaS & APIs",
        DeploymentFamily.UNKNOWN: "Unknown",
    }
)


TECHNICAL_SURFACE_FAMILY_MAP: Final[Mapping[str, DeploymentFamily]] = MappingProxyType(
    {
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
)


def deployment_family_for_surface(surface_type: object) -> DeploymentFamily:
    """Return a family only for an exact approved technical-surface value."""

    if type(surface_type) is not str:
        return DeploymentFamily.UNKNOWN
    return TECHNICAL_SURFACE_FAMILY_MAP.get(surface_type, DeploymentFamily.UNKNOWN)


def parse_deployment_family(value: object) -> DeploymentFamily:
    """Parse an exact persisted/API family value with a conservative fallback."""

    if isinstance(value, DeploymentFamily):
        return value
    if type(value) is not str:
        return DeploymentFamily.UNKNOWN
    try:
        return DeploymentFamily(value)
    except ValueError:
        return DeploymentFamily.UNKNOWN


def parse_hosting_mode(value: object) -> HostingMode:
    """Parse hosting independently from deployment family and control posture."""

    if isinstance(value, HostingMode):
        return value
    if type(value) is not str:
        return HostingMode.UNKNOWN
    try:
        return HostingMode(value)
    except ValueError:
        return HostingMode.UNKNOWN


def translate_containment_capability(
    verified_capability: object,
    *,
    verified_external_action_path: bool = False,
    verified_external_evidence: bool = False,
) -> ContainmentCapability:
    """Translate verified capability without promoting registration or simulation.

    External containment is recognized only when the caller has independently
    verified both the integrated external action path and its action evidence.
    """

    if type(verified_capability) is not str:
        return ContainmentCapability.UNKNOWN
    if verified_capability == "end_to_end":
        return ContainmentCapability.DIRECT
    if verified_capability == "surface":
        return ContainmentCapability.SURFACE_LIMITED
    if verified_capability == "none":
        return ContainmentCapability.NONE
    if (
        verified_capability == "external"
        and verified_external_action_path is True
        and verified_external_evidence is True
    ):
        return ContainmentCapability.EXTERNAL
    return ContainmentCapability.UNKNOWN
