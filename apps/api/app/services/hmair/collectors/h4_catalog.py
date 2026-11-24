"""Closed HMAIR H4 metadata collector profile catalog.

Profiles describe bounded, customer-authorised metadata collection.  They are
configuration only: profile or adapter presence is never evidence of a live
connection, completed collection, or estate coverage.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Literal

from pydantic import Field

from app.services.hmair.contracts import (
    DiscoveryTargetType,
    ObservationType,
    SourceSurface,
    StrictContract,
)


H4CollectorFamily = Literal[
    "managed_ai",
    "kubernetes",
    "saas",
    "identity",
    "repository_ci",
    "network",
    "api_catalog",
    "data_platform",
]
H4ConnectionMode = Literal[
    "typed_direct",
    "existing_connector",
    "attested_metadata_feed",
]


class H4CollectorProfile(StrictContract):
    profile_id: str = Field(min_length=1, max_length=64)
    family: H4CollectorFamily
    provider: str = Field(min_length=1, max_length=64)
    target_type: DiscoveryTargetType
    source_surface: SourceSurface
    observation_types: tuple[ObservationType, ...] = Field(min_length=1, max_length=16)
    active_capabilities: tuple[str, ...] = ()
    passive_capabilities: tuple[str, ...] = Field(min_length=1, max_length=16)
    permissions_required: tuple[str, ...] = Field(min_length=1, max_length=16)
    sensitive_data_accessed: tuple[str, ...] = ()
    privacy_exclusions: tuple[str, ...] = Field(min_length=1, max_length=16)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=16)
    denominator_behavior: str = Field(min_length=1, max_length=160)
    data_residency: str = Field(min_length=1, max_length=128)
    supported_connection_modes: tuple[H4ConnectionMode, ...] = Field(
        min_length=1, max_length=3
    )
    connector_provider_keys: tuple[str, ...] = Field(default=(), max_length=16)
    evidence_strength: Literal["source_metadata_pending_completion"] = (
        "source_metadata_pending_completion"
    )
    control_capability: Literal["monitor_only"] = "monitor_only"


_PRIVACY_EXCLUSIONS = (
    "raw_prompts",
    "raw_responses",
    "source_code",
    "file_content",
    "database_rows",
    "vector_content",
    "authentication_material",
    "private_material",
)
_LIMITATIONS = (
    "adapter_presence_is_not_coverage",
    "customer_owned_connection_required",
    "live_completion_receipt_required",
    "metadata_only",
    "unknown_without_current_source_evidence",
)
_DENOMINATOR = (
    "Customer-authorised source inventory is the denominator; absent, stale, or "
    "partial source inventory remains unknown."
)
_RESIDENCY = "tenant_region_or_customer_selected_source_region"


def _profile(
    profile_id: str,
    family: H4CollectorFamily,
    provider: str,
    target_type: DiscoveryTargetType,
    source_surface: SourceSurface,
    observation_types: tuple[ObservationType, ...],
    passive_capabilities: tuple[str, ...],
    permissions_required: tuple[str, ...],
    *,
    modes: tuple[H4ConnectionMode, ...] = ("attested_metadata_feed",),
    connector_provider_keys: tuple[str, ...] = (),
) -> H4CollectorProfile:
    return H4CollectorProfile(
        profile_id=profile_id,
        family=family,
        provider=provider,
        target_type=target_type,
        source_surface=source_surface,
        observation_types=observation_types,
        passive_capabilities=passive_capabilities,
        permissions_required=permissions_required,
        privacy_exclusions=_PRIVACY_EXCLUSIONS,
        limitations=_LIMITATIONS,
        denominator_behavior=_DENOMINATOR,
        data_residency=_RESIDENCY,
        supported_connection_modes=modes,
        connector_provider_keys=connector_provider_keys,
    )


H4_COLLECTOR_PROFILES = (
    _profile(
        "azure_managed_ai", "managed_ai", "azure", DiscoveryTargetType.CLOUD_SUBSCRIPTION,
        SourceSurface.CLOUD, (ObservationType.MODEL_DEPLOYMENT, ObservationType.AGENT_RESOURCE),
        ("Managed AI resource inventory", "Deployment and agent relationships"),
        ("Azure AI resource metadata reader",), modes=("existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("azure_openai", "microsoft_foundry"),
    ),
    _profile(
        "aws_managed_ai", "managed_ai", "aws", DiscoveryTargetType.CLOUD_SUBSCRIPTION,
        SourceSurface.CLOUD, (ObservationType.MODEL_DEPLOYMENT, ObservationType.AGENT_RESOURCE),
        ("Managed AI resource inventory", "Deployment and agent relationships"),
        ("AWS AI resource metadata reader",), modes=("existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("aws",),
    ),
    _profile(
        "gcp_managed_ai", "managed_ai", "gcp", DiscoveryTargetType.CLOUD_PROJECT,
        SourceSurface.CLOUD, (ObservationType.MODEL_DEPLOYMENT, ObservationType.AGENT_RESOURCE),
        ("Managed AI resource inventory", "Deployment and agent relationships"),
        ("GCP AI resource metadata viewer",), modes=("attested_metadata_feed",),
    ),
    _profile(
        "kubernetes_ai_workloads", "kubernetes", "kubernetes", DiscoveryTargetType.KUBERNETES_CLUSTER,
        SourceSurface.KUBERNETES, (ObservationType.AGENT_RESOURCE, ObservationType.MODEL_CONFIG, ObservationType.MCP_SERVER),
        ("AI workload inventory", "Runtime and service relationship metadata"),
        ("Kubernetes workload metadata reader",),
    ),
    _profile(
        "microsoft365_ai", "saas", "microsoft365", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.LICENSE_ASSIGNMENT, ObservationType.ACTIVE_USER),
        ("AI feature and licence inventory", "Bounded activity metadata"),
        ("Microsoft Graph approved metadata scopes",), modes=("typed_direct", "existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("microsoft_365", "outlook", "teams", "onedrive_sharepoint", "office_apps", "power_platform"),
    ),
    _profile(
        "github_ai", "saas", "github", DiscoveryTargetType.REPOSITORY_ORG,
        SourceSurface.SOURCE_CODE, (ObservationType.AI_SAAS_FEATURE, ObservationType.ACTIVE_USER, ObservationType.AGENT_CONFIG),
        ("AI feature and seat inventory", "Repository-scoped configuration metadata"),
        ("GitHub App approved metadata permissions",), modes=("typed_direct", "attested_metadata_feed"),
    ),
    _profile(
        "google_workspace_ai", "saas", "google_workspace", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.LICENSE_ASSIGNMENT, ObservationType.ACTIVE_USER),
        ("AI feature and licence inventory", "Bounded activity metadata"),
        ("Google Workspace approved metadata scopes",), modes=("existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("google_workspace", "gmail"),
    ),
    _profile(
        "slack_ai", "saas", "slack", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.ACTIVE_USER),
        ("AI feature inventory", "Bounded activity metadata"), ("Slack approved metadata scopes",),
        modes=("existing_connector", "attested_metadata_feed"), connector_provider_keys=("slack",),
    ),
    _profile(
        "salesforce_ai", "saas", "salesforce", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.AGENT_RESOURCE),
        ("AI feature inventory", "Agent and integration metadata"), ("Salesforce approved metadata scopes",),
    ),
    _profile(
        "servicenow_ai", "saas", "servicenow", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.AGENT_RESOURCE),
        ("AI feature inventory", "Agent and integration metadata"), ("ServiceNow approved metadata scopes",),
    ),
    _profile(
        "atlassian_ai", "saas", "atlassian", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.ACTIVE_USER),
        ("AI feature inventory", "Bounded activity metadata"), ("Atlassian approved metadata scopes",),
        modes=("existing_connector", "attested_metadata_feed"), connector_provider_keys=("jira",),
    ),
    _profile(
        "notion_ai", "saas", "notion", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.ACTIVE_USER),
        ("AI feature inventory", "Bounded activity metadata"), ("Notion approved metadata scopes",),
    ),
    _profile(
        "zoom_ai", "saas", "zoom", DiscoveryTargetType.SAAS_TENANT,
        SourceSurface.SAAS, (ObservationType.AI_SAAS_FEATURE, ObservationType.ACTIVE_USER),
        ("AI feature inventory", "Bounded activity metadata"), ("Zoom approved metadata scopes",),
    ),
    _profile(
        "entra_ai_identity", "identity", "entra", DiscoveryTargetType.IDENTITY_TENANT,
        SourceSurface.IDENTITY, (ObservationType.OAUTH_APP, ObservationType.SERVICE_PRINCIPAL, ObservationType.MANAGED_IDENTITY),
        ("AI application identity inventory", "Assignment and ownership metadata"),
        ("Entra directory metadata reader",), modes=("existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("entra_id",),
    ),
    _profile(
        "okta_ai_identity", "identity", "okta", DiscoveryTargetType.IDENTITY_TENANT,
        SourceSurface.IDENTITY, (ObservationType.OAUTH_APP, ObservationType.SERVICE_PRINCIPAL),
        ("AI application identity inventory", "Assignment and ownership metadata"),
        ("Okta application metadata reader",),
    ),
    _profile(
        "google_ai_identity", "identity", "google_identity", DiscoveryTargetType.IDENTITY_TENANT,
        SourceSurface.IDENTITY, (ObservationType.OAUTH_APP, ObservationType.SERVICE_PRINCIPAL),
        ("AI application identity inventory", "Assignment and ownership metadata"),
        ("Google identity application metadata reader",),
    ),
    _profile(
        "repository_ai_metadata", "repository_ci", "repository", DiscoveryTargetType.REPOSITORY_ORG,
        SourceSurface.SOURCE_CODE, (ObservationType.SDK_DEPENDENCY, ObservationType.PACKAGE_REFERENCE, ObservationType.PROMPT_CONFIG, ObservationType.AGENT_CONFIG, ObservationType.TOOL_CONFIG, ObservationType.MODEL_CONFIG),
        ("AI dependency and configuration inventory", "Repository relationship metadata"),
        ("Repository metadata reader",), modes=("existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("checkmarx",),
    ),
    _profile(
        "cicd_ai_metadata", "repository_ci", "cicd", DiscoveryTargetType.REPOSITORY_ORG,
        SourceSurface.CI_CD, (ObservationType.PACKAGE_REFERENCE, ObservationType.AI_ENDPOINT_REFERENCE, ObservationType.AGENT_CONFIG),
        ("AI build integration inventory", "Pipeline relationship metadata"),
        ("CI configuration metadata reader",),
    ),
    _profile(
        "dns_ai_metadata", "network", "dns", DiscoveryTargetType.DNS_DOMAIN,
        SourceSurface.DNS, (ObservationType.DNS_LOOKUP,), ("AI destination lookup metadata",),
        ("Approved DNS telemetry reader",),
    ),
    _profile(
        "swg_ai_metadata", "network", "swg", DiscoveryTargetType.NETWORK_RANGE,
        SourceSurface.NETWORK, (ObservationType.NETWORK_FLOW,), ("AI destination flow metadata",),
        ("Secure web gateway metadata reader",), modes=("existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("netskope", "zscaler"),
    ),
    _profile(
        "proxy_ai_metadata", "network", "proxy", DiscoveryTargetType.NETWORK_RANGE,
        SourceSurface.NETWORK, (ObservationType.NETWORK_FLOW,), ("AI destination flow metadata",),
        ("Proxy metadata reader",),
    ),
    _profile(
        "firewall_ai_metadata", "network", "firewall", DiscoveryTargetType.NETWORK_RANGE,
        SourceSurface.NETWORK, (ObservationType.NETWORK_FLOW,), ("AI destination flow metadata",),
        ("Firewall metadata reader",), modes=("existing_connector", "attested_metadata_feed"),
        connector_provider_keys=("fortinet",),
    ),
    _profile(
        "flow_ai_metadata", "network", "flow", DiscoveryTargetType.NETWORK_RANGE,
        SourceSurface.NETWORK, (ObservationType.NETWORK_FLOW,), ("AI destination flow metadata",),
        ("Network flow metadata reader",),
    ),
    _profile(
        "api_gateway_ai_metadata", "network", "api_gateway", DiscoveryTargetType.API_GATEWAY,
        SourceSurface.API_GATEWAY, (ObservationType.API_CALL, ObservationType.AI_ENDPOINT_REFERENCE),
        ("AI route and endpoint inventory", "Bounded request metadata"),
        ("API gateway metadata reader",),
    ),
    _profile(
        "service_mesh_ai_metadata", "network", "service_mesh", DiscoveryTargetType.KUBERNETES_CLUSTER,
        SourceSurface.SERVICE_MESH, (ObservationType.NETWORK_FLOW, ObservationType.AI_ENDPOINT_REFERENCE),
        ("AI service route inventory", "Workload relationship metadata"),
        ("Service mesh metadata reader",),
    ),
    _profile(
        "api_catalog_ai_metadata", "api_catalog", "api_catalog", DiscoveryTargetType.API_GATEWAY,
        SourceSurface.API_GATEWAY, (ObservationType.AI_ENDPOINT_REFERENCE, ObservationType.API_CALL),
        ("AI API catalog inventory", "Ownership and route metadata"),
        ("API catalog metadata reader",),
    ),
    _profile(
        "database_ai_metadata", "data_platform", "database", DiscoveryTargetType.DATABASE_PLATFORM,
        SourceSurface.DATABASE, (ObservationType.MODEL_CONFIG, ObservationType.VECTOR_DB_REFERENCE),
        ("AI database integration inventory", "Configuration relationship metadata"),
        ("Database catalog metadata reader",),
    ),
    _profile(
        "vector_store_ai_metadata", "data_platform", "vector_store", DiscoveryTargetType.DATABASE_PLATFORM,
        SourceSurface.VECTOR_STORE, (ObservationType.VECTOR_DB_REFERENCE,),
        ("Vector store inventory", "Index relationship metadata"),
        ("Vector store catalog metadata reader",),
    ),
    _profile(
        "search_rag_knowledge_metadata", "data_platform", "rag", DiscoveryTargetType.DATABASE_PLATFORM,
        SourceSurface.DATABASE, (ObservationType.RAG_INDEX,),
        ("Search and RAG index inventory", "Knowledge source relationship metadata"),
        ("Search catalog metadata reader",),
    ),
    _profile(
        "prompt_registry_metadata", "data_platform", "prompt_registry", DiscoveryTargetType.AI_PROVIDER_ACCOUNT,
        SourceSurface.MODEL_ENDPOINT, (ObservationType.PROMPT_CONFIG,),
        ("Prompt registry entry inventory", "Version and ownership metadata"),
        ("Prompt registry metadata reader",),
    ),
    _profile(
        "memory_store_metadata", "data_platform", "memory_store", DiscoveryTargetType.DATABASE_PLATFORM,
        SourceSurface.DATABASE, (ObservationType.TOOL_CONFIG, ObservationType.RAG_INDEX),
        ("Agent memory store inventory", "Retention and ownership metadata"),
        ("Memory store catalog metadata reader",),
    ),
)

_PROFILE_BY_ID = MappingProxyType(
    {profile.profile_id: profile for profile in H4_COLLECTOR_PROFILES}
)
H4_CONNECTOR_TARGET_TYPES = MappingProxyType(
    {
        provider_key: profile.target_type.value
        for profile in H4_COLLECTOR_PROFILES
        for provider_key in profile.connector_provider_keys
    }
)


def get_h4_collector_profile(profile_id: str) -> H4CollectorProfile:
    try:
        return _PROFILE_BY_ID[profile_id]
    except KeyError:
        raise LookupError("H4 collector profile is not registered") from None


__all__ = [
    "H4CollectorProfile",
    "H4_COLLECTOR_PROFILES",
    "H4_CONNECTOR_TARGET_TYPES",
    "get_h4_collector_profile",
]
