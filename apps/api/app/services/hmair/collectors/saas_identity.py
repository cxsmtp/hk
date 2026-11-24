from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class SaaSAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_saas_ai"
    collector_id = "phase2-saas-ai-metadata"
    source_surface = SourceSurface.SAAS
    supported_target = DiscoveryTargetType.SAAS_TENANT
    passive_capabilities = (
        "AI feature license policy bot connector and usage metadata",
    )
    permissions_required = ("Provider admin metadata read permissions",)
    limitations = (
        "License assignment and feature enablement do not prove usage",
        "Usage remains unknown when the provider omits activity telemetry",
        "Adapter is default off until explicitly enabled",
    )


class IdentityAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_identity_ai"
    collector_id = "phase2-identity-ai-metadata"
    source_surface = SourceSurface.IDENTITY
    supported_target = DiscoveryTargetType.IDENTITY_TENANT
    passive_capabilities = (
        "AI OAuth application principal identity consent and assignment metadata",
    )
    permissions_required = ("Identity directory metadata read permissions",)
    limitations = (
        "Assignments and consent prove potential access and never usage",
        "Secret values are not collected",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["IdentityAIDiscoveryCollector", "SaaSAIDiscoveryCollector"]
