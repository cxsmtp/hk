from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class AzureAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_azure_ai"
    collector_id = "phase2-azure-ai-metadata"
    source_surface = SourceSurface.CLOUD
    supported_target = DiscoveryTargetType.CLOUD_SUBSCRIPTION
    passive_capabilities = (
        "Foundry account project agent model and connection metadata",
        "Azure OpenAI deployment and AI Search metadata",
        "AI relevant APIM AKS Container Apps and Functions relationships",
        "Managed identity references",
    )
    permissions_required = (
        "Azure resource metadata reader",
        "Foundry project metadata reader where enabled",
    )
    limitations = (
        "Read only AI relevant metadata and relationships",
        "Does not read prompts data plane contents secrets or customer data",
        "Provider usage is unknown when Azure does not expose usage telemetry",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["AzureAIDiscoveryCollector"]
