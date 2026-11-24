from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class RepositoryAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_repository_ai"
    collector_id = "phase2-repository-ai-metadata"
    source_surface = SourceSurface.SOURCE_CODE
    supported_target = DiscoveryTargetType.REPOSITORY
    passive_capabilities = (
        "AI dependency endpoint MCP prompt config agent workflow and IaC metadata",
    )
    permissions_required = ("Authorized repository metadata read permissions",)
    limitations = (
        "Stores paths hashes dependencies and bounded safe metadata only",
        "Does not copy complete proprietary files prompts or source code",
        "Static references do not prove deployment or usage",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["RepositoryAIDiscoveryCollector"]
