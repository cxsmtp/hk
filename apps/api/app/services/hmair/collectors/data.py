from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class DataAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_data_ai"
    collector_id = "phase2-data-ai-metadata"
    source_surface = SourceSurface.DATABASE
    supported_target = DiscoveryTargetType.DATABASE_PLATFORM
    passive_capabilities = (
        "Vector index RAG knowledge prompt and memory store metadata",
    )
    permissions_required = ("Database catalog metadata read permissions",)
    limitations = (
        "Does not read database rows vectors documents prompts or source data",
        "Metadata presence does not prove an active AI relationship",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["DataAIDiscoveryCollector"]
