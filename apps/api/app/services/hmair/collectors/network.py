from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class NetworkAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_network_ai"
    collector_id = "phase2-network-ai-metadata"
    source_surface = SourceSurface.NETWORK
    supported_target = DiscoveryTargetType.NETWORK_RANGE
    passive_capabilities = (
        "DNS SWG proxy firewall endpoint flow API gateway and mesh metadata",
    )
    permissions_required = ("Authorized network metadata feed",)
    limitations = (
        "Network traffic is evidence and not authoritative asset identity",
        "Static domains alone never identify product user purpose agent or model",
        "Payload bodies credentials and prompts are not collected",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["NetworkAIDiscoveryCollector"]
