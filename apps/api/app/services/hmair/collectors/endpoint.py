from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class EndpointPathCollector(PathNativeCollector):
    collector_type = "phase2_endpoint"
    collector_id = "phase2-endpoint-existing-telemetry"
    source_surface = SourceSurface.ENDPOINT
    supported_target = DiscoveryTargetType.ENDPOINT_GROUP
    passive_capabilities = (
        "installed application metadata",
        "process metadata",
        "package and runtime metadata",
    )
    permissions_required = ("existing endpoint telemetry",)
    limitations = (
        "Does not read prompts credentials histories arbitrary files or source content",
        "Installed metadata does not prove usage",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["EndpointPathCollector"]
