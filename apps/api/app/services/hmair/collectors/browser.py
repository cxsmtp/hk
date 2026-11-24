from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class BrowserPathCollector(PathNativeCollector):
    collector_type = "phase2_browser"
    collector_id = "phase2-browser-existing-telemetry"
    source_surface = SourceSurface.BROWSER
    supported_target = DiscoveryTargetType.BROWSER_TENANT
    passive_capabilities = (
        "AI web application usage metadata",
        "managed extension metadata",
    )
    permissions_required = ("existing browser companion telemetry",)
    limitations = (
        "Does not collect prompts cookies page bodies downloads or upload contents",
        "Personal or enterprise account state remains unknown without identity evidence",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["BrowserPathCollector"]
