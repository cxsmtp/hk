from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class MCPGatewayPathCollector(PathNativeCollector):
    collector_type = "phase2_mcp_gateway"
    collector_id = "phase2-mcp-existing-telemetry"
    source_surface = SourceSurface.MCP
    supported_target = DiscoveryTargetType.MCP_ENVIRONMENT
    passive_capabilities = (
        "MCP server metadata",
        "MCP tool schema fingerprints",
        "MCP call aggregate metadata",
    )
    permissions_required = ("existing MCP Gateway telemetry",)
    limitations = (
        "Does not retain raw tool arguments results credentials or prompts",
        "Unproxied MCP activity remains unknown unless corroborated by another source",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["MCPGatewayPathCollector"]
