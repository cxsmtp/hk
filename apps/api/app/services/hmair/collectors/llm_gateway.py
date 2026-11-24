from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class LLMGatewayPathCollector(PathNativeCollector):
    collector_type = "phase2_llm_gateway"
    collector_id = "phase2-llm-gateway-existing-telemetry"
    source_surface = SourceSurface.MODEL_ENDPOINT
    supported_target = DiscoveryTargetType.LLM_GATEWAY
    passive_capabilities = (
        "model route metadata",
        "request and token aggregates",
        "direct provider bypass metadata",
    )
    permissions_required = ("existing LLM Gateway telemetry",)
    limitations = (
        "Does not retain prompt response token credential or raw request content",
        "Model identity remains unknown when provider telemetry does not expose it",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["LLMGatewayPathCollector"]
