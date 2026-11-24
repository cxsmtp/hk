from app.services.hmair.collectors.path_native import PathNativeCollector
from app.services.hmair.contracts import DiscoveryTargetType, SourceSurface


class AWSAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_aws_ai"
    collector_id = "phase2-aws-ai-metadata"
    source_surface = SourceSurface.CLOUD
    supported_target = DiscoveryTargetType.CLOUD_SUBSCRIPTION
    passive_capabilities = (
        "Bedrock model agent and endpoint metadata",
        "AI relevant Lambda EKS and IAM context",
    )
    permissions_required = ("AWS AI resource metadata read permissions",)
    limitations = (
        "Read only AI relevant metadata and not general CSPM inventory",
        "Provider usage is unknown unless usage evidence is supplied",
        "Adapter is default off until explicitly enabled",
    )


class GCPAIDiscoveryCollector(PathNativeCollector):
    collector_type = "phase2_gcp_ai"
    collector_id = "phase2-gcp-ai-metadata"
    source_surface = SourceSurface.CLOUD
    supported_target = DiscoveryTargetType.CLOUD_PROJECT
    passive_capabilities = (
        "Vertex AI model agent and endpoint metadata",
        "AI relevant GKE and service account context",
    )
    permissions_required = ("GCP AI resource metadata viewer permissions",)
    limitations = (
        "Read only AI relevant metadata and not general CSPM inventory",
        "Provider usage is unknown unless usage evidence is supplied",
        "Adapter is default off until explicitly enabled",
    )


__all__ = ["AWSAIDiscoveryCollector", "GCPAIDiscoveryCollector"]
