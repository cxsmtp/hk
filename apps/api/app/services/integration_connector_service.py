from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from app.services.outbound_destination_policy import (
    OutboundDestinationPolicy,
    build_outbound_destination_policy,
    canonical_origin,
    request_with_redirect_validation,
)
from app.services.microsoft_graph_integration_service import (
    build_microsoft_admin_consent_url,
    is_microsoft_graph_provider,
    metadata_only_graph_record,
    microsoft_graph_security_profile,
    normalize_permission_mode,
    resolve_microsoft_graph_scopes,
)


@dataclass(frozen=True)
class ConnectorSpec:
    auth_method: str
    scopes: tuple[str, ...]
    data_pulled: tuple[str, ...]
    polling_cadence_minutes: int
    evidence_nodes_produced: tuple[str, ...]


@dataclass(frozen=True)
class SignalMapping:
    signal_key: str
    signal_type: str
    control_id: str
    severity: str
    evidence_signal_type: str
    drift_title: str
    endpoint: str
    list_key: str | None = None


@dataclass(frozen=True)
class ProviderDefinition:
    key: str
    display_name: str
    category: str
    supports_live_pull: bool
    base_url: str | None
    auth_mode: str
    signal_mappings: tuple[SignalMapping, ...]
    connector_spec: ConnectorSpec
    stub_reason: str = ""


@dataclass
class PullSignal:
    signal_key: str
    payload: dict[str, Any]
    observed_at: datetime


@dataclass
class NormalizedSignal:
    signal_type: str
    severity: str
    payload: dict[str, Any]
    control_id: str
    evidence_signal_type: str
    drift_title: str


@dataclass
class ConnectorPullResult:
    status: str
    is_stub: bool
    stub_reason: str
    error: str | None
    pulled_count: int
    normalized_signals: list[NormalizedSignal]


def _spec(
    *,
    auth_method: str,
    scopes: tuple[str, ...],
    data_pulled: tuple[str, ...],
    polling_cadence_minutes: int,
    evidence_nodes_produced: tuple[str, ...],
) -> ConnectorSpec:
    return ConnectorSpec(
        auth_method=auth_method,
        scopes=scopes,
        data_pulled=data_pulled,
        polling_cadence_minutes=polling_cadence_minutes,
        evidence_nodes_produced=evidence_nodes_produced,
    )


def _sailpoint_api_variant(connector_config: dict[str, Any], secrets: dict[str, Any]) -> str:
    variant = str(
        connector_config.get("api_variant")
        or connector_config.get("variant")
        or connector_config.get("mode")
        or secrets.get("api_variant")
        or ""
    ).strip().lower()
    if variant in {"iiq", "iiq_scim", "identityiq", "identityiq_scim", "scim"}:
        return "iiq_scim"
    return "identitynow_v3"


SAILPOINT_SIGNAL_MAPPINGS_IDN: tuple[SignalMapping, ...] = (
    SignalMapping(
        signal_key="identities",
        signal_type="identity.sailpoint.identities",
        control_id="CTRL-AI-IAM-001",
        severity="high",
        evidence_signal_type="connector.sailpoint.identities",
        drift_title="SailPoint identity drift",
        endpoint="/v3/identities?limit=5",
        list_key="items",
    ),
    SignalMapping(
        signal_key="access_requests",
        signal_type="identity.sailpoint.access_requests",
        control_id="CTRL-AI-IAM-001",
        severity="med",
        evidence_signal_type="connector.sailpoint.access_requests",
        drift_title="SailPoint access request anomalies",
        endpoint="/v3/access-requests?limit=5",
        list_key="items",
    ),
    SignalMapping(
        signal_key="role_assignments",
        signal_type="identity.sailpoint.role_assignments",
        control_id="CTRL-AI-IAM-001",
        severity="high",
        evidence_signal_type="connector.sailpoint.role_assignments",
        drift_title="SailPoint role assignment drift",
        endpoint="/v3/role-assignments?limit=5",
        list_key="items",
    ),
)


SAILPOINT_SIGNAL_MAPPINGS_IIQ_SCIM: tuple[SignalMapping, ...] = (
    SignalMapping(
        signal_key="identities",
        signal_type="identity.sailpoint.identities",
        control_id="CTRL-AI-IAM-001",
        severity="high",
        evidence_signal_type="connector.sailpoint.identities",
        drift_title="SailPoint IIQ identities drift",
        endpoint="/Users?startIndex=1&count=5",
        list_key="Resources",
    ),
    SignalMapping(
        signal_key="roles",
        signal_type="identity.sailpoint.roles",
        control_id="CTRL-AI-IAM-001",
        severity="high",
        evidence_signal_type="connector.sailpoint.roles",
        drift_title="SailPoint IIQ role drift",
        endpoint="/Roles?startIndex=1&count=5",
        list_key="Resources",
    ),
    SignalMapping(
        signal_key="entitlements",
        signal_type="identity.sailpoint.entitlements",
        control_id="CTRL-DLP-001",
        severity="high",
        evidence_signal_type="connector.sailpoint.entitlements",
        drift_title="SailPoint IIQ entitlement drift",
        endpoint="/Entitlements?startIndex=1&count=5",
        list_key="Resources",
    ),
    SignalMapping(
        signal_key="accounts",
        signal_type="identity.sailpoint.accounts",
        control_id="CTRL-AI-IAM-001",
        severity="med",
        evidence_signal_type="connector.sailpoint.accounts",
        drift_title="SailPoint IIQ account posture drift",
        endpoint="/Accounts?startIndex=1&count=5",
        list_key="Resources",
    ),
    SignalMapping(
        signal_key="events",
        signal_type="identity.sailpoint.events",
        control_id="CTRL-TOOL-001",
        severity="med",
        evidence_signal_type="connector.sailpoint.events",
        drift_title="SailPoint IIQ task/event anomalies",
        endpoint="/TaskResults?startIndex=1&count=5",
        list_key="Resources",
    ),
)


def _sailpoint_signal_mappings(connector_config: dict[str, Any], secrets: dict[str, Any]) -> tuple[SignalMapping, ...]:
    variant = _sailpoint_api_variant(connector_config, secrets)
    if variant == "iiq_scim":
        return SAILPOINT_SIGNAL_MAPPINGS_IIQ_SCIM
    return SAILPOINT_SIGNAL_MAPPINGS_IDN


PROVIDERS: dict[str, ProviderDefinition] = {
    "entra_id": ProviderDefinition(
        key="entra_id",
        display_name="Microsoft Entra ID",
        category="identity",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph)",
            scopes=("AuditLog.Read.All", "Directory.Read.All"),
            data_pulled=("Sign-ins", "Directory audits", "Provisioning events"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.entra.signin_risk",
                "connector.entra.directory_audit",
                "connector.entra.provisioning",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="signins",
                signal_type="identity.entra.signin_risk",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.entra.signin_risk",
                drift_title="Entra risky sign-in activity",
                endpoint="/auditLogs/signIns?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="directory_audit",
                signal_type="identity.entra.directory_audit",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.entra.directory_audit",
                drift_title="Entra directory audit drift",
                endpoint="/auditLogs/directoryAudits?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="provisioning",
                signal_type="identity.entra.provisioning",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.entra.provisioning",
                drift_title="Entra provisioning anomalies",
                endpoint="/auditLogs/provisioning?$top=5",
                list_key="value",
            ),
        ),
    ),
    "sailpoint": ProviderDefinition(
        key="sailpoint",
        display_name="SailPoint",
        category="identity",
        supports_live_pull=True,
        base_url=None,
        auth_mode="sailpoint_client_credentials",
        connector_spec=_spec(
            auth_method="IdentityNow OAuth2 client credentials OR IdentityIQ SCIM basic/api-key",
            scopes=("sp:scopes:all", "IdentityIQ SCIM role-based access"),
            data_pulled=("Identities", "Roles", "Events", "Entitlements", "Accounts"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.sailpoint.identities",
                "connector.sailpoint.roles",
                "connector.sailpoint.events",
                "connector.sailpoint.entitlements",
                "connector.sailpoint.accounts",
            ),
        ),
        signal_mappings=(
            *SAILPOINT_SIGNAL_MAPPINGS_IDN,
            *tuple(row for row in SAILPOINT_SIGNAL_MAPPINGS_IIQ_SCIM if row.signal_key != "identities"),
        ),
    ),
    "aws": ProviderDefinition(
        key="aws",
        display_name="AWS",
        category="cloud",
        supports_live_pull=True,
        base_url=None,
        auth_mode="aws_sdk",
        connector_spec=_spec(
            auth_method="AWS access key + secret key (boto3)",
            scopes=("cloudtrail:LookupEvents", "iam:ListRoles", "s3:ListAllMyBuckets"),
            data_pulled=("CloudTrail events", "IAM roles", "S3 ACL/public exposure"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.aws.cloudtrail",
                "connector.aws.iam",
                "connector.aws.s3_public",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="cloudtrail_events",
                signal_type="cloud.aws.cloudtrail.anomaly",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.aws.cloudtrail",
                drift_title="AWS CloudTrail anomaly detected",
                endpoint="cloudtrail.lookup_events",
            ),
            SignalMapping(
                signal_key="iam_roles",
                signal_type="cloud.aws.iam.role_exposure",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.aws.iam",
                drift_title="AWS IAM privilege drift",
                endpoint="iam.list_roles",
            ),
            SignalMapping(
                signal_key="s3_public_access",
                signal_type="cloud.aws.s3.public_access",
                control_id="CTRL-DLP-001",
                severity="critical",
                evidence_signal_type="connector.aws.s3_public",
                drift_title="AWS S3 public access drift",
                endpoint="s3.public_access",
            ),
        ),
    ),
    "microsoft_365": ProviderDefinition(
        key="microsoft_365",
        display_name="Microsoft 365 / SharePoint",
        category="collaboration",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph)",
            scopes=("AuditLog.Read.All", "Sites.Read.All", "Reports.Read.All"),
            data_pulled=("SharePoint activity", "Directory audit logs", "Provisioning events", "Copilot/AI usage indicators"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.m365.sharepoint.activity",
                "connector.m365.audit.unified",
                "connector.m365.exchange.activity",
                "connector.m365.ai_usage",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="sharepoint_activity",
                signal_type="saas.microsoft365.sharepoint.activity",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.m365.sharepoint.activity",
                drift_title="SharePoint activity drift",
                endpoint="/auditLogs/signIns?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="unified_audit",
                signal_type="saas.microsoft365.audit.unified",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.m365.audit.unified",
                drift_title="Microsoft 365 unified audit drift",
                endpoint="/auditLogs/directoryAudits?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="exchange_activity",
                signal_type="saas.microsoft365.exchange.activity",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.m365.exchange.activity",
                drift_title="Exchange mailbox activity drift",
                endpoint="/auditLogs/provisioning?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="ai_usage",
                signal_type="saas.microsoft365.ai_usage",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.m365.ai_usage",
                drift_title="Microsoft 365 AI/Copilot usage drift",
                endpoint="/auditLogs/signIns?$top=5&$filter=contains(appDisplayName,'Copilot')",
                list_key="value",
            ),
        ),
    ),
    "outlook": ProviderDefinition(
        key="outlook",
        display_name="Outlook / Exchange Online",
        category="collaboration",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph)",
            scopes=("AuditLog.Read.All", "Mail.ReadBasic.All"),
            data_pulled=("Mailbox activity", "Exchange audit activity", "AI-related mailbox usage"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.outlook.mail_activity",
                "connector.outlook.mailbox_rules",
                "connector.outlook.ai_usage",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="mail_activity",
                signal_type="saas.outlook.mail_activity",
                control_id="CTRL-DLP-001",
                severity="med",
                evidence_signal_type="connector.outlook.mail_activity",
                drift_title="Outlook mailbox activity drift",
                endpoint="/auditLogs/signIns?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="mailbox_rules",
                signal_type="saas.outlook.mailbox_rules",
                control_id="CTRL-TOOL-001",
                severity="med",
                evidence_signal_type="connector.outlook.mailbox_rules",
                drift_title="Outlook mailbox rules drift",
                endpoint="/auditLogs/directoryAudits?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="ai_usage",
                signal_type="saas.outlook.ai_usage",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.outlook.ai_usage",
                drift_title="Outlook AI usage drift",
                endpoint="/auditLogs/signIns?$top=5&$filter=contains(appDisplayName,'Copilot')",
                list_key="value",
            ),
        ),
    ),
    "teams": ProviderDefinition(
        key="teams",
        display_name="Microsoft Teams",
        category="collaboration",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph)",
            scopes=("AuditLog.Read.All", "ChatMessage.Read.All", "ChannelMessage.Read.All", "Files.Read.All"),
            data_pulled=("Teams chat metadata", "Teams channel activity", "Teams AI usage indicators"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.teams.chat_messages",
                "connector.teams.channel_messages",
                "connector.teams.ai_usage",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="chat_messages",
                signal_type="saas.teams.chat_messages",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.teams.chat_messages",
                drift_title="Teams chat message activity drift",
                endpoint="/chats?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="channel_messages",
                signal_type="saas.teams.channel_messages",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.teams.channel_messages",
                drift_title="Teams channel message drift",
                endpoint="/teams?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="ai_usage",
                signal_type="saas.teams.ai_usage",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.teams.ai_usage",
                drift_title="Teams AI usage drift",
                endpoint="/auditLogs/signIns?$top=5&$filter=contains(appDisplayName,'Teams')",
                list_key="value",
            ),
        ),
    ),
    "onedrive_sharepoint": ProviderDefinition(
        key="onedrive_sharepoint",
        display_name="OneDrive / SharePoint",
        category="storage",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph)",
            scopes=("AuditLog.Read.All", "Files.Read.All", "Sites.Read.All"),
            data_pulled=("OneDrive file metadata", "SharePoint site activity", "Sharing posture signals"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.onedrive.file_access",
                "connector.sharepoint.file_sharing",
                "connector.sharepoint.ai_ingestion_risk",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="onedrive_file_access",
                signal_type="saas.onedrive.file_access",
                control_id="CTRL-DLP-001",
                severity="med",
                evidence_signal_type="connector.onedrive.file_access",
                drift_title="OneDrive file access drift",
                endpoint="/me/drive/root/children?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="sharepoint_file_sharing",
                signal_type="saas.sharepoint.file_sharing",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.sharepoint.file_sharing",
                drift_title="SharePoint file sharing drift",
                endpoint="/sites?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="sharepoint_ai_ingestion_risk",
                signal_type="saas.sharepoint.ai_ingestion_risk",
                control_id="CTRL-RAG-001",
                severity="high",
                evidence_signal_type="connector.sharepoint.ai_ingestion_risk",
                drift_title="SharePoint AI ingestion risk drift",
                endpoint="/auditLogs/directoryAudits?$top=5",
                list_key="value",
            ),
        ),
    ),
    "office_apps": ProviderDefinition(
        key="office_apps",
        display_name="Office Apps (Word/Excel/PowerPoint)",
        category="productivity",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph)",
            scopes=("AuditLog.Read.All", "Files.Read.All", "Reports.Read.All"),
            data_pulled=("Copilot usage indicators", "Document activity metadata", "Office app governance posture"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.office_apps.copilot_usage",
                "connector.office_apps.document_activity",
                "connector.office_apps.sensitive_content_signal",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="copilot_usage",
                signal_type="saas.office_apps.copilot_usage",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.office_apps.copilot_usage",
                drift_title="Office Copilot usage drift",
                endpoint="/auditLogs/signIns?$top=5&$filter=contains(appDisplayName,'Copilot')",
                list_key="value",
            ),
            SignalMapping(
                signal_key="document_activity",
                signal_type="saas.office_apps.document_activity",
                control_id="CTRL-DLP-001",
                severity="med",
                evidence_signal_type="connector.office_apps.document_activity",
                drift_title="Office document activity drift",
                endpoint="/auditLogs/directoryAudits?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="sensitive_content_signal",
                signal_type="saas.office_apps.sensitive_content_signal",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.office_apps.sensitive_content_signal",
                drift_title="Office sensitive content signal drift",
                endpoint="/auditLogs/provisioning?$top=5",
                list_key="value",
            ),
        ),
    ),
    "microsoft_defender": ProviderDefinition(
        key="microsoft_defender",
        display_name="Microsoft Defender",
        category="security",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0/security",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph security API)",
            scopes=("SecurityEvents.Read.All", "AuditLog.Read.All"),
            data_pulled=("Security alerts", "Incidents", "Defender risk telemetry"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.microsoft_defender.alerts",
                "connector.microsoft_defender.incidents",
                "connector.microsoft_defender.ai_risk_signal",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="alerts",
                signal_type="security.microsoft_defender.alerts",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.microsoft_defender.alerts",
                drift_title="Microsoft Defender alert drift",
                endpoint="/alerts?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="incidents",
                signal_type="security.microsoft_defender.incidents",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.microsoft_defender.incidents",
                drift_title="Microsoft Defender incident drift",
                endpoint="/incidents?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="ai_risk_signal",
                signal_type="security.microsoft_defender.ai_risk_signal",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.microsoft_defender.ai_risk_signal",
                drift_title="Microsoft Defender AI risk signal",
                endpoint="/alerts?$top=5",
                list_key="value",
            ),
        ),
    ),
    "azure_openai": ProviderDefinition(
        key="azure_openai",
        display_name="Azure OpenAI Service",
        category="ai_platform",
        supports_live_pull=True,
        base_url=None,
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="Bearer token or API key (Azure endpoint)",
            scopes=("Cognitive Services User", "Monitoring Reader"),
            data_pulled=("Azure OpenAI deployment metadata", "API usage indicators", "Gateway routing posture"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.azure_openai.api_usage",
                "connector.azure_openai.prompt_activity",
                "connector.azure_openai.gateway_routing",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="api_usage",
                signal_type="ai.azure_openai.api_usage",
                control_id="CTRL-INPUT-001",
                severity="med",
                evidence_signal_type="connector.azure_openai.api_usage",
                drift_title="Azure OpenAI API usage drift",
                endpoint="/openai/deployments?api-version=2024-02-15-preview",
                list_key="data",
            ),
            SignalMapping(
                signal_key="prompt_activity",
                signal_type="ai.azure_openai.prompt_activity",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.azure_openai.prompt_activity",
                drift_title="Azure OpenAI prompt activity drift",
                endpoint="/openai/files?api-version=2024-02-15-preview",
                list_key="data",
            ),
            SignalMapping(
                signal_key="gateway_routing",
                signal_type="ai.azure_openai.gateway_routing",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.azure_openai.gateway_routing",
                drift_title="Azure OpenAI gateway routing posture drift",
                endpoint="/openai/deployments?api-version=2024-02-15-preview",
                list_key="data",
            ),
        ),
    ),
    "microsoft_foundry": ProviderDefinition(
        key="microsoft_foundry",
        display_name="Microsoft Azure AI Foundry",
        category="ai_platform",
        supports_live_pull=True,
        base_url=None,
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="Bearer token (Azure AI Foundry / Azure Resource Manager)",
            scopes=("Azure AI User", "Cognitive Services User", "Reader", "Monitoring Reader"),
            data_pulled=(
                "Foundry projects",
                "Foundry agents",
                "Model deployments",
                "Models",
                "Service principals and managed identities",
                "Agent tools",
                "Agent data sources",
            ),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.microsoft_foundry.projects",
                "connector.microsoft_foundry.agents",
                "connector.microsoft_foundry.deployments",
                "connector.microsoft_foundry.agent_touchpoints",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="projects",
                signal_type="ai.microsoft_foundry.projects",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.microsoft_foundry.projects",
                drift_title="Microsoft Foundry project inventory drift",
                endpoint="/projects?api-version=2025-05-01-preview",
                list_key="value",
            ),
            SignalMapping(
                signal_key="agents",
                signal_type="ai.microsoft_foundry.agents",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.microsoft_foundry.agents",
                drift_title="Microsoft Foundry agent inventory drift",
                endpoint="/agents?api-version=2025-05-01-preview",
                list_key="value",
            ),
            SignalMapping(
                signal_key="deployments",
                signal_type="ai.microsoft_foundry.deployments",
                control_id="CTRL-TOOL-001",
                severity="med",
                evidence_signal_type="connector.microsoft_foundry.deployments",
                drift_title="Microsoft Foundry model deployment drift",
                endpoint="/deployments?api-version=2025-05-01-preview",
                list_key="value",
            ),
            SignalMapping(
                signal_key="agent_touchpoints",
                signal_type="ai.microsoft_foundry.agent_touchpoints",
                control_id="CTRL-CHAIN-001",
                severity="high",
                evidence_signal_type="connector.microsoft_foundry.agent_touchpoints",
                drift_title="Microsoft Foundry agent tool/data-source touchpoint drift",
                endpoint="/agents?api-version=2025-05-01-preview",
                list_key="value",
            ),
        ),
    ),
    "power_platform": ProviderDefinition(
        key="power_platform",
        display_name="Power Platform (Power Apps / Power Automate)",
        category="productivity",
        supports_live_pull=True,
        base_url="https://graph.microsoft.com/v1.0",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token (Microsoft Graph + M365 activity signals)",
            scopes=("AuditLog.Read.All", "User.Read.All", "Files.Read.All"),
            data_pulled=("Power Platform usage indicators", "Flow/app activity metadata", "AI workflow governance signals"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.power_platform.usage",
                "connector.power_platform.flow_activity",
                "connector.power_platform.ai_workflow_risk",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="usage",
                signal_type="saas.power_platform.usage",
                control_id="CTRL-INPUT-001",
                severity="med",
                evidence_signal_type="connector.power_platform.usage",
                drift_title="Power Platform usage drift",
                endpoint="/auditLogs/signIns?$top=5&$filter=contains(appDisplayName,'Power')",
                list_key="value",
            ),
            SignalMapping(
                signal_key="flow_activity",
                signal_type="saas.power_platform.flow_activity",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.power_platform.flow_activity",
                drift_title="Power Platform flow activity drift",
                endpoint="/auditLogs/directoryAudits?$top=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="ai_workflow_risk",
                signal_type="saas.power_platform.ai_workflow_risk",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.power_platform.ai_workflow_risk",
                drift_title="Power Platform AI workflow risk signal",
                endpoint="/auditLogs/provisioning?$top=5",
                list_key="value",
            ),
        ),
    ),
    "google_workspace": ProviderDefinition(
        key="google_workspace",
        display_name="Google Workspace / Drive",
        category="collaboration",
        supports_live_pull=True,
        base_url="https://admin.googleapis.com",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token",
            scopes=(
                "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                "https://www.googleapis.com/auth/admin.reports.usage.readonly",
            ),
            data_pulled=("Admin activity", "Drive activity", "Login activity"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.gworkspace.admin_activity",
                "connector.gworkspace.drive_activity",
                "connector.gworkspace.login_activity",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="admin_activity",
                signal_type="saas.google_workspace.admin_activity",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.gworkspace.admin_activity",
                drift_title="Google Workspace admin activity drift",
                endpoint="/admin/reports/v1/activity/users/all/applications/admin?maxResults=5",
                list_key="items",
            ),
            SignalMapping(
                signal_key="drive_activity",
                signal_type="saas.google_workspace.drive_activity",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.gworkspace.drive_activity",
                drift_title="Google Drive sharing drift",
                endpoint="/admin/reports/v1/activity/users/all/applications/drive?maxResults=5",
                list_key="items",
            ),
            SignalMapping(
                signal_key="login_activity",
                signal_type="saas.google_workspace.login_activity",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.gworkspace.login_activity",
                drift_title="Google login anomaly drift",
                endpoint="/admin/reports/v1/activity/users/all/applications/login?maxResults=5",
                list_key="items",
            ),
            SignalMapping(
                signal_key="ai_usage",
                signal_type="saas.google_workspace.ai_usage",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.gworkspace.ai_usage",
                drift_title="Google Workspace AI usage drift",
                endpoint="/admin/reports/v1/activity/users/all/applications/gmail?maxResults=5",
                list_key="items",
            ),
        ),
    ),
    "slack": ProviderDefinition(
        key="slack",
        display_name="Slack",
        category="collaboration",
        supports_live_pull=True,
        base_url="https://slack.com/api",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="Bearer API token",
            scopes=("channels:history", "search:read", "auditlogs:read"),
            data_pulled=("Workspace audit events", "Message search", "Channel activity"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.slack.audit.events",
                "connector.slack.messages.search",
                "connector.slack.ai_usage",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="audit_events",
                signal_type="saas.slack.audit_events",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.slack.audit.events",
                drift_title="Slack audit activity drift",
                endpoint="/team.accessLogs?count=5",
                list_key="logins",
            ),
            SignalMapping(
                signal_key="message_search",
                signal_type="saas.slack.message_search",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.slack.messages.search",
                drift_title="Slack message activity drift",
                endpoint="/search.messages?query=chatgpt%20OR%20claude%20OR%20gemini%20OR%20mistral&count=5",
                list_key="matches",
            ),
            SignalMapping(
                signal_key="ai_usage",
                signal_type="saas.slack.ai_usage",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.slack.ai_usage",
                drift_title="Slack AI usage drift",
                endpoint="/search.messages?query=chatgpt%20OR%20claude%20OR%20gemini%20OR%20copilot&count=5",
                list_key="matches",
            ),
        ),
    ),
    "gmail": ProviderDefinition(
        key="gmail",
        display_name="Gmail",
        category="collaboration",
        supports_live_pull=True,
        base_url="https://gmail.googleapis.com/gmail/v1/users/me",
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="OAuth2 bearer token",
            scopes=("https://www.googleapis.com/auth/gmail.readonly",),
            data_pulled=("Mailbox metadata", "Filtered messages", "AI-related patterns"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.gmail.messages.list",
                "connector.gmail.labels",
                "connector.gmail.ai_usage",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="messages",
                signal_type="saas.gmail.messages",
                control_id="CTRL-DLP-001",
                severity="med",
                evidence_signal_type="connector.gmail.messages.list",
                drift_title="Gmail message metadata drift",
                endpoint="/messages?maxResults=5",
                list_key="messages",
            ),
            SignalMapping(
                signal_key="labels",
                signal_type="saas.gmail.labels",
                control_id="CTRL-TOOL-001",
                severity="low",
                evidence_signal_type="connector.gmail.labels",
                drift_title="Gmail label posture drift",
                endpoint="/labels",
                list_key="labels",
            ),
            SignalMapping(
                signal_key="ai_usage",
                signal_type="saas.gmail.ai_usage",
                control_id="CTRL-INPUT-001",
                severity="high",
                evidence_signal_type="connector.gmail.ai_usage",
                drift_title="Gmail AI usage drift",
                endpoint="/messages?q=chatgpt+OR+claude+OR+gemini+OR+mistral&maxResults=5",
                list_key="messages",
            ),
        ),
    ),
    "jira": ProviderDefinition(
        key="jira",
        display_name="Jira",
        category="ticketing",
        supports_live_pull=True,
        base_url=None,
        auth_mode="jira_basic",
        connector_spec=_spec(
            auth_method="Basic auth (email + API token)",
            scopes=("read:jira-work", "manage:jira-configuration"),
            data_pulled=("Audit records", "Permission schemes", "Project roles"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.jira.audit.records",
                "connector.jira.permission_schemes",
                "connector.jira.project_roles",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="audit_records",
                signal_type="ticketing.jira.audit.records",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.jira.audit.records",
                drift_title="Jira audit records drift",
                endpoint="/rest/api/3/auditing/record?maxResults=5",
                list_key="records",
            ),
            SignalMapping(
                signal_key="permission_schemes",
                signal_type="ticketing.jira.permission_schemes",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.jira.permission_schemes",
                drift_title="Jira permission scheme drift",
                endpoint="/rest/api/3/permissionscheme?maxResults=5",
                list_key="permissionSchemes",
            ),
            SignalMapping(
                signal_key="project_roles",
                signal_type="ticketing.jira.project_roles",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.jira.project_roles",
                drift_title="Jira project role drift",
                endpoint="/rest/api/3/project/search?maxResults=5",
                list_key="values",
            ),
        ),
    ),
    "openai": ProviderDefinition(
        key="openai",
        display_name="OpenAI",
        category="ai_platform",
        supports_live_pull=True,
        base_url="https://api.openai.com/v1",
        auth_mode="openai_admin",
        connector_spec=_spec(
            auth_method="Admin API key / bearer token",
            scopes=("organization.usage.read", "organization.costs.read"),
            data_pulled=("Completions usage", "Embeddings usage", "Daily costs"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.openai.usage.completions",
                "connector.openai.usage.embeddings",
                "connector.openai.costs.daily",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="usage_completions",
                signal_type="ai.openai.usage.completions",
                control_id="CTRL-INPUT-001",
                severity="med",
                evidence_signal_type="connector.openai.usage.completions",
                drift_title="OpenAI completion usage drift",
                endpoint="/organization/usage/completions?limit=5",
                list_key="data",
            ),
            SignalMapping(
                signal_key="usage_embeddings",
                signal_type="ai.openai.usage.embeddings",
                control_id="CTRL-RAG-001",
                severity="med",
                evidence_signal_type="connector.openai.usage.embeddings",
                drift_title="OpenAI embeddings usage drift",
                endpoint="/organization/usage/embeddings?limit=5",
                list_key="data",
            ),
            SignalMapping(
                signal_key="costs",
                signal_type="ai.openai.costs.daily",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.openai.costs.daily",
                drift_title="OpenAI cost anomaly",
                endpoint="/organization/costs?limit=5",
                list_key="data",
            ),
        ),
    ),
    "anthropic": ProviderDefinition(
        key="anthropic",
        display_name="Anthropic / Claude",
        category="ai_platform",
        supports_live_pull=True,
        base_url="https://api.anthropic.com/v1",
        auth_mode="anthropic_key",
        connector_spec=_spec(
            auth_method="x-api-key",
            scopes=("organization:read",),
            data_pulled=("Usage telemetry", "Workspace metadata", "API key inventory"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.anthropic.usage",
                "connector.anthropic.workspace.membership",
                "connector.anthropic.keys.rotation",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="usage",
                signal_type="ai.anthropic.usage",
                control_id="CTRL-INPUT-001",
                severity="med",
                evidence_signal_type="connector.anthropic.usage",
                drift_title="Anthropic usage drift",
                endpoint="/organizations/usage?limit=5",
                list_key="data",
            ),
            SignalMapping(
                signal_key="workspace_membership",
                signal_type="ai.anthropic.workspace.membership",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.anthropic.workspace.membership",
                drift_title="Anthropic workspace membership drift",
                endpoint="/organizations/workspaces?limit=5",
                list_key="data",
            ),
            SignalMapping(
                signal_key="api_keys",
                signal_type="ai.anthropic.keys.rotation",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.anthropic.keys.rotation",
                drift_title="Anthropic API key hygiene drift",
                endpoint="/organizations/api_keys?limit=5",
                list_key="data",
            ),
        ),
    ),
    "gemini": ProviderDefinition(
        key="gemini",
        display_name="Google Gemini",
        category="ai_platform",
        supports_live_pull=True,
        base_url="https://generativelanguage.googleapis.com/v1beta",
        auth_mode="gemini_api_key",
        connector_spec=_spec(
            auth_method="x-goog-api-key",
            scopes=("generativelanguage.models.readonly",),
            data_pulled=("Model metadata", "File inventory", "Tuned model inventory"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.gemini.models",
                "connector.gemini.files",
                "connector.gemini.tuned_models",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="models",
                signal_type="ai.gemini.models",
                control_id="CTRL-INPUT-001",
                severity="med",
                evidence_signal_type="connector.gemini.models",
                drift_title="Gemini model inventory drift",
                endpoint="/models?pageSize=5",
                list_key="models",
            ),
            SignalMapping(
                signal_key="files",
                signal_type="ai.gemini.files",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.gemini.files",
                drift_title="Gemini file handling drift",
                endpoint="/files?pageSize=5",
                list_key="files",
            ),
            SignalMapping(
                signal_key="tuned_models",
                signal_type="ai.gemini.tuned_models",
                control_id="CTRL-TOOL-001",
                severity="med",
                evidence_signal_type="connector.gemini.tuned_models",
                drift_title="Gemini tuned model drift",
                endpoint="/tunedModels?pageSize=5",
                list_key="tunedModels",
            ),
        ),
    ),
    "fortinet": ProviderDefinition(
        key="fortinet",
        display_name="Fortinet",
        category="network_firewall",
        supports_live_pull=True,
        base_url=None,
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="Bearer API token",
            scopes=("read:firewall", "read:eventlog"),
            data_pulled=("Event logs", "Firewall policies", "Interface posture"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.fortinet.events",
                "connector.fortinet.policies",
                "connector.fortinet.interfaces",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="events",
                signal_type="network.fortinet.events",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.fortinet.events",
                drift_title="Fortinet event drift",
                endpoint="/api/v2/monitor/log/event?count=5",
                list_key="results",
            ),
            SignalMapping(
                signal_key="firewall_policies",
                signal_type="network.fortinet.firewall_policies",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.fortinet.policies",
                drift_title="Fortinet firewall policy drift",
                endpoint="/api/v2/cmdb/firewall/policy?vdom=root",
                list_key="results",
            ),
            SignalMapping(
                signal_key="interfaces",
                signal_type="network.fortinet.interfaces",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.fortinet.interfaces",
                drift_title="Fortinet interface drift",
                endpoint="/api/v2/monitor/system/interface?count=5",
                list_key="results",
            ),
        ),
    ),
    "netskope": ProviderDefinition(
        key="netskope",
        display_name="Netskope",
        category="network_firewall",
        supports_live_pull=True,
        base_url=None,
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="Bearer API token",
            scopes=("events:read", "alerts:read", "tenant:read"),
            data_pulled=("Security events", "Alerts", "Tenant posture"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.netskope.events",
                "connector.netskope.alerts",
                "connector.netskope.tenant",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="events",
                signal_type="network.netskope.events",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.netskope.events",
                drift_title="Netskope event drift",
                endpoint="/api/v2/events?limit=5",
                list_key="data",
            ),
            SignalMapping(
                signal_key="alerts",
                signal_type="network.netskope.alerts",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.netskope.alerts",
                drift_title="Netskope alert drift",
                endpoint="/api/v2/alerts?limit=5",
                list_key="data",
            ),
            SignalMapping(
                signal_key="tenant",
                signal_type="network.netskope.tenant_posture",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.netskope.tenant",
                drift_title="Netskope tenant posture drift",
                endpoint="/api/v2/tenant",
            ),
        ),
    ),
    "zscaler": ProviderDefinition(
        key="zscaler",
        display_name="Zscaler",
        category="network_firewall",
        supports_live_pull=True,
        base_url=None,
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="Bearer API token",
            scopes=("auditlogs.read", "firewall.read", "urlcategories.read"),
            data_pulled=("Audit logs", "Firewall rules", "URL category posture"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.zscaler.audit_logs",
                "connector.zscaler.firewall_rules",
                "connector.zscaler.url_categories",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="audit_logs",
                signal_type="network.zscaler.audit_logs",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.zscaler.audit_logs",
                drift_title="Zscaler audit log drift",
                endpoint="/api/v1/auditLogs?limit=5",
                list_key="data",
            ),
            SignalMapping(
                signal_key="firewall_rules",
                signal_type="network.zscaler.firewall_rules",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.zscaler.firewall_rules",
                drift_title="Zscaler firewall rule drift",
                endpoint="/api/v1/firewallRules?limit=5",
                list_key="list",
            ),
            SignalMapping(
                signal_key="url_categories",
                signal_type="network.zscaler.url_categories",
                control_id="CTRL-DLP-001",
                severity="med",
                evidence_signal_type="connector.zscaler.url_categories",
                drift_title="Zscaler URL category drift",
                endpoint="/api/v1/urlCategories?limit=5",
                list_key="list",
            ),
        ),
    ),
    "checkmarx": ProviderDefinition(
        key="checkmarx",
        display_name="Checkmarx One",
        category="appsec",
        supports_live_pull=True,
        base_url=None,
        auth_mode="checkmarx_one_oauth",
        connector_spec=_spec(
            auth_method="OAuth2 client credentials or API key (refresh token) via Checkmarx One IAM",
            scopes=("manage-results", "manage-projects", "manage-scans"),
            data_pulled=(
                "Scan history and status",
                "Project posture and tags",
                "SAST/SCA/KICS/DAST findings",
                "Results summary and severity counts",
                "Audit trail events",
            ),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.checkmarx.scans",
                "connector.checkmarx.projects",
                "connector.checkmarx.findings",
                "connector.checkmarx.results_summary",
                "connector.checkmarx.audit_trail",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="scans",
                signal_type="appsec.checkmarx.scans",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.checkmarx.scans",
                drift_title="Checkmarx scan posture drift",
                endpoint="/api/scans?limit=5&sort=-created_at",
                list_key="scans",
            ),
            SignalMapping(
                signal_key="projects",
                signal_type="appsec.checkmarx.projects",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.checkmarx.projects",
                drift_title="Checkmarx project posture drift",
                endpoint="/api/projects?limit=5",
                list_key="projects",
            ),
            SignalMapping(
                signal_key="findings",
                signal_type="appsec.checkmarx.findings",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.checkmarx.findings",
                drift_title="Checkmarx finding drift (SAST/SCA/KICS)",
                endpoint="/api/results?limit=10&severity=CRITICAL,HIGH",
                list_key="results",
            ),
            SignalMapping(
                signal_key="results_summary",
                signal_type="appsec.checkmarx.results_summary",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.checkmarx.results_summary",
                drift_title="Checkmarx results summary drift",
                endpoint="/api/scan-summary",
                list_key="scansSummaries",
            ),
            SignalMapping(
                signal_key="audit_trail",
                signal_type="appsec.checkmarx.audit_trail",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.checkmarx.audit_trail",
                drift_title="Checkmarx audit trail drift",
                endpoint="/api/audit?limit=5",
                list_key="items",
            ),
        ),
    ),
    "akamai": ProviderDefinition(
        key="akamai",
        display_name="Akamai API Security",
        category="api_security",
        supports_live_pull=True,
        base_url=None,
        auth_mode="bearer",
        connector_spec=_spec(
            auth_method="Bearer API token",
            scopes=("appsec:read", "config:read"),
            data_pulled=("AppSec events", "Security configs", "Security policies"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.akamai.appsec.events",
                "connector.akamai.appsec.configs",
                "connector.akamai.appsec.policies",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="appsec_events",
                signal_type="api.akamai.appsec.events",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.akamai.appsec.events",
                drift_title="Akamai AppSec event drift",
                endpoint="/appsec/v1/events?limit=5",
                list_key="events",
            ),
            SignalMapping(
                signal_key="appsec_configs",
                signal_type="api.akamai.appsec.configs",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.akamai.appsec.configs",
                drift_title="Akamai AppSec config drift",
                endpoint="/appsec/v1/configs",
                list_key="configurations",
            ),
            SignalMapping(
                signal_key="appsec_policies",
                signal_type="api.akamai.appsec.policies",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.akamai.appsec.policies",
                drift_title="Akamai AppSec policy drift",
                endpoint="/appsec/v1/security-policies",
                list_key="policies",
            ),
        ),
    ),
    "crowdstrike": ProviderDefinition(
        key="crowdstrike",
        display_name="CrowdStrike",
        category="endpoint",
        supports_live_pull=True,
        base_url="https://api.crowdstrike.com",
        auth_mode="crowdstrike_client_credentials",
        connector_spec=_spec(
            auth_method="OAuth2 client credentials",
            scopes=("detects:read", "incidents:read", "hosts:read"),
            data_pulled=("Detections", "Incidents", "Host posture"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.crowdstrike.detects",
                "connector.crowdstrike.incidents",
                "connector.crowdstrike.hosts",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="detects",
                signal_type="endpoint.crowdstrike.detects",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.crowdstrike.detects",
                drift_title="CrowdStrike detection drift",
                endpoint="/detects/queries/detects/v1?limit=5",
                list_key="resources",
            ),
            SignalMapping(
                signal_key="incidents",
                signal_type="endpoint.crowdstrike.incidents",
                control_id="CTRL-TOOL-001",
                severity="high",
                evidence_signal_type="connector.crowdstrike.incidents",
                drift_title="CrowdStrike incident drift",
                endpoint="/incidents/queries/incidents/v1?limit=5",
                list_key="resources",
            ),
            SignalMapping(
                signal_key="hosts",
                signal_type="endpoint.crowdstrike.hosts",
                control_id="CTRL-AI-IAM-001",
                severity="med",
                evidence_signal_type="connector.crowdstrike.hosts",
                drift_title="CrowdStrike host posture drift",
                endpoint="/devices/queries/devices/v1?limit=5",
                list_key="resources",
            ),
        ),
    ),
    "cyberark": ProviderDefinition(
        key="cyberark",
        display_name="CyberArk",
        category="pam",
        supports_live_pull=True,
        base_url=None,
        auth_mode="cyberark_logon",
        connector_spec=_spec(
            auth_method="CyberArk logon token or pre-issued authorization token",
            scopes=("accounts:read", "safes:read", "activities:read"),
            data_pulled=("Privileged accounts", "Safe posture", "Vault activities"),
            polling_cadence_minutes=15,
            evidence_nodes_produced=(
                "connector.cyberark.accounts",
                "connector.cyberark.safes",
                "connector.cyberark.activities",
            ),
        ),
        signal_mappings=(
            SignalMapping(
                signal_key="accounts",
                signal_type="pam.cyberark.accounts",
                control_id="CTRL-AI-IAM-001",
                severity="high",
                evidence_signal_type="connector.cyberark.accounts",
                drift_title="CyberArk account drift",
                endpoint="/api/Accounts?limit=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="safes",
                signal_type="pam.cyberark.safes",
                control_id="CTRL-DLP-001",
                severity="high",
                evidence_signal_type="connector.cyberark.safes",
                drift_title="CyberArk safe drift",
                endpoint="/api/Safes?limit=5",
                list_key="value",
            ),
            SignalMapping(
                signal_key="activities",
                signal_type="pam.cyberark.activities",
                control_id="CTRL-TOOL-001",
                severity="med",
                evidence_signal_type="connector.cyberark.activities",
                drift_title="CyberArk activity drift",
                endpoint="/api/Activities?limit=5",
                list_key="value",
            ),
        ),
    ),
}


def list_provider_catalog() -> list[dict[str, Any]]:
    catalog: list[dict[str, Any]] = []
    for provider in PROVIDERS.values():
        spec_scopes = list(provider.connector_spec.scopes)
        microsoft_meta: dict[str, Any] | None = None
        if is_microsoft_graph_provider(provider.key):
            scope_resolution = resolve_microsoft_graph_scopes(
                provider_key=provider.key,
                permission_mode=normalize_permission_mode(None),
                include_optional=True,
            )
            spec_scopes = list(scope_resolution["selected_scopes"])
            microsoft_meta = {
                "app_registration_mode": "single_tenant",
                "oauth_flow": "client_credentials",
                "default_permission_mode": scope_resolution["permission_mode"],
                "required_scopes": list(scope_resolution["required_scopes"]),
                "optional_scopes": list(scope_resolution["optional_scopes"]),
                "security_profile": microsoft_graph_security_profile(),
                "consent_url_template": "https://login.microsoftonline.com/{tenant_id}/adminconsent?client_id={client_id}&redirect_uri={redirect_uri}",
            }

        row = {
            "provider_key": provider.key,
            "display_name": provider.display_name,
            "category": provider.category,
            "supports_live_pull": provider.supports_live_pull,
            "is_stub": not provider.supports_live_pull,
            "stub_reason": provider.stub_reason,
            "connector_spec": {
                "auth_method": provider.connector_spec.auth_method,
                "scopes": spec_scopes,
                "data_pulled": list(provider.connector_spec.data_pulled),
                "polling_cadence_minutes": provider.connector_spec.polling_cadence_minutes,
                "evidence_nodes_produced": list(provider.connector_spec.evidence_nodes_produced),
            },
            "signals": [
                {
                    "signal_key": mapping.signal_key,
                    "signal_type": mapping.signal_type,
                    "control_id": mapping.control_id,
                    "severity": mapping.severity,
                    "evidence_signal_type": mapping.evidence_signal_type,
                    "modules": modules_for_signal(provider.key, mapping.signal_type),
                }
                for mapping in provider.signal_mappings
            ],
        }
        if microsoft_meta is not None:
            row["microsoft_graph"] = microsoft_meta
        catalog.append(row)
    return catalog


def _first_non_empty(data: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_records(payload: Any, list_key: str | None) -> list[dict[str, Any]]:
    def _normalize_list(items: list[Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in items:
            if isinstance(item, dict):
                out.append(item)
            elif item is not None:
                out.append({"value": item})
        return out

    if isinstance(payload, list):
        return _normalize_list(payload)
    if isinstance(payload, dict):
        if list_key and isinstance(payload.get(list_key), list):
            return _normalize_list(payload[list_key])
        for key in ("data", "value", "items", "records", "values", "resources", "results", "list", "models", "files", "tunedModels", "Resources"):
            value = payload.get(key)
            if isinstance(value, list):
                return _normalize_list(value)
        return [payload] if payload else []
    return []


HIGH_PRIVILEGE_OAUTH_SCOPE_MARKERS = (
    "directory.readwrite.all",
    "directory.read.all",
    "files.readwrite.all",
    "files.read.all",
    "sites.fullcontrol.all",
    "sites.readwrite.all",
    "sites.read.all",
    "mail.readwrite",
    "mail.read",
    "mail.send",
    "chatmessage.read.all",
    "channelmessage.read.all",
    "user.read.all",
    "securityevents.read.all",
    "offline_access",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
)
SENSITIVE_SECRET_MARKERS = (
    "secret",
    "token",
    "api_key",
    "apikey",
    "client_secret",
    "private_key",
    "password",
    "connection_string",
)


def _uniq_sorted(values: list[str]) -> list[str]:
    return sorted({str(item).strip() for item in values if str(item).strip()})


def _iter_nested_strings(value: Any) -> list[str]:
    out: list[str] = []
    stack: list[Any] = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            token = current.strip()
            if token:
                out.append(token)
        elif isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, (list, tuple, set)):
            stack.extend(list(current))
    return out


def _scope_tokens(value: Any) -> list[str]:
    out: list[str] = []
    for raw in _iter_nested_strings(value):
        normalized = raw
        for delimiter in (",", ";", "\n", "\t"):
            normalized = normalized.replace(delimiter, " ")
        for token in normalized.split(" "):
            cleaned = token.strip()
            if not cleaned:
                continue
            lowered = cleaned.lower()
            if lowered in {"openid", "profile", "email", "offline_access"}:
                out.append(cleaned)
                continue
            if "/" in cleaned or "." in cleaned:
                out.append(cleaned)
    return _uniq_sorted(out)


def _is_high_privilege_scope(scope: str) -> bool:
    token = str(scope or "").strip().lower()
    if not token:
        return False
    if any(marker in token for marker in HIGH_PRIVILEGE_OAUTH_SCOPE_MARKERS):
        return True
    if ".all" in token and any(marker in token for marker in ("read", "write", "mail", "file", "site", "directory", "chat")):
        return True
    if "readwrite" in token or "fullcontrol" in token:
        return True
    return False


def _oauth_scope_risk_score(*, scopes: list[str], high_privilege_scopes: list[str]) -> float:
    score = 0.2
    if len(scopes) >= 5:
        score += 0.1
    if high_privilege_scopes:
        score += 0.45
        score += min(0.25, 0.05 * float(len(high_privilege_scopes)))
    if any(".all" in str(scope).lower() for scope in scopes):
        score += 0.1
    return round(max(0.0, min(0.99, score)), 2)


def _extract_oauth_scopes(record: dict[str, Any]) -> list[str]:
    scope_candidates: list[Any] = [
        record.get("scope"),
        record.get("scopes"),
        record.get("oauth_scopes"),
        record.get("oauthScopes"),
        record.get("consentedScopes"),
        record.get("permissions"),
        record.get("permissionScopes"),
        record.get("delegatedScopes"),
        record.get("roles"),
        record.get("requiredResourceAccess"),
        record.get("resourceAccess"),
        record.get("modifiedProperties"),
        record.get("additionalDetails"),
    ]
    scopes: list[str] = []
    for candidate in scope_candidates:
        scopes.extend(_scope_tokens(candidate))
    return _uniq_sorted(scopes)


def _extract_oauth_users(record: dict[str, Any]) -> list[str]:
    users: list[str] = []
    direct_candidates = [
        record.get("user_id"),
        record.get("userId"),
        record.get("userPrincipalName"),
        record.get("user"),
        record.get("actor"),
        record.get("owner"),
        record.get("createdBy"),
    ]
    initiated_by = record.get("initiatedBy")
    if isinstance(initiated_by, dict):
        direct_candidates.extend(
            [
                initiated_by.get("userPrincipalName"),
                (initiated_by.get("user") or {}).get("id") if isinstance(initiated_by.get("user"), dict) else None,
                (initiated_by.get("user") or {}).get("userPrincipalName")
                if isinstance(initiated_by.get("user"), dict)
                else None,
            ]
        )
    raw_users = record.get("users")
    if isinstance(raw_users, list):
        for item in raw_users:
            if isinstance(item, dict):
                direct_candidates.extend([item.get("user_id"), item.get("userId"), item.get("email"), item.get("id")])
            else:
                direct_candidates.append(item)

    for candidate in direct_candidates:
        token = str(candidate or "").strip()
        if token:
            users.append(token)
    return _uniq_sorted(users)


def _extract_accessed_systems(record: dict[str, Any]) -> list[str]:
    systems: list[str] = []
    direct = [
        record.get("resourceDisplayName"),
        record.get("resource"),
        record.get("resource_id"),
        record.get("target_resource"),
        record.get("siteUrl"),
        record.get("site"),
        record.get("mailbox"),
        record.get("api_endpoint"),
        record.get("appDisplayName"),
        record.get("clientAppUsed"),
    ]
    for item in direct:
        token = str(item or "").strip()
        if token:
            systems.append(token)

    for key in ("targetResources", "resources", "systems", "accessedSystems"):
        payload = record.get(key)
        if isinstance(payload, list):
            for row in payload:
                if isinstance(row, dict):
                    systems.extend(
                        [
                            str(row.get("displayName") or "").strip(),
                            str(row.get("id") or "").strip(),
                            str(row.get("resource") or "").strip(),
                        ]
                    )
                else:
                    systems.append(str(row or "").strip())
    return _uniq_sorted(systems)


def _extract_sensitivity_flags(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in (
        "sensitivity_flags",
        "sensitivityFlags",
        "sensitivity",
        "classification",
        "data_classification",
        "labels",
        "riskLevel",
        "riskLevelDuringSignIn",
        "riskState",
    ):
        value = record.get(key)
        if isinstance(value, (list, tuple, set)):
            out.extend([str(item).strip() for item in value if str(item).strip()])
        else:
            token = str(value or "").strip()
            if token:
                out.append(token)
    return _uniq_sorted(out)


def _extract_named_keys(value: Any) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        names.extend([str(key).strip() for key in value.keys() if str(key).strip()])
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                token = (
                    str(item.get("name") or "").strip()
                    or str(item.get("key") or "").strip()
                    or str(item.get("id") or "").strip()
                )
                if token:
                    names.append(token)
            elif isinstance(item, str):
                token = item.strip()
                if "=" in token:
                    token = token.split("=", 1)[0].strip()
                if token:
                    names.append(token)
    elif isinstance(value, str):
        token = value.strip()
        if token:
            if "=" in token:
                token = token.split("=", 1)[0].strip()
            names.append(token)
    return _uniq_sorted(names)


def _record_has_protected_secret_context(record: dict[str, Any], sensitivity_flags: list[str]) -> bool:
    mode = str(record.get("record_mode") or "").strip().lower()
    if mode == "metadata_only":
        return True
    for key in ("content_redacted", "redacted", "masked", "encrypted", "protected"):
        value = record.get(key)
        if isinstance(value, bool) and value:
            return True
    lowered_flags = {str(item).strip().lower() for item in sensitivity_flags}
    return bool({"encrypted", "redacted", "masked", "protected"}.intersection(lowered_flags))


def _extract_secret_exposure(record: dict[str, Any]) -> dict[str, Any]:
    env_variables: list[str] = []
    for key in ("environment", "env", "env_vars", "environmentVariables", "variables"):
        env_variables.extend(_extract_named_keys(record.get(key)))
    env_variables = _uniq_sorted(env_variables)

    secrets: list[str] = []
    for key in (
        "secrets",
        "secret",
        "api_key",
        "apiKey",
        "token",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "password",
        "connection_string",
        "connectionString",
    ):
        value = record.get(key)
        if value is not None and str(value).strip():
            secrets.append(key)
            secrets.extend(_extract_named_keys(value))
    if not secrets:
        for name in env_variables:
            lowered = str(name).strip().lower()
            if any(marker in lowered for marker in SENSITIVE_SECRET_MARKERS):
                secrets.append(name)
    secrets = _uniq_sorted(secrets)

    sensitivity_flags = _extract_sensitivity_flags(record)
    unprotected = bool(secrets) and not _record_has_protected_secret_context(record, sensitivity_flags)
    return {
        "env_variables": env_variables,
        "secrets": secrets,
        "sensitivity_flags": sensitivity_flags,
        "unprotected_secrets_accessed": unprotected,
    }


def _is_new_oauth_app_event(*, record: dict[str, Any], signal_type: str) -> bool:
    blob = " ".join(
        [
            str(signal_type or ""),
            str(record.get("activityDisplayName") or ""),
            str(record.get("operationType") or ""),
            str(record.get("eventName") or ""),
            str(record.get("event_type") or ""),
            str(record.get("action") or ""),
        ]
    ).strip().lower()
    markers = (
        "consent to application",
        "grant consent",
        "oauth",
        "service principal created",
        "app registration",
        "add application",
        "application created",
        "install app",
    )
    return any(marker in blob for marker in markers)


def _is_abnormal_oauth_access(
    *,
    record: dict[str, Any],
    systems_accessed: list[str],
    secret_exposure: dict[str, Any],
) -> bool:
    explicit_flag = bool(record.get("anomaly_flag")) or bool(record.get("abnormal_access_pattern"))
    risk_blob = " ".join(
        [
            str(record.get("riskLevel") or ""),
            str(record.get("riskLevelDuringSignIn") or ""),
            str(record.get("riskState") or ""),
            str(record.get("status") or ""),
            str(record.get("failureReason") or ""),
            str(record.get("error") or ""),
        ]
    ).strip().lower()
    if explicit_flag:
        return True
    if any(marker in risk_blob for marker in ("high", "risky", "suspicious", "impossible", "anomaly", "compromised")):
        return True
    if len(systems_accessed) >= 3:
        return True
    return bool(secret_exposure.get("unprotected_secrets_accessed"))


def _extract_oauth_app(
    *,
    record: dict[str, Any],
    provider_key: str,
    signal_type: str,
    observed_at: datetime,
) -> tuple[dict[str, Any] | None, list[str]]:
    app_id = _first_non_empty(record, ["app_id", "appId", "applicationId", "servicePrincipalId", "id"])
    client_id = _first_non_empty(record, ["client_id", "clientId", "appId", "applicationId"])
    name = _first_non_empty(record, ["name", "appDisplayName", "applicationName", "clientAppUsed", "resourceDisplayName"])
    publisher = (
        _first_non_empty(record, ["publisher", "publisherName", "developer"])
        or (
            str((record.get("verifiedPublisher") or {}).get("displayName") or "").strip()
            if isinstance(record.get("verifiedPublisher"), dict)
            else None
        )
    )
    scopes = _extract_oauth_scopes(record)
    users = _extract_oauth_users(record)
    high_privilege_scopes = [scope for scope in scopes if _is_high_privilege_scope(scope)]
    if not any([app_id, client_id, name, scopes]):
        return None, []

    last_used = (
        _first_non_empty(
            record,
            [
                "last_used",
                "lastUsed",
                "lastSignInDateTime",
                "activityDateTime",
                "timestamp",
                "createdDateTime",
            ],
        )
        or observed_at.isoformat()
    )
    oauth_app = {
        "app_id": str(app_id or client_id or name or f"{provider_key}:{signal_type}").strip(),
        "name": str(name or app_id or provider_key).strip(),
        "client_id": str(client_id or app_id or "").strip() or None,
        "publisher": str(publisher or "").strip() or None,
        "scopes": scopes,
        "users": users,
        "risk_score": _oauth_scope_risk_score(scopes=scopes, high_privilege_scopes=high_privilege_scopes),
        "last_used": last_used,
    }
    return oauth_app, high_privilege_scopes


def _oauth_relationships_for_app(*, oauth_app: dict[str, Any], anomaly_flag: bool) -> list[dict[str, Any]]:
    app_id = str(oauth_app.get("app_id") or "").strip()
    if not app_id:
        return []
    scopes = [str(item).strip() for item in (oauth_app.get("scopes") or []) if str(item).strip()]
    relationships: list[dict[str, Any]] = []
    for user in oauth_app.get("users") or []:
        user_id = str(user or "").strip()
        if not user_id:
            continue
        relationships.append(
            {
                "user_id": user_id,
                "app_id": app_id,
                "scopes": scopes,
                "anomaly_flag": bool(anomaly_flag),
            }
        )
    return relationships


def _oauth_correlation_id(*, provider_key: str, app_id: str, users: list[str]) -> str:
    seed = "|".join(
        [
            str(provider_key or "").strip().lower(),
            str(app_id or "").strip().lower(),
            *[str(item).strip().lower() for item in sorted(users)[:3]],
        ]
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:40]
    return f"oauth_chain_{digest}"


def _signals_modules_doc_path() -> Path:
    return Path(__file__).resolve().parent / "integrations" / "SIGNALS_TO_MODULES.md"


@lru_cache(maxsize=1)
def _load_signal_module_map() -> dict[tuple[str, str], list[str]]:
    path = _signals_modules_doc_path()
    if not path.exists():
        return {}

    mapping: dict[tuple[str, str], list[str]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        connector, signal_type, modules_cell = cells[0], cells[1], cells[2]
        connector = connector.replace("`", "").strip()
        signal_type = signal_type.replace("`", "").strip()
        if connector.lower() in {"connector", "---"}:
            continue
        if not connector or not signal_type:
            continue
        modules: list[str] = []
        for part in modules_cell.split(","):
            cleaned = part.replace("`", "").strip()
            if cleaned:
                modules.append(cleaned)
        if modules:
            mapping[(connector, signal_type)] = modules
    return mapping


def modules_for_signal(provider_key: str, signal_type: str) -> list[str]:
    module_map = _load_signal_module_map()
    modules = module_map.get((provider_key, signal_type), [])
    return list(modules)


def list_connector_signal_coverage(provider_key: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for provider in PROVIDERS.values():
        if provider_key and provider.key != provider_key:
            continue
        for mapping in provider.signal_mappings:
            rows.append(
                {
                    "provider_key": provider.key,
                    "provider_name": provider.display_name,
                    "provider_category": provider.category,
                    "signal_key": mapping.signal_key,
                    "signal_type": mapping.signal_type,
                    "control_id": mapping.control_id,
                    "severity": mapping.severity,
                    "evidence_signal_type": mapping.evidence_signal_type,
                    "drift_title": mapping.drift_title,
                    "modules": modules_for_signal(provider.key, mapping.signal_type),
                }
            )
    rows.sort(key=lambda item: (item["control_id"], item["provider_key"], item["signal_type"]))
    return rows


def _resolve_endpoint(endpoint: str, fields: dict[str, Any]) -> str:
    resolved = endpoint
    for key, value in fields.items():
        resolved = resolved.replace("{{" + key + "}}", str(value))
    return resolved


def _monitoring_destination_source(provider_key: str) -> str:
    return "checkmarx" if provider_key == "checkmarx" else f"monitoring:{provider_key}"


def build_monitoring_destination_policy() -> OutboundDestinationPolicy:
    allowed: dict[str, list[str]] = {}
    for provider in PROVIDERS.values():
        if provider.base_url and "{{" not in provider.base_url and "}}" not in provider.base_url:
            allowed.setdefault(_monitoring_destination_source(provider.key), []).append(
                canonical_origin(provider.base_url)
            )
        if is_microsoft_graph_provider(provider.key):
            allowed.setdefault(_monitoring_destination_source(provider.key), []).append(
                "https://login.microsoftonline.com"
            )
    from app.services.checkmarx_one_service import CHECKMARX_REGIONS

    allowed["checkmarx"] = [
        origin
        for region in CHECKMARX_REGIONS.values()
        for origin in (region["api_url"], region["iam_url"])
    ]
    return build_outbound_destination_policy(allowed)


def validate_monitoring_connector_destination(
    *,
    provider_key: str,
    connector_config: dict[str, Any],
    destination_policy: OutboundDestinationPolicy | None = None,
) -> OutboundDestinationPolicy:
    policy = destination_policy or build_monitoring_destination_policy()
    provider = PROVIDERS.get(provider_key)
    if provider is None or not provider.supports_live_pull or provider.auth_mode == "aws_sdk":
        return policy
    source = _monitoring_destination_source(provider_key)
    base_url = _resolve_endpoint(
        str(connector_config.get("base_url") or provider.base_url or ""),
        connector_config,
    ).rstrip("/")
    if "{{" in base_url or "}}" in base_url:
        raise ValueError("Unresolved base_url template.")
    if not base_url:
        raise ValueError("Missing base_url configuration.")
    policy.validate(base_url, source=source)

    if is_microsoft_graph_provider(provider_key):
        tenant_id = str(connector_config.get("tenant_id") or "common").strip()
        token_url = _resolve_endpoint(
            str(
                connector_config.get("token_url")
                or f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            ),
            connector_config,
        ).strip()
        if "{{" in token_url or "}}" in token_url:
            raise ValueError("Unresolved token_url template.")
        policy.validate(token_url, source=source)
    if provider_key == "checkmarx":
        from app.services.checkmarx_one_service import CHECKMARX_REGIONS

        region = str(connector_config.get("region") or "us").strip().lower()
        defaults = CHECKMARX_REGIONS.get(region, CHECKMARX_REGIONS["us"])
        policy.validate(
            str(connector_config.get("iam_url") or defaults["iam_url"]),
            source=source,
        )
    return policy


def _oauth_client_credentials_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str | None = None,
    client_assertion: str | None = None,
    client_assertion_type: str | None = None,
    scope: str | None = None,
    destination_policy: OutboundDestinationPolicy,
    destination_source: str,
) -> str:
    form_data: dict[str, str] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
    }
    if client_secret:
        form_data["client_secret"] = client_secret
    if client_assertion:
        form_data["client_assertion"] = client_assertion
        form_data["client_assertion_type"] = (
            client_assertion_type
            or "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        )
    if not form_data.get("client_secret") and not form_data.get("client_assertion"):
        raise ValueError("OAuth token request missing client_secret or client_assertion")
    if scope:
        form_data["scope"] = scope

    response = request_with_redirect_validation(
        "POST",
        token_url,
        source=destination_source,
        policy=destination_policy,
        timeout=20.0,
        client_factory=httpx.Client,
        data=form_data,
    )
    response.raise_for_status()
    payload = response.json()
    token = str(payload.get("access_token") or "").strip()
    if not token:
        raise ValueError("OAuth token response missing access_token")
    return token


def _cyberark_logon_token(
    *,
    base_url: str,
    username: str,
    password: str,
    logon_path: str,
    destination_policy: OutboundDestinationPolicy,
    destination_source: str,
) -> str:
    response = request_with_redirect_validation(
        "POST",
        f"{base_url}{logon_path}",
        source=destination_source,
        policy=destination_policy,
        timeout=20.0,
        client_factory=httpx.Client,
        json={"username": username, "password": password},
    )
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, str):
        token = payload.strip()
    elif isinstance(payload, dict):
        token = str(payload.get("token") or payload.get("CyberArkLogonResult") or "").strip()
    else:
        token = ""
    if not token:
        raise ValueError("CyberArk logon response missing token")
    return token


def _authenticate_http(
    provider: ProviderDefinition,
    connector_config: dict[str, Any],
    secrets: dict[str, Any],
    *,
    destination_policy: OutboundDestinationPolicy,
) -> tuple[str, dict[str, str], str]:
    base_url = _resolve_endpoint(
        str(connector_config.get("base_url") or provider.base_url or ""),
        connector_config,
    ).rstrip("/")
    if not base_url:
        return "", {}, "Missing base_url configuration."
    if not base_url.lower().startswith("https://"):
        return "", {}, "Transport security violation: base_url must use HTTPS/TLS."
    destination_source = _monitoring_destination_source(provider.key)
    destination_policy.validate(base_url, source=destination_source)

    if is_microsoft_graph_provider(provider.key):
        # Prefer OAuth client credentials for enterprise Microsoft Graph deployments.
        existing_token = _first_non_empty(secrets, ["access_token", "token"])
        if existing_token:
            return base_url, {"Authorization": f"Bearer {existing_token}"}, ""

        tenant_id = _first_non_empty(secrets, ["tenant_id"]) or _first_non_empty(connector_config, ["tenant_id"])
        client_id = _first_non_empty(secrets, ["client_id"]) or _first_non_empty(connector_config, ["client_id"])
        client_secret = _first_non_empty(secrets, ["client_secret"])
        client_assertion = _first_non_empty(secrets, ["client_assertion", "client_certificate_assertion"])
        client_assertion_type = _first_non_empty(
            secrets,
            ["client_assertion_type"],
        ) or "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        if not tenant_id or not client_id or (not client_secret and not client_assertion):
            return "", {}, "Missing Microsoft Graph credentials. Provide access_token or tenant_id + client_id + (client_secret or client_assertion)."

        token_url = _resolve_endpoint(
            str(
                connector_config.get("token_url")
                or f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            ),
            connector_config,
        ).strip()
        if not token_url.lower().startswith("https://"):
            return "", {}, "Transport security violation: token_url must use HTTPS/TLS."

        token = _oauth_client_credentials_token(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            client_assertion=client_assertion,
            client_assertion_type=client_assertion_type,
            scope="https://graph.microsoft.com/.default",
            destination_policy=destination_policy,
            destination_source=destination_source,
        )
        return base_url, {"Authorization": f"Bearer {token}"}, ""

    if provider.auth_mode == "okta_token":
        token = _first_non_empty(secrets, ["api_token", "token"])
        if not token:
            return "", {}, "Missing Okta API token."
        return base_url, {"Authorization": f"SSWS {token}"}, ""

    if provider.auth_mode == "jira_basic":
        email = _first_non_empty(secrets, ["email", "username"])
        token = _first_non_empty(secrets, ["api_token", "token"])
        if not email or not token:
            return "", {}, "Missing Jira email/api_token credentials."
        auth_value = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("utf-8")
        return base_url, {"Authorization": f"Basic {auth_value}"}, ""

    if provider.auth_mode == "anthropic_key":
        api_key = _first_non_empty(secrets, ["api_key", "token"])
        if not api_key:
            return "", {}, "Missing Anthropic API key."
        return base_url, {"x-api-key": api_key, "anthropic-version": "2023-06-01"}, ""

    if provider.auth_mode == "gemini_api_key":
        api_key = _first_non_empty(secrets, ["api_key", "token"])
        if not api_key:
            return "", {}, "Missing Gemini API key."
        return base_url, {"x-goog-api-key": api_key}, ""

    if provider.auth_mode == "openai_admin":
        token = _first_non_empty(secrets, ["access_token", "api_key", "token"])
        if not token:
            return "", {}, "Missing OpenAI admin key/token."
        headers = {"Authorization": f"Bearer {token}"}
        org_id = _first_non_empty(secrets, ["organization_id", "org_id"])
        if org_id:
            headers["OpenAI-Organization"] = org_id
        return base_url, headers, ""

    if provider.auth_mode == "sailpoint_client_credentials":
        variant = _sailpoint_api_variant(connector_config, secrets)
        if variant == "iiq_scim":
            username = _first_non_empty(secrets, ["username", "user", "client_id"])
            password_or_key = _first_non_empty(secrets, ["password", "api_key", "client_secret"])
            bearer_token = _first_non_empty(secrets, ["access_token", "token", "api_key"])
            auth_scheme = str(connector_config.get("auth_scheme") or secrets.get("auth_scheme") or "").strip().lower()

            if username and password_or_key:
                basic_value = base64.b64encode(f"{username}:{password_or_key}".encode("utf-8")).decode("utf-8")
                return base_url, {"Authorization": f"Basic {basic_value}"}, ""
            if bearer_token:
                if auth_scheme == "x_api_key":
                    header_name = str(connector_config.get("api_key_header") or secrets.get("api_key_header") or "X-API-Key").strip()
                    return base_url, {header_name: bearer_token}, ""
                return base_url, {"Authorization": f"Bearer {bearer_token}"}, ""
            return "", {}, (
                "Missing SailPoint IdentityIQ SCIM credentials. Provide username+password/api_key "
                "or bearer token/api_key."
            )

        client_id = _first_non_empty(secrets, ["client_id"])
        client_secret = _first_non_empty(secrets, ["client_secret"])
        if not client_id or not client_secret:
            return "", {}, "Missing SailPoint client credentials."
        token_path = str(connector_config.get("token_path") or "/oauth/token")
        scope = _first_non_empty(secrets, ["scope"])
        token = _oauth_client_credentials_token(
            token_url=f"{base_url}{token_path}",
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            destination_policy=destination_policy,
            destination_source=destination_source,
        )
        return base_url, {"Authorization": f"Bearer {token}"}, ""

    if provider.auth_mode == "crowdstrike_client_credentials":
        client_id = _first_non_empty(secrets, ["client_id"])
        client_secret = _first_non_empty(secrets, ["client_secret"])
        if not client_id or not client_secret:
            return "", {}, "Missing CrowdStrike client credentials."
        token_path = str(connector_config.get("token_path") or "/oauth2/token")
        token = _oauth_client_credentials_token(
            token_url=f"{base_url}{token_path}",
            client_id=client_id,
            client_secret=client_secret,
            scope=None,
            destination_policy=destination_policy,
            destination_source=destination_source,
        )
        return base_url, {"Authorization": f"Bearer {token}"}, ""

    if provider.auth_mode == "checkmarx_one_oauth":
        existing_token = _first_non_empty(secrets, ["access_token", "token"])
        has_oauth_credentials = bool(
            (_first_non_empty(secrets, ["client_id"]) and _first_non_empty(secrets, ["client_secret"]))
            or _first_non_empty(secrets, ["api_key", "refresh_token"])
        )
        if existing_token and not has_oauth_credentials:
            return base_url, {"Authorization": f"Bearer {existing_token}"}, ""

        from app.services.checkmarx_one_service import create_client_from_connector_config, CheckmarxAuthError
        try:
            cx_client = create_client_from_connector_config(
                connector_config,
                secrets,
                destination_policy=destination_policy,
            )
            token = cx_client.authenticate()
            # Use the CxOne API URL as base, not the generic base_url
            return cx_client.api_url, {"Authorization": f"Bearer {token}"}, ""
        except (ValueError, CheckmarxAuthError) as exc:
            return "", {}, f"Checkmarx One authentication failed: {exc}"

    if provider.auth_mode == "cyberark_logon":
        token = _first_non_empty(secrets, ["access_token", "token"])
        if token:
            return base_url, {"Authorization": token}, ""
        username = _first_non_empty(secrets, ["username"])
        password = _first_non_empty(secrets, ["password"])
        if not username or not password:
            return "", {}, "Missing CyberArk token or username/password."
        logon_path = str(connector_config.get("logon_path") or "/PasswordVault/API/Auth/CyberArk/Logon")
        token = _cyberark_logon_token(
            base_url=base_url,
            username=username,
            password=password,
            logon_path=logon_path,
            destination_policy=destination_policy,
            destination_source=destination_source,
        )
        return base_url, {"Authorization": token}, ""

    token = _first_non_empty(secrets, ["access_token", "api_key", "token"])
    if not token:
        return "", {}, "Missing bearer token/api key."
    return base_url, {"Authorization": f"Bearer {token}"}, ""


def _pull_http_signals(
    provider: ProviderDefinition,
    *,
    connector_config: dict[str, Any],
    secrets: dict[str, Any],
    headers: dict[str, str],
    base_url: str,
    mappings: tuple[SignalMapping, ...] | None = None,
    destination_policy: OutboundDestinationPolicy,
) -> list[PullSignal]:
    output: list[PullSignal] = []
    context_fields = {**connector_config, **secrets}
    forbidden_query_markers = ("access_token=", "token=", "api_key=", "client_secret=", "password=")
    selected_mappings = mappings or provider.signal_mappings
    for mapping in selected_mappings:
        endpoint = _resolve_endpoint(mapping.endpoint, context_fields)
        endpoint_lower = endpoint.lower()
        if "?" in endpoint_lower and any(marker in endpoint_lower for marker in forbidden_query_markers):
            raise ValueError(
                f"Transport security violation for provider {provider.key}: sensitive token material in query string."
            )
        response = request_with_redirect_validation(
            "GET",
            f"{base_url}{endpoint}",
            source=_monitoring_destination_source(provider.key),
            policy=destination_policy,
            timeout=20.0,
            client_factory=httpx.Client,
            headers=headers,
        )
        response.raise_for_status()
        records = _extract_records(response.json(), mapping.list_key)
        if not records:
            continue
        output.append(
            PullSignal(
                signal_key=mapping.signal_key,
                payload=records[0],
                observed_at=datetime.now(timezone.utc),
            )
        )
    return output


def _pull_aws_signals(secrets: dict[str, Any], connector_config: dict[str, Any]) -> tuple[list[PullSignal], str | None]:
    try:
        import boto3
    except Exception:
        return [], "boto3 is not installed; unable to run AWS connector."

    access_key = _first_non_empty(secrets, ["access_key_id", "aws_access_key_id"])
    secret_key = _first_non_empty(secrets, ["secret_access_key", "aws_secret_access_key"])
    region = str(connector_config.get("region") or secrets.get("region") or "us-east-1")
    if not access_key or not secret_key:
        return [], "Missing AWS credentials (access_key_id/secret_access_key)."

    session = boto3.session.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )

    pulled: list[PullSignal] = []
    now = datetime.now(timezone.utc)

    from app.services import connector_activity

    # Connector API activity (app/services/connector_activity.py): one record per AWS API call.
    session.events.register("before-call", connector_activity.boto3_before_hook())
    session.events.register("after-call", connector_activity.boto3_hook("aws"))
    cloudtrail = session.client("cloudtrail")
    iam = session.client("iam")
    s3 = session.client("s3")

    ct = cloudtrail.lookup_events(MaxResults=5)
    ct_events = ct.get("Events") or []
    if ct_events:
        pulled.append(PullSignal(signal_key="cloudtrail_events", payload=ct_events[0], observed_at=now))

    roles = iam.list_roles(MaxItems=5)
    iam_roles = roles.get("Roles") or []
    if iam_roles:
        pulled.append(PullSignal(signal_key="iam_roles", payload=iam_roles[0], observed_at=now))

    buckets = s3.list_buckets().get("Buckets") or []
    if buckets:
        bucket_name = buckets[0].get("Name")
        acl = s3.get_bucket_acl(Bucket=bucket_name) if bucket_name else {}
        pulled.append(PullSignal(signal_key="s3_public_access", payload={"bucket": bucket_name, "acl": acl}, observed_at=now))

    return pulled, None


def run_provider_pull(
    *,
    provider_key: str,
    connector_config: dict[str, Any],
    secrets: dict[str, Any],
    destination_policy: OutboundDestinationPolicy | None = None,
) -> ConnectorPullResult:
    provider = PROVIDERS.get(provider_key)
    if provider is None:
        return ConnectorPullResult(
            status="error",
            is_stub=False,
            stub_reason="",
            error="Unknown provider key.",
            pulled_count=0,
            normalized_signals=[],
        )

    if not provider.supports_live_pull:
        return ConnectorPullResult(
            status="stub",
            is_stub=True,
            stub_reason=provider.stub_reason,
            error=None,
            pulled_count=0,
            normalized_signals=[],
        )

    pulled: list[PullSignal]
    active_mappings: tuple[SignalMapping, ...] = provider.signal_mappings
    try:
        if provider.auth_mode == "aws_sdk":
            pulled, aws_error = _pull_aws_signals(secrets, connector_config)
            if aws_error:
                return ConnectorPullResult(
                    status="error",
                    is_stub=False,
                    stub_reason="",
                    error=aws_error,
                    pulled_count=0,
                    normalized_signals=[],
                )
        else:
            policy = validate_monitoring_connector_destination(
                provider_key=provider_key,
                connector_config=connector_config,
                destination_policy=destination_policy,
            )
            base_url, headers, auth_error = _authenticate_http(
                provider,
                connector_config,
                secrets,
                destination_policy=policy,
            )
            if auth_error:
                return ConnectorPullResult(
                    status="error",
                    is_stub=False,
                    stub_reason="",
                    error=auth_error,
                    pulled_count=0,
                    normalized_signals=[],
                )
            if provider.key == "sailpoint":
                active_mappings = _sailpoint_signal_mappings(connector_config, secrets)
            pulled = _pull_http_signals(
                provider,
                connector_config=connector_config,
                secrets=secrets,
                headers=headers,
                base_url=base_url,
                destination_policy=policy,
                mappings=active_mappings,
            )
    except Exception as exc:  # noqa: BLE001
        return ConnectorPullResult(
            status="error",
            is_stub=False,
            stub_reason="",
            error=str(exc),
            pulled_count=0,
            normalized_signals=[],
        )

    mapping_by_key = {row.signal_key: row for row in active_mappings}
    normalized: list[NormalizedSignal] = []
    microsoft_permission_mode = normalize_permission_mode(connector_config.get("permission_mode"))
    microsoft_scope_resolution = None
    metadata_only_ingestion = bool(connector_config.get("metadata_only_ingestion", True))
    if is_microsoft_graph_provider(provider.key):
        microsoft_scope_resolution = resolve_microsoft_graph_scopes(
            provider_key=provider.key,
            permission_mode=microsoft_permission_mode,
            include_optional=True,
        )
    include_content_scan = bool(connector_config.get("content_scanning_enabled", False))
    content_storage_policy = str(connector_config.get("content_storage_policy") or "").strip().lower()
    content_storage_allowed = bool(
        include_content_scan
        and content_storage_policy in {"allow_preview", "policy_content_scan", "redacted_preview"}
    )

    for signal in pulled:
        mapping = mapping_by_key.get(signal.signal_key)
        if not mapping:
            continue
        raw_record_payload = signal.payload if isinstance(signal.payload, dict) else {"value": signal.payload}
        record_payload = raw_record_payload
        if is_microsoft_graph_provider(provider.key):
            record_payload = metadata_only_graph_record(
                record=record_payload,
                provider_key=provider.key,
                signal_type=mapping.signal_type,
                include_content=content_storage_allowed,
            )

        source_metadata = {
            "provider_key": provider.key,
            "provider_name": provider.display_name,
            "provider_category": provider.category,
            "auth_method": provider.connector_spec.auth_method,
            "transport_security": microsoft_graph_security_profile() if is_microsoft_graph_provider(provider.key) else {"tls_minimum": "1.2+"},
        }
        if provider.key == "sailpoint":
            source_metadata["sailpoint_api_variant"] = _sailpoint_api_variant(connector_config, secrets)
        if microsoft_scope_resolution is not None:
            source_metadata["permission_mode"] = microsoft_scope_resolution["permission_mode"]
            source_metadata["resolved_scopes"] = list(microsoft_scope_resolution["selected_scopes"])
            source_metadata["metadata_only_ingestion"] = bool(metadata_only_ingestion and not content_storage_allowed)
            source_metadata["content_storage_policy"] = (
                content_storage_policy if content_storage_allowed else "metadata_only"
            )
            tenant_id = str(connector_config.get("tenant_id") or secrets.get("tenant_id") or "").strip()
            client_id = str(connector_config.get("client_id") or secrets.get("client_id") or "").strip()
            redirect_uri = str(connector_config.get("redirect_uri") or "").strip()
            if tenant_id and client_id and redirect_uri:
                try:
                    source_metadata["admin_consent_url"] = build_microsoft_admin_consent_url(
                        tenant_id=tenant_id,
                        client_id=client_id,
                        redirect_uri=redirect_uri,
                    )
                except ValueError:
                    pass

        provider_supports_oauth_enrichment = is_microsoft_graph_provider(provider.key) or provider.key == "google_workspace"
        enrichment_record_payload = raw_record_payload if provider_supports_oauth_enrichment else record_payload
        systems_accessed = _extract_accessed_systems(enrichment_record_payload)
        secret_exposure = _extract_secret_exposure(enrichment_record_payload)
        oauth_app: dict[str, Any] | None = None
        high_privilege_scopes: list[str] = []
        oauth_relationships: list[dict[str, Any]] = []
        oauth_new_app = False
        abnormal_access_pattern = False
        if provider_supports_oauth_enrichment:
            oauth_app, high_privilege_scopes = _extract_oauth_app(
                record=enrichment_record_payload,
                provider_key=provider.key,
                signal_type=mapping.signal_type,
                observed_at=signal.observed_at,
            )
            if oauth_app is not None:
                oauth_new_app = _is_new_oauth_app_event(record=enrichment_record_payload, signal_type=mapping.signal_type)
                abnormal_access_pattern = _is_abnormal_oauth_access(
                    record=enrichment_record_payload,
                    systems_accessed=systems_accessed,
                    secret_exposure=secret_exposure,
                )
                oauth_relationships = _oauth_relationships_for_app(
                    oauth_app=oauth_app,
                    anomaly_flag=abnormal_access_pattern,
                )
                source_metadata["oauth_app_discovered"] = True
                source_metadata["oauth_app_id"] = oauth_app.get("app_id")
                source_metadata["oauth_app_risk_score"] = oauth_app.get("risk_score")

        normalized_payload: dict[str, Any] = {
            "source_metadata": source_metadata,
            "control_id": mapping.control_id,
            "signal_key": mapping.signal_key,
            "observed_at": signal.observed_at.isoformat(),
            "record": record_payload,
            "systems_accessed": systems_accessed,
            "env_variables": list(secret_exposure.get("env_variables") or []),
            "secrets": list(secret_exposure.get("secrets") or []),
            "sensitivity_flags": list(secret_exposure.get("sensitivity_flags") or []),
            "unprotected_secrets_accessed": bool(secret_exposure.get("unprotected_secrets_accessed")),
        }
        if oauth_app is not None:
            normalized_payload["oauth_app"] = oauth_app
            normalized_payload["oauth_relationships"] = oauth_relationships
            normalized_payload["high_privilege_scopes"] = high_privilege_scopes
            normalized_payload["oauth_high_risk_scopes"] = bool(high_privilege_scopes)
            normalized_payload["oauth_new_app"] = bool(oauth_new_app)
            normalized_payload["abnormal_access_pattern"] = bool(abnormal_access_pattern)
            primary_users = [str(item.get("user_id") or "").strip() for item in oauth_relationships if isinstance(item, dict)]
            primary_users = [item for item in primary_users if item]
            if primary_users and not str(normalized_payload.get("user_id") or "").strip():
                normalized_payload["user_id"] = primary_users[0]
            app_id = str(oauth_app.get("app_id") or "").strip()
            if app_id:
                correlation_id = _oauth_correlation_id(provider_key=provider.key, app_id=app_id, users=primary_users)
                normalized_payload["correlation_id"] = correlation_id
                normalized_payload["context_id"] = correlation_id
                normalized_payload["chain_id"] = correlation_id
                normalized_payload["entity_type"] = "tool"
                normalized_payload["entity_id"] = app_id
            if bool(oauth_new_app) and bool(high_privilege_scopes) and bool(abnormal_access_pattern):
                normalized_payload["reason_code"] = "oauth_supply_chain_attack"
                normalized_payload["connector_risk_exposed"] = True
            elif bool(high_privilege_scopes):
                normalized_payload["reason_code"] = "connector_risk_oauth_high_privilege_scope"
                normalized_payload["connector_risk_exposed"] = True
            normalized_payload["risk_score"] = float(oauth_app.get("risk_score") or 0.0)
        if bool(secret_exposure.get("unprotected_secrets_accessed")):
            normalized_payload["reason_code"] = str(normalized_payload.get("reason_code") or "connector_risk_unprotected_secrets")
            normalized_payload["connector_risk_exposed"] = True

        normalized.append(
            NormalizedSignal(
                signal_type=mapping.signal_type,
                severity=mapping.severity,
                payload=normalized_payload,
                control_id=mapping.control_id,
                evidence_signal_type=mapping.evidence_signal_type,
                drift_title=mapping.drift_title,
            )
        )

    return ConnectorPullResult(
        status="success",
        is_stub=False,
        stub_reason="",
        error=None,
        pulled_count=len(pulled),
        normalized_signals=normalized,
    )
