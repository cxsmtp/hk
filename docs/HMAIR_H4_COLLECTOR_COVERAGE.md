# HMAIR H4 collector coverage contract

H4 defines a closed catalog of metadata-only collection profiles. A profile
describes an admissible source and its safe projection; **profile presence is not coverage**.
Live coverage requires a customer-owned connection, a current
source denominator, a successful bounded collection, and a verifiable
completion receipt.

## Profile catalog

The Permission and Metadata columns are per-profile declarations. All rows are
passive, metadata-only, monitor-only, and default-off.

| Profile | Target / surface | Acquisition | Permission | Metadata |
| --- | --- | --- | --- | --- |
| `azure_managed_ai` | Cloud subscription / Cloud | Existing connector or attested feed | Azure AI resource metadata reader | Managed AI resources, deployments, agents, relationships |
| `aws_managed_ai` | Cloud subscription / Cloud | Existing connector or attested feed | AWS AI resource metadata reader | Managed AI resources, deployments, agents, relationships |
| `gcp_managed_ai` | Cloud project / Cloud | Attested feed | GCP AI resource metadata viewer | Managed AI resources, deployments, agents, relationships |
| `kubernetes_ai_workloads` | Kubernetes cluster / Kubernetes | Attested feed | Kubernetes workload metadata reader | AI workloads, runtimes, services, model and MCP configuration |
| `microsoft365_ai` | SaaS tenant / SaaS | Typed direct, existing connector, or attested feed | Microsoft Graph approved metadata scopes | AI features, licences, bounded user activity |
| `github_ai` | Repository organization / Source code | Typed direct or attested feed | GitHub App approved metadata permissions | AI features, seats, repository-scoped configuration |
| `google_workspace_ai` | SaaS tenant / SaaS | Existing connector or attested feed | Google Workspace approved metadata scopes | AI features, licences, bounded user activity |
| `slack_ai` | SaaS tenant / SaaS | Existing connector or attested feed | Slack approved metadata scopes | AI features and bounded user activity |
| `salesforce_ai` | SaaS tenant / SaaS | Attested feed | Salesforce approved metadata scopes | AI features, agents, integrations |
| `servicenow_ai` | SaaS tenant / SaaS | Attested feed | ServiceNow approved metadata scopes | AI features, agents, integrations |
| `atlassian_ai` | SaaS tenant / SaaS | Existing connector or attested feed | Atlassian approved metadata scopes | AI features and bounded user activity |
| `notion_ai` | SaaS tenant / SaaS | Attested feed | Notion approved metadata scopes | AI features and bounded user activity |
| `zoom_ai` | SaaS tenant / SaaS | Attested feed | Zoom approved metadata scopes | AI features and bounded user activity |
| `entra_ai_identity` | Identity tenant / Identity | Existing connector or attested feed | Entra directory metadata reader | OAuth apps, service principals, managed identities, assignments |
| `okta_ai_identity` | Identity tenant / Identity | Attested feed | Okta application metadata reader | OAuth apps, service principals, assignments |
| `google_ai_identity` | Identity tenant / Identity | Attested feed | Google identity application metadata reader | OAuth apps, service principals, assignments |
| `repository_ai_metadata` | Repository organization / Source code | Existing connector or attested feed | Repository metadata reader | Dependencies and AI configuration relationships; no source files |
| `cicd_ai_metadata` | Repository organization / CI/CD | Attested feed | CI configuration metadata reader | AI build integrations, endpoint references, pipeline relationships |
| `dns_ai_metadata` | DNS domain / DNS | Attested feed | Approved DNS telemetry reader | AI destination lookup metadata |
| `swg_ai_metadata` | Network range / Network | Existing connector or attested feed | Secure web gateway metadata reader | AI destination flow metadata |
| `proxy_ai_metadata` | Network range / Network | Attested feed | Proxy metadata reader | AI destination flow metadata |
| `firewall_ai_metadata` | Network range / Network | Existing connector or attested feed | Firewall metadata reader | AI destination flow metadata |
| `flow_ai_metadata` | Network range / Network | Attested feed | Network flow metadata reader | AI destination flow metadata |
| `api_gateway_ai_metadata` | API gateway / API gateway | Attested feed | API gateway metadata reader | AI routes, endpoints, bounded request metadata |
| `service_mesh_ai_metadata` | Kubernetes cluster / Service mesh | Attested feed | Service mesh metadata reader | AI service routes and workload relationships |
| `api_catalog_ai_metadata` | API gateway / API gateway | Attested feed | API catalog metadata reader | AI API inventory, ownership, routes |
| `database_ai_metadata` | Database platform / Database | Attested feed | Database catalog metadata reader | AI database integrations and configuration relationships |
| `vector_store_ai_metadata` | Database platform / Vector store | Attested feed | Vector store catalog metadata reader | Vector-store and index relationship metadata |
| `search_rag_knowledge_metadata` | Database platform / Database | Attested feed | Search catalog metadata reader | Search, RAG index, and knowledge-source relationships |
| `prompt_registry_metadata` | AI provider account / Model endpoint | Attested feed | Prompt registry metadata reader | Registry entries, versions, ownership; no prompt body |
| `memory_store_metadata` | Database platform / Database | Attested feed | Memory store catalog metadata reader | Agent-memory store, retention, ownership metadata |

## Permissions

Every profile declares the least metadata-read permission it needs. A customer
administrator must authorise the connection and its bounded target. H4 does not
accept embedded connection secrets or arbitrary executable customer code.
Microsoft 365 and GitHub may use their typed direct source contracts. Other
profiles use an existing approved connector or a separately attested metadata
feed until a typed direct collector is accepted.

## Health and freshness

An unconnected profile reports `unknown`. Connected sources report their actual
health and last successful collection. Stale health, a missing denominator, an
expired authority reference, an incomplete unit result, or a missing completion
receipt cannot be promoted to current coverage.

## Safety and privacy

All profiles are passive and `monitor_only`. They collect inventory,
configuration, relationship, and bounded usage metadata only. Raw prompts,
responses, source files, database rows, vector contents, authentication
material, and private material are excluded. Empty results mean only that the
admitted source returned no safe records in the selected window.

## Residency

Projected records stay in the configured tenant region. The customer-owned
source can remain in its selected source region; any cross-region metadata
transfer must be declared by the connector and customer configuration.

## Limitations

- Catalog entries are not live provider implementations by themselves.
- Registry presence, connector configuration, or a successful authentication
  test does not establish estate coverage.
- Coverage cannot exceed the source-owned denominator or selected target.
- Unsupported, unavailable, partial, stale, and unknown paths stay explicit.
- Provider inventory metadata does not prove active use unless an independent
  usage signal says so.

## Live acceptance boundary

Source and fixture acceptance proves that each H4 family uses the same typed,
tenant-safe projection path and rejects raw content. Production acceptance is
separate for every customer and source. It requires customer authorisation,
connected-source health, an authoritative denominator, a bounded successful
run, signed per-unit completion evidence, and audit/UI reconciliation. No H4
profile creates certification, legal compliance, or a full-enterprise scan
claim.
