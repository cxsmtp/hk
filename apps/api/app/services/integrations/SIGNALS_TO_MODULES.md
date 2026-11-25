# Signals To Modules Mapping

This mapping defines which product modules consume connector signals.

## Modules
- `governance` (AI Governance / Trust Center)
- `interaction_security` (LLM Gateway + policy enforcement)
- `shadow_ai` (Shadow AI Discovery & Control)
- `ai_iam` (AI Identity & Access Management)
- `monitoring` (Continuous Controls & Integration Monitoring)
- `validation` (AI Control Validation / Simulations)
- `auditor` (Fully Automated Auditor)

## Connector Signals

| Connector | Signal | Modules |
|---|---|---|
| `entra_id` | `identity.entra.signin_risk` | `ai_iam`, `monitoring`, `auditor` |
| `entra_id` | `identity.entra.directory_audit` | `governance`, `monitoring`, `auditor` |
| `entra_id` | `identity.entra.provisioning` | `ai_iam`, `monitoring`, `validation` |
| `sailpoint` | `identity.sailpoint.identities` | `ai_iam`, `monitoring`, `auditor` |
| `sailpoint` | `identity.sailpoint.access_requests` | `ai_iam`, `monitoring`, `auditor` |
| `sailpoint` | `identity.sailpoint.role_assignments` | `ai_iam`, `monitoring`, `validation` |
| `aws` | `cloud.aws.cloudtrail.anomaly` | `monitoring`, `validation`, `auditor` |
| `aws` | `cloud.aws.iam.role_exposure` | `ai_iam`, `monitoring`, `auditor` |
| `aws` | `cloud.aws.s3.public_access` | `interaction_security`, `monitoring`, `auditor` |
| `microsoft_365` | `saas.microsoft365.sharepoint.activity` | `interaction_security`, `monitoring`, `auditor` |
| `microsoft_365` | `saas.microsoft365.audit.unified` | `governance`, `monitoring`, `auditor` |
| `microsoft_365` | `saas.microsoft365.exchange.activity` | `shadow_ai`, `monitoring`, `auditor` |
| `google_workspace` | `saas.google_workspace.admin_activity` | `governance`, `monitoring`, `auditor` |
| `google_workspace` | `saas.google_workspace.drive_activity` | `interaction_security`, `monitoring`, `auditor` |
| `google_workspace` | `saas.google_workspace.login_activity` | `ai_iam`, `monitoring`, `auditor` |
| `jira` | `ticketing.jira.audit.records` | `governance`, `monitoring`, `auditor` |
| `jira` | `ticketing.jira.permission_schemes` | `ai_iam`, `monitoring`, `auditor` |
| `jira` | `ticketing.jira.project_roles` | `monitoring`, `validation`, `auditor` |
| `openai` | `ai.openai.usage.completions` | `interaction_security`, `monitoring`, `auditor` |
| `openai` | `ai.openai.usage.embeddings` | `interaction_security`, `validation`, `auditor` |
| `openai` | `ai.openai.costs.daily` | `governance`, `monitoring`, `auditor` |
| `anthropic` | `ai.anthropic.usage` | `interaction_security`, `monitoring`, `auditor` |
| `anthropic` | `ai.anthropic.workspace.membership` | `ai_iam`, `monitoring`, `auditor` |
| `anthropic` | `ai.anthropic.keys.rotation` | `ai_iam`, `monitoring`, `auditor` |
| `gemini` | `ai.gemini.models` | `governance`, `monitoring`, `auditor` |
| `gemini` | `ai.gemini.files` | `interaction_security`, `monitoring`, `auditor` |
| `gemini` | `ai.gemini.tuned_models` | `validation`, `monitoring`, `auditor` |
| `fortinet` | `network.fortinet.events` | `interaction_security`, `monitoring`, `auditor` |
| `fortinet` | `network.fortinet.firewall_policies` | `governance`, `monitoring`, `auditor` |
| `fortinet` | `network.fortinet.interfaces` | `monitoring`, `validation`, `auditor` |
| `netskope` | `network.netskope.events` | `interaction_security`, `monitoring`, `auditor` |
| `netskope` | `network.netskope.alerts` | `shadow_ai`, `monitoring`, `auditor` |
| `netskope` | `network.netskope.tenant_posture` | `governance`, `monitoring`, `auditor` |
| `zscaler` | `network.zscaler.audit_logs` | `governance`, `monitoring`, `auditor` |
| `zscaler` | `network.zscaler.firewall_rules` | `interaction_security`, `monitoring`, `auditor` |
| `zscaler` | `network.zscaler.url_categories` | `shadow_ai`, `monitoring`, `auditor` |
| `checkmarx` | `appsec.checkmarx.scans` | `monitoring`, `validation`, `auditor` |
| `checkmarx` | `appsec.checkmarx.projects` | `governance`, `monitoring`, `auditor` |
| `checkmarx` | `appsec.checkmarx.findings` | `interaction_security`, `monitoring`, `auditor` |
| `checkmarx` | `appsec.checkmarx.results_summary` | `monitoring`, `validation`, `auditor` |
| `checkmarx` | `appsec.checkmarx.audit_trail` | `governance`, `ai_iam`, `auditor` |
| `akamai` | `api.akamai.appsec.events` | `interaction_security`, `monitoring`, `auditor` |
| `akamai` | `api.akamai.appsec.configs` | `governance`, `monitoring`, `auditor` |
| `akamai` | `api.akamai.appsec.policies` | `validation`, `monitoring`, `auditor` |
| `crowdstrike` | `endpoint.crowdstrike.detects` | `interaction_security`, `monitoring`, `auditor` |
| `crowdstrike` | `endpoint.crowdstrike.incidents` | `monitoring`, `validation`, `auditor` |
| `crowdstrike` | `endpoint.crowdstrike.hosts` | `ai_iam`, `monitoring`, `auditor` |
| `cyberark` | `pam.cyberark.accounts` | `ai_iam`, `monitoring`, `auditor` |
| `cyberark` | `pam.cyberark.safes` | `governance`, `monitoring`, `auditor` |
| `cyberark` | `pam.cyberark.activities` | `ai_iam`, `monitoring`, `auditor` |
