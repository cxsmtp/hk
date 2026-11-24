# Deployment Quick Starts

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


This document defines the approved onboarding contract for Browser, Endpoint, Runtime, and SaaS & APIs deployments. Quick starts reuse existing integration, gateway, endpoint, browser, and setup actions. They do not create a new gateway, collector system, policy engine, event pipeline, or dashboard.

## Availability

The four quick starts and monitor-first administrative APIs are planned additive slices. At the 2026-07-24 planning snapshot they are not implemented and must not be presented as live.

Initial flags default to false:

```dotenv
DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED=false
DEPLOYMENT_FAMILY_COVERAGE_ENABLED=false
DEPLOYMENT_MONITOR_FIRST_ADMIN_ENABLED=false
NEXT_PUBLIC_DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED=false
```

Existing setup and technical Deployment Surface workflows remain available. A quick start may be exposed only when its underlying action exists and the tenant rollout flag is enabled.

## Common four-step flow

Every family follows:

1. Connect.
2. Configure.
3. Test.
4. Monitor.

Before the operator confirms a step, the wizard must show:

- exact permissions requested;
- data collected;
- actual control and evidence capability;
- expected blind spots and limitations;
- failure and degraded behavior;
- rollback and uninstall instructions.

The values must come from the selected technical surface or connector manifest and current source evidence. The wizard must not fill missing facts with a family-level assumption.

## Monitor-first activation

New instances default to monitor or shadow. Blocking is not the default.

The activation sequence is:

```text
Connect
→ Observe
→ Review predicted impact
→ Tune
→ Enable warning/review
→ Enable blocking
```

Operators must be able to review:

- actions observed;
- actions that would be blocked;
- actual blocks;
- overrides;
- false-positive labels;
- Unknown coverage;
- evidence-backed recommendations.

A simulation or predicted impact does not prove live containment, authorization, or evidence coverage. Coverage changes only after current runtime observations and evidence verify the active path.

## Browser quick start

Eligible technical surfaces are:

- `browser_extension`
- `browser_agent`
- `managed_browser`
- `browser_automation_control`

### Connect

- Select the exact browser surface and tenant.
- Display the permissions and collected-data declaration supplied by that surface.
- Verify the configured endpoint, tenant, and managed state where the integration reports them.
- Create or reconcile the technical Deployment Surface without claiming inline control.

### Configure

- Show `hosting_mode` and existing `deployment_mode` separately.
- Select monitor or shadow posture for the new instance.
- Display the current policy bundle and feature-flag state when known.
- Show unsupported or unverified browser paths as Unknown.

### Test

- Use the existing browser test action supported by the selected surface.
- Record the observation, decision, evidence references, health result, and limitations that actually occur.
- Do not label a detected or post-action event as pre-execution authorization.

### Monitor

- Show heartbeat or last activity, version, policy state, evidence lag, degradation, bypass state, and Unknown coverage when available.
- Drill down to exact browser instances, paths, identities, and destinations.
- Recommend posture expansion only from observed evidence.

## Endpoint quick start

Eligible technical surfaces are:

- `endpoint_agent`
- `endpoint_discovery`
- `local_agent_telemetry`
- `desktop_ai_control`
- `local_ai_proxy`
- `local_proxy`
- `ide_companion`
- `developer_endpoint`
- `local_mcp_runtime`
- `cli_agent_runtime`
- `mdm_discovery`

### Connect

- Select the exact endpoint, local proxy, developer, local runtime, or discovery surface.
- Display its exact permissions and data collection before enrollment.
- Verify tenant and instance identity from the authoritative source.
- Do not infer privileged prevention from endpoint presence or telemetry.

### Configure

- Keep hosting, control posture, family, and technical type separate.
- Default the new instance to monitor or shadow.
- Show collection scope, policy source, local failure behavior, and any external action requirement.
- Leave unverified identity, health, or capability Unknown.

### Test

- Run only a supported existing test action for the selected technical surface.
- Verify the observed identity, runtime, target, policy result, receipts or evidence, and health state.
- Treat metadata-only or passive observations as such.

### Monitor

- Show last heartbeat or action, collector version, policy version and age, cache state, latency, evidence lag, degradation, bypass, and upgrade state when those measurements exist.
- Drill down to exact endpoint instances and observed AI paths.
- Keep known or inventoried endpoint assets that lack a current accepted observation visible as Not Covered or Unknown according to evidence. Truly unobserved endpoint estate remains outside the measured population and denominator.

## Runtime quick start

Eligible technical surfaces are:

- `llm_gateway`
- `mcp_gateway`
- `sdk`
- `sdk_app_embed`
- `runtime_mesh`
- `azure_foundry`
- `azure_apim`
- `kong`
- `envoy`
- `kubernetes`
- `aks`
- `container_apps`
- `custom_agent_runtime`
- `internal_api_authorization`

### Connect

- Select the exact gateway, SDK, platform, mesh, runtime, or authorization surface.
- Display the required credentials, permissions, and collected-data declaration without exposing secret values.
- Verify provider, environment, region, tenant, and technical endpoint where reported.
- Registration alone remains Unknown for authorization and containment.

### Configure

- Default to monitor or shadow.
- Show routing, policy, fail behavior, control mode, evidence mode, and known limitations from authoritative configuration.
- Keep request-only, partial, post-execution, monitor-only, and external-required modes distinct from complete inline coverage.

### Test

- Use the existing gateway, SDK, MCP, or runtime test action supported by that surface.
- Bind the result to the exact technical surface, identity, runtime, destination or tool, decision, receipt, and evidence references.
- A passing configuration test does not prove every production path traverses Hawk.

### Monitor

- Show request and decision activity, latency, cache and bundle age, evidence lag, degradation, bypass state, and upgrade state when measured.
- Drill down to exact LLM, MCP, SDK, platform, runtime, and internal authorization paths.
- Surface observed unprotected routes only from bypass telemetry.

## SaaS & APIs quick start

Eligible technical surfaces are:

- `microsoft_365`
- `copilot`
- `google_workspace`
- `slack`
- `salesforce`
- `service_now`
- `github`
- `gitlab`
- `saas_connector`
- `saas_ai_connector`
- `oauth_app_connector`
- `siem_connector`
- `webhook`
- `custom_connector`

### Connect

- Select the exact SaaS, API, OAuth, SIEM, webhook, or custom connector.
- Display scopes, tenant or organization access, collected data, and destination before authorization.
- Confirm connector ownership and source identity when the provider supplies them.
- Do not treat connector registration as inline authorization, external containment, or complete evidence.

### Configure

- Default to monitor or shadow.
- Show the exact sync or event scope, control posture, evidence capability, failure behavior, and expected blind spots.
- Mark unavailable pre-execution control as monitor-only, external-required, or Unknown according to verified capability. Keep `none` available for containment or evidence capability where that separate contract applies.

### Test

- Use the existing connector or delivery test supported by that technical surface.
- Verify the actual delivery, observation, evidence reference, health, and authorization or containment limitations.
- A successful webhook or SIEM test proves only the tested delivery path.

### Monitor

- Show last sync, heartbeat, or action; connector version; policy age; evidence and export lag; degraded mode; bypass state; and upgrade state when available.
- Drill down to the exact SaaS or API instance, identities, actions, destinations, and evidence.
- Keep provider paths outside Hawk's control explicit.

## Failure and degraded behavior

Each quick start must disclose the selected surface's actual failure behavior before activation. The UI must distinguish:

- inline control from monitor-only, detected-only, or post-execution observation;
- direct containment from surface-limited, verified external, none, or Unknown;
- complete evidence from partial, metadata-only, none, or Unknown;
- healthy from warning, degraded, offline, stale, or Unknown;
- a supported bypass detector from an unverified detector.

When configuration, health, identity, capability, or evidence cannot be verified, the safe display state is Unknown. The wizard must not silently promote a deployment because a connection test succeeded.

## Rollback and uninstall

Before connection, each wizard must present surface-specific rollback and uninstall guidance supplied by the underlying integration. At minimum, the operator must be able to identify:

- how to return the instance to monitor or shadow;
- how to disable the family UI or administrative feature flag;
- how to revoke granted credentials, tokens, consent, or scopes through the owning system;
- how to stop or disconnect the exact technical component;
- what additive audit and evidence data Hawk retains;
- what control or visibility is lost after rollback;
- how to verify that the component is no longer active.

Rollback must not delete historical methodology results or silently remove audit evidence. Disabling the family experience leaves existing technical Deployment Surface reads and `control-coverage/1.0` intact.

Administrative test, mode, and posture changes require admin RBAC, an audit record, before-and-after values, changed fields, redacted secrets, and a rollback target. Until that safety contract is implemented, the quick starts remain read-only guidance around existing setup actions.

## Completion evidence

A quick start is complete only when:

1. the exact technical instance is reconciled to the authenticated tenant;
2. requested permissions and collected data were disclosed;
3. monitor or shadow is active for a new instance;
4. the test result is recorded without overstating capability;
5. health and evidence references are visible when produced;
6. limitations, blind spots, failure behavior, and rollback are explicit;
7. the operator can drill into the exact technical surface and observed paths.

Connection success alone is not completion and does not increase Control Coverage.
