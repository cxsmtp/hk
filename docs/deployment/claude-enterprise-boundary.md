# Claude Enterprise organization boundary

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


Implemented: endpoint-package deployment renderer, generic TLS-proxy tenant-header adapter, and tenant-bound Hawk API inference-hook receiver. Status: **not deployed; enterprise acceptance unverified**. Existing capability declarations remain unverified.

## Personal laptop test mode

This laptop is personal and runs CrowdStrike EDR. No MDM profile, Windows policy, proxy, certificate or CrowdStrike setting is installed or changed. No private Claude history or credentials are used. Run the synthetic test harness:

```bash
bash infra/scripts/test-claude-enterprise-boundary.sh
```

It checks artifact contents and header replacement, simulates signed Anthropic requests against FastAPI in process, tests replay and signature rejection, and exercises the bridge to the existing policy service using synthetic stubs. It does not contact Anthropic, create Redis claims or establish CrowdStrike coexistence. CrowdStrike installation alone does not supply the required organization, MDM configuration or TLS inspection route.

Real personal-account denial, account switching, existing sessions, off-office routing and Enterprise inference-hook execution require an Enterprise test organization and a managed test deployment. Do not apply a synthetic organization profile to the personal app: it can prevent login.

## Layer 1: managed desktop login

Use the packaged endpoint interpreter to run:

```text
python -m hawk_endpoint_agent.native_control.cli render-claude-enterprise \
  --org-id ACTUAL_CLAUDE_ORGANIZATION_UUID --output-directory NEW_OUTPUT_DIRECTORY
```

The new directory contains `claude.mobileconfig`, `claude-windows.reg`, `claude-tenant-restriction.py` and `deployment.json`. UUID validation occurs before writing. Existing directories are not overwritten. No host configuration is applied.

Deploy the profile through macOS MDM, using preference domain `com.anthropic.claudefordesktop`. The Windows artifact writes only `forceLoginOrgUUID` under `HKLM\SOFTWARE\Policies\Claude`. Repeat `--org-id` for an allowlist: macOS accepts the array; the Windows artifact deliberately uses only the first UUID as the primary login organization, avoiding an undocumented registry encoding for arrays. The proxy allowlist includes all supplied organizations.

Membership restriction alone does not demonstrate that each conversation uses the governed organization. Test existing sessions and switching between a permitted enterprise and personal organization.

## Layer 2: mandatory proxy restriction

Use `deployment.json` to configure the customer's SWG, or deploy the generated addon in an existing managed mitmproxy environment with the Hawk endpoint Python package installed. The addon replaces the base and all numbered `anthropic-allowed-org-ids` headers, including duplicates and client-supplied values. Allowlists are capped at 500 UUIDs and split into up to ten documented header slots. Plain HTTP on a targeted host is denied.

Target hosts are exactly `claude.ai`, `api.anthropic.com`, `claude.com`, and `anthropic.com`. No wildcard inspection is silently enabled. Validate every actual app destination; additional paths or hosts are uncovered until explicitly configured and tested. The addon neither provides a TCP/TLS proxy nor establishes certificate trust or forced routing. Use the managed proxy's verified TLS inspection, mandatory off-office routing, direct-egress restrictions, and operational monitoring. Uninspected traffic must not silently bypass the tenant boundary.

## Layer 3: Enterprise inference receiver

Route: `POST /native-controls/claude-enterprise/{integration_id}/inference` (include the deployment's external API prefix where applicable). Provision the receiver on an owned public HTTPS host, port 443, with a public CA certificate, no redirects and no reverse tunnel. Localhost cannot receive live Anthropic hooks.

The route is disabled until an operator provisions a private JSON file and sets `HAWK_CLAUDE_ENTERPRISE_BINDINGS_FILE` to its absolute path. Example structure (replace the labels; these are not valid IDs):

```json
{
  "customer-test": {
    "enabled": true,
    "organization_id": "ACTUAL_CLAUDE_ORGANIZATION_UUID",
    "tenant_id": "ACTUAL_HAWK_TENANT_UUID",
    "ai_system_id": "REGISTERED_HAWK_AI_SYSTEM_UUID",
    "secret_envs": ["HAWK_CLAUDE_HOOK_SECRET_CUSTOMER_TEST"]
  }
}
```

The file must be mode 0600, non-symlink, and controlled by deployment operations. Protect its parent directory. Load the `whsec_...` signing secret from the deployment's secret manager into the named server environment variable; never put the secret in generated profiles or chat. Up to two references support a bounded rotation overlap. Remove the old reference after rotation acceptance. Binding a secret delegates only that organization's requests to the specified Hawk tenant and AI system; no request header can select another Hawk tenant or asset.

The receiver verifies Standard Webhooks HMAC over raw bytes, a five-minute timestamp tolerance, request-ID equality and exact organization binding. Shared Redis claims reject replay; duplicates conservatively deny rather than reusing an old allow. Redis failure denies. Only an explicit policy allow passes; every other policy result denies. An inactive/monitor tenant, minimal gateway mode, unhealthy control plane, unavailable policy or failed audit commit cannot produce an allow. Existing governance and AI-system approval checks remain in place.

The full supplied message structure, including extracted attachment text and tool arguments/results, goes through Hawk's existing gateway policy service. The bridge does not truncate it. Missing attachment text and unknown content types receive a policy denial for incomplete inspection, not an HTTP schema error. Images/binary content omitted by Anthropic cannot be inspected. Future source names are advisory and do not change authority. Policy evaluation does not execute tools or invoke the model.

Both verdicts return HTTP 200 with Anthropic's allow/deny JSON. Final policy verdicts are audited using opaque correlation and reference IDs, without adding raw transcripts to this adapter's audit payload. The existing gateway's content-retention policy still applies to its own records. Authentication/configuration failures return generic denial without logging request bodies or secrets. Configure ingress/access logs accordingly.

Accept up to 64 MiB without request compression; configure ingress limits, concurrency and request timeouts accordingly. Keep verdict responses uncompressed and under 64 KiB. Measure end-to-end latency against the configured Anthropic timeout; an overdue verdict relies on the provider-side failure policy.

In Claude's Enterprise settings, require **Block the request**, **100% rollout**, **Enforce verdicts on**, **Shadow mode off**, and no role exclusions for the claimed scope. Initial provider defaults may allow requests on failure. Test allow, deny, invalid signature, policy outage and service outage before claiming protection. Disabling enforcement, sampled rollout or role exclusions reduces coverage independently of Hawk.

## Coverage and rollback

This governs supported enterprise inference after the content reaches Anthropic and before model processing. It does not inspect personal accounts, cover voice mode, block output, inspect raw images, or authorize a tool's execution. Personal/unapproved account access is the proxy's separate tenant boundary.

Rollback through the same MDM/SWG that applied the rules, restoring the prior managed values. Disable the test inference integration in both Claude and the Hawk binding, then retire its signing secret. Removing any layer changes coverage and must not leave a protected status behind. No external deployment or protection state is changed by the renderer or the synthetic tests.

Sources: [Desktop policy](https://support.claude.com/en/articles/12622667-enterprise-configuration-for-claude-desktop), [Tenant Restrictions](https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions), [Inference wire protocol](https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint), [Enterprise hook configuration](https://platform.claude.com/docs/en/manage-claude/inference-hooks-configuration).
