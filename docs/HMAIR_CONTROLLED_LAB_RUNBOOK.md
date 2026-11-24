# HMAIR controlled-lab endpoint discovery runbook

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## Purpose and boundary

This runbook validates one **enrolled macOS lab endpoint** with the existing
read-only endpoint metadata scanner. It is not an organisation-wide deep scan,
does not enumerate a fleet, and must be run only in a separate controlled lab
deployment.

The resulting scan has an explicit denominator of one endpoint. It can report
only installed/configured supported AI products, public app/version metadata,
allowlisted IDE and browser-extension metadata, safe AI configuration metadata,
and configured MCP server names. It does not establish that an application,
extension, account, MCP server, or model is approved, used, reachable, or
enforceable.

The workflow never collects or transmits raw prompts, page content, browser
history, cookies, account identifiers, configuration contents, tool arguments,
tool results, secrets, tokens, private keys, file paths, or arbitrary process
arguments.

## Prerequisites

- A separate lab database, tenant, and endpoint—not a customer production
  tenant.
- A current API and endpoint-agent build that contains
  `POST /endpoint-agent/discovery/snapshots` and
  `--hmair-discovery-snapshot`.
- A macOS lab laptop with administrator-authorized endpoint enrolment.
- An administrator who can issue a one-time endpoint enrolment authorization.
- A browser able to access the lab UI. For the local demo TLS setup, use
  `https://hawk.localhost:3443` and accept the local certificate only after
  confirming it is the intended lab stack.

Do not reuse an existing production endpoint identity. Existing endpoint
identities do not receive the new discovery scope automatically.

## 1. Enable the smallest lab-only server capability

Create a lab-specific copy of the deployment environment file. Preserve the
required, already-secret-managed values; never paste secrets into this runbook
or an endpoint configuration. Add only these HMAIR values:

```dotenv
HMAIR_CORE=true
HMAIR_ENDPOINT=true
HMAIR_ACTIVE_SCAN=false
HMAIR_CLOUD=false
HMAIR_SAAS=false
HMAIR_IDENTITY=false
HMAIR_REPOSITORY=false
HMAIR_NETWORK=false
HMAIR_DATABASE=false
HMAIR_FINGERPRINTING=false
HMAIR_USAGE_ATTRIBUTION=false
HMAIR_SHADOW_AI=false
HMAIR_REACHABILITY=false
```

Start or rebuild only the separate lab stack with the lab environment file.
For the repository demo compose file, the variable that selects the API
container environment is `HAWK_APP_ENV_FILE`; point it at the lab file rather
than modifying the regular `.env` file. Use a distinct Compose project name and
volumes for the lab.

Before continuing, check API readiness. A failed readiness check, an unexpected
migration head, or a production tenant means stop and correct the lab setup;
do not run the endpoint command.

## 2. Create a new endpoint authorization

As a tenant administrator, create a one-time enrollment authorization for the
exact lab endpoint ID through the existing endpoint enrollment route or UI.
Use the normal endpoint scopes plus:

```text
endpoint:discovery:write
```

The default scope set for a *new* authorization now includes this scope.
If an existing lab endpoint must be reused, issue a new authorization and
re-enroll it; do not attempt to edit its scope token or configuration locally.

Consume the one-use enrollment through the existing macOS installer or the
existing `--enroll-existing-config --enrollment-bundle-stdin` workflow. Keep
the enrollment bundle in standard input only. It must never be placed in a
shell argument, environment variable, saved file, ticket, or log.

Verify the device identity before scanning:

```bash
HAWK_ROOT="$HOME/Library/Application Support/Hawk/EndpointAgent"
"$HAWK_ROOT/runtime/bin/hawk-endpoint-agent" \
  --config "$HAWK_ROOT/state/endpoint-agent.json" \
  --verify-device-identity
```

The successful result must be a bounded identity-health receipt. Do not record
key material, access tokens, or an enrollment bundle in test evidence.

## 3. Run one explicitly requested lab snapshot

The normal endpoint-agent service does not run this discovery path
automatically. Run exactly one explicit command:

```bash
HAWK_ROOT="$HOME/Library/Application Support/Hawk/EndpointAgent"
"$HAWK_ROOT/runtime/bin/hawk-endpoint-agent" \
  --config "$HAWK_ROOT/state/endpoint-agent.json" \
  --hmair-discovery-snapshot
```

Expected output is a bounded JSON receipt containing only:

- `ok`;
- `scan_id`;
- `status`;
- `observations_count`;
- `endpoint_denominator` (always `1` for this path);
- `limitations`.

Do not treat a client-side error as evidence of no AI use. It is an unverified
or unavailable collection path until investigated.

## 4. Validate it in the UI

Open **Assets → Scan Operations** in the lab UI and select **Endpoint metadata
snapshot**. Confirm all of the following:

1. The scan type is `collector_specific` and its result says the enterprise-wide
   claim is prohibited.
2. The scan has a single assignment and an endpoint denominator of one.
3. The warnings list includes `coverage:single_enrolled_endpoint` and
   `active_scan:not_performed`.
4. Unsupported/unconnected sources include browser activity, MCP runtime, LLM
   runtime, SaaS, cloud, identity, repository, network, and database unless a
   separately validated collector has been deployed for them.
5. No raw prompt, secret, account identifier, path, browser history, or cookie
   is visible in the scan result.

The Scan Operations view already labels partial results as non-enterprise-wide
and shows unsupported/unknown sources. It is the authoritative UI for this lab
receipt; do not use a dashboard count as evidence of endpoint coverage.

## 5. Record a truthful lab result

State the result as:

> Trinya completed a metadata-only observation from one enrolled lab endpoint.
> The result is limited to the declared local sources and does not represent
> organisation-wide discovery or coverage of browser activity, MCP runtime,
> LLM runtime, SaaS, cloud, identity, repositories, network, or databases.

Never describe it as a deep scan of the organisation, complete agent/MCP
discovery, or an enforcement validation.

## 6. Cleanup and rollback

1. Export only the bounded scan receipt and the relevant audit event if the lab
   evidence must be retained.
2. Revoke the lab endpoint identity through the existing endpoint management
   route or UI.
3. Stop the separate lab stack or set `HMAIR_CORE=false` and
   `HMAIR_ENDPOINT=false`, then restart only the lab API/worker deployment.
4. Keep production flags unchanged.

The default endpoint uninstaller retains local state unless its explicit purge
option is used. Follow the lab retention decision before selecting that option;
do not delete evidence by default.

## What remains unsupported after this lab

- fleet enumeration and authoritative enterprise denominators;
- active endpoint scanning;
- observed browser activity without a connected browser collector;
- MCP gateway/runtime and LLM-runtime activity;
- SaaS, cloud, identity, repository, network, and database discovery;
- canonical asset resolution, reachability, continuous scheduling, and
  enterprise rollout controls.

Those require separate source-specific collectors, customer administrator
consent, authoritative denominators, and their own acceptance evidence.
