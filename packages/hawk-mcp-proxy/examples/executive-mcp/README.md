# Hawk Executive MCP

Read-only MCP server for executives who need tenant-scoped AI governance answers from Claude or Codex without opening the full web platform.

## Tools

- `get_executive_summary` — headline actions, blocks, providers, MCP/GitHub posture, coverage, spend status and recommendations.
- `query_executive_metrics` — scoped queries for actions, blocks, top violations, framework mappings, providers, MCP tools, GitHub repositories, coverage, spend and tokens.
- `create_executive_presentation` — creates an audited PPTX executive brief from the same evidence.

## Security model

- Requires `HAWK_EXEC_API_URL`, `HAWK_EXEC_TENANT_ID`, and `HAWK_EXEC_ACCESS_TOKEN` or their `HAWK_*` aliases.
- All API calls include `X-Tenant-ID`.
- Platform RBAC is enforced by the API.
- Raw prompt content is excluded.
- Named-user detail is returned only when the authenticated role is permitted.
- Presentation creation is audited.

## Recommended local setup for Claude Desktop and Codex Desktop

Run the setup helper once from the repository root. It signs in locally, writes
the same tenant-scoped Executive MCP server into Claude Desktop and Codex
Desktop, and preserves the existing MCP servers in both config files.

```bash
node "/opt/hawk/packages/hawk-mcp-proxy/bin/setup-hawk-executive-mcp.mjs" \
  --api https://api.hawk.localhost:3443 \
  --repo "/opt/hawk" \
  --insecure-local-tls
```

If you already have a short-lived tenant token in the current shell:

```bash
node "/opt/hawk/packages/hawk-mcp-proxy/bin/setup-hawk-executive-mcp.mjs" \
  --api https://api.hawk.localhost:3443 \
  --repo "/opt/hawk" \
  --tenant "$HAWK_EXEC_TENANT_ID" \
  --token "$HAWK_EXEC_ACCESS_TOKEN"
```

Then restart Claude Desktop and Codex Desktop. The MCP server name should be:

```text
hawk-executive
```

Use the local stdio setup above for desktop demos. Claude/Codex hosted custom
connectors require a trusted, reachable HTTPS hostname; local `hawk.localhost`
may not be reachable from their remote connector runtimes.

## Demo test prompts

Use these exact prompts in Claude Desktop or Codex Desktop after restart:

```text
Use the Hawk Executive MCP to get an executive summary for the last 30 days. Return only the summary and mention which MCP tool was used.
```

```text
Use the Hawk Executive MCP to query executive metrics for blocked actions grouped by application for the last 30 days. Return the top 10 rows and mention which MCP tool was used.
```

```text
Use the Hawk Executive MCP to query executive metrics for github_repositories for the last 30 days. Return repositories, AI tools involved, and policy decision summary if present.
```

```text
Use the Hawk Executive MCP to query tokens, then spend, for the last 30 days. Explain whether the values are provider-reported, estimated, or unavailable.
```

```text
Use the Hawk Executive MCP to create an executive presentation titled 'AI Governance Executive Brief' for the last 30 days. Return the generated file path and do not include raw prompts.
```

## Claude Desktop config fragment

```json
{
  "mcpServers": {
    "hawk-executive": {
      "command": "/usr/local/bin/node",
      "args": [
        "/opt/hawk/packages/hawk-mcp-proxy/bin/hawk-executive-mcp.mjs",
        "--gateway",
        "https://api.hawk.localhost:3443",
        "--tenant",
        "TENANT_ID",
        "--token",
        "SHORT_LIVED_ACCESS_TOKEN",
        "--stdio-framing",
        "content-length"
      ]
    }
  }
}
```

## Codex config fragment

```toml
[mcp_servers.hawk-executive]
command = "/usr/local/bin/node"
args = [
  "/opt/hawk/packages/hawk-mcp-proxy/bin/hawk-executive-mcp.mjs",
  "--gateway", "https://api.hawk.localhost:3443",
  "--tenant", "TENANT_ID",
  "--token", "SHORT_LIVED_ACCESS_TOKEN",
  "--stdio-framing", "content-length",
]
```

## Remote hosted MCP gateway

The hosted gateway is available at:

```text
https://api.hawk.localhost:3443/mcp/executive
```

It speaks JSON-RPC over streamable HTTP and exposes the same executive tools as
the local stdio bridge. It is intended for MCP clients that can call a remote
HTTPS endpoint.

### Codex Streamable HTTP setup

In Codex, choose **Connect to a custom MCP → Streamable HTTP**:

```text
Name: Hawk Executive
Type: Streamable HTTP
URL: https://api.hawk.localhost:3443/mcp/executive
Bearer token env var: HAWK_EXEC_ACCESS_TOKEN
Headers:
  X-Tenant-ID: TENANT_ID
```

Use a short-lived platform access token. The endpoint enforces the authenticated
user's tenant role and never returns raw prompt content.

### Claude custom connector setup

Claude's custom connector screen accepts an HTTPS MCP server URL. Use:

```text
Name: Hawk Executive
MCP server URL: https://api.hawk.localhost:3443/mcp/executive
```

The hosted gateway advertises OAuth protected-resource metadata and dynamic
client registration for MCP clients that cannot send custom tenant headers. The
authorization flow signs in with a Hawk tenant user, selects or confirms the
tenant, and returns a short-lived tenant-bound connector token.

For local development, Claude may reject `hawk.localhost` if the certificate is
self-signed or the host is not reachable from Claude's connector runtime. For a
production demo, expose the same path behind the public Hawk API hostname with
trusted TLS:

```text
https://api.<customer-domain>/mcp/executive
```

The connector token is still checked against the live user, tenant membership
and role on every MCP call.

### Quick protocol check

Unauthenticated metadata:

```bash
curl --insecure https://api.hawk.localhost:3443/mcp/executive
```

Authenticated tool discovery:

```bash
curl --insecure https://api.hawk.localhost:3443/mcp/executive \
  -H "Authorization: Bearer $HAWK_EXEC_ACCESS_TOKEN" \
  -H "X-Tenant-ID: $HAWK_EXEC_TENANT_ID" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":"tools","method":"tools/list"}'
```

OAuth metadata checks:

```bash
curl --insecure https://api.hawk.localhost:3443/mcp/executive/.well-known/oauth-protected-resource
curl --insecure https://api.hawk.localhost:3443/mcp/executive/.well-known/oauth-authorization-server
```
