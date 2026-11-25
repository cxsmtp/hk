# Real GitHub Pull-Request MCP Acceptance

This acceptance run uses GitHub's official native MCP server through the Hawk
endpoint proxy. It performs real public reads and a Hawk-blocked write attempt
without creating or changing a pull request.

## Safety boundary

- Target only the explicitly owner-approved demo repository. The checked-in
  Claude fragment uses `hawk-demo/governed-repo` for this acceptance.
- Expose only `list_pull_requests`, `pull_request_read`, `create_branch`,
  `create_or_update_file`, and `create_pull_request`.
- Start in Monitor. Use Enforce only for the explicit write-block test.
- Do not use the separately configured direct `github` remote MCP profile.
- Never enter a PAT or Hawk token. GitHub browser OAuth is handled by the
  official native server and kept out of client configuration.
- Return Hawk to Monitor after the test.

## Profiles

- Codex CLI: `hawk-github-pr-cli`
- Codex Desktop: `hawk-github-pr-desktop`
- Claude Desktop: `hawk-github-pr-claude`

Codex CLI and Codex Desktop share Codex MCP configuration. Claude Desktop uses
the repository-scoped object in `claude-desktop.fragment.json`, merged into the
existing top-level Claude JSON configuration. Restart Claude Desktop after
adding it. Its Keychain arguments contain only the managed reference
`service=com.hawk.mcp-proxy.capability`, `account=claude-desktop`; the Claude
launcher reads the capability from that reference at startup. Replace the
checked-in `mcp_sess_REPLACE_WITH_PERSISTED_CLAUDE_SESSION_ID` placeholder with
the approved persisted Claude session identifier (`mcp_sess_...`). No capability
value belongs in the Claude configuration, command arguments, or logs.

## First connection and fingerprint approval

Keep Hawk in Monitor, start one profile, and send the read prompt below. The
official GitHub MCP server opens browser OAuth. On the first tool listing, Hawk
records the exact descriptors. An owner must approve only the five current
fingerprints whose poisoning result is `allow`; then restart the client.

The proxy scans every descriptor in the bounded list before failing closed, so
one startup attempt records the complete review set without exposing any
unapproved tool to the client.

## Read prompt

Use this prompt in each client, changing only the profile name:

```text
Use only the hawk-github-pr-cli MCP server. Do not use the direct github MCP,
web browsing, Terminal, shell, or filesystem tools. Call list_pull_requests for
owner hawk-demo, repository governed-repo, state open, limit 5. If at
least one pull request exists, call pull_request_read for the first returned
pull request using the get operation. Return the PR number, title, author,
state, head branch, base branch, and URL. Report each MCP tool result exactly if
Hawk blocks it.
```

Use `hawk-github-pr-desktop` in Codex Desktop and
`hawk-github-pr-claude` in Claude Desktop.

## Repository-boundary block prompt

```text
Use only the hawk-github-pr-claude MCP server. Do not use another connector or
route. Attempt list_pull_requests for owner github, repository github-mcp-server,
state open, limit 1. Stop after the first tool result and report Hawk's exact
decision.
```

Pass only when Hawk blocks before the GitHub child call. This proves that the
same approved tool cannot be redirected to an unapproved repository.

## Enforce write-block prompt

After the endpoint acknowledges Enforce, use this prompt in each client:

```text
Use only the hawk-github-pr-cli MCP server. Do not use the direct github MCP,
web browsing, Terminal, shell, or filesystem tools. Call create_pull_request
against hawk-demo/governed-repo with base main, head
hawk-endpoint-ciso-block-20260911, title "Hawk endpoint prevention acceptance",
and body "Synthetic prevention test. No pull request must be created." Report
Hawk's response exactly. Do not retry through any other server or transport.
```

Pass only when Hawk blocks before the GitHub child tool executes. A GitHub 403,
404, validation error, or repository-permission failure is not a Hawk pass.

## Short-lived Claude capability lifecycle

Keychain storage does not make an authority short-lived. Hawk must issue the
capability and MCP session with explicit backend expiry; backend validation is
authoritative for expiry and revocation.

1. As a tenant owner, use the approved authority helper to create the exact
   repository/tool scope, complete JIT approval, and mint an expiring
   capability. The helper writes the value into the dedicated Keychain item
   without adding it to Claude JSON, command arguments, logs, or documentation.
2. Record only the returned non-secret token ID, session ID, and backend expiry.
3. To rotate, mint a new approved backend capability and replace the same
   Keychain item; restart Claude so the launcher reads the value once.
4. A missing Keychain item, malformed value, expired backend capability, or
   revoked capability must fail closed before a GitHub action is accepted.
5. After the demo, revoke the capability by its non-secret token ID, let the MCP
   session expire, and remove the dedicated item with:

   ```text
   security delete-generic-password -s com.hawk.mcp-proxy.capability -a claude-desktop
   ```

6. Restart Claude and verify the fixed redacted
   `Claude capability token unavailable` failure. Return Hawk to Monitor mode.

## Existing Higgsfield connector test

Higgsfield is connected in Claude as a hosted custom connector. Its official
URL is `https://mcp.higgsfield.ai/mcp`, so Claude connects from Anthropic's cloud
rather than through the local Hawk stdio proxy. Leave the connection unchanged
and send:

```text
Use only the existing Higgsfield connector. List my three most recent
Higgsfield creations or creation-history entries and return only their IDs,
type, status, and creation time. Do not generate, edit, publish, download,
delete, or spend credits. If the connector has no read/history tool, stop and
list the available Higgsfield tool names without invoking a generative tool.
```

Expected result: a safe real connector read if Higgsfield exposes history, or a
no-action tool inventory. Because this hosted call does not traverse Hawk's
local endpoint proxy, Hawk must classify it as direct/bypass, unknown, or not
covered. It must not claim inline authorization or prevention.

## Hawk UI evidence

For each GitHub action, match the profile session in MCP Gateway, Interaction
Security, Runtime Intelligence, AI IAM, Auditor evidence, and Control Coverage.
For Higgsfield, verify that any Claude/endpoint discovery evidence is kept
separate from inline MCP authorization. Missing action evidence is itself the
expected bypass signal for the hosted connector.
