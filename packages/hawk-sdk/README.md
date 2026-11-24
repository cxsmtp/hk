# Hawk AI SDK

TypeScript SDK for embedding Hawk AI Action Control Plane checks into apps, agent runtimes, MCP proxies, and gateway-side integrations.

The SDK intentionally wraps the enforcement paths that exist today:

- `POST /gateway/llm/intercept`
- `POST /gateway/mcp/authorize`
- `POST /gateway/mcp/tools/scan`
- `POST /runtime-control/data-transfer-check`
- `POST /runtime-control/data-transfer-justify`

It does not claim universal prevention. Hawk can only return `inline_prevented` when your application, gateway, MCP proxy, or browser path calls Hawk before execution.

## Install

```bash
npm install @hawk-ai/sdk
```

For the local pilot repo, build it directly:

```bash
../../apps/web/node_modules/.bin/tsc -p tsconfig.json
```

## Usage

```ts
import { HawkClient, assertHawkAllowed } from "@hawk-ai/sdk";

const hawk = new HawkClient({
  apiUrl: process.env.HAWK_API_URL!,
  tenantId: process.env.HAWK_TENANT_ID!,
  accessToken: process.env.HAWK_ACCESS_TOKEN!,
});

const result = await hawk.withLlmAuthorization(
  {
    ai_system_id: "internal-assistant",
    actor_type: "human",
    actor_id: "user-123",
    prompt: "Summarize public company filings",
    provider: "azure_openai",
    model: "gpt-4o",
  },
  async () => {
    // This callback is not executed when Hawk returns block/review/step_up.
    return callYourModelProvider();
  },
);
```

Use lower-level decision calls when you need custom UX:

```ts
const decision = await hawk.llmIntercept({
  ai_system_id: "internal-assistant",
  actor_type: "human",
  actor_id: "user-123",
  prompt: "Summarize public company filings",
  provider: "azure_openai",
  model: "gpt-4o",
});

assertHawkAllowed(decision);
```

## Endpoint-agent mode (Node.js)

Node applications can authorize directly through the enrolled user's local Hawk endpoint agent without configuring an API URL, tenant ID, access token, or API key:

```ts
import {
  HawkClient,
  assertEndpointAuthorized,
  assertHawkAllowed,
} from "@hawk-ai/sdk/endpoint";

const hawk = new HawkClient({
  mode: "endpoint",
  endpointSocketPath: process.env.HAWK_ENDPOINT_SOCKET!,
  endpointTrustedDeviceThumbprint: process.env.HAWK_ENDPOINT_DEVICE_THUMBPRINT!,
  clientName: "bank-assistant",
  clientVersion: "1.0.0",
});

const decision = await hawk.endpointLlm({
  ai_system_id: "bank-assistant",
  actor_type: "human",
  actor_id: "user-123",
  prompt: "Summarize the approved policy",
});
assertEndpointAuthorized(decision);
assertHawkAllowed(decision);
```

The explicit endpoint surfaces are `endpointLlm()`, `endpointSdk()`, `endpointDeveloperAgent()`, `endpointFoundry()`, and `endpointDataTransfer()`. Foundry provider attribution and Node process/client metadata are bound by the SDK; caller-provided inline, pre-action, receipt, process, and client trust fields are discarded.

Developer-agent authorization requires a short-lived `capability_token` supplied with each `endpointDeveloperAgent()` request. The SDK does not invent a token, keep it in client configuration, or copy it into the returned decision/receipt.

`dataTransferCheck()` remains the remote-backend request shape and fails explicitly in endpoint mode. Use `endpointDataTransfer()` with direct pre-action content when the local agent is the control point; the returned decision and receipt never retain the raw prompt or copied text.

Endpoint IPC is fail closed: an unavailable or untrusted socket, timeout, malformed/oversized/uncorrelated response, unknown action, approval/review/redaction request, or a scoped result cannot authorize generic SDK execution. Scope remains blocked because the SDK cannot enforce resource constraints on an arbitrary caller; a future surface-specific constraint enforcer must provide that proof before scope can be enabled.

`endpointTrustedDeviceThumbprint` is required. It is the public SHA-256 key pin
written by endpoint enrollment, not a credential. Each local response carries a
fresh P-256 signature; the SDK uses only the signed payload and rejects socket
replacement, unsigned output, pin mismatch, and stale output.

Monitor mode remains non-enforcing: the effective action may continue, but the response sets `endpoint_authorized: false`, uses `decision_source: "endpoint_agent_monitor"`, and exposes `would_decision`. `assertEndpointAuthorized()` and `withLlmAuthorization()` fail closed on such monitor-only evidence, so code that requires inline authorization cannot mistake observation for enforcement.

The default timeout is 10 seconds so an eight-second live backend decision still has IPC margin. Node endpoint functionality lives only at `@hawk-ai/sdk/endpoint`; the root `@hawk-ai/sdk` entry is the browser-safe remote-backend client and has no dependency on Node socket, filesystem, path, or crypto modules.

## MCP Tool Authorization

```ts
const result = await hawk.mcpAuthorize({
  ai_system_id: "developer-agent",
  actor_id: "agent-42",
  capability_token: "capability-token-from-hawk-or-your-runtime",
  action: "write_file",
  resource: "repo://payments/auth.py",
  tool_name: "write_file",
  chain_id: "chain-123",
});
```

For inline MCP execution, wrap the actual tool call:

```ts
const result = await hawk.withMcpAuthorization(
  {
    ai_system_id: "developer-agent",
    actor_id: "agent-42",
    capability_token: "capability-token-from-hawk-or-your-runtime",
    action: "write_file",
    resource: "repo://payments/auth.py",
    tool_name: "write_file",
    chain_id: "chain-123",
  },
  async () => runActualMcpTool(),
);
```

## Tool Fingerprinting

```ts
await hawk.scanMcpTool({
  mcp_server_id: "github-mcp",
  tool_name: "create_pull_request",
  tool_version: "1.2.0",
  description: "Create a pull request",
  schema: { type: "object" },
});
```

## Browser-Visible Data Transfer

```ts
const transfer = await hawk.dataTransferCheck({
  copy_context: {
    copied_text_hash: "sha256:...",
    copied_text_preview_redacted: "Customer email: [email]",
  },
  paste_context: {
    destination_domain: "chatgpt.com",
    destination_surface_type: "public_ai",
  },
});
```

`guardDataTransfer()` blocks or pauses the caller when Hawk returns `block`, `review`, or `require_justification`. If justification is required, collect justification and call `dataTransferJustify()` before retrying the user action.

## What This SDK Can Control

| Surface | Apps/providers | Inline control today |
|---|---|---|
| Internal AI apps | Azure OpenAI, Microsoft Foundry app backends, OpenAI, Anthropic, Gemini, Bedrock, self-hosted models | Yes, when the app calls `withLlmAuthorization()` before the model call |
| LLM gateway/proxy | Any provider routed through your gateway | Yes, call `guardLlmAction()` before forwarding |
| MCP proxy/gateway | Cursor/Claude Code/Codex/agent runtimes using a Hawk-routed MCP proxy | Yes, call `withMcpAuthorization()` before `tools/call` |
| Developer tools | IDE agents, repo assistants, CI assistants | Yes for tool/model calls routed through the SDK or Hawk MCP/LLM gateway |
| Browser extension | ChatGPT/Claude/Gemini/Perplexity and visible browser AI/data movement flows | Browser extension is the inline control point; SDK is not needed in the page |
| Microsoft Copilot / M365 | Copilot activity, Copilot Studio, Graph/OAuth telemetry | Not universal inline via SDK; use connectors/Graph for telemetry and external remediation unless calls route through your app/gateway |
| Native desktop AI apps | Desktop apps/CLI tools | Only inline when traffic or tool calls route through Hawk Local Proxy, SDK, LLM Gateway, or MCP Gateway |

## Security Notes

- Do not put raw secrets into SDK telemetry payloads.
- Use redacted summaries, hashes, counts, and metadata for sensitive fields.
- Keep access tokens server-side for app embeds where possible.
- Client-side/browser usage should rely on short-lived tokens and server-side policy decisions.
- Control mode honesty still applies: detected-only telemetry is not prevention.
