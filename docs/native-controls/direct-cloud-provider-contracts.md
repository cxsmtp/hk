# Direct and cloud provider model-route contracts

Hawk represents the following five boundaries independently:

| Provider | Product | Runtime location | Method | Current state |
|---|---|---|---|---|
| Anthropic | Direct API | Provider hosted | API intercept | Unverified / Not tested |
| Google | Gemini API | Provider hosted | API intercept | Unverified / Not tested |
| Google | Vertex AI | Customer cloud | API intercept | Unverified / Not tested |
| Azure | Azure OpenAI direct API | Customer cloud | API intercept | Unverified / Not tested |
| Microsoft | Foundry hosted model/runtime | Remote agent | SaaS control API | Unverified / Not tested |

They are reviewed provider-control contracts, not executable Hawk adapters,
provider policy engines, route-binding records, or tenant deployment proof.
Each profile is Enforce-ineligible until an immutable deployment acceptance
binds the exact provider, product, runtime location, account/tenant context,
model provider/model, route identity and deployment identity, and proves
allow, block and protected non-execution on that exact route.

## Deliberate separations

- Anthropic Direct API is not Claude Code, Enterprise Inference Hook, Tenant
  Restrictions, or a generic gateway route.
- Gemini API is not Gemini CLI and Vertex AI is not Gemini API. Each carries a
  different runtime location and customer/provider configuration boundary.
- Azure OpenAI direct API is not Microsoft Agent Framework or Microsoft
  Foundry hosted model/runtime.
- Microsoft Foundry hosted model/runtime is not a local Function middleware,
  direct Azure API call, hosted tool/MCP execution or endpoint floor.
- OpenAI Direct API keeps the existing action-class-specific OpenAI adapter;
  this module intentionally adds no second OpenAI Direct API contract.
- AWS Bedrock and AgentCore are represented by their separate contracts.

## Capability truth

The profiles can describe a potential model request boundary and post-response
observation only. Before real acceptance, every such claim is `UNVERIFIED`.
They never authorize a function/tool proposal, function execution, hosted
tool, MCP operation, parameter, target, destination, persistent side effect,
or remote execution. Those require an independent accepted Hawk control point.

The existing generic Hawk Gateway stays a separate routed model
request/response capability. It does not promote any direct/cloud contract,
alternate route, account context, deployment, tool path, hosted execution, or
provider-native lifecycle boundary.
