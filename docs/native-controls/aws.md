# AWS Bedrock and AgentCore

Hawk models nine separate AWS control contracts. They are reviewed capability
boundaries, not AWS installers, live integrations, or Enforce claims:

- Bedrock Model API: a customer-owned invocation route may be a model-request
  boundary. It does not authorize a tool proposed by a model.
- Bedrock Guardrails: external input/output content policy only. It never
  establishes exact function, parameter, target, subject, approval, or
  execution authorization. An AWS Guardrail deny is monotonic: Hawk cannot
  weaken it to allow or approval. Hawk accepts only the documented
  `NONE` and `GUARDRAIL_INTERVENED` response actions; malformed or missing
  outcomes are rejected rather than interpreted as allow.
- Bedrock AgentCore: hosting/runtime identity and route context only. Hosting
  an agent or MCP tool does not make AWS a Hawk action authorization boundary.
- Bedrock Action Runtime: the customer action executor is the possible
  pre-execution function boundary. Post-Lambda observation cannot prevent an
  already completed consequence.
- Bedrock MCP: a customer-cloud MCP tool loop is a generic MCP boundary. It is
  neither a local-endpoint MCP boundary nor a provider-hosted MCP boundary.
- AgentCore Gateway MCP: a separate provider-hosted MCP tool-policy boundary.
  It does not inherit exact Hawk parameter, target, subject, approval, or
  execution binding, and its prompt/resource operations are not generalized
  into tool-control claims.
- Bedrock Knowledge Base: retrieval/context boundary only, not a tool or
  target-service authorization or content-inspection point.
- Bedrock Agents Classic: compatibility-only and maintenance-mode inventory.
  It does not inherit AgentCore, action-runtime, or MCP control claims.
- Custom Bedrock Agent: a customer-built action loop can be integrated, but
  every product, action class, account, route, and target must be accepted
  independently.

All nine profiles are `UNVERIFIED` with deployment acceptance `NOT_TESTED`.
They are not Enforce-eligible. Before a profile may be promoted, Hawk requires
tenant/account/region/route-bound evidence for the exact runtime and action
class: a reviewed allow result, block result, and proof that the protected
callback did not execute. Direct Bedrock APIs, alternate AgentCore routes,
direct MCP targets, and direct target-service calls remain explicit bypass
paths until the customer deployment proves otherwise.

No AWS service version is currently accepted. `2026-08-20` is the Hawk review
date, not an AWS provider version. Unknown runtime versions resolve to
`UNKNOWN`; supplied but unaccepted versions resolve to `UNSUPPORTED`. The
contracts therefore carry no accepted minimum or maximum provider range.

The contracts cite the following AWS product boundaries:

- [Bedrock Guardrails independent API](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-independent-api.html)
- [ApplyGuardrail response action schema](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ApplyGuardrail.html)
- [Bedrock action group Lambda invocation](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-lambda.html)
- [AgentCore Runtime hosting](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html)
- [Customer agent/tool runtime integration](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html)
- [AgentCore Gateway MCP operations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-using.html)
- [AgentCore Gateway policy boundary](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/use-gateway-with-policy.html)
- [Bedrock Knowledge Base retrieval APIs](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-how-retrieval.html)
- [Bedrock Agents Classic action groups and maintenance notice](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-action-create.html)
