# Agent Touchpoint Graph


The Agent Touchpoint Graph is an investigation view powered by Runtime Intelligence and AI IAM data. It is not a separate dashboard product.

## Node Types

- User
- Agent
- Agent session
- Delegated agent
- MCP server
- MCP tool
- SaaS app
- API
- Data source
- Repo
- File
- Browser page
- Approval
- JIT grant
- Webhook
- Scheduled job
- Memory object
- External destination
- Evidence bundle
- Finding

## Edge Types

- initiated
- delegated_to
- invoked_tool
- used_identity
- requested_approval
- approved_by
- executed_action
- created_side_effect
- accessed_data
- wrote_memory
- created_webhook
- created_scheduled_job
- sent_to_external
- tainted
- blocked_by_policy
- has_evidence

## Blast Radius

Blast radius is calculated from observed touchpoint edges and chain-scoped deferred side effects.

Scores:

- `data_access_score`
- `tool_action_score`
- `privilege_score`
- `persistence_score`
- `external_exfiltration_score`
- `delegation_score`
- `overall_blast_radius_score`

The panel must distinguish theoretical reach from observed/executed actions. The first implementation calculates observed reach only.

## Investigation Use

A finding should drill into:

action -> actor -> authority -> surface -> approval/JIT/tool/deferred side effect -> policy decision -> evidence -> chain timeline

Example:

User -> Agent A -> Agent B -> MCP Tool -> SaaS Admin Action -> Webhook

