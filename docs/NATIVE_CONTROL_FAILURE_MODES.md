# Native Control Failure Modes

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


| Failure | Selector/coverage behavior | Operational outcome |
|---|---|---|
| Callback unauthenticated | Candidate rejected; coverage Unknown | Finding/metric on validation failure |
| Replay detected | Event rejected before policy | Replay counter; no execution authority |
| Validation older than 15 minutes | Candidate rejected | Monitor/Enforce transition fails |
| Policy expired | Candidate rejected | `NATIVE_CONTROL_POLICY_STALE` profile available for findings |
| Configuration fingerprint mismatch | Candidate rejected; coverage Unknown | Keep out of enforce |
| Provider version outside tested range | Candidate rejected | Use verified fallback or remain Not Covered |
| Native hook missing/unverified | Native claim unavailable to selector | Gateway/endpoint fallback may be selected if eligible |
| Strong point fails, weak point insufficient | No silent failover | `CONTROL_REQUIREMENT_UNSATISFIED`; fail closed when enabled |
| Assurance decreases | New selection identity | Downgrade evidence, finding, and metric |
| Gateway bypass | Gateway coverage does not extend to bypassed traffic | Blind spot remains visible |
| Endpoint/client binding removed | Runtime control no longer verified | Coverage becomes Unknown/Not Covered |
| Unsupported local policy feature | No local guess | `REMOTE_EVALUATION_REQUIRED` |

Degradation is explicit per integration: fail closed, fail open with evidence, local policy only, block high risk only, require exception, or monitor only. The selector rejects a mode that the action's requirement profile does not permit.
