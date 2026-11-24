# Native Control Security


## Callback authentication

Trusted envelopes use P-256 ECDSA (`ES256`) and bind tenant, integration, provider/product, environment, credential ID/epoch, event type, timestamps, nonce, payload hash, and action hash. Only the public key is stored by Hawk. Cross-tenant, cross-installation, wrong-environment, wrong-event, expired, future, revoked, and wrong-epoch events are rejected.

## Replay and parsing

Replay claims are persisted as hashes of event IDs and nonces. Envelopes reject duplicate JSON keys, unknown fields, excessive size/depth, invalid hashes, invalid signatures, and unsupported algorithms. Payload hashes use constant-time comparison. Raw payloads are not logged.

## Authority

Provider-controlled identity, tenant, role, approval, risk, and policy fields are ignored by adapters. Hawk resolves these fields from trusted server context. The adapter only normalizes bounded action metadata into the existing Authorization Request.

## Local policy and helper

Local policy is a signed, expiring, integration-scoped declarative subset with only action class and decision rules. Unsupported features return `REMOTE_EVALUATION_REQUIRED`. Executable code, scripts, commands, binaries, modules, plugins, dynamic imports, and update artifacts are forbidden.

The helper accepts only policy install, configuration apply, decision cache, and metadata sync messages. It has no command execution or generic remote administration operation.

## Key separation and updates

Policy verification requires a `policy_signing` key role. Software artifacts require a different `software_update_signing` role and bind artifact, SBOM, provenance, canary/staged/stable channel, and rollback hashes/version. A policy key cannot validate an update.

Evidence/callback/integration identity remain separate roles in existing Hawk stores. Production software signing private keys are not stored in the application database.

## Data minimization

The default adapter contract accepts hashes and canonical metadata. It does not collect hidden reasoning. Raw prompt/response traversal occurs only on the verified Hawk gateway path and remains subject to configured privacy and retention policy.
