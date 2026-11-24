# Native Control Privacy


Native controls default to canonical metadata and hashes: action class, tool fingerprint, parameter/target/destination hashes, identity binding, timestamps, result classification, and evidence references.

Provider adapters reject unexpected fields and do not accept raw provider claims as authority. Hidden chain-of-thought or private model reasoning is never requested or stored.

The verified gateway fallback necessarily traverses prompt, response, and actionable metadata through the configured Hawk gateway boundary. Endpoint-runtime fallback evaluates canonical metadata; raw content handling follows endpoint policy. Provider guardrail services may process content in the provider boundary but are not treated as complete Hawk action authorization.

Customer retention, redaction, field exclusion, regional storage, and evidence controls continue to use Hawk's existing privacy and retention plane. The native framework stores public keys and hashed replay identifiers, never workload private keys or provider API secrets.
