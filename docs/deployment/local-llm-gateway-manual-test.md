# Local LLM gateway manual test

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


This local test uses the existing Hawk API implementation with separate,
process-local model settings. It shares the platform database and policies;
it is not an isolated tenant or a production deployment.

## Running topology

- Hawk test API: `127.0.0.1:8001`
- Hawk test HTTPS entry: `https://api.hawk.localhost:3444`
- Ollama: `127.0.0.1:11434`, installed model `qwen3.5:9b`
- Local TLS relay to Ollama: `https://api.hawk.localhost:11435/v1`

All new listeners bind to loopback. The existing platform on port 3443 is
unchanged. The relay uses the existing development certificate; the test API
trusts that certificate explicitly rather than disabling certificate validation.
This is process-session deployment, not an installed launch-at-login service.

The API must start from `apps/api` for its migration check. Strict control-plane
checks also require a live Celery worker and scheduler with compatible component
identities. Start each service in its own terminal from the repository root:

```bash
bash infra/scripts/local-llm-test-service.sh api
bash infra/scripts/local-llm-test-service.sh worker
bash infra/scripts/local-llm-test-service.sh beat
```

Do not start duplicate workers/schedulers when these services are already running.
These services share the local platform queues and database. They do not replace
the separately running Ollama and HTTPS relays described above.

## Interactive test

From the repository root:

```bash
python3 infra/scripts/manual-llm-gateway-test.py
```

Enter your normal Hawk email and password (hidden), then select the tenant,
registered AI system, policy pack and version. Operator-or-higher access is
required for model calls. The helper does not save credentials or edit policy.
Selections accept the displayed number or an exact ID; Enter selects the only
item when there is a single choice. Fail-secure errors include failed check names.

Start with a synthetic, in-scope question for the selected AI system, such as
`Explain how to register a support complaint in one sentence.`
Then test an input forbidden by that policy. Do not use real customer data.

Each prompt calls `POST /llm-gateway/chat/complete` with provider `ollama` and
prints the decision, whether the provider was invoked, response coverage,
event/request IDs, evidence references and the released answer.
Use `/quit` to exit. Requests create normal platform audit/evidence records.

Acceptance is an allowed request with a real answer plus a policy-denied
request with `provider_invoked: false`. A provider smoke test alone does not
prove policy enforcement. A login, registration, permission, policy or
governance error must be resolved through the normal platform workflow;
the helper does not bypass it. Streaming is not supported by this route.

API documentation: `https://api.hawk.localhost:3444/docs`.
Do not point test clients directly at Ollama: that bypasses Hawk.

## Reversible masking and document review

Reversible masking is off until a tenant's persisted policy version sets
`scope.llm_gateway_security.reversible_masking.enabled` to `true`. For document
creation and upload, the same policy must also set `documents_enabled` to
`true`. The request cannot turn either setting on. Use synthetic values while
testing. When enabled, names, labelled passports and account numbers are sent
to the model as request-scoped placeholders. The gateway restores them only
after the final response controls allow release. Blocked, held and redacted
responses are not restored. The mapping expires and is destroyed after the
request, including provider failures. Existing streaming remains unsupported.

The `POST /llm-gateway/documents/complete` route accepts multipart fields
`tenant_id`, `ai_system_id`, `policy_version_id`, `provider`, `mode` (`draft` or
`transform`), `output_format` (`pdf` or `docx`), and `instruction`. Transform
also requires a `file` with matching extension, MIME type and file signature.
The response supplies `content_base64`, `media_type`, a generic download name
and the usual gateway decision/evidence. Treat it as a new document: PDF/DOCX
text and basic heading, paragraph, list and table structure are reconstructed;
original layout and styling are not preserved. Scanned, encrypted, active,
external or oversized files fail closed. PDF output currently fails closed on
non-ASCII text rather than silently replacing glyphs. DOCX supports Unicode.

For isolated real-provider acceptance, run
`apps/api/.venv/bin/python infra/scripts/run_isolated_llm_provider_acceptance.py --documents-only`
from the repository root. It uses a temporary tenant and database, verifies
the installed Ollama model digest, exercises chat and PDF/DOCX paths, and
writes synthetic review files plus a sanitized report under
a fresh private child of `/private/tmp/hawk-reversible-masking-qa` for each
run. To choose the location explicitly, pass `--artifact-dir` with a fresh,
nonexistent direct child of `/private/tmp/hawk-reversible-masking-qa`; the CLI
records this evidence as `real_ollama`. It must not point at the shared demo database. Inspect the
returned decisions and reconstructed files; the report deliberately contains
hashes, relative filenames, byte lengths and booleans instead of original text.
The dated `hawk-reversible-masking-qa-20260927` directory is stale and is not
acceptance evidence.

Current bounded acceptance status: **blocked**. The corrected real-provider
`--transforms-only` run reached the first PDF transform and failed closed with
`document_gateway_status_400_stage_documents_complete_mode_transform_format_pdf_code_invalid_document_response`.
The sanitized progress record is
`/private/tmp/hawk-reversible-masking-qa/run-oocp_4sa/acceptance-progress.json`
and is marked `real_ollama` with terminal failure. No DOCX transform was
attempted, no real document was released, and no promotion claim is valid.
The dated 20260927 directory is contaminated by mock-test artifacts and must
remain excluded from acceptance evidence.

Final harness review is also not approved. Two bounded corrections remain:
require an explicit evidence source even for non-live report validation, and
preserve completed-flow counts in the SIGTERM progress write before lab cleanup.
The targeted tests passing does not close these review findings. No additional
provider invocation or browser acceptance followed this review.

## Process-local API configuration

The test API loads the existing native-demo environment, then overrides:

```text
OPENAI_API_KEY=ollama-local
OPENAI_BASE_URL=https://api.hawk.localhost:11435/v1
OPENAI_MODEL=qwen3.5:9b
LLM_MODEL=qwen3.5:9b
LLM_TIMEOUT_SECS=180
LLM_MAX_TOKENS=4096
SSL_CERT_FILE=<repository>/infra/tls/local/hawk-local.crt
```

`ollama-local` is a non-secret placeholder required by the OpenAI-compatible
adapter; it is not a commercial provider credential. No `.env` files are changed.
The local unencrypted Ollama hop stays on loopback. This setup does not establish
production mTLS, device-wide routing or prevention of direct local Ollama access.
