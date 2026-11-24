# Hawk gateway overhead benchmark methodology

## Purpose and claim boundary

This benchmark measures observed end-to-end latency for a direct request and the
corresponding Hawk-routed request against one deterministic, local,
OpenAI-compatible upstream stub. It isolates the cost of the Hawk request path
from public-network and model-provider variance.

The benchmark does not establish a product performance claim by itself.
Headline latency and overhead exist only for measured pairs whose direct and
Hawk legs both succeed and whose Hawk response carries the expected upstream
proof and expected governance assertions. Failed, unreconciled, or ungoverned
attempts remain visible only as diagnostics. A claim-eligible run requires at
least 100 comparison-eligible pairs, zero excluded measured pairs, an exact
approved dirty-patch match when the tools checkout is dirty, stable pre/post
source and implementation snapshots, and raw artifacts from the stated runner
hardware and environment. One hundred eligible observations is the minimum
that gives nearest-rank p99 a distinct 99th observation. Unit-test fixtures and
generated examples are validation inputs, not measurements.

## Compared paths

Each pair uses the same canonical JSON request bytes, timeout, HTTP version,
connection-pool limits, and keep-alive policy.

- `baseline`: runner → deterministic local upstream
- `hawk`: runner → Hawk OpenAI-compatible gateway → the same deterministic
  local upstream

The two legs need different connection pools because they have different first
destinations. The pools have identical settings and remain open for the full
run. The Hawk leg adds only the authentication and tenant headers required by
Hawk. Both legs receive the identical request body.

This harness accepts only loopback endpoints. Both the Hawk base URL and
deterministic upstream must use HTTP on `127.0.0.1`, `::1`, or `localhost`.
Loopback spelling does not establish how Hawk was built, which checkout it
uses, whether it runs in a container or VM, or whether port forwarding crosses
a resource boundary. The recorded hardware therefore describes the benchmark
runner only. Target metadata explicitly marks Hawk process provenance as
unverified and never attributes the runner checkout or hardware to Hawk.
Container or VM limits still need explicit non-sensitive flags.

All deterministic runner clients use `trust_env=False`. Environment proxy
variables are intentionally ignored because a proxy would change the measured
topology. Proxy-based measurements require a separate methodology and harness.

The upstream exposes the contract `hawk-deterministic-openai-stub/1.0` and
creates a fresh 256-bit session nonce when the stub starts. The runner creates a
fresh 256-bit request nonce for each run and places it in the identical request
body sent over both paths. The stub derives the response proof from its
contract, session nonce, and the run request nonce. Every successful sample
must reproduce that run-unique proof. This attests that the response implements
the checked stub session contract and prevents a stale public constant from
satisfying the check. It does not establish Hawk process or checkout
provenance.

## Pairing and execution order

Warmup pairs run before measured pairs. Every warmup request remains in
`samples.ndjson` with `excluded_warmup: true`; it is never silently discarded.

The two legs in a pair run sequentially. The first leg alternates to reduce
ordering bias:

- even pair index: baseline, then Hawk;
- odd pair index: Hawk, then baseline.

Pairs may run concurrently up to the recorded concurrency. Measured requests do
not start until the warmup stage completes.

## Local setup

Run the deterministic upstream in a dedicated terminal:

```bash
python infra/scripts/load_gateway_request_path.py stub --host 127.0.0.1 --port 8765
```

Start the Hawk API using the deployment under test and configure its OpenAI
provider to use that same stub:

```text
OPENAI_BASE_URL=http://127.0.0.1:8765/v1
OPENAI_API_KEY=<non-production local stub value>
OPENAI_MODEL=hawk-deterministic-stub
```

Use a dedicated benchmark tenant, AI system, policy version, and policy profile.
The selected policy must permit the deterministic request. Obtain a short-lived
Hawk bearer token through the normal authentication flow and pass it only
through the environment:

```bash
export HAWK_BENCHMARK_BEARER_TOKEN='<short-lived token>'
python infra/scripts/load_gateway_request_path.py run \
  --hawk-base-url http://127.0.0.1:8000 \
  --upstream-url http://127.0.0.1:8765/v1/chat/completions \
  --tenant-id '<tenant id>' \
  --ai-system-id '<AI system id>' \
  --policy-version-id '<policy version id>' \
  --policy-profile 'benchmark-allow-v1' \
  --environment-label 'runner-hardware-description' \
  --approved-patch-sha256 '<approved patch SHA-256 when the tree is dirty>' \
  --warmup-pairs 10 \
  --measured-pairs 100 \
  --concurrency 1 \
  --timeout-seconds 20 \
  --flag receipts_enabled=true \
  --flag cache_profile='"declared-profile"'
```

Do not pass credentials through `--flag`, identifiers, labels, or policy
profile names. The artifact validator rejects common credential field names and
secret markers, but that is a guardrail rather than a secret-management system.
Inspect the exact calculated source state before an approval review:

```bash
python infra/scripts/load_gateway_request_path.py source-state
```

Omit `--approved-patch-sha256` for a clean tree. For a dirty tree, the supplied
digest must exactly equal the harness-calculated dirty-patch digest, which binds
tracked, staged, unmerged, and untracked non-ignored state. A missing or
mismatched approval digest is recorded but explicitly ineligible for a
performance claim.

## Raw artifact contract

Every run is written beneath the ignored directory:

```text
apps/api/artifacts/benchmarks/<run-id>/
├── metadata.json
├── samples.ndjson
└── summary.json
```

`metadata.json` records:

- environment label, operating system, and Python version;
- machine/processor class, logical CPU count, and physical memory (explicit
  `null` when a count is unavailable);
- Git revision, exact dirty/clean boolean, calculated dirty-patch SHA-256,
  optional independently approved patch SHA-256, their exact-match result, and
  source claim eligibility;
- loopback endpoint topology, runner-only hardware scope, benchmark-tools-only
  source scope, and explicitly unverified Hawk process provenance;
- immutable SHA-256 bindings for the harness, reporter, and this methodology,
  plus their closed contract versions;
- pre/post source and implementation snapshot stability;
- the exact required Hawk decision, control mode, evidence outcome, and receipt
  outcome for a comparison-eligible pair;
- operator-declared policy profile, exact policy version ID, and non-sensitive
  flags;
- request payload byte count and SHA-256;
- concurrency, timeout, HTTP version, and connection mode;
- warmup/measured pair counts;
- deterministic upstream contract and response-proof hash;
- run start and finish timestamps.

Every NDJSON sample records:

- run, pair, leg, and sequence identity;
- the explicit warmup-exclusion marker;
- UTC start/finish timestamps and observed end-to-end milliseconds;
- request/response byte counts and SHA-256 hashes;
- the canonical metadata SHA-256, binding every raw sample to the run
  provenance;
- upstream response-proof hash;
- HTTP status and bounded failure class;
- Hawk decision, control mode, evidence outcome, and receipt outcome.

The raw artifact deliberately excludes request bodies, response bodies,
prompts, headers, bearer tokens, exception text, and endpoint URLs. Unknown
decision, control, evidence, or receipt state remains `unknown`; the reporter
does not infer successful governance. Evidence is present only for a nonempty,
bounded list of opaque evidence-node IDs or a bundle object with a bounded
opaque `evidence_bundle_id`. A receipt is present only for a bounded opaque
decision or execution receipt-ID string. Malformed scalar, collection, or
object shapes are recorded as missing, never promoted to present.

Schemas are exact and closed. Missing fields, unexpected fields, duplicate or
incomplete pairs, non-alternating ordering, mismatched payloads, inconsistent
warmup markers, timing contradictions, pair overlap above recorded
concurrency, impossible status/failure combinations, and non-canonical NDJSON
are rejected. Transport failures have status `0` and no response; HTTP errors
have a non-2xx status; invalid responses and response-proof mismatches have a
2xx status.

## Calculations

Only non-warmup raw samples contribute to the summary. Every attempt contributes
to throughput, failure, status, decision, and other diagnostic counts.

For each comparison-eligible measured pair:

```text
observed_overhead_ms = hawk_e2e_ms - baseline_e2e_ms
```

The value is neither clamped nor replaced. A negative observed delta remains
negative. A pair is excluded from headline comparison when either leg fails,
the Hawk proof does not reconcile, or the Hawk leg does not report `allow`,
`inline_allowed`, present evidence, and a present receipt. The summary reports
the excluded-pair count and bounded reasons. With zero eligible pairs, headline
latency and overhead are `null`. Headline diagnostics may exist below the claim
threshold, but a performance claim is ineligible unless at least 100 pairs are
eligible and no measured pair is excluded; this prevents a small,
selection-biased survivor subset from being published as the run result.

Latency and paired-overhead p50/p95/p99 use the nearest-rank definition:

```text
rank = ceil(percentile / 100 × sample_count)
```

Headline direct/Hawk latency percentiles use only comparison-eligible pairs.
All-attempt and failed-attempt latency are separately labeled diagnostics and
must not be presented as gateway overhead.

Throughput is the measured request count divided by the UTC wall-clock window
from the earliest measured start to the latest measured finish. Failure rate is
failed measured samples divided by measured samples, reported for all samples
and separately for each leg. A sample succeeds only when its HTTP status is
2xx, its response is valid JSON, and it carries the expected deterministic
upstream proof.

`summary.json` includes the SHA-256 of the exact `samples.ndjson` bytes. Each
raw sample includes the canonical `metadata.json` SHA-256, so the raw checksum
also binds the recorded run provenance. Summary metrics, counts, outcome
distributions, and checksum are reproducible from raw samples. They are not
populated from operator-entered aggregates.

## Verification and tamper handling

Reproduce and verify an existing result:

```bash
python infra/scripts/test_report_summary.py \
  --verify-benchmark-run apps/api/artifacts/benchmarks/<run-id>
```

Verification fails when the raw-sample checksum changes, the stored summary
differs from a fresh calculation, the JSON is not canonical, or any schema,
pairing, privacy, or completeness rule fails. Preserve the full run directory
as one unit when moving artifacts to approved evidence storage.

Generated run data is ignored by Git and must not be committed.

The hashes detect inconsistent or modified files; they are not digital
signatures and do not establish who produced a run. Use the platform's approved
signed evidence storage when provenance authenticity is required.

## Measurement controls and limitations

- Run Hawk and the runner in the intended otherwise idle local topology and
  record any container/VM CPU or memory limits as flags. The artifact itself
  attests only the runner hardware and loopback endpoints.
- Keep Hawk, the runner, and the deterministic stub topology unchanged across
  compared runs.
- Use the same policy version and declared cache profile for every run being
  compared.
- Repeat independent runs rather than combining samples from different run
  directories.
- A dirty tools checkout is eligible only when the supplied independently
  approved patch hash exactly matches the harness-calculated dirty-patch hash.
  A syntactically valid but different digest remains ineligible. The match is a
  content binding, not proof that the approval process occurred.
- The harness, reporter, and methodology hashes identify the exact tools used;
  they are captured before requests. Source and implementation snapshots are
  recomputed after requests; any change makes the run claim-ineligible.
- The local stub removes public-network and model inference variability. It
  does not predict production provider latency.
- A comparison-eligible Hawk leg must report the configured allow decision,
  inline control, evidence, and receipt. The result includes that observed Hawk
  gateway path and local provider hop, but does not prove the Hawk binary,
  checkout, container, or individual internal component identity.
- This slice reports latency, observed paired overhead, throughput, failure,
  status, decision, control, evidence, and receipt outcomes. Other platform
  metrics in the wider validation plan require their own evidence-backed
  harnesses.
