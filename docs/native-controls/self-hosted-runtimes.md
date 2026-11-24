# Self-Hosted Runtime Control Boundaries

Hawk treats model identity and serving-runtime identity as separate facts.
For example, a Meta Llama model may be served by Llama Stack, Ollama, vLLM,
Text Generation Inference, llama.cpp, Kubernetes, custom Python, an
OpenAI-compatible server, or an agent framework.  A runtime name, endpoint
URL, or request protocol does not prove the model provider/model, customer
identity, tool authorization, MCP authorization, target authorization, or
provider-native lifecycle control.

The Phase 4 runtime profiles are reviewed contracts only. They are separated
by the boundary Hawk would actually have to intercept:

- customer model/runtime: Meta Llama, Qwen, DeepSeek, and Kimi
- serving runtime: Llama Stack, Ollama, vLLM, and Text Generation Inference
- provider API: Qwen, DeepSeek, and Kimi
- customer tool loop: Qwen-Agent, DeepSeek customer tool loop/agent framework,
  and Kimi coding agent
- Unknown OpenAI-Compatible Runtime
- Unknown Anthropic-Compatible Runtime
- Custom Model Runtime

Each is `UNVERIFIED` and `NOT_TESTED`. None can be selected for Enforce. Model
and provider-API profiles label only a possible model-request/response
interception boundary. Qwen-Agent, the DeepSeek customer tool-loop/agent
framework, and Kimi coding profiles label only a possible customer-owned
tool-dispatch boundary. Serving-stack profiles do not infer the model
provider/model. None installs an interceptor, establishes a provider-native
hook, or silently controls a serving stack.

The existing generic Hawk Gateway remains independently verified only where
traffic is actually routed through Hawk.  That evidence covers model
request/response on the bound route.  It does not transfer to a self-hosted
runtime, direct route, alternate endpoint, sidecar, remote executor, tool
loop, MCP server, parameter, target, destination, provider account, or
provider-native hook.

Before any profile can move beyond Monitor, Hawk requires the canonical exact,
immutable deployment acceptance record. It binds provider, product, runtime,
version, adapter, environment, deployment reference, deployment identity,
model provider, model, route identity, action class, method, and lifecycle.
The acceptance must prove a real allow, a real block, protected non-execution,
fresh route evidence, bounded latency, and the configured failure behaviour.
Direct and alternate endpoints, sidecar bypass, runtime/model-route drift,
remote execution, and unsupported versions must be tested independently.

The compatibility aliases `openai-compatible` and `anthropic-compatible` map
to the `unknown_provider` family. The serving aliases `llama-stack`, `ollama`,
`vllm`, and `tgi` map to `self_hosted_runtime`. These aliases deliberately do
not inherit OpenAI, Anthropic, Meta, or another model-provider capability. A
future acceptance may bind an authenticated, non-placeholder model-provider
identity, but that identity does not change the compatibility profile into a
provider-native control point.

Model-produced tool-call text is not a tool authorization boundary.  Tool,
MCP, function, parameter, target, destination, endpoint, gateway, and target
service control each require their own accepted Hawk control point.
