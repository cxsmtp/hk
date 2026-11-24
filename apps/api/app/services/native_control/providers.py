from __future__ import annotations


_ALIASES = {
    "claude": "anthropic",
    "gemini": "google",
    "google_gemini": "google",
    "azure_openai": "azure",
    "azure_ai": "azure",
    "azure_ai_foundry": "azure",
    "bedrock": "aws",
    "amazon_bedrock": "aws",
    "llama": "meta",
    "meta_llama": "meta",
    "kimi": "moonshot_kimi",
    "moonshot": "moonshot_kimi",
    "qwen": "alibaba_qwen",
    "alibaba": "alibaba_qwen",
    # A protocol label is not a provider identity.  Keep unknown compatible
    # servers in a dedicated non-inheriting family so they cannot receive
    # OpenAI or Anthropic native-control claims by name normalization.
    "openai_compatible_unknown": "unknown_provider",
    "unknown_openai_compatible": "unknown_provider",
    "anthropic_compatible_unknown": "unknown_provider",
    "unknown_anthropic_compatible": "unknown_provider",
    "openai_compatible": "unknown_provider",
    "anthropic_compatible": "unknown_provider",
    "custom_model_runtime": "unknown_provider",
    # Serving stacks are runtime identities, not model-provider identities.
    # They have independent conservative matrix rows and inherit no model or
    # provider-native capability from the models they happen to serve.
    "llama_stack": "self_hosted_runtime",
    "ollama": "self_hosted_runtime",
    "vllm": "self_hosted_runtime",
    "tgi": "self_hosted_runtime",
    "text_generation_inference": "self_hosted_runtime",
}


def canonical_provider(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _ALIASES.get(normalized, normalized or "unknown")
