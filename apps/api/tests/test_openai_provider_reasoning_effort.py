from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.services.ai_orchestration import providers as orchestration_providers
from app.services.brain.providers import provider_factory
from app.services.brain.providers.openai_provider import OpenAIProvider


class _Response:
    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return {"choices": [{"message": {"content": "synthetic response"}}]}


class _Client:
    def __init__(self, captured: list[dict], **_kwargs):
        self.captured = captured

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, _url, *, json, **_kwargs):
        self.captured.append(json)
        return _Response()


def test_openai_reasoning_effort_absent_omits_field_and_none_includes_it(monkeypatch):
    captured: list[dict] = []
    monkeypatch.setattr("app.services.brain.providers.openai_provider.httpx.Client", lambda **kwargs: _Client(captured, **kwargs))
    baseline = OpenAIProvider(api_key="local-placeholder", model="qwen3.5:9b", base_url="http://127.0.0.1:11434/v1", max_tokens=80)
    configured = OpenAIProvider(api_key="local-placeholder", model="qwen3.5:9b", base_url="http://127.0.0.1:11434/v1", max_tokens=80, reasoning_effort="none")
    assert baseline.generate_text("synthetic", "synthetic") == "synthetic response"
    assert configured.generate_text("synthetic", "synthetic") == "synthetic response"
    assert "reasoning_effort" not in captured[0]
    assert captured[1]["reasoning_effort"] == "none"
    assert captured[0]["max_tokens"] == captured[1]["max_tokens"] == 80


@pytest.mark.parametrize("invalid", ["low", "minimal", "NONE", "", "disabled"])
def test_openai_reasoning_effort_rejects_other_values(invalid):
    with pytest.raises(ValueError):
        Settings._validate_openai_reasoning_effort(invalid)
    with pytest.raises(ValueError):
        OpenAIProvider(api_key="synthetic", model="synthetic", reasoning_effort=invalid)
    assert Settings.model_fields["openai_reasoning_effort"].default is None
    assert Settings._validate_openai_reasoning_effort("none") == "none"


def test_factory_and_llama_orchestration_propagate_opt_in(monkeypatch):
    factory_settings = SimpleNamespace(
        openai_api_key="synthetic", llm_api_key="", openai_model="qwen3.5:9b", llm_model="",
        openai_base_url="http://127.0.0.1:11434/v1", llm_base_url=None, llm_api_version=None,
        llm_timeout_secs=75, llm_temperature=0.0, llm_max_tokens=80, openai_reasoning_effort="none",
    )
    monkeypatch.setattr(provider_factory, "settings", factory_settings)
    monkeypatch.setattr(orchestration_providers, "settings", factory_settings)
    provider = provider_factory._build_provider("openai")
    llama = orchestration_providers._llama_provider(SimpleNamespace(model="qwen3.5:9b"))
    assert provider.reasoning_effort == llama.reasoning_effort == "none"
    assert provider.max_tokens == llama.max_tokens == 80
    factory_settings.openai_reasoning_effort = None
    assert provider_factory._build_provider("openai").reasoning_effort is None
    assert orchestration_providers._llama_provider(SimpleNamespace(model="qwen3.5:9b")).reasoning_effort is None
